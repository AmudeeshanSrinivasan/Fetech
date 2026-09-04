"""Bounded context broker for code/runtime graphs, QMD, and exact source evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from fetech.models import (
    ContextBundle,
    ContextNeed,
    ContextProviderReport,
    ContextProviderStatus,
    ContextSource,
    ContextTokenUsage,
)

_MAX_QUESTION_BYTES = 16_384
_MAX_QMD_NOTES = 100
_MAX_GRAPH_NODES = 24
_MAX_GRAPH_PATHS = 16
_MAX_SOURCE_LOCATIONS = 12
_MAX_SOURCE_MATCHES = 8
_MAX_SOURCE_FILE_BYTES = 5_000_000
_CONTEXT_PROCESS_TIMEOUT_SECONDS = 15.0
_CONTEXT_PROCESS_OUTPUT_BYTES = 2_000_000

_CODE_SIGNALS = frozenset(
    {
        "architecture",
        "call",
        "calls",
        "class",
        "code",
        "dependency",
        "function",
        "implementation",
        "module",
        "package",
        "source",
    }
)
_RUNTIME_SIGNALS = frozenset(
    {
        "artifact",
        "attempt",
        "cancelled",
        "event",
        "failure",
        "ledger",
        "provenance",
        "result",
        "run",
        "runtime",
        "trace",
    }
)
_DECISION_SIGNALS = frozenset(
    {
        "accepted",
        "adr",
        "blocker",
        "decision",
        "history",
        "milestone",
        "note",
        "previous",
        "roadmap",
        "superseded",
    }
)
_GENERIC_VERIFICATION_TERMS = (
    _CODE_SIGNALS
    | _RUNTIME_SIGNALS
    | _DECISION_SIGNALS
    | {
        "explain",
        "find",
        "handle",
        "handles",
        "implement",
        "implemented",
        "implements",
        "project",
        "show",
        "trace",
    }
)
_UUID_RE = re.compile(
    r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"
)
_GRAPH_NODE_RE = re.compile(
    r"^NODE (?P<label>.+?) \[src=(?P<src>.*?) loc=(?P<loc>.*?) community=.*\]$"
)
_GRAPH_EDGE_RE = re.compile(r"^EDGE (?P<edge>.+? --.+?--> .+)$")
_SOURCE_LOCATION_RE = re.compile(r"^(?P<path>.+):L(?P<line>\d+)(?:-L(?P<end>\d+))?$")

ProviderName = Literal["code_graph", "runtime_graph", "qmd", "exact_source"]


@dataclass(frozen=True)
class ContextBudget:
    graphify_tokens: int = 1_200
    qmd_tokens: int = 1_200
    source_tokens: int = 2_000
    total_tokens: int = 4_000
    hard_ceiling: int = 8_000
    qmd_notes: int = 3

    def __post_init__(self) -> None:
        token_values = (
            self.graphify_tokens,
            self.qmd_tokens,
            self.source_tokens,
            self.total_tokens,
            self.hard_ceiling,
        )
        if any(isinstance(value, bool) or not isinstance(value, int) for value in token_values):
            raise ValueError("context token budgets must be integers")
        if min(self.graphify_tokens, self.qmd_tokens, self.source_tokens) < 0:
            raise ValueError("context source token budgets cannot be negative")
        if self.total_tokens <= 0 or self.hard_ceiling <= 0:
            raise ValueError("context total token budgets must be positive")
        if self.total_tokens > self.hard_ceiling:
            raise ValueError("default context budget cannot exceed its hard ceiling")
        if (
            isinstance(self.qmd_notes, bool)
            or not isinstance(self.qmd_notes, int)
            or not 1 <= self.qmd_notes <= _MAX_QMD_NOTES
        ):
            raise ValueError(f"QMD note limit must be an integer from 1 to {_MAX_QMD_NOTES}")


@dataclass(frozen=True)
class _RetrievalOutcome:
    sources: tuple[ContextSource, ...]
    report: ContextProviderReport


class ContextBroker:
    def __init__(
        self,
        repository: Path,
        *,
        runtime_graph: Path | None = None,
        vault: Path | None = None,
        qmd_index: str = "obsidian-mind",
        budget: ContextBudget | None = None,
    ) -> None:
        self.repository = repository.expanduser().resolve()
        self.code_graph = self.repository / "graphify-out" / "graph.json"
        self.runtime_graph = (
            runtime_graph.expanduser().resolve()
            if runtime_graph is not None
            else self.repository / ".fetech" / "runtime-graphify" / "graph.json"
        )
        self.vault = vault.expanduser().resolve() if vault else None
        self.qmd_index = qmd_index
        self.budget = budget or ContextBudget()

    async def search(self, question: str, *, token_budget: int | None = None) -> ContextBundle:
        _validate_question(question)
        if token_budget is not None and (
            isinstance(token_budget, bool) or not isinstance(token_budget, int) or token_budget <= 0
        ):
            raise ValueError("context token budget must be a positive integer")
        limit = min(
            self.budget.total_tokens if token_budget is None else token_budget,
            self.budget.hard_ceiling,
        )
        needs = classify_context_needs(question)
        code_requested = ContextNeed.CODE_ARCHITECTURE in needs
        runtime_requested = ContextNeed.RUNTIME_HISTORY in needs
        qmd_requested = ContextNeed.DECISION_HISTORY in needs

        source_limit = min(self.budget.source_tokens, limit // 2) if code_requested else 0
        primary_limit = max(0, limit - source_limit)
        graph_count = int(code_requested) + int(runtime_requested)
        graph_total = min(self.budget.graphify_tokens, primary_limit) if graph_count else 0
        qmd_limit = (
            min(self.budget.qmd_tokens, max(0, primary_limit - graph_total))
            if qmd_requested
            else 0
        )
        graph_limits = _split_budget(graph_total, graph_count)
        graph_limit_index = 0

        tasks: dict[ProviderName, asyncio.Task[_RetrievalOutcome]] = {}
        if code_requested:
            tasks["code_graph"] = asyncio.create_task(
                self._retrieve_graph(
                    question,
                    graph_limits[graph_limit_index],
                    provider="code_graph",
                    graph=self.code_graph,
                )
            )
            graph_limit_index += 1
        if runtime_requested:
            tasks["runtime_graph"] = asyncio.create_task(
                self._retrieve_graph(
                    question,
                    graph_limits[graph_limit_index],
                    provider="runtime_graph",
                    graph=self.runtime_graph,
                )
            )
        if qmd_requested:
            tasks["qmd"] = asyncio.create_task(self._retrieve_qmd(question, qmd_limit))

        outcomes: dict[ProviderName, _RetrievalOutcome] = {
            "code_graph": _skipped("code_graph", "not selected for this question"),
            "runtime_graph": _skipped("runtime_graph", "not selected for this question"),
            "qmd": _skipped("qmd", "not selected for this question"),
            "exact_source": _skipped("exact_source", "no source verification was required"),
        }
        if tasks:
            completed = await asyncio.gather(*tasks.values())
            outcomes.update(dict(zip(tasks, completed, strict=True)))

        fallback_reason: str | None = None
        primary_sources = [
            source
            for provider in ("code_graph", "runtime_graph", "qmd")
            for source in outcomes[provider].sources
        ]
        simplified = " ".join(_terms(question)[:6])
        if not primary_sources and simplified and simplified != question:
            retry_tasks: dict[ProviderName, asyncio.Task[_RetrievalOutcome]] = {}
            if outcomes["code_graph"].report.status == ContextProviderStatus.EMPTY:
                retry_tasks["code_graph"] = asyncio.create_task(
                    self._retrieve_graph(
                        simplified,
                        graph_limits[0],
                        provider="code_graph",
                        graph=self.code_graph,
                        attempts=2,
                    )
                )
            runtime_index = 1 if code_requested else 0
            if outcomes["runtime_graph"].report.status == ContextProviderStatus.EMPTY:
                retry_tasks["runtime_graph"] = asyncio.create_task(
                    self._retrieve_graph(
                        simplified,
                        graph_limits[runtime_index],
                        provider="runtime_graph",
                        graph=self.runtime_graph,
                        attempts=2,
                    )
                )
            if outcomes["qmd"].report.status == ContextProviderStatus.EMPTY:
                retry_tasks["qmd"] = asyncio.create_task(
                    self._retrieve_qmd(simplified, qmd_limit, attempts=2)
                )
            if retry_tasks:
                retried = await asyncio.gather(*retry_tasks.values())
                outcomes.update(dict(zip(retry_tasks, retried, strict=True)))
                fallback_reason = "simplified query after retrieval miss"

        qmd_sources = list(outcomes["qmd"].sources)
        omitted_results = max(0, len(qmd_sources) - self.budget.qmd_notes)
        qmd_sources = qmd_sources[: self.budget.qmd_notes]
        primary_candidates = [
            *outcomes["code_graph"].sources,
            *outcomes["runtime_graph"].sources,
            *qmd_sources,
        ]
        primary_sources = _deduplicate(primary_candidates)
        omitted_results += len(primary_candidates) - len(primary_sources)

        code_locations = tuple(
            location
            for source in outcomes["code_graph"].sources
            for location in source.source_locations
        )
        if code_requested and source_limit > 0 and code_locations:
            outcomes["exact_source"] = await self._retrieve_source_locations(
                code_locations,
                source_limit,
                verification_terms=_verification_terms(
                    question,
                    tuple(
                        node
                        for source in outcomes["code_graph"].sources
                        for node in source.graph_nodes
                    ),
                ),
                require_term_match=True,
            )
            if not outcomes["exact_source"].sources:
                outcomes["exact_source"] = await self._retrieve_exact_source(
                    question,
                    source_limit,
                )
                fallback_reason = fallback_reason or "exact source search after stale graph locations"
        elif code_requested and source_limit > 0:
            outcomes["exact_source"] = await self._retrieve_exact_source(question, source_limit)
            if not outcomes["code_graph"].sources:
                fallback_reason = fallback_reason or "exact source search after code graph miss"
        elif not primary_sources:
            fallback_limit = min(self.budget.source_tokens, limit)
            outcomes["exact_source"] = await self._retrieve_exact_source(question, fallback_limit)
            fallback_reason = fallback_reason or "exact source search after retrieval miss"

        exact_sources = list(outcomes["exact_source"].sources)
        primary_sources = _mark_verified_graph_sources(primary_sources, exact_sources)
        final_candidates = [*primary_sources, *exact_sources]
        sources = _deduplicate(final_candidates)
        omitted_results += len(final_candidates) - len(sources)
        estimated = sum(_estimate_tokens(source.excerpt) for source in sources)
        while sources and estimated > limit:
            sources.pop()
            omitted_results += 1
            estimated = sum(_estimate_tokens(source.excerpt) for source in sources)

        usage = _token_usage(sources)
        freshness_values = [source.freshness for source in sources if source.freshness is not None]
        reports = tuple(
            outcomes[provider].report
            for provider in ("code_graph", "runtime_graph", "qmd", "exact_source")
        )
        verified_count = sum(source.verified for source in sources)
        represented_planes = len({source.source_type for source in sources})
        confidence = min(
            1.0,
            (0.25 if sources else 0.0)
            + (0.2 if any(source.source_type.endswith("graph") for source in sources) else 0.0)
            + (0.25 if any(source.source_type == "exact_source" for source in sources) else 0.0)
            + (0.15 if verified_count else 0.0)
            + 0.1 * max(0, represented_planes - 1),
        )
        return ContextBundle(
            question=question,
            sources=tuple(sources),
            needs=needs,
            confidence=confidence,
            omitted_results=omitted_results,
            token_budget=limit,
            estimated_tokens=usage.total,
            fallback_reason=fallback_reason,
            provider_reports=reports,
            token_usage=usage,
            freshness=min(freshness_values) if freshness_values else None,
        )

    async def _graphify(self, question: str, token_limit: int) -> list[ContextSource]:
        """Compatibility wrapper for the repository architecture graph."""

        return list(
            (
                await self._retrieve_graph(
                    question,
                    token_limit,
                    provider="code_graph",
                    graph=self.code_graph,
                )
            ).sources
        )

    async def _retrieve_graph(
        self,
        question: str,
        token_limit: int,
        *,
        provider: Literal["code_graph", "runtime_graph"],
        graph: Path,
        attempts: int = 1,
    ) -> _RetrievalOutcome:
        if token_limit <= 0:
            return _skipped(provider, "no token budget was allocated")
        if not graph.is_file():
            return _outcome(provider, ContextProviderStatus.UNAVAILABLE, detail="graph file is unavailable")
        result = await _run(
            "graphify",
            "query",
            question,
            "--budget",
            str(token_limit),
            "--graph",
            str(graph),
            cwd=self.repository,
        )
        failure = _process_failure(provider, result, attempts=attempts)
        if failure is not None:
            return failure
        excerpt = _truncate(result.stdout.strip(), token_limit)
        if not excerpt:
            return _outcome(provider, ContextProviderStatus.EMPTY, attempts=attempts)
        nodes, paths, locations = _graph_selections(excerpt)
        title = (
            "Repository architecture graph"
            if provider == "code_graph"
            else "Runtime provenance graph"
        )
        source = _source(
            source_type=provider,
            title=title,
            locator=str(graph),
            excerpt=excerpt,
            score=1.0 if provider == "code_graph" else 0.95,
            freshness=_freshness(graph),
            provenance=("graphify query", f"{provider} projection"),
            source_locations=locations,
            graph_nodes=nodes,
            graph_paths=paths,
        )
        return _outcome(
            provider,
            ContextProviderStatus.SUCCEEDED,
            attempts=attempts,
            sources=(source,),
        )

    async def _qmd(self, question: str, token_limit: int) -> list[ContextSource]:
        """Compatibility wrapper for scoped QMD retrieval."""

        return list((await self._retrieve_qmd(question, token_limit)).sources)

    async def _retrieve_qmd(
        self,
        question: str,
        token_limit: int,
        *,
        attempts: int = 1,
    ) -> _RetrievalOutcome:
        if token_limit <= 0:
            return _skipped("qmd", "no token budget was allocated")
        if self.vault is None or not self.vault.is_dir():
            return _outcome("qmd", ContextProviderStatus.UNAVAILABLE, detail="vault is not configured")
        result = await _run(
            "qmd",
            "search",
            question,
            "--index",
            self.qmd_index,
            "--format",
            "json",
            "--full-path",
            "-n",
            str(min(_MAX_QMD_NOTES, self.budget.qmd_notes * 4)),
            cwd=self.repository,
        )
        failure = _process_failure("qmd", result, attempts=attempts)
        if failure is not None:
            return failure
        try:
            documents = json.loads(result.stdout)
        except json.JSONDecodeError:
            return _outcome(
                "qmd",
                ContextProviderStatus.FAILED,
                attempts=attempts,
                detail="provider returned invalid JSON",
            )
        if not isinstance(documents, list):
            return _outcome(
                "qmd",
                ContextProviderStatus.FAILED,
                attempts=attempts,
                detail="provider returned an invalid result shape",
            )
        sources: list[ContextSource] = []
        per_note_limit = max(1, token_limit // self.budget.qmd_notes)
        for document in documents:
            if not isinstance(document, dict):
                continue
            raw_locator = document.get("file")
            if not isinstance(raw_locator, str):
                continue
            locator_path = Path(raw_locator).expanduser()
            if not locator_path.is_absolute():
                locator_path = self.vault / locator_path
            locator_path = locator_path.resolve()
            if not locator_path.is_relative_to(self.vault):
                continue
            excerpt = _truncate(str(document.get("snippet", "")), per_note_limit)
            if not excerpt:
                continue
            try:
                score = max(0.0, float(document.get("score", 0.0)))
            except (TypeError, ValueError):
                score = 0.0
            sources.append(
                _source(
                    source_type="qmd",
                    title=str(document.get("title", "QMD result")),
                    locator=str(locator_path),
                    excerpt=excerpt,
                    score=score,
                    freshness=_freshness(locator_path),
                    provenance=("QMD lexical search",),
                )
            )
        status = ContextProviderStatus.SUCCEEDED if sources else ContextProviderStatus.EMPTY
        return _outcome("qmd", status, attempts=attempts, sources=tuple(sources))

    async def _exact_source(
        self, question: str, token_limit: int, *, exclude: set[str]
    ) -> list[ContextSource]:
        outcome = await self._retrieve_exact_source(question, token_limit)
        return [source for source in outcome.sources if source.locator not in exclude]

    async def _retrieve_exact_source(
        self,
        question: str,
        token_limit: int,
    ) -> _RetrievalOutcome:
        terms = _terms(question)
        if token_limit <= 0:
            return _skipped("exact_source", "no token budget was allocated")
        if not terms:
            return _outcome("exact_source", ContextProviderStatus.EMPTY, attempts=0)
        pattern = "|".join(re.escape(term) for term in terms[:8])
        result = await _run(
            "rg",
            "--json",
            "-n",
            "-i",
            "--glob",
            "!graphify-out/**",
            "--glob",
            "!.fetech/**",
            "--glob",
            "!.venv/**",
            "--glob",
            "!dist/**",
            "--glob",
            "!*.lock",
            "--max-filesize",
            str(_MAX_SOURCE_FILE_BYTES),
            pattern,
            ".",
            cwd=self.repository,
        )
        if result.returncode == 1:
            return _outcome("exact_source", ContextProviderStatus.EMPTY, attempts=1)
        failure = _process_failure("exact_source", result, attempts=1)
        if failure is not None:
            return failure
        matches: dict[str, tuple[float, int]] = {}
        order = 0
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                continue
            if record.get("type") != "match" or not isinstance(record.get("data"), dict):
                continue
            data = record["data"]
            path_data = data.get("path")
            line_number = data.get("line_number")
            if not isinstance(path_data, dict) or not isinstance(path_data.get("text"), str):
                continue
            if not isinstance(line_number, int) or line_number <= 0:
                continue
            location = f"{path_data['text']}:L{line_number}"
            line_data = data.get("lines")
            matched_text = (
                str(line_data.get("text", "")) if isinstance(line_data, dict) else ""
            )
            score = _term_relevance(matched_text, terms)
            previous = matches.get(location)
            if previous is None or score > previous[0]:
                matches[location] = (score, order)
            order += 1
        locations = [
            location
            for location, _ in sorted(
                matches.items(),
                key=lambda item: (-item[1][0], item[1][1], item[0]),
            )[:_MAX_SOURCE_MATCHES]
        ]
        return await self._retrieve_source_locations(locations, token_limit)

    async def _retrieve_source_locations(
        self,
        locations: tuple[str, ...] | list[str],
        token_limit: int,
        *,
        verification_terms: tuple[str, ...] = (),
        require_term_match: bool = False,
    ) -> _RetrievalOutcome:
        unique_locations = tuple(dict.fromkeys(locations))[:_MAX_SOURCE_LOCATIONS]
        if token_limit <= 0:
            return _skipped("exact_source", "no token budget was allocated")
        if not unique_locations:
            return _outcome("exact_source", ContextProviderStatus.EMPTY, attempts=1)
        per_source_limit = max(1, token_limit // len(unique_locations))
        sources: list[ContextSource] = []
        for location in unique_locations:
            parsed = _SOURCE_LOCATION_RE.fullmatch(location)
            if parsed is None:
                continue
            path = (self.repository / parsed.group("path")).resolve()
            if not _is_bounded_source_file(path, self.repository):
                continue
            line_number = int(parsed.group("line"))
            excerpt = _source_window(path, line_number, per_source_limit)
            if not excerpt or (
                require_term_match and not _contains_any_term(excerpt, verification_terms)
            ):
                continue
            relative = path.relative_to(self.repository).as_posix()
            canonical_location = f"{relative}:L{line_number}"
            sources.append(
                _source(
                    source_type="exact_source",
                    title=relative,
                    locator=canonical_location,
                    excerpt=excerpt,
                    score=1.1,
                    freshness=_freshness(path),
                    provenance=("exact source window", "repository-scoped path"),
                    source_locations=(canonical_location,),
                    verified=True,
                )
            )
        status = ContextProviderStatus.SUCCEEDED if sources else ContextProviderStatus.EMPTY
        return _outcome("exact_source", status, attempts=1, sources=tuple(sources))


@dataclass(frozen=True)
class _ProcessResult:
    returncode: int
    stdout: str
    stderr: str


async def _run(
    *arguments: str,
    cwd: Path,
    timeout_seconds: float = _CONTEXT_PROCESS_TIMEOUT_SECONDS,
    maximum_output_bytes: int = _CONTEXT_PROCESS_OUTPUT_BYTES,
) -> _ProcessResult:
    if timeout_seconds <= 0 or maximum_output_bytes <= 0:
        raise ValueError("context subprocess limits must be positive")
    try:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            cwd=cwd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError:
        return _ProcessResult(127, "", f"{arguments[0]} is not installed")
    stdout_task = asyncio.create_task(_read_stream_bounded(process.stdout, maximum_output_bytes))
    stderr_task = asyncio.create_task(_read_stream_bounded(process.stderr, maximum_output_bytes))
    try:
        async with asyncio.timeout(timeout_seconds):
            stdout, stderr = await asyncio.gather(stdout_task, stderr_task)
            await process.wait()
    except TimeoutError:
        await _stop_process(process, stdout_task, stderr_task)
        return _ProcessResult(124, "", "context subprocess timed out")
    except _ContextOutputLimitError:
        await _stop_process(process, stdout_task, stderr_task)
        return _ProcessResult(125, "", "context subprocess exceeded its output limit")
    except asyncio.CancelledError:
        await _stop_process(process, stdout_task, stderr_task)
        raise
    return _ProcessResult(
        process.returncode or 0,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
    )


class _ContextOutputLimitError(RuntimeError):
    pass


async def _read_stream_bounded(
    stream: asyncio.StreamReader | None,
    maximum_output_bytes: int,
) -> bytes:
    if stream is None:
        return b""
    chunks: list[bytes] = []
    size = 0
    while True:
        chunk = await stream.read(65_536)
        if not chunk:
            return b"".join(chunks)
        size += len(chunk)
        if size > maximum_output_bytes:
            raise _ContextOutputLimitError
        chunks.append(chunk)


async def _stop_process(
    process: asyncio.subprocess.Process,
    *tasks: asyncio.Task[bytes],
) -> None:
    for task in tasks:
        task.cancel()
    if process.returncode is None:
        with suppress(ProcessLookupError):
            process.kill()
    await asyncio.gather(*tasks, return_exceptions=True)
    await process.wait()


def classify_context_needs(question: str) -> tuple[ContextNeed, ...]:
    """Classify a question without a model or external state."""

    _validate_question(question)
    words = {term.lower() for term in _terms(question)}
    selected: set[ContextNeed] = set()
    if words & _CODE_SIGNALS:
        selected.add(ContextNeed.CODE_ARCHITECTURE)
    if words & _RUNTIME_SIGNALS or _UUID_RE.search(question):
        selected.add(ContextNeed.RUNTIME_HISTORY)
    if words & _DECISION_SIGNALS:
        selected.add(ContextNeed.DECISION_HISTORY)
    if not selected:
        selected.update((ContextNeed.CODE_ARCHITECTURE, ContextNeed.DECISION_HISTORY))
    return tuple(need for need in ContextNeed if need in selected)


def _validate_question(question: str) -> None:
    if not isinstance(question, str):
        raise ValueError("context question must be text")
    if len(question) > _MAX_QUESTION_BYTES or len(question.encode("utf-8")) > _MAX_QUESTION_BYTES:
        raise ValueError("context question exceeds the bounded byte limit")
    if not question.strip():
        raise ValueError("context question cannot be blank")


def _split_budget(total: int, count: int) -> tuple[int, ...]:
    if count <= 0:
        return ()
    base, remainder = divmod(total, count)
    return tuple(base + int(index < remainder) for index in range(count))


def _terms(question: str) -> list[str]:
    ignored = {
        "about",
        "from",
        "have",
        "into",
        "that",
        "the",
        "this",
        "what",
        "when",
        "where",
        "which",
        "with",
    }
    return [
        word
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_-]{2,}", question)
        if word.lower() not in ignored
    ]


def _truncate(text: str, token_limit: int) -> str:
    return text[: max(0, token_limit * 4)]


def _estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4) if text else 0


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _freshness(path: Path) -> datetime | None:
    try:
        return datetime.fromtimestamp(path.stat().st_mtime, tz=UTC)
    except OSError:
        return None


def _is_bounded_source_file(path: Path, repository: Path) -> bool:
    try:
        return (
            path.is_relative_to(repository)
            and path.is_file()
            and path.stat().st_size <= _MAX_SOURCE_FILE_BYTES
        )
    except OSError:
        return False


def _source(
    *,
    source_type: str,
    title: str,
    locator: str,
    excerpt: str,
    score: float,
    freshness: datetime | None,
    provenance: tuple[str, ...],
    source_locations: tuple[str, ...] = (),
    graph_nodes: tuple[str, ...] = (),
    graph_paths: tuple[str, ...] = (),
    verified: bool = False,
) -> ContextSource:
    return ContextSource(
        source_type=source_type,
        title=title,
        locator=locator,
        excerpt=excerpt,
        score=score,
        freshness=freshness,
        provenance=provenance,
        content_sha256=_digest(excerpt),
        source_locations=source_locations,
        graph_nodes=graph_nodes,
        graph_paths=graph_paths,
        verified=verified,
    )


def _graph_selections(excerpt: str) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]]:
    nodes: list[str] = []
    paths: list[str] = []
    locations: list[str] = []
    for line in excerpt.splitlines():
        node = _GRAPH_NODE_RE.fullmatch(line)
        if node is not None:
            label = node.group("label")
            if label not in nodes and len(nodes) < _MAX_GRAPH_NODES:
                nodes.append(label)
            source = node.group("src")
            location = node.group("loc")
            if location:
                combined = (
                    location
                    if location.startswith("ledger://") or not source
                    else f"{source}:{location}"
                )
                if combined not in locations and len(locations) < _MAX_SOURCE_LOCATIONS:
                    locations.append(combined)
            continue
        edge = _GRAPH_EDGE_RE.fullmatch(line)
        if edge is not None and len(paths) < _MAX_GRAPH_PATHS:
            path = edge.group("edge")
            if path not in paths:
                paths.append(path)
    return tuple(nodes), tuple(paths), tuple(locations)


def _source_window(path: Path, line_number: int, token_limit: int) -> str:
    start = max(1, line_number - 2)
    stop = line_number + 2
    selected: list[str] = []
    try:
        with path.open("r", encoding="utf-8", errors="replace") as handle:
            for current, line in enumerate(handle, start=1):
                if current < start:
                    continue
                if current > stop:
                    break
                selected.append(f"{current}: {line.rstrip()}")
    except OSError:
        return ""
    return _truncate("\n".join(selected), token_limit)


def _contains_any_term(text: str, terms: tuple[str, ...]) -> bool:
    lowered = text.casefold()
    return any(len(term) >= 3 and term.casefold() in lowered for term in terms)


def _verification_terms(question: str, graph_nodes: tuple[str, ...]) -> tuple[str, ...]:
    candidates = [*_terms(question)]
    for node in graph_nodes:
        candidates.extend(_terms(node))
    return tuple(
        dict.fromkeys(
            term
            for term in candidates
            if len(term) >= 3 and term.casefold() not in _GENERIC_VERIFICATION_TERMS
        )
    )


def _term_relevance(text: str, terms: list[str]) -> float:
    lowered = text.casefold()
    score = 0.0
    for term in dict.fromkeys(terms):
        if term.casefold() not in lowered:
            continue
        score += 1.0 + min(len(term), 32) / 8
        if any(character.isupper() for character in term) and term in text:
            score += 3.0
    return score


def _outcome(
    provider: ProviderName,
    status: ContextProviderStatus,
    *,
    attempts: int = 0,
    sources: tuple[ContextSource, ...] = (),
    detail: str | None = None,
) -> _RetrievalOutcome:
    return _RetrievalOutcome(
        sources=sources,
        report=ContextProviderReport(
            provider=provider,
            status=status,
            attempts=attempts,
            result_count=len(sources),
            detail=detail,
        ),
    )


def _skipped(provider: ProviderName, detail: str) -> _RetrievalOutcome:
    return _outcome(provider, ContextProviderStatus.SKIPPED, detail=detail)


def _process_failure(
    provider: ProviderName,
    result: _ProcessResult,
    *,
    attempts: int,
) -> _RetrievalOutcome | None:
    if result.returncode == 0:
        return None
    if result.returncode == 127:
        status = ContextProviderStatus.UNAVAILABLE
        detail = "provider executable is unavailable"
    elif result.returncode == 124:
        status = ContextProviderStatus.TIMED_OUT
        detail = "provider exceeded its time limit"
    elif result.returncode == 125:
        status = ContextProviderStatus.OUTPUT_LIMIT
        detail = "provider exceeded its output limit"
    else:
        status = ContextProviderStatus.FAILED
        detail = "provider returned a non-zero status"
    return _outcome(provider, status, attempts=attempts, detail=detail)


def _deduplicate(sources: list[ContextSource]) -> list[ContextSource]:
    seen: set[tuple[str, str]] = set()
    result: list[ContextSource] = []
    for source in sorted(sources, key=lambda item: item.score, reverse=True):
        digest = source.content_sha256 or _digest(source.excerpt)
        key = (source.locator, digest)
        if key not in seen:
            seen.add(key)
            result.append(source)
    return result


def _mark_verified_graph_sources(
    sources: list[ContextSource],
    exact_sources: list[ContextSource],
) -> list[ContextSource]:
    verified_locations = {
        location for source in exact_sources for location in source.source_locations
    }
    result: list[ContextSource] = []
    for source in sources:
        if source.source_type == "code_graph" and verified_locations.intersection(
            source.source_locations
        ):
            source = source.model_copy(
                update={
                    "verified": True,
                    "provenance": (*source.provenance, "confirmed in exact source"),
                }
            )
        result.append(source)
    return result


def _token_usage(sources: list[ContextSource]) -> ContextTokenUsage:
    totals = {
        "code_graph": 0,
        "runtime_graph": 0,
        "qmd": 0,
        "exact_source": 0,
    }
    for source in sources:
        if source.source_type in totals:
            totals[source.source_type] += _estimate_tokens(source.excerpt)
    total = sum(totals.values())
    return ContextTokenUsage(**totals, total=total)
