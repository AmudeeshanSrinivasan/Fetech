"""Bounded context broker for Graphify, QMD, and exact source evidence."""

from __future__ import annotations

import asyncio
import json
import re
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from fetech.models import ContextBundle, ContextSource

_MAX_QUESTION_BYTES = 16_384
_MAX_QMD_NOTES = 100
_CONTEXT_PROCESS_TIMEOUT_SECONDS = 15.0
_CONTEXT_PROCESS_OUTPUT_BYTES = 2_000_000


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


class ContextBroker:
    def __init__(
        self,
        repository: Path,
        *,
        vault: Path | None = None,
        qmd_index: str = "obsidian-mind",
        budget: ContextBudget | None = None,
    ) -> None:
        self.repository = repository.expanduser().resolve()
        self.vault = vault.expanduser().resolve() if vault else None
        self.qmd_index = qmd_index
        self.budget = budget or ContextBudget()

    async def search(self, question: str, *, token_budget: int | None = None) -> ContextBundle:
        if not isinstance(question, str):
            raise ValueError("context question must be text")
        if len(question) > _MAX_QUESTION_BYTES or len(question.encode("utf-8")) > _MAX_QUESTION_BYTES:
            raise ValueError("context question exceeds the bounded byte limit")
        if not question.strip():
            raise ValueError("context question cannot be blank")
        if token_budget is not None and (
            isinstance(token_budget, bool) or not isinstance(token_budget, int) or token_budget <= 0
        ):
            raise ValueError("context token budget must be a positive integer")
        limit = min(
            self.budget.total_tokens if token_budget is None else token_budget,
            self.budget.hard_ceiling,
        )
        graph_limit = min(self.budget.graphify_tokens, limit)
        qmd_limit = min(self.budget.qmd_tokens, max(0, limit - graph_limit))
        source_limit = max(0, limit - graph_limit - qmd_limit)
        graph_task = asyncio.create_task(self._graphify(question, graph_limit))
        qmd_task = asyncio.create_task(self._qmd(question, qmd_limit))
        graph_sources, qmd_sources = await asyncio.gather(graph_task, qmd_task)
        omitted_results = max(0, len(qmd_sources) - self.budget.qmd_notes)
        qmd_sources = qmd_sources[: self.budget.qmd_notes]
        candidates = [*graph_sources, *qmd_sources]
        sources = _deduplicate(candidates)
        omitted_results += len(candidates) - len(sources)
        fallback_reason: str | None = None
        if not sources:
            simplified = " ".join(_terms(question)[:6])
            if simplified and simplified != question:
                retry_graph, retry_qmd = await asyncio.gather(
                    self._graphify(simplified, graph_limit), self._qmd(simplified, qmd_limit)
                )
                omitted_results += max(0, len(retry_qmd) - self.budget.qmd_notes)
                retry_candidates = [
                    *retry_graph,
                    *retry_qmd[: self.budget.qmd_notes],
                ]
                sources = _deduplicate(retry_candidates)
                omitted_results += len(retry_candidates) - len(sources)
                fallback_reason = "simplified query after retrieval miss"
        exact_sources = await self._exact_source(
            question, source_limit, exclude={source.locator for source in sources}
        )
        final_candidates = [*sources, *exact_sources]
        sources = _deduplicate(final_candidates)
        omitted_results += len(final_candidates) - len(sources)
        estimated = sum(_estimate_tokens(source.excerpt) for source in sources)
        while sources and estimated > limit:
            sources.pop()
            omitted_results += 1
            estimated = sum(_estimate_tokens(source.excerpt) for source in sources)
        return ContextBundle(
            question=question,
            sources=tuple(sources),
            confidence=min(1.0, 0.35 * len(sources)),
            omitted_results=omitted_results,
            token_budget=limit,
            estimated_tokens=estimated,
            fallback_reason=fallback_reason,
        )

    async def _graphify(self, question: str, token_limit: int) -> list[ContextSource]:
        if token_limit <= 0 or not (self.repository / "graphify-out" / "graph.json").exists():
            return []
        result = await _run(
            "graphify",
            "query",
            question,
            "--budget",
            str(token_limit),
            "--graph",
            str(self.repository / "graphify-out" / "graph.json"),
            cwd=self.repository,
        )
        if result.returncode != 0 or not result.stdout.strip():
            return []
        excerpt = _truncate(result.stdout.strip(), token_limit)
        return [
            ContextSource(
                source_type="graphify",
                title="Repository architecture graph",
                locator=str(self.repository / "graphify-out" / "graph.json"),
                excerpt=excerpt,
                score=1.0,
                provenance=("graphify query",),
            )
        ]

    async def _qmd(self, question: str, token_limit: int) -> list[ContextSource]:
        if token_limit <= 0 or self.vault is None or not self.vault.is_dir():
            return []
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
        if result.returncode != 0:
            return []
        try:
            documents = json.loads(result.stdout)
        except json.JSONDecodeError:
            return []
        sources: list[ContextSource] = []
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
            excerpt = _truncate(str(document.get("snippet", "")), token_limit // self.budget.qmd_notes)
            sources.append(
                ContextSource(
                    source_type="obsidian",
                    title=str(document.get("title", "QMD result")),
                    locator=str(locator_path),
                    excerpt=excerpt,
                    score=float(document.get("score", 0.0)),
                    provenance=("QMD search",),
                )
            )
        return sources

    async def _exact_source(
        self, question: str, token_limit: int, *, exclude: set[str]
    ) -> list[ContextSource]:
        terms = _terms(question)
        if token_limit <= 0 or not terms:
            return []
        pattern = "|".join(re.escape(term) for term in terms[:8])
        result = await _run(
            "rg",
            "-n",
            "-i",
            "--glob",
            "!graphify-out/**",
            "--glob",
            "!*.lock",
            pattern,
            str(self.repository),
            cwd=self.repository,
        )
        if result.returncode not in {0, 1}:
            return []
        lines = result.stdout.splitlines()[:12]
        excerpt = _truncate("\n".join(lines), token_limit)
        if not excerpt:
            return []
        locator = str(self.repository)
        if locator in exclude:
            return []
        return [
            ContextSource(
                source_type="source",
                title="Exact repository matches",
                locator=locator,
                excerpt=excerpt,
                score=0.7,
                provenance=("rg exact search",),
            )
        ]


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
    return _ProcessResult(
        process.returncode or 0, stdout.decode(errors="replace"), stderr.decode(errors="replace")
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
        word for word in re.findall(r"[A-Za-z_][A-Za-z0-9_-]{2,}", question) if word.lower() not in ignored
    ]


def _truncate(text: str, token_limit: int) -> str:
    return text[: max(0, token_limit * 4)]


def _estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def _deduplicate(sources: list[ContextSource]) -> list[ContextSource]:
    seen: set[tuple[str, str]] = set()
    result: list[ContextSource] = []
    for source in sorted(sources, key=lambda item: item.score, reverse=True):
        key = (source.locator, source.excerpt)
        if key not in seen:
            seen.add(key)
            result.append(source)
    return result
