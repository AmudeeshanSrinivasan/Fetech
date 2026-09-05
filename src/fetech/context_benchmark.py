"""Deterministic evaluation harness for bounded context retrieval.

The benchmark measures retrieval and evidence properties only. Answer correctness is
accepted exclusively from a separate, complete evaluation file so the harness never
turns evidence recall into a fabricated answer-quality score.
"""

from __future__ import annotations

import asyncio
import fnmatch
import hashlib
import json
import re
import statistics
import subprocess
from collections.abc import Sequence
from pathlib import Path
from typing import Final, Literal, Protocol

import yaml
from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from fetech.context import classify_context_needs
from fetech.models import ContextBundle, ContextNeed, ContextSource

_MAX_TRACKED_FILE_BYTES = 5_000_000
_MAX_TRACKED_FILES = 20_000
_MAX_CORPUS_BYTES = 100_000_000
_WORD_RE = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_'-]*")
_SOURCE_LINE_RE = re.compile(r":L\d+(?:-L\d+)?$")
INDEPENDENT_REVIEW_ATTESTATION: Final[
    Literal[
        "I independently judged both blinded answers without knowing which source produced them."
    ]
] = (
    "I independently judged both blinded answers without knowing which source produced them."
)


class ContextBenchmarkError(ValueError):
    """Raised when benchmark inputs or evidence violate the bounded contract."""


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class EvidenceExpectation(_FrozenModel):
    id: str = Field(pattern=r"^[a-z0-9][a-z0-9_-]{1,63}$")
    source_type: Literal["code_graph", "runtime_graph", "qmd", "exact_source"]
    locator: str | None = Field(default=None, min_length=1, max_length=512)
    any_terms: tuple[str, ...] = Field(default=(), max_length=12)

    @model_validator(mode="after")
    def require_locator_or_terms(self) -> EvidenceExpectation:
        if self.locator is None and not self.any_terms:
            raise ValueError("an evidence expectation needs a locator or search term")
        if any(not term.strip() or len(term) > 128 for term in self.any_terms):
            raise ValueError("evidence terms must be non-empty and at most 128 characters")
        return self


class ContextBenchmarkTask(_FrozenModel):
    id: str = Field(pattern=r"^CTX-[A-Z]+-[0-9]{3}$")
    question: str = Field(min_length=1, max_length=16_384)
    expected_needs: tuple[ContextNeed, ...] = Field(min_length=1, max_length=3)
    evidence: tuple[EvidenceExpectation, ...] = Field(min_length=1, max_length=8)
    baseline_files: tuple[str, ...] = Field(min_length=1, max_length=24)

    @model_validator(mode="after")
    def require_unique_ordered_values(self) -> ContextBenchmarkTask:
        canonical = tuple(need for need in ContextNeed if need in self.expected_needs)
        if self.expected_needs != canonical:
            raise ValueError("expected context needs must be unique and in canonical order")
        evidence_ids = [item.id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence expectation IDs must be unique within a task")
        if len(set(self.baseline_files)) != len(self.baseline_files):
            raise ValueError("baseline files must be unique within a task")
        for value in self.baseline_files:
            path = Path(value)
            if (
                path.is_absolute() or path.as_posix() != value
                or any(part in {".", ".."} for part in value.split("/"))
                or "\\" in value or not value or any(c in value for c in "*?[]\0")
            ):
                raise ValueError("baseline files must be canonical repository-relative file paths")
        for item in self.evidence:
            if item.source_type == "exact_source" and item.locator not in self.baseline_files:
                raise ValueError("baseline files must retain every expected exact-source document")
        return self


class ContextBenchmarkTargets(_FrozenModel):
    minimum_tasks: int = Field(default=100, ge=100, le=1_000)
    minimum_repository_words: int = Field(default=5_000, ge=5_000)
    minimum_median_token_reduction_percent: float = Field(default=70.0, ge=0, le=100)
    maximum_bundle_tokens: int = Field(default=4_000, ge=1, le=8_000)
    minimum_relevant_evidence_recall_percent: float = Field(default=95.0, ge=0, le=100)
    maximum_answer_correctness_drop_points: float = Field(default=2.0, ge=0, le=100)
    minimum_lineage_coverage_percent: float = Field(default=100.0, ge=0, le=100)
    maximum_full_vault_loads: int = Field(default=0, ge=0)
    maximum_qmd_notes_per_bundle: int = Field(default=3, ge=1, le=100)


class ContextBenchmarkSuite(_FrozenModel):
    schema_version: Literal["2.0"] = "2.0"
    name: str = Field(min_length=1, max_length=128)
    default_token_budget: int = Field(default=4_000, ge=1, le=8_000)
    maximum_baseline_tokens: int = Field(default=100_000, ge=1, le=100_000)
    targets: ContextBenchmarkTargets
    baseline_globs: dict[ContextNeed, tuple[str, ...]]
    tasks: tuple[ContextBenchmarkTask, ...]

    @model_validator(mode="after")
    def require_complete_suite(self) -> ContextBenchmarkSuite:
        if len(self.tasks) < self.targets.minimum_tasks:
            raise ValueError(
                f"benchmark needs at least {self.targets.minimum_tasks} tasks; "
                f"found {len(self.tasks)}"
            )
        identifiers = [task.id for task in self.tasks]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("benchmark task IDs must be unique")
        questions = [task.question.casefold().strip() for task in self.tasks]
        if len(questions) != len(set(questions)):
            raise ValueError("benchmark questions must be unique")
        missing_profiles = set(ContextNeed).difference(self.baseline_globs)
        if missing_profiles:
            raise ValueError(f"baseline globs missing profiles: {sorted(missing_profiles)}")
        for profile, patterns in self.baseline_globs.items():
            if not patterns or any(not pattern.strip() for pattern in patterns):
                raise ValueError(f"baseline profile {profile} must contain non-empty globs")
        for task in self.tasks:
            classified = classify_context_needs(task.question)
            if classified != task.expected_needs:
                raise ValueError(
                    f"task {task.id} expects {task.expected_needs} but classifies as {classified}"
                )
        return self


class AnswerEvaluation(_FrozenModel):
    task_id: str = Field(pattern=r"^CTX-[A-Z]+-[0-9]{3}$")
    full_context_correct: StrictBool
    broker_correct: StrictBool


class AnswerEvaluationSet(_FrozenModel):
    schema_version: Literal["2.0"] = "2.0"
    evaluator: str = Field(min_length=1, max_length=128)
    independence_attestation: Literal[
        "I independently judged both blinded answers without knowing which source produced them."
    ]
    answer_producer: str = Field(min_length=1, max_length=128)
    generation_protocol_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    suite_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    review_packet_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evaluations: tuple[AnswerEvaluation, ...]

    @model_validator(mode="after")
    def reject_duplicates(self) -> AnswerEvaluationSet:
        identifiers = [item.task_id for item in self.evaluations]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("answer evaluation task IDs must be unique")
        return self


class BenchmarkGate(_FrozenModel):
    status: Literal["PASSED", "FAILED", "NOT_MEASURED"]
    observed: int | float | bool | None
    target: str


class BenchmarkTaskResult(_FrozenModel):
    task_id: str
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    expected_needs: tuple[ContextNeed, ...]
    observed_needs: tuple[ContextNeed, ...]
    baseline_tokens: int = Field(ge=1)
    baseline_files: tuple[str, ...]
    baseline_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    broker_tokens: int = Field(ge=0)
    token_usage: dict[str, int]
    token_reduction_percent: float
    expected_evidence_count: int = Field(ge=1)
    matched_evidence_ids: tuple[str, ...]
    evidence_recall_percent: float = Field(ge=0, le=100)
    lineage_complete: bool
    qmd_notes: int = Field(ge=0)
    full_vault_load_observed: bool
    omitted_results: int = Field(ge=0)
    fallback_reason: str | None
    provider_statuses: dict[str, str]
    full_context_correct: bool | None = None
    broker_correct: bool | None = None


class BenchmarkMetrics(_FrozenModel):
    task_count: int = Field(ge=0)
    repository_word_count: int = Field(ge=0)
    baseline_file_count: int = Field(ge=0)
    median_full_context_tokens: float = Field(ge=0)
    median_broker_tokens: float = Field(ge=0)
    maximum_broker_tokens: int = Field(ge=0)
    median_token_reduction_percent: float
    relevant_evidence_recall_percent: float = Field(ge=0, le=100)
    routing_accuracy_percent: float = Field(ge=0, le=100)
    lineage_coverage_percent: float = Field(ge=0, le=100)
    full_vault_loads_observed: int = Field(ge=0)
    omitted_results_total: int = Field(ge=0)
    fallback_task_count: int = Field(ge=0)
    full_context_answer_correctness_percent: float | None = Field(default=None, ge=0, le=100)
    broker_answer_correctness_percent: float | None = Field(default=None, ge=0, le=100)
    answer_correctness_drop_points: float | None = None


class ContextBenchmarkReport(_FrozenModel):
    schema_version: Literal["1.0"] = "1.0"
    suite_name: str
    baseline_method: Literal["curated-task-full-documents-v2"] = "curated-task-full-documents-v2"
    baseline_limitations: tuple[str, ...] = (
        "Task document selection is curated, not an unrestricted repository baseline.",
        "Runtime and decision baselines are repository proxies; matching snapshots are still required.",
        "Token counts are estimates; verify the selected model tokenizer before generation.",
    )
    suite_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_commit: str | None = Field(default=None, pattern=r"^[0-9a-f]{40}$")
    source_dirty: bool
    answer_evaluator: str | None = None
    answer_producer: str | None = None
    answer_generation_protocol_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    answer_review_packet_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    answer_evaluation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    status: Literal["PASSED", "FAILED", "INCOMPLETE"]
    metrics: BenchmarkMetrics
    gates: dict[str, BenchmarkGate]
    tasks: tuple[BenchmarkTaskResult, ...]


class ContextSearch(Protocol):
    async def search(self, question: str, *, token_budget: int | None = None) -> ContextBundle: ...


class _BaselineCorpus(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)

    paths_by_need: dict[ContextNeed, frozenset[Path]]
    tokens_by_path: dict[Path, int]
    contexts_by_task: dict[str, str]
    repository_word_count: int
    baseline_file_count: int


def load_benchmark_suite(path: Path) -> ContextBenchmarkSuite:
    """Load and strictly validate a bounded YAML benchmark suite."""

    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, yaml.YAMLError) as exc:
        raise ContextBenchmarkError("unable to read the context benchmark suite") from exc
    try:
        return ContextBenchmarkSuite.model_validate(raw)
    except ValueError as exc:
        raise ContextBenchmarkError(str(exc)) from exc


def load_answer_evaluations(path: Path) -> AnswerEvaluationSet:
    """Load independent answer outcomes without accepting prompts or answer text."""

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ContextBenchmarkError("unable to read answer evaluations") from exc
    try:
        return AnswerEvaluationSet.model_validate(raw)
    except ValueError as exc:
        raise ContextBenchmarkError(str(exc)) from exc


def validate_benchmark_environment(
    repository: Path,
    suite: ContextBenchmarkSuite,
) -> dict[str, int]:
    """Validate task cardinality, routing, and the tracked full-context corpus."""

    corpus = _build_baseline_corpus(repository, suite)
    return {
        "task_count": len(suite.tasks),
        "repository_word_count": corpus.repository_word_count,
        "baseline_file_count": corpus.baseline_file_count,
        "maximum_task_baseline_tokens": max(
            _estimate_tokens(context) for context in corpus.contexts_by_task.values()
        ),
    }


async def run_context_benchmark(
    broker: ContextSearch,
    repository: Path,
    suite: ContextBenchmarkSuite,
    *,
    answer_evaluations: AnswerEvaluationSet | None = None,
    concurrency: int = 4,
    suite_bytes: bytes | None = None,
) -> ContextBenchmarkReport:
    """Run bounded broker retrieval and compute the acceptance metrics."""

    if isinstance(concurrency, bool) or not 1 <= concurrency <= 16:
        raise ContextBenchmarkError("benchmark concurrency must be from 1 to 16")
    resolved_repository = repository.expanduser().resolve()
    serialized_suite = suite_bytes or yaml.safe_dump(
        suite.model_dump(mode="json"), sort_keys=True
    ).encode("utf-8")
    suite_sha256 = hashlib.sha256(serialized_suite).hexdigest()
    identity = benchmark_source_identity(resolved_repository)
    if answer_evaluations is not None:
        if answer_evaluations.suite_sha256 != suite_sha256:
            raise ContextBenchmarkError("answer evaluations do not match the benchmark suite")
        if identity[0] is None or answer_evaluations.source_commit != identity[0]:
            raise ContextBenchmarkError("answer evaluations do not match the source commit")
    corpus = _build_baseline_corpus(resolved_repository, suite)
    evaluations = _evaluation_map(suite, answer_evaluations)
    semaphore = asyncio.Semaphore(concurrency)

    async def evaluate(task: ContextBenchmarkTask) -> BenchmarkTaskResult:
        async with semaphore:
            bundle = await broker.search(task.question, token_budget=suite.default_token_budget)
        if bundle.estimated_tokens != bundle.token_usage.total:
            raise ContextBenchmarkError(
                f"task {task.id} returned inconsistent context token accounting"
            )
        baseline_context = corpus.contexts_by_task[task.id]
        baseline_tokens = _estimate_tokens(baseline_context)
        matched = tuple(
            expectation.id
            for expectation in task.evidence
            if _expectation_matches(expectation, bundle.sources, resolved_repository)
        )
        recall = 100.0 * len(matched) / len(task.evidence)
        reduction = 100.0 * (1.0 - bundle.estimated_tokens / baseline_tokens)
        qmd_notes = sum(source.source_type == "qmd" for source in bundle.sources)
        full_vault_load = qmd_notes > suite.targets.maximum_qmd_notes_per_bundle
        evaluation = evaluations.get(task.id)
        return BenchmarkTaskResult(
            task_id=task.id,
            question_sha256=hashlib.sha256(task.question.encode("utf-8")).hexdigest(),
            expected_needs=task.expected_needs,
            observed_needs=bundle.needs,
            baseline_tokens=baseline_tokens,
            baseline_files=task.baseline_files,
            baseline_sha256=hashlib.sha256(baseline_context.encode("utf-8")).hexdigest(),
            broker_tokens=bundle.estimated_tokens,
            token_usage={
                "code_graph": bundle.token_usage.code_graph,
                "runtime_graph": bundle.token_usage.runtime_graph,
                "qmd": bundle.token_usage.qmd,
                "exact_source": bundle.token_usage.exact_source,
                "total": bundle.token_usage.total,
            },
            token_reduction_percent=round(reduction, 4),
            expected_evidence_count=len(task.evidence),
            matched_evidence_ids=matched,
            evidence_recall_percent=round(recall, 4),
            lineage_complete=_lineage_complete(bundle.sources),
            qmd_notes=qmd_notes,
            full_vault_load_observed=full_vault_load,
            omitted_results=bundle.omitted_results,
            fallback_reason=bundle.fallback_reason,
            provider_statuses={
                report.provider: report.status.value for report in bundle.provider_reports
            },
            full_context_correct=(evaluation.full_context_correct if evaluation else None),
            broker_correct=(evaluation.broker_correct if evaluation else None),
        )

    task_results = tuple(await asyncio.gather(*(evaluate(task) for task in suite.tasks)))
    metrics = _metrics(task_results, corpus)
    gates = _gates(metrics, suite.targets, answer_evaluations is not None)
    if any(gate.status == "FAILED" for gate in gates.values()):
        status: Literal["PASSED", "FAILED", "INCOMPLETE"] = "FAILED"
    elif any(gate.status == "NOT_MEASURED" for gate in gates.values()):
        status = "INCOMPLETE"
    else:
        status = "PASSED"
    return ContextBenchmarkReport(
        suite_name=suite.name,
        suite_sha256=suite_sha256,
        source_commit=identity[0],
        source_dirty=identity[1],
        answer_evaluator=(answer_evaluations.evaluator if answer_evaluations else None),
        answer_producer=(answer_evaluations.answer_producer if answer_evaluations else None),
        answer_generation_protocol_sha256=(
            answer_evaluations.generation_protocol_sha256 if answer_evaluations else None
        ),
        answer_review_packet_sha256=(
            answer_evaluations.review_packet_sha256 if answer_evaluations else None
        ),
        answer_evaluation_sha256=(
            hashlib.sha256(
                answer_evaluations.model_dump_json().encode("utf-8")
            ).hexdigest()
            if answer_evaluations
            else None
        ),
        status=status,
        metrics=metrics,
        gates=gates,
        tasks=task_results,
    )


def render_benchmark_json(report: ContextBenchmarkReport) -> str:
    """Render stable machine-readable evidence without questions or answer text."""

    return report.model_dump_json(indent=2) + "\n"


def render_benchmark_markdown(report: ContextBenchmarkReport) -> str:
    """Render a bounded human summary of the benchmark evidence."""

    metrics = report.metrics
    lines = [
        f"# Context benchmark: {report.suite_name}",
        "",
        f"Status: **{report.status}**",
        "",
        "## Measurements",
        "",
        "| Metric | Observed |",
        "| --- | ---: |",
        f"| Tasks | {metrics.task_count} |",
        f"| Repository words | {metrics.repository_word_count} |",
        f"| Median full-context tokens | {metrics.median_full_context_tokens:.1f} |",
        f"| Median broker tokens | {metrics.median_broker_tokens:.1f} |",
        f"| Median token reduction | {metrics.median_token_reduction_percent:.2f}% |",
        f"| Relevant-evidence recall | {metrics.relevant_evidence_recall_percent:.2f}% |",
        f"| Routing accuracy | {metrics.routing_accuracy_percent:.2f}% |",
        f"| Lineage coverage | {metrics.lineage_coverage_percent:.2f}% |",
        f"| Full-vault loads observed | {metrics.full_vault_loads_observed} |",
        f"| Omitted candidates | {metrics.omitted_results_total} |",
        f"| Fallback tasks | {metrics.fallback_task_count} |",
        "",
        "## Gates",
        "",
        "| Gate | Status | Observed | Target |",
        "| --- | --- | ---: | --- |",
    ]
    for name, gate in report.gates.items():
        observed = "not measured" if gate.observed is None else str(gate.observed)
        lines.append(f"| `{name}` | {gate.status} | {observed} | {gate.target} |")
    failing = [
        task
        for task in report.tasks
        if task.evidence_recall_percent < 100
        or not task.lineage_complete
        or task.broker_tokens > 4_000
    ][:25]
    lines.extend(
        [
            "",
            "## Evidence boundary",
            "",
            "Questions and answer text are deliberately absent; task records contain only stable IDs and",
            "question SHA-256 values. Answer correctness remains `NOT_MEASURED` until a complete independent",
            "evaluation file supplies boolean full-context and broker outcomes for every task.",
            "",
            "The full-vault-load observation covers material returned in `ContextBundle`; it does not",
            "inspect a provider's private indexing implementation.",
        ]
    )
    lines.extend(["", "Baseline method: `" + report.baseline_method + "`.", ""])
    lines.extend(f"- {limitation}" for limitation in report.baseline_limitations)
    if failing:
        lines.extend(["", "## First failing task records", ""])
        for task in failing:
            lines.append(
                f"- `{task.task_id}`: recall {task.evidence_recall_percent:.2f}%, "
                f"tokens {task.broker_tokens}, lineage={str(task.lineage_complete).lower()}"
            )
    return "\n".join(lines) + "\n"


def write_benchmark_report(
    report: ContextBenchmarkReport,
    json_path: Path,
    markdown_path: Path | None = None,
) -> None:
    """Atomically write bounded benchmark evidence."""

    _atomic_write(json_path, render_benchmark_json(report))
    if markdown_path is not None:
        _atomic_write(markdown_path, render_benchmark_markdown(report))


def _build_baseline_corpus(
    repository: Path,
    suite: ContextBenchmarkSuite,
) -> _BaselineCorpus:
    repository = repository.expanduser().resolve()
    tracked = _tracked_paths(repository)
    tokens_by_path: dict[Path, int] = {}
    words_by_path: dict[Path, int] = {}
    text_by_path: dict[Path, str] = {}
    corpus_bytes = 0
    for relative in tracked:
        candidate = repository / relative
        if candidate.is_symlink():
            continue
        path = candidate.resolve()
        if not path.is_relative_to(repository) or not path.is_file():
            continue
        try:
            payload = path.read_bytes()
        except OSError:
            continue
        if len(payload) > _MAX_TRACKED_FILE_BYTES or b"\0" in payload:
            continue
        corpus_bytes += len(payload)
        if corpus_bytes > _MAX_CORPUS_BYTES:
            raise ContextBenchmarkError("tracked benchmark text exceeds the corpus byte limit")
        text = payload.decode("utf-8", errors="replace")
        tokens_by_path[path] = _estimate_tokens(text)
        text_by_path[path] = text
        words_by_path[path] = len(_WORD_RE.findall(text))

    paths_by_need: dict[ContextNeed, frozenset[Path]] = {}
    for need, patterns in suite.baseline_globs.items():
        selected = frozenset(
            (repository / relative).resolve()
            for relative in tracked
            if any(fnmatch.fnmatchcase(relative, pattern) for pattern in patterns)
            and (repository / relative).resolve() in tokens_by_path
        )
        if not selected:
            raise ContextBenchmarkError(f"baseline profile {need.value} selected no tracked text")
        paths_by_need[need] = selected
    contexts_by_task: dict[str, str] = {}
    selected_paths: set[Path] = set()
    for task in suite.tasks:
        allowed = frozenset(path for need in task.expected_needs for path in paths_by_need[need])
        documents: list[str] = []
        for relative in task.baseline_files:
            path = (repository / relative).resolve()
            if relative not in tracked or path not in allowed:
                raise ContextBenchmarkError(f"task {task.id} baseline document is unavailable: {relative}")
            selected_paths.add(path)
            documents.append(f"--- {relative} ---\n{text_by_path[path]}")
        context = "\n\n".join(documents)
        if _estimate_tokens(context) > suite.maximum_baseline_tokens:
            raise ContextBenchmarkError(f"task {task.id} exceeds the full-document baseline token limit")
        contexts_by_task[task.id] = context
    all_paths = frozenset(selected_paths)
    repository_words = sum(words_by_path[path] for path in all_paths)
    if repository_words < suite.targets.minimum_repository_words:
        raise ContextBenchmarkError(
            f"tracked benchmark corpus has {repository_words} words; "
            f"requires at least {suite.targets.minimum_repository_words}"
        )
    return _BaselineCorpus(
        paths_by_need=paths_by_need,
        tokens_by_path=tokens_by_path,
        contexts_by_task=contexts_by_task,
        repository_word_count=repository_words,
        baseline_file_count=len(all_paths),
    )


def build_task_baseline_contexts(
    repository: Path, suite: ContextBenchmarkSuite,
) -> dict[str, str]:
    """Return the exact complete documents measured by the curated baseline."""

    return _build_baseline_corpus(repository, suite).contexts_by_task


def _tracked_paths(repository: Path) -> tuple[str, ...]:
    try:
        completed = subprocess.run(
            ("git", "ls-files", "-z"),
            cwd=repository,
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ContextBenchmarkError("unable to enumerate tracked benchmark files") from exc
    if completed.returncode != 0:
        raise ContextBenchmarkError("benchmark repository must be a readable Git worktree")
    decoded = completed.stdout.decode("utf-8", errors="strict")
    paths = tuple(path for path in decoded.split("\0") if path and ".." not in Path(path).parts)
    if len(paths) > _MAX_TRACKED_FILES:
        raise ContextBenchmarkError("tracked benchmark corpus exceeds the file-count limit")
    return paths


def _evaluation_map(
    suite: ContextBenchmarkSuite,
    evaluations: AnswerEvaluationSet | None,
) -> dict[str, AnswerEvaluation]:
    if evaluations is None:
        return {}
    result = {item.task_id: item for item in evaluations.evaluations}
    expected = {task.id for task in suite.tasks}
    if set(result) != expected:
        missing = len(expected.difference(result))
        extra = len(set(result).difference(expected))
        raise ContextBenchmarkError(
            f"answer evaluations must cover the suite exactly (missing={missing}, extra={extra})"
        )
    return result


def _expectation_matches(
    expectation: EvidenceExpectation,
    sources: Sequence[ContextSource],
    repository: Path,
) -> bool:
    for source in sources:
        if source.source_type != expectation.source_type:
            continue
        locators = (source.locator, *source.source_locations)
        if expectation.locator is not None and not any(
            _locator_matches(expectation.locator, locator, repository) for locator in locators
        ):
            continue
        searchable = "\n".join(
            (source.title, source.excerpt, *source.graph_nodes, *source.graph_paths)
        ).casefold()
        if expectation.any_terms and not any(
            term.casefold() in searchable for term in expectation.any_terms
        ):
            continue
        return True
    return False


def _locator_matches(expected: str, actual: str, repository: Path) -> bool:
    expected_value = _SOURCE_LINE_RE.sub("", expected.replace("\\", "/").lstrip("./"))
    actual_value = _SOURCE_LINE_RE.sub("", actual.replace("\\", "/"))
    repository_prefix = repository.as_posix().rstrip("/") + "/"
    if actual_value.startswith(repository_prefix):
        actual_value = actual_value[len(repository_prefix) :]
    return (
        actual_value == expected_value
        or actual_value.endswith("/" + expected_value)
        or (expected_value.startswith("ledger://") and actual_value.startswith(expected_value))
    )


def _lineage_complete(sources: Sequence[ContextSource]) -> bool:
    return bool(sources) and all(
        bool(source.locator)
        and bool(source.content_sha256)
        and bool(source.provenance or source.source_locations)
        for source in sources
    )


def _metrics(
    results: tuple[BenchmarkTaskResult, ...],
    corpus: _BaselineCorpus,
) -> BenchmarkMetrics:
    expected = sum(result.expected_evidence_count for result in results)
    matched = sum(len(result.matched_evidence_ids) for result in results)
    evaluated = [
        result
        for result in results
        if result.full_context_correct is not None and result.broker_correct is not None
    ]
    full_correctness = None
    broker_correctness = None
    correctness_drop = None
    if evaluated:
        full_correctness = 100.0 * sum(bool(item.full_context_correct) for item in evaluated) / len(
            evaluated
        )
        broker_correctness = 100.0 * sum(bool(item.broker_correct) for item in evaluated) / len(
            evaluated
        )
        correctness_drop = full_correctness - broker_correctness
    return BenchmarkMetrics(
        task_count=len(results),
        repository_word_count=corpus.repository_word_count,
        baseline_file_count=corpus.baseline_file_count,
        median_full_context_tokens=statistics.median(
            result.baseline_tokens for result in results
        ),
        median_broker_tokens=statistics.median(result.broker_tokens for result in results),
        maximum_broker_tokens=max((result.broker_tokens for result in results), default=0),
        median_token_reduction_percent=round(
            statistics.median(result.token_reduction_percent for result in results), 4
        ),
        relevant_evidence_recall_percent=round(100.0 * matched / expected, 4),
        routing_accuracy_percent=round(
            100.0 * sum(result.observed_needs == result.expected_needs for result in results)
            / len(results),
            4,
        ),
        lineage_coverage_percent=round(
            100.0 * sum(result.lineage_complete for result in results) / len(results), 4
        ),
        full_vault_loads_observed=sum(result.full_vault_load_observed for result in results),
        omitted_results_total=sum(result.omitted_results for result in results),
        fallback_task_count=sum(result.fallback_reason is not None for result in results),
        full_context_answer_correctness_percent=(
            round(full_correctness, 4) if full_correctness is not None else None
        ),
        broker_answer_correctness_percent=(
            round(broker_correctness, 4) if broker_correctness is not None else None
        ),
        answer_correctness_drop_points=(
            round(correctness_drop, 4) if correctness_drop is not None else None
        ),
    )


def _gates(
    metrics: BenchmarkMetrics,
    targets: ContextBenchmarkTargets,
    answers_measured: bool,
) -> dict[str, BenchmarkGate]:
    correctness_status: Literal["PASSED", "FAILED", "NOT_MEASURED"]
    if not answers_measured or metrics.answer_correctness_drop_points is None:
        correctness_status = "NOT_MEASURED"
    elif metrics.answer_correctness_drop_points <= targets.maximum_answer_correctness_drop_points:
        correctness_status = "PASSED"
    else:
        correctness_status = "FAILED"
    return {
        "task_count": _gate(
            metrics.task_count >= targets.minimum_tasks,
            metrics.task_count,
            f">= {targets.minimum_tasks}",
        ),
        "repository_size": _gate(
            metrics.repository_word_count >= targets.minimum_repository_words,
            metrics.repository_word_count,
            f">= {targets.minimum_repository_words} words",
        ),
        "median_token_reduction": _gate(
            metrics.median_token_reduction_percent
            >= targets.minimum_median_token_reduction_percent,
            metrics.median_token_reduction_percent,
            f">= {targets.minimum_median_token_reduction_percent}%",
        ),
        "bundle_token_ceiling": _gate(
            metrics.maximum_broker_tokens <= targets.maximum_bundle_tokens,
            metrics.maximum_broker_tokens,
            f"<= {targets.maximum_bundle_tokens}",
        ),
        "relevant_evidence_recall": _gate(
            metrics.relevant_evidence_recall_percent
            >= targets.minimum_relevant_evidence_recall_percent,
            metrics.relevant_evidence_recall_percent,
            f">= {targets.minimum_relevant_evidence_recall_percent}%",
        ),
        "deterministic_routing": _gate(
            metrics.routing_accuracy_percent == 100.0,
            metrics.routing_accuracy_percent,
            "= 100%",
        ),
        "answer_correctness_drop": BenchmarkGate(
            status=correctness_status,
            observed=metrics.answer_correctness_drop_points,
            target=f"<= {targets.maximum_answer_correctness_drop_points} percentage points",
        ),
        "lineage_coverage": _gate(
            metrics.lineage_coverage_percent >= targets.minimum_lineage_coverage_percent,
            metrics.lineage_coverage_percent,
            f">= {targets.minimum_lineage_coverage_percent}%",
        ),
        "full_vault_loads": _gate(
            metrics.full_vault_loads_observed <= targets.maximum_full_vault_loads,
            metrics.full_vault_loads_observed,
            f"<= {targets.maximum_full_vault_loads}",
        ),
    }


def _gate(passed: bool, observed: int | float | bool, target: str) -> BenchmarkGate:
    return BenchmarkGate(status="PASSED" if passed else "FAILED", observed=observed, target=target)


def benchmark_source_identity(repository: Path) -> tuple[str | None, bool]:
    """Return the checked-out commit and whether the worktree differs from it."""

    try:
        commit = subprocess.run(
            ("git", "rev-parse", "HEAD"),
            cwd=repository,
            check=True,
            capture_output=True,
            text=True,
            timeout=15,
        ).stdout.strip()
        dirty = bool(
            subprocess.run(
                ("git", "status", "--porcelain"),
                cwd=repository,
                check=True,
                capture_output=True,
                text=True,
                timeout=15,
            ).stdout
        )
    except (OSError, subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None, True
    return (commit if re.fullmatch(r"[0-9a-f]{40}", commit) else None), dirty


def _estimate_tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4) if text else 0


def _atomic_write(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(content, encoding="utf-8")
    temporary.replace(path)
