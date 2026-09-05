"""Deterministic context-efficiency benchmark conformance."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from fetech.context_benchmark import (
    AnswerEvaluation,
    AnswerEvaluationSet,
    ContextBenchmarkError,
    ContextBenchmarkSuite,
    load_benchmark_suite,
    render_benchmark_json,
    run_context_benchmark,
    validate_benchmark_environment,
)
from fetech.models import ContextBundle, ContextSource, ContextTokenUsage

ROOT = Path(__file__).resolve().parents[1]
SUITE_PATH = ROOT / "benchmarks" / "context-tasks.yaml"


class _FixtureBroker:
    def __init__(
        self,
        suite: ContextBenchmarkSuite,
        *,
        include_evidence: bool = True,
        estimated_tokens: int = 600,
        extra_qmd_notes: int = 0,
    ) -> None:
        self._tasks = {task.question: task for task in suite.tasks}
        self._include_evidence = include_evidence
        self._estimated_tokens = estimated_tokens
        self._extra_qmd_notes = extra_qmd_notes

    async def search(
        self,
        question: str,
        *,
        token_budget: int | None = None,
    ) -> ContextBundle:
        task = self._tasks[question]
        sources: list[ContextSource] = []
        if self._include_evidence:
            for expectation in task.evidence:
                terms = " ".join(expectation.any_terms) or expectation.id
                if expectation.locator is not None:
                    locator = expectation.locator
                elif expectation.source_type == "runtime_graph":
                    locator = "ledger://runs/fixture/events/fixture"
                else:
                    locator = f"fixture://{expectation.id}"
                excerpt = f"bounded evidence for {terms}"
                sources.append(
                    ContextSource(
                        source_type=expectation.source_type,
                        title=terms,
                        locator=locator,
                        excerpt=excerpt,
                        provenance=("fixture retrieval",),
                        content_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
                        source_locations=(locator,) if expectation.source_type == "exact_source" else (),
                        verified=expectation.source_type == "exact_source",
                    )
                )
        for index in range(self._extra_qmd_notes):
            excerpt = f"additional bounded QMD note {index}"
            sources.append(
                ContextSource(
                    source_type="qmd",
                    title=f"note {index}",
                    locator=f"vault/note-{index}.md",
                    excerpt=excerpt,
                    provenance=("fixture QMD",),
                    content_sha256=hashlib.sha256(excerpt.encode()).hexdigest(),
                )
            )
        return ContextBundle(
            question=question,
            sources=tuple(sources),
            needs=task.expected_needs,
            token_budget=token_budget or 4_000,
            estimated_tokens=self._estimated_tokens,
            token_usage=ContextTokenUsage(
                exact_source=self._estimated_tokens,
                total=self._estimated_tokens,
            ),
            omitted_results=2,
            fallback_reason="fixture fallback" if not self._include_evidence else None,
        )


def _suite() -> ContextBenchmarkSuite:
    return load_benchmark_suite(SUITE_PATH)


def _complete_evaluations(
    suite: ContextBenchmarkSuite,
    *,
    broker_failures: int = 0,
) -> AnswerEvaluationSet:
    return AnswerEvaluationSet(
        evaluator="independent fixture evaluator",
        evaluations=tuple(
            AnswerEvaluation(
                task_id=task.id,
                full_context_correct=True,
                broker_correct=index >= broker_failures,
            )
            for index, task in enumerate(suite.tasks)
        ),
    )


def test_checked_in_suite_has_100_unique_representative_tasks() -> None:
    suite = _suite()
    summary = validate_benchmark_environment(ROOT, suite)

    assert summary["task_count"] == 100
    assert summary["repository_word_count"] >= 5_000
    assert summary["baseline_file_count"] > 0
    assert {need for task in suite.tasks for need in task.expected_needs} == set(suite.baseline_globs)
    assert sum(task.id.startswith("CTX-CODE-") for task in suite.tasks) == 50
    assert sum(task.id.startswith("CTX-RUNTIME-") for task in suite.tasks) == 20
    assert sum(task.id.startswith("CTX-DECISION-") for task in suite.tasks) == 20
    assert sum(task.id.startswith("CTX-MIXED-") for task in suite.tasks) == 10
    for task in suite.tasks:
        for expectation in task.evidence:
            if expectation.source_type == "exact_source":
                assert expectation.locator is not None
                path = ROOT / expectation.locator
                assert path.is_file()
                content = path.read_text(encoding="utf-8", errors="replace").casefold()
                assert any(term.casefold() in content for term in expectation.any_terms)


@pytest.mark.asyncio
async def test_complete_fixture_run_passes_every_acceptance_gate_without_prompt_logging() -> None:
    suite = _suite()
    report = await run_context_benchmark(
        _FixtureBroker(suite),
        ROOT,
        suite,
        answer_evaluations=_complete_evaluations(suite),
        suite_bytes=SUITE_PATH.read_bytes(),
    )

    assert report.status == "PASSED"
    assert all(gate.status == "PASSED" for gate in report.gates.values())
    assert report.metrics.task_count == 100
    assert report.metrics.median_token_reduction_percent >= 70
    assert report.metrics.maximum_broker_tokens <= 4_000
    assert report.metrics.relevant_evidence_recall_percent == 100
    assert report.metrics.lineage_coverage_percent == 100
    assert report.metrics.answer_correctness_drop_points == 0
    serialized = render_benchmark_json(report)
    assert suite.tasks[0].question not in serialized
    assert "bounded evidence" not in serialized
    assert str(Path.home()) not in serialized


@pytest.mark.asyncio
async def test_answer_correctness_is_explicitly_incomplete_without_evaluations() -> None:
    suite = _suite()
    report = await run_context_benchmark(_FixtureBroker(suite), ROOT, suite)

    assert report.status == "INCOMPLETE"
    assert report.gates["answer_correctness_drop"].status == "NOT_MEASURED"
    assert report.metrics.full_context_answer_correctness_percent is None
    assert report.metrics.broker_answer_correctness_percent is None


@pytest.mark.asyncio
async def test_missing_evidence_and_large_bundles_fail_closed() -> None:
    suite = _suite()
    report = await run_context_benchmark(
        _FixtureBroker(suite, include_evidence=False, estimated_tokens=4_001),
        ROOT,
        suite,
        answer_evaluations=_complete_evaluations(suite),
    )

    assert report.status == "FAILED"
    assert report.gates["bundle_token_ceiling"].status == "FAILED"
    assert report.gates["relevant_evidence_recall"].status == "FAILED"
    assert report.gates["lineage_coverage"].status == "FAILED"
    assert report.metrics.relevant_evidence_recall_percent == 0
    assert report.metrics.fallback_task_count == 100


@pytest.mark.asyncio
async def test_more_than_three_qmd_notes_is_observed_as_a_full_vault_load_violation() -> None:
    suite = _suite()
    report = await run_context_benchmark(
        _FixtureBroker(suite, extra_qmd_notes=4),
        ROOT,
        suite,
        answer_evaluations=_complete_evaluations(suite),
    )

    assert report.status == "FAILED"
    assert report.gates["full_vault_loads"].status == "FAILED"
    assert report.metrics.full_vault_loads_observed == 100


@pytest.mark.asyncio
async def test_answer_evaluations_must_cover_every_task_exactly() -> None:
    suite = _suite()
    incomplete = AnswerEvaluationSet(
        evaluator="fixture",
        evaluations=_complete_evaluations(suite).evaluations[:-1],
    )

    with pytest.raises(ContextBenchmarkError, match="cover the suite exactly"):
        await run_context_benchmark(
            _FixtureBroker(suite),
            ROOT,
            suite,
            answer_evaluations=incomplete,
        )


@pytest.mark.asyncio
async def test_answer_correctness_drop_above_two_points_fails() -> None:
    suite = _suite()
    report = await run_context_benchmark(
        _FixtureBroker(suite),
        ROOT,
        suite,
        answer_evaluations=_complete_evaluations(suite, broker_failures=3),
    )

    assert report.status == "FAILED"
    assert report.metrics.answer_correctness_drop_points == 3
    assert report.gates["answer_correctness_drop"].status == "FAILED"


def test_ci_validates_the_suite_without_requiring_private_providers() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "Validate context benchmark harness" in workflow
    assert "scripts/run_context_benchmark.py --validate-only" in workflow
    assert "pytest tests/test_context_benchmark.py -q" in workflow
