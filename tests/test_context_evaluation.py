"""Conformance for the blinded context-answer evaluation workflow."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from fetech.context_benchmark import (
    INDEPENDENT_REVIEW_ATTESTATION,
    ContextBenchmarkError,
    load_benchmark_suite,
)
from fetech.context_evaluation import (
    BlindingAssignment,
    CandidateAnswerSet,
    ReviewRating,
    build_blinded_review,
    build_candidate_templates,
    finalize_blinded_review,
    write_local_json,
)

ROOT = Path(__file__).resolve().parents[1]
SUITE_PATH = ROOT / "benchmarks" / "context-tasks.yaml"
COMMIT = "a" * 40
PROTOCOL = b"same frozen answer instructions and settings"


def _filled(template: CandidateAnswerSet, prefix: str) -> CandidateAnswerSet:
    return template.model_copy(
        update={
            "producer": "fixture answer system v1",
            "answers": tuple(
                answer.model_copy(update={"answer": f"{prefix} answer for {answer.task_id}"})
                for answer in template.answers
            ),
        }
    )


def _workflow() -> tuple[object, ...]:
    suite_bytes = SUITE_PATH.read_bytes()
    suite = load_benchmark_suite(SUITE_PATH)
    full_template, broker_template = build_candidate_templates(
        suite, suite_bytes, PROTOCOL, COMMIT
    )
    full = _filled(full_template, "reference")
    broker = _filled(broker_template, "bounded")
    packet, mapping, ratings = build_blinded_review(
        suite,
        suite_bytes,
        PROTOCOL,
        COMMIT,
        full,
        broker,
        assignment_bits=tuple(index % 2 == 0 for index, _ in enumerate(suite.tasks)),
    )
    return suite, suite_bytes, full, broker, packet, mapping, ratings


def test_templates_are_complete_but_cannot_be_scored_as_answers() -> None:
    suite = load_benchmark_suite(SUITE_PATH)
    full, broker = build_candidate_templates(
        suite, SUITE_PATH.read_bytes(), PROTOCOL, COMMIT
    )

    assert len(full.answers) == len(broker.answers) == 100
    assert full.source_kind == "full_context"
    assert broker.source_kind == "broker"
    assert all(answer.answer is None for answer in full.answers)
    with pytest.raises(ContextBenchmarkError, match="producer must be identified"):
        build_blinded_review(
            suite, SUITE_PATH.read_bytes(), PROTOCOL, COMMIT, full, broker
        )

    filled_full = _filled(full, "reference")
    filled_broker = _filled(broker, "bounded").model_copy(
        update={"producer": "different answer system"}
    )
    with pytest.raises(ContextBenchmarkError, match="same identified producer"):
        build_blinded_review(
            suite,
            SUITE_PATH.read_bytes(),
            PROTOCOL,
            COMMIT,
            filled_full,
            filled_broker,
        )


def test_blinded_packet_hides_answer_sources_and_finalizer_unblinds_scores() -> None:
    suite, suite_bytes, _, _, packet, mapping, ratings = _workflow()
    packet_json = packet.model_dump_json()

    assert '"source_kind"' not in packet_json
    assert '"producer"' not in packet_json
    completed = ratings.model_copy(
        update={
            "evaluator": "independent fixture reviewer",
            "independence_attestation": INDEPENDENT_REVIEW_ATTESTATION,
            "ratings": tuple(
                ReviewRating(
                    task_id=task.id,
                    question_sha256=rating.question_sha256,
                    candidate_a_correct=(
                        True
                        if assignment.candidate_a_source == "full_context"
                        else index >= 3
                    ),
                    candidate_b_correct=(
                        index >= 3
                        if assignment.candidate_a_source == "full_context"
                        else True
                    ),
                )
                for index, (task, assignment, rating) in enumerate(
                    zip(suite.tasks, mapping.assignments, ratings.ratings, strict=True)
                )
            ),
        }
    )

    evaluations = finalize_blinded_review(
        suite, suite_bytes, PROTOCOL, COMMIT, packet, mapping, completed
    )

    assert len(evaluations.evaluations) == 100
    assert all(item.full_context_correct for item in evaluations.evaluations)
    assert sum(not item.broker_correct for item in evaluations.evaluations) == 3
    assert evaluations.review_packet_sha256 == mapping.packet_sha256


def test_finalizer_rejects_incomplete_or_tampered_review_artifacts() -> None:
    suite, suite_bytes, _, _, packet, mapping, ratings = _workflow()
    with pytest.raises(ContextBenchmarkError, match="identify the evaluator"):
        finalize_blinded_review(
            suite, suite_bytes, PROTOCOL, COMMIT, packet, mapping, ratings
        )

    tampered = packet.model_copy(update={"packet_id": "f" * 64})
    completed = ratings.model_copy(
        update={
            "evaluator": "reviewer",
            "independence_attestation": INDEPENDENT_REVIEW_ATTESTATION,
        }
    )
    with pytest.raises(ContextBenchmarkError, match="do not match the blinded packet"):
        finalize_blinded_review(
            suite, suite_bytes, PROTOCOL, COMMIT, tampered, mapping, completed
        )

    first = mapping.assignments[0]
    changed_source = "broker" if first.candidate_a_source == "full_context" else "full_context"
    changed_mapping = mapping.model_copy(
        update={
            "assignments": (
                BlindingAssignment(task_id=first.task_id, candidate_a_source=changed_source),
                *mapping.assignments[1:],
            )
        }
    )
    with pytest.raises(ContextBenchmarkError, match="packet commitment"):
        finalize_blinded_review(
            suite, suite_bytes, PROTOCOL, COMMIT, packet, changed_mapping, completed
        )


def test_local_writer_preserves_existing_work_and_limits_mapping_permissions(
    tmp_path: Path,
) -> None:
    _, _, _, _, _, mapping, _ = _workflow()
    output = tmp_path / "mapping.json"

    write_local_json(output, mapping, private=True)

    assert stat.S_IMODE(output.stat().st_mode) == 0o600
    with pytest.raises(ContextBenchmarkError, match="refusing to overwrite"):
        write_local_json(output, mapping, private=True)
