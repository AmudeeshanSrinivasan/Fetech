"""Blinded, commit-bound answer evaluation for the context benchmark.

The module prepares local review artifacts but never generates correctness labels.
Only a reviewer who did not build the broker can supply the final judgments.
"""

from __future__ import annotations

import hashlib
import json
import os
import random
import tempfile
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool, model_validator

from fetech.context_benchmark import (
    INDEPENDENT_REVIEW_ATTESTATION,
    AnswerEvaluation,
    AnswerEvaluationSet,
    ContextBenchmarkError,
    ContextBenchmarkSuite,
)

_TASK_ID_PATTERN = r"^CTX-[A-Z]+-[0-9]{3}$"
_SHA256_PATTERN = r"^[0-9a-f]{64}$"
_COMMIT_PATTERN = r"^[0-9a-f]{40}$"


class _FrozenModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CandidateAnswer(_FrozenModel):
    task_id: str = Field(pattern=_TASK_ID_PATTERN)
    question: str = Field(min_length=1, max_length=16_384)
    question_sha256: str = Field(pattern=_SHA256_PATTERN)
    answer: str | None = Field(default=None, min_length=1, max_length=32_768)


class CandidateAnswerSet(_FrozenModel):
    schema_version: Literal["1.0"] = "1.0"
    suite_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_commit: str = Field(pattern=_COMMIT_PATTERN)
    generation_protocol_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_kind: Literal["full_context", "broker"]
    producer: str | None = Field(default=None, min_length=1, max_length=128)
    answers: tuple[CandidateAnswer, ...]

    @model_validator(mode="after")
    def reject_duplicates(self) -> CandidateAnswerSet:
        identifiers = [answer.task_id for answer in self.answers]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("candidate answer task IDs must be unique")
        return self


class BlindedAnswer(_FrozenModel):
    label: Literal["A", "B"]
    answer: str = Field(min_length=1, max_length=32_768)


class BlindedReviewTask(_FrozenModel):
    task_id: str = Field(pattern=_TASK_ID_PATTERN)
    question: str = Field(min_length=1, max_length=16_384)
    question_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidates: tuple[BlindedAnswer, BlindedAnswer]

    @model_validator(mode="after")
    def require_canonical_labels(self) -> BlindedReviewTask:
        if tuple(candidate.label for candidate in self.candidates) != ("A", "B"):
            raise ValueError("blinded candidates must be ordered A then B")
        return self


class BlindedReviewPacket(_FrozenModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_id: str = Field(pattern=_SHA256_PATTERN)
    suite_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_commit: str = Field(pattern=_COMMIT_PATTERN)
    answer_producer: str = Field(min_length=1, max_length=128)
    generation_protocol_sha256: str = Field(pattern=_SHA256_PATTERN)
    assignment_commitment_sha256: str = Field(pattern=_SHA256_PATTERN)
    tasks: tuple[BlindedReviewTask, ...]


class BlindingAssignment(_FrozenModel):
    task_id: str = Field(pattern=_TASK_ID_PATTERN)
    candidate_a_source: Literal["full_context", "broker"]


class BlindingMap(_FrozenModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_sha256: str = Field(pattern=_SHA256_PATTERN)
    suite_sha256: str = Field(pattern=_SHA256_PATTERN)
    source_commit: str = Field(pattern=_COMMIT_PATTERN)
    mapping_nonce: str = Field(pattern=_SHA256_PATTERN)
    assignments: tuple[BlindingAssignment, ...]


class ReviewRating(_FrozenModel):
    task_id: str = Field(pattern=_TASK_ID_PATTERN)
    question_sha256: str = Field(pattern=_SHA256_PATTERN)
    candidate_a_correct: StrictBool | None = None
    candidate_b_correct: StrictBool | None = None
    note: str | None = Field(default=None, max_length=2_048)


class ReviewRatings(_FrozenModel):
    schema_version: Literal["1.0"] = "1.0"
    packet_sha256: str = Field(pattern=_SHA256_PATTERN)
    evaluator: str | None = Field(default=None, min_length=1, max_length=128)
    independence_attestation: str | None = Field(default=None, max_length=256)
    ratings: tuple[ReviewRating, ...]


def build_candidate_templates(
    suite: ContextBenchmarkSuite,
    suite_bytes: bytes,
    generation_protocol_bytes: bytes,
    source_commit: str,
) -> tuple[CandidateAnswerSet, CandidateAnswerSet]:
    """Create full-context and broker answer templates for separate producers."""

    _require_commit(source_commit)
    suite_sha256 = hashlib.sha256(suite_bytes).hexdigest()
    protocol_sha256 = hashlib.sha256(generation_protocol_bytes).hexdigest()
    answers = tuple(
        CandidateAnswer(
            task_id=task.id,
            question=task.question,
            question_sha256=_question_sha256(task.question),
        )
        for task in suite.tasks
    )
    return (
        CandidateAnswerSet(
            suite_sha256=suite_sha256,
            source_commit=source_commit,
            generation_protocol_sha256=protocol_sha256,
            source_kind="full_context",
            answers=answers,
        ),
        CandidateAnswerSet(
            suite_sha256=suite_sha256,
            source_commit=source_commit,
            generation_protocol_sha256=protocol_sha256,
            source_kind="broker",
            answers=answers,
        ),
    )


def build_blinded_review(
    suite: ContextBenchmarkSuite,
    suite_bytes: bytes,
    generation_protocol_bytes: bytes,
    source_commit: str,
    full_context: CandidateAnswerSet,
    broker: CandidateAnswerSet,
    *,
    assignment_bits: tuple[bool, ...] | None = None,
) -> tuple[BlindedReviewPacket, BlindingMap, ReviewRatings]:
    """Blind two complete candidate sets and return the review artifacts."""

    _require_commit(source_commit)
    suite_sha256 = hashlib.sha256(suite_bytes).hexdigest()
    protocol_sha256 = hashlib.sha256(generation_protocol_bytes).hexdigest()
    _validate_candidate_set(
        suite, suite_sha256, protocol_sha256, source_commit, full_context, "full_context"
    )
    _validate_candidate_set(
        suite, suite_sha256, protocol_sha256, source_commit, broker, "broker"
    )
    answer_producer = full_context.producer
    if answer_producer is None:
        raise ContextBenchmarkError("the answer producer must be identified")
    if (
        answer_producer != broker.producer
        or full_context.generation_protocol_sha256 != broker.generation_protocol_sha256
    ):
        raise ContextBenchmarkError(
            "both answer sets must use the same identified producer and generation protocol"
        )
    if assignment_bits is None:
        generator = random.SystemRandom()
        assignment_bits = tuple(bool(generator.getrandbits(1)) for _ in suite.tasks)
    if len(assignment_bits) != len(suite.tasks):
        raise ContextBenchmarkError("blinding assignments must cover every benchmark task")

    packet_tasks: list[BlindedReviewTask] = []
    assignments: list[BlindingAssignment] = []
    for task, full_answer, broker_answer, full_is_a in zip(
        suite.tasks,
        full_context.answers,
        broker.answers,
        assignment_bits,
        strict=True,
    ):
        full_text = _completed_answer(full_answer)
        broker_text = _completed_answer(broker_answer)
        a_text, b_text = (
            (full_text, broker_text) if full_is_a else (broker_text, full_text)
        )
        packet_tasks.append(
            BlindedReviewTask(
                task_id=task.id,
                question=task.question,
                question_sha256=_question_sha256(task.question),
                candidates=(
                    BlindedAnswer(label="A", answer=a_text),
                    BlindedAnswer(label="B", answer=b_text),
                ),
            )
        )
        assignments.append(
            BlindingAssignment(
                task_id=task.id,
                candidate_a_source="full_context" if full_is_a else "broker",
            )
        )

    mapping_nonce = os.urandom(32).hex()
    assignment_commitment = _assignment_commitment(tuple(assignments), mapping_nonce)
    packet = BlindedReviewPacket(
        packet_id=hashlib.sha256(uuid.uuid4().bytes).hexdigest(),
        suite_sha256=suite_sha256,
        source_commit=source_commit,
        answer_producer=answer_producer,
        generation_protocol_sha256=full_context.generation_protocol_sha256,
        assignment_commitment_sha256=assignment_commitment,
        tasks=tuple(packet_tasks),
    )
    packet_sha256 = model_sha256(packet)
    mapping = BlindingMap(
        packet_sha256=packet_sha256,
        suite_sha256=suite_sha256,
        source_commit=source_commit,
        mapping_nonce=mapping_nonce,
        assignments=tuple(assignments),
    )
    ratings = ReviewRatings(
        packet_sha256=packet_sha256,
        ratings=tuple(
            ReviewRating(task_id=task.id, question_sha256=_question_sha256(task.question))
            for task in suite.tasks
        ),
    )
    return packet, mapping, ratings


def finalize_blinded_review(
    suite: ContextBenchmarkSuite,
    suite_bytes: bytes,
    generation_protocol_bytes: bytes,
    source_commit: str,
    packet: BlindedReviewPacket,
    mapping: BlindingMap,
    ratings: ReviewRatings,
) -> AnswerEvaluationSet:
    """Validate and unblind a complete independent review."""

    _require_commit(source_commit)
    suite_sha256 = hashlib.sha256(suite_bytes).hexdigest()
    protocol_sha256 = hashlib.sha256(generation_protocol_bytes).hexdigest()
    packet_sha256 = model_sha256(packet)
    if (
        packet.suite_sha256 != suite_sha256
        or mapping.suite_sha256 != suite_sha256
        or packet.source_commit != source_commit
        or mapping.source_commit != source_commit
        or packet.generation_protocol_sha256 != protocol_sha256
    ):
        raise ContextBenchmarkError("review artifacts do not match the suite and source commit")
    if mapping.packet_sha256 != packet_sha256 or ratings.packet_sha256 != packet_sha256:
        raise ContextBenchmarkError("review artifacts do not match the blinded packet")
    if packet.assignment_commitment_sha256 != _assignment_commitment(
        mapping.assignments, mapping.mapping_nonce
    ):
        raise ContextBenchmarkError("blinding map does not match its packet commitment")
    if ratings.evaluator is None:
        raise ContextBenchmarkError("the independent reviewer must identify the evaluator")
    if ratings.independence_attestation != INDEPENDENT_REVIEW_ATTESTATION:
        raise ContextBenchmarkError("the independent-review attestation is missing or invalid")

    expected = tuple(task.id for task in suite.tasks)
    if tuple(task.task_id for task in packet.tasks) != expected:
        raise ContextBenchmarkError("blinded packet must cover suite tasks in canonical order")
    if tuple(item.task_id for item in mapping.assignments) != expected:
        raise ContextBenchmarkError("blinding map must cover suite tasks in canonical order")
    if tuple(item.task_id for item in ratings.ratings) != expected:
        raise ContextBenchmarkError("review ratings must cover suite tasks in canonical order")

    evaluations: list[AnswerEvaluation] = []
    for task, packet_task, assignment, rating in zip(
        suite.tasks, packet.tasks, mapping.assignments, ratings.ratings, strict=True
    ):
        expected_question_sha = _question_sha256(task.question)
        if (
            packet_task.question != task.question
            or packet_task.question_sha256 != expected_question_sha
            or rating.question_sha256 != expected_question_sha
        ):
            raise ContextBenchmarkError("review task questions do not match the benchmark suite")
        if rating.candidate_a_correct is None or rating.candidate_b_correct is None:
            raise ContextBenchmarkError("every blinded candidate must receive a boolean judgment")
        a_correct = rating.candidate_a_correct
        b_correct = rating.candidate_b_correct
        full_correct, broker_correct = (
            (a_correct, b_correct)
            if assignment.candidate_a_source == "full_context"
            else (b_correct, a_correct)
        )
        evaluations.append(
            AnswerEvaluation(
                task_id=task.id,
                full_context_correct=full_correct,
                broker_correct=broker_correct,
            )
        )

    return AnswerEvaluationSet(
        evaluator=ratings.evaluator,
        independence_attestation=INDEPENDENT_REVIEW_ATTESTATION,
        answer_producer=packet.answer_producer,
        generation_protocol_sha256=packet.generation_protocol_sha256,
        suite_sha256=suite_sha256,
        source_commit=source_commit,
        review_packet_sha256=packet_sha256,
        evaluations=tuple(evaluations),
    )


def load_candidate_answers(path: Path) -> CandidateAnswerSet:
    return _load_json_model(path, CandidateAnswerSet, "candidate answers")


def load_review_packet(path: Path) -> BlindedReviewPacket:
    return _load_json_model(path, BlindedReviewPacket, "blinded review packet")


def load_blinding_map(path: Path) -> BlindingMap:
    return _load_json_model(path, BlindingMap, "blinding map")


def load_review_ratings(path: Path) -> ReviewRatings:
    return _load_json_model(path, ReviewRatings, "review ratings")


def model_sha256(model: BaseModel) -> str:
    """Hash one canonical Pydantic JSON representation."""

    return hashlib.sha256(model.model_dump_json().encode("utf-8")).hexdigest()


def write_local_json(
    path: Path,
    model: BaseModel,
    *,
    private: bool = False,
    force: bool = False,
) -> None:
    """Write a local review artifact without accidentally replacing reviewer work."""

    destination = path.expanduser().resolve()
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists() and not force:
            raise ContextBenchmarkError(f"refusing to overwrite existing file: {destination.name}")
        payload = model.model_dump_json(indent=2) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.", dir=destination.parent
        )
        temporary = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600 if private else 0o644)
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            if force:
                os.replace(temporary, destination)
            else:
                os.link(temporary, destination)
                temporary.unlink()
        finally:
            if temporary.exists():
                temporary.unlink()
    except ContextBenchmarkError:
        raise
    except OSError as exc:
        raise ContextBenchmarkError("unable to write local answer-review artifact") from exc


def _load_json_model[T: BaseModel](path: Path, model: type[T], label: str) -> T:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        return model.model_validate(raw)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise ContextBenchmarkError(f"unable to read {label}") from exc


def _validate_candidate_set(
    suite: ContextBenchmarkSuite,
    suite_sha256: str,
    protocol_sha256: str,
    source_commit: str,
    candidate_set: CandidateAnswerSet,
    source_kind: Literal["full_context", "broker"],
) -> None:
    if (
        candidate_set.source_kind != source_kind
        or candidate_set.suite_sha256 != suite_sha256
        or candidate_set.source_commit != source_commit
        or candidate_set.generation_protocol_sha256 != protocol_sha256
    ):
        raise ContextBenchmarkError(f"{source_kind} answers do not match the evaluation source")
    if candidate_set.producer is None:
        raise ContextBenchmarkError(f"{source_kind} answer producer must be identified")
    if tuple(answer.task_id for answer in candidate_set.answers) != tuple(
        task.id for task in suite.tasks
    ):
        raise ContextBenchmarkError(f"{source_kind} answers must cover tasks in canonical order")
    for task, answer in zip(suite.tasks, candidate_set.answers, strict=True):
        if answer.question != task.question or answer.question_sha256 != _question_sha256(
            task.question
        ):
            raise ContextBenchmarkError(f"{source_kind} answer questions do not match the suite")
        _completed_answer(answer)


def _assignment_commitment(
    assignments: tuple[BlindingAssignment, ...],
    mapping_nonce: str,
) -> str:
    canonical = json.dumps(
        [assignment.model_dump(mode="json") for assignment in assignments],
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(bytes.fromhex(mapping_nonce) + canonical).hexdigest()


def _completed_answer(answer: CandidateAnswer) -> str:
    if answer.answer is None or not answer.answer.strip():
        raise ContextBenchmarkError("every candidate task must contain a non-empty answer")
    return answer.answer


def _question_sha256(question: str) -> str:
    return hashlib.sha256(question.encode("utf-8")).hexdigest()


def _require_commit(source_commit: str) -> None:
    hexadecimal = "0123456789abcdef"
    if len(source_commit) != 40 or any(character not in hexadecimal for character in source_commit):
        raise ContextBenchmarkError("answer evaluation requires a canonical Git commit")
