"""Local, bounded evidence freeze for a future paired answer-generation run.

This is an input artifact, not a correctness result. Capturing evidence never
contacts a model, reads an entire vault, or modifies the authoritative ledger.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from fetech.context_benchmark import (
    ContextBenchmarkError,
    ContextBenchmarkSuite,
    benchmark_source_identity,
    validate_benchmark_environment,
)
from fetech.models import ContextNeed, ProvenanceEvent
from fetech.provenance import runtime_graph_from_events

NOTE_PATHS = (
    "brain/Fetech Architecture.md",
    "brain/Fetech Decisions.md",
    "brain/Fetech Gotchas.md",
    "reference/Fetech Capability Catalog.md",
    "reference/Fetech Runbook.md",
    "work/active/Fetech.md",
)
_MAX_DOCUMENT_BYTES = 5_000_000
_MAX_SNAPSHOT_BYTES = 32_000_000
_MAX_EVENTS = 2_000
_HASH = r"^[0-9a-f]{64}$"


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class _Frozen(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class FrozenDocument(_Frozen):
    locator: str = Field(min_length=1, max_length=512)
    kind: Literal["repository", "note", "runtime_events", "runtime_graph"]
    text: str = Field(min_length=1, max_length=_MAX_DOCUMENT_BYTES)
    sha256: str = Field(pattern=_HASH)

    @model_validator(mode="after")
    def verify_content(self) -> FrozenDocument:
        if _sha(self.text) != self.sha256:
            raise ValueError("frozen document hash mismatch")
        if len(self.text.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
            raise ValueError("frozen document byte limit exceeded")
        return self


class FrozenTaskInput(_Frozen):
    task_id: str = Field(pattern=r"^CTX-[A-Z]+-[0-9]{3}$")
    question_sha256: str = Field(pattern=_HASH)
    baseline_locators: tuple[str, ...] = Field(min_length=1, max_length=32)
    baseline_sha256: str = Field(pattern=_HASH)
    estimated_tokens: int = Field(ge=1, le=100_000)


class ContextEvidenceSnapshot(_Frozen):
    schema_version: Literal["1.0"] = "1.0"
    baseline_method: Literal["frozen-runtime-notes-v1"] = "frozen-runtime-notes-v1"
    stage: Literal["AWAITING_BROKER_REPLAY"] = "AWAITING_BROKER_REPLAY"
    captured_at: datetime
    source_commit: str = Field(pattern=r"^[0-9a-f]{40}$")
    source_dirty: bool
    suite_sha256: str = Field(pattern=_HASH)
    generation_protocol_sha256: str = Field(pattern=_HASH)
    documents: tuple[FrozenDocument, ...] = Field(min_length=1, max_length=256)
    tasks: tuple[FrozenTaskInput, ...] = Field(min_length=100, max_length=1_000)

    @model_validator(mode="after")
    def verify_integrity(self) -> ContextEvidenceSnapshot:
        documents = {doc.locator: doc for doc in self.documents}
        if len(documents) != len(self.documents):
            raise ValueError("duplicate frozen document locator")
        if sum(len(doc.text.encode("utf-8")) for doc in self.documents) > _MAX_SNAPSHOT_BYTES:
            raise ValueError("frozen corpus exceeds byte limit")
        if len({task.task_id for task in self.tasks}) != len(self.tasks):
            raise ValueError("duplicate frozen task")
        if {doc.locator for doc in self.documents if doc.kind == "note"} != {
            f"note://{path}" for path in NOTE_PATHS
        }:
            raise ValueError("snapshot must contain exactly the six approved Fetech notes")
        for task in self.tasks:
            if len(set(task.baseline_locators)) != len(task.baseline_locators):
                raise ValueError("duplicate baseline document")
            if any(locator not in documents for locator in task.baseline_locators):
                raise ValueError("baseline references a missing frozen document")
            text = _baseline_text(documents, task.baseline_locators)
            if _sha(text) != task.baseline_sha256 or _tokens(text) != task.estimated_tokens:
                raise ValueError("frozen baseline hash or token accounting mismatch")
        event_doc = documents.get("ledger://events")
        graph_doc = documents.get("graph://runtime")
        if event_doc is None or graph_doc is None:
            raise ValueError("snapshot requires authoritative events and their runtime projection")
        events = _parse_events(event_doc.text)
        if json.loads(graph_doc.text) != runtime_graph_from_events(events):
            raise ValueError("runtime graph does not match frozen ledger events")
        return self


def _tokens(text: str) -> int:
    return max(1, (len(text) + 3) // 4)


def _baseline_text(documents: dict[str, FrozenDocument], locators: tuple[str, ...]) -> str:
    return "\n\n".join(f"--- {name} ---\n{documents[name].text}" for name in locators)


def snapshot_baselines(snapshot: ContextEvidenceSnapshot) -> dict[str, str]:
    """Return complete frozen texts; never silently truncate or consult live files."""

    checked = ContextEvidenceSnapshot.model_validate(snapshot.model_dump())
    docs = {doc.locator: doc for doc in checked.documents}
    return {task.task_id: _baseline_text(docs, task.baseline_locators) for task in checked.tasks}


def _regular_path(root: Path, relative: str) -> Path:
    path = Path(relative)
    if (path.is_absolute() or path.as_posix() != relative
            or any(part in {"", ".", ".."} for part in relative.split("/"))
            or "\\" in relative):
        raise ContextBenchmarkError("snapshot input must be a canonical relative path")
    root = root.expanduser().resolve()
    candidate = root
    for part in path.parts:
        candidate /= part
        if candidate.is_symlink():
            raise ContextBenchmarkError("snapshot input cannot traverse a symlink")
    if not candidate.is_file():
        raise ContextBenchmarkError("snapshot input is not an existing regular file")
    return candidate


def _read_text(path: Path, limit: int = _MAX_DOCUMENT_BYTES) -> str:
    if path.is_symlink() or not path.is_file():
        raise ContextBenchmarkError("snapshot input is not a regular file")
    with path.open("rb") as stream:
        payload = stream.read(limit + 1)
    if len(payload) > limit:
        raise ContextBenchmarkError("snapshot input exceeds byte limit")
    try:
        return payload.decode("utf-8", errors="strict")
    except UnicodeError as exc:
        raise ContextBenchmarkError("snapshot input must be UTF-8 text") from exc


def _parse_events(text: str) -> tuple[ProvenanceEvent, ...]:
    raw = json.loads(text)
    if not isinstance(raw, list) or not 1 <= len(raw) <= _MAX_EVENTS:
        raise ContextBenchmarkError("snapshot requires 1 to 2000 ledger events")
    events = tuple(ProvenanceEvent.model_validate(item) for item in raw)
    identifiers = {event.event_id for event in events}
    if len(identifiers) != len(events):
        raise ContextBenchmarkError("duplicate ledger event identity")
    if any(parent not in identifiers for event in events for parent in event.parent_event_ids):
        raise ContextBenchmarkError("ledger snapshot contains a missing parent event")
    return events


def read_ledger_events(path: Path) -> str:
    """Read only event rows in one SQLite read transaction, with count/byte bounds."""

    path = _regular_path(path.parent, path.name)
    try:
        with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=5)) as connection:
            connection.execute("PRAGMA query_only=ON")
            connection.execute("BEGIN")
            count, size = connection.execute(
                "SELECT count(*), coalesce(sum(length(CAST(payload_json AS BLOB)) + "
                "length(CAST(parent_event_ids_json AS BLOB)) + "
                "length(CAST(actor AS BLOB)) + length(CAST(event_type AS BLOB)) + 256), 0) "
                "FROM provenance_events"
            ).fetchone()
            if not 1 <= count <= _MAX_EVENTS or size > _MAX_DOCUMENT_BYTES:
                raise ContextBenchmarkError("ledger event snapshot exceeds count/byte bounds or is empty")
            rows = connection.execute(
                "SELECT event_id, run_id, event_type, timestamp, actor, payload_json, "
                "parent_event_ids_json FROM provenance_events ORDER BY sequence LIMIT ?",
                (_MAX_EVENTS + 1,),
            ).fetchall()
    except sqlite3.Error as exc:
        raise ContextBenchmarkError("unable to read existing SQLite event ledger") from exc
    events = [ProvenanceEvent(
        event_id=row[0], run_id=row[1], event_type=row[2], timestamp=row[3], actor=row[4],
        payload=json.loads(row[5]), parent_event_ids=json.loads(row[6]),
    ).model_dump(mode="json") for row in rows]
    text = json.dumps(events, sort_keys=True, indent=2)
    _parse_events(text)
    if len(text.encode("utf-8")) > _MAX_DOCUMENT_BYTES:
        raise ContextBenchmarkError("encoded ledger snapshot exceeds byte limit")
    return text


def _task_locators(suite: ContextBenchmarkSuite) -> dict[str, tuple[str, ...]]:
    result: dict[str, tuple[str, ...]] = {}
    for task in suite.tasks:
        locators: list[str] = []
        if ContextNeed.CODE_ARCHITECTURE in task.expected_needs:
            # Keep code-only curated baselines; mixed tasks omit event/note proxy docs.
            paths = task.baseline_files if len(task.expected_needs) == 1 else tuple(
                item.locator for item in task.evidence
                if item.source_type == "exact_source" and item.locator is not None
            )
            locators.extend(f"repo://{path}" for path in dict.fromkeys(paths))
        if ContextNeed.RUNTIME_HISTORY in task.expected_needs:
            locators.extend(("ledger://events", "graph://runtime"))
        if ContextNeed.DECISION_HISTORY in task.expected_needs:
            # Selection is frozen before retrieval, not cherry-picked from returned snippets.
            locators.extend(f"note://{path}" for path in NOTE_PATHS)
        result[task.id] = tuple(locators)
    return result


def capture_evidence_snapshot(
    repository: Path, suite: ContextBenchmarkSuite, suite_bytes: bytes, protocol_bytes: bytes,
    *, vault: Path, ledger: Path, runtime_graph: Path, development: bool = False,
) -> ContextEvidenceSnapshot:
    """Freeze bounded authoritative inputs; leave original files and stores unchanged."""

    repository = repository.expanduser().resolve()
    commit, dirty = benchmark_source_identity(repository)
    if commit is None or (dirty and not development):
        raise ContextBenchmarkError("snapshot requires a clean commit; use development mode for rehearsal")
    validate_benchmark_environment(repository, suite)
    documents: list[FrozenDocument] = []
    observed: dict[Path, str] = {}

    def add(locator: str, kind: Literal["repository", "note", "runtime_events", "runtime_graph"],
            text: str, path: Path | None = None) -> None:
        doc = FrozenDocument(locator=locator, kind=kind, text=text, sha256=_sha(text))
        documents.append(doc)
        if path is not None:
            observed[path] = doc.sha256

    for relative in sorted({path for task in suite.tasks for path in task.baseline_files}):
        path = _regular_path(repository, relative)
        add(f"repo://{relative}", "repository", _read_text(path), path)
    expected_notes = {
        item.locator for task in suite.tasks for item in task.evidence if item.source_type == "qmd"
    }
    if not expected_notes.issubset(NOTE_PATHS):
        raise ContextBenchmarkError("suite references a note outside the approved Fetech allowlist")
    for relative in NOTE_PATHS:
        path = _regular_path(vault, relative)
        add(f"note://{relative}", "note", _read_text(path), path)
    events = read_ledger_events(ledger)
    add("ledger://events", "runtime_events", events)
    graph_path = _regular_path(runtime_graph.parent, runtime_graph.name)
    add("graph://runtime", "runtime_graph", _read_text(graph_path), graph_path)
    doc_map = {doc.locator: doc for doc in documents}
    selection = _task_locators(suite)
    tasks = []
    for task in suite.tasks:
        text = _baseline_text(doc_map, selection[task.id])
        if _tokens(text) > suite.maximum_baseline_tokens:
            raise ContextBenchmarkError(f"task {task.id} frozen baseline exceeds token limit")
        tasks.append(FrozenTaskInput(
            task_id=task.id, question_sha256=_sha(task.question),
            baseline_locators=selection[task.id], baseline_sha256=_sha(text),
            estimated_tokens=_tokens(text),
        ))
    if any(_sha(_read_text(path)) != digest for path, digest in observed.items()):
        raise ContextBenchmarkError("an input changed while capturing evidence")
    if read_ledger_events(ledger) != events or benchmark_source_identity(repository) != (commit, dirty):
        raise ContextBenchmarkError("ledger or source identity changed while capturing evidence")
    return ContextEvidenceSnapshot(
        captured_at=datetime.now(UTC), source_commit=commit, source_dirty=dirty,
        suite_sha256=hashlib.sha256(suite_bytes).hexdigest(),
        generation_protocol_sha256=hashlib.sha256(protocol_bytes).hexdigest(),
        documents=tuple(documents), tasks=tuple(tasks),
    )


def load_evidence_snapshot(path: Path) -> ContextEvidenceSnapshot:
    """Validate every document, task baseline and ledger projection on load."""

    return ContextEvidenceSnapshot.model_validate_json(_read_text(path, _MAX_SNAPSHOT_BYTES))


def validate_snapshot_binding(
    snapshot: ContextEvidenceSnapshot, suite: ContextBenchmarkSuite,
    suite_bytes: bytes, protocol_bytes: bytes, source_commit: str,
) -> None:
    """Reject a rehearsal or a snapshot from different source/protocol/task inputs."""

    snapshot = ContextEvidenceSnapshot.model_validate(snapshot.model_dump())
    if snapshot.source_dirty or snapshot.source_commit != source_commit:
        raise ContextBenchmarkError("snapshot is not bound to the clean evaluated source commit")
    if (snapshot.suite_sha256 != hashlib.sha256(suite_bytes).hexdigest()
            or snapshot.generation_protocol_sha256 != hashlib.sha256(protocol_bytes).hexdigest()):
        raise ContextBenchmarkError("snapshot suite or generation protocol differs")
    selection = _task_locators(suite)
    if [(task.task_id, task.question_sha256, task.baseline_locators) for task in snapshot.tasks] != [
        (task.id, _sha(task.question), selection[task.id]) for task in suite.tasks
    ]:
        raise ContextBenchmarkError("snapshot task order, question or baseline selection differs")
