"""Hermetic input-freeze tests; no live vault, model or mutable ledger access."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from pathlib import Path
from uuid import uuid4

import pytest

from fetech import context_snapshot as module
from fetech.context_benchmark import ContextBenchmarkError, load_benchmark_suite
from fetech.context_evaluation import write_local_json
from fetech.context_snapshot import (
    NOTE_PATHS,
    ContextEvidenceSnapshot,
    capture_evidence_snapshot,
    load_evidence_snapshot,
    read_ledger_events,
    snapshot_baselines,
    validate_snapshot_binding,
)
from fetech.models import ProvenanceEvent
from fetech.provenance import runtime_graph_from_events

ROOT = Path(__file__).resolve().parents[1]
SUITE_PATH = ROOT / "benchmarks/context-tasks.yaml"
COMMIT = "1" * 40


@pytest.fixture
def inputs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict:
    repository = tmp_path / "repository"
    vault = tmp_path / "vault"
    suite = load_benchmark_suite(SUITE_PATH)
    for relative in {path for task in suite.tasks for path in task.baseline_files}:
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Complete source {relative}\n", encoding="utf-8")
    for relative in NOTE_PATHS:
        path = vault / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"Complete frozen note {relative}\n", encoding="utf-8")
    # An unrelated private note must never be inspected or included.
    (vault / "unrelated.md").write_text("OUT_OF_SCOPE_PRIVATE_CONTENT", encoding="utf-8")
    ledger = tmp_path / "ledger.sqlite3"
    event = ProvenanceEvent(event_id=uuid4(), run_id=uuid4(), event_type="planning.completed",
                            actor="python-rules-v1", payload={"status": "SUCCEEDED"})
    with sqlite3.connect(ledger) as connection:
        connection.execute("CREATE TABLE provenance_events (sequence INTEGER, event_id TEXT, "
                           "run_id TEXT, event_type TEXT, timestamp TEXT, actor TEXT, "
                           "payload_json TEXT, parent_event_ids_json TEXT)")
        connection.execute("INSERT INTO provenance_events VALUES (1, ?, ?, ?, ?, ?, ?, ?)", (
            str(event.event_id), str(event.run_id), event.event_type, event.timestamp.isoformat(),
            event.actor, json.dumps(event.payload), "[]",
        ))
    graph = tmp_path / "graph.json"
    graph.write_text(json.dumps(runtime_graph_from_events((event,))), encoding="utf-8")
    monkeypatch.setattr(module, "benchmark_source_identity", lambda _: (COMMIT, False))
    monkeypatch.setattr(module, "validate_benchmark_environment", lambda *_: {})
    return dict(repository=repository, suite=suite, suite_bytes=SUITE_PATH.read_bytes(),
                protocol_bytes=b"fixture protocol", vault=vault, ledger=ledger, runtime_graph=graph)


def test_snapshot_freezes_complete_evidence_and_preserves_originals(inputs: dict, tmp_path: Path) -> None:
    before = hashlib.sha256(inputs["ledger"].read_bytes()).hexdigest()
    snapshot = capture_evidence_snapshot(**inputs)
    assert len(snapshot.tasks) == 100
    assert snapshot.stage == "AWAITING_BROKER_REPLAY"
    assert sum(doc.kind == "note" for doc in snapshot.documents) == 6
    assert "OUT_OF_SCOPE_PRIVATE_CONTENT" not in snapshot.model_dump_json()
    contexts = snapshot_baselines(snapshot)
    assert "planning.completed" in contexts["CTX-RUNTIME-001"]
    assert "Complete source" not in contexts["CTX-RUNTIME-001"]
    assert all(f"Complete frozen note {path}" in contexts["CTX-DECISION-001"] for path in NOTE_PATHS)
    assert "Complete source" not in contexts["CTX-DECISION-001"]
    assert "Complete source" in contexts["CTX-MIXED-001"]
    assert "ledger://events" in contexts["CTX-MIXED-001"]
    assert hashlib.sha256(inputs["ledger"].read_bytes()).hexdigest() == before
    path = tmp_path / "snapshot.json"
    write_local_json(path, snapshot, private=True)
    assert path.stat().st_mode & 0o777 == 0o600
    assert load_evidence_snapshot(path) == snapshot
    (inputs["vault"] / NOTE_PATHS[0]).write_text("Later unrelated change", encoding="utf-8")
    assert snapshot_baselines(load_evidence_snapshot(path)) == contexts
    with pytest.raises(ContextBenchmarkError, match="refusing to overwrite"):
        write_local_json(path, snapshot, private=True)


@pytest.mark.parametrize("target", ["document", "baseline", "tokens", "missing", "duplicate"])
def test_snapshot_rejects_tampering(inputs: dict, target: str) -> None:
    raw = capture_evidence_snapshot(**inputs).model_dump(mode="json")
    if target == "document":
        raw["documents"][0]["text"] += " changed"
    elif target == "baseline":
        raw["tasks"][0]["baseline_sha256"] = "0" * 64
    elif target == "tokens":
        raw["tasks"][0]["estimated_tokens"] += 1
    elif target == "missing":
        raw["tasks"][0]["baseline_locators"] = ["repo://missing.py"]
    else:
        raw["tasks"][1] = raw["tasks"][0]
    with pytest.raises(ValueError):
        ContextEvidenceSnapshot.model_validate(raw)


def test_stale_runtime_graph_rejected(inputs: dict) -> None:
    graph = json.loads(inputs["runtime_graph"].read_text())
    graph["nodes"][1]["payload"] = {"status": "fabricated"}
    inputs["runtime_graph"].write_text(json.dumps(graph), encoding="utf-8")
    with pytest.raises(ValueError, match="does not match"):
        capture_evidence_snapshot(**inputs)


def test_changed_inputs_abort_capture(inputs: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    read = module._read_text
    counts: dict[Path, int] = {}

    def changing(path: Path, *args: int) -> str:
        counts[path] = counts.get(path, 0) + 1
        text = read(path, *args)
        return text + "changed" if counts[path] > 1 else text

    monkeypatch.setattr(module, "_read_text", changing)
    with pytest.raises(ContextBenchmarkError, match="changed while capturing"):
        capture_evidence_snapshot(**inputs)


def test_clean_binding_and_development_refusal(inputs: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    snapshot = capture_evidence_snapshot(**inputs)
    args = (inputs["suite"], inputs["suite_bytes"], inputs["protocol_bytes"], COMMIT)
    validate_snapshot_binding(snapshot, *args)
    with pytest.raises(ContextBenchmarkError, match="protocol differs"):
        validate_snapshot_binding(snapshot, args[0], args[1], b"changed", COMMIT)
    monkeypatch.setattr(module, "benchmark_source_identity", lambda _: (COMMIT, True))
    with pytest.raises(ContextBenchmarkError, match="clean commit"):
        capture_evidence_snapshot(**inputs)
    development = capture_evidence_snapshot(**inputs, development=True)
    with pytest.raises(ContextBenchmarkError, match="clean evaluated"):
        validate_snapshot_binding(development, *args)


@pytest.mark.parametrize("kind", ["file", "parent"])
def test_note_symlinks_are_rejected(inputs: dict, kind: str, tmp_path: Path) -> None:
    vault = inputs["vault"]
    target = vault / NOTE_PATHS[0]
    if kind == "file":
        target.unlink()
        target.symlink_to(vault / NOTE_PATHS[1])
    else:
        brain = vault / "brain"
        brain.rename(tmp_path / "outside")
        brain.symlink_to(tmp_path / "outside", target_is_directory=True)
    with pytest.raises(ContextBenchmarkError, match="symlink"):
        capture_evidence_snapshot(**inputs)


def test_bounds_fail_without_truncation(inputs: dict, monkeypatch: pytest.MonkeyPatch) -> None:
    suite = inputs["suite"].model_copy(update={"maximum_baseline_tokens": 1})
    with pytest.raises(ContextBenchmarkError, match="exceeds token limit"):
        capture_evidence_snapshot(**{**inputs, "suite": suite})
    monkeypatch.setattr(module, "_MAX_EVENTS", 0)
    with pytest.raises(ContextBenchmarkError, match="count/byte bounds"):
        read_ledger_events(inputs["ledger"])


def test_missing_ledger_is_not_created(tmp_path: Path) -> None:
    path = tmp_path / "missing.sqlite3"
    with pytest.raises(ContextBenchmarkError):
        read_ledger_events(path)
    assert not path.exists()


def test_missing_parent_and_duplicate_events_rejected(inputs: dict) -> None:
    with sqlite3.connect(inputs["ledger"]) as connection:
        connection.execute("UPDATE provenance_events SET parent_event_ids_json = ?",
                           (json.dumps([str(uuid4())]),))
    with pytest.raises(ContextBenchmarkError, match="missing parent"):
        read_ledger_events(inputs["ledger"])
    with sqlite3.connect(inputs["ledger"]) as connection:
        connection.execute("UPDATE provenance_events SET parent_event_ids_json = '[]'")
        connection.execute("INSERT INTO provenance_events SELECT * FROM provenance_events")
    with pytest.raises(ContextBenchmarkError, match="duplicate ledger"):
        read_ledger_events(inputs["ledger"])
