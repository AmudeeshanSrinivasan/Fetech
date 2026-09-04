from __future__ import annotations

import asyncio
import sys
from dataclasses import replace
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock
from urllib.parse import urlsplit
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.config import Settings
from fetech.context import ContextBroker, ContextBudget, _ProcessResult, _run
from fetech.daemon import create_app
from fetech.executor import ExecutionEngine
from fetech.gateway import UniversalFetchGateway
from fetech.http3 import _MARKER, CurlHTTP3Client, HTTP3Response
from fetech.ledger import EventLedger
from fetech.logic.process import ProcessResult
from fetech.models import (
    Artifact,
    AttemptStatus,
    FetchAttempt,
    FetchPlan,
    FetchRequest,
    FetchResult,
    PlanNode,
    ProvenanceEvent,
    QualityAssessment,
    Resource,
    ResourceBudget,
    ResultStatus,
    RetryRule,
    RunState,
)
from fetech.security import normalize_url, sanitize_url
from fetech.storage import FileSystemCAS


def _settings(root: Path) -> Settings:
    return replace(
        Settings.from_environment(),
        data_dir=root,
        database_path=root / "ledger.sqlite3",
        artifact_dir=root / "artifacts",
        runtime_graph_path=root / "runtime-graph.json",
    )


@pytest.mark.asyncio
async def test_event_stream_cannot_lose_event_between_history_and_subscription(
    tmp_path: Path,
) -> None:
    ledger = EventLedger.sqlite(tmp_path / "events.sqlite3")
    await ledger.initialize()
    request = FetchRequest(target="https://example.com/")
    run_id = uuid4()
    await ledger.create_run(run_id, request.model_dump(mode="json"), datetime.now(UTC))
    await ledger.append(ProvenanceEvent(run_id=run_id, event_type="first", actor="test"))

    stream = ledger.stream(run_id)
    assert (await anext(stream)).event_type == "first"
    await ledger.append(ProvenanceEvent(run_id=run_id, event_type="between", actor="test"))
    assert (await asyncio.wait_for(anext(stream), 0.5)).event_type == "between"

    await ledger.update_run(run_id, RunState.FINISHED)
    with pytest.raises(StopAsyncIteration):
        await anext(stream)
    await ledger.close()


@pytest.mark.asyncio
async def test_gateway_restores_artifacts_and_finalizes_interrupted_runs(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path)
    request = FetchRequest(target="https://example.com/")
    ledger = EventLedger.sqlite(settings.database_path)
    await ledger.initialize()

    completed_id = uuid4()
    await ledger.create_run(
        completed_id,
        request.model_dump(mode="json"),
        datetime.now(UTC),
    )
    cas = FileSystemCAS(settings.artifact_dir)
    uri, digest, size = await cas.put(b"persisted artifact")
    resource = Resource(canonical_url=request.target, requested_url=request.target)
    artifact = Artifact(
        role="primary",
        representation="raw",
        media_type="text/plain",
        cas_uri=uri,
        sha256=digest,
        size=size,
        source_resource_id=resource.resource_id,
        extractor_version="test",
        quality=QualityAssessment(accepted=True),
    )
    await ledger.update_run(
        completed_id,
        RunState.FINISHED,
        FetchResult(
            run_id=completed_id,
            status=ResultStatus.SUCCEEDED,
            resources=(resource,),
            artifacts=(artifact,),
            remaining_budget=request.budget,
        ),
    )

    interrupted_id = uuid4()
    await ledger.create_run(
        interrupted_id,
        request.model_dump(mode="json"),
        datetime.now(UTC),
    )
    await ledger.update_run(interrupted_id, RunState.RUNNING)
    await ledger.close()

    gateway = UniversalFetchGateway(settings)
    await gateway.initialize()
    assert gateway.get_artifact(artifact.artifact_id) == artifact
    recovered = await gateway.wait(interrupted_id)
    assert recovered.status == ResultStatus.FAILED
    assert any(item.code == "run_interrupted" for item in recovered.diagnostics)
    assert (await gateway.get_run(interrupted_id)).state == RunState.FINISHED
    events = await gateway.ledger.events(interrupted_id)
    assert events[-1].event_type == "run.recovered_interrupted"
    await gateway.close()


class _ConcurrentAdapter:
    def __init__(self) -> None:
        self.started: set[str] = set()
        self.both_started = asyncio.Event()

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        self.started.add(node.id)
        if len(self.started) == 2:
            self.both_started.set()
        await asyncio.wait_for(self.both_started.wait(), 0.5)
        context.attempts.append(
            FetchAttempt(
                capability_id=node.capability_id,
                sanitized_destination=context.request.target,
                status=AttemptStatus.SUCCEEDED,
                finished_at=datetime.now(UTC),
            )
        )


class _EarlyStopAdapter:
    def __init__(self) -> None:
        self.loser_started = asyncio.Event()
        self.loser_cancelled = asyncio.Event()

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=context.request.target,
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        if node.id == "winner":
            await asyncio.wait_for(self.loser_started.wait(), 0.5)
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.SUCCEEDED,
                    "finished_at": datetime.now(UTC),
                }
            )
            context.accepted = True
            return
        if node.id == "loser":
            self.loser_started.set()
            try:
                await asyncio.Event().wait()
            finally:
                self.loser_cancelled.set()
            return
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
            }
        )


@pytest.mark.asyncio
async def test_executor_runs_ready_parallel_group_concurrently(tmp_path: Path) -> None:
    ledger = EventLedger.sqlite(tmp_path / "events.sqlite3")
    await ledger.initialize()
    request = FetchRequest(
        target="https://example.com/",
        budget=ResourceBudget(attempts=2),
    )
    run_id = uuid4()
    await ledger.create_run(run_id, request.model_dump(mode="json"), datetime.now(UTC))
    nodes = tuple(
        PlanNode(
            id=f"node-{index}",
            capability_id=f"capability-{index}",
            adapter="concurrent",
            parallel_group="test-group",
            retry=RetryRule(maximum=0),
        )
        for index in range(2)
    )
    adapter = _ConcurrentAdapter()
    engine = ExecutionEngine(
        adapters={"concurrent": adapter},
        cas=FileSystemCAS(tmp_path / "cas"),
        ledger=ledger,
    )

    result = await engine.execute(run_id, FetchPlan(request=request, nodes=nodes))

    assert adapter.started == {"node-0", "node-1"}
    assert len(result.attempts) == 2
    assert result.remaining_budget.attempts == 0
    await ledger.close()


@pytest.mark.asyncio
async def test_executor_cancels_losing_parallel_branch_and_resolves_group(
    tmp_path: Path,
) -> None:
    ledger = EventLedger.sqlite(tmp_path / "events.sqlite3")
    await ledger.initialize()
    request = FetchRequest(
        target="https://example.com/",
        budget=ResourceBudget(attempts=3),
    )
    run_id = uuid4()
    await ledger.create_run(run_id, request.model_dump(mode="json"), datetime.now(UTC))
    nodes = (
        PlanNode(
            id="winner",
            capability_id="winner",
            adapter="early-stop",
            parallel_group="alternatives",
            stop_on_acceptance=True,
            retry=RetryRule(maximum=0),
        ),
        PlanNode(
            id="loser",
            capability_id="loser",
            adapter="early-stop",
            parallel_group="alternatives",
            stop_on_acceptance=True,
            retry=RetryRule(maximum=0),
        ),
        PlanNode(
            id="downstream",
            capability_id="downstream",
            adapter="early-stop",
            dependencies=("loser",),
            retry=RetryRule(maximum=0),
        ),
    )
    adapter = _EarlyStopAdapter()
    engine = ExecutionEngine(
        adapters={"early-stop": adapter},
        cas=FileSystemCAS(tmp_path / "cas"),
        ledger=ledger,
    )

    result = await engine.execute(run_id, FetchPlan(request=request, nodes=nodes))

    assert adapter.loser_cancelled.is_set()
    assert [attempt.status for attempt in result.attempts] == [
        AttemptStatus.SUCCEEDED,
        AttemptStatus.CANCELLED,
        AttemptStatus.SUCCEEDED,
    ]
    assert any(event.event_type == "attempt.cancelled" for event in await ledger.events(run_id))
    assert any(outcome.capability_id == "downstream" for outcome in result.capability_outcomes)
    await ledger.close()


@pytest.mark.asyncio
async def test_retry_rule_honors_codes_and_backoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target="https://example.com/"),
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    node = PlanNode(
        id="retry",
        capability_id="http_get",
        adapter="test",
        retry=RetryRule(
            maximum=1,
            backoff_seconds=0.25,
            retryable_codes=("connection",),
        ),
    )
    sleep = AsyncMock()
    monkeypatch.setattr("fetech.executor.asyncio.sleep", sleep)
    calls = 0

    async def transient(_: PlanNode, __: ExecutionContext) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise AdapterExecutionError("transient", code="connection")

    await ExecutionEngine._with_retries(transient, node, context, node.retry)
    assert calls == 2
    sleep.assert_awaited_once_with(0.25)

    calls = 0

    async def permanent(_: PlanNode, __: ExecutionContext) -> None:
        nonlocal calls
        calls += 1
        raise AdapterExecutionError("permanent", code="validation")

    with pytest.raises(AdapterExecutionError, match="permanent"):
        await ExecutionEngine._with_retries(permanent, node, context, node.retry)
    assert calls == 1


@pytest.mark.asyncio
async def test_context_broker_requires_explicit_scoped_vault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runner = AsyncMock(return_value=_ProcessResult(0, "[]", ""))
    monkeypatch.setattr("fetech.context._run", runner)
    broker = ContextBroker(tmp_path, vault=None)
    assert await broker._qmd("private topic", 100) == []
    runner.assert_not_awaited()

    vault = tmp_path / "vault"
    vault.mkdir()
    inside = vault / "inside.md"
    outside = tmp_path / "outside.md"
    runner.return_value = _ProcessResult(
        0,
        __import__("json").dumps(
            [
                {"title": "inside", "file": str(inside), "snippet": "allowed", "score": 1},
                {"title": "outside", "file": str(outside), "snippet": "blocked", "score": 1},
            ]
        ),
        "",
    )
    scoped = ContextBroker(tmp_path, vault=vault)
    sources = await scoped._qmd("topic", 100)
    assert [source.locator for source in sources] == [str(inside)]


@pytest.mark.asyncio
async def test_context_limits_inputs_processes_and_omission_count(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ValueError, match="QMD note limit"):
        ContextBudget(qmd_notes=0)
    broker = ContextBroker(tmp_path)
    with pytest.raises(ValueError, match="positive integer"):
        await broker.search("question", token_budget=0)
    with pytest.raises(ValueError, match="bounded byte"):
        await broker.search("q" * 16_385)

    too_large = await _run(
        sys.executable,
        "-c",
        "print('x' * 1000)",
        cwd=tmp_path,
        maximum_output_bytes=100,
    )
    assert too_large.returncode == 125
    timed_out = await _run(
        sys.executable,
        "-c",
        "import time; time.sleep(1)",
        cwd=tmp_path,
        timeout_seconds=0.01,
    )
    assert timed_out.returncode == 124

    vault = tmp_path / "vault"
    vault.mkdir()
    documents = [
        {
            "title": f"note-{index}",
            "file": str(vault / f"note-{index}.md"),
            "snippet": f"excerpt-{index}",
            "score": 1,
        }
        for index in range(4)
    ]

    async def fake_run(*arguments: str, **_: Any) -> _ProcessResult:
        if arguments[0] == "qmd":
            return _ProcessResult(0, __import__("json").dumps(documents), "")
        return _ProcessResult(1, "", "")

    monkeypatch.setattr("fetech.context._run", fake_run)
    result = await ContextBroker(tmp_path, vault=vault).search("notes")
    assert len(result.sources) == 3
    assert result.omitted_results == 1


def test_fetch_request_rejects_unbounded_public_fields() -> None:
    with pytest.raises(ValidationError):
        FetchRequest(target="https://example.com/" + "a" * 16_384)
    with pytest.raises(ValidationError):
        FetchRequest(
            target="https://example.com/",
            allow_capabilities=frozenset(f"capability-{index}" for index in range(257)),
        )
    with pytest.raises(ValidationError):
        FetchRequest(
            target="https://example.com/",
            metadata={"key": "x" * 65_537},
        )


@pytest.mark.parametrize("operation", [normalize_url, sanitize_url])
def test_ipv6_url_rendering_preserves_required_brackets(operation: Any) -> None:
    rendered = operation("https://[2606:4700:4700::1111]:8443/a?x=1")
    parsed = urlsplit(rendered)
    assert rendered.startswith("https://[2606:4700:4700::1111]:8443/")
    assert parsed.hostname == "2606:4700:4700::1111"
    assert parsed.port == 8443


@pytest.mark.asyncio
async def test_http3_curl_disables_user_configuration(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, ...]] = []

    async def bounded(arguments: tuple[str, ...], _: bytes, **__: Any) -> ProcessResult:
        calls.append(arguments)
        stdout = (
            b"curl test HTTP3" if "--version" in arguments else b"body" + _MARKER + b"200\ttext/plain\t\t3"
        )
        return ProcessResult(0, stdout, b"")

    monkeypatch.setattr("fetech.http3.shutil.which", lambda _: "/usr/bin/curl")
    monkeypatch.setattr("fetech.http3.run_bounded", bounded)
    response: HTTP3Response = await CurlHTTP3Client().fetch(
        "https://example.com/",
        address="93.184.216.34",
        user_agent="Fetech/test",
        timeout_seconds=1,
        maximum_bytes=1_000,
    )
    assert response.body == b"body"
    assert all(arguments[1] == "--disable" for arguments in calls)


@pytest.mark.asyncio
async def test_cas_verify_is_total_for_invalid_or_missing_uris(tmp_path: Path) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    assert await cas.verify("not-a-cas-uri") is False
    assert await cas.verify("cas://sha256/" + "0" * 64) is False


def test_daemon_returns_typed_context_and_artifact_boundary_errors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "runtime"))
    application = create_app()

    with TestClient(application) as client:
        oversized = client.post(
            "/v1/context/search",
            params={"question": "☃" * 6_000},
        )
        assert oversized.status_code == 422

        source_id = uuid4()
        missing = Artifact(
            role="primary",
            representation="raw",
            media_type="text/plain",
            cas_uri="cas://sha256/" + "0" * 64,
            sha256="0" * 64,
            size=1,
            source_resource_id=source_id,
            extractor_version="test",
        )
        application.state.gateway._artifacts[missing.artifact_id] = missing
        missing_response = client.get(
            f"/v1/artifacts/{missing.artifact_id}",
            params={"content": "true"},
        )
        assert missing_response.status_code == 404

        uri, digest, size = asyncio.run(application.state.gateway.cas.put(b"bounded artifact"))
        bounded = missing.model_copy(
            update={
                "artifact_id": uuid4(),
                "cas_uri": uri,
                "sha256": digest,
                "size": size,
            }
        )
        application.state.gateway._artifacts[bounded.artifact_id] = bounded
        bounded_response = client.get(
            f"/v1/artifacts/{bounded.artifact_id}",
            params={"content": "true", "maximum_bytes": 1},
        )
        assert bounded_response.status_code == 413

        corrupt_digest = "1" * 64
        corrupt_path = (
            application.state.gateway.cas.root / corrupt_digest[:2] / corrupt_digest[2:4] / corrupt_digest
        )
        corrupt_path.parent.mkdir(parents=True)
        corrupt_path.write_bytes(b"not the declared digest")
        corrupt = missing.model_copy(
            update={
                "artifact_id": uuid4(),
                "cas_uri": f"cas://sha256/{corrupt_digest}",
                "sha256": corrupt_digest,
                "size": len(b"not the declared digest"),
            }
        )
        application.state.gateway._artifacts[corrupt.artifact_id] = corrupt
        corrupt_response = client.get(
            f"/v1/artifacts/{corrupt.artifact_id}",
            params={"content": "true"},
        )
        assert corrupt_response.status_code == 409
