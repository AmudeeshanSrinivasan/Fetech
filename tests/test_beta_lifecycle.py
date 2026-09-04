"""Beta run-lifecycle, cancellation, and trace conformance."""

from __future__ import annotations

import asyncio
import threading
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from fetech.adapters.base import ExecutionContext
from fetech.cli import app as cli_app
from fetech.client import FetechClient
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.ledger import EventLedger
from fetech.models import (
    AttemptStatus,
    Diagnostic,
    FetchAttempt,
    FetchRequest,
    FetchResult,
    FetchRun,
    PlanNode,
    ProvenanceEvent,
    ResultStatus,
    RunState,
)


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


class _BlockingAdapter:
    def __init__(self) -> None:
        self.started = threading.Event()

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        context.attempts.append(
            FetchAttempt(
                capability_id=node.capability_id,
                sanitized_destination=context.request.target,
                status=AttemptStatus.RUNNING,
            )
        )
        self.started.set()
        await asyncio.Event().wait()


def _block_gateway(gateway: UniversalFetchGateway) -> _BlockingAdapter:
    adapter = _BlockingAdapter()
    gateway.adapters["core"] = adapter
    gateway.executor.adapters = gateway.adapters
    return adapter


def _assert_cancelled(snapshot: FetchRun) -> None:
    assert snapshot.state == RunState.FINISHED
    assert snapshot.result is not None
    assert snapshot.result.status == ResultStatus.FAILED
    assert [diagnostic.code for diagnostic in snapshot.result.diagnostics][-1] == "run_cancelled"
    assert snapshot.result.attempts[-1].status == AttemptStatus.CANCELLED
    assert snapshot.result.attempts[-1].failure_code == "execution_cancelled"


@pytest.mark.asyncio
async def test_sdk_cancel_is_idempotent_and_waiter_cancellation_does_not_cancel_run(
    tmp_path: Path,
) -> None:
    client = FetechClient(_settings(tmp_path))
    adapter = _block_gateway(client.gateway)
    handle = await client.submit(FetchRequest(target="https://example.com"))
    assert await asyncio.to_thread(adapter.started.wait, 1)

    waiter = asyncio.create_task(handle.result())
    await asyncio.sleep(0)
    waiter.cancel()
    with pytest.raises(asyncio.CancelledError):
        await waiter
    assert (await handle.snapshot()).state == RunState.RUNNING

    first = await handle.cancel()
    second = await client.cancel(handle.run_id)
    _assert_cancelled(first)
    assert second == first
    assert await handle.result() == first.result

    events = tuple([event async for event in handle.events()])
    event_types = [event.event_type for event in events]
    assert event_types.count("run.cancelled") == 1
    assert "run.finished" not in event_types
    assert event_types[-1] == "run.cancelled"
    assert events[-1].payload == {"code": "run_cancelled", "reason": "requested"}
    await client.close()


@pytest.mark.asyncio
async def test_cancelling_foreground_fetch_finalizes_its_durable_run(tmp_path: Path) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))
    adapter = _block_gateway(gateway)
    fetch = asyncio.create_task(gateway.fetch(FetchRequest(target="https://example.com")))
    assert await asyncio.to_thread(adapter.started.wait, 1)
    [(run_id, _, _, _)] = await gateway.ledger.unfinished_runs()

    fetch.cancel()
    with pytest.raises(asyncio.CancelledError):
        await fetch

    snapshot = await gateway.get_run(run_id)
    _assert_cancelled(snapshot)
    events = await gateway.provenance(run_id)
    assert events[-1].event_type == "run.cancelled"
    assert events[-1].payload["reason"] == "caller_cancelled"
    await gateway.close()


@pytest.mark.asyncio
async def test_gateway_shutdown_finalizes_active_runs_before_closing_ledger(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    gateway = UniversalFetchGateway(settings)
    adapter = _block_gateway(gateway)
    submitted = await gateway.submit(FetchRequest(target="https://example.com"))
    assert await asyncio.to_thread(adapter.started.wait, 1)

    await gateway.close()

    ledger = EventLedger.sqlite(settings.database_path)
    await ledger.initialize()
    state, _, result = await ledger.run_snapshot(submitted.run_id)
    events = await ledger.events(submitted.run_id)
    assert state == RunState.FINISHED
    assert result is not None
    assert result.diagnostics[-1].code == "run_cancelled"
    assert events[-1].event_type == "run.cancelled"
    assert events[-1].payload["reason"] == "shutdown"
    await ledger.close()


@pytest.mark.asyncio
async def test_planning_cancellation_cannot_leave_an_orphaned_queued_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))
    started = asyncio.Event()

    async def block_plan(_: FetchRequest) -> None:
        started.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(gateway.logic, "plan", block_plan)
    submission = asyncio.create_task(gateway.submit(FetchRequest(target="https://example.com")))
    await asyncio.wait_for(started.wait(), 1)
    [(run_id, state, _, _)] = await gateway.ledger.unfinished_runs()
    assert state == RunState.PLANNING

    submission.cancel()
    with pytest.raises(asyncio.CancelledError):
        await submission

    snapshot = await gateway.get_run(run_id)
    assert snapshot.state == RunState.FINISHED
    assert snapshot.result is not None
    assert snapshot.result.diagnostics[-1].code == "run_cancelled"
    assert (await gateway.provenance(run_id))[-1].event_type == "run.cancelled"
    await gateway.close()


@pytest.mark.asyncio
async def test_atomic_terminal_transition_allows_exactly_one_winner(tmp_path: Path) -> None:
    ledger = EventLedger.sqlite(tmp_path / "ledger.sqlite3")
    await ledger.initialize()
    run_id = uuid4()
    request = FetchRequest(target="https://example.com")
    await ledger.create_run(run_id, request.model_dump(mode="json"), datetime.now(UTC))

    events = (
        ProvenanceEvent(run_id=run_id, event_type="run.finished", actor="test"),
        ProvenanceEvent(run_id=run_id, event_type="run.cancelled", actor="test"),
    )
    results = tuple(
        FetchResult(
            run_id=run_id,
            status=ResultStatus.SUCCEEDED if index == 0 else ResultStatus.FAILED,
            diagnostics=(Diagnostic(code=f"terminal_{index}", message="bounded"),),
            provenance_event_ids=(event.event_id,),
        )
        for index, event in enumerate(events)
    )

    winners = await asyncio.gather(
        *(ledger.finish_run(event, result) for event, result in zip(events, results, strict=True))
    )
    assert sorted(winners) == [False, True]
    stored_events = await ledger.events(run_id)
    assert len(stored_events) == 1
    _, _, stored_result = await ledger.run_snapshot(run_id)
    assert stored_result is not None
    assert stored_events[0].event_id in stored_result.provenance_event_ids
    await ledger.close()


def test_rest_cancel_sse_and_unknown_run_contracts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    from fetech.daemon import create_app

    application = create_app()
    adapter = _block_gateway(application.state.gateway)
    with TestClient(application) as client:
        submitted = client.post("/v1/fetch", json={"target": "https://example.com"})
        assert submitted.status_code == 202, submitted.text
        run_id = submitted.json()["run_id"]
        assert adapter.started.wait(1)

        cancelled = client.delete(f"/v1/runs/{run_id}")
        repeated = client.delete(f"/v1/runs/{run_id}")
        stream = client.get(f"/v1/runs/{run_id}/events")
        unknown = uuid4()
        missing_run = client.delete(f"/v1/runs/{unknown}")
        missing_stream = client.get(f"/v1/runs/{unknown}/events")

    assert cancelled.status_code == 200, cancelled.text
    assert repeated.json() == cancelled.json()
    _assert_cancelled(FetchRun.model_validate(cancelled.json()))
    assert stream.status_code == 200
    assert stream.text.count("event: run.cancelled") == 1
    assert "event: run.finished" not in stream.text
    assert missing_run.status_code == 404
    assert missing_stream.status_code == 404


@pytest.mark.asyncio
async def test_mcp_submit_cancel_and_trace_use_the_same_terminal_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import fetech.mcp_server as mcp_module

    gateway = UniversalFetchGateway(_settings(tmp_path))
    adapter = _block_gateway(gateway)
    monkeypatch.setattr(mcp_module, "UniversalFetchGateway", lambda **_: gateway)
    tools: dict[str, Any] = mcp_module.build_server()._tool_manager._tools

    submitted = FetchRun.model_validate_json(
        await tools["submit_fetch"].fn(target="https://example.com")
    )
    assert await asyncio.to_thread(adapter.started.wait, 1)
    cancelled = FetchRun.model_validate_json(
        await tools["cancel_fetch"].fn(str(submitted.run_id))
    )
    trace = await tools["get_fetch_trace"].fn(str(submitted.run_id))
    provenance = await tools["query_provenance"].fn(str(submitted.run_id))

    _assert_cancelled(cancelled)
    assert trace.count("run.cancelled") == 1
    assert provenance.count("run.cancelled") == 1
    with pytest.raises(KeyError, match="unknown run"):
        await tools["query_provenance"].fn(str(uuid4()))
    await gateway.close()


def test_cli_cancel_targets_the_owning_daemon_without_following_redirects(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    run_id = uuid4()
    snapshot = FetchRun(
        run_id=run_id,
        state=RunState.FINISHED,
        submitted_at=datetime.now(UTC),
        result=FetchResult(
            run_id=run_id,
            status=ResultStatus.FAILED,
            diagnostics=(Diagnostic(code="run_cancelled", message="cancelled"),),
        ),
    )
    observed: dict[str, object] = {}

    def respond(method: str, url: str, **kwargs: object) -> httpx.Response:
        observed.update(method=method, url=url, **kwargs)
        return httpx.Response(
            200,
            json=snapshot.model_dump(mode="json"),
            request=httpx.Request(method, url),
        )

    monkeypatch.setattr("fetech.cli.httpx.request", respond)
    invocation = CliRunner().invoke(cli_app, ["cancel", str(run_id)])

    assert invocation.exit_code == 0, invocation.output
    assert FetchRun.model_validate_json(invocation.output) == snapshot
    assert observed == {
        "method": "DELETE",
        "url": f"http://127.0.0.1:8787/v1/runs/{run_id}",
        "timeout": 10.0,
        "follow_redirects": False,
    }


@pytest.mark.parametrize(
    "daemon_url",
    [
        "file:///tmp/fetech.sock",
        "http://operator@example.com",
        "http://example.com/base",
        "http://example.com?query=1",
    ],
)
def test_cli_cancel_rejects_ambiguous_daemon_origins(
    daemon_url: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(
        "fetech.cli.httpx.request",
        lambda *_args, **_kwargs: pytest.fail("called"),
    )
    invocation = CliRunner().invoke(
        cli_app,
        ["cancel", str(uuid4()), "--daemon-url", daemon_url],
    )

    assert invocation.exit_code != 0
    assert "daemon URL must be an HTTP(S) origin" in invocation.output
