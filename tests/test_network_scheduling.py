from __future__ import annotations

import asyncio
import json
from collections import defaultdict
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from fetech.adapters.base import ExecutionContext
from fetech.adapters.cache import CacheAdapter
from fetech.adapters.http import HTTPAdapter
from fetech.adapters.media import MediaAdapter
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.logic.process import ProcessResult
from fetech.models import FetchRequest, ResourceBudget, ResultStatus
from fetech.scheduling import (
    NetworkDeadlineExceededError,
    NetworkScheduler,
    _normalize_host,
)
from fetech.security import SafeURLPolicy
from fetech.storage import FileSystemCAS
from fetech.wayback import PinnedWaybackHTTPClient, WaybackSnapshotConnector
from fetech.yt_dlp import YTDLPMetadataWorker


@pytest.mark.asyncio
async def test_scheduler_enforces_global_and_per_host_concurrency() -> None:
    scheduler = NetworkScheduler(
        global_concurrency=2,
        per_host_concurrency=1,
    )
    active_global = 0
    active_by_host: defaultdict[str, int] = defaultdict(int)
    maximum_global = 0
    maximum_by_host: defaultdict[str, int] = defaultdict(int)

    async def work(host: str) -> None:
        nonlocal active_global, maximum_global
        async with scheduler.slot(host, deadline_seconds=1):
            active_global += 1
            active_by_host[host] += 1
            maximum_global = max(maximum_global, active_global)
            maximum_by_host[host] = max(
                maximum_by_host[host],
                active_by_host[host],
            )
            await asyncio.sleep(0.02)
            active_by_host[host] -= 1
            active_global -= 1

    await asyncio.gather(
        work("a.example"),
        work("a.example"),
        work("b.example"),
        work("b.example"),
    )

    assert maximum_global == 2
    assert maximum_by_host == {"a.example": 1, "b.example": 1}


@pytest.mark.asyncio
async def test_scheduler_applies_politeness_between_request_starts() -> None:
    scheduler = NetworkScheduler(
        global_concurrency=2,
        per_host_concurrency=2,
        per_host_min_interval_seconds=0.03,
    )
    started: list[float] = []

    async def work() -> None:
        async with scheduler.slot("example.com", deadline_seconds=1):
            started.append(asyncio.get_running_loop().time())

    await asyncio.gather(work(), work())

    assert len(started) == 2
    assert started[1] - started[0] >= 0.025


@pytest.mark.asyncio
async def test_scheduler_deadline_and_cancellation_do_not_leak_capacity() -> None:
    scheduler = NetworkScheduler(
        global_concurrency=1,
        per_host_concurrency=1,
    )
    entered = asyncio.Event()

    async def hold() -> None:
        async with scheduler.slot("example.com", deadline_seconds=1):
            entered.set()
            await asyncio.Event().wait()

    holder = asyncio.create_task(hold())
    await entered.wait()

    with pytest.raises(
        NetworkDeadlineExceededError,
        match="deadline is exhausted",
    ):
        async with scheduler.slot("example.com", deadline_seconds=0.01):
            raise AssertionError("queued operation must not enter")

    holder.cancel()
    holder.cancel()
    with pytest.raises(asyncio.CancelledError):
        await holder

    async with scheduler.slot("example.com", deadline_seconds=0.1):
        pass


@pytest.mark.asyncio
async def test_scheduler_preserves_unrelated_operation_timeout() -> None:
    scheduler = NetworkScheduler()
    operation_timeout = TimeoutError("operation-specific timeout")

    with pytest.raises(TimeoutError) as raised:
        async with scheduler.slot("example.com", deadline_seconds=1):
            raise operation_timeout

    assert raised.value is operation_timeout
    assert not isinstance(raised.value, NetworkDeadlineExceededError)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "deadline_seconds",
    [True, 0, -1, float("inf"), float("nan")],
)
async def test_scheduler_rejects_invalid_deadline_with_typed_error(
    deadline_seconds: object,
) -> None:
    scheduler = NetworkScheduler()

    with pytest.raises(
        NetworkDeadlineExceededError,
        match="deadline is exhausted",
    ):
        async with scheduler.slot(
            "example.com",
            deadline_seconds=deadline_seconds,  # type: ignore[arg-type]
        ):
            raise AssertionError("invalid deadline must not acquire capacity")


@pytest.mark.asyncio
async def test_scheduler_admits_waiters_fifo_without_host_head_of_line() -> None:
    scheduler = NetworkScheduler(
        global_concurrency=2,
        per_host_concurrency=1,
    )
    holder_entered = asyncio.Event()
    release_holder = asyncio.Event()
    order: list[str] = []

    async def hold_busy_host() -> None:
        async with scheduler.slot("busy.example", deadline_seconds=1):
            holder_entered.set()
            await release_holder.wait()

    async def record(host: str) -> None:
        async with scheduler.slot(host, deadline_seconds=1):
            order.append(host)

    holder = asyncio.create_task(hold_busy_host())
    await holder_entered.wait()
    blocked_same_host = asyncio.create_task(record("busy.example"))
    await asyncio.sleep(0)
    eligible_cold_host = asyncio.create_task(record("cold.example"))

    await eligible_cold_host
    assert order == ["cold.example"]
    release_holder.set()
    await asyncio.gather(holder, blocked_same_host)
    assert order == ["cold.example", "busy.example"]


@pytest.mark.asyncio
async def test_scheduler_preserves_fifo_order_for_equally_eligible_waiters() -> None:
    scheduler = NetworkScheduler(
        global_concurrency=1,
        per_host_concurrency=1,
    )
    holder_entered = asyncio.Event()
    release_holder = asyncio.Event()
    order: list[str] = []

    async def hold() -> None:
        async with scheduler.slot("holder.example", deadline_seconds=1):
            holder_entered.set()
            await release_holder.wait()

    async def record(host: str) -> None:
        async with scheduler.slot(host, deadline_seconds=1):
            order.append(host)

    holder = asyncio.create_task(hold())
    await holder_entered.wait()
    first = asyncio.create_task(record("first.example"))
    await asyncio.sleep(0)
    second = asyncio.create_task(record("second.example"))
    await asyncio.sleep(0)
    release_holder.set()

    await asyncio.gather(holder, first, second)
    assert order == ["first.example", "second.example"]


@pytest.mark.asyncio
async def test_scheduler_bounds_and_evicts_politeness_history() -> None:
    scheduler = NetworkScheduler(
        global_concurrency=2,
        per_host_concurrency=1,
        per_host_min_interval_seconds=0.03,
        host_history_limit=2,
    )

    for host in ("one.example", "two.example"):
        async with scheduler.slot(host, deadline_seconds=1):
            pass

    third_entered = asyncio.Event()

    async def use_third_host() -> None:
        async with scheduler.slot("three.example", deadline_seconds=1):
            third_entered.set()

    third = asyncio.create_task(use_third_host())
    await asyncio.sleep(0)
    assert not third_entered.is_set()
    assert len(scheduler._last_started_at) == 2

    await third
    assert third_entered.is_set()
    assert len(scheduler._last_started_at) <= 2
    assert "three.example" in scheduler._last_started_at


@pytest.mark.asyncio
async def test_zero_interval_does_not_retain_host_history() -> None:
    scheduler = NetworkScheduler(
        per_host_min_interval_seconds=0,
        host_history_limit=1,
    )

    for index in range(10):
        async with scheduler.slot(
            f"host-{index}.example",
            deadline_seconds=1,
        ):
            pass

    assert scheduler._last_started_at == {}


@pytest.mark.parametrize(
    ("host", "expected"),
    [
        ("EXAMPLE.COM.", "example.com"),
        ("bücher.example", "xn--bcher-kva.example"),
        ("192.0.2.1", "192.0.2.1"),
        ("192.0.2.1.", "192.0.2.1"),
        ("[2001:0DB8:0:0::1]", "2001:db8::1"),
    ],
)
def test_scheduler_normalizes_equivalent_hosts(
    host: str,
    expected: str,
) -> None:
    assert _normalize_host(host) == expected


@pytest.mark.parametrize(
    "host",
    [
        "",
        ".",
        " example.com",
        "example.com ",
        "example..com",
        "example.com..",
        "-leading.example",
        "trailing-.example",
        "bad_name.example",
        "example.com:443",
        "[2001:db8::1",
        "[example.com]",
        "[192.0.2.1]",
        "fe80::1%en0",
        "999.999.999.999",
        f"{'a' * 64}.example",
    ],
)
def test_scheduler_rejects_malformed_hosts(host: str) -> None:
    with pytest.raises(ValueError, match="host is invalid"):
        _normalize_host(host)


@pytest.mark.parametrize("host", [None, 123, b"example.com"])
def test_scheduler_rejects_non_string_hosts(host: object) -> None:
    with pytest.raises(ValueError, match="host is invalid"):
        _normalize_host(host)  # type: ignore[arg-type]


@pytest.mark.parametrize("host_history_limit", [True, 0, -1, 1.5])
def test_scheduler_rejects_invalid_host_history_limit(
    host_history_limit: object,
) -> None:
    with pytest.raises(ValueError, match="limits are invalid"):
        NetworkScheduler(
            host_history_limit=host_history_limit,  # type: ignore[arg-type]
        )


@pytest.mark.asyncio
async def test_http_dns_and_request_share_one_scheduler_admission(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = NetworkScheduler(
        global_concurrency=1,
        per_host_concurrency=1,
    )
    policy = SafeURLPolicy()
    observed_active: list[int] = []
    acquisitions = 0
    original_acquire = scheduler._acquire

    async def counted_acquire(host: str) -> None:
        nonlocal acquisitions
        acquisitions += 1
        await original_acquire(host)

    async def public(_host: str, _port: int) -> tuple[str, ...]:
        observed_active.append(scheduler._active_global)
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        observed_active.append(scheduler._active_global)
        return httpx.Response(200, content=b"scheduled")

    monkeypatch.setattr(scheduler, "_acquire", counted_acquire)
    monkeypatch.setattr(policy, "_resolve", public)
    adapter = HTTPAdapter(
        user_agent="Fetech-test/1",
        policy=policy,
        transport=httpx.MockTransport(respond),
        scheduler=scheduler,
    )
    request = FetchRequest(target="https://example.com/resource")
    context = ExecutionContext(
        run_id=uuid4(),
        request=request,
        cas=FileSystemCAS(tmp_path / "cas"),
    )

    response, body, _ = await adapter._request(request.target, context)

    assert response.status_code == 200
    assert body == b"scheduled"
    assert acquisitions == 1
    assert observed_active == [1, 1]
    assert scheduler._active_global == 0


@pytest.mark.asyncio
async def test_direct_http_adapter_deadline_includes_dns_policy_time(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = NetworkScheduler(
        global_concurrency=1,
        per_host_concurrency=1,
    )
    policy = SafeURLPolicy()
    transport_called = False

    async def slow_public(_host: str, _port: int) -> tuple[str, ...]:
        await asyncio.sleep(0.03)
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return httpx.Response(200, content=b"too late")

    monkeypatch.setattr(policy, "_resolve", slow_public)
    adapter = HTTPAdapter(
        user_agent="Fetech-test/1",
        policy=policy,
        transport=httpx.MockTransport(respond),
        scheduler=scheduler,
    )
    request = FetchRequest(
        target="https://example.com/resource",
        budget=ResourceBudget(deadline_seconds=0.01),
    )
    context = ExecutionContext(
        run_id=uuid4(),
        request=request,
        cas=FileSystemCAS(tmp_path / "cas"),
    )

    with pytest.raises(
        NetworkDeadlineExceededError,
        match="deadline is exhausted",
    ):
        await adapter._request(request.target, context)

    assert not transport_called
    assert scheduler._active_global == 0


@pytest.mark.asyncio
async def test_gateway_maps_network_deadline_to_budget_exhausted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph.json",
        per_host_min_interval_seconds=0,
    )
    gateway = UniversalFetchGateway(settings)

    async def slow_public(_host: str, _port: int) -> tuple[str, ...]:
        await asyncio.sleep(0.03)
        return ("93.184.216.34",)

    monkeypatch.setattr(gateway.policy, "_resolve", slow_public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(200, content=b"too late")
        ),
        scheduler=gateway.network_scheduler,
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/resource",
            budget=ResourceBudget(deadline_seconds=0.01),
        )
    )

    assert result.status == ResultStatus.BUDGET_EXHAUSTED
    assert any(
        diagnostic.code == "budget_exhausted"
        for diagnostic in result.diagnostics
    )
    assert any(
        attempt.failure_code == "budget_exhausted"
        for attempt in result.attempts
    )
    await gateway.close()


@pytest.mark.asyncio
async def test_ytdlp_and_wayback_share_one_global_runtime_slot(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scheduler = NetworkScheduler(
        global_concurrency=1,
        per_host_concurrency=1,
    )
    yt_started = asyncio.Event()
    release_yt = asyncio.Event()
    wayback_started = asyncio.Event()

    async def bounded(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        yt_started.set()
        await release_yt.wait()
        return ProcessResult(
            returncode=0,
            stdout=json.dumps(
                {
                    "schema": "fetech.yt_dlp.worker.v1",
                    "status": "succeeded",
                    "network_bytes": 10,
                    "decompressed_bytes": 10,
                    "redirects": 0,
                    "metadata": {
                        "id": "video-1",
                        "title": "Scheduled fixture",
                        "webpage_url": "https://www.youtube.com/watch?v=video-1",
                    },
                },
                separators=(",", ":"),
            ).encode(),
            stderr=b"",
        )

    class MockPinnedTransport(httpx.AsyncBaseTransport):
        def pin(self, host: str, addresses: tuple[str, ...]) -> None:
            assert host == "archive.org"
            assert addresses == ("93.184.216.34",)

        async def handle_async_request(
            self,
            request: httpx.Request,
        ) -> httpx.Response:
            wayback_started.set()
            return httpx.Response(
                200,
                stream=httpx.ByteStream(b"{}"),
                request=request,
            )

    policy = SafeURLPolicy()

    async def public(_host: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    monkeypatch.setattr("fetech.yt_dlp._distribution_version", lambda _: "test")
    monkeypatch.setattr("fetech.yt_dlp.run_bounded", bounded)
    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        MockPinnedTransport,
    )

    yt_worker = YTDLPMetadataWorker(scheduler=scheduler)
    wayback_client = PinnedWaybackHTTPClient(
        policy=policy,
        user_agent="Fetech-test/1",
        scheduler=scheduler,
    )
    yt_task = asyncio.create_task(
        yt_worker.metadata(
            "https://www.youtube.com/watch?v=video-1",
            timeout_seconds=1,
            maximum_output_bytes=10_000,
            maximum_network_bytes=1_000,
            maximum_redirects=1,
        )
    )
    await yt_started.wait()
    wayback_task = asyncio.create_task(
        wayback_client.get(
            "https://archive.org/wayback/available",
            allowed_host="archive.org",
            maximum_bytes=100,
            maximum_redirects=0,
            deadline_seconds=1,
        )
    )

    await asyncio.sleep(0.03)
    assert not wayback_started.is_set()
    release_yt.set()

    yt_result, wayback_result = await asyncio.gather(yt_task, wayback_task)
    assert yt_result.metadata["id"] == "video-1"
    assert wayback_result.body == b"{}"
    assert wayback_started.is_set()


def test_gateway_injects_one_scheduler_into_all_builtin_network_paths(
    tmp_path: Path,
) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph.json",
        global_concurrency=3,
        per_host_concurrency=1,
        per_host_min_interval_seconds=0.25,
    )
    gateway = UniversalFetchGateway(settings)

    http = gateway.adapters["http"]
    media = gateway.adapters["media"]
    cache = gateway.adapters["cache"]
    assert isinstance(http, HTTPAdapter)
    assert isinstance(media, MediaAdapter)
    assert isinstance(cache, CacheAdapter)
    assert isinstance(media.youtube_provider, YTDLPMetadataWorker)
    wayback = cache.connectors["internet_archive_snapshot"]
    assert isinstance(wayback, WaybackSnapshotConnector)
    assert isinstance(wayback.client, PinnedWaybackHTTPClient)
    assert http.scheduler is gateway.network_scheduler
    assert media.youtube_provider.scheduler is gateway.network_scheduler
    assert wayback.client.scheduler is gateway.network_scheduler
