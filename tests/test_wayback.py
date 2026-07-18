"""Hermetic conformance tests for the built-in Internet Archive connector."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from fetech.adapters.base import (
    AdapterBudgetExceededError,
    AdapterExecutionError,
    AdapterNotFoundError,
    ExecutionContext,
)
from fetech.adapters.cache import (
    CacheAdapter,
    SnapshotConnectorUsage,
    SnapshotStore,
)
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import (
    AttemptStatus,
    FetchAttempt,
    FetchRequest,
    PlanNode,
    ResourceBudget,
)
from fetech.security import PolicyBlockedError, SafeURLPolicy
from fetech.storage import FileSystemCAS
from fetech.wayback import (
    PinnedWaybackHTTPClient,
    WaybackHTTPResponse,
    WaybackSnapshotConnector,
)

_ORIGINAL = "https://example.com/article?lang=en"
_TIMESTAMP = "20260102030405"
_RETURNED_CAPTURE = (
    f"http://web.archive.org/web/{_TIMESTAMP}/{_ORIGINAL}"
)
_RAW_CAPTURE = (
    f"https://web.archive.org/web/{_TIMESTAMP}id_/{_ORIGINAL}"
)


@dataclass
class _FixtureHTTPClient:
    responses: list[WaybackHTTPResponse]
    calls: list[tuple[str, str, int, float, int]] = field(default_factory=list)

    async def get(
        self,
        url: str,
        *,
        allowed_host: str,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> WaybackHTTPResponse:
        self.calls.append(
            (
                url,
                allowed_host,
                maximum_bytes,
                deadline_seconds,
                maximum_redirects,
            )
        )
        if not self.responses:
            raise AssertionError("unexpected Wayback HTTP call")
        response = self.responses.pop(0)
        usage.record(
            wire_bytes=len(response.body),
            decompressed_bytes=len(response.body),
        )
        return response


@dataclass
class _PartialTimeoutHTTPClient:
    fail_on_call: int
    partial_body: bytes
    calls: int = 0

    async def get(
        self,
        url: str,
        *,
        allowed_host: str,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> WaybackHTTPResponse:
        del url, allowed_host, maximum_bytes, maximum_redirects, deadline_seconds
        self.calls += 1
        if self.calls == self.fail_on_call:
            usage.record(
                wire_bytes=len(self.partial_body),
                decompressed_bytes=len(self.partial_body),
            )
            raise TimeoutError("private connector timeout detail")
        availability = _availability()
        usage.record(
            wire_bytes=len(availability),
            decompressed_bytes=len(availability),
        )
        return WaybackHTTPResponse(
            status_code=200,
            url="https://archive.org/wayback/available",
            headers={"content-type": "application/json"},
            body=availability,
        )


@dataclass
class _RedirectBudgetHTTPClient:
    maximums: list[int] = field(default_factory=list)

    async def get(
        self,
        url: str,
        *,
        allowed_host: str,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> WaybackHTTPResponse:
        del url, allowed_host, maximum_bytes, deadline_seconds
        self.maximums.append(maximum_redirects)
        usage.record(redirects=1)
        raise AdapterBudgetExceededError("Wayback redirect budget exhausted")


class _MockPinnedTransport(httpx.AsyncBaseTransport):
    def __init__(
        self,
        handler: httpx.AsyncBaseTransport,
    ) -> None:
        self.handler = handler
        self.pins: list[tuple[str, tuple[str, ...]]] = []

    def pin(self, host: str, addresses: tuple[str, ...]) -> None:
        self.pins.append((host, addresses))

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        return await self.handler.handle_async_request(request)

    async def aclose(self) -> None:
        await self.handler.aclose()


class _SlowStream(httpx.AsyncByteStream):
    async def __aiter__(self):
        await asyncio.sleep(0.05)
        yield b"{}"


def _availability(
    *,
    locator: str = _RETURNED_CAPTURE,
    available: bool = True,
    status: str = "200",
    timestamp: str = _TIMESTAMP,
) -> bytes:
    return json.dumps(
        {
            "archived_snapshots": {
                "closest": {
                    "available": available,
                    "status": status,
                    "timestamp": timestamp,
                    "url": locator,
                }
            }
        },
        sort_keys=True,
    ).encode()


@pytest.mark.asyncio
async def test_builtin_wayback_connector_fetches_an_exact_bounded_capture() -> None:
    client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url=(
                    "https://archive.org/wayback/available?"
                    "url=https%3A%2F%2Fexample.com%2Farticle%3Flang%3Den"
                ),
                headers={"content-type": "application/json"},
                body=_availability(),
            ),
            WaybackHTTPResponse(
                status_code=200,
                url=_RAW_CAPTURE,
                headers={
                    "content-type": "text/html; charset=utf-8",
                    "etag": '"wayback-fixture"',
                    "last-modified": "Fri, 02 Jan 2026 03:04:05 GMT",
                },
                body=(
                    b"<html><body>Useful archived fixture with enough deterministic "
                    b"content for quality validation.</body></html>"
                ),
            ),
        ]
    )
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )

    snapshot = await connector.fetch_snapshot(
        _ORIGINAL,
        maximum_bytes=10_000,
        deadline_seconds=5,
    )

    assert snapshot.original_url == _ORIGINAL
    assert snapshot.snapshot_url == _RAW_CAPTURE
    assert snapshot.media_type == "text/html"
    assert snapshot.captured_at.isoformat() == "2026-01-02T03:04:05+00:00"
    assert snapshot.etag == '"wayback-fixture"'
    assert snapshot.auxiliary_bytes == len(_availability())
    assert [call[1] for call in client.calls] == ["archive.org", "web.archive.org"]
    assert client.calls[0][2] == 10_000
    assert client.calls[1][2] == 10_000 - len(_availability())
    assert client.calls[0][3] == 5
    assert 0 < client.calls[1][3] <= 5
    assert client.calls[1][0] == _RAW_CAPTURE


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "original",
    [
        "https://example.com/article?token=never-send",
        "https://example.com/article?session_id=never-send",
    ],
)
async def test_wayback_never_sends_sensitive_query_values_to_archive_org(
    original: str,
) -> None:
    client = _FixtureHTTPClient([])
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )

    with pytest.raises(PolicyBlockedError, match="sensitive URL query"):
        await connector.fetch_snapshot(
            original,
            maximum_bytes=10_000,
            deadline_seconds=5,
        )

    assert client.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "availability",
    [
        _availability(
            locator=(
                f"https://attacker.example/web/{_TIMESTAMP}/{_ORIGINAL}"
            )
        ),
        _availability(
            locator=(
                f"https://web.archive.org/web/{_TIMESTAMP}/"
                "https://different.example/article"
            )
        ),
        _availability(timestamp="not-a-timestamp"),
    ],
)
async def test_wayback_rejects_origin_pivots_and_malformed_capture_metadata(
    availability: bytes,
) -> None:
    client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url="https://archive.org/wayback/available",
                headers={"content-type": "application/json"},
                body=availability,
            )
        ]
    )
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )

    with pytest.raises(AdapterExecutionError):
        await connector.fetch_snapshot(
            _ORIGINAL,
            maximum_bytes=10_000,
            deadline_seconds=5,
        )

    assert len(client.calls) == 1


@pytest.mark.asyncio
async def test_wayback_missing_capture_is_a_typed_not_found() -> None:
    client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url="https://archive.org/wayback/available",
                headers={"content-type": "application/json"},
                body=b'{"archived_snapshots":{}}',
            )
        ]
    )
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )

    with pytest.raises(AdapterNotFoundError, match="no Wayback snapshot"):
        await connector.fetch_snapshot(
            _ORIGINAL,
            maximum_bytes=10_000,
            deadline_seconds=5,
        )


@pytest.mark.asyncio
async def test_wayback_rejects_an_http_final_capture_even_after_safe_metadata() -> None:
    client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url="https://archive.org/wayback/available",
                headers={"content-type": "application/json"},
                body=_availability(),
            ),
            WaybackHTTPResponse(
                status_code=200,
                url=_RETURNED_CAPTURE,
                headers={"content-type": "text/html"},
                body=b"useful archived content",
            ),
        ]
    )
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )

    with pytest.raises(AdapterExecutionError, match="exact archive origin"):
        await connector.fetch_snapshot(
            _ORIGINAL,
            maximum_bytes=10_000,
            deadline_seconds=5,
        )


@pytest.mark.asyncio
async def test_wayback_requires_raw_mode_on_the_final_capture() -> None:
    client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url="https://archive.org/wayback/available",
                headers={"content-type": "application/json"},
                body=_availability(),
            ),
            WaybackHTTPResponse(
                status_code=200,
                url=(
                    f"https://web.archive.org/web/{_TIMESTAMP}/{_ORIGINAL}"
                ),
                headers={"content-type": "text/html"},
                body=b"useful but rewritten archived content",
            ),
        ]
    )
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )

    with pytest.raises(AdapterExecutionError, match="raw snapshot mode"):
        await connector.fetch_snapshot(
            _ORIGINAL,
            maximum_bytes=10_000,
            deadline_seconds=5,
        )


@pytest.mark.asyncio
async def test_wayback_revalidates_snapshot_bytes_and_media_type() -> None:
    availability = _availability()
    oversized_client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url="https://archive.org/wayback/available",
                headers={"content-type": "application/json"},
                body=availability,
            ),
            WaybackHTTPResponse(
                status_code=200,
                url=_RAW_CAPTURE,
                headers={"content-type": "text/html"},
                body=b"123456",
            ),
        ]
    )
    oversized = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=oversized_client,
    )

    with pytest.raises(AdapterBudgetExceededError, match="byte budget"):
        await oversized.fetch_snapshot(
            _ORIGINAL,
            maximum_bytes=len(availability) + 5,
            deadline_seconds=5,
        )

    invalid_type_client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url="https://archive.org/wayback/available",
                headers={"content-type": "application/json"},
                body=availability,
            ),
            WaybackHTTPResponse(
                status_code=200,
                url=_RAW_CAPTURE,
                headers={"content-type": "text/html, application/json"},
                body=b"useful archived content",
            ),
        ]
    )
    invalid_type = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=invalid_type_client,
    )

    with pytest.raises(AdapterExecutionError, match="media type"):
        await invalid_type.fetch_snapshot(
            _ORIGINAL,
            maximum_bytes=10_000,
            deadline_seconds=5,
        )


@pytest.mark.asyncio
async def test_cache_adapter_charges_wayback_lookup_and_capture_bytes(
    tmp_path: Path,
) -> None:
    availability = _availability()
    capture = (
        b"<html><body>Useful archived fixture content with deterministic "
        b"quality, provenance, and budget accounting.</body></html>"
    )
    client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url="https://archive.org/wayback/available",
                headers={"content-type": "application/json"},
                body=availability,
            ),
            WaybackHTTPResponse(
                status_code=200,
                url=_RAW_CAPTURE,
                headers={"content-type": "text/html"},
                body=capture,
            ),
        ]
    )
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )
    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(
            target=_ORIGINAL,
            budget=ResourceBudget(
                bytes=10_000,
                decompressed_bytes=10_000,
            ),
        ),
        cas=cas,
    )
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", cas),
        connectors={"internet_archive_snapshot": connector},
    )

    await adapter.execute(
        PlanNode(
            id="cache-internet-archive",
            capability_id="internet_archive_snapshot",
            adapter="cache",
        ),
        context,
    )

    assert context.attempts[-1].consumed_budget == {
        "bytes": len(availability) + len(capture),
        "decompressed_bytes": len(availability) + len(capture),
    }
    assert context.accepted is True


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_on_call", [1, 2])
async def test_cache_adapter_charges_partial_wayback_bytes_on_timeout(
    tmp_path: Path,
    fail_on_call: int,
) -> None:
    partial = b"partial-response"
    client = _PartialTimeoutHTTPClient(
        fail_on_call=fail_on_call,
        partial_body=partial,
    )
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )
    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target=_ORIGINAL),
        cas=cas,
    )
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", cas),
        connectors={"internet_archive_snapshot": connector},
    )

    with pytest.raises(TimeoutError, match="connector exceeded its deadline"):
        await adapter.execute(
            PlanNode(
                id="cache-internet-archive",
                capability_id="internet_archive_snapshot",
                adapter="cache",
            ),
            context,
        )

    expected = len(partial)
    if fail_on_call == 2:
        expected += len(_availability())
    attempt = context.attempts[-1]
    assert attempt.status == AttemptStatus.FAILED
    assert attempt.failure_code == "budget_exhausted"
    assert attempt.warnings == (
        "snapshot connector deadline budget exhausted",
    )
    assert attempt.consumed_budget == {
        "bytes": expected,
        "decompressed_bytes": expected,
    }


@pytest.mark.asyncio
async def test_cache_adapter_charges_failed_wayback_redirect_and_preserves_budget_type(
    tmp_path: Path,
) -> None:
    client = _RedirectBudgetHTTPClient()
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )
    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(
            target=_ORIGINAL,
            budget=ResourceBudget(redirects=0),
        ),
        cas=cas,
    )
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", cas),
        connectors={"internet_archive_snapshot": connector},
    )

    with pytest.raises(AdapterBudgetExceededError, match="redirects budget exhausted"):
        await adapter.execute(
            PlanNode(
                id="cache-internet-archive",
                capability_id="internet_archive_snapshot",
                adapter="cache",
            ),
            context,
        )

    attempt = context.attempts[-1]
    assert client.maximums == [0]
    assert attempt.status == AttemptStatus.FAILED
    assert attempt.failure_code == "budget_exhausted"
    assert attempt.consumed_budget == {"redirects": 1}


@pytest.mark.asyncio
async def test_cache_adapter_passes_remaining_wayback_redirects_and_deadline(
    tmp_path: Path,
) -> None:
    availability = _availability()
    capture = (
        b"<html><body>Useful archived fixture content with deterministic "
        b"quality and remaining-budget accounting.</body></html>"
    )
    client = _FixtureHTTPClient(
        [
            WaybackHTTPResponse(
                status_code=200,
                url="https://archive.org/wayback/available",
                headers={"content-type": "application/json"},
                body=availability,
            ),
            WaybackHTTPResponse(
                status_code=200,
                url=_RAW_CAPTURE,
                headers={"content-type": "text/html"},
                body=capture,
            ),
        ]
    )
    connector = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=client,
    )
    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(
            target=_ORIGINAL,
            budget=ResourceBudget(
                deadline_seconds=5,
                redirects=8,
                bytes=10_000,
                decompressed_bytes=10_000,
            ),
        ),
        cas=cas,
        attempts=[
            FetchAttempt(
                capability_id="prior-acquisition",
                adapter_version="test",
                started_at=datetime.now(UTC) - timedelta(seconds=1),
                sanitized_destination="https://example.com/",
                status=AttemptStatus.SUCCEEDED,
                consumed_budget={"redirects": 6},
            )
        ],
    )
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", cas),
        connectors={"internet_archive_snapshot": connector},
    )

    await adapter.execute(
        PlanNode(
            id="cache-internet-archive",
            capability_id="internet_archive_snapshot",
            adapter="cache",
        ),
        context,
    )

    assert [call[4] for call in client.calls] == [2, 2]
    assert 0 < client.calls[0][3] < 4.5
    assert 0 < client.calls[1][3] <= client.calls[0][3]
    assert context.attempts[-1].consumed_budget == {
        "bytes": len(availability) + len(capture),
        "decompressed_bytes": len(availability) + len(capture),
    }


@pytest.mark.asyncio
async def test_pinned_wayback_http_client_enforces_identity_and_byte_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json", "content-length": "2"},
            stream=httpx.ByteStream(b"{}"),
        )

    transports: list[_MockPinnedTransport] = []

    def transport_factory() -> _MockPinnedTransport:
        transport = _MockPinnedTransport(httpx.MockTransport(handler))
        transports.append(transport)
        return transport

    async def resolve(host: str, port: int) -> tuple[str, ...]:
        assert (host, port) == ("archive.org", 443)
        return ("93.184.216.34",)

    policy = SafeURLPolicy()
    monkeypatch.setattr(policy, "_resolve", resolve)
    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        transport_factory,
    )
    client = PinnedWaybackHTTPClient(
        policy=policy,
        user_agent="Fetech-test/1",
    )

    response = await client.get(
        "https://archive.org/wayback/available?url=https%3A%2F%2Fexample.com",
        allowed_host="archive.org",
        maximum_bytes=2,
        deadline_seconds=5,
    )

    assert response.body == b"{}"
    assert requests[0].headers["accept-encoding"] == "identity"
    assert "authorization" not in requests[0].headers
    assert "cookie" not in requests[0].headers
    assert "referer" not in requests[0].headers
    assert transports[0].pins == [("archive.org", ("93.184.216.34",))]

    def oversized(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-length": "3"},
            stream=httpx.ByteStream(b"123"),
        )

    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        lambda: _MockPinnedTransport(httpx.MockTransport(oversized)),
    )
    with pytest.raises(AdapterBudgetExceededError, match="byte budget"):
        await client.get(
            "https://archive.org/wayback/available",
            allowed_host="archive.org",
            maximum_bytes=2,
            deadline_seconds=5,
        )


@pytest.mark.asyncio
async def test_pinned_wayback_http_client_enforces_a_total_stream_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve(_host: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    policy = SafeURLPolicy()
    monkeypatch.setattr(policy, "_resolve", resolve)
    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        lambda: _MockPinnedTransport(
            httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    headers={"content-length": "2"},
                    stream=_SlowStream(),
                )
            )
        ),
    )
    client = PinnedWaybackHTTPClient(
        policy=policy,
        user_agent="Fetech-test/1",
    )

    with pytest.raises(TimeoutError, match="deadline"):
        await client.get(
            "https://archive.org/wayback/available",
            allowed_host="archive.org",
            maximum_bytes=10,
            deadline_seconds=0.01,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("headers", "message"),
    [
        ([("content-encoding", "gzip")], "compression"),
        ([("transfer-encoding", "gzip")], "transfer encoding"),
        ([("x-duplicate", str(index)) for index in range(129)], "too many headers"),
    ],
)
async def test_pinned_wayback_client_rejects_unsafe_response_headers(
    monkeypatch: pytest.MonkeyPatch,
    headers: list[tuple[str, str]],
    message: str,
) -> None:
    async def resolve(_host: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    policy = SafeURLPolicy()
    monkeypatch.setattr(policy, "_resolve", resolve)
    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        lambda: _MockPinnedTransport(
            httpx.MockTransport(
                lambda _request: httpx.Response(
                    200,
                    headers=headers,
                    stream=httpx.ByteStream(b"body"),
                )
            )
        ),
    )
    client = PinnedWaybackHTTPClient(
        policy=policy,
        user_agent="Fetech-test/1",
    )

    with pytest.raises(AdapterExecutionError, match=message):
        await client.get(
            "https://archive.org/wayback/available",
            allowed_host="archive.org",
            maximum_bytes=1_000,
            deadline_seconds=5,
        )


@pytest.mark.asyncio
async def test_wayback_transport_errors_are_sanitized(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def resolve(_host: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    def fail(_request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("private transport token=never-expose")

    policy = SafeURLPolicy()
    monkeypatch.setattr(policy, "_resolve", resolve)
    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        lambda: _MockPinnedTransport(httpx.MockTransport(fail)),
    )
    client = PinnedWaybackHTTPClient(
        policy=policy,
        user_agent="Fetech-test/1",
    )

    with pytest.raises(AdapterExecutionError, match="transport failed") as caught:
        await client.get(
            "https://archive.org/wayback/available",
            allowed_host="archive.org",
            maximum_bytes=1_000,
            deadline_seconds=5,
        )

    assert "never-expose" not in str(caught.value)

    def time_out(_request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("private timeout token=never-expose")

    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        lambda: _MockPinnedTransport(httpx.MockTransport(time_out)),
    )
    with pytest.raises(TimeoutError, match="deadline") as timeout:
        await client.get(
            "https://archive.org/wayback/available",
            allowed_host="archive.org",
            maximum_bytes=1_000,
            deadline_seconds=5,
        )
    assert "never-expose" not in str(timeout.value)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "location",
    [
        "https://attacker.example/capture",
        "http://archive.org/wayback/available",
    ],
)
async def test_pinned_wayback_http_client_rejects_redirect_origin_pivots(
    monkeypatch: pytest.MonkeyPatch,
    location: str,
) -> None:
    calls = 0

    def redirect(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            302,
            headers={"location": location},
        )

    async def resolve(_host: str, _port: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    policy = SafeURLPolicy()
    monkeypatch.setattr(policy, "_resolve", resolve)
    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        lambda: _MockPinnedTransport(httpx.MockTransport(redirect)),
    )
    client = PinnedWaybackHTTPClient(
        policy=policy,
        user_agent="Fetech-test/1",
    )
    usage = SnapshotConnectorUsage()

    with pytest.raises(PolicyBlockedError, match="exact HTTPS archive origin"):
        await client.get(
            "https://archive.org/wayback/available",
            allowed_host="archive.org",
            maximum_bytes=1_000,
            maximum_redirects=2,
            deadline_seconds=5,
            usage=usage,
        )

    assert calls == 1
    assert usage.redirects == 1


@pytest.mark.asyncio
async def test_pinned_wayback_client_blocks_same_host_dns_rebinding(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0
    resolutions = 0

    def redirect(_request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(
            302,
            headers={"location": "/wayback/available?url=https%3A%2F%2Fexample.com"},
        )

    async def resolve(_host: str, _port: int) -> tuple[str, ...]:
        nonlocal resolutions
        resolutions += 1
        return ("93.184.216.34",) if resolutions == 1 else ("127.0.0.1",)

    policy = SafeURLPolicy()
    monkeypatch.setattr(policy, "_resolve", resolve)
    monkeypatch.setattr(
        "fetech.wayback.PinnedAsyncHTTPTransport",
        lambda: _MockPinnedTransport(httpx.MockTransport(redirect)),
    )
    client = PinnedWaybackHTTPClient(
        policy=policy,
        user_agent="Fetech-test/1",
    )

    with pytest.raises(PolicyBlockedError, match="non-public address"):
        await client.get(
            "https://archive.org/wayback/available",
            allowed_host="archive.org",
            maximum_bytes=1_000,
            deadline_seconds=5,
        )

    assert calls == 1
    assert resolutions == 2


@pytest.mark.parametrize(
    "user_agent",
    [
        " Fetech-test/1",
        "Fetech-test/1\nX-Injected: yes",
        "Fetech-test/☃",
    ],
)
def test_wayback_rejects_unsafe_user_agent_headers(user_agent: str) -> None:
    with pytest.raises(ValueError, match="user agent"):
        PinnedWaybackHTTPClient(
            policy=SafeURLPolicy(),
            user_agent=user_agent,
        )


def test_gateway_registers_builtin_wayback_and_allows_an_explicit_override(
    tmp_path: Path,
) -> None:
    settings = Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph.json",
    )
    gateway = UniversalFetchGateway(settings)
    adapter = gateway.adapters["cache"]

    assert isinstance(adapter, CacheAdapter)
    assert isinstance(
        adapter.connectors["internet_archive_snapshot"],
        WaybackSnapshotConnector,
    )

    override = _FixtureHTTPClient([])
    configured = WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech-test/1",
        client=override,
    )
    overridden_gateway = UniversalFetchGateway(
        settings,
        snapshot_connectors={"internet_archive_snapshot": configured},
    )
    overridden = overridden_gateway.adapters["cache"]

    assert isinstance(overridden, CacheAdapter)
    assert overridden.connectors["internet_archive_snapshot"] is configured
