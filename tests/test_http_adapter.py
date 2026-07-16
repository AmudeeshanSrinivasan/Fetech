from __future__ import annotations

import gzip
from collections.abc import AsyncIterator
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.adapters.http import HTTPAdapter
from fetech.models import AttemptStatus, FetchRequest, PlanNode, ResourceBudget
from fetech.security import SafeURLPolicy
from fetech.storage import FileSystemCAS
from fetech.transport import PinnedAsyncHTTPTransport


def _context(tmp_path: Path, request: FetchRequest) -> ExecutionContext:
    return ExecutionContext(run_id=uuid4(), request=request, cas=FileSystemCAS(tmp_path / "cas"))


def _public_policy(monkeypatch: pytest.MonkeyPatch) -> SafeURLPolicy:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    return policy


class _ChunkedStream(httpx.AsyncByteStream):
    async def __aiter__(self) -> AsyncIterator[bytes]:
        yield b"x" * 60
        yield b"y" * 60


@pytest.mark.asyncio
async def test_default_transport_pool_is_fresh_per_request() -> None:
    adapter = HTTPAdapter(user_agent="Fetech/test")
    first = adapter._transport_for_request()
    second = adapter._transport_for_request()
    assert isinstance(first, PinnedAsyncHTTPTransport)
    assert isinstance(second, PinnedAsyncHTTPTransport)
    assert first is not second
    await first.aclose()
    await second.aclose()


@pytest.mark.asyncio
async def test_redirect_loop_is_detected_before_repeating_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    paths: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        location = "/b" if request.url.path == "/a" else "/a"
        return httpx.Response(302, headers={"location": location})

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(
            target="https://example.com/a",
            budget=ResourceBudget(redirects=10),
        ),
    )
    with pytest.raises(AdapterExecutionError, match="redirect loop detected"):
        await adapter._request(context.request.target, context)
    assert paths == ["/a", "/b"]


@pytest.mark.asyncio
async def test_every_redirect_host_is_policy_checked(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved: list[str] = []
    policy = SafeURLPolicy()

    async def public(host: str, _: int) -> tuple[str, ...]:
        resolved.append(host)
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)

    async def respond(request: httpx.Request) -> httpx.Response:
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": "https://cdn.example/asset"})
        return httpx.Response(200, content=b"asset")

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        transport=httpx.MockTransport(respond),
    )
    context = _context(tmp_path, FetchRequest(target="https://example.com/start"))
    response, body, _ = await adapter._request(context.request.target, context)
    assert response.url.host == "cdn.example"
    assert body == b"asset"
    assert resolved == ["example.com", "cdn.example"]
    assert len(context.policy_decisions) == 10
    assert [decision.policy_id for decision in context.policy_decisions].count(
        "rate_limit_policy"
    ) == 2


@pytest.mark.asyncio
async def test_content_length_rejects_oversized_wire_body_before_reading(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-length": "101"}, content=b"small")

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(
            target="https://example.com/large",
            budget=ResourceBudget(bytes=100, decompressed_bytes=1_000),
        ),
    )
    with pytest.raises(AdapterExecutionError, match="Content-Length exceeded"):
        await adapter._request(context.request.target, context)


@pytest.mark.asyncio
async def test_streamed_wire_body_is_bounded_without_content_length(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, stream=_ChunkedStream())

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(
            target="https://example.com/chunked",
            budget=ResourceBudget(bytes=100, decompressed_bytes=1_000),
        ),
    )
    with pytest.raises(AdapterExecutionError, match="wire byte budget"):
        await adapter._request(context.request.target, context)


@pytest.mark.asyncio
async def test_transfer_budget_failure_marks_attempt_failed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-length": "101"}, content=b"small")

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(
            target="https://example.com/large",
            budget=ResourceBudget(bytes=100, decompressed_bytes=1_000),
        ),
    )
    with pytest.raises(AdapterExecutionError, match="Content-Length exceeded"):
        await adapter.execute(
            PlanNode(id="http", capability_id="http_get", adapter="http"),
            context,
        )
    assert context.attempts[-1].status == AttemptStatus.FAILED
    assert context.attempts[-1].failure_code == "AdapterExecutionError"


@pytest.mark.asyncio
async def test_decompressed_body_has_independent_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expanded = b"x" * 2_000
    compressed = gzip.compress(expanded)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
            },
            content=compressed,
        )

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(
            target="https://example.com/compressed",
            budget=ResourceBudget(bytes=len(compressed) + 10, decompressed_bytes=1_000),
        ),
    )
    with pytest.raises(AdapterExecutionError, match="decompressed byte budget"):
        await adapter._request(context.request.target, context)


@pytest.mark.asyncio
async def test_attempt_records_wire_and_decompressed_consumption(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expanded = b"useful content " * 100
    compressed = gzip.compress(expanded)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "text/plain",
                "content-encoding": "gzip",
                "content-length": str(len(compressed)),
            },
            content=compressed,
        )

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(
            target="https://example.com/compressed",
            budget=ResourceBudget(
                bytes=len(compressed) + 10,
                decompressed_bytes=len(expanded) + 10,
            ),
        ),
    )
    await adapter.execute(PlanNode(id="http", capability_id="http_get", adapter="http"), context)
    attempt = context.attempts[-1]
    assert attempt.bytes_received == len(compressed)
    assert attempt.consumed_budget["bytes"] == len(compressed)
    assert attempt.consumed_budget["decompressed_bytes"] == len(expanded)
    assert context.artifacts[-1].size == len(expanded)
