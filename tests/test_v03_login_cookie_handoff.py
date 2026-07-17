from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.adapters.http import HTTPAdapter
from fetech.models import FetchRequest, ResourceBudget
from fetech.security import PolicyBlockedError, SafeURLPolicy
from fetech.storage import FileSystemCAS


def _context(tmp_path: Path, *, intent: str = "fetch") -> ExecutionContext:
    return ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(
            target="https://login.example/session",
            intent=intent,
            authentication_ref="vault://form/proposal",
            budget=ResourceBudget(redirects=3),
        ),
        cas=FileSystemCAS(tmp_path / "cas"),
    )


def _public_policy(monkeypatch: pytest.MonkeyPatch) -> SafeURLPolicy:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    return policy


def _adapter(
    monkeypatch: pytest.MonkeyPatch,
    handler: httpx.AsyncBaseTransport,
) -> HTTPAdapter:
    return HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=handler,
    )


@pytest.mark.asyncio
async def test_same_origin_login_cookie_handoff_is_ephemeral_and_scrubbed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    login_secret = "login-cookie-never-return"
    final_secret = "rotated-cookie-never-return"
    observed: list[tuple[str, str, str | None]] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(
            (request.method, request.url.path, request.headers.get("cookie"))
        )
        if request.url.path == "/session":
            return httpx.Response(
                303,
                headers={
                    "location": "/workspace",
                    "set-cookie": (
                        f"session={login_secret}; Secure; HttpOnly; Path=/"
                    ),
                },
            )
        return httpx.Response(
            200,
            headers={
                "content-type": "text/plain",
                "set-cookie": (
                    f"session={final_secret}; Secure; HttpOnly; Path=/"
                ),
            },
            content=b"private workspace",
        )

    adapter = _adapter(monkeypatch, httpx.MockTransport(respond))
    context = _context(tmp_path)
    response, body, _ = await adapter._request(
        context.request.target,
        context,
        method_override="POST",
        body=b"username=agent&password=private",
        extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
        allow_ephemeral_login_cookies=True,
        credential_mode="anonymous",
    )

    assert body == b"private workspace"
    assert observed == [
        ("POST", "/session", None),
        ("GET", "/workspace", f"session={login_secret}"),
    ]
    assert "set-cookie" not in response.headers
    assert "cookie" not in response.request.headers
    assert list(response.cookies.jar) == []
    assert context.sensitive_state == {}
    serialized = json.dumps(
        [outcome.model_dump(mode="json") for outcome in context.capability_outcomes]
    )
    assert login_secret not in serialized
    assert final_secret not in serialized
    assert login_secret not in repr(context)
    assert final_secret not in repr(context)


@pytest.mark.asyncio
async def test_login_cookie_is_withheld_and_destroyed_on_cross_origin_redirect(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "same-origin-only"
    observed: list[tuple[str, str, str | None]] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(
            (request.url.host, request.url.path, request.headers.get("cookie"))
        )
        if request.url.host == "login.example":
            return httpx.Response(
                302,
                headers={
                    "location": "https://workspace.example/home",
                    "set-cookie": f"session={secret}; Secure; HttpOnly; Path=/",
                },
            )
        return httpx.Response(200, content=b"redirected")

    adapter = _adapter(monkeypatch, httpx.MockTransport(respond))
    context = _context(tmp_path)
    response, body, _ = await adapter._request(
        context.request.target,
        context,
        method_override="POST",
        body=b"approved=true",
        allow_ephemeral_login_cookies=True,
        credential_mode="anonymous",
    )

    assert body == b"redirected"
    assert observed == [
        ("login.example", "/session", None),
        ("workspace.example", "/home", None),
    ]
    assert secret not in repr(context)
    assert "cookie" not in response.request.headers


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "set_cookie",
    [
        "session=insecure-cookie; HttpOnly; Path=/",
        f"session={'x' * 4097}; Secure; HttpOnly; Path=/",
    ],
)
async def test_insecure_or_oversized_login_cookie_is_rejected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    set_cookie: str,
) -> None:
    requests = 0

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        return httpx.Response(
            303,
            headers={"location": "/workspace", "set-cookie": set_cookie},
        )

    adapter = _adapter(monkeypatch, httpx.MockTransport(respond))
    context = _context(tmp_path)

    with pytest.raises(AdapterExecutionError, match="ephemeral login cookie") as caught:
        await adapter._request(
            context.request.target,
            context,
            method_override="POST",
            body=b"approved=true",
            allow_ephemeral_login_cookies=True,
            credential_mode="anonymous",
        )

    assert requests == 1
    assert "insecure-cookie" not in str(caught.value)
    assert "x" * 128 not in str(caught.value)
    assert context.sensitive_state == {}


@pytest.mark.asyncio
async def test_body_preserving_login_redirect_is_blocked_before_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "must-not-replay"
    observed: list[str | None] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(request.headers.get("cookie"))
        return httpx.Response(
            307,
            headers={
                "location": "/workspace",
                "set-cookie": f"session={secret}; Secure; Path=/",
            },
        )

    adapter = _adapter(monkeypatch, httpx.MockTransport(respond))
    context = _context(tmp_path)

    with pytest.raises(PolicyBlockedError, match="exact-target"):
        await adapter._request(
            context.request.target,
            context,
            method_override="POST",
            body=b"approved=true",
            allow_ephemeral_login_cookies=True,
            credential_mode="anonymous",
        )

    assert observed == [None]
    assert secret not in repr(context)


@pytest.mark.asyncio
async def test_robots_request_remains_anonymous_during_cookie_handoff(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "crawl-login-cookie"
    observed: list[tuple[str, str, str | None]] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(
            (request.method, request.url.path, request.headers.get("cookie"))
        )
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        if request.url.path == "/session":
            return httpx.Response(
                303,
                headers={
                    "location": "/workspace",
                    "set-cookie": f"session={secret}; Secure; HttpOnly; Path=/",
                },
            )
        return httpx.Response(200, content=b"private workspace")

    adapter = _adapter(monkeypatch, httpx.MockTransport(respond))
    context = _context(tmp_path, intent="crawl")
    _, body, _ = await adapter._request(
        context.request.target,
        context,
        method_override="POST",
        body=b"approved=true",
        allow_ephemeral_login_cookies=True,
        credential_mode="anonymous",
    )

    assert body == b"private workspace"
    assert observed == [
        ("GET", "/robots.txt", None),
        ("POST", "/session", None),
        ("GET", "/workspace", f"session={secret}"),
    ]


@pytest.mark.asyncio
async def test_cookie_handoff_is_disabled_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[str | None] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(request.headers.get("cookie"))
        if request.url.path == "/session":
            return httpx.Response(
                303,
                headers={
                    "location": "/workspace",
                    "set-cookie": "session=ignored; Secure; HttpOnly; Path=/",
                },
            )
        return httpx.Response(200, content=b"public")

    adapter = _adapter(monkeypatch, httpx.MockTransport(respond))
    context = _context(tmp_path)
    _, body, _ = await adapter._request(
        context.request.target,
        context,
        method_override="POST",
        body=b"approved=true",
        credential_mode="anonymous",
    )

    assert body == b"public"
    assert observed == [None, None]
