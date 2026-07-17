from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from sqlalchemy import select

from fetech.adapters.base import (
    AdapterAuthExpiredError,
    AdapterAuthRequiredError,
    AdapterDependencyError,
    ExecutionContext,
)
from fetech.adapters.http import HTTPAdapter
from fetech.auth import (
    CredentialMaterial,
    CredentialProviderUnavailableError,
    InMemoryCredentialProvider,
    authentication_cache_scope,
    canonical_origin,
)
from fetech.config import Settings
from fetech.conformance import release_report
from fetech.gateway import UniversalFetchGateway
from fetech.ledger import EventRow, RunRow
from fetech.models import FetchRequest, ResourceBudget, ResultStatus
from fetech.registry import CapabilityRegistry
from fetech.security import PolicyBlockedError, SafeURLPolicy
from fetech.storage import CacheKey, FileSystemCAS


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
        per_host_min_interval_seconds=0,
    )


def _context(tmp_path: Path, request: FetchRequest) -> ExecutionContext:
    return ExecutionContext(run_id=uuid4(), request=request, cas=FileSystemCAS(tmp_path / "cas"))


def _public_policy(monkeypatch: pytest.MonkeyPatch) -> SafeURLPolicy:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    return policy


def test_credential_contract_is_repr_safe_exact_origin_and_https_only() -> None:
    reference = "vault://account/private-reference"
    request = FetchRequest(target="https://example.com", authentication_ref=reference)
    material = CredentialMaterial.bearer("https://EXAMPLE.com:443", "top-secret-token")

    assert reference not in repr(request)
    assert "top-secret-token" not in repr(material)
    assert material.origin == "https://example.com"
    assert material.applies_to("https://example.com:443/private?q=yes")
    assert not material.applies_to("https://sub.example.com/private")
    assert not material.applies_to("https://example.com:8443/private")
    assert canonical_origin("http://EXAMPLE.com:80/path") == "http://example.com"

    with pytest.raises(ValueError, match="HTTPS"):
        CredentialMaterial.api_key("http://example.com", "secret")
    with pytest.raises(ValueError, match="forbidden"):
        CredentialMaterial(
            origin="https://example.com",
            capability_id="api_key",
            headers={"Host": "attacker.example"},
        )


@pytest.mark.asyncio
async def test_exact_origin_credentials_are_injected_per_request(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://account/one"
    material = CredentialMaterial(
        origin="https://example.com",
        capability_id="api_key",
        headers={"X-API-Key": "api-secret"},
        cookies={"session": "cookie-secret"},
    )
    provider = InMemoryCredentialProvider({reference: material})
    observed: list[httpx.Headers] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(request.headers)
        return httpx.Response(200, content=b"authenticated")

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=provider,
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(target="https://EXAMPLE.com:443/private", authentication_ref=reference),
    )
    _, body, _ = await adapter._request(context.request.target, context)

    assert body == b"authenticated"
    assert observed[0]["x-api-key"] == "api-secret"
    assert observed[0]["cookie"] == "session=cookie-secret"
    assert any(outcome.capability_id == "api_key" for outcome in context.capability_outcomes)
    assert any(outcome.capability_id == "connector_auth" for outcome in context.capability_outcomes)
    serialized = json.dumps([outcome.model_dump(mode="json") for outcome in context.capability_outcomes])
    assert "api-secret" not in serialized
    assert "cookie-secret" not in serialized
    assert reference not in serialized


@pytest.mark.asyncio
async def test_redirects_retain_exact_origin_auth_and_strip_cross_origin_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://account/redirect"
    provider = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.bearer(
                "https://a.example.com",
                "redirect-secret",
            )
        }
    )
    observed: list[tuple[str, str | None, str | None]] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(
            (
                f"{request.url.host}{request.url.path}",
                request.headers.get("authorization"),
                request.headers.get("cookie"),
            )
        )
        if request.url.path == "/start":
            return httpx.Response(302, headers={"location": "/same-origin"})
        if request.url.path == "/same-origin":
            return httpx.Response(
                302,
                headers={
                    "location": "https://b.example.com/final",
                    "set-cookie": "server_session=server-secret; Domain=.example.com; Secure",
                },
            )
        return httpx.Response(200, content=b"final")

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=provider,
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(
            target="https://a.example.com/start",
            authentication_ref=reference,
            budget=ResourceBudget(redirects=3),
        ),
    )
    _, body, _ = await adapter._request(context.request.target, context)

    assert body == b"final"
    assert observed == [
        ("a.example.com/start", "Bearer redirect-secret", None),
        ("a.example.com/same-origin", "Bearer redirect-secret", None),
        ("b.example.com/final", None, None),
    ]


@pytest.mark.asyncio
async def test_authenticated_crawl_never_sends_credentials_to_robots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://account/crawl"
    provider = InMemoryCredentialProvider(
        {reference: CredentialMaterial.cookie_session("https://example.com", {"session": "secret"})}
    )
    observed: dict[str, str | None] = {}

    async def respond(request: httpx.Request) -> httpx.Response:
        observed[request.url.path] = request.headers.get("cookie")
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        return httpx.Response(200, content=b"private content")

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=provider,
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(
            target="https://example.com/private",
            intent="crawl",
            authentication_ref=reference,
        ),
    )
    await adapter._request(context.request.target, context)

    assert observed == {"/robots.txt": None, "/private": "session=secret"}


@pytest.mark.asyncio
async def test_scope_mismatch_and_unknown_reference_fail_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    called = False

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    policy = _public_policy(monkeypatch)
    reference = "vault://account/wrong-origin"
    mismatch = HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        credential_provider=InMemoryCredentialProvider(
            {reference: CredentialMaterial.api_key("https://other.example", "secret")}
        ),
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        FetchRequest(target="https://example.com/private", authentication_ref=reference),
    )
    with pytest.raises(PolicyBlockedError, match="scope"):
        await mismatch._request(context.request.target, context)

    unknown = HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        credential_provider=InMemoryCredentialProvider({}),
        transport=httpx.MockTransport(respond),
    )
    with pytest.raises(AdapterAuthRequiredError, match="could not be resolved"):
        await unknown._request(context.request.target, context)

    gateway = UniversalFetchGateway(
        _settings(tmp_path / "unknown"),
        credential_provider=InMemoryCredentialProvider({}),
    )
    gateway.adapters["http"] = unknown
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(context.request)
    assert result.status == ResultStatus.AUTH_REQUIRED
    assert result.attempts[0].failure_code == "auth_required"
    await gateway.close()
    assert not called


@pytest.mark.asyncio
async def test_expired_credentials_are_typed_redacted_and_not_retried(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://account/expired-reference"
    secret = "expired-secret-value"
    provider = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.bearer(
                "https://example.com",
                secret,
                expires_at=datetime.now(UTC) - timedelta(seconds=1),
            )
        }
    )
    called = False

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    gateway = UniversalFetchGateway(_settings(tmp_path), credential_provider=provider)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=_public_policy(monkeypatch),
        credential_provider=provider,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(
        FetchRequest(target="https://example.com/private", authentication_ref=reference)
    )

    assert result.status == ResultStatus.AUTH_REQUIRED
    assert not called
    assert len(result.attempts) == 1
    assert result.attempts[0].failure_code == "auth_expired"
    assert [diagnostic.code for diagnostic in result.diagnostics] == ["auth_expired"]
    events = await gateway.ledger.events(result.run_id)
    assert "attempt.auth_expired" in {event.event_type for event in events}

    async with gateway.ledger.sessions() as session:
        run_row = await session.scalar(select(RunRow).where(RunRow.run_id == str(result.run_id)))
        event_rows = (
            await session.scalars(select(EventRow).where(EventRow.run_id == str(result.run_id)))
        ).all()
    assert run_row is not None
    stored = f"{run_row.request_json}\n{run_row.result_json}\n" + "\n".join(
        row.payload_json for row in event_rows
    )
    assert json.loads(run_row.request_json)["authentication_ref"] == "[REDACTED]"
    assert reference not in stored
    assert secret not in stored
    await gateway.close()


@pytest.mark.asyncio
async def test_only_explicit_protocol_evidence_marks_server_rejection_expired(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://account/server-expiry"
    provider = InMemoryCredentialProvider(
        {reference: CredentialMaterial.bearer("https://example.com", "server-secret")}
    )
    responses = iter(
        (
            httpx.Response(401),
            httpx.Response(
                401,
                headers={
                    "www-authenticate": (
                        'Bearer error="invalid_token", error_description="access token expired"'
                    )
                },
            ),
        )
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=provider,
        transport=httpx.MockTransport(lambda _: next(responses)),
    )
    context = _context(
        tmp_path,
        FetchRequest(target="https://example.com/private", authentication_ref=reference),
    )

    with pytest.raises(AdapterAuthRequiredError) as rejected:
        await adapter._request(context.request.target, context)
    assert type(rejected.value) is AdapterAuthRequiredError
    with pytest.raises(AdapterAuthExpiredError):
        await adapter._request(context.request.target, context)


@pytest.mark.asyncio
async def test_provider_failure_and_authenticated_http3_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class UnavailableProvider:
        async def resolve(self, _: str) -> CredentialMaterial:
            raise CredentialProviderUnavailableError("internal provider secret")

    class UnexpectedHTTP3Client:
        called = False

        async def fetch(self, *_: object, **__: object) -> object:
            self.called = True
            raise AssertionError("HTTP/3 transport must not run")

    transport_called = False

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return httpx.Response(200)

    request = FetchRequest(
        target="https://example.com/private",
        authentication_ref="vault://account/unavailable",
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=UnavailableProvider(),
        transport=httpx.MockTransport(respond),
    )
    context = _context(tmp_path, request)
    with pytest.raises(AdapterDependencyError) as unavailable:
        await adapter._request(request.target, context)
    assert str(unavailable.value) == "credential provider is unavailable"
    assert "internal provider secret" not in str(unavailable.value)
    assert not transport_called

    gateway = UniversalFetchGateway(
        _settings(tmp_path / "provider-unavailable"),
        credential_provider=UnavailableProvider(),
    )
    gateway.adapters["http"] = adapter
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(request)
    assert result.status == ResultStatus.DEPENDENCY_MISSING
    assert result.attempts[0].failure_code == "dependency_missing"
    assert "internal provider secret" not in result.model_dump_json()
    await gateway.close()

    http3 = UnexpectedHTTP3Client()
    http3_adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        http3_client=http3,  # type: ignore[arg-type]
    )
    http3_request = request.model_copy(update={"output_requirements": ("http_3",)})
    with pytest.raises(AdapterDependencyError, match="authenticated HTTP/3"):
        await http3_adapter._request(http3_request.target, _context(tmp_path, http3_request))
    assert not http3.called


@pytest.mark.asyncio
async def test_public_request_never_resolves_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class MustNotResolve:
        async def resolve(self, _: str) -> CredentialMaterial:
            raise AssertionError("public requests must not resolve credentials")

    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=MustNotResolve(),
        transport=httpx.MockTransport(lambda _: httpx.Response(200, content=b"public")),
    )
    request = FetchRequest(target="https://example.com/public")
    _, body, _ = await adapter._request(request.target, _context(tmp_path, request))
    assert body == b"public"


def test_cache_scope_factory_separates_public_and_authenticated_requests() -> None:
    public_request = FetchRequest(target="https://example.com")
    first_ref = "vault://account/one"
    second_ref = "vault://account/two"
    first_request = FetchRequest(target="https://example.com", authentication_ref=first_ref)
    second_request = FetchRequest(target="https://example.com", authentication_ref=second_ref)

    def key(request: FetchRequest) -> CacheKey:
        return CacheKey.for_request(
            request,
            url=request.target,
            representation="clean_text",
            parser_version="reader-v1",
        )

    public, first, second = key(public_request), key(first_request), key(second_request)
    assert public.authentication_scope == "public"
    assert first.authentication_scope == authentication_cache_scope(first_ref)
    assert first_ref not in first.authentication_scope
    assert len({public.digest, first.digest, second.digest}) == 3


def test_v03_report_closes_authentication_and_structured_api_categories() -> None:
    registry = CapabilityRegistry()
    report = release_report(registry, "v0.3")

    assert report["capability_count"] == 23
    assert report["available_count"] == 23
    assert report["closure_ready"] is True
    assert report["status_counts"] == {"native": 21, "optional": 2}
    assert report["gaps"] == []
    assert all(
        entry.available for entry in registry if entry.closure_release == "v0.3"
    )
