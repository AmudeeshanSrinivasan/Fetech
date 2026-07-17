from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from fetech.adapters.api import normalize_api_payload
from fetech.adapters.auth import AuthAdapter
from fetech.adapters.base import (
    AdapterAuthExpiredError,
    AdapterAuthRequiredError,
    AdapterExecutionError,
    ExecutionContext,
)
from fetech.adapters.http import HTTPAdapter
from fetech.auth import CredentialMaterial, InMemoryCredentialProvider
from fetech.auth_flows import (
    FormSubmission,
    FormSubmissionApproval,
    InMemoryFormSubmissionProvider,
    OriginScopedSession,
)
from fetech.config import Settings
from fetech.executor import ExecutionEngine
from fetech.gateway import UniversalFetchGateway
from fetech.ledger import EventLedger
from fetech.models import (
    FetchPlan,
    FetchRequest,
    PlanNode,
    ResourceBudget,
    ResultStatus,
    RunState,
)
from fetech.security import PolicyBlockedError, SafeURLPolicy
from fetech.storage import FileSystemCAS


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
        per_host_min_interval_seconds=0,
    )


def _context(tmp_path: Path, request: FetchRequest) -> ExecutionContext:
    return ExecutionContext(
        run_id=uuid4(),
        request=request,
        cas=FileSystemCAS(tmp_path / "cas"),
    )


def _public_policy(monkeypatch: pytest.MonkeyPatch) -> SafeURLPolicy:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    return policy


def test_structured_json_lists_and_openapi_paths_obey_record_bounds() -> None:
    json_result = normalize_api_payload(
        "json_endpoint",
        b'{"results":[1,2,3,4],"nested":{"items":["a","b","c"]}}',
        media_type="application/json",
        source_url="https://example.com/data",
        authority_url="https://example.com/data",
        maximum_records=2,
    )
    assert json_result.document["data"] == {
        "nested": {"items": ["a", "b"]},
        "results": [1, 2],
    }
    assert json_result.omitted_records == 3

    openapi_result = normalize_api_payload(
        "openapi_discovery",
        (
            b'{"openapi":"3.1.0","paths":{'
            b'"/a":{"get":{}},"/b":{"get":{}},"/c":{"get":{}}}}'
        ),
        media_type="application/json",
        source_url="https://example.com/openapi.json",
        authority_url="https://example.com/openapi.json",
        maximum_records=2,
    )
    assert list(openapi_result.document["data"]["paths"]) == ["/a", "/b"]
    assert openapi_result.omitted_records == 1


def test_credential_material_and_opaque_references_are_byte_bounded() -> None:
    with pytest.raises(ValueError, match="byte limit"):
        CredentialMaterial.bearer("https://example.com", "x" * (16 * 1024))
    with pytest.raises(ValueError, match="invalid cookie"):
        CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "x" * (4 * 1024 + 1)},
        )
    with pytest.raises(ValueError, match="byte limit"):
        FetchRequest(
            target="https://example.com",
            authentication_ref="é" * 2_048,
        )


class _RefreshProvider:
    def __init__(
        self,
        initial: CredentialMaterial,
        refreshed: CredentialMaterial,
    ) -> None:
        self.initial = initial
        self.refreshed = refreshed
        self.refresh_calls = 0
        self.refresh_references: list[str] = []

    async def resolve(self, _: str) -> CredentialMaterial:
        return self.initial

    async def refresh(self, reference: str) -> CredentialMaterial:
        self.refresh_calls += 1
        self.refresh_references.append(reference)
        self.initial = self.refreshed
        return self.refreshed


@pytest.mark.asyncio
async def test_wrong_origin_and_non_bearer_material_cannot_trigger_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expired = datetime.now(UTC) - timedelta(seconds=1)
    valid = datetime.now(UTC) + timedelta(hours=1)
    wrong_origin = _RefreshProvider(
        CredentialMaterial.bearer(
            "https://other.example",
            "old-secret",
            expires_at=expired,
        ),
        CredentialMaterial.bearer(
            "https://example.com",
            "new-secret",
            expires_at=valid,
        ),
    )
    request = FetchRequest(
        target="https://example.com/private",
        authentication_ref="vault://wrong-origin",
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=wrong_origin,
        transport=httpx.MockTransport(lambda _: httpx.Response(200)),
    )
    with pytest.raises(PolicyBlockedError, match="scope"):
        await adapter._request(request.target, _context(tmp_path / "origin", request))
    assert wrong_origin.refresh_calls == 0

    api_key = _RefreshProvider(
        CredentialMaterial.api_key(
            "https://example.com",
            "old-key",
            expires_at=expired,
        ),
        CredentialMaterial.api_key(
            "https://example.com",
            "new-key",
            expires_at=valid,
        ),
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=api_key,
        transport=httpx.MockTransport(lambda _: httpx.Response(200)),
    )
    request = request.model_copy(update={"authentication_ref": "vault://api-key"})
    with pytest.raises(AdapterAuthExpiredError):
        await adapter._request(request.target, _context(tmp_path / "api-key", request))
    assert api_key.refresh_calls == 0


@pytest.mark.asyncio
async def test_bearer_invalid_token_refresh_requires_authorized_session_descriptor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = datetime.now(UTC) + timedelta(hours=1)
    initial = CredentialMaterial.bearer(
        "https://example.com",
        "old-token",
        expires_at=valid,
    )
    refreshed = CredentialMaterial.bearer(
        "https://example.com",
        "new-token",
        expires_at=valid,
    )
    provider = _RefreshProvider(initial, refreshed)
    request = FetchRequest(
        target="https://example.com/private",
        authentication_ref="vault://bearer",
    )
    basic = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=provider,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                401,
                headers={"www-authenticate": 'Basic realm="expired account"'},
            )
        ),
    )
    with pytest.raises(AdapterAuthRequiredError):
        await basic._request(request.target, _context(tmp_path / "basic", request))
    assert provider.refresh_calls == 0

    calls = 0

    def bearer_response(_: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        if calls == 1:
            return httpx.Response(
                401,
                headers={
                    "www-authenticate": (
                        'Bearer error="invalid_token", '
                        'error_description="access token expired"'
                    )
                },
            )
        return httpx.Response(200, content=b"refreshed")

    bearer = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=provider,
        transport=httpx.MockTransport(bearer_response),
    )
    with pytest.raises(AdapterAuthExpiredError):
        await bearer._request(
            request.target,
            _context(tmp_path / "bearer-no-session", request),
        )
    assert provider.refresh_calls == 0

    calls = 0
    session_context = _context(tmp_path / "bearer-session", request)
    session_context.sensitive_state["origin_scoped_session"] = (
        OriginScopedSession.oauth(
            "https://example.com",
            "vault://bearer",
            issuer_origin="https://identity.example.com",
            refresh_ref="vault://bearer/refresh",
        )
    )
    _, body, _ = await bearer._request(request.target, session_context)
    assert body == b"refreshed"
    assert provider.refresh_calls == 1
    assert provider.refresh_references == ["vault://bearer/refresh"]


@pytest.mark.asyncio
async def test_server_challenge_refresh_rejects_changed_credential_type(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = datetime.now(UTC) + timedelta(hours=1)
    provider = _RefreshProvider(
        CredentialMaterial.bearer(
            "https://example.com",
            "old-token",
            expires_at=valid,
        ),
        CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "wrong-kind"},
            expires_at=valid,
        ),
    )
    request = FetchRequest(
        target="https://example.com/private",
        authentication_ref="vault://bearer",
    )
    context = _context(tmp_path, request)
    context.sensitive_state["origin_scoped_session"] = OriginScopedSession.sso(
        "https://example.com",
        "vault://bearer",
        issuer_origin="https://identity.example.com",
        refresh_ref="vault://bearer/refresh",
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=provider,
        transport=httpx.MockTransport(
            lambda _: httpx.Response(
                401,
                headers={
                    "www-authenticate": (
                        'Bearer error="invalid_token", '
                        'error_description="access token expired"'
                    )
                },
            )
        ),
    )

    with pytest.raises(AdapterAuthRequiredError, match="authentication type"):
        await adapter._request(request.target, context)
    assert provider.refresh_references == ["vault://bearer/refresh"]


@pytest.mark.asyncio
async def test_body_preserving_same_origin_redirect_requires_new_approval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str]] = []

    def respond(request: httpx.Request) -> httpx.Response:
        observed.append((request.method, request.url.path))
        return httpx.Response(307, headers={"location": "/second"})

    request = FetchRequest(
        target="https://example.com/first",
        budget=ResourceBudget(redirects=2),
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    with pytest.raises(PolicyBlockedError, match="cannot replay"):
        await adapter._request(
            request.target,
            _context(tmp_path, request),
            method_override="POST",
            body=b"secret=one-use",
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert observed == [("POST", "/first")]


@pytest.mark.asyncio
async def test_missing_session_dependency_blocks_authenticated_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://session/access"
    credentials = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.bearer(
                "https://example.com",
                "must-not-be-sent",
            )
        }
    )
    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        credential_provider=credentials,
    )
    policy = _public_policy(monkeypatch)
    transport_called = False

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return httpx.Response(200, content=b"must not be fetched")

    http = HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        credential_provider=credentials,
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["auth"] = AuthAdapter(
        http,
        credential_provider=credentials,
        session_provider=gateway.session_provider,
        form_submission_provider=gateway.form_submission_provider,
    )
    gateway.executor.adapters = gateway.adapters

    try:
        result = await gateway.fetch(
            FetchRequest(
                target="https://example.com/private",
                authentication_ref=reference,
                output_requirements=("login_session",),
            )
        )
    finally:
        await gateway.close()

    assert result.status == ResultStatus.DEPENDENCY_MISSING
    assert not transport_called
    assert [(attempt.capability_id, attempt.failure_code) for attempt in result.attempts] == [
        ("login_session", "dependency_missing")
    ]
    http_outcome = next(
        outcome
        for outcome in result.capability_outcomes
        if outcome.capability_id == "http_get"
    )
    assert http_outcome.status.value == "NOT_APPLICABLE"


@pytest.mark.asyncio
async def test_failed_csrf_dependency_blocks_form_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://form/proposal"
    target = "https://example.com/login"
    forms = InMemoryFormSubmissionProvider(
        {
            reference: FormSubmission(
                target=target,
                method="POST",
                fields={"username": "agent"},
                authentication_ref=reference,
                approval=FormSubmissionApproval.grant(target, "POST"),
            )
        }
    )
    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        form_submission_provider=forms,
    )
    policy = _public_policy(monkeypatch)
    observed_methods: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed_methods.append(request.method)
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<form method='post'></form>",
        )

    http = HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        credential_provider=gateway.credential_provider,
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["auth"] = AuthAdapter(
        http,
        credential_provider=gateway.credential_provider,
        session_provider=gateway.session_provider,
        form_submission_provider=forms,
    )
    gateway.executor.adapters = gateway.adapters

    try:
        result = await gateway.fetch(
            FetchRequest(
                target=target,
                authentication_ref=reference,
                output_requirements=("csrf_token", "form_submit"),
                approved_capabilities=frozenset({"form_submit"}),
            )
        )
    finally:
        await gateway.close()

    assert observed_methods == ["GET"]
    assert [attempt.capability_id for attempt in result.attempts] == [
        "http_get",
        "csrf_token",
    ]
    form_outcome = next(
        outcome
        for outcome in result.capability_outcomes
        if outcome.capability_id == "form_submit"
    )
    assert form_outcome.status.value == "NOT_APPLICABLE"


@pytest.mark.asyncio
async def test_failed_node_blocks_dependents_but_not_independent_fallbacks(
    tmp_path: Path,
) -> None:
    calls: list[str] = []

    class FailingAdapter:
        async def execute(self, _: PlanNode, __: ExecutionContext) -> None:
            raise AdapterExecutionError("expected failure")

    class RecordingAdapter:
        async def execute(self, node: PlanNode, _: ExecutionContext) -> None:
            calls.append(node.id)

    ledger = EventLedger.sqlite(tmp_path / "branch-ledger.sqlite3")
    await ledger.initialize()
    request = FetchRequest(target="https://example.com")
    run_id = uuid4()
    await ledger.create_run(run_id, request.model_dump(mode="json"), datetime.now(UTC))
    engine = ExecutionEngine(
        adapters={
            "failing": FailingAdapter(),
            "recording": RecordingAdapter(),
        },
        cas=FileSystemCAS(tmp_path / "branch-cas"),
        ledger=ledger,
    )
    plan = FetchPlan(
        request=request,
        nodes=(
            PlanNode(
                id="failed",
                capability_id="clean_text",
                adapter="failing",
            ),
            PlanNode(
                id="dependent",
                capability_id="main_article",
                adapter="recording",
                dependencies=("failed",),
            ),
            PlanNode(
                id="independent",
                capability_id="raw_html",
                adapter="recording",
            ),
            PlanNode(
                id="fallback",
                capability_id="boilerplate_removal",
                adapter="recording",
                fallback_for="failed",
            ),
        ),
    )

    try:
        result = await engine.execute(run_id, plan)
    finally:
        await ledger.close()

    assert calls == ["independent", "fallback"]
    dependent = next(
        outcome
        for outcome in result.capability_outcomes
        if outcome.capability_id == "main_article"
    )
    assert dependent.status.value == "NOT_APPLICABLE"


@pytest.mark.asyncio
async def test_unexpected_adapter_failure_finishes_run_with_typed_result(
    tmp_path: Path,
) -> None:
    class CrashingAdapter:
        async def execute(self, _: PlanNode, __: ExecutionContext) -> None:
            raise RuntimeError("internal secret detail")

    gateway = UniversalFetchGateway(_settings(tmp_path))
    gateway.adapters["core"] = CrashingAdapter()
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(FetchRequest(target="https://example.com"))

    assert result.status == ResultStatus.FAILED
    assert result.diagnostics[0].code == "internal_error"
    assert "internal secret detail" not in result.model_dump_json()
    snapshot = await gateway.get_run(result.run_id)
    assert snapshot.state == RunState.FINISHED
    assert snapshot.result is not None
    assert snapshot.result.status == ResultStatus.FAILED
    await gateway.close()


@pytest.mark.asyncio
async def test_planning_failure_finishes_with_typed_result(
    tmp_path: Path,
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))
    request = FetchRequest(
        target="https://example.com/data",
        output_requirements=("rest", "graphql"),
    )

    result = await gateway.fetch(request)

    assert result.status == ResultStatus.FAILED
    assert [diagnostic.code for diagnostic in result.diagnostics] == [
        "planning_failed"
    ]
    snapshot = await gateway.get_run(result.run_id)
    assert snapshot.state == RunState.FINISHED
    assert snapshot.result == result
    events = await gateway.ledger.events(result.run_id)
    assert "run.planning_failed" in {event.event_type for event in events}

    submitted = await gateway.submit(request)
    assert submitted.state == RunState.FINISHED
    assert submitted.result is not None
    assert (await gateway.wait(submitted.run_id)).status == ResultStatus.FAILED
    await gateway.close()


@pytest.mark.asyncio
async def test_approved_form_login_establishes_ephemeral_same_origin_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://form/login-proposal"
    password = "form-password-never-persist"
    cookie = "login-cookie-never-persist"
    csrf = "csrf-from-source"
    action = "https://example.com/session"
    forms = InMemoryFormSubmissionProvider(
        {
            reference: FormSubmission(
                target=action,
                method="POST",
                fields={"username": "agent", "password": password},
                authentication_ref=reference,
                approval=FormSubmissionApproval.grant(action, "POST"),
            )
        }
    )
    observed: list[tuple[str, str, str | None]] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(
            (request.method, request.url.path, request.headers.get("cookie"))
        )
        if request.url.path == "/login":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text=(
                    '<form action="/session" method="post">'
                    f'<input type="hidden" name="csrf_token" value="{csrf}">'
                    "</form>"
                ),
            )
        if request.url.path == "/session":
            return httpx.Response(
                303,
                headers={
                    "location": "/workspace",
                    "set-cookie": (
                        f"session={cookie}; Secure; HttpOnly; Path=/"
                    ),
                },
            )
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="Authenticated workspace content is complete and useful. " * 10,
        )

    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        form_submission_provider=forms,
    )
    http = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=gateway.credential_provider,
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["auth"] = AuthAdapter(
        http,
        credential_provider=gateway.credential_provider,
        session_provider=gateway.session_provider,
        form_submission_provider=forms,
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/login",
            output_requirements=("csrf_token", "form_submit"),
            authentication_ref=reference,
            approved_capabilities=frozenset({"form_submit"}),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    assert observed == [
        ("GET", "/login", None),
        ("POST", "/session", None),
        ("GET", "/workspace", f"session={cookie}"),
    ]
    outcomes = {
        (outcome.capability_id, outcome.status.value)
        for outcome in result.capability_outcomes
    }
    assert ("form_submit", "APPLIED") in outcomes
    assert ("cookie_session", "APPLIED") in outcomes
    assert ("login_session", "APPLIED") in outcomes
    serialized = result.model_dump_json()
    assert password not in serialized
    assert cookie not in serialized
    assert reference not in serialized
    stored = b"".join(
        path.read_bytes()
        for path in gateway.settings.artifact_dir.rglob("*")
        if path.is_file()
    )
    assert password.encode() not in stored
    assert cookie.encode() not in stored
    await gateway.close()
