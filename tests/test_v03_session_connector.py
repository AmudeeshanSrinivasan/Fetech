from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4

import httpx
import pytest

from fetech.adapters.auth import AuthAdapter
from fetech.adapters.base import (
    AdapterAuthExpiredError,
    AdapterAuthRequiredError,
    AdapterDependencyError,
    AdapterExecutionError,
    ExecutionContext,
)
from fetech.adapters.http import HTTPAdapter
from fetech.auth import (
    CredentialMaterial,
    CredentialProvider,
    InMemoryCredentialProvider,
)
from fetech.auth_flows import (
    AuthFlowError,
    CSRFTokenMaterial,
    FormSubmission,
    FormSubmissionApproval,
    FormSubmissionNotFoundError,
    FormSubmissionProvider,
    InMemoryFormSubmissionProvider,
    InMemorySessionProvider,
    NullFormSubmissionProvider,
    OriginScopedSession,
    SessionCapability,
    SessionProvider,
)
from fetech.models import (
    FetchRequest,
    PlanNode,
    QualityAssessment,
    Resource,
)
from fetech.security import PolicyBlockedError, SafeURLPolicy
from fetech.storage import FileSystemCAS, build_artifact


def _context(
    tmp_path: Path,
    *,
    target: str = "https://example.com/private",
    authentication_ref: str = "vault://session/access",
    privacy_profile: Literal["public", "private"] = "public",
) -> ExecutionContext:
    return ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(
            target=target,
            authentication_ref=authentication_ref,
            privacy_profile=privacy_profile,
        ),
        cas=FileSystemCAS(tmp_path / str(uuid4())),
    )


def _node(capability_id: str) -> PlanNode:
    return PlanNode(
        id=f"auth-{capability_id}",
        capability_id=capability_id,
        adapter="auth",
    )


def _public_policy(monkeypatch: pytest.MonkeyPatch) -> SafeURLPolicy:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    return policy


def _adapter(
    monkeypatch: pytest.MonkeyPatch,
    credentials: CredentialProvider,
    *,
    sessions: SessionProvider | None = None,
    forms: FormSubmissionProvider | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
) -> AuthAdapter:
    http = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        credential_provider=credentials,
        transport=transport,
    )
    return AuthAdapter(
        http,
        credential_provider=credentials,
        session_provider=sessions,
        form_submission_provider=forms,
    )


class _TrackingSessionProvider:
    def __init__(self, session: OriginScopedSession) -> None:
        self.session = session
        self.calls = 0

    async def resolve(self, authentication_ref: str) -> OriginScopedSession:
        del authentication_ref
        self.calls += 1
        return self.session


class _TrackingCredentialProvider:
    def __init__(
        self,
        material: CredentialMaterial,
        *,
        refreshed: CredentialMaterial | None = None,
    ) -> None:
        self.material = material
        self.refreshed = refreshed
        self.resolve_calls = 0
        self.refresh_calls = 0

    async def resolve(self, reference: str) -> CredentialMaterial:
        del reference
        self.resolve_calls += 1
        return self.material

    async def refresh(self, reference: str) -> CredentialMaterial:
        del reference
        self.refresh_calls += 1
        if self.refreshed is None:
            raise AssertionError("refresh must not be called")
        return self.refreshed


@pytest.mark.asyncio
async def test_destination_policy_runs_before_session_or_credential_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://session/access"
    session_provider = _TrackingSessionProvider(
        OriginScopedSession.login_session("https://example.com", reference)
    )
    credentials = _TrackingCredentialProvider(
        CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "secret"},
        )
    )
    adapter = _adapter(
        monkeypatch,
        credentials,
        sessions=session_provider,
    )
    context = _context(
        tmp_path,
        target="https://localhost/private",
        authentication_ref=reference,
    )

    with pytest.raises(PolicyBlockedError):
        await adapter.execute(_node("login_session"), context)

    assert session_provider.calls == 0
    assert credentials.resolve_calls == 0
    assert credentials.refresh_calls == 0
    assert context.attempts[-1].failure_code == "policy"


@pytest.mark.asyncio
async def test_private_profile_is_checked_before_provider_access(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://workspace/access"
    session_provider = _TrackingSessionProvider(
        OriginScopedSession.private_workspace(
            "https://example.com",
            reference,
            connector_id="workspace.documents",
        )
    )
    credentials = _TrackingCredentialProvider(
        CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "secret"},
        )
    )
    adapter = _adapter(
        monkeypatch,
        credentials,
        sessions=session_provider,
    )
    context = _context(tmp_path, authentication_ref=reference)

    with pytest.raises(PolicyBlockedError) as error:
        await adapter.execute(_node("private_workspace"), context)

    assert session_provider.calls == 0
    assert credentials.resolve_calls == 0
    assert error.value.decisions[0].policy_id == "private_workspace_privacy"
    assert context.attempts[-1].failure_code == "policy"


@pytest.mark.asyncio
async def test_absent_session_provider_is_dependency_missing_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://session/access"
    credentials = _TrackingCredentialProvider(
        CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "secret"},
        )
    )
    adapter = _adapter(monkeypatch, credentials)
    context = _context(tmp_path, authentication_ref=reference)

    with pytest.raises(AdapterDependencyError, match="session provider"):
        await adapter.execute(_node("login_session"), context)

    assert credentials.resolve_calls == 0
    assert context.attempts[-1].failure_code == "dependency_missing"


@pytest.mark.asyncio
@pytest.mark.parametrize("capability_id", ["sso", "private_workspace"])
async def test_missing_configured_external_connector_is_dependency_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capability_id: str,
) -> None:
    credentials = _TrackingCredentialProvider(
        CredentialMaterial.bearer("https://example.com", "secret")
    )
    adapter = _adapter(
        monkeypatch,
        credentials,
        sessions=InMemorySessionProvider({}),
    )
    context = _context(
        tmp_path,
        privacy_profile="private" if capability_id == "private_workspace" else "public",
    )

    with pytest.raises(AdapterDependencyError, match="connector"):
        await adapter.execute(_node(capability_id), context)

    assert credentials.resolve_calls == 0
    assert context.attempts[-1].failure_code == "dependency_missing"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("capability_id", "session", "material", "privacy_profile"),
    [
        (
            "login_session",
            OriginScopedSession.login_session(
                "https://example.com",
                "vault://session/access",
            ),
            CredentialMaterial.cookie_session(
                "https://example.com",
                {"session": "login-secret"},
            ),
            "public",
        ),
        (
            "sso",
            OriginScopedSession.sso(
                "https://example.com",
                "vault://session/access",
                issuer_origin="https://idp.example",
                scopes=("documents:read",),
            ),
            CredentialMaterial.bearer(
                "https://example.com",
                "sso-secret",
            ),
            "public",
        ),
        (
            "private_workspace",
            OriginScopedSession.private_workspace(
                "https://example.com",
                "vault://session/access",
                connector_id="workspace.documents",
            ),
            CredentialMaterial.cookie_session(
                "https://example.com",
                {"session": "workspace-secret"},
            ),
            "private",
        ),
    ],
)
async def test_configured_session_connectors_validate_typed_descriptors(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capability_id: str,
    session: OriginScopedSession,
    material: CredentialMaterial,
    privacy_profile: Literal["public", "private"],
) -> None:
    reference = "vault://session/access"
    adapter = _adapter(
        monkeypatch,
        InMemoryCredentialProvider({reference: material}),
        sessions=InMemorySessionProvider({reference: session}),
    )
    context = _context(
        tmp_path,
        authentication_ref=reference,
        privacy_profile=privacy_profile,
    )

    await adapter.execute(_node(capability_id), context)

    assert context.attempts[-1].failure_code is None
    assert context.sensitive_state["origin_scoped_session"] is session
    outcome = next(
        item for item in context.capability_outcomes if item.capability_id == capability_id
    )
    if capability_id == "sso":
        assert outcome.details["issuer_origin"] == "https://idp.example"
        assert outcome.details["scope_count"] == 1
    if capability_id == "private_workspace":
        assert outcome.details["connector_id"] == "workspace.documents"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "session",
    [
        OriginScopedSession.login_session(
            "https://example.com",
            "vault://different/reference",
        ),
        OriginScopedSession.oauth(
            "https://example.com",
            "vault://session/access",
            issuer_origin="https://idp.example",
        ),
        OriginScopedSession.login_session(
            "https://other.example",
            "vault://session/access",
        ),
    ],
)
async def test_descriptor_reference_capability_and_origin_mismatch_fail_before_credentials(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    session: OriginScopedSession,
) -> None:
    credentials = _TrackingCredentialProvider(
        CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "secret"},
        )
    )
    adapter = _adapter(
        monkeypatch,
        credentials,
        sessions=_TrackingSessionProvider(session),
    )
    context = _context(tmp_path)

    with pytest.raises(AdapterAuthRequiredError):
        await adapter.execute(_node("login_session"), context)

    assert credentials.resolve_calls == 0
    assert context.attempts[-1].failure_code == "auth_required"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "material",
    [
        CredentialMaterial.bearer(
            "https://other.example",
            "expired-secret",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        ),
        CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "expired-secret"},
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        ),
    ],
)
async def test_existing_credential_binding_is_checked_before_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    material: CredentialMaterial,
) -> None:
    reference = "vault://session/access"
    refresh_ref = "vault://session/refresh"
    session = OriginScopedSession.oauth(
        "https://example.com",
        reference,
        issuer_origin="https://idp.example",
        refresh_ref=refresh_ref,
    )
    credentials = _TrackingCredentialProvider(
        material,
        refreshed=CredentialMaterial.bearer(
            "https://example.com",
            "fresh-secret",
        ),
    )
    adapter = _adapter(
        monkeypatch,
        credentials,
        sessions=InMemorySessionProvider({reference: session}),
    )
    context = _context(tmp_path, authentication_ref=reference)

    with pytest.raises(AdapterAuthRequiredError):
        await adapter.execute(_node("oauth"), context)

    assert credentials.refresh_calls == 0
    assert context.attempts[-1].failure_code == "auth_required"


@pytest.mark.asyncio
@pytest.mark.parametrize("capability_id", ["oauth", "sso"])
async def test_only_descriptor_authorized_bearer_sessions_refresh_with_sanitized_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capability_id: str,
) -> None:
    reference = "vault://session/access"
    refresh_ref = "vault://session/refresh"
    expired_secret = "expired-secret-value"
    refreshed_secret = "refreshed-secret-value"
    session = OriginScopedSession(
        origin="https://example.com",
        capability_id=SessionCapability(capability_id),
        authentication_ref=reference,
        issuer_origin="https://idp.example",
        refresh_ref=refresh_ref,
    )
    credentials = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.bearer(
                "https://example.com",
                expired_secret,
                expires_at=datetime.now(UTC) - timedelta(minutes=1),
            )
        },
        refreshed={
            refresh_ref: CredentialMaterial.bearer(
                "https://example.com",
                refreshed_secret,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        },
    )
    adapter = _adapter(
        monkeypatch,
        credentials,
        sessions=InMemorySessionProvider({reference: session}),
    )
    context = _context(tmp_path, authentication_ref=reference)

    await adapter.execute(_node(capability_id), context)

    assert context.attempts[-1].failure_code is None
    assert [event[0] for event in context.pending_events] == [
        "auth.refresh.started",
        "auth.refresh.succeeded",
        "auth.session.validated",
    ]
    serialized_events = repr(context.pending_events)
    assert reference not in serialized_events
    assert refresh_ref not in serialized_events
    assert expired_secret not in serialized_events
    assert refreshed_secret not in serialized_events
    assert all(
        payload.get("capability_id") == capability_id
        for _, _, payload in context.pending_events
    )


@pytest.mark.asyncio
async def test_sso_refresh_cannot_change_bearer_to_cookie_material(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://session/access"
    refresh_ref = "vault://session/refresh"
    session = OriginScopedSession.sso(
        "https://example.com",
        reference,
        issuer_origin="https://idp.example",
        refresh_ref=refresh_ref,
    )
    credentials = _TrackingCredentialProvider(
        CredentialMaterial.bearer(
            "https://example.com",
            "expired-secret",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
        ),
        refreshed=CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "wrong-kind"},
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        ),
    )
    adapter = _adapter(
        monkeypatch,
        credentials,
        sessions=InMemorySessionProvider({reference: session}),
    )
    context = _context(tmp_path, authentication_ref=reference)

    with pytest.raises(AdapterAuthRequiredError, match="authentication type"):
        await adapter.execute(_node("sso"), context)

    assert credentials.refresh_calls == 1
    assert context.attempts[-1].failure_code == "auth_required"


@pytest.mark.asyncio
@pytest.mark.parametrize("capability_id", ["login_session", "private_workspace"])
async def test_cookie_and_workspace_sessions_never_enter_oauth_refresh(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capability_id: str,
) -> None:
    reference = "vault://session/access"
    expired = CredentialMaterial.cookie_session(
        "https://example.com",
        {"session": "expired-secret"},
        expires_at=datetime.now(UTC) - timedelta(minutes=1),
    )
    credentials = _TrackingCredentialProvider(
        expired,
        refreshed=CredentialMaterial.cookie_session(
            "https://example.com",
            {"session": "fresh-secret"},
        ),
    )
    session = (
        OriginScopedSession.login_session("https://example.com", reference)
        if capability_id == "login_session"
        else OriginScopedSession.private_workspace(
            "https://example.com",
            reference,
            connector_id="workspace.documents",
        )
    )
    adapter = _adapter(
        monkeypatch,
        credentials,
        sessions=InMemorySessionProvider({reference: session}),
    )
    context = _context(
        tmp_path,
        authentication_ref=reference,
        privacy_profile="private" if capability_id == "private_workspace" else "public",
    )

    with pytest.raises(AdapterAuthExpiredError):
        await adapter.execute(_node(capability_id), context)

    assert credentials.refresh_calls == 0
    assert context.attempts[-1].failure_code == "auth_expired"
    assert not any(
        event_type.startswith("auth.refresh")
        for event_type, _, _ in context.pending_events
    )


@pytest.mark.asyncio
async def test_form_provider_consumption_is_atomic_and_one_shot() -> None:
    reference = "vault://form/proposal"
    target = "https://example.com/session"
    submission = FormSubmission(
        target=target,
        method="POST",
        fields={"username": "agent"},
        authentication_ref=reference,
        approval=FormSubmissionApproval.grant(target, "POST"),
    )
    provider = InMemoryFormSubmissionProvider({reference: submission})

    outcomes = await asyncio.gather(
        provider.consume(reference, uuid4()),
        provider.consume(reference, uuid4()),
        return_exceptions=True,
    )

    assert sum(item is submission for item in outcomes) == 1
    assert sum(isinstance(item, FormSubmissionNotFoundError) for item in outcomes) == 1
    with pytest.raises(FormSubmissionNotFoundError):
        await NullFormSubmissionProvider().consume(reference, uuid4())


def test_get_form_proposals_are_rejected() -> None:
    with pytest.raises(AuthFlowError, match="GET form proposals"):
        FormSubmission(
            target="https://example.com/search",
            method="GET",
            fields={"q": "fetech"},
        )


@pytest.mark.asyncio
async def test_csrf_is_bound_to_redirected_resource_matching_artifact_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://session/access"
    credentials = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.cookie_session(
                "https://example.com",
                {"session": "secret"},
            )
        }
    )
    adapter = _adapter(monkeypatch, credentials)
    context = _context(
        tmp_path,
        target="https://example.com/start",
        authentication_ref=reference,
    )
    redirected = Resource(
        canonical_url="https://example.com/login",
        requested_url="https://example.com/start",
        authority_url="https://example.com/start",
        media_type="text/html",
        status_code=200,
    )
    body = (
        b'<form action="/session" method="post">'
        b'<input type="hidden" name="csrf_token" value="redirect-secret">'
        b"</form>"
    )
    uri, digest, size = await context.cas.put(body)
    raw = build_artifact(
        role="source",
        representation="raw",
        media_type="text/html",
        cas_uri=uri,
        digest=digest,
        size=size,
        resource=redirected,
        extractor="test/1",
        quality=QualityAssessment(),
    )
    context.resources.append(redirected)
    context.artifacts.append(raw)

    await adapter.execute(_node("csrf_token"), context)

    token = context.sensitive_state["csrf_token"]
    assert isinstance(token, CSRFTokenMaterial)
    assert token.source_url == "https://example.com/login"
    assert token.form_action == "https://example.com/session"
    assert context.sensitive_state["csrf_source_resource_id"] == redirected.resource_id

    context.resources.clear()
    with pytest.raises(AdapterDependencyError, match="matching source"):
        await adapter.execute(_node("csrf_token"), context)
    assert context.attempts[-1].failure_code == "dependency_missing"


@pytest.mark.asyncio
async def test_provider_csrf_must_match_current_artifact_bound_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://form/proposal"
    source_url = "https://example.com/login"
    action = "https://example.com/session"
    extracted = CSRFTokenMaterial(
        source_url=source_url,
        form_action=action,
        form_method="POST",
        field_name="csrf_token",
        token="fresh-source-token",
    )
    supplied = CSRFTokenMaterial(
        source_url=source_url,
        form_action=action,
        form_method="POST",
        field_name="csrf_token",
        token="stale-provider-token",
    )
    forms = InMemoryFormSubmissionProvider(
        {
            reference: FormSubmission(
                target=action,
                method="POST",
                fields={"username": "agent"},
                authentication_ref=reference,
                csrf=supplied,
                approval=FormSubmissionApproval.grant(action, "POST"),
            )
        }
    )
    transport_called = False

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal transport_called
        transport_called = True
        return httpx.Response(200)

    adapter = _adapter(
        monkeypatch,
        InMemoryCredentialProvider({}),
        forms=forms,
        transport=httpx.MockTransport(respond),
    )
    context = _context(
        tmp_path,
        target=source_url,
        authentication_ref=reference,
    )
    source = Resource(
        canonical_url=source_url,
        requested_url=source_url,
        authority_url=source_url,
        media_type="text/html",
        status_code=200,
    )
    context.resources.append(source)
    context.sensitive_state["csrf_token"] = extracted
    context.sensitive_state["csrf_source_resource_id"] = source.resource_id

    with pytest.raises(AdapterExecutionError, match="current source binding"):
        await adapter.execute(_node("form_submit"), context)

    assert not transport_called
    assert context.attempts[-1].failure_code == "adapter_failed"


@pytest.mark.asyncio
async def test_auth_adapter_consumes_form_proposal_once(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://form/proposal"
    action = "https://example.com/session"
    credentials = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.cookie_session(
                "https://example.com",
                {"session": "secret"},
            )
        }
    )
    forms = InMemoryFormSubmissionProvider(
        {
            reference: FormSubmission(
                target=action,
                method="POST",
                fields={"username": "agent"},
                authentication_ref=reference,
                approval=FormSubmissionApproval.grant(action, "POST"),
            )
        }
    )

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="Authenticated content is complete and useful. " * 10,
        )

    adapter = _adapter(
        monkeypatch,
        credentials,
        forms=forms,
        transport=httpx.MockTransport(respond),
    )
    first = _context(
        tmp_path,
        target="https://example.com/login",
        authentication_ref=reference,
    )
    await adapter.execute(_node("form_submit"), first)

    second = _context(
        tmp_path,
        target="https://example.com/login",
        authentication_ref=reference,
    )
    with pytest.raises(AdapterDependencyError):
        await adapter.execute(_node("form_submit"), second)

    assert first.attempts[-1].failure_code is None
    assert second.attempts[-1].failure_code == "dependency_missing"
