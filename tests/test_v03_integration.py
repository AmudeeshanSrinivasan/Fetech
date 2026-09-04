from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest

from fetech.adapters.auth import AuthAdapter
from fetech.adapters.base import ExecutionContext
from fetech.adapters.http import HTTPAdapter
from fetech.auth import CredentialMaterial, InMemoryCredentialProvider
from fetech.auth_flows import (
    FormSubmission,
    FormSubmissionApproval,
    InMemoryFormSubmissionProvider,
    InMemorySessionProvider,
    OriginScopedSession,
    SessionProvider,
)
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import FetchRequest, ResourceBudget, ResultStatus
from fetech.planning import API_CAPABILITY_ORDER, DeterministicPlanner
from fetech.registry import CapabilityRegistry
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


def _public_policy(monkeypatch: pytest.MonkeyPatch) -> SafeURLPolicy:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    return policy


def _wire_http(
    gateway: UniversalFetchGateway,
    policy: SafeURLPolicy,
    transport: httpx.AsyncBaseTransport,
    provider: InMemoryCredentialProvider | None = None,
    form_provider: InMemoryFormSubmissionProvider | None = None,
    session_provider: SessionProvider | None = None,
) -> HTTPAdapter:
    credential_provider = provider or InMemoryCredentialProvider({})
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        credential_provider=credential_provider,
        transport=transport,
    )
    gateway.adapters["http"] = adapter
    gateway.adapters["auth"] = AuthAdapter(
        adapter,
        credential_provider=credential_provider,
        session_provider=session_provider,
        form_submission_provider=form_provider,
    )
    gateway.executor.adapters = gateway.adapters
    return adapter


@pytest.mark.parametrize("capability_id", API_CAPABILITY_ORDER)
def test_planner_selects_every_v03_api_capability(capability_id: str) -> None:
    request = FetchRequest(
        target="https://example.com/resource",
        output_requirements=(capability_id,),
    )
    plan = DeterministicPlanner(CapabilityRegistry()).plan(request)
    selected = [
        node
        for node in plan.nodes
        if node.adapter == "api" and node.capability_id == capability_id
    ]
    assert len(selected) == 1
    assert selected[0].dependencies == ("http",)


def test_planner_auto_detects_named_api_and_builds_safe_auth_nodes() -> None:
    planner = DeterministicPlanner(CapabilityRegistry())
    github = planner.plan(FetchRequest(target="https://api.github.com/repos/openai/openai-python"))
    assert any(
        node.adapter == "api" and node.capability_id == "github_api"
        for node in github.nodes
    )

    oauth = planner.plan(
        FetchRequest(
            target="https://example.com/data.json",
            output_requirements=("oauth", "json_endpoint"),
            authentication_ref="vault://oauth/example",
        )
    )
    auth_node = next(node for node in oauth.nodes if node.capability_id == "oauth")
    http_node = next(node for node in oauth.nodes if node.adapter == "http")
    assert auth_node.retry.maximum == 0
    assert http_node.dependencies == (auth_node.id,)
    assert all(node.adapter != "variants" for node in oauth.nodes)

    form = planner.plan(
        FetchRequest(
            target="https://example.com/login",
            output_requirements=("csrf_token", "form_submit"),
            authentication_ref="vault://form/example",
            approved_capabilities=frozenset({"form_submit"}),
        )
    )
    submit = next(node for node in form.nodes if node.capability_id == "form_submit")
    assert submit.requires_approval
    assert submit.retry.maximum == 0
    assert submit.dependencies == ("auth-csrf-token",)


@pytest.mark.asyncio
async def test_oauth_refreshes_once_and_emits_sanitized_events(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://oauth/private"
    refresh_reference = "vault://oauth/private/refresh"
    expired_secret = "expired-oauth-secret"
    refreshed_secret = "refreshed-oauth-secret"
    provider = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.bearer(
                "https://example.com",
                expired_secret,
                expires_at=datetime.now(UTC) - timedelta(seconds=1),
            )
        },
        refreshed={
            refresh_reference: CredentialMaterial.bearer(
                "https://example.com",
                refreshed_secret,
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
        },
    )
    sessions = InMemorySessionProvider(
        {
            reference: OriginScopedSession.oauth(
                "https://example.com",
                reference,
                issuer_origin="https://identity.example",
                refresh_ref=refresh_reference,
            )
        }
    )
    observed: list[str | None] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(request.headers.get("authorization"))
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"data": [{"id": 1}]},
        )

    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        credential_provider=provider,
        session_provider=sessions,
    )
    _wire_http(
        gateway,
        _public_policy(monkeypatch),
        httpx.MockTransport(respond),
        provider,
        session_provider=sessions,
    )
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/data.json",
            output_requirements=("oauth", "json_endpoint"),
            authentication_ref=reference,
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    assert observed == [f"Bearer {refreshed_secret}"]
    assert expired_secret not in result.model_dump_json()
    assert refreshed_secret not in result.model_dump_json()
    assert any(
        outcome.capability_id == "oauth" and outcome.status.value == "APPLIED"
        for outcome in result.capability_outcomes
    )
    event_types = {event.event_type for event in await gateway.ledger.events(result.run_id)}
    assert {"auth.refresh.started", "auth.refresh.succeeded"} <= event_types
    await gateway.close()


@pytest.mark.asyncio
async def test_private_workspace_requires_private_profile_before_transport(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://workspace/private"
    provider = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.cookie_session(
                "https://example.com",
                {"session": "private-cookie"},
            )
        }
    )
    called = False

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        credential_provider=provider,
    )
    _wire_http(
        gateway,
        _public_policy(monkeypatch),
        httpx.MockTransport(respond),
        provider,
    )
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/private",
            output_requirements=("private_workspace",),
            authentication_ref=reference,
        )
    )

    assert result.status == ResultStatus.BLOCKED_BY_POLICY
    assert not called
    assert any(
        decision.policy_id == "private_workspace_privacy"
        and not decision.allowed
        for decision in result.policy_decisions
    )
    await gateway.close()


@pytest.mark.asyncio
async def test_approved_csrf_form_submission_is_ephemeral_and_same_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://form/private"
    form_secret = "password-never-persist"
    csrf_secret = "csrf-never-submit-to-logs"
    provider = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.cookie_session(
                "https://example.com",
                {"session": "configured-cookie"},
            )
        }
    )
    action = "https://example.com/session"
    approval = FormSubmissionApproval.grant(action, "POST")
    submission = FormSubmission(
        target=action,
        method="POST",
        fields={"username": "agent", "password": form_secret},
        authentication_ref=reference,
        approval=approval,
    )
    form_provider = InMemoryFormSubmissionProvider({reference: submission})
    observed: list[tuple[str, str, bytes]] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        content = await request.aread()
        observed.append((request.method, request.url.path, content))
        if request.url.path == "/login":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text=(
                    '<form action="/session" method="post">'
                    f'<input type="hidden" name="csrf_token" value="{csrf_secret}">'
                    "</form>"
                ),
            )
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="Authenticated workspace content is complete and useful. " * 10,
        )

    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        credential_provider=provider,
        form_submission_provider=form_provider,
    )
    _wire_http(
        gateway,
        _public_policy(monkeypatch),
        httpx.MockTransport(respond),
        provider,
        form_provider,
    )
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/login",
            output_requirements=("csrf_token", "form_submit"),
            authentication_ref=reference,
            approved_capabilities=frozenset({"form_submit"}),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    assert [(method, path) for method, path, _ in observed] == [
        ("GET", "/login"),
        ("POST", "/session"),
    ]
    submitted = parse_qs(observed[1][2].decode())
    assert submitted == {
        "csrf_token": [csrf_secret],
        "password": [form_secret],
        "username": ["agent"],
    }
    serialized = result.model_dump_json()
    assert form_secret not in serialized
    assert csrf_secret not in serialized
    assert reference not in serialized
    stored_bodies = b"".join(
        path.read_bytes()
        for path in gateway.settings.artifact_dir.rglob("*")
        if path.is_file()
    )
    assert form_secret.encode() not in stored_bodies
    assert any(
        outcome.capability_id == "form_submit"
        and outcome.status.value == "APPLIED"
        for outcome in result.capability_outcomes
    )
    await gateway.close()


@pytest.mark.asyncio
async def test_form_submit_without_request_approval_is_blocked_before_post(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    reference = "vault://form/unapproved"
    provider = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.cookie_session(
                "https://example.com",
                {"session": "configured-cookie"},
            )
        }
    )
    action = "https://example.com/session"
    form_provider = InMemoryFormSubmissionProvider(
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
    methods: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        methods.append(request.method)
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="Login form content is available for an approved submission.",
        )

    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        credential_provider=provider,
        form_submission_provider=form_provider,
    )
    _wire_http(
        gateway,
        _public_policy(monkeypatch),
        httpx.MockTransport(respond),
        provider,
        form_provider,
    )
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/login",
            output_requirements=("form_submit",),
            authentication_ref=reference,
        )
    )

    assert result.status == ResultStatus.BLOCKED_BY_POLICY
    assert methods == ["GET"]
    assert any(
        decision.policy_id == "capability_approval" and not decision.allowed
        for decision in result.policy_decisions
    )
    await gateway.close()


@pytest.mark.asyncio
async def test_request_body_redirects_never_replay_cross_origin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[tuple[str, str, bytes]] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        content = await request.aread()
        observed.append((request.method, request.url.host or "", content))
        return httpx.Response(
            307,
            headers={"location": "https://other.example/collect"},
        )

    request = FetchRequest(
        target="https://example.com/submit",
        approved_capabilities=frozenset({"form_submit"}),
        budget=ResourceBudget(redirects=2),
    )
    context = ExecutionContext(
        run_id=uuid4(),
        request=request,
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    with pytest.raises(PolicyBlockedError, match="cannot replay"):
        await adapter._request(
            request.target,
            context,
            method_override="POST",
            body=b"secret=never-replayed",
            extra_headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
    assert observed == [("POST", "example.com", b"secret=never-replayed")]


@pytest.mark.asyncio
async def test_named_api_runs_through_gateway_with_lineage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"id": 1, "full_name": "openai/example"},
        )

    gateway = UniversalFetchGateway(_settings(tmp_path))
    _wire_http(
        gateway,
        _public_policy(monkeypatch),
        httpx.MockTransport(respond),
    )
    result = await gateway.fetch(
        FetchRequest(
            target="https://api.github.com/repos/openai/example",
            output_requirements=("github_api",),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    primary = next(
        artifact for artifact in result.artifacts if artifact.representation == "api_response"
    )
    raw = next(artifact for artifact in result.artifacts if artifact.representation == "raw")
    assert primary.parent_artifact_ids == (raw.artifact_id,)
    assert any(
        outcome.capability_id == "github_api"
        and outcome.status.value == "APPLIED"
        for outcome in result.capability_outcomes
    )
    body = json.loads(
        await gateway.cas.get(primary.cas_uri, maximum_bytes=primary.size)
    )
    assert body["authority_url"] == "https://api.github.com/repos/openai/example"
    await gateway.close()


def test_v03_closure_is_119_cumulative_capabilities() -> None:
    document = CapabilityRegistry().as_document()
    releases = document["releases"]
    assert releases["v0.3"] == {
        "release": "v0.3",
        "capability_count": 23,
        "implementation_path_count": 23,
        "runtime_available_count": 21,
        "closure_ready": True,
        "status_counts": {"native": 21, "optional": 2},
        "gaps": [],
    }
    assert sum(
        int(releases[release]["implementation_path_count"])
        for release in ("v0.1", "v0.2", "v0.3")
    ) == 119
