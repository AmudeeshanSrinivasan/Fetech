from __future__ import annotations

from pathlib import Path
from urllib.parse import parse_qs
from uuid import uuid4

import httpx
import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from sqlalchemy import select

from fetech.adapters.discovery import DiscoveryAdapter
from fetech.adapters.http import HTTPAdapter
from fetech.auth import CredentialMaterial, InMemoryCredentialProvider
from fetech.config import Settings
from fetech.daemon import create_app
from fetech.gateway import UniversalFetchGateway
from fetech.ledger import EventLedger, EventRow, RunRow
from fetech.models import (
    FetchPlan,
    FetchRequest,
    ProvenanceEvent,
    ResourceBudget,
    ResultStatus,
)
from fetech.planning import DeterministicPlanner
from fetech.registry import CapabilityRegistry
from fetech.security import SafeURLPolicy


def test_fetch_request_accepts_only_documented_privacy_profiles() -> None:
    assert FetchRequest(target="https://example.com").privacy_profile == "public"
    assert (
        FetchRequest(
            target="https://example.com/private",
            privacy_profile="private",
            output_requirements=("private_workspace",),
        ).privacy_profile
        == "private"
    )

    for invalid in ("internal", "non-public", "PRIVATE", "", " public"):
        with pytest.raises(ValidationError, match="privacy_profile"):
            FetchRequest(target="https://example.com", privacy_profile=invalid)  # type: ignore[arg-type]


def test_authenticated_plan_has_redacted_public_and_raw_in_memory_views() -> None:
    secret = "unknown-name-secret"
    ordinary = "ordinary-looking-value"
    request = FetchRequest(
        target=f"https://example.com/data.json?opaque={secret}&page={ordinary}",
        output_requirements=("json_endpoint",),
        authentication_ref="vault://fetech/account",
    )

    plan = DeterministicPlanner(CapabilityRegistry()).plan(request)
    serialized = plan.model_dump_json()

    assert secret not in serialized
    assert ordinary not in serialized
    assert plan.request.target == (
        "https://example.com/data.json?"
        "opaque=%5BREDACTED%5D&page=%5BREDACTED%5D"
    )
    assert plan.execution_request.target == request.target

    persisted_plan = FetchPlan.model_validate_json(serialized)
    with pytest.raises(ValueError, match="no in-memory execution request"):
        _ = persisted_plan.execution_request
    with pytest.raises(ValueError, match="does not match"):
        persisted_plan.bind_execution_request(
            request.model_copy(
                update={"target": "https://attacker.example/other?opaque=secret"}
            )
        )


def test_rest_plan_never_returns_authenticated_query_values(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    secret = "rest-unknown-secret"
    ordinary = "rest-ordinary-value"
    application = create_app()

    with TestClient(application) as client:
        response = client.post(
            "/v1/plan",
            json={
                "target": (
                    "https://example.com/data.json?"
                    f"opaque={secret}&page={ordinary}"
                ),
                "output_requirements": ["json_endpoint"],
                "authentication_ref": "vault://fetech/account",
            },
        )

    assert response.status_code == 200, response.text
    serialized = response.text
    assert secret not in serialized
    assert ordinary not in serialized
    assert response.json()["request"]["target"] == (
        "https://example.com/data.json?"
        "opaque=%5BREDACTED%5D&page=%5BREDACTED%5D"
    )


@pytest.mark.asyncio
async def test_authenticated_target_is_raw_only_for_transport_and_redacted_everywhere_else(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret = "transport-unknown-secret"
    ordinary = "transport-ordinary-value"
    target = f"https://example.com/data.json?opaque={secret}&page={ordinary}"
    reference = "vault://fetech/account"
    provider = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.bearer(
                "https://example.com",
                "runtime-only-token",
            )
        }
    )
    settings = Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
        per_host_min_interval_seconds=0,
    )
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    transported: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        transported.append(str(request.url))
        assert request.headers["authorization"] == "Bearer runtime-only-token"
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"items": [{"id": 1}]},
        )

    gateway = UniversalFetchGateway(settings, credential_provider=provider)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        credential_provider=provider,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters
    request = FetchRequest(
        target=target,
        output_requirements=("json_endpoint",),
        authentication_ref=reference,
    )
    result = await gateway.fetch(request)

    assert result.status == ResultStatus.SUCCEEDED
    assert len(transported) == 1
    assert parse_qs(httpx.URL(transported[0]).query.decode()) == {
        "opaque": [secret],
        "page": [ordinary],
    }
    assert secret not in result.model_dump_json()
    assert ordinary not in result.model_dump_json()
    artifact_bytes = b"".join(
        [
            await gateway.cas.get(
                artifact.cas_uri,
                maximum_bytes=max(1, artifact.size),
            )
            for artifact in result.artifacts
        ]
    )
    assert secret.encode() not in artifact_bytes
    assert ordinary.encode() not in artifact_bytes

    events = await gateway.ledger.events(result.run_id)
    snapshot = await gateway.get_run(result.run_id)
    async with gateway.ledger.sessions() as session:
        run_row = await session.scalar(
            select(RunRow).where(RunRow.run_id == str(result.run_id))
        )
        event_rows = (
            await session.scalars(
                select(EventRow).where(EventRow.run_id == str(result.run_id))
            )
        ).all()
    assert run_row is not None
    durable = "\n".join(
        [
            run_row.request_json,
            run_row.result_json or "",
            *(row.payload_json for row in event_rows),
            *(event.model_dump_json() for event in events),
            snapshot.model_dump_json(),
            settings.runtime_graph_path.read_text(encoding="utf-8"),
        ]
    )
    assert secret not in durable
    assert ordinary not in durable
    assert "%5BREDACTED%5D" in run_row.request_json
    await gateway.close()


@pytest.mark.asyncio
async def test_authenticated_crawl_report_redacts_every_query_value(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    secret = "crawl-unknown-secret"
    ordinary = "crawl-ordinary-value"
    reference = "vault://fetech/crawl"
    provider = InMemoryCredentialProvider(
        {
            reference: CredentialMaterial.bearer(
                "https://example.com",
                "runtime-only-token",
            )
        }
    )
    settings = Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
        per_host_min_interval_seconds=0,
    )
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)

    async def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="Useful authenticated crawl content. " * 20,
        )

    gateway = UniversalFetchGateway(settings, credential_provider=provider)
    http = HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        credential_provider=provider,
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["discovery"] = DiscoveryAdapter(http)
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(
        FetchRequest(
            target=(
                "https://example.com/root?"
                f"opaque={secret}&page={ordinary}"
            ),
            intent="crawl",
            authentication_ref=reference,
            budget=ResourceBudget(crawl_pages=1),
        )
    )

    report = next(
        artifact
        for artifact in result.artifacts
        if artifact.representation == "crawl_report"
    )
    body = await gateway.cas.get(report.cas_uri, maximum_bytes=report.size)
    assert secret.encode() not in body
    assert ordinary.encode() not in body
    assert b"%5BREDACTED%5D" in body
    await gateway.close()


@pytest.mark.asyncio
async def test_event_ledger_recursively_redacts_adversarial_secret_keys(
    tmp_path: Path,
) -> None:
    secrets = {
        "csrf_token": "csrf-never-store",
        "refreshToken": "refresh-never-store",
        "session-cookie": "cookie-never-store",
        "client_secret": "client-never-store",
        "password_hash": "password-never-store",
        "authentication_ref": "auth-ref-never-store",
        "auth_header": "auth-header-never-store",
        "credential_blob": "credential-never-store",
        "apiKey": "api-key-never-store",
    }
    payload = {
        **secrets,
        "safe": "retained",
        "model_tokens": 123,
        "token_budget": 4_000,
        "nested": [
            {
                "safe_child": "retained-child",
                "access_token": "nested-token-never-store",
            },
            {
                "deeper": (
                    {
                        "sessionCookie": "deep-cookie-never-store",
                        "clientPassword": "deep-password-never-store",
                    },
                )
            },
        ],
        "authority_url": "https://example.com/path?token=never-store&q=retained",
    }

    ledger = EventLedger.sqlite(tmp_path / "events.sqlite3")
    await ledger.initialize()
    run_id = uuid4()
    await ledger.append(
        ProvenanceEvent(
            run_id=run_id,
            event_type="security.regression",
            actor="test",
            payload=payload,
        )
    )

    stored = (await ledger.events(run_id))[0].payload
    await ledger.close()

    for key in secrets:
        assert stored[key] == "[REDACTED]"
    assert stored["safe"] == "retained"
    assert stored["model_tokens"] == 123
    assert stored["token_budget"] == 4_000
    assert stored["nested"] == [
        {
            "safe_child": "retained-child",
            "access_token": "[REDACTED]",
        },
        {
            "deeper": [
                {
                    "sessionCookie": "[REDACTED]",
                    "clientPassword": "[REDACTED]",
                }
            ]
        },
    ]
    assert stored["authority_url"] == (
        "https://example.com/path?token=%5BREDACTED%5D&q=retained"
    )

    serialized = str(stored)
    assert all(secret not in serialized for secret in secrets.values())
    assert "nested-token-never-store" not in serialized
    assert "deep-cookie-never-store" not in serialized
    assert "deep-password-never-store" not in serialized
