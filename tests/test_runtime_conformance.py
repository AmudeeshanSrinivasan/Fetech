from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from fetech.adapters.http import HTTPAdapter
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import FetchRequest, ResultStatus
from fetech.security import SafeURLPolicy


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


@pytest.mark.asyncio
async def test_full_gateway_fetch_is_persisted_and_projected(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)

    async def respond(request: httpx.Request) -> httpx.Response:
        assert request.headers["user-agent"].startswith("Fetech/")
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<html><main>Bounded useful fixture content for the universal runtime.</main></html>",
        )

    gateway = UniversalFetchGateway(_settings(tmp_path))
    gateway.policy = policy
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters
    await gateway.initialize()
    result = await gateway.fetch(FetchRequest(target="https://example.com/article"))
    assert result.status == ResultStatus.SUCCEEDED
    assert [artifact.representation for artifact in result.artifacts] == [
        "raw",
        "url_candidates",
        "clean_text",
    ]
    snapshot = await gateway.get_run(result.run_id)
    assert snapshot.result == result
    graph = json.loads(gateway.settings.runtime_graph_path.read_text(encoding="utf-8"))
    assert graph["graph"]["projection"] == "fetech-runtime"
    assert any(node["type"] == "FetchRun" for node in graph["nodes"])
    await gateway.close()


@pytest.mark.asyncio
async def test_gateway_returns_policy_block_without_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))
    called = False

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200, text="should not happen")

    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(FetchRequest(target="http://127.0.0.1/secret"))
    assert result.status == ResultStatus.BLOCKED_BY_POLICY
    assert not called
    assert result.artifacts == ()
    await gateway.close()


def test_fastapi_contract_routes(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    from fastapi.testclient import TestClient

    from fetech.daemon import create_app

    with TestClient(create_app()) as client:
        capabilities = client.get("/v1/capabilities")
        assert capabilities.status_code == 200
        assert capabilities.json()["capability_count"] == 155
        plan = client.post("/v1/plan", json={"target": "https://example.com"})
        assert plan.status_code == 200
        assert plan.json()["deterministic"] is True
        explanation = client.get("/v1/capabilities/http_get/explanation")
        assert explanation.status_code == 200
        assert explanation.json()["backend"] == "python"
        assert explanation.json()["eligible"] is True
        denied = client.post(
            "/v1/capabilities/http_get/explanation",
            json={
                "target": "https://example.com",
                "deny_capabilities": ["http_get"],
            },
        )
        assert denied.status_code == 200
        assert denied.json()["eligible"] is False
        assert denied.json()["conclusion"] == "ineligible"
        assert "denied by the request policy" in denied.json()["reasons"][0]


def test_mcp_server_registers_scoped_tools(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    from fetech.mcp_server import build_server

    server = build_server()
    assert server.name == "fetech-context"
