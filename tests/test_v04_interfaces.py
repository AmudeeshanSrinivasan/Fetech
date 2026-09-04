"""SDK, REST, CLI, and MCP parity for the real v0.4 gateway."""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from fetech.adapters.documents import (
    DocumentAdapter,
    GitLFSResolvedObject,
    GitLFSResolveRequest,
    PDFOCRPage,
)
from fetech.adapters.http import HTTPAdapter
from fetech.cli import app as cli_app
from fetech.client import FetechClient
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import FetchRequest, FetchResult, ResultStatus

_TARGET = "https://example.com/readme.txt"
_TEXT_BODY = b"Useful bounded interface fixture with stable source lineage and provenance. " * 4


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


def _wire_http(
    gateway: UniversalFetchGateway,
    monkeypatch: pytest.MonkeyPatch,
    *,
    status_code: int,
) -> None:
    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code,
            headers={"content-type": "text/plain"},
            content=_TEXT_BODY if status_code == 200 else b"",
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters


def _request() -> FetchRequest:
    return FetchRequest(target=_TARGET, output_requirements=("txt",))


def _wait_for_rest_result(client: TestClient) -> tuple[FetchResult, str]:
    submitted = client.post("/v1/fetch", json=_request().model_dump(mode="json"))
    assert submitted.status_code == 202, submitted.text
    run_id = submitted.json()["run_id"]
    for _ in range(200):
        snapshot = client.get(f"/v1/runs/{run_id}")
        assert snapshot.status_code == 200, snapshot.text
        document = snapshot.json()
        if document["result"] is not None:
            events = client.get(f"/v1/runs/{run_id}/events")
            assert events.status_code == 200, events.text
            return FetchResult.model_validate(document["result"]), events.text
        time.sleep(0.005)
    pytest.fail("REST fetch run did not finish")


def _contract_signature(result: FetchResult) -> tuple[object, ...]:
    return (
        result.status,
        tuple(artifact.representation for artifact in result.artifacts),
        tuple((attempt.capability_id, attempt.status, attempt.failure_code) for attempt in result.attempts),
        tuple(diagnostic.code for diagnostic in result.diagnostics),
    )


def _assert_success_contract(result: FetchResult) -> None:
    assert result.status == ResultStatus.SUCCEEDED
    assert result.resources
    raw = next(artifact for artifact in result.artifacts if artifact.representation == "raw")
    document = next(artifact for artifact in result.artifacts if artifact.representation == "document")
    assert raw.source_resource_id == result.resources[0].resource_id
    assert document.source_resource_id == result.resources[0].resource_id
    assert raw.artifact_id in document.parent_artifact_ids
    assert document.quality.accepted
    assert {attempt.capability_id for attempt in result.attempts} == {"http_get", "txt"}
    assert all(attempt.artifact_ids for attempt in result.attempts)
    assert result.provenance_event_ids


def _assert_not_found_contract(result: FetchResult) -> None:
    assert result.status == ResultStatus.NOT_FOUND
    assert not result.resources
    assert not result.artifacts
    assert len(result.attempts) == 1
    attempt = result.attempts[0]
    assert attempt.capability_id == "http_get"
    assert attempt.failure_code == "not_found"
    assert [diagnostic.code for diagnostic in result.diagnostics] == ["not_found"]
    assert result.provenance_event_ids


class _Resolver:
    async def resolve(
        self,
        request: GitLFSResolveRequest,
    ) -> GitLFSResolvedObject:
        return GitLFSResolvedObject(origin=request.origin, body=b"")


class _PDFOCR:
    async def extract_pdf(
        self,
        body: bytes,
        *,
        page_count: int,
        language: str | None,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> tuple[PDFOCRPage, ...]:
        del body, page_count, language, timeout_seconds, maximum_output_bytes
        return (PDFOCRPage(locator="page:1", text="bounded OCR fixture"),)


@pytest.mark.asyncio
async def test_sdk_projects_exact_v04_capability_nodes(tmp_path: Path) -> None:
    async with FetechClient(_settings(tmp_path)) as client:
        plan = await client.plan(
            FetchRequest(
                target="https://example.com/photo.jpg",
                output_requirements=("image_metadata", "exif_metadata"),
            )
        )

    assert [node.capability_id for node in plan.nodes if node.adapter == "media"] == [
        "image_metadata",
        "exif_metadata",
    ]


def test_sdk_and_rest_inject_document_providers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fetech.daemon import create_app

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "rest"))
    resolver = _Resolver()
    ocr = _PDFOCR()
    client = FetechClient(
        _settings(tmp_path / "sdk"),
        git_lfs_resolver=resolver,
        pdf_ocr_provider=ocr,
    )
    sdk_adapter = client.gateway.adapters["documents"]
    assert isinstance(sdk_adapter, DocumentAdapter)
    assert sdk_adapter.git_lfs_resolver is resolver
    assert sdk_adapter.pdf_ocr_provider is ocr

    application = create_app(
        git_lfs_resolver=resolver,
        pdf_ocr_provider=ocr,
    )
    rest_adapter = application.state.gateway.adapters["documents"]
    assert isinstance(rest_adapter, DocumentAdapter)
    assert rest_adapter.git_lfs_resolver is resolver
    assert rest_adapter.pdf_ocr_provider is ocr


def test_rest_projects_exact_v04_capability_nodes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    from fastapi.testclient import TestClient

    from fetech.daemon import create_app

    with TestClient(create_app()) as client:
        response = client.post(
            "/v1/plan",
            json={
                "target": "https://example.com/report.pdf",
                "output_requirements": ["scanned_pdf"],
            },
        )
        capabilities = client.get("/v1/capabilities").json()

    assert response.status_code == 200
    assert any(
        node["capability_id"] == "scanned_pdf" and node["adapter"] == "documents"
        for node in response.json()["nodes"]
    )
    assert capabilities["releases"]["v0.4"]["closure_ready"] is True
    assert capabilities["releases"]["v0.4"]["implementation_path_count"] == 36
    assert capabilities["releases"]["v0.4"]["runtime_available_count"] == 17


def test_cli_projects_exact_v04_capability_nodes(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    result = CliRunner().invoke(
        cli_app,
        [
            "plan",
            "https://example.com/article",
            "--output",
            "local_snapshot",
            "--output",
            "rag_document_cache",
        ],
    )

    assert result.exit_code == 0, result.output
    document = json.loads(result.output)
    assert [node["capability_id"] for node in document["nodes"] if node["adapter"] == "cache"] == [
        "local_snapshot",
        "rag_document_cache",
    ]


@pytest.mark.asyncio
async def test_mcp_document_and_media_tools_share_the_v04_gateway_contract(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fetech import mcp_server

    observed: list[FetchRequest] = []
    providers: dict[str, object] = {}

    class StubGateway:
        def __init__(self, **values: object) -> None:
            providers.update(values)

        async def fetch(self, request: FetchRequest) -> FetchResult:
            observed.append(request)
            return FetchResult(status=ResultStatus.SUCCEEDED)

    monkeypatch.setattr(mcp_server, "UniversalFetchGateway", StubGateway)
    resolver = _Resolver()
    ocr = _PDFOCR()
    server = mcp_server.build_server(
        git_lfs_resolver=resolver,
        pdf_ocr_provider=ocr,
    )
    tools = server._tool_manager._tools

    await tools["extract_document"].fn("https://example.com/report.pdf")
    await tools["extract_media"].fn("https://example.com/movie.mp4")

    assert [request.output_requirements for request in observed] == [
        ("document",),
        ("video",),
    ]
    assert {
        "extract_document",
        "extract_media",
        "fetch_content",
        "get_fetch_trace",
        "query_provenance",
    }.issubset(tools)
    assert providers["git_lfs_resolver"] is resolver
    assert providers["pdf_ocr_provider"] is ocr


def test_real_gateway_success_contract_is_identical_across_all_interfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdk_client = FetechClient(_settings(tmp_path / "sdk"))
    _wire_http(sdk_client.gateway, monkeypatch, status_code=200)

    async def sdk_fetch() -> tuple[FetchResult, tuple[str, ...]]:
        async with sdk_client:
            handle = await sdk_client.submit(_request())
            result = await handle.result()
            events = tuple([event.event_type async for event in handle.events()])
            return result, events

    sdk_result, sdk_events = asyncio.run(sdk_fetch())
    assert sdk_events[-1] == "run.finished"

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "rest"))
    from fetech.daemon import create_app

    application = create_app()
    rest_gateway = application.state.gateway
    _wire_http(rest_gateway, monkeypatch, status_code=200)
    with TestClient(application) as rest_client:
        rest_result, rest_events = _wait_for_rest_result(rest_client)
        raw = next(artifact for artifact in rest_result.artifacts if artifact.representation == "raw")
        metadata = rest_client.get(f"/v1/artifacts/{raw.artifact_id}")
        content = rest_client.get(
            f"/v1/artifacts/{raw.artifact_id}",
            params={"content": "true"},
        )
    assert metadata.status_code == 200
    assert metadata.json()["sha256"] == raw.sha256
    assert content.status_code == 200
    assert content.content == _TEXT_BODY
    assert "event: run.finished" in rest_events

    cli_client = FetechClient(_settings(tmp_path / "cli"))
    _wire_http(cli_client.gateway, monkeypatch, status_code=200)
    import fetech.cli as cli_module

    monkeypatch.setattr(cli_module, "FetechClient", lambda: cli_client)
    cli_invocation = CliRunner().invoke(
        cli_app,
        ["fetch", _TARGET, "--output", "txt"],
    )
    assert cli_invocation.exit_code == 0, cli_invocation.output
    cli_result = FetchResult.model_validate_json(cli_invocation.output)

    mcp_gateway = UniversalFetchGateway(_settings(tmp_path / "mcp"))
    _wire_http(mcp_gateway, monkeypatch, status_code=200)
    import fetech.mcp_server as mcp_module

    monkeypatch.setattr(
        mcp_module,
        "UniversalFetchGateway",
        lambda **_: mcp_gateway,
    )
    server = mcp_module.build_server()
    tools = server._tool_manager._tools

    async def mcp_fetch() -> tuple[FetchResult, str, str]:
        result = FetchResult.model_validate_json(
            await tools["fetch_content"].fn(
                target=_TARGET,
                outputs=["txt"],
            )
        )
        trace = await tools["get_fetch_trace"].fn(str(result.run_id))
        provenance = await tools["query_provenance"].fn(str(result.run_id))
        await mcp_gateway.close()
        return result, trace, provenance

    mcp_result, mcp_trace, mcp_provenance = asyncio.run(mcp_fetch())
    assert "run.finished" in mcp_trace
    assert "attempt.finished" in mcp_provenance

    results = (sdk_result, rest_result, cli_result, mcp_result)
    for result in results:
        _assert_success_contract(result)
    assert len({_contract_signature(result) for result in results}) == 1


def test_real_gateway_typed_failure_is_identical_across_all_interfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sdk_client = FetechClient(_settings(tmp_path / "sdk"))
    _wire_http(sdk_client.gateway, monkeypatch, status_code=404)

    async def sdk_fetch() -> FetchResult:
        async with sdk_client:
            return await sdk_client.fetch(_request())

    sdk_result = asyncio.run(sdk_fetch())

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "rest"))
    from fetech.daemon import create_app

    application = create_app()
    _wire_http(application.state.gateway, monkeypatch, status_code=404)
    with TestClient(application) as rest_client:
        rest_result, rest_events = _wait_for_rest_result(rest_client)
    assert "event: attempt.not_found" in rest_events

    cli_client = FetechClient(_settings(tmp_path / "cli"))
    _wire_http(cli_client.gateway, monkeypatch, status_code=404)
    import fetech.cli as cli_module

    monkeypatch.setattr(cli_module, "FetechClient", lambda: cli_client)
    cli_invocation = CliRunner().invoke(
        cli_app,
        ["fetch", _TARGET, "--output", "txt"],
    )
    assert cli_invocation.exit_code == 0, cli_invocation.output
    cli_result = FetchResult.model_validate_json(cli_invocation.output)

    mcp_gateway = UniversalFetchGateway(_settings(tmp_path / "mcp"))
    _wire_http(mcp_gateway, monkeypatch, status_code=404)
    import fetech.mcp_server as mcp_module

    monkeypatch.setattr(
        mcp_module,
        "UniversalFetchGateway",
        lambda **_: mcp_gateway,
    )
    server = mcp_module.build_server()
    tools: dict[str, Any] = server._tool_manager._tools

    async def mcp_fetch() -> FetchResult:
        result = FetchResult.model_validate_json(
            await tools["fetch_content"].fn(
                target=_TARGET,
                outputs=["txt"],
            )
        )
        await mcp_gateway.close()
        return result

    mcp_result = asyncio.run(mcp_fetch())

    results = (sdk_result, rest_result, cli_result, mcp_result)
    for result in results:
        _assert_not_found_contract(result)
    assert len({_contract_signature(result) for result in results}) == 1
