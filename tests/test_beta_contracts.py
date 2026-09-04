"""Beta contract versioning and cross-interface discovery conformance."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from typer.testing import CliRunner

from fetech.cli import app as cli_app
from fetech.client import FetechClient
from fetech.config import Settings
from fetech.contracts import contract_manifest
from fetech.models import Artifact, FetchPlan, FetchRequest, FetchResult


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


@pytest.mark.parametrize(
    ("model", "document"),
    [
        (FetchRequest, {"schema_version": "2.0", "target": "https://example.com"}),
        (
            FetchPlan,
            {
                "schema_version": "2.0",
                "request": {"target": "https://example.com"},
                "nodes": [],
            },
        ),
        (FetchResult, {"schema_version": "2.0", "status": "FAILED"}),
        (
            Artifact,
            {
                "schema_version": "2.0",
                "role": "source",
                "representation": "raw",
                "media_type": "text/plain",
                "cas_uri": "cas://sha256/" + "0" * 64,
                "sha256": "0" * 64,
                "size": 0,
                "source_resource_id": "00000000-0000-0000-0000-000000000001",
                "extractor_version": "fixture/1",
            },
        ),
    ],
)
def test_versioned_contracts_reject_unknown_schema_versions(
    model: type[Any],
    document: dict[str, Any],
) -> None:
    with pytest.raises(ValidationError, match=r"1\.0"):
        model.model_validate(document)


def test_legacy_request_without_version_migrates_to_current_contract() -> None:
    request = FetchRequest.model_validate({"target": "https://example.com"})

    assert request.schema_version == "1.0"
    assert request.model_dump(mode="json")["schema_version"] == "1.0"


def test_contract_manifest_is_ordered_unique_and_deterministic() -> None:
    first = contract_manifest()
    second = contract_manifest()
    names = [descriptor.name for descriptor in first.contracts]

    assert first == second
    assert first.api_version == "v1"
    assert first.schema_version == "1.0"
    assert names == sorted(names)
    assert len(names) == len(set(names))
    assert {
        "Artifact",
        "ContextProviderReport",
        "ContextSource",
        "ContextTokenUsage",
        "ContractManifest",
        "FetchPlan",
        "FetchRequest",
        "FetchResult",
        "ReasoningQuery",
        "ReasoningResult",
    } <= set(names)
    assert all(len(descriptor.json_schema_sha256) == 64 for descriptor in first.contracts)


def test_sdk_rest_cli_and_mcp_expose_identical_contract_manifest(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected = contract_manifest().model_dump(mode="json")

    sdk = FetechClient(_settings(tmp_path / "sdk"))
    assert sdk.contracts().model_dump(mode="json") == expected
    asyncio.run(sdk.close())

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "rest"))
    from fetech.daemon import create_app

    application = create_app()
    with TestClient(application) as rest_client:
        response = rest_client.get("/v1/contracts")
        assert response.status_code == 200, response.text
        assert response.json() == expected
        assert "/v1/contracts" in application.openapi()["paths"]

    cli = CliRunner().invoke(cli_app, ["contracts"])
    assert cli.exit_code == 0, cli.output
    assert json.loads(cli.output) == expected

    import fetech.mcp_server as mcp_module

    server = mcp_module.build_server()
    tool = server._tool_manager._tools["get_contracts"]
    assert json.loads(asyncio.run(tool.fn())) == expected


def test_rest_rejects_unknown_request_schema_version(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    from fetech.daemon import create_app

    with TestClient(create_app()) as client:
        response = client.post(
            "/v1/plan",
            json={"schema_version": "2.0", "target": "https://example.com"},
        )

    assert response.status_code == 422
    assert response.json()["detail"][0]["loc"] == ["body", "schema_version"]
