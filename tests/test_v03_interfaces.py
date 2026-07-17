from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from fetech.auth import NullCredentialProvider
from fetech.auth_flows import NullFormSubmissionProvider, NullSessionProvider
from fetech.cli import app as cli_app
from fetech.daemon import create_app
from fetech.models import FetchRequest, FetchResult, ResultStatus


def test_fetch_request_v03_fields_round_trip_without_secret_material() -> None:
    request = FetchRequest(
        target="https://api.example.com/private",
        authentication_ref="vault://fetech/example",
        privacy_profile="private",
        approved_capabilities=frozenset({"form_submit", "http_post"}),
    )

    encoded = request.model_dump_json()
    restored = FetchRequest.model_validate_json(encoded)

    assert restored.authentication_ref == "vault://fetech/example"
    assert restored.privacy_profile == "private"
    assert restored.approved_capabilities == frozenset({"form_submit", "http_post"})
    assert not {"password", "cookie", "authorization", "api_key"} & set(
        json.loads(encoded)
    )


def test_daemon_openapi_and_plan_preserve_v03_request_fields(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    application = create_app(
        credential_provider=NullCredentialProvider(),
        session_provider=NullSessionProvider(),
        form_submission_provider=NullFormSubmissionProvider(),
    )

    schema = application.openapi()
    assert "/v1/plan" in schema["paths"]
    assert application.state.gateway.credential_provider.__class__ is NullCredentialProvider
    assert (
        application.state.gateway.form_submission_provider.__class__
        is NullFormSubmissionProvider
    )
    assert application.state.gateway.session_provider.__class__ is NullSessionProvider

    with TestClient(application) as client:
        response = client.post(
            "/v1/plan",
            json={
                "target": "https://api.example.com/private",
                "authentication_ref": "vault://fetech/example",
                "privacy_profile": "private",
                "approved_capabilities": ["form_submit", "http_post"],
            },
        )
        invalid = client.post(
            "/v1/plan",
            json={
                "target": "https://api.example.com/private",
                "privacy_profile": "secret",
            },
        )
        unsafe_plan = client.post(
            "/v1/plan",
            json={
                "target": "https://api.example.com/data",
                "output_requirements": ["rest", "graphql"],
            },
        )
        failed_run = client.post(
            "/v1/fetch",
            json={
                "target": "https://api.example.com/data",
                "output_requirements": ["rest", "graphql"],
            },
        )

    assert response.status_code == 200, response.text
    planned_request = response.json()["request"]
    assert planned_request["authentication_ref"] == "vault://fetech/example"
    assert planned_request["privacy_profile"] == "private"
    assert set(planned_request["approved_capabilities"]) == {
        "form_submit",
        "http_post",
    }
    assert invalid.status_code == 422
    assert unsafe_plan.status_code == 422
    assert unsafe_plan.json()["detail"] == (
        "request could not produce a valid execution plan"
    )
    assert failed_run.status_code == 202
    assert failed_run.json()["state"] == "FINISHED"
    assert failed_run.json()["result"]["status"] == "FAILED"
    assert failed_run.json()["result"]["diagnostics"][0]["code"] == "planning_failed"


@pytest.mark.asyncio
async def test_mcp_fetch_content_exposes_scoped_v03_request_parameters(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    import fetech.mcp_server as mcp_server

    observed: dict[str, Any] = {}

    class StubGateway:
        def __init__(self, **providers: object) -> None:
            observed["providers"] = providers

        async def fetch(self, request: FetchRequest) -> FetchResult:
            observed["request"] = request
            return FetchResult(status=ResultStatus.SUCCEEDED)

    monkeypatch.setattr(mcp_server, "UniversalFetchGateway", StubGateway)
    credential_provider = NullCredentialProvider()
    form_submission_provider = NullFormSubmissionProvider()
    session_provider = NullSessionProvider()
    server = mcp_server.build_server(
        credential_provider=credential_provider,
        session_provider=session_provider,
        form_submission_provider=form_submission_provider,
    )
    tool = server._tool_manager._tools["fetch_content"]

    properties = tool.parameters["properties"]
    assert properties["privacy_profile"]["enum"] == ["public", "private"]
    assert "authentication_ref" in properties
    assert "approved_capabilities" in properties
    assert not {
        "authorization",
        "cookies",
        "headers",
        "password",
        "secret",
        "token",
    } & set(properties)

    await tool.fn(
        target="https://api.example.com/private",
        outputs=["json"],
        maximum_bytes=2048,
        authentication_ref="vault://fetech/example",
        privacy_profile="private",
        approved_capabilities=["form_submit"],
    )

    request = observed["request"]
    assert isinstance(request, FetchRequest)
    assert request.authentication_ref == "vault://fetech/example"
    assert request.privacy_profile == "private"
    assert request.approved_capabilities == frozenset({"form_submit"})
    providers = observed["providers"]
    assert providers == {
        "credential_provider": credential_provider,
        "form_submission_provider": form_submission_provider,
        "session_provider": session_provider,
    }


def test_cli_plan_and_fetch_expose_strict_v03_options() -> None:
    runner = CliRunner(env={"COLUMNS": "30"})

    for command in ("plan", "fetch"):
        help_result = runner.invoke(cli_app, [command, "--help"])
        assert help_result.exit_code == 0, help_result.output
        assert "--auth-ref" in help_result.output
        assert "--privacy" in help_result.output
        assert "<public|private>" in help_result.output
        assert "--approve" in help_result.output

        invalid = runner.invoke(
            cli_app,
            [command, "https://example.com", "--privacy", "secret"],
        )
        assert invalid.exit_code == 2
