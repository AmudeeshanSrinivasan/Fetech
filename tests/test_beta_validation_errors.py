"""Beta public validation-error parity and redaction conformance."""

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
from fetech.errors import (
    FetechValidationError,
    public_validation_error,
    validate_fetch_request,
    validate_uuid,
)
from fetech.models import FetchRequest


def _settings(path: Path) -> Settings:
    return Settings(
        data_dir=path,
        database_path=path / "ledger.sqlite3",
        artifact_dir=path / "artifacts",
        runtime_graph_path=path / "runtime-graph" / "graph.json",
    )


def _document(exc: FetechValidationError) -> dict[str, Any]:
    return exc.error.model_dump(mode="json")


def test_contract_models_hide_inputs_and_public_errors_remove_untrusted_details() -> None:
    secret = "vault://" + "private-value-" * 200
    with pytest.raises(ValidationError) as caught:
        FetchRequest.model_validate(
            {
                "target": "https://example.com",
                "authentication_ref": secret,
            }
        )

    assert secret not in str(caught.value)
    error = public_validation_error(caught.value)
    encoded = error.model_dump_json()
    assert secret not in encoded
    assert error.code == "INVALID_REQUEST"
    assert error.status_code == 422
    assert error.retryable is False

    untrusted_key = "attacker_supplied_secret_field"
    with pytest.raises(ValidationError) as extra:
        FetchRequest.model_validate(
            {
                "target": "https://example.com",
                untrusted_key: "do-not-return-this-value",
            }
        )
    extra_error = public_validation_error(extra.value)
    extra_encoded = extra_error.model_dump_json()
    assert untrusted_key not in extra_encoded
    assert "do-not-return-this-value" not in extra_encoded
    assert extra_error.issues[0].location == ("<field>",)


def test_public_error_bounds_issue_count_and_reports_omissions() -> None:
    class ManyErrors(Exception):
        def errors(self, **_: object) -> list[dict[str, object]]:
            return [
                {
                    "loc": ("body", f"untrusted-{index}"),
                    "type": "value_error",
                    "input": f"secret-{index}",
                    "ctx": {"error": f"secret-{index}"},
                }
                for index in range(40)
            ]

    error = public_validation_error(ManyErrors())
    encoded = error.model_dump_json()

    assert len(error.issues) == 32
    assert error.omitted_issues == 8
    assert {issue.location for issue in error.issues} == {("<field>",)}
    assert "secret-" not in encoded
    assert "untrusted-" not in encoded


def test_invalid_fetch_request_is_identical_across_sdk_rest_cli_and_mcp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "vault://validation-secret"
    payload = {"target": "", "authentication_ref": secret}

    sdk = FetechClient(_settings(tmp_path / "sdk"))
    with pytest.raises(FetechValidationError) as sdk_caught:
        asyncio.run(sdk.fetch(payload))
    asyncio.run(sdk.close())
    expected = _document(sdk_caught.value)

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "rest"))
    from fetech.daemon import create_app

    application = create_app()
    with TestClient(application) as rest_client:
        response = rest_client.post("/v1/fetch", json=payload)
    assert response.status_code == 422

    cli_result = CliRunner().invoke(
        cli_app,
        ["fetch", "", "--auth-ref", secret],
    )
    assert cli_result.exit_code == 2, cli_result.output

    import fetech.mcp_server as mcp_module

    tool = mcp_module.build_server()._tool_manager._tools["fetch_content"]
    with pytest.raises(FetechValidationError) as mcp_caught:
        asyncio.run(tool.fn(target="", authentication_ref=secret))

    observed = (
        response.json(),
        json.loads(cli_result.output),
        _document(mcp_caught.value),
    )
    assert all(document == expected for document in observed)
    assert expected["issues"] == [
        {
            "location": ["target"],
            "code": "string_too_short",
            "message": "value is too short",
        }
    ]
    assert secret not in json.dumps((expected, *observed))


def test_invalid_run_id_is_identical_across_sdk_rest_cli_and_mcp(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    invalid_id = "not-a-private-run-id"
    with pytest.raises(FetechValidationError) as direct_caught:
        validate_uuid(invalid_id, "run_id")
    expected = _document(direct_caught.value)

    sdk = FetechClient(_settings(tmp_path / "sdk"))
    with pytest.raises(FetechValidationError) as sdk_caught:
        asyncio.run(sdk.cancel(invalid_id))
    asyncio.run(sdk.close())

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "interfaces"))
    from fetech.daemon import create_app

    with TestClient(create_app()) as rest_client:
        response = rest_client.get(f"/v1/runs/{invalid_id}")
    assert response.status_code == 422

    cli_result = CliRunner().invoke(cli_app, ["run", invalid_id])
    assert cli_result.exit_code == 2, cli_result.output

    import fetech.mcp_server as mcp_module

    tool = mcp_module.build_server()._tool_manager._tools["query_provenance"]
    with pytest.raises(FetechValidationError) as mcp_caught:
        asyncio.run(tool.fn(invalid_id))

    observed = (
        _document(sdk_caught.value),
        response.json(),
        json.loads(cli_result.output),
        _document(mcp_caught.value),
    )
    assert all(document == expected for document in observed)
    assert invalid_id not in json.dumps((expected, *observed))
    assert expected["issues"][0] == {
        "location": ["run_id"],
        "code": "uuid_parsing",
        "message": "value has an invalid format",
    }


def test_oversized_context_question_is_identical_across_interfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    question = "private-context-" * 1_100
    sdk = FetechClient(_settings(tmp_path / "sdk"), repository=tmp_path)
    with pytest.raises(FetechValidationError) as sdk_caught:
        asyncio.run(sdk.context(question))
    asyncio.run(sdk.close())
    expected = _document(sdk_caught.value)

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "interfaces"))
    monkeypatch.setenv("FETECH_REPOSITORY", str(tmp_path))
    from fetech.daemon import create_app

    with TestClient(create_app()) as rest_client:
        response = rest_client.post(
            "/v1/context/search",
            params={"question": question},
        )
    assert response.status_code == 422

    cli_result = CliRunner().invoke(
        cli_app,
        ["context", question, "--repository", str(tmp_path)],
    )
    assert cli_result.exit_code == 2, cli_result.output

    import fetech.mcp_server as mcp_module

    tool = mcp_module.build_server()._tool_manager._tools["get_context"]
    with pytest.raises(FetechValidationError) as mcp_caught:
        asyncio.run(tool.fn(question))

    observed = (
        response.json(),
        json.loads(cli_result.output),
        _document(mcp_caught.value),
    )
    assert all(document == expected for document in observed)
    assert expected["issues"][0] == {
        "location": ["question"],
        "code": "string_too_long",
        "message": "value is too long",
    }
    assert question not in json.dumps((expected, *observed))


def test_openapi_declares_the_public_error_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    from fetech.daemon import create_app

    schema = create_app().openapi()
    response_schema = schema["paths"]["/v1/fetch"]["post"]["responses"]["422"]["content"][
        "application/json"
    ]["schema"]

    assert response_schema == {"$ref": "#/components/schemas/PublicError"}
    assert "PublicError" in schema["components"]["schemas"]


def test_validate_fetch_request_returns_existing_models_without_copying() -> None:
    request = FetchRequest(target="https://example.com")

    assert validate_fetch_request(request) is request
