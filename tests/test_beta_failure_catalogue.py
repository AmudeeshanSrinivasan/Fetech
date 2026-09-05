"""Beta public failure-semantics catalogue and interface parity."""

from __future__ import annotations

import ast
import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from typer.testing import CliRunner

from fetech.cli import app as cli_app
from fetech.client import FetechClient
from fetech.config import Settings
from fetech.contracts import contract_manifest
from fetech.failures import PUBLIC_VALIDATION_ISSUE_CODES, failure_catalogue
from fetech.models import (
    Diagnostic,
    DiscoveredTarget,
    FetchAttempt,
    PublicErrorCode,
    ResultStatus,
)

_BUILT_IN_CODES = {
    "adapter_failed",
    "adapter_missing",
    "auth_expired",
    "auth_required",
    "budget_exhausted",
    "cache_error",
    "cache_miss",
    "cache_revalidation_required",
    "cancelled",
    "dependency_missing",
    "dependency_skipped",
    "document_error",
    "early_stop",
    "empty_response",
    "execution_cancelled",
    "fetch_failed",
    "internal_error",
    "malformed_api_payload",
    "malformed_document",
    "media_extraction_failed",
    "not_found",
    "parallel_sibling_stopped_execution",
    "planning_failed",
    "policy",
    "policy_blocked",
    "run_cancelled",
    "run_interrupted",
    "snapshot_integrity",
    "transport_error",
    "unsafe_or_malformed_archive",
}

_FAILURE_PRODUCERS = (
    "adapters/api.py",
    "adapters/archive.py",
    "adapters/auth.py",
    "adapters/cache.py",
    "adapters/discovery.py",
    "adapters/documents.py",
    "adapters/http.py",
    "adapters/media.py",
    "adapters/structured.py",
    "executor.py",
    "gateway.py",
)


def _literal_strings(node: ast.AST) -> set[str]:
    return {
        candidate.value
        for candidate in ast.walk(node)
        if isinstance(candidate, ast.Constant) and isinstance(candidate.value, str)
    }


def _built_in_runtime_codes() -> set[str]:
    root = Path(__file__).parents[1] / "src" / "fetech"
    codes: set[str] = set()
    for relative_path in _FAILURE_PRODUCERS:
        tree = ast.parse((root / relative_path).read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                if any(isinstance(target, ast.Name) and target.id == "failure_code" for target in targets):
                    codes.update(_literal_strings(node.value))
            if isinstance(node, ast.Dict):
                for field_name, value in zip(node.keys, node.values, strict=True):
                    if (
                        isinstance(field_name, ast.Constant)
                        and field_name.value == "failure_code"
                    ):
                        codes.update(_literal_strings(value))
            if (
                relative_path == "adapters/cache.py"
                and isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == "_failure_code"
            ):
                for nested in ast.walk(node):
                    if isinstance(nested, ast.Return) and nested.value is not None:
                        codes.update(_literal_strings(nested.value))
            if (
                relative_path == "executor.py"
                and isinstance(node, ast.Compare)
                and isinstance(node.left, ast.Name)
                and node.left.id == "raw_cancellation_reason"
            ):
                for comparator in node.comparators:
                    codes.update(_literal_strings(comparator))
            if not isinstance(node, ast.Call):
                continue
            function_name = (
                node.func.attr
                if isinstance(node.func, ast.Attribute)
                else node.func.id
                if isinstance(node.func, ast.Name)
                else ""
            )
            if function_name in {"Diagnostic", "FetchAttempt", "DiscoveredTarget"}:
                for keyword in node.keywords:
                    if keyword.arg in {"code", "failure_code"}:
                        codes.update(_literal_strings(keyword.value))
            elif function_name == "_fail_attempt" and len(node.args) >= 3:
                codes.update(_literal_strings(node.args[2]))
            elif function_name == "_record_terminal_failure":
                for keyword in node.keywords:
                    if keyword.arg == "code":
                        codes.update(_literal_strings(keyword.value))
            elif function_name in {
                "_mark_running_attempt_cancelled",
                "_mark_running_attempt_failed",
            }:
                for argument in node.args[1:]:
                    codes.update(_literal_strings(argument))
    return codes


def _settings(path: Path) -> Settings:
    return Settings(
        data_dir=path,
        database_path=path / "ledger.sqlite3",
        artifact_dir=path / "artifacts",
        runtime_graph_path=path / "runtime-graph" / "graph.json",
    )


def test_failure_catalogue_is_complete_ordered_and_deterministic() -> None:
    first = failure_catalogue()
    second = failure_catalogue()
    statuses = [descriptor.status for descriptor in first.result_statuses]
    codes = [descriptor.code for descriptor in first.codes]
    public_errors = [descriptor.code for descriptor in first.public_errors]

    assert first == second
    assert first.schema_version == "1.0"
    assert first.api_version == "v1"
    assert statuses == sorted(ResultStatus, key=lambda status: status.value)
    assert len(statuses) == len(set(statuses)) == 9
    assert codes == sorted(_BUILT_IN_CODES)
    assert len(codes) == len(set(codes))
    assert public_errors == list(PublicErrorCode)
    assert all(descriptor.retryable is False for descriptor in first.result_statuses)
    assert all(descriptor.retryable is False for descriptor in first.codes)
    assert all(
        code in _BUILT_IN_CODES
        for descriptor in first.result_statuses
        for code in descriptor.common_diagnostic_codes
    )

    first.codes[0].summary = "caller mutation"
    assert failure_catalogue().codes[0].summary != "caller mutation"


def test_catalogue_covers_every_static_builtin_runtime_code() -> None:
    assert _built_in_runtime_codes() == _BUILT_IN_CODES


def test_failure_catalogue_documents_cross_interface_delivery() -> None:
    catalogue = failure_catalogue()

    for descriptor in catalogue.result_statuses:
        assert descriptor.sdk_delivery == "FetchResult"
        assert descriptor.rest_submission_status == 202
        assert descriptor.rest_result_status == 200
        assert descriptor.cli_exit_code == 0
        assert descriptor.mcp_delivery == "FetchResult JSON"

    invalid_request = catalogue.public_errors[0]
    assert invalid_request.code == PublicErrorCode.INVALID_REQUEST
    assert invalid_request.issue_codes == tuple(sorted(PUBLIC_VALIDATION_ISSUE_CODES))
    assert invalid_request.sdk_delivery == "FetechValidationError"
    assert invalid_request.rest_status == 422
    assert invalid_request.cli_exit_code == 2
    assert invalid_request.mcp_delivery == "tool error"


def test_public_failure_code_fields_are_bounded_identifiers() -> None:
    oversized = "a" * 129

    with pytest.raises(ValidationError):
        Diagnostic(code=oversized, message="bounded")
    with pytest.raises(ValidationError):
        FetchAttempt(
            capability_id="http_get",
            sanitized_destination="https://example.com/",
            failure_code="Read Error",
        )
    with pytest.raises(ValidationError):
        DiscoveredTarget(
            url="https://example.com/",
            depth=0,
            relation="root",
            failure_code="<exception>",
        )


def test_failure_contracts_are_registered() -> None:
    names = {descriptor.name for descriptor in contract_manifest().contracts}

    assert {
        "FailureCatalogue",
        "FailureCodeDescriptor",
        "PublicErrorDescriptor",
        "ResultStatusDescriptor",
    } <= names


def test_sdk_rest_cli_and_mcp_expose_identical_failure_catalogue(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected = failure_catalogue().model_dump(mode="json")

    sdk = FetechClient(_settings(tmp_path / "sdk"))
    assert sdk.failures().model_dump(mode="json") == expected
    asyncio.run(sdk.close())

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "rest"))
    from fetech.daemon import create_app

    application = create_app()
    with TestClient(application) as rest_client:
        response = rest_client.get("/v1/failures")
        assert response.status_code == 200, response.text
        assert response.json() == expected
        assert "/v1/failures" in application.openapi()["paths"]

    cli = CliRunner().invoke(cli_app, ["failures"])
    assert cli.exit_code == 0, cli.output
    assert json.loads(cli.output) == expected

    import fetech.mcp_server as mcp_module

    server = mcp_module.build_server()
    tool = server._tool_manager._tools["get_failures"]
    assert json.loads(asyncio.run(tool.fn())) == expected
