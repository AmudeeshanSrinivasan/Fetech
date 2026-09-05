"""Fail-closed snapshots for the Beta v1 public interface surface."""

from __future__ import annotations

import inspect
import json
from collections.abc import Callable, Mapping, Sequence
from enum import Enum
from pathlib import Path
from typing import Any

from fetech.client import FetchHandle, FetechClient
from fetech.contracts import _public_contract_schemas, contract_manifest

BASELINE_ID = "beta-v1"
BASELINE_SCHEMA_VERSION = "1.0"
_MAX_BASELINE_BYTES = 5_000_000
_REST_METHODS = frozenset({"delete", "get", "patch", "post", "put"})


class CompatibilityBaselineError(RuntimeError):
    """The checked-in baseline is absent, malformed, oversized, or stale."""


def build_compatibility_snapshot() -> dict[str, Any]:
    """Build the deterministic public SDK, REST, CLI, and MCP surface snapshot.

    The complete operation requires the ``server`` and ``mcp`` extras. It does
    not initialize the daemon, open the ledger, or perform network activity.
    """

    manifest = contract_manifest()
    schemas = _public_contract_schemas()
    contracts = {
        descriptor.name: {
            "schema_version": descriptor.schema_version,
            "json_schema_sha256": descriptor.json_schema_sha256,
            "schema": schemas[descriptor.name],
        }
        for descriptor in manifest.contracts
    }
    return {
        "schema_version": BASELINE_SCHEMA_VERSION,
        "baseline_id": BASELINE_ID,
        "api_version": manifest.api_version,
        "contracts": contracts,
        "sdk": _sdk_surface(),
        "rest": _rest_surface(),
        "cli": _cli_surface(),
        "mcp": _mcp_surface(),
    }


def compatibility_differences(
    expected: object,
    actual: object,
    *,
    maximum: int = 100,
) -> tuple[str, ...]:
    """Return bounded exact-surface differences in deterministic path order."""

    if maximum < 1:
        raise ValueError("maximum compatibility differences must be positive")
    differences: list[str] = []
    _compare(expected, actual, "$", differences, maximum)
    return tuple(differences)


def load_compatibility_baseline(path: Path) -> dict[str, Any]:
    """Load and minimally validate a bounded checked-in compatibility snapshot."""

    resolved = path.expanduser().resolve()
    try:
        size = resolved.stat().st_size
    except OSError as exc:
        raise CompatibilityBaselineError("compatibility baseline is unavailable") from exc
    if size > _MAX_BASELINE_BYTES:
        raise CompatibilityBaselineError("compatibility baseline exceeds the byte limit")
    try:
        document = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise CompatibilityBaselineError("compatibility baseline is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise CompatibilityBaselineError("compatibility baseline must be a JSON object")
    if document.get("schema_version") != BASELINE_SCHEMA_VERSION:
        raise CompatibilityBaselineError("compatibility baseline schema version is unsupported")
    if document.get("baseline_id") != BASELINE_ID:
        raise CompatibilityBaselineError("compatibility baseline identifier is unsupported")
    return document


def verify_compatibility_baseline(path: Path) -> tuple[str, ...]:
    """Compare the current exact public surface with a checked-in baseline."""

    return compatibility_differences(
        load_compatibility_baseline(path),
        build_compatibility_snapshot(),
    )


def write_compatibility_baseline(path: Path) -> None:
    """Atomically write the current deterministic compatibility snapshot."""

    resolved = path.expanduser().resolve()
    resolved.parent.mkdir(parents=True, exist_ok=True)
    encoded = (
        json.dumps(
            build_compatibility_snapshot(),
            ensure_ascii=True,
            indent=2,
            sort_keys=True,
        )
        + "\n"
    )
    if len(encoded.encode("utf-8")) > _MAX_BASELINE_BYTES:
        raise CompatibilityBaselineError("generated compatibility baseline exceeds the byte limit")
    temporary = resolved.with_name(f".{resolved.name}.tmp")
    try:
        temporary.write_text(encoded, encoding="utf-8")
        temporary.replace(resolved)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise CompatibilityBaselineError("compatibility baseline could not be written") from exc


def _sdk_surface() -> dict[str, object]:
    import fetech

    return {
        "exports": sorted(fetech.__all__),
        "classes": {
            model.__name__: {
                "constructor": _callable_surface(model.__init__),
                "methods": {
                    name: _callable_surface(function)
                    for name, function in inspect.getmembers(model, inspect.isfunction)
                    if not name.startswith("_") or name in {"__aenter__", "__aexit__"}
                },
            }
            for model in (FetechClient, FetchHandle)
        }
    }


def _callable_surface(function: Callable[..., Any]) -> dict[str, object]:
    signature = inspect.signature(function)
    parameters: list[dict[str, object]] = []
    for parameter in signature.parameters.values():
        if parameter.name == "self":
            continue
        required = parameter.default is inspect.Parameter.empty
        entry: dict[str, object] = {
            "name": parameter.name,
            "kind": parameter.kind.name,
            "required": required,
            "annotation": _annotation_name(parameter.annotation),
        }
        if not required:
            entry["default"] = _json_value(parameter.default)
        parameters.append(entry)
    return {
        "async": inspect.iscoroutinefunction(function) or inspect.isasyncgenfunction(function),
        "parameters": parameters,
        "return": _annotation_name(signature.return_annotation),
    }


def _annotation_name(annotation: object) -> str | None:
    if annotation is inspect.Signature.empty:
        return None
    if isinstance(annotation, str):
        return annotation
    return inspect.formatannotation(annotation)


def _rest_surface() -> dict[str, object]:
    try:
        from fetech.daemon import create_app

        application = create_app()
    except (ImportError, RuntimeError) as exc:
        raise CompatibilityBaselineError(
            "install fetech[server] to inspect the REST compatibility surface"
        ) from exc

    paths = application.openapi().get("paths", {})
    if not isinstance(paths, Mapping):
        raise CompatibilityBaselineError("generated OpenAPI paths are malformed")
    operations: list[dict[str, object]] = []
    for path, path_item in sorted(paths.items()):
        if not isinstance(path, str) or not path.startswith("/v1/"):
            continue
        if not isinstance(path_item, Mapping):
            raise CompatibilityBaselineError("generated OpenAPI path item is malformed")
        for method, operation in sorted(path_item.items()):
            if method not in _REST_METHODS:
                continue
            if not isinstance(operation, Mapping):
                raise CompatibilityBaselineError("generated OpenAPI operation is malformed")
            parameters = operation.get("parameters", [])
            if not isinstance(parameters, Sequence) or isinstance(parameters, str | bytes):
                raise CompatibilityBaselineError("generated OpenAPI parameters are malformed")
            responses = operation.get("responses", {})
            if not isinstance(responses, Mapping):
                raise CompatibilityBaselineError("generated OpenAPI responses are malformed")
            entry: dict[str, object] = {
                "method": method.upper(),
                "path": path,
                "parameters": sorted(
                    (_rest_parameter(parameter) for parameter in parameters),
                    key=lambda parameter: (str(parameter.get("in")), str(parameter.get("name"))),
                ),
                "responses": {
                    str(status): _rest_response(response)
                    for status, response in sorted(responses.items(), key=lambda item: str(item[0]))
                },
            }
            request_body = operation.get("requestBody")
            if request_body is not None:
                entry["request_body"] = _json_value(request_body)
            if operation.get("deprecated") is True:
                entry["deprecated"] = True
            if "security" in operation:
                entry["security"] = _json_value(operation["security"])
            operations.append(entry)
    return {"operations": operations}


def _rest_parameter(parameter: object) -> dict[str, object]:
    if not isinstance(parameter, Mapping):
        raise CompatibilityBaselineError("generated OpenAPI parameter is malformed")
    return {
        field_name: _json_value(parameter[field_name])
        for field_name in ("name", "in", "required", "schema")
        if field_name in parameter
    }


def _rest_response(response: object) -> dict[str, object]:
    if not isinstance(response, Mapping):
        raise CompatibilityBaselineError("generated OpenAPI response is malformed")
    return {
        field_name: _json_value(response[field_name])
        for field_name in ("content", "headers", "links")
        if field_name in response
    }


def _cli_surface() -> dict[str, object]:
    from typer.main import get_command

    from fetech.cli import app

    root = get_command(app)
    commands = getattr(root, "commands", None)
    if not isinstance(commands, Mapping):
        raise CompatibilityBaselineError("Typer did not produce a command group")
    result: dict[str, object] = {}
    for command_name, command in sorted(commands.items()):
        parameters = getattr(command, "params", None)
        if not isinstance(parameters, list):
            raise CompatibilityBaselineError("Typer command parameters are malformed")
        result[str(command_name)] = {
            "parameters": [_cli_parameter(parameter) for parameter in parameters]
        }
    return {
        "no_args_is_help": bool(getattr(root, "no_args_is_help", False)),
        "commands": result,
    }


def _cli_parameter(parameter: object) -> dict[str, object]:
    to_info_dict = getattr(parameter, "to_info_dict", None)
    if not callable(to_info_dict):
        raise CompatibilityBaselineError("Typer parameter metadata is unavailable")
    information = to_info_dict()
    if not isinstance(information, Mapping):
        raise CompatibilityBaselineError("Typer parameter metadata is malformed")
    stable_fields = (
        "count",
        "default",
        "envvar",
        "flag_value",
        "hidden",
        "is_flag",
        "multiple",
        "name",
        "nargs",
        "opts",
        "param_type_name",
        "prompt",
        "required",
        "secondary_opts",
        "type",
    )
    return {
        field_name: _json_value(information[field_name])
        for field_name in stable_fields
        if field_name in information
    }


def _mcp_surface() -> dict[str, object]:
    try:
        from fetech.mcp_server import build_server

        server = build_server()
    except (ImportError, RuntimeError) as exc:
        raise CompatibilityBaselineError(
            "install fetech[mcp] to inspect the MCP compatibility surface"
        ) from exc

    manager = getattr(server, "_tool_manager", None)
    tools = getattr(manager, "_tools", None)
    if not isinstance(tools, Mapping):
        raise CompatibilityBaselineError("MCP tool metadata is unavailable")
    return {
        "tools": {
            str(tool_name): {
                "input_schema": _json_value(getattr(tool, "parameters", None)),
                "result": _annotation_name(inspect.signature(tool.fn).return_annotation),
            }
            for tool_name, tool in sorted(tools.items())
        }
    }


def _json_value(value: object) -> Any:
    if value is None or isinstance(value, str | int | float | bool):
        return value
    if isinstance(value, Path):
        return "<path>"
    if isinstance(value, Enum):
        return _json_value(value.value)
    if isinstance(value, Mapping):
        return {
            str(field_name): _json_value(field_value)
            for field_name, field_value in sorted(value.items(), key=lambda item: str(item[0]))
        }
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [_json_value(item) for item in value]
    raise CompatibilityBaselineError(
        f"public surface contains unsupported metadata type {type(value).__name__}"
    )


def _compare(
    expected: object,
    actual: object,
    path: str,
    differences: list[str],
    maximum: int,
) -> None:
    if len(differences) >= maximum:
        return
    if type(expected) is not type(actual):
        differences.append(
            f"{path}: type changed from {type(expected).__name__} to {type(actual).__name__}"
        )
        return
    if isinstance(expected, dict) and isinstance(actual, dict):
        expected_fields = set(expected)
        actual_fields = set(actual)
        for field_name in sorted(expected_fields - actual_fields):
            differences.append(f"{path}.{field_name}: removed")
            if len(differences) >= maximum:
                return
        for field_name in sorted(actual_fields - expected_fields):
            differences.append(f"{path}.{field_name}: added")
            if len(differences) >= maximum:
                return
        for field_name in sorted(expected_fields & actual_fields):
            _compare(
                expected[field_name],
                actual[field_name],
                f"{path}.{field_name}",
                differences,
                maximum,
            )
            if len(differences) >= maximum:
                return
        return
    if isinstance(expected, list) and isinstance(actual, list):
        if len(expected) != len(actual):
            differences.append(f"{path}: length changed from {len(expected)} to {len(actual)}")
            if len(differences) >= maximum:
                return
        for index, (expected_item, actual_item) in enumerate(zip(expected, actual, strict=False)):
            _compare(
                expected_item,
                actual_item,
                f"{path}[{index}]",
                differences,
                maximum,
            )
            if len(differences) >= maximum:
                return
        return
    if expected != actual:
        differences.append(f"{path}: value changed")
