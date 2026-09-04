"""Sanitized public-interface error normalization."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from typing import Any
from uuid import UUID

from pydantic import ValidationError

from fetech.models import (
    FetchRequest,
    PublicError,
    PublicErrorCode,
    ValidationIssue,
)

_MAX_PUBLIC_ISSUES = 32
_LOCATION_PREFIXES = frozenset({"body", "path", "query"})
_PUBLIC_LOCATION_NAMES = frozenset(
    {
        "request",
        "schema_version",
        "target",
        "intent",
        "output_requirements",
        "authentication_ref",
        "privacy_profile",
        "policy_profile",
        "freshness_seconds",
        "language",
        "region",
        "allow_capabilities",
        "deny_capabilities",
        "approved_capabilities",
        "budget",
        "deadline_seconds",
        "attempts",
        "redirects",
        "bytes",
        "decompressed_bytes",
        "crawl_pages",
        "crawl_depth",
        "browser_seconds",
        "archive_members",
        "archive_ratio",
        "model_tokens",
        "monetary_ceiling",
        "question",
        "token_budget",
        "maximum_bytes",
        "maximum_pages",
        "maximum_depth",
        "capability_id",
        "run_id",
        "artifact_id",
        "content",
    }
)
_SAFE_CODE = re.compile(r"[^a-z0-9_.-]+")
_PUBLIC_ERROR_CODES = frozenset(
    {
        "bool_parsing",
        "bool_type",
        "bytes_too_long",
        "bytes_too_short",
        "bytes_type",
        "decimal_parsing",
        "decimal_type",
        "extra_forbidden",
        "finite_number",
        "float_parsing",
        "float_type",
        "greater_than",
        "greater_than_equal",
        "int_from_float",
        "int_parsing",
        "int_type",
        "less_than",
        "less_than_equal",
        "list_type",
        "literal_error",
        "mapping_type",
        "missing",
        "model_type",
        "multiple_of",
        "set_type",
        "string_pattern_mismatch",
        "string_too_long",
        "string_too_short",
        "string_type",
        "tuple_type",
        "url_parsing",
        "url_scheme",
        "uuid_parsing",
        "uuid_type",
        "value_error",
    }
)


class FetechValidationError(ValueError):
    """Typed validation exception whose text is the sanitized public contract."""

    def __init__(self, error: PublicError) -> None:
        self.error = error
        super().__init__(error.model_dump_json())


def validate_fetch_request(value: FetchRequest | Mapping[str, Any]) -> FetchRequest:
    """Validate an SDK/interface request without exposing rejected input values."""

    if isinstance(value, FetchRequest):
        return value
    try:
        return FetchRequest.model_validate(value)
    except ValidationError as exc:
        raise FetechValidationError(public_validation_error(exc)) from None


def validate_context_request(question: object, token_budget: object) -> tuple[str, int]:
    """Validate and hard-cap public context inputs consistently across interfaces."""

    if not isinstance(question, str):
        raise invalid_parameter(("question",), code="string_type")
    if not question.strip():
        raise invalid_parameter(("question",), code="string_too_short")
    if len(question) > 16_384 or len(question.encode("utf-8")) > 16_384:
        raise invalid_parameter(("question",), code="string_too_long")
    if isinstance(token_budget, bool) or not isinstance(token_budget, int):
        raise invalid_parameter(("token_budget",), code="int_type")
    if token_budget <= 0:
        raise invalid_parameter(("token_budget",), code="greater_than_equal")
    return question, min(token_budget, 8_000)


def validation_exception(
    exc: Exception,
    *,
    location: Sequence[str | int] = ("request",),
) -> FetechValidationError:
    """Convert a known validation exception into the public typed exception."""

    if isinstance(exc, FetechValidationError):
        return exc
    return FetechValidationError(public_validation_error(exc, location=location))


def invalid_parameter(
    location: Sequence[str | int],
    *,
    code: str = "invalid_value",
) -> FetechValidationError:
    """Create a sanitized validation error for an explicitly checked parameter."""

    issue = ValidationIssue(
        location=_safe_location(location, fallback=("request",)),
        code=_safe_code(code),
        message=_public_message(code),
    )
    return FetechValidationError(_error((issue,)))


def validate_uuid(value: UUID | str, location: str) -> UUID:
    """Parse a public UUID argument through the sanitized validation boundary."""

    if isinstance(value, UUID):
        return value
    try:
        return UUID(value)
    except (AttributeError, TypeError, ValueError):
        raise invalid_parameter((location,), code="uuid_parsing") from None


def public_validation_error(
    exc: Exception,
    *,
    location: Sequence[str | int] = ("request",),
) -> PublicError:
    """Return a bounded error envelope without input, context, URLs, or exception text."""

    if isinstance(exc, FetechValidationError):
        return exc.error

    raw_errors = _validation_errors(exc)
    if not raw_errors:
        issue = ValidationIssue(
            location=_safe_location(location, fallback=("request",)),
            code="invalid_value",
            message=_public_message("invalid_value"),
        )
        return _error((issue,))

    issues: list[ValidationIssue] = []
    for raw in raw_errors[:_MAX_PUBLIC_ISSUES]:
        raw_location = raw.get("loc")
        selected_location = (
            tuple(raw_location)
            if isinstance(raw_location, (list, tuple))
            else tuple(location)
        )
        code = _safe_code(raw.get("type", "invalid_value"))
        issues.append(
            ValidationIssue(
                location=_safe_location(selected_location, fallback=location),
                code=code,
                message=_public_message(code),
            )
        )
    return _error(tuple(issues), omitted=max(0, len(raw_errors) - len(issues)))


def _validation_errors(exc: Exception) -> list[Mapping[str, Any]]:
    errors = getattr(exc, "errors", None)
    if not callable(errors):
        return []
    try:
        raw = errors(include_url=False, include_context=False, include_input=False)
    except TypeError:
        raw = errors()
    if not isinstance(raw, list):
        return []
    return [item for item in raw if isinstance(item, Mapping)]


def _safe_code(value: object) -> str:
    normalized = _SAFE_CODE.sub("_", str(value).lower())[:128].strip("_.-")
    return normalized if normalized in _PUBLIC_ERROR_CODES else "invalid_value"


def _safe_location(
    location: Iterable[str | int],
    *,
    fallback: Sequence[str | int],
) -> tuple[str | int, ...]:
    values = list(location)
    if values and values[0] in _LOCATION_PREFIXES:
        values.pop(0)
    safe: list[str | int] = []
    for value in values[:8]:
        if isinstance(value, int):
            safe.append(max(0, value))
        elif value in _PUBLIC_LOCATION_NAMES:
            safe.append(value)
        else:
            safe.append("<field>")
    if safe:
        return tuple(safe)
    fallback_values = [
        value
        if isinstance(value, int) or value in _PUBLIC_LOCATION_NAMES
        else "<field>"
        for value in tuple(fallback)[:8]
    ]
    return tuple(fallback_values) or ("request",)


def _public_message(code: str) -> str:
    if code == "missing" or code.endswith(".missing"):
        return "field is required"
    if "extra_forbidden" in code:
        return "unexpected field"
    if "literal" in code or "enum" in code:
        return "value is not supported"
    if "too_short" in code or "min_length" in code:
        return "value is too short"
    if "too_long" in code or "max_length" in code:
        return "value is too long"
    if any(
        marker in code
        for marker in (
            "greater_than",
            "less_than",
            "multiple_of",
            "finite_number",
        )
    ):
        return "value is outside the allowed range"
    if code.endswith("_parsing"):
        return "value has an invalid format"
    if "type" in code:
        return "value has the wrong type"
    return "value is invalid"


def _error(issues: tuple[ValidationIssue, ...], *, omitted: int = 0) -> PublicError:
    return PublicError(
        code=PublicErrorCode.INVALID_REQUEST,
        message="request validation failed",
        status_code=422,
        issues=issues,
        omitted_issues=min(omitted, 1_000_000),
    )
