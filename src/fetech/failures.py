"""Versioned, deterministic public failure semantics."""

from __future__ import annotations

from fetech.models import (
    FailureCatalogue,
    FailureCodeDescriptor,
    PublicErrorCode,
    PublicErrorDescriptor,
    ResultStatus,
    ResultStatusDescriptor,
)
from fetech.version import __version__

PUBLIC_VALIDATION_ISSUE_CODES = frozenset(
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
        "invalid_value",
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

_CODE_DESCRIPTORS: tuple[FailureCodeDescriptor, ...] = (
    FailureCodeDescriptor(
        code="adapter_failed",
        scopes=("attempt", "diagnostic"),
        summary="A selected adapter failed without a more specific public failure code.",
    ),
    FailureCodeDescriptor(
        code="adapter_missing",
        scopes=("diagnostic",),
        summary="The plan selected an adapter that is not registered in this runtime.",
    ),
    FailureCodeDescriptor(
        code="auth_expired",
        scopes=("attempt", "diagnostic"),
        summary="Origin-scoped authentication material expired during acquisition.",
    ),
    FailureCodeDescriptor(
        code="auth_required",
        scopes=("attempt", "diagnostic"),
        summary="The target requires authentication that the request did not provide.",
    ),
    FailureCodeDescriptor(
        code="budget_exhausted",
        scopes=("attempt", "diagnostic"),
        summary="A declared resource or deadline budget was exhausted.",
    ),
    FailureCodeDescriptor(
        code="cache_error",
        scopes=("attempt",),
        summary="A cache or snapshot operation failed without a more specific cache code.",
    ),
    FailureCodeDescriptor(
        code="cache_miss",
        scopes=("attempt",),
        summary="No cache entry or snapshot satisfied the requested lookup.",
    ),
    FailureCodeDescriptor(
        code="cache_revalidation_required",
        scopes=("attempt",),
        summary="A cached response required origin revalidation before it could be accepted.",
    ),
    FailureCodeDescriptor(
        code="cancelled",
        scopes=("attempt",),
        summary="An adapter stopped because its execution task was cancelled.",
    ),
    FailureCodeDescriptor(
        code="dependency_missing",
        scopes=("attempt", "diagnostic"),
        summary="A required optional runtime dependency or configured provider was unavailable.",
    ),
    FailureCodeDescriptor(
        code="dependency_skipped",
        scopes=("diagnostic",),
        summary="A plan node was skipped because one of its dependencies did not complete.",
    ),
    FailureCodeDescriptor(
        code="document_error",
        scopes=("attempt",),
        summary="Document processing failed without a more specific document code.",
    ),
    FailureCodeDescriptor(
        code="early_stop",
        scopes=("attempt",),
        summary="A branch was cancelled after the request stop predicate was satisfied.",
    ),
    FailureCodeDescriptor(
        code="empty_response",
        scopes=("crawl",),
        summary="A crawled target completed without producing a resource.",
    ),
    FailureCodeDescriptor(
        code="execution_cancelled",
        scopes=("attempt",),
        summary="A running plan node was cancelled before completion.",
    ),
    FailureCodeDescriptor(
        code="fetch_failed",
        scopes=("crawl",),
        summary="A crawled target failed without a more specific public crawl code.",
    ),
    FailureCodeDescriptor(
        code="internal_error",
        scopes=("diagnostic",),
        summary="The runtime encountered an unexpected internal failure.",
    ),
    FailureCodeDescriptor(
        code="malformed_api_payload",
        scopes=("attempt",),
        summary="A structured API response could not be parsed within its format contract.",
    ),
    FailureCodeDescriptor(
        code="malformed_document",
        scopes=("attempt",),
        summary="Document input was malformed or violated bounded parser constraints.",
    ),
    FailureCodeDescriptor(
        code="media_extraction_failed",
        scopes=("attempt",),
        summary="Media metadata or artifact extraction failed.",
    ),
    FailureCodeDescriptor(
        code="not_found",
        scopes=("attempt", "diagnostic"),
        summary="The requested origin resource was not found.",
    ),
    FailureCodeDescriptor(
        code="parallel_sibling_stopped_execution",
        scopes=("attempt",),
        summary="A parallel branch was cancelled after a sibling requested execution stop.",
    ),
    FailureCodeDescriptor(
        code="planning_failed",
        scopes=("diagnostic",),
        summary="The request could not produce a schema-valid executable plan.",
    ),
    FailureCodeDescriptor(
        code="policy",
        scopes=("attempt",),
        summary="An adapter operation was rejected by deterministic policy.",
    ),
    FailureCodeDescriptor(
        code="policy_blocked",
        scopes=("diagnostic",),
        summary="The request or all viable acquisition paths were blocked by policy.",
    ),
    FailureCodeDescriptor(
        code="run_cancelled",
        scopes=("diagnostic",),
        summary="The fetch run was cancelled by the caller or runtime lifecycle.",
    ),
    FailureCodeDescriptor(
        code="run_interrupted",
        scopes=("diagnostic",),
        summary="A previously active run was interrupted before terminal persistence.",
    ),
    FailureCodeDescriptor(
        code="snapshot_integrity",
        scopes=("attempt",),
        summary="Snapshot content failed integrity or authority validation.",
    ),
    FailureCodeDescriptor(
        code="transport_error",
        scopes=("attempt",),
        summary="HTTP transport failed without a more specific public failure code.",
    ),
    FailureCodeDescriptor(
        code="unsafe_or_malformed_archive",
        scopes=("attempt",),
        summary="Archive input was malformed or violated extraction safety limits.",
    ),
)

_RESULT_STATUS_DESCRIPTORS: tuple[ResultStatusDescriptor, ...] = (
    ResultStatusDescriptor(
        status=ResultStatus.AUTH_REQUIRED,
        summary="Acquisition requires new or refreshed origin-scoped authentication.",
        successful=False,
        artifact_disposition="optional",
        common_diagnostic_codes=("auth_expired", "auth_required"),
    ),
    ResultStatusDescriptor(
        status=ResultStatus.BLOCKED_BY_POLICY,
        summary="Deterministic policy rejected every permitted acquisition path.",
        successful=False,
        artifact_disposition="optional",
        common_diagnostic_codes=("policy_blocked",),
    ),
    ResultStatusDescriptor(
        status=ResultStatus.BUDGET_EXHAUSTED,
        summary="The run exhausted a declared resource budget before acceptance.",
        successful=False,
        artifact_disposition="optional",
        common_diagnostic_codes=("budget_exhausted",),
    ),
    ResultStatusDescriptor(
        status=ResultStatus.DEPENDENCY_MISSING,
        summary="No acceptable result was possible because a required dependency was unavailable.",
        successful=False,
        artifact_disposition="optional",
        common_diagnostic_codes=(
            "adapter_missing",
            "dependency_missing",
            "dependency_skipped",
        ),
    ),
    ResultStatusDescriptor(
        status=ResultStatus.FAILED,
        summary="The run ended without an acceptable artifact or a more specific terminal status.",
        successful=False,
        artifact_disposition="optional",
        common_diagnostic_codes=(
            "adapter_failed",
            "internal_error",
            "planning_failed",
            "run_cancelled",
            "run_interrupted",
        ),
    ),
    ResultStatusDescriptor(
        status=ResultStatus.LOW_QUALITY,
        summary="Artifacts were produced but none satisfied the requested quality threshold.",
        successful=False,
        artifact_disposition="artifacts_required",
    ),
    ResultStatusDescriptor(
        status=ResultStatus.NOT_FOUND,
        summary="The requested origin resource was not found.",
        successful=False,
        artifact_disposition="optional",
        common_diagnostic_codes=("not_found",),
    ),
    ResultStatusDescriptor(
        status=ResultStatus.PARTIAL,
        summary="Useful artifacts were produced, but the request was not fully satisfied.",
        successful=True,
        artifact_disposition="artifacts_required",
    ),
    ResultStatusDescriptor(
        status=ResultStatus.SUCCEEDED,
        summary="At least one accepted artifact satisfied the request.",
        successful=True,
        artifact_disposition="accepted_required",
    ),
)

_PUBLIC_ERROR_DESCRIPTORS: tuple[PublicErrorDescriptor, ...] = (
    PublicErrorDescriptor(
        code=PublicErrorCode.INVALID_REQUEST,
        summary="The public request failed bounded schema or parameter validation.",
        issue_codes=tuple(sorted(PUBLIC_VALIDATION_ISSUE_CODES)),
        rest_status=422,
        cli_exit_code=2,
    ),
)


def failure_catalogue() -> FailureCatalogue:
    """Return the canonical, deterministic public failure catalogue."""

    return FailureCatalogue(
        package_version=__version__,
        result_statuses=tuple(
            descriptor.model_copy(deep=True)
            for descriptor in sorted(
                _RESULT_STATUS_DESCRIPTORS,
                key=lambda descriptor: descriptor.status.value,
            )
        ),
        codes=tuple(
            descriptor.model_copy(deep=True)
            for descriptor in sorted(_CODE_DESCRIPTORS, key=lambda descriptor: descriptor.code)
        ),
        public_errors=tuple(
            descriptor.model_copy(deep=True)
            for descriptor in sorted(
                _PUBLIC_ERROR_DESCRIPTORS,
                key=lambda descriptor: descriptor.code.value,
            )
        ),
    )
