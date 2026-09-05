# Failure semantics

Fetech has two public failure boundaries. A valid acquisition request always completes as a typed
`FetchResult`, including policy, authentication, dependency, budget, quality, not-found, partial,
and execution outcomes. Input rejected before execution raises or returns a versioned `PublicError`.
Callers must inspect the typed document instead of parsing messages or Python exception names.

The canonical machine-readable inventory is returned by
`fetech.failures.failure_catalogue()`. The same `FailureCatalogue` document is exposed through
`FetechClient.failures()`, `fetech failures`, `GET /v1/failures`, and MCP `get_failures`. Its
`schema_version` is `1.0`; additions or semantic changes follow the public contract compatibility
process and appear in `fetech contracts` schema hashes.

## Terminal results

| `FetchResult.status` | Meaning | Artifact contract |
| --- | --- | --- |
| `SUCCEEDED` | At least one accepted artifact satisfied the request | An accepted artifact is required |
| `PARTIAL` | Useful artifacts exist but the request was not fully satisfied | An artifact is required |
| `BLOCKED_BY_POLICY` | Deterministic policy rejected every permitted path | Artifacts are optional |
| `AUTH_REQUIRED` | New or refreshed origin-scoped authentication is required | Artifacts are optional |
| `DEPENDENCY_MISSING` | A required optional dependency or provider was unavailable | Artifacts are optional |
| `BUDGET_EXHAUSTED` | A declared resource budget ended the run before acceptance | Artifacts are optional |
| `LOW_QUALITY` | Produced artifacts did not meet the requested quality threshold | An artifact is required |
| `NOT_FOUND` | The requested origin resource was not found | Artifacts are optional |
| `FAILED` | No acceptable artifact or more specific terminal status applies | Artifacts are optional |

`SUCCEEDED` and `PARTIAL` are the two success-bearing states. The other states are terminal
non-success outcomes. A terminal result is not marked automatically retryable: the planner already
performs bounded retries and fallbacks, and another run may require a changed budget, credential,
dependency, policy, target, or runtime. Applications may make that change explicitly and submit a
new request.

REST submission returns HTTP 202 and run retrieval returns HTTP 200 for every terminal
`FetchResult.status`; terminal semantics are in the body. The SDK returns `FetchResult`, the CLI
prints it and exits 0, and synchronous MCP acquisition tools return its JSON. HTTP and process exit
codes therefore describe interface delivery, not acquisition success.

## Built-in codes

`FetchAttempt.failure_code`, `DiscoveredTarget.failure_code`, and `Diagnostic.code` share stable,
sanitized identifiers but have distinct scopes. Messages and warnings are explanatory text and are
not compatibility keys.

| Code | Scope | Meaning |
| --- | --- | --- |
| `adapter_failed` | attempt, diagnostic | Adapter failure without a more specific public code |
| `adapter_missing` | diagnostic | Planned adapter is not registered |
| `auth_expired` | attempt, diagnostic | Authentication material expired |
| `auth_required` | attempt, diagnostic | Required authentication was unavailable |
| `budget_exhausted` | attempt, diagnostic | A declared budget was exhausted |
| `cache_error` | attempt | Cache operation failed without a more specific cache code |
| `cache_miss` | attempt | No cache entry or snapshot satisfied the lookup |
| `cache_revalidation_required` | attempt | Cached content required origin revalidation |
| `cancelled` | attempt | An adapter task was cancelled |
| `dependency_missing` | attempt, diagnostic | Optional dependency or configured provider was unavailable |
| `dependency_skipped` | diagnostic | A node was skipped after a dependency did not complete |
| `document_error` | attempt | Document processing failed |
| `early_stop` | attempt | A branch stopped after request acceptance |
| `empty_response` | crawl | A crawled target produced no resource |
| `execution_cancelled` | attempt | A plan node was cancelled before completion |
| `fetch_failed` | crawl | A crawled target failed without a more specific crawl code |
| `internal_error` | diagnostic | Unexpected runtime failure |
| `malformed_api_payload` | attempt | Structured API response violated its format contract |
| `malformed_document` | attempt | Document input violated parser constraints |
| `media_extraction_failed` | attempt | Media extraction failed |
| `not_found` | attempt, diagnostic | Origin resource was not found |
| `parallel_sibling_stopped_execution` | attempt | A sibling branch requested execution stop |
| `planning_failed` | diagnostic | No schema-valid executable plan was produced |
| `policy` | attempt | Adapter operation was rejected by policy |
| `policy_blocked` | diagnostic | Every viable acquisition path was rejected by policy |
| `run_cancelled` | diagnostic | Caller or runtime lifecycle cancelled the run |
| `run_interrupted` | diagnostic | An active run was recovered without terminal persistence |
| `snapshot_integrity` | attempt | Snapshot integrity or authority validation failed |
| `transport_error` | attempt | HTTP transport failed without a more specific public code |
| `unsafe_or_malformed_archive` | attempt | Archive was malformed or violated extraction limits |

These identifiers do not expose dependency exception types. New built-in codes may be added in a
compatible catalogue revision; existing meanings and scopes cannot be repurposed within contract
version `1.0`. Injected third-party adapters may emit extension codes, but callers must treat an
unknown code generically and continue to use the enclosing status and scope as authority.

## Pre-execution errors

`INVALID_REQUEST` is the current `PublicErrorCode`. It contains an HTTP-equivalent status of 422,
is not retryable without changing the request, and includes at most 32 sanitized validation issues.
Its descriptor also publishes the complete allowlist of stable `ValidationIssue.code` values;
unknown validator types collapse to `invalid_value`.
The SDK raises `FetechValidationError`; REST returns HTTP 422; the CLI writes the same JSON to
standard error and exits 2; MCP reports a tool error carrying the same envelope.

Framework, connectivity, process-launch, and deployment failures that occur outside a Fetech
handler are interface failures and may not have a `PublicError`. They must not be mistaken for a
completed acquisition result.
