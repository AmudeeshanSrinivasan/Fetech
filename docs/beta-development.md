# Beta development

Beta begins contract stabilization after the v0.4 capability-closure candidate. Runtime coverage
remains 13/13 categories and 155/155 registered implementation paths.

## Release boundary

The official `0.4.0a0` publication contract remains frozen at 10/14 gates on the `main` commit from
which this branch was created. Beta work must not regenerate v0.4 candidate artifacts, mark an
external approval as passed, or weaken a gate. The four outstanding v0.4 gates remain:

1. systemd 257+ target-host attestation;
2. qualified human legal approval of the exact candidate artifacts;
3. Git tag and GitHub Release after the pre-publication approvals;
4. package publication after release approval.

The first two are pre-publication gates. The final two are post-publication receipts and cannot be
used to authorize their own actions.

`release/fetech-v0.4.0a0-freeze.toml` records the exact candidate commit, the 10/14 gate count, the
four blocked gate IDs, and hashes of tracked and local candidate evidence. It is a Beta boundary
record, not approval evidence. Repository tests verify tracked evidence against the frozen commit;
when ignored local artifacts are present, their hashes are checked too. Beta never regenerates the
v0.4 SBOM or license report from later source. CI exercises that frozen-evidence test instead of
running the old candidate profile against later Beta commits.

## Stabilization sequence

Beta work proceeds in bounded increments:

1. version and publish the machine-readable Python, REST, CLI, and MCP contract inventory
   (implemented);
2. expand cross-interface conformance for lifecycle operations, cancellation, and event streaming
   (implemented);
3. complete dual-graph and bounded-context behavior with source verification (implemented);
4. normalize public validation errors, then extend fuzzing, reproducible-build, storage-lifecycle,
   and failure-documentation evidence (validation normalization, native and format-aware fuzz
   slices, same-host reproducible-build evidence, the local storage lifecycle, and the public
   failure catalogue are implemented; the Linux-isolated format campaign remains in progress);
5. freeze release-candidate APIs only after compatibility and migration tests pass.

Increment 5 now enforces the current Beta `v1` surface through a checked-in exact baseline and
pre-Beta migration fixtures. The required-Linux fuzz expansion remains a separately visible,
deferred part of Increment 4; this local API-freeze work does not satisfy or waive it.

The Beta distribution version is `0.5.0b1`. Source, runtime, lock, FastAPI and build metadata must
agree on that identity. Assigning the version does not create a tag, GitHub Release or package
publication, and it does not alter the frozen `0.4.0a0` publication contract. The bounded scope and
remaining evidence gaps are recorded in [`releases/v0.5.0b1.md`](releases/v0.5.0b1.md).

## Increment 1: contract discovery and fail-closed versions

The public contract version remains `1.0`, and the REST namespace remains `v1`.

- `FetchRequest`, `FetchPlan`, `FetchResult`, and `Artifact` accept only an explicit
  `schema_version` of `1.0`.
- Documents from the pre-Beta surface that omit the field are normalized to `1.0` for backward
  compatibility.
- `fetech.contracts.contract_manifest()` builds an ordered, deterministic inventory of public
  models and their canonical serialization JSON Schema SHA-256 values.
- `FetechClient.contracts()`, `fetech contracts`, `GET /v1/contracts`, and MCP `get_contracts`
  expose the same typed manifest.
- Schema hashes are drift detectors. They do not certify compatibility or authenticate a build.

Changing any public model now requires focused version behavior tests and the cross-interface
manifest parity test in `tests/test_beta_contracts.py`.

## Increment 2: authoritative lifecycle and cancellation

`UniversalFetchGateway` remains the single lifecycle owner. The durable state sequence is:

```text
QUEUED -> PLANNING -> RUNNING -> FINISHED
                  \-> FINISHED (cancelled or failed)
```

`EventLedger.finish_run()` atomically stores a terminal event and canonical result. Its conditional
transition permits one winner: once a run is `FINISHED`, completion, failure, shutdown, and repeated
cancellation cannot overwrite it or append a contradictory terminal event.

Cancellation keeps the locked result-status enum. A cancelled run returns `FAILED`, or `PARTIAL`
when useful artifacts were already produced, with a `run_cancelled` diagnostic. The terminal event
is `run.cancelled` and records only a bounded reason (`requested`, `caller_cancelled`, or `shutdown`).
Any in-flight attempt is retained as `CANCELLED`; prior artifacts, provenance, and consumed budget
remain in the result.

| Interface | Lifecycle operation |
| --- | --- |
| Python SDK | `FetchHandle.cancel()` and `FetechClient.cancel(run_id)` |
| REST | `DELETE /v1/runs/{run_id}` |
| CLI | `fetech cancel RUN_ID [--daemon-url ORIGIN]` |
| MCP | `submit_fetch` followed by `cancel_fetch` |

The CLI cancellation command deliberately contacts the running daemon. Opening a second local
gateway against the daemon's SQLite file would not own its asyncio task and is not a valid
cancellation mechanism. The daemon origin must be HTTP(S) without userinfo, a path, query, or
fragment, and redirects are disabled.

`FetchHandle.result()` shields the submitted run from cancellation of a waiter. In contrast,
cancelling the foreground `FetechClient.fetch()` coroutine explicitly cancels and durably finalizes
the run it created. Cancellation during planning is also finalized, preventing orphaned `QUEUED` or
`PLANNING` rows. SSE validates the run before sending headers, so an unknown run returns HTTP 404;
known streams end after their single terminal event.

Focused coverage lives in `tests/test_beta_lifecycle.py` and includes planning/execution races,
idempotency, partial-attempt retention, atomic terminal competition, unknown traces, and all four
interfaces.

## Increment 3: dual graphs and bounded context

Repository architecture and runtime provenance remain separate Graphify projections. The broker now
classifies each question deterministically as code architecture, runtime history, decision history,
or a combination. It queries only the selected planes and shares the 1,200-token graph allowance
when both graphs are required. The daemon, SDK, CLI, and MCP server all bind runtime retrieval to the
configured daemon-data graph rather than treating `graphify-out/graph.json` as runtime evidence.

Code-graph conclusions are checked against bounded, repository-scoped source windows. Verification
requires the window to contain a question or selected-node term; a stale-but-existing line number is
not accepted. On stale locations the broker performs an exact search, returns the fresh source line,
and leaves the graph excerpt marked unverified until Graphify is refreshed.

Every provider emits a typed report, including skipped, empty, unavailable, timeout, output-limit,
and failure states. Sources include SHA-256 identity, freshness, selected nodes/paths, exact
locations, and verification state. Deduplication uses locator plus hash; token usage is separated by
plane and is trimmed to the requested budget. Runtime projections now contain sanitized event
metadata and ledger locators, use atomic file replacement, and are serialized by the gateway.

See [`context-broker.md`](context-broker.md) for the routing, budget, authority, and interface
contracts. Focused coverage lives in `tests/test_beta_context.py`.

## Increment 4: validation errors and hardening evidence

`PublicError` is the versioned, bounded validation-error envelope shared by the Python SDK, REST,
CLI, and MCP. `INVALID_REQUEST` errors carry an HTTP-equivalent status, retryability, at most 32
sanitized issues, and an omitted-issue count. Issues expose only allowlisted field locations,
stable error codes, and generic messages. They never include rejected input, Pydantic context,
exception text, URLs, credentials, or secret-bearing user-defined field names.

`FetechValidationError` is the SDK exception boundary and serializes to the same `PublicError`
document. SDK request methods accept either an already validated `FetchRequest` or a mapping and
validate mappings through this boundary. FastAPI replaces its default request-validation response,
the CLI emits the document to standard error with exit code 2, and MCP surfaces the same serialized
document as its tool error. Framework-level failures that happen before a command/tool handler can
run remain transport errors; inputs accepted by a Fetech handler use the shared contract.

This does not change acquisition failures. Policy blocks, authentication requirements, missing
dependencies, budget exhaustion, low quality, not-found resources, partial output, and execution
failures remain canonical `FetchResult.status` values with diagnostics and provenance.

`FailureCatalogue` makes those terminal semantics discoverable without relying on exception or
message text. It inventories all nine result statuses, stable built-in attempt/crawl/diagnostic
codes, artifact expectations, and the separate `INVALID_REQUEST` delivery contract. The SDK, CLI,
REST, and MCP expose an identical document through `FetechClient.failures()`, `fetech failures`,
`GET /v1/failures`, and `get_failures`. Public attempt and crawl fallbacks now use stable generic
codes rather than dependency exception class names. See
[`failure-semantics.md`](failure-semantics.md).

The deterministic fuzz suite covers request/URL handling, JSON/XML, native document formats,
archives, media headers/metadata, and logic-engine validation. Its format-aware slice adds generated
RSS/Atom/sitemap/OpenAPI YAML, including duplicate OpenAPI mutation, plus HTML
reader/discovery/navigation, browser and document worker envelopes, and structured ZIP cases. The
two slices found and fixed untyped parser errors, missing
serialized-output enforcement, invalid-Unicode and malformed-worker-JSON escapes, and non-finite
browser observations. See [`fuzzing.md`](fuzzing.md), `tests/test_beta_parser_fuzz.py`, and
`tests/test_beta_format_fuzz.py` for the exact evidence boundary.

The reproducible-build gate creates two independent tracked-source copies, fixes
`SOURCE_DATE_EPOCH` to the source commit, requires identical wheel and source-distribution bytes,
validates bounded archive metadata and wheel `RECORD`, and clean-installs both artifact kinds. Beta
CI retains its machine-readable receipt. This is same-host build-stability evidence, not a signed
release attestation or proof of cross-platform reproducibility. See
[`reproducible-builds.md`](reproducible-builds.md).

The local storage lifecycle now serializes writes under a whole-data-directory content quota, keeps
terminal-ledger headroom, supports explicit finished-run retention with immutable tombstones, prunes
expired snapshot metadata, and garbage-collects only old CAS blobs outside the combined ledger/cache
live set. Startup also recovers interrupted runs and abandoned CAS/snapshot staging files before
accepting work. The evidence and secure-deletion limits are documented in
[`storage-lifecycle.md`](storage-lifecycle.md).

The remaining Increment 4 work is the required-Linux OOXML/PDF and broader container-mutation fuzz
campaign. Focused validation and failure-catalogue coverage lives in
`tests/test_beta_validation_errors.py` and `tests/test_beta_failure_catalogue.py`.

## Increment 5: API compatibility and migration freeze

`compatibility/beta-v1.json` is the deterministic exact-surface baseline for the contract schemas,
Python SDK methods, REST operations, CLI commands and MCP tools. CI rebuilds the surface with the
locked dependencies and fails on every difference. Additions are blocked as well as removals and
changes so that a reviewer—not an automatic schema heuristic—decides compatibility before an
explicit baseline refresh.

Representative `0.4.0a0` request, plan, artifact and result fixtures omit `schema_version` and must
normalize to `1.0`, round-trip, and continue rejecting explicit unknown versions. See
[`api-compatibility.md`](api-compatibility.md) for the evidence boundary and reviewed refresh
workflow. Focused coverage lives in `tests/test_beta_compatibility.py`.

## Verification

```bash
uv run pytest tests/test_beta_contracts.py tests/test_v04_interfaces.py tests/test_runtime_conformance.py
uv run pytest tests/test_beta_lifecycle.py
uv run pytest tests/test_beta_context.py
uv run pytest tests/test_beta_validation_errors.py
uv run pytest tests/test_beta_failure_catalogue.py
uv run pytest tests/test_beta_parser_fuzz.py tests/test_beta_format_fuzz.py
uv run pytest tests/test_beta_reproducible_builds.py
uv run pytest tests/test_beta_storage_lifecycle.py
uv run pytest tests/test_beta_compatibility.py
uv run pytest tests/test_beta_version.py
uv run python scripts/check_beta_compatibility.py
uv run pytest
uv run ruff check .
uv run mypy src/fetech
git diff --check
```
