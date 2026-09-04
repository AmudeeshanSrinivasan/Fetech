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
   and failure-documentation evidence (validation normalization, the first native-parser fuzz
   slice, and same-host reproducible-build evidence are implemented; remaining work is in
   progress);
5. freeze release-candidate APIs only after compatibility and migration tests pass.

No Beta distribution version has been assigned. Package metadata remains `0.4.0a0` until a separate
version decision is made; this development branch is not a published v0.4 artifact.

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

The first deterministic fuzz slice covers request/URL handling, JSON/XML, native document formats,
archives, media headers/metadata, and logic-engine validation. It found and fixed raw CSV-error
escape, missing document serialized-output enforcement, and untyped malformed Clingo output. See
[`fuzzing.md`](fuzzing.md) and `tests/test_beta_parser_fuzz.py` for the exact evidence boundary.

The reproducible-build gate creates two independent tracked-source copies, fixes
`SOURCE_DATE_EPOCH` to the source commit, requires identical wheel and source-distribution bytes,
validates bounded archive metadata and wheel `RECORD`, and clean-installs both artifact kinds. Beta
CI retains its machine-readable receipt. This is same-host build-stability evidence, not a signed
release attestation or proof of cross-platform reproducibility. See
[`reproducible-builds.md`](reproducible-builds.md).

The remaining Increment 4 work is format-aware fuzz expansion, storage
quota/retention/garbage-collection/crash-recovery behavior, and a complete public failure catalogue.
Focused validation coverage lives in `tests/test_beta_validation_errors.py`.

## Verification

```bash
uv run pytest tests/test_beta_contracts.py tests/test_v04_interfaces.py tests/test_runtime_conformance.py
uv run pytest tests/test_beta_lifecycle.py
uv run pytest tests/test_beta_context.py
uv run pytest tests/test_beta_validation_errors.py
uv run pytest tests/test_beta_parser_fuzz.py
uv run pytest tests/test_beta_reproducible_builds.py
uv run pytest
uv run ruff check .
uv run mypy src/fetech
git diff --check
```
