# Fetech

Fetech is an Apache-2.0, policy-aware content-acquisition runtime. It registers 155 capabilities
across 13 categories and selects only the capabilities needed for a request.

The current release is an alpha implementation of the full architecture: it includes the canonical
registry and contracts, deterministic planning, SSRF-safe HTTP acquisition, typed artifacts, a
SQLite event ledger, content-addressed storage, quality validation, runtime provenance projection,
Python SDK, CLI, REST, and MCP interfaces, and a bounded Graphify/QMD context broker. Heavy browser, document,
media, and OCR engines are optional extras.

The v0.1 closure set contains 56 capabilities, and the checked-in conformance overlay reports all
56 implementation paths: 51 native and five optional. HTTP/3 is an optional bounded
`curl --http3-only` path and returns `DEPENDENCY_MISSING` when the configured
curl build lacks HTTP/3. `GET /v1/capabilities` and `fetech capabilities` expose the same release report; the
project does not infer availability from manifest registration alone.

Fetech uses a deliberately narrow polyglot design. Python 3.12 is the required runtime and remains
authoritative for public APIs, security, budgets, adapters, artifacts, and persistence. A pure-Python
planner is always available. Optional Clingo and SWI-Prolog backends can add constraint optimization
and declarative reasoning without becoming security or execution authorities.

| Layer | Responsibility | Required |
| --- | --- | --- |
| Python | SDK, CLI, REST, MCP, contracts, policy enforcement, workers, storage, validation | Yes |
| Clingo | Capability/dependency constraints, plan feasibility, bounded optimization | No |
| SWI-Prolog | Policy explanation, rule evaluation, provenance and lineage queries | No |

Logic-engine results are treated as untrusted proposals. Python accepts only registered capability
IDs and schema-valid outputs, then reapplies destination, authorization, and resource policies before
execution. Fetech continues deterministically when either logic engine is absent or times out.

> **Alpha status:** the current package ships the pure-Python planner, a bounded Clingo planner
> adapter, and a bounded SWI-Prolog reasoner. Python remains the default. Clingo can be installed with
> the `logic` extra; SWI-Prolog is discovered as an explicitly installed system executable.

Every fetch result includes `capability_outcomes`. These distinguish applied and observed features
from not-applicable, blocked, dependency-missing, and failed paths. Attempt, deadline, redirect,
wire-byte, and decompressed-byte budgets are decremented cumulatively in `remaining_budget`.

## Quick start

```bash
uv sync --extra dev --extra web --extra server --extra mcp
uv run fetech capabilities --summary
uv run fetech plan https://example.com
uv run fetech fetch https://example.com
uv run fetech-daemon
```

Optional logic backends are installed and selected explicitly:

```bash
uv sync --extra logic
uv run fetech plan https://example.com --backend clingo
uv run fetech explain http_get --backend prolog
```

The Prolog command requires `swipl` on `PATH`; set `FETECH_PROLOG_EXECUTABLE` for another reviewed
binary location. Daemons select backends with `FETECH_PLANNER_BACKEND=clingo` and
`FETECH_REASONER_BACKEND=prolog`. Backend absence, timeout, malformed output, or parity failure falls
back to Python unless `FETECH_LOGIC_FALLBACK=false`. See
[the architecture](docs/architecture.md) and [ADR 0001](docs/adr/0001-polyglot-logic-backends.md)
for the backend contracts and trust boundaries.

The optional remote reader is disabled until an operator configures
`FETECH_JINA_READER_TEMPLATE` with a `{target}` placeholder. A request must also use
`policy_profile=allow_remote_readers`, remain public and unauthenticated, and contain no sensitive
query values. The original publisher resource remains authoritative.

`browser_reader_mode` uses a separate bounded Python/Playwright subprocess over the already-fetched
HTML. Its context is offline, JavaScript is disabled, and every request is aborted. It does not open
the networked browser-rendering surface planned for v0.2.

The local logic runner is bounded by input/output, CPU, and wall time; Linux also applies an
address-space limit. It is not a full OS sandbox. Deployments must isolate solver processes to deny
network and unrestricted filesystem/process access as described in the security model.

## Verification

```bash
uv run pytest
uv run ruff check .
uv run mypy src/fetech
git diff --check
```

See [the architecture](docs/architecture.md), [security model](SECURITY.md), and
[capability catalogue](docs/capability-catalog.md).
