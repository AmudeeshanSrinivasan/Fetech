# Fetech

Fetech is an Apache-2.0, policy-aware content-acquisition runtime. It registers 155 capabilities
across 13 categories and selects only the capabilities needed for a request.

The current v0.3 alpha implements the canonical registry and contracts, deterministic planning,
SSRF-safe HTTP acquisition, bounded crawling, deterministic URL alternatives, isolated browser
rendering, typed artifacts, a SQLite event ledger, content-addressed storage, quality validation,
runtime provenance projection, Python SDK, CLI, REST, MCP, a bounded Graphify/QMD context broker,
origin-scoped authentication sessions, approved form submission, and bounded structured API/feed
normalization. Document, media, and OCR capability closure remains scheduled for v0.4; browser
binaries remain optional extras for the already implemented browser paths.

The v0.1 closure set contains 56 capabilities, v0.2 adds 40, and v0.3 adds 23, for 119 cumulative
implementation paths. The v0.3 overlay reports 21 native paths and two configured optional
connectors (`sso` and `private_workspace`) with no planned gaps. HTTP/3 is an optional bounded
`curl --http3-only` path and returns `DEPENDENCY_MISSING` when the configured curl build lacks
HTTP/3. `GET /v1/capabilities` and `fetech capabilities` expose the same release reports; the project
does not infer availability from manifest registration alone.

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
uv run fetech crawl https://example.com --max-pages 20 --max-depth 2
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

`browser_reader_mode` uses a bounded Python/Playwright subprocess over already-fetched HTML with
JavaScript disabled. The v0.2 browser adapter uses a separate bounded rendering mode with JavaScript
enabled. Both modes are offline, block service workers, and abort every subresource request; the
rendering mode can apply bounded selector waits, scrolling, expansion clicks, cookie-banner actions,
SPA observation, visible-text extraction, and screenshots without giving page scripts network access.

Puppeteer and Selenium are optional isolated connector paths. Configure
`FETECH_PUPPETEER_CONNECTOR_URL` or `FETECH_SELENIUM_CONNECTOR_URL`, and use
`policy_profile=allow_remote_browsers` on a public, unauthenticated request. Connectors receive the
already-fetched HTML and an `offline` network policy, never credentials. Search discovery is likewise
disabled until `FETECH_SEARCH_PROVIDER_TEMPLATE` contains a `{query}` placeholder and a crawl uses
`policy_profile=allow_search_discovery` (the CLI `--search` flag).

Authenticated library requests use an injected `CredentialProvider`. `FetchRequest` carries only an
opaque reference; resolved headers and cookies remain in memory, require an exact HTTPS origin, and
are rebuilt per redirect hop. Cross-origin redirects receive no credentials and `robots.txt` is
always fetched without authentication. High-level login, OAuth, SSO, and private-workspace requests
also require a trusted `SessionProvider` descriptor whose capability, opaque reference, exact
origin, issuer/scopes, and optional connector identity are validated before HTTP use. Defaults fail
closed. Descriptor-authorized OAuth/SSO bearer sessions may refresh at most once for an idempotent
retrieval; sanitized refresh lifecycle events enter the ledger.

The packaged CLI and the zero-argument daemon/MCP entry points deliberately use null providers.
Authenticated execution in v0.3 therefore uses the Python SDK or an embedded
`create_app(...)`/`build_server(...)` with explicitly injected providers; unconfigured entry points
return typed authentication or dependency failures.

Mutating form operations require both `approved_capabilities={"form_submit"}` and a short-lived,
exact-target `FormSubmissionApproval` supplied through an injected `FormSubmissionProvider`. Form
proposals are consumed once per run. Fields and CSRF values remain ephemeral and are never placed in
`FetchRequest`, plans, diagnostics, or events. A successful approved POST may carry bounded Secure
cookies across a same-origin 301/302/303 login redirect for that request chain only; the cookies are
scrubbed before the response returns. Body-preserving redirects are blocked without a new
exact-target approval. Provider-supplied CSRF material is accepted only when it exactly matches the
token and source lineage extracted in the current run.

The v0.3 API adapter consumes only raw artifacts already acquired by the HTTP boundary. It supports
bounded REST, GraphQL response, JSON, XML, RSS, Atom, sitemap, OpenAPI, GitHub, Semantic Scholar,
arXiv, OpenReview, and Crossref/OpenAlex normalization with original-source authority and parent
lineage. XML DTD/entity declarations, excessive nesting, duplicate JSON keys, unsafe OpenAPI YAML
aliases, wrong named-API origins, and unrecognized named schemas fail closed. See
[the v0.3 authentication and API conformance guide](docs/v0.3-authentication-foundation.md).

The local logic runner is bounded by input/output, CPU, and wall time; Linux also applies an
address-space limit. It is not a full OS sandbox. Deployments must isolate solver processes to deny
network and unrestricted filesystem/process access as described in the security model.

## Verification

```bash
uv run pytest
uv run ruff check .
uv run mypy src/fetech
uv run python scripts/generate_release_evidence.py --check
uv build
git diff --check
```

See [the architecture](docs/architecture.md), [security policy](SECURITY.md),
[v0.3 threat model](docs/security-threat-model.md),
[capability catalogue](docs/capability-catalog.md), and
[v0.3 release notes](docs/releases/v0.3.0a0.md). The tracked
[SPDX SBOM](release/fetech-0.3.0a0.spdx.json),
[dependency-license report](release/dependency-licenses.md), and
[competitor matrix](docs/competitor-matrix.md) are release evidence, not claims of certification or
market superiority.
