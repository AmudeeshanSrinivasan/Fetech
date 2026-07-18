# Fetech

Fetech is an Apache-2.0, policy-aware content-acquisition runtime. It registers 155 capabilities
across 13 categories and selects only the capabilities needed for a request.

The current release-candidate branch implements the canonical registry and contracts, deterministic
planning, SSRF-safe HTTP acquisition, bounded crawling, URL alternatives, bounded browser,
document, media, and archive subprocesses, typed artifacts, a SQLite event ledger,
content-addressed storage, validated snapshots, quality validation, runtime provenance projection,
Python SDK, CLI, REST, MCP, a bounded Graphify/QMD context broker, origin-scoped authentication
sessions, approved form submission, and bounded structured API/feed normalization.

The published `v0.3.0a0` prerelease closes 119 paths. The unreleased `v0.4.0a0` candidate adds the final 36
document, media, cache, snapshot, and archive paths, giving 155/155 implementation paths: 17 v0.4
paths are native and 19 use typed optional dependencies or configured providers. Optional means an
implementation boundary ships but its binary or service may be absent; absence returns
`DEPENDENCY_MISSING`. HTTP/3 similarly uses bounded `curl --http3-only`.
`GET /v1/capabilities` and `fetech capabilities` expose implementation-path and guaranteed-runtime
counts separately; Fetech never infers successful local execution merely from manifest
registration.

> **Release status:** `0.4.0a0` is an unreleased candidate. Package and lock metadata now identify
> `0.4.0a0`, but no v0.4 tag, GitHub Release, or package publication exists. The preferred offline
> Docling path, shared network admission, and an independent
> POSIX startup deadline are implemented. Fail-closed Linux per-worker profiles are implemented;
> passing release-commit Linux enforcement evidence and target systemd verification, a clean
> release-commit wheel rerun of the successful source-tree and development-wheel Docling smokes,
> request-level coordination inside
> yt-dlp's multi-host
> subprocess traffic, exact-version live evidence for optional tools and services, artifact-level
> notice and redistribution legal review for LicenseRef-tagged NVIDIA and pypdfium2 distributions,
> verified wheel/source distributions and checksums, a tag, and package publication remain release
> gates. Candidate evidence and notes are not published-release artifacts.

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

Install the v0.4 file and media engines explicitly, or use `--all-extras` for conformance work:

```bash
uv sync --extra documents --extra media
uv run fetech fetch https://example.com/report.pdf --output pdf
uv run fetech fetch https://example.com/photo.jpg --output image_metadata --output exif_metadata
uv run fetech fetch https://example.com/article --output local_snapshot
```

PDF/Office engines come from `fetech[documents]`. PDF parsing prefers the exact locked Docling Slim
path only when `FETECH_DOCLING_ARTIFACTS_PATH` names an existing, explicitly provisioned local model
directory and an independent expected digest matches its canonical manifest. When the path is set
through the environment and `FETECH_DOCLING_ARTIFACTS_SHA256` is omitted, Fetech uses only the
compiled v0.4 reference digest shown below; any different bundle therefore requires an explicit
digest. The documents extra
uses `docling-slim[convert-core,format-pdf,models-local]==2.113.0`; `convert-core` is required for the
local `DocumentConverter` path. Docling remote services, external plugins, OCR, enrichments, and
implicit model downloads remain disabled. Its separate worker ceiling defaults to 4096 MiB and can
be bounded from 1024–8192 MiB with `FETECH_DOCLING_WORKER_MEMORY_MB`; ordinary document workers
retain the smaller default. The smaller pypdf path remains the deterministic fallback. Tesseract and
FFmpeg/FFprobe are separately installed executables; the media extra does not redistribute them.
Live transcription, Git LFS resolution, PDF OCR fallback, and remote snapshot/archive services
other than the built-in Wayback path require explicitly injected providers. Git LFS results are
restricted to the requested canonical origin and rechecked against the pointer size and SHA-256. A
configured PDF OCR provider must return bounded, page-located output; without one, a textless PDF
remains checked-only `NEEDS_OCR`.

### Offline Docling reference bundle

The v0.4 reference configuration is deliberately narrow:

| Field | Reviewed reference |
| --- | --- |
| Model repository | `docling-project/docling-layout-heron` |
| Hugging Face revision | `8f39ad3c0b4c58e9c2d2c84a38465abf757272d8` |
| Canonical bundle SHA-256 | `e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76` |
| Published model-card license identifier | `apache-2.0` |

Provision it once from the exact revision. The command refuses an existing output directory,
verifies the downloaded canonical manifest against the independent expected digest, removes write
bits, and revalidates the published tree:

```bash
uv sync --extra documents
uv run python scripts/provision_docling_artifacts.py \
  --output-dir runtime-data/docling-models/2.113.0 \
  --cache-dir runtime-data/docling-download-cache \
  --revision 8f39ad3c0b4c58e9c2d2c84a38465abf757272d8 \
  --expected-sha256 e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76
```

Both project-local directories live under ignored `runtime-data/`; model binaries and download
caches are not committed or included in the Fetech wheel. Recheck every manifest entry and file
without network access:

```bash
uv run python scripts/provision_docling_artifacts.py \
  --verify-only \
  --output-dir runtime-data/docling-models/2.113.0 \
  --expected-sha256 e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76
```

Configure the runtime explicitly with both halves of the trust anchor:

```bash
export FETECH_DOCLING_ARTIFACTS_PATH="$PWD/runtime-data/docling-models/2.113.0"
export FETECH_DOCLING_ARTIFACTS_SHA256="e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76"
```

For the exact reference bundle only, the environment loader uses that compiled digest when the
SHA-256 variable is absent. It never accepts a digest declared only by the model directory itself.
Direct SDK construction with a custom artifact path must supply the matching expected digest.

The focused artifact-bound gate is:

```bash
uv run python scripts/collect_v04_smoke_evidence.py \
  --source-tree \
  --docling-artifacts-path runtime-data/docling-models/2.113.0 \
  --docling-artifacts-sha256 e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76 \
  --require-docling \
  --output release/fetech-v0.4-docling-development-smoke.json
```

The focused source-tree Docling subset and a separately unpacked development-wheel Docling subset
passed on 2026-07-18 with
Docling Slim 2.113.0, all four pinned parser components, the six-file 171,764,371-byte bundle, and
the expected bundle digest. The wheel gate also verified every installed Fetech package member
against the wheel `RECORD` and bound the evidence to the exact wheel SHA-256 recorded in the
sanitized result. Results are retained in `release/fetech-v0.4-docling-development-smoke.json` and
`release/fetech-v0.4-docling-wheel-smoke.json`. Because that wheel is still versioned `0.3.0a0` and
was built from the unreleased development tree, the clean release-commit v0.4.0a0 wheel must rerun the
same gate in the release environment. Those JSON files are focused development evidence, not
complete v0.4 smoke passes; their browser, Tesseract, source-cleanliness, and live-service statuses
remain recorded independently. The Python worker audit hook is defense in depth around
reviewed imports and file access, not a native-code or operating-system sandbox. Hostile-input
production parsing requires Linux `required` containment and a root-owned read-only model tree as
described in the [deployment guide](docs/deployment-containment.md). The captured Apache-2.0
model-card identifier is provenance evidence, not legal approval; a human must review the exact
model files, notices, and redistribution terms before publishing a bundle or image.

PNG, GIF, JPEG, TIFF, and WebP inputs receive bounded structural validation. Podcast RSS parsing
limits input bytes, XML nodes, depth, and episodes, and never follows enclosure URLs. Provider
return types and output bounds are revalidated, while unexpected provider exception text is not
copied into public diagnostics.

The media extra supplies the optional `yt-dlp` dependency used by the built-in YouTube metadata
worker. That worker receives a canonical public YouTube locator only, disables user configuration,
cookies, plugins, downloads, external commands, JavaScript runtimes, and remote components, and
permits only HTTPS identity-encoded responses from reviewed YouTube/Google host families after
public-address DNS validation. It bounds redirects, response bytes, process output, file size, CPU,
and wall time, and attempts a best-effort address-space ceiling on Linux, then returns a strict
URL-redacted metadata projection for Python validation.
Internet Archive snapshots use the built-in bounded Wayback connector only when that explicit
capability is requested; it validates DNS and every redirect, requires exact archive origins,
streams within the remaining budget, and preserves the original publisher as authority. Other
remote archive/cache paths require configured connectors.

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

Puppeteer and Selenium are optional offline connector paths. Configure
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

The v0.4 document and archive adapters send hostile bytes to ephemeral bounded child processes and
independently validate the returned capability, parser, schema, locators, and budgets before CAS
admission. Media extraction uses bounded native parsers, fixed-argument Tesseract/FFmpeg/FFprobe
workers, or the bounded built-in yt-dlp metadata worker. Snapshot metadata is immutable and
authentication-partitioned; third-party archive/cache connectors are blocked for authenticated
requests and never replace publisher authority. Cache/archive alternatives can run after policy and
before HTTP; checked-only alternatives fall through, while post-acquisition cache strategies accept
only the exact validated representation. Wire, decompressed-byte, archive-member, and deadline
consumption is accounted cumulatively. See
[the v0.4 conformance guide](docs/v0.4-conformance.md).

The common development subprocess runner bounds input/output, CPU, file size/file descriptors, and total wall
time; on POSIX an isolated bootstrap applies limits and must complete within its own startup
deadline before the worker receives only the remaining wall budget. Linux also attempts an
address-space limit. Required Linux mode adds cgroup-v2, namespace, selective read-only mount,
bounded tmpfs, capability, seccomp, and default-deny networking profiles for the built-in document,
archive, image, offline browser, FFmpeg, FFprobe, and Tesseract workers. Logic engines, optional
curl, and injected providers are not covered and must be isolated separately or disabled. Primary
HTTP and built-in Wayback requests use the shared global/per-host scheduler. Local yt-dlp remains
development-only until an allowlisting egress broker mediates its internal multi-host requests.

## Verification

```bash
uv run pytest
uv run ruff check .
uv run mypy src/fetech
uv run python scripts/generate_release_evidence.py --check-published
uv run python scripts/generate_release_evidence.py \
  --overlay-profile scripts/release_v04_candidate.toml --check
uv build
git diff --check
```

See [the architecture](docs/architecture.md), [security policy](SECURITY.md),
[threat model](docs/security-threat-model.md),
[capability catalogue](docs/capability-catalog.md), and
[v0.4 conformance guide](docs/v0.4-conformance.md). The tracked v0.3
[SPDX SBOM](release/fetech-0.3.0a0.spdx.json),
[dependency-license report](release/dependency-licenses.md), and
[competitor matrix](docs/competitor-matrix.md) are release evidence, not claims of certification or
market superiority. The published v0.3 evidence is immutable and is hash- and metadata-verified from
`scripts/release_published.toml`; it is not regenerated from the v0.4 candidate lock. The
separately tracked
[v0.4.0a0 candidate SBOM](release/fetech-0.4.0a0-candidate.spdx.json) and
[candidate dependency-license report](release/dependency-licenses-0.4.0a0-candidate.md) are
explicitly unreleased evidence for package version `0.4.0a0`.
