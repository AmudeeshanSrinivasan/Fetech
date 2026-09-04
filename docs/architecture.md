# Fetech architecture

Fetech is a Python-first, optionally polyglot content-acquisition runtime. Python 3.12 owns the public
interfaces and every security-sensitive effect. Clingo and SWI-Prolog are optional reasoning engines
behind typed protocols; neither is required for deterministic operation.

Implementation status: the alpha implements the Python runtime and deterministic planner, the Clingo
`PlannerBackend`, and the SWI-Prolog `ReasonerBackend`. Python is the default and fallback. The
Clingo executable may come from `fetech[logic]` or an explicitly configured path; SWI-Prolog remains
an explicitly installed system dependency.

The registry combines the immutable 13/155 manifest with a code-owned conformance overlay. The
overlay prevents a registered roadmap capability from being advertised as available. The current
reports are v0.1 at 56/56, v0.2 at 40/40, and v0.3 at 23/23 implementation paths, all with
`closure_ready=true`. The v0.4.0a0 candidate adds 36/36 document, media, cache, snapshot, and
archive paths, also with `closure_ready=true`, for 155 cumulative paths. v0.4 contains 17 native
paths and 19 typed optional paths. HTTP/3 uses an optional bounded
curl subprocess, reuses Python-validated DNS addresses, and refuses fallback to HTTP/2 or HTTP/1.1.
Browser reader mode and v0.2 browser rendering use offline Playwright subprocesses over acquired
HTML. Reader mode disables JavaScript; rendering enables JavaScript and bounded interactions while
aborting every subresource. Optional Puppeteer and Selenium service connectors use the same
already-fetched-HTML/offline contract.

The v0.3 release closes authentication/private sessions and structured APIs/feeds. Twenty-one paths
are native. `sso` and `private_workspace` are optional because they require an explicitly configured
operator connector, but their typed boundary, policy checks, failure semantics, and tests ship in the
Apache core.

The v0.4 implementation routes hostile document and archive bytes through ephemeral bounded workers,
uses bounded native or external-tool media parsers, and stores sanitized immutable snapshot metadata
over CAS artifacts. It includes built-in bounded yt-dlp and Wayback paths; other live media and
snapshot connectors are injected protocols whose results are revalidated. Missing optional
dependencies, tools, or providers are observable dependency failures; neither
registration nor cache presence is accepted as evidence. Package metadata identifies `0.4.0a0`,
but the candidate remains untagged and unpublished.

## Runtime flow

```text
SDK / CLI / REST / MCP
        |
        v
Python request normalization and security policy
        |
        v
Python deterministic classifier and baseline planner
        |
        +---- optional Clingo constraint planner
        |       input: bounded registered capability facts
        |       output: schema-valid plan proposal
        |
        +---- optional Prolog reasoner
        |       input: bounded sanitized policy/provenance facts
        |       output: explanations or rule solutions
        |
        v
Python registry, policy, dependency, and budget validation
        |
        v
Python execution DAG and bounded workers
        |
        v
Artifacts, quality checks, event ledger, cache, and graph projections
```

For a crawl, the HTTP root node enforces robots policy and the discovery node runs a deterministic
same-domain frontier. Page, depth, attempt, byte, redirect, deadline, concurrency, and per-host pacing
limits remain cumulative. Sitemap, internal/related/category/pagination links, safe URL candidates,
and optional search results feed the frontier; rejected cross-domain and over-depth candidates remain
observable. The result includes a typed `CrawlReport` and a CAS-backed `crawl_report` artifact.

`UniversalFetchGateway` owns one bounded `NetworkScheduler`. Primary HTTP and built-in Wayback hold
one shared slot across DNS/policy evaluation and the associated request for each hop; queue,
resolution, redirect, and transfer work consumes one cumulative deadline. Failed and partial HTTP
transfers retain observed byte usage. Host pacing history is bounded, eligible waiters are admitted
fairly, and cancellation releases capacity synchronously. The bounded yt-dlp subprocess consumes
one operation-level slot; because its internal networking spans several allowed hosts without parent
IPC, those internal requests are not represented as individual scheduler admissions.

For ordinary web retrieval, `candidate_url_expansion` owns the 13 non-schedulable URL generators.
It writes a sanitized `url_candidates` artifact and may try a safe alternative only when extracted
visible text is inadequate. Private, authenticated, or secret-bearing requests never fetch variants;
`https_to_http` is always recorded as blocked.

## Authentication boundary

Python resolves `FetchRequest.authentication_ref` through an injected asynchronous
`CredentialProvider`. The reference is an opaque lookup key, not credential material. The default
provider resolves nothing, so an authenticated request cannot silently fall back to anonymous
fetching. Library callers may inject an in-memory provider; daemon integrations can implement the
same protocol for an OS keychain or configured vault without changing fetch contracts.

`CredentialMaterial` is scoped to one canonical HTTPS origin: scheme, IDNA-normalized host, and
effective port must all match. Material is resolved only after destination policy succeeds. The HTTP
adapter builds authentication headers and cookies for each validated hop and never puts them on the
shared client. It clears the HTTPX cookie jar before every hop, withholds credentials after any
cross-origin redirect, and fetches `robots.txt` without them. A first-hop scope mismatch is a policy
block. Authenticated HTTP/3 currently returns `DEPENDENCY_MISSING` because the bounded curl path has
no secret-safe credential channel.

Known local expiry or explicit server expiry evidence produces `AUTH_REQUIRED` with an
`auth_expired` diagnostic and `attempt.auth_expired` provenance event. Other 401/403 responses remain
generic authentication-required failures. Public and authenticated cache keys use separate
partitions; authenticated partitions contain a domain-separated SHA-256 digest of the opaque
reference, never the reference or credential value. Clingo and Prolog receive none of this material
and cannot authorize or inject it.

High-level `login_session`, `oauth`, `sso`, and `private_workspace` nodes first apply destination and
privacy policy, then resolve a separate `OriginScopedSession` through `SessionProvider`. Python
validates the descriptor capability, opaque reference, exact origin, issuer/scopes, connector
identity, and credential type before HTTP. A descriptor-authorized refreshable provider may replace
an expired OAuth/SSO bearer token once, and only for GET or HEAD. The adapter queues sanitized
`auth.refresh.started`, `auth.refresh.succeeded`, or `auth.refresh.failed` events through the
executor-owned ledger boundary.

`csrf_token` runs over a bounded already-acquired HTML artifact and stores the extracted value only
in the execution context's sensitive in-memory state. `form_submit` resolves a bounded proposal from
an injected provider, which atomically consumes it for one run. Provider-supplied CSRF material must
exactly match the token and source lineage extracted in the current run. Python requires a
request-level capability approval and a live approval grant bound to the exact HTTPS action and
method immediately before I/O. POST/PUT/PATCH/DELETE bodies are never placed in plan parameters or
metadata. A 303, or a 301/302 following POST, becomes GET and drops the body; every body-preserving
redirect fails closed. For an anonymous approved login POST only, bounded Secure cookies may cross
same-origin GET redirects in request-local memory before being scrubbed.

## Structured API boundary

The API adapter performs no network I/O. It consumes the authoritative raw artifact created by a
successful HTTP attempt, then emits canonical JSON with a parent-artifact edge and the publisher URL
preserved as authority.

JSON parsing rejects duplicate keys, non-finite values, excessive nodes, and excessive depth. XML
parsing rejects DTD/entity declarations and bounds nodes and depth. RSS, Atom, sitemap, GraphQL, and
OpenAPI handlers require recognizable roots or envelopes. OpenAPI YAML uses the safe loader and
rejects aliases/anchors; external references are represented as data and never followed. Named API
connectors require an exact approved official origin/path plus a recognizable response schema. All
thirteen capabilities share HTTP security, authentication, redirects, budgets, and provenance
instead of creating independent transport stacks.

## Document, media, and archive worker boundaries

The document and archive adapters perform no acquisition. They read an already admitted raw artifact,
derive request-owned limits, and call `fetech.document_worker` or `fetech.archive_worker` through the
bounded subprocess runner. The request protocol contains bytes, a path suffix, canonical capability
ID, and numeric limits; it omits the host, query, credentials, opaque authentication reference, and
caller target path. An enabled Docling parse additionally receives one validated absolute
read-only model-artifact directory plus an independently configured expected bundle SHA-256. The
parent and child require the canonical manifest, rehash every bounded model file, and reject a
digest mismatch. The parent also recomputes format evidence and validates the returned parser
identity, exact artifact identity, schema, locator family, byte/block/member bounds, and complete
output before CAS admission. In development mode the child remains an ordinary bounded host
process. Linux required mode places it in the canonical `document_parser` profile before any input
is sent.
Before Docling imports, the document worker also installs a Python audit hook that
denies Python-level sockets, process creation, filesystem mutation, and reads outside reviewed
interpreter/package/model roots. The Pillow image decoder applies the same policy after loading
reviewed plugins. Audit hooks are bypassable by native code and are not an operating-system
sandbox.

PDF parsing prefers the exact locked
`docling-slim[convert-core,format-pdf,models-local]==2.113.0` path when an operator configures local
model artifacts. The v0.4 trust anchor is
`docling-project/docling-layout-heron@8f39ad3c0b4c58e9c2d2c84a38465abf757272d8`
with canonical bundle SHA-256
`e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76`.
Remote services, external plugins, implicit model downloads, OCR, enrichments, and image generation
are disabled. Python rejects non-success, timeout/error, sparse, or incomplete conversion results.
The smaller pypdf implementation remains a deterministic, observable fallback; release evidence
must still record a successful real installed contract/content smoke against the reviewed bundle.

Textless PDFs remain checked-only `NEEDS_OCR` unless an injected PDF OCR provider returns bounded,
page-located output that passes parent validation. Git LFS pointers similarly use an injected
resolver that receives a sanitized target and canonical origin; Python rejects wrong result types,
origin changes, size/hash mismatches, timeouts, and over-budget bodies. `github_raw` accepts only the
exact `raw.githubusercontent.com` HTTPS origin and a bounded repository path.

The media adapter uses bounded native parsers for structurally checked PNG/GIF/JPEG/TIFF/WebP
images, EXIF, byte/node/depth-limited podcast feeds, subtitles, and WAV data. Tesseract, FFprobe, and
FFmpeg paths use fixed argument vectors with input/output, CPU, and wall-time limits; Linux also
attempts an address-space ceiling.
Transcription remains an injected provider boundary. Live YouTube metadata uses the optional
`YTDLPMetadataWorker`: a bounded child process with a sanitized environment, fixed invocation,
disabled user configuration/plugins/cookies/downloads/external execution, exact HTTPS host and
public-DNS checks, identity-only responses, redirect/byte/process ceilings, and a strict
URL-redacted output schema. Python revalidates its fields and consumed budgets. Injected providers
receive no runtime credentials, but providers that process acquired bytes must be trusted for that
content. Linux required mode refuses the local yt-dlp path until an allowlisting egress broker is
available.

POSIX workers start through an isolated bootstrap with its own deadline. The bootstrap applies
irreversible CPU, core-dump, file-size, and file-descriptor limits and then replaces itself with the
fixed worker command; communication receives only the remaining total wall budget, and termination
targets the process group. That is the explicit development backend.

Linux required mode wraps the fixed target in a trusted profile: a delegated cgroup-v2 leaf,
explicit Bubblewrap namespaces, selective read-only mounts, bounded private tmpfs, dropped
capabilities, `no_new_privileges`, and an inner strict rlimit/libseccomp bootstrap. Offline document,
archive, image, browser, FFmpeg, FFprobe, and Tesseract profiles receive a new network namespace.
Cleanup uses `cgroup.kill`, not only a process-group signal. Native media processes do not inherit
the Python audit policy; the required Linux boundary is therefore authoritative for them.
Injected providers and Clingo/Prolog remain separate boundaries and require independent isolation
when enabled for hostile production input.

## Validated snapshot boundary

`SnapshotStore` writes immutable, bounded JSON records that refer to integrity-checked CAS artifacts.
Keys include normalized URL, representation, authentication scope, policy profile, language, region,
parser version, and relevant `Vary` values. Authenticated scope uses a domain-separated digest of the
opaque reference. Metadata contains neither that reference nor credentials.

Fresh, stale-while-revalidate, revalidation-required, and miss states are explicit. A verified 304
creates a new immutable record instead of mutating history. The built-in Internet Archive connector
uses exact `archive.org` and `web.archive.org` HTTPS origins, policy-validates and pins every
redirect hop, streams bounded identity-encoded responses, and binds capture metadata to the
requested original URL. Optional search-cache, web-archive, and CDN connectors must enforce the
same destination/redirect policy and stream limits. The core rejects third-party connector use for
private or authenticated requests and validates returned type, source authority, HTTPS locator,
body, and provider origin. Adapter snapshot URLs remain locators and never replace publisher
authority.

Previous-snapshot and configured archive alternatives are policy-gated before HTTP so they can
recover from an unavailable origin. Misses, failures, and checked-only quality fall through. Mixed
content/cache requests retain HTTP and extraction, then write only an accepted artifact of the
capability's exact representation. Connector body quality is assessed before admission; a
low-quality copy remains checked-only and is stored as unsuccessful.

Typed cache-only plans also include their producer dependency: `clean_text` for the RAG-document
cache, `rendered_html` for the browser cache, and a configured `search_results` connector for the
two search caches. If an optional producer is not configured, execution reports a dependency
failure instead of relabeling raw HTTP.

Attempt consumption is accumulated across nodes. Document/media normalized output consumes the
decompressed-byte budget, connectors consume remaining wire and decompressed bytes, and archive
extraction consumes expanded bytes and member counts. A later node cannot reuse a predecessor's
spent allowance.

## Language responsibilities

### Python

Python is required and authoritative. It owns:

- versioned Pydantic contracts and capability registry validation;
- URL normalization, DNS pinning, redirect checks, authorization, approvals, and budgets;
- per-hop redirect policy, redirect-loop detection, and separate wire/decompressed transfer budgets;
- cumulative attempt/deadline accounting, per-host pacing, and bounded robots enforcement for crawls;
- deterministic classification and the safe baseline planner;
- HTTP, browser, API, document, media, archive, cache, and storage adapters;
- bounded same-domain discovery, sitemap parsing, URL alternatives, and crawl reports;
- artifact normalization, quality assessment, provenance events, and result statuses;
- SDK, CLI, REST, SSE, MCP, SQLite metadata, and filesystem CAS interfaces, with Postgres/S3
  retained as storage-protocol extension points;
- validation of every Clingo answer set and Prolog solution.

`FetchResult.capability_outcomes` records both scheduled operations and capabilities negotiated
inside another stage. This keeps HTTP protocol negotiation, redirect types, page-state detectors,
policies, and validation observable without turning each one into a no-op plan node.

### Clingo

Clingo is an optional planning backend for finite constraint problems. Appropriate uses include:

- selecting registered capabilities that satisfy requested representations;
- enforcing dependency, availability, risk, approval, and isolation constraints;
- reserving attempt, byte, browser-time, and monetary budgets;
- choosing fallback order and parallel groups;
- minimizing expected cost, risk, or latency after feasibility is established.

The Clingo program receives generated facts only. It may not read the manifest, filesystem, network,
credentials, or response bodies directly. An answer set is converted into a `FetchPlan` proposal and
must pass the same Python validation as a hand-built plan. Zero, multiple, malformed, unknown, or
timed-out answers use the pure-Python fallback or return a typed failure according to caller policy.

### SWI-Prolog

SWI-Prolog is an optional rule and explanation backend. Appropriate uses include:

- explaining why a capability is eligible, denied, or selected;
- evaluating declarative relationships that do not perform external effects;
- querying artifact lineage and provenance relationships;
- detecting contradictions among bounded policy or evidence facts;
- deriving human-readable decision paths from sanitized facts.

Prolog cannot authorize a request, inject credentials, execute an adapter, or accept evidence. Python
converts bounded solutions to typed explanations and independently applies all enforcement checks.

## Backend protocols

The Python control plane exposes separate protocols rather than coupling execution to a particular
logic process:

```python
class PlannerBackend(Protocol):
    async def propose(self, request: FetchRequest, registry: RegistryView) -> FetchPlanProposal: ...

class ReasonerBackend(Protocol):
    async def explain(self, query: ReasoningQuery) -> ReasoningResult: ...
```

The built-in Python planner and Clingo adapter implement the same `PlannerBackend` proposal boundary.
Required core explanations remain ordinary typed Python diagnostics; the Prolog adapter provides
richer bounded derivations when `swipl` is installed. Backend selection is explicit in configuration
and recorded in provenance.

## Failure and fallback semantics

| Condition | Required behavior |
| --- | --- |
| Clingo or Prolog is not installed | Continue with Python-only operation |
| Backend exceeds CPU, output, solution, or wall-time limit | Cancel its process group and use safe fallback or typed failure |
| Backend exceeds Linux address-space limit | Terminate it and use safe fallback or typed failure |
| Output references an unknown capability | Reject the complete proposal |
| Output violates allow/deny policy or budget | Reject; logic cannot override Python |
| Clingo returns no feasible plan | Use baseline plan when safe, otherwise return a typed diagnostic |
| Prolog returns no solution | Return an empty/unknown explanation, never an allow decision |
| Multiple solutions are returned | Apply deterministic Python ordering and configured solution limit |

## Evidence and provenance

The append-only event ledger and immutable artifacts remain authoritative. Logic inputs and outputs
are derivative records. Provenance events identify the backend, executable/ruleset version, manifest
or schema hash, sanitized input hash, result hash, elapsed time, and fallback reason. Repository
Graphify and runtime Graphify projections remain separate and rebuildable.

## Packaging

The Apache-2.0 Python core installs and runs independently. Clingo and document/media libraries are
optional extras; SWI-Prolog, Tesseract, and FFmpeg/FFprobe are external executables discovered
explicitly. Configured PDF OCR, snapshot, transcript, Git LFS, and browser services remain separate
providers/connectors except for the built-in Wayback connector. The media extra supplies yt-dlp for
the built-in metadata worker; it does not download media or invoke external downloaders. Dependency
licenses and bundled artifacts must be included in the dependency-license report and SPDX SBOM or
external-tool inventory as applicable. Fetech does not silently download a solver, media binary,
model, or connector or change planner backends during a fetch.

The common development process runner is resource-bounded but is not an operating-system sandbox.
macOS supports only that backend. The Linux daemon's explicit required mode adds the built-in
document/archive/image/offline-browser/native-media containment profiles described in
[the deployment guide](deployment-containment.md). Logic engines and injected providers are not
silently covered by those profiles and must be isolated separately or disabled.

The focused source-tree and development-wheel Docling contract/content subsets pass against the
immutable local reference bundle, including wheel `RECORD` and digest binding. Publishing v0.4
additionally requires the complete installed Docling 2.113 gate from the clean release-commit wheel,
passing Linux containment evidence from the release commit and target systemd verification, and
either brokered allowlisted egress for yt-dlp or an explicitly development-only local yt-dlp
release claim.
Publication also
requires exact-version live smoke evidence for optional dependencies, tools, and connectors; dated
endpoint/service evidence for Wayback; artifact-level notice and redistribution legal review for
the explicit NVIDIA proprietary/EULA and pypdfium2 mixed-distribution LicenseRefs; and verified
release-specific SBOM, dependency-license, wheel, source-distribution, checksum, tag, and package
artifacts. The exact-version catalog now covers all 167 third-party identities in the current
universal lock and regenerates the v0.4.0a0 candidate reports; those candidate artifacts do not
by themselves satisfy the remaining publication steps. The published v0.3 evidence is immutable historical
evidence and is checked against its separate release profile instead of being regenerated from the
current lock.

See [ADR 0001](adr/0001-polyglot-logic-backends.md), the [security policy](../SECURITY.md), and the
[implementation threat model](security-threat-model.md). The historical
[v0.3 SPDX SBOM](../release/fetech-0.3.0a0.spdx.json) and
[dependency-license report](../release/dependency-licenses.md) are verified against
`scripts/release_published.toml`. New candidate and release evidence is generated from its
declared lock and overlay inputs. The [competitor matrix](competitor-matrix.md) records
source-bounded positioning without a superiority claim. See also the
[capability catalogue](capability-catalog.md).
