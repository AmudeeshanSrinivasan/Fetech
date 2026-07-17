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
`closure_ready=true`, for 119 cumulative paths. HTTP/3 uses an optional bounded
curl subprocess, reuses Python-validated DNS addresses, and refuses fallback to HTTP/2 or HTTP/1.1.
Browser reader mode and v0.2 browser rendering use offline Playwright subprocesses over acquired
HTML. Reader mode disables JavaScript; rendering enables JavaScript and bounded interactions while
aborting every subresource. Optional Puppeteer and Selenium service connectors use the same
already-fetched-HTML/offline contract.

The v0.3 release closes authentication/private sessions and structured APIs/feeds. Twenty-one paths
are native. `sso` and `private_workspace` are optional because they require an explicitly configured
operator connector, but their typed boundary, policy checks, failure semantics, and tests ship in the
Apache core.

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
Python execution DAG and isolated workers
        |
        v
Artifacts, quality checks, event ledger, cache, and graph projections
```

For a crawl, the HTTP root node enforces robots policy and the discovery node runs a deterministic
same-domain frontier. Page, depth, attempt, byte, redirect, deadline, concurrency, and per-host pacing
limits remain cumulative. Sitemap, internal/related/category/pagination links, safe URL candidates,
and optional search results feed the frontier; rejected cross-domain and over-depth candidates remain
observable. The result includes a typed `CrawlReport` and a CAS-backed `crawl_report` artifact.

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

The Apache-2.0 Python core installs and runs independently. Clingo is an optional extra or external
executable; SWI-Prolog is an external executable discovered explicitly at startup. Their licenses and
bundled artifacts must be included in the dependency-license report and SPDX SBOM. Fetech does not
silently download a solver or change planner backends during a fetch.

The local logic runner is resource-bounded but is not an operating-system sandbox. Linux applies an
address-space limit in addition to CPU, output, and wall-time limits; macOS currently lacks the
address-space limit. A production daemon must place logic engines in an isolated worker or container
that denies network and unrestricted filesystem/process access.

See [ADR 0001](adr/0001-polyglot-logic-backends.md), the [security policy](../SECURITY.md), and the
[implementation threat model](security-threat-model.md). Release evidence is reproducibly generated
from the universal lock into the [SPDX SBOM](../release/fetech-0.3.0a0.spdx.json) and
[dependency-license report](../release/dependency-licenses.md); the
[competitor matrix](competitor-matrix.md) records source-bounded positioning without a superiority
claim. See also the [capability catalogue](capability-catalog.md).
