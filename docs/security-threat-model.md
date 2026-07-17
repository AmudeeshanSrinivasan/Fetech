# Fetech security threat model

Status: v0.3 implementation snapshot

Last reviewed: 2026-07-17

Reference platform: Linux daemon; macOS local development and library use

This document describes the security posture of the Fetech v0.3 runtime. It is
an implementation-grounded threat model, not a certification or a claim that
the process is a complete sandbox. The normative runtime invariants remain in
[`SECURITY.md`](../SECURITY.md).

v0.3 is a single-tenant, local/self-hosted alpha. Python is authoritative for
security, authorization, budgets, storage, and execution. Clingo and SWI-Prolog
may propose plans or explanations, but their output is untrusted and cannot
override Python policy checks.

## Scope

This model covers:

- the Python SDK, CLI, REST daemon, SSE endpoints, and MCP server;
- target normalization, DNS and redirect validation, HTTP transport, browser
  rendering, authenticated sessions, structured APIs, document parsing, and
  archive extraction;
- optional Clingo and SWI-Prolog subprocesses;
- SQLite event/metadata storage, the filesystem content-addressed store (CAS),
  caches, and runtime Graphify projections;
- operator-provided authentication/session providers and optional remote
  acquisition connectors; and
- repository and vault excerpts returned by the bounded context broker.

It describes the 119-capability v0.3 closure state. It does not assume the
document, OCR, media, and archive isolation planned for v0.4 already exists.

## Security objectives

Fetech is designed to:

1. prevent fetched targets and redirects from reaching prohibited network
   destinations;
2. keep credentials origin-scoped and absent from plans, logs, graphs, and
   ordinary diagnostics;
3. require explicit, bounded authorization for state-changing requests;
4. constrain time, attempts, bytes, redirects, crawl breadth, and subprocess
   output;
5. preserve original-source authority and complete artifact lineage;
6. detect low-quality or adversarial page states without bypassing access
   controls; and
7. keep fetching functional when optional models or logic engines are absent or
   rejected.

Fetech does not claim to protect against a user or process with root access to
the host, a compromised operating-system kernel, physical access to an
unencrypted host, or a malicious operator controlling the runtime and its data
directory.

## Assets

| Asset | Required property | Examples |
|---|---|---|
| Credentials and session material | Confidentiality, exact-origin use, short lifetime | Bearer tokens, API keys, cookies, refresh handles, opaque auth references |
| Authorization decisions | Integrity, auditability, bounded replay | Form-submission approvals, method and target grants, policy decisions |
| Authenticated content | Confidentiality, integrity, scope separation | Private HTML, API responses, downloaded documents, screenshots |
| Public content and derived artifacts | Integrity, provenance, bounded storage | Raw bodies, normalized text, structured API data, extracted files |
| Request metadata | Confidentiality where sensitive, integrity | Targets, query values, intent, language, policy profile |
| Runtime state | Integrity, availability | Plans, budgets, attempts, cache entries, run status |
| Evidence and provenance | Integrity, traceability | Ledger events, source locators, hashes, accepted/checked-only status |
| Policy and capability configuration | Integrity | Registry, allow/deny lists, Clingo rules, Prolog rules, connector settings |
| Host resources | Availability, containment | CPU, memory, disk, file descriptors, processes, network capacity |
| Repository and memory context | Confidentiality, bounded disclosure | Source excerpts, Graphify results, QMD note excerpts |

## Architecture and trust boundaries

```text
Trusted caller
    |
    |  SDK / CLI / REST / MCP boundary
    v
Python gateway and policy authority
    |            |              |
    |            |              +--> SQLite ledger / cache / filesystem CAS
    |            |
    |            +--> bounded local subprocesses
    |                 (browser, Clingo, Prolog, optional curl HTTP/3)
    |
    +--> DNS and public network --> publisher or authenticated origin
    |
    +--> operator-configured provider or optional remote connector

Context caller --> context broker --> Graphify / repository / QMD vault excerpts
```

The important boundaries are:

| Boundary | Data crossing it | Trust decision |
|---|---|---|
| Caller to interface | Request, auth reference, policy, budgets | The v0.3 daemon and MCP server assume a trusted single-tenant caller |
| Gateway to network | Sanitized request plus per-hop credentials when authorized | Every destination and redirect is independently policy-checked |
| Gateway to session provider | Opaque reference and typed session request | Provider is operator-trusted; returned descriptors are schema- and origin-validated |
| Gateway to local worker | Bounded HTML, facts, rules, or command arguments | Worker output is untrusted and must satisfy typed Python validation |
| Gateway to remote connector | Public, unauthenticated acquisition input | Connector is operator-trusted and disabled unless explicitly enabled |
| Runtime to persistence | Events, metadata, raw and derived content | Metadata is sanitized; artifact bytes are not redacted |
| Context broker to repository/vault | Bounded search and excerpts | Caller is trusted to receive selected project context |

## Adversaries

The model considers:

- a malicious public site controlling DNS answers, redirects, headers, markup,
  scripts, compressed bodies, documents, archives, and response timing;
- a compromised authenticated origin attempting credential capture, cross-origin
  redirection, CSRF manipulation, or approval replay;
- an attacker able to submit requests to an exposed REST or MCP endpoint;
- a malicious or compromised parser, browser, logic engine, executable, Python
  dependency, authentication provider, or remote connector;
- a local unprivileged process attempting to read the daemon data directory;
- an operator who accidentally enables unsafe network exposure, broad egress,
  insecure filesystem permissions, or an untrusted extension; and
- a resource-exhaustion attacker targeting CPU, memory, process count, disk, or
  network budgets.

Fetched text and instructions are always untrusted data. They are not authority
for tool use, policy changes, authentication, or subsequent agent actions.

## Authenticated data handling

Metadata secrecy and content secrecy are different guarantees.

Fetech removes credentials, sensitive headers, cookies, form request bodies,
opaque refresh material, and authenticated query values from serialized plans,
ledger events, runtime graphs, and normal diagnostics. The private execution
request retains the real target only for the in-process execution path.

The HTTP adapter stores the response body verbatim as a `raw` CAS artifact,
including an authenticated response. Derived artifacts can also contain private
content. For example, a fetched authenticated HTML page may be stored raw and
then yield clean text, rendered HTML, a screenshot, or structured data.

An approved form request body is not persisted as an artifact. A derived CSRF
token is not separately persisted. However, the original HTML response from
which a CSRF value was derived is a raw response artifact and may naturally
contain that value. The response to the form submission is also stored as raw
content.

The filesystem CAS is immutable and SHA-256 content-addressed, but v0.3 does
not provide:

- encryption at rest;
- per-artifact access-control lists;
- a retention, expiry, or secure-deletion policy;
- separate physical stores for public and authenticated bytes; or
- a total data-directory storage quota.

Cache keys separate public and authenticated scopes using a domain-separated
digest of the opaque authentication reference. The CAS itself deduplicates
identical bytes globally, so identical public and private content can share one
physical blob. Operators must therefore treat the complete CAS and all derived
artifacts as potentially confidential.

`GET /v1/artifacts/{artifact_id}` can return bounded artifact content. The v0.3
endpoint has no built-in user authentication or per-artifact authorization.
Artifact UUIDs are not access-control tokens.

## STRIDE analysis

Severity is the expected impact in the documented single-tenant deployment. An
internet-exposed daemon without an authenticating reverse proxy raises several
items to critical.

### Spoofing

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| S-1 | DNS rebinding or redirect-based origin spoofing | Normalize and resolve every hop; reject loopback, private, link-local, reserved, multicast, unspecified, metadata, and disallowed ports; never downgrade HTTPS; pin validated addresses while retaining TLS hostname verification | DNS and CA compromise remain outside the application boundary; a trusted custom transport can weaken connect-time pinning |
| S-2 | A provider returns credentials for a different site | Session descriptors carry capability, opaque reference, issuer, scopes, connector, and exact HTTPS origin; Python validates them before use | A malicious operator-configured provider can still disclose its own secrets or lie about external state |
| S-3 | A caller impersonates another daemon user | None inside the v0.3 daemon or MCP server | High if more than one mutually untrusted caller can reach either interface |

### Tampering

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| T-1 | Clingo, Prolog, or a model proposes an unsafe plan | Accept only registered capability IDs and typed schema-valid output; reapply Python policy and budget checks; deterministic Python fallback remains available | Compromise of the Python policy authority or registry is out of scope |
| T-2 | A body or artifact is changed after acquisition | SHA-256 content addressing, immutable CAS writes, artifact lineage, and parser/version metadata | A local attacker able to modify the database, CAS, or executable can corrupt state or replace both content and metadata; v0.3 has no signed ledger |
| T-3 | An attacker modifies a form submission or replays approval | Capability approval plus exact target/method grant; GET form proposals rejected; one-shot form provider; body-preserving redirects blocked | The runtime does not provide business-level transaction confirmation or remote-origin idempotency |
| T-4 | A malicious structured payload changes parser meaning | Bounded parsers reject duplicate JSON keys, non-finite numbers, XML DTD/entities, unsafe YAML anchors, and external references | Parser implementation bugs and format confusion remain possible |

### Repudiation

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| R-1 | A caller denies initiating an authenticated fetch or submission | Append-only logical event history records run, capability, policy, attempts, actor/adapter, and sanitized outcomes | Events identify runtime actors, not cryptographically authenticated human identities; local DB owners can alter SQLite |
| R-2 | A provider denies issuing a session or refresh | Sanitized lifecycle events and descriptor metadata are recorded without secrets | No cross-system signed receipt exists |

### Information disclosure

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| I-1 | Credentials leak through logs, plans, graphs, redirects, or cache keys | Opaque references; recursive event sanitization; authenticated query redaction; exact-origin credential injection; anonymous robots checks; cross-origin withholding; no durable shared cookie jar | New extension code or operator logging can bypass conventions; secrets present inside response content remain in artifacts |
| I-2 | Authenticated raw or derived artifacts are read by another caller or local process | Single-tenant assumption; bounded artifact reads; authenticated cache-key separation; normal temporary-file creation uses restrictive defaults | CAS is unencrypted, globally deduplicated, has no ACL/retention layer, and daemon artifact reads have no built-in authorization |
| I-3 | Cookies escape during redirects or browser handoff | Per-hop origin checks; ephemeral, same-origin, `Secure` cookie handoff; handoff state is scrubbed; body-preserving redirects are blocked | A compromised authorized origin can receive the credentials legitimately scoped to it |
| I-4 | A remote reader, search service, or browser connector receives sensitive data | Disabled by default; explicitly allowed public and unauthenticated targets only; endpoint must be HTTPS and policy-approved; browser connector receives acquired HTML under an offline contract | The remote processor sees submitted public content and may retain it according to its own policy |
| I-5 | Context search exposes repository or vault content | Default 4,000-token bundle, 8,000-token hard ceiling, top-result limits, no full-vault load | The context API has no multi-user ACL and can disclose selected source or note excerpts to any trusted interface caller |
| I-6 | Content hashes reveal that a known private body exists | Artifact UUID boundary and no direct hash-search interface in ordinary fetch contracts | A caller with storage or metadata access can perform confirmation attacks against predictable content |

### Denial of service

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| D-1 | Infinite redirects, oversized bodies, decompression bombs, or crawl explosion | Deadlines, attempts, redirects, wire bytes, decompressed bytes, pages, depth, archive members/ratio, per-host concurrency, and early stopping | Aggregate disk growth across runs and hostile parser allocation before checks can exhaust the host |
| D-2 | A subprocess hangs or floods output | Wall timeout, CPU limit, bounded stdout/stderr, new process group, and group termination | Process controls are not a complete sandbox; macOS has no address-space cap and fork/process-tree races remain platform concerns |
| D-3 | Concurrent requests starve the daemon | Global/per-host controls and request budgets | v0.3 has no tenant quotas, admission-control identity, or durable distributed scheduler |
| D-4 | Ledger or CAS fills the disk | Per-artifact and request byte budgets | No total retention or storage quota is implemented |

### Elevation of privilege

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| E-1 | SSRF reaches local services or cloud metadata | Scheme, port, address-class, redirect, and DNS checks; pinned transport; browser subrequests aborted; `file://` rejected | An unsafe custom transport, proxy, resolver, or connector can invalidate network assumptions |
| E-2 | Page script, parser input, archive, or solver escapes its worker | Browser works from already-acquired HTML, starts offline, blocks service workers, and aborts page routes; subprocesses have time/output/CPU bounds; archive paths, links, devices, nesting, members, size, and ratio are checked | Browser/solver subprocesses lack syscall, namespace, filesystem, and complete network isolation; document and archive parsing run in-process in v0.3 |
| E-3 | Fetched instructions authorize new actions | Content is marked untrusted; models and logic engines cannot determine security or authorization; mutating methods require explicit approval | A downstream agent that ignores the untrusted-content marker can still be prompt-injected |
| E-4 | An unauthenticated network client controls fetching or reads traces/artifacts | Default daemon bind is loopback; deployment is documented as single tenant | No built-in daemon/MCP authentication, authorization, or tenant isolation exists |

## Network and credential invariants

- Only HTTP and HTTPS URL targets are accepted. Credentials embedded in URLs
  and `file://` targets are blocked.
- HTTPS is never downgraded. An explicitly supplied public HTTP URL can be
  fetched only when policy permits it; the default policy currently permits
  public HTTP.
- Every redirect is normalized, re-resolved, and independently checked.
- The standard pinned transport connects to an approved IP address while
  preserving TLS hostname verification and disables ambient proxy environment
  use.
- A custom transport is an operator-trusted extension point. It must preserve
  destination validation and pinning semantics.
- Credentials are injected only for the exact authorized HTTPS origin and are
  reconsidered on every hop. Cross-origin redirects do not receive them.
- Robots retrieval is anonymous. `robots.txt` is policy input, never proof of
  authorization.
- OAuth and SSO flows are bearer-only in v0.3. Refresh requires an authorized
  descriptor and produces sanitized events.
- HTTP/3 is optional, HTTPS-only, IP-pinned, process-bounded, and fails closed
  for authenticated requests.

Public HTTP has no transport confidentiality or server authentication.
Network-path attackers can read and alter its content. Operators handling
security-sensitive material should disable public HTTP.

## Worker isolation by platform

The common bounded process runner is used for local Clingo, SWI-Prolog,
Playwright browser work, and optional curl HTTP/3 execution.

| Control | Linux | macOS |
|---|---|---|
| Separate process session/group | Yes | Yes |
| Wall-clock timeout | Yes | Yes |
| Bounded stdout/stderr | Yes | Yes |
| Process-group termination | Yes | Yes |
| CPU resource limit | Yes | Yes |
| Address-space resource limit | Attempted | Not applied because the pre-exec child rejects it on macOS |
| Syscall filtering | No | No |
| User/mount/network namespace | No | No |
| General filesystem denial | No | No |
| General worker-process network denial | No | No |

Playwright adds application-level containment: it receives already-fetched
HTML, starts its context offline, blocks service workers, aborts every page
route, and applies bounded readiness and interaction rules. Reader mode disables
JavaScript; render mode permits JavaScript. These controls restrict page
behavior but do not create an operating-system sandbox for the browser process.
Linux `RLIMIT_AS` is a per-process virtual-address ceiling, not an aggregate
resident-memory limit for Chromium's process tree. Production browser workers
therefore still require a container or service-level memory limit. The local
ceiling allows V8's
[one-terabyte sandbox and guard regions](https://chromium.googlesource.com/v8/v8/+/refs/heads/main/include/v8-internal.h#188)
to initialize; it does not permit that amount of resident memory.

Linux is the reference daemon platform, but a production operator must still
add container or service-level isolation, a dedicated unprivileged account,
filesystem restrictions, and egress controls. macOS remains supported for local
development and library use; without an address-space cap or a complete OS
sandbox, it must not be represented as a hardened environment for hostile
browser or parser workloads.

Document parsers and archive handling currently execute inside the
daemon/library process. Their format and expansion limits reduce risk but do not
contain a parser exploit. This is a major v0.3 residual risk.

## Operational assumptions and deployment requirements

A secure v0.3 deployment assumes:

1. one trusted tenant and one administrative domain per daemon;
2. loopback binding, or an authenticating and authorizing TLS reverse proxy
   before any non-loopback exposure;
3. a dedicated unprivileged service account and a data directory readable only
   by that account and approved backup operators;
4. encrypted host storage and encrypted, access-controlled backups whenever
   authenticated fetching is enabled;
5. container/service sandboxing and default-deny egress appropriate to each
   worker in production;
6. trusted, pinned executables and dependency updates from reviewed sources;
7. trusted session providers, secret stores, custom transports, and remote
   connectors;
8. secrets supplied through configured providers rather than source, plan,
   graph, or command-line text;
9. explicit retention, quota, backup, incident-response, and deletion procedures
   for the SQLite database and CAS;
10. public HTTP disabled when authenticity or confidentiality matters; and
11. Graphify outputs, event databases, CAS data, and context results treated as
    sensitive operational material.

The daemon should not be placed directly on the public internet. Interface
conformance tests establish behavior parity; they do not establish transport
authentication.

## Abuse exclusions

Fetech must not be configured or extended to:

- solve CAPTCHAs or bypass bot protections;
- evade paywalls, DRM, authentication, rate limits, or publisher access
  controls;
- perform credential stuffing, password guessing, MFA interception, session
  theft, or authorization elevation;
- interpret `robots.txt`, cache presence, or a reader/archive copy as permission
  to access content;
- submit mutating forms without a live, exact-scope approval;
- replace the original publisher URL with an adapter or archive URL as source
  authority;
- use fetched instructions as executable policy;
- access arbitrary local files through URL handling; or
- send authenticated or private content to a public remote connector.

Operators remain responsible for legal authority, contractual restrictions,
data protection, and publisher terms applicable to each target.

## Verification mapping

The following tests provide implementation evidence. They are regression
controls, not proofs against unknown vulnerabilities.

| Security property | Primary verification |
|---|---|
| URL policy, private-address rejection, HTTPS downgrade prevention | `tests/test_enma_invariants.py`, `tests/test_http_adapter.py` |
| Per-redirect validation and pinned connection behavior | `tests/test_http_adapter.py`, pinned-transport tests |
| Wire, decompressed, redirect, and deadline budgets | `tests/test_http_adapter.py`, budget/conformance tests |
| Exact-origin authentication, redirect withholding, anonymous robots, expiry, and cache separation | `tests/test_v03_auth.py` |
| Session-provider validation, authorized refresh, and pure failure paths | `tests/test_v03_session_connector.py`, v0.3 runtime regression tests |
| Form approvals, one-shot consumption, redirect method semantics, and cookie handoff | `tests/test_v03_auth_flows.py`, `tests/test_v03_session_connector.py`, `tests/test_v03_runtime_regressions.py` |
| Public/execution plan separation plus plan, event, graph, and diagnostic sanitization | `tests/test_v03_security_regressions.py` |
| Browser offline routing, bounded rendering, page-state rejection | `tests/test_v02_browser.py`, browser conformance tests |
| Logic-engine timeout, output bounds, sensitive-fact rejection, invalid-plan fallback | logic-backend tests |
| Archive traversal, link, member, expansion, and ratio limits | `tests/test_enma_invariants.py` |
| CAS hashing, cache isolation, ledger lineage, and rebuild behavior | storage, ledger, and v0.1 invariant tests |
| Bounded JSON, XML, feed, OpenAPI, and GraphQL normalization | `tests/test_v03_api.py`, structured-API regression tests |
| SDK, REST, CLI, and MCP behavioral parity | `tests/test_v03_interfaces.py`, runtime conformance tests |

Release verification also runs the full test suite, Ruff, mypy, and
`git diff --check`. Security-sensitive changes to Clingo or Prolog require
golden-result, invalid-output, timeout, and pure-Python fallback coverage.

## Residual risk register

| Risk | v0.3 rating | Required response |
|---|---:|---|
| REST or MCP exposed to untrusted clients without authentication or per-run/artifact authorization | High | Keep loopback-only or require an authenticating reverse proxy and network ACL |
| Hostile documents and archives parsed in the daemon process | High | Accept only in controlled deployments; isolate these workers in v0.4 |
| Authenticated raw/derived artifacts stored without CAS encryption, ACL, retention, or secure deletion | High | Restrict/encrypt the data directory, define retention, and prevent untrusted interface access |
| Browser and logic workers lack a complete OS sandbox; macOS also lacks an address-space cap | Medium–High | Add container/service isolation, egress controls, and host monitoring |
| Public HTTP content can be observed or modified in transit | Medium | Disable public HTTP for integrity- or confidentiality-sensitive work |
| Optional remote connectors and session providers are trusted processors | Medium | Review, pin, scope, monitor, and disable unless required |
| Third-party parser, browser, curl, Clingo, or Prolog supply-chain compromise | Medium | Pin dependencies, produce an SBOM/license report, scan, and update deliberately |
| CAS/SQLite growth can exhaust disk across otherwise bounded runs | Medium | Apply external filesystem quotas, monitoring, retention, and alerting |
| Content-address deduplication can confirm equality across auth scopes to a storage-level observer | Low–Medium | Restrict metadata/storage access; add scoped physical storage where needed |
| SQLite ledger is append-only by application convention, not cryptographically tamper-evident | Low–Medium | Restrict filesystem access and use external audit/backup controls when required |

No v0.3 control makes hostile native dependencies safe after full code
execution. Suspected compromise requires revoking credentials, stopping the
daemon, preserving the data directory for investigation, rotating provider
secrets, and rebuilding from trusted artifacts.

## Deferred v0.4 risks and gates

v0.4 must not claim closure of document, OCR, media, archive, or snapshot
security until it adds and verifies:

- ephemeral document, OCR, archive, and media workers with explicit CPU, memory,
  disk, process, filesystem, network, and time restrictions;
- hardened Docling/OCR and yt-dlp/FFmpeg execution with bounded inputs, outputs,
  frames, duration, and transformations;
- archive nesting controls enforced across worker boundaries and adversarial
  bomb/path/link fixtures;
- fuzzing and malformed-input corpora for every native parser boundary;
- total storage quotas, retention and garbage-collection behavior, crash
  recovery, and stale snapshot controls;
- an authenticated artifact-delivery boundary and scoped storage protocol before
  any multi-user deployment;
- documented encryption-at-rest and deletion expectations for filesystem, S3,
  SQLite, and Postgres implementations;
- malware-scanning integration points where deployments require them; and
- equivalent SSRF, credential, and provenance guarantees for archive and
  Internet Archive integrations.

Multi-tenant administration remains post-v1. Until an ADR explicitly changes
that decision, adding Postgres or S3 does not make a daemon multi-tenant.

## Maintenance

Update this threat model whenever a trust boundary, authentication flow,
storage protocol, executable worker, remote connector, artifact-delivery path,
or default policy changes. Each release should pair it with the dependency
license report, SPDX SBOM, adversarial security suite, and documented residual
risks.
