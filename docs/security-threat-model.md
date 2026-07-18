# Fetech security threat model

Status: v0.4.0a0 unreleased candidate snapshot

Last reviewed: 2026-07-18

Reference platform: Linux daemon; macOS local development and library use

This document describes the security posture of the Fetech v0.4.0a0 candidate runtime. It is
an implementation-grounded threat model, not a certification or a claim that
the process is a complete sandbox. The normative runtime invariants remain in
[`SECURITY.md`](../SECURITY.md).

Fetech is a single-tenant, local/self-hosted alpha. Python is authoritative for
security, authorization, budgets, storage, and execution. Clingo and SWI-Prolog
may propose plans or explanations, but their output is untrusted and cannot
override Python policy checks.

## Scope

This model covers:

- the Python SDK, CLI, REST daemon, SSE endpoints, and MCP server;
- target normalization, DNS and redirect validation, HTTP transport, browser
  rendering, authenticated sessions, structured APIs, document parsing, and
  bounded document/archive subprocesses, media tools/providers, and validated snapshots;
- optional Clingo and SWI-Prolog subprocesses;
- SQLite event/metadata storage, the filesystem content-addressed store (CAS),
  caches, and runtime Graphify projections;
- operator-provided authentication/session providers and optional remote
  acquisition connectors; and
- repository and vault excerpts returned by the bounded context broker.

It describes the 155-capability candidate conformance state: 119 v0.1-v0.3
paths and 36 v0.4 document, media, cache, snapshot, and archive paths. Optional
binaries and configured connectors remain unavailable unless the operator
installs or injects them; the explicitly requested public Internet Archive path
uses a built-in exact-host, redirect-validated connector.

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
    |                 (browser, document, archive, media tools,
    |                  Clingo, Prolog, optional curl HTTP/3)
    |
    +--> DNS and public network --> publisher or authenticated origin
    |
    +--> built-in Wayback service or operator-configured provider/remote connector

Context caller --> context broker --> Graphify / repository / QMD vault excerpts
```

The important boundaries are:

| Boundary | Data crossing it | Trust decision |
|---|---|---|
| Caller to interface | Request, auth reference, policy, budgets | The daemon and MCP server assume a trusted single-tenant caller |
| Gateway to network | Sanitized request plus per-hop credentials when authorized | Every destination and redirect is independently policy-checked |
| Gateway to session provider | Opaque reference and typed session request | Provider is operator-trusted; returned descriptors are schema- and origin-validated |
| Gateway to local worker | Bounded HTML/document/archive/media bytes, facts, rules, or fixed command arguments | Worker output is untrusted and must satisfy independent typed Python validation. The portable development runner is not an OS sandbox; Linux required mode adds the fail-closed boundary only for the covered document, archive, image, offline-browser, and native-media workers |
| Gateway to built-in Wayback service | Public, unauthenticated acquisition input | The capability must be explicit; Python fixes service origins, validates public DNS and every redirect, bounds bytes/time, and treats remote metadata/content as untrusted |
| Gateway to injected remote connector | Public, unauthenticated acquisition input | The implementation is operator-trusted and disabled unless explicitly enabled; Python still revalidates its bounded result |
| Runtime to content-processing provider | Already acquired document/media bytes or a sanitized target under a typed provider protocol | Provider is operator-trusted for submitted content; returned types, fields, locators, origins, and sizes are revalidated |
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
request retains the real target only in request-local memory; document workers
receive at most its path suffix.

The HTTP adapter stores the response body verbatim as a `raw` CAS artifact,
including an authenticated response. Derived artifacts can also contain private
content. For example, a fetched authenticated HTML page may be stored raw and
then yield clean text, rendered HTML, a screenshot, or structured data.

An approved form request body is not persisted as an artifact. A derived CSRF
token is not separately persisted. However, the original HTML response from
which a CSRF value was derived is a raw response artifact and may naturally
contain that value. The response to the form submission is also stored as raw
content.

The filesystem CAS is immutable and SHA-256 content-addressed, but the alpha does
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

`GET /v1/artifacts/{artifact_id}` can return bounded artifact content. The
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
| S-3 | A caller impersonates another daemon user | None inside the daemon or MCP server | High if more than one mutually untrusted caller can reach either interface |

### Tampering

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| T-1 | Clingo, Prolog, or a model proposes an unsafe plan | Accept only registered capability IDs and typed schema-valid output; reapply Python policy and budget checks; deterministic Python fallback remains available | Compromise of the Python policy authority or registry is out of scope |
| T-2 | A body or artifact is changed after acquisition | SHA-256 content addressing, immutable CAS writes, artifact lineage, parser/version metadata, and snapshot integrity rechecks | A local attacker able to modify the database, CAS, or executable can corrupt state or replace both content and metadata; the alpha has no signed ledger |
| T-3 | An attacker modifies a form submission or replays approval | Capability approval plus exact target/method grant; GET form proposals rejected; one-shot form provider; body-preserving redirects blocked | The runtime does not provide business-level transaction confirmation or remote-origin idempotency |
| T-4 | A malicious structured payload changes parser meaning | Bounded parsers reject duplicate JSON keys, non-finite numbers, XML DTD/entities, unsafe YAML anchors, external references, contradictory worker format/parser identities, and invalid locator schemas | Parser implementation bugs and format confusion remain possible |

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
| I-4 | A remote reader, search, browser, or snapshot connector receives sensitive data | Disabled by default; public and unauthenticated targets only; endpoints must be HTTPS and policy-approved; payloads are bounded and sanitized for their connector contract | The remote processor sees submitted public content and may retain it according to its own policy |
| I-5 | Context search exposes repository or vault content | Default 4,000-token bundle, 8,000-token hard ceiling, top-result limits, no full-vault load | The context API has no multi-user ACL and can disclose selected source or note excerpts to any trusted interface caller |
| I-6 | Content hashes reveal that a known private body exists | Artifact UUID boundary and no direct hash-search interface in ordinary fetch contracts | A caller with storage or metadata access can perform confirmation attacks against predictable content |
| I-7 | An injected OCR/transcription/document provider receives private acquired bytes | Providers are explicit operator configuration, receive no runtime credentials, use bounded typed inputs, and have schema/size/origin validation on output | The provider necessarily sees submitted content; the runtime does not prove that an injected implementation is local, confidential, or non-retaining |

### Denial of service

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| D-1 | Infinite redirects, oversized bodies, decompression bombs, or crawl explosion | Deadlines, attempts, redirects, cumulative wire/decompressed bytes, pages, depth, archive members/ratio, bounded worker input/output, per-host concurrency, and early stopping | Aggregate disk growth across runs and allocation inside native dependencies before process limits can exhaust the host |
| D-2 | A subprocess hangs or floods output | Independent POSIX spawn/bootstrap deadline, one total wall budget, CPU limit, bounded stdout/stderr, new process group, and group termination; Linux required mode adds per-worker cgroup CPU, memory, PID, and cleanup controls for covered built-in workers | Development mode, macOS, logic engines, optional curl, local yt-dlp, and injected providers remain outside the required Linux boundary; host-wide resource exhaustion and kernel/container defects remain possible |
| D-3 | Concurrent requests starve the daemon | Primary HTTP and built-in Wayback use shared global/per-host admission and pacing; the bounded local yt-dlp subprocess consumes a shared operation slot in development; all paths use request budgets | yt-dlp's internal requests to several allowed hosts are not individually coordinated by the parent scheduler; required mode therefore refuses it until egress is brokered. The single-tenant alpha also has no tenant quotas, admission-control identity, or durable distributed scheduler |
| D-4 | Ledger or CAS fills the disk | Per-artifact and request byte budgets | No total retention or storage quota is implemented |

### Elevation of privilege

| ID | Threat | Current controls | Residual risk |
|---|---|---|---|
| E-1 | SSRF reaches local services or cloud metadata | Scheme, port, address-class, redirect, and DNS checks; pinned transport; browser subrequests aborted; `file://` rejected | An unsafe custom transport, proxy, resolver, or connector can invalidate network assumptions |
| E-2 | Page script, parser input, archive, media tool, or solver escapes its worker | Browser works from acquired offline HTML; document/archive payloads omit host and credential material; document and Pillow workers add a Python audit hook; tool arguments are fixed; parent processes revalidate output. For covered built-in workers, Linux required mode adds user/mount/PID/IPC/UTS/cgroup/network namespaces, selective read-only mounts, bounded tmpfs, no capabilities, `no_new_privileges`, libseccomp, cgroup ceilings, and forced descendant cleanup | Kernel, Bubblewrap, libseccomp, browser, parser, and native-code defects remain possible. Development mode, macOS, logic engines, optional curl, local yt-dlp, and injected providers do not receive this boundary; model and browser bundles still require reviewed immutable deployment artifacts |
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
Playwright browser work, document/archive parsing, Tesseract/FFmpeg/FFprobe
media tools, local yt-dlp, and optional curl HTTP/3 execution. Linux `required`
mode wraps only the covered document, archive, image, offline-browser, and
native-media invocations in the stronger boundary.

| Control | Linux development or uncovered process | Linux required covered worker | macOS |
|---|---|---|---|
| Separate process session/group, startup deadline, wall timeout, bounded output, and group termination | Yes | Yes | Yes |
| CPU, core-dump, output-file, and file-descriptor resource limits | Best effort | Strict inner bootstrap plus outer service limits | Best effort |
| Address-space resource limit | Best effort | Strict inner bootstrap; separate aggregate cgroup memory ceiling | Not applied because the bootstrap omits unsupported macOS `RLIMIT_AS` |
| Aggregate CPU, resident-memory, and PID limits | No per-worker cgroup | One delegated cgroup-v2 leaf per invocation | No |
| Syscall filtering and `no_new_privileges` | No | Reviewed libseccomp denylist; fail closed if unavailable | No |
| User, mount, PID, IPC, UTS, and cgroup namespaces | No | Yes | No |
| Filesystem view and writable scratch | Host view; selected Python audit hooks only | Minimal read-only mounts plus private size-limited `/tmp` and `/dev/shm` | Host view; selected Python audit hooks only |
| Worker-process network denial | Application/Python controls only | New network namespace for every covered offline profile | Application/Python controls only |

Playwright also receives already-fetched HTML, starts its context offline, blocks
service workers, aborts every page route, and applies bounded readiness and
interaction rules. Reader mode disables JavaScript; render mode permits it. In
required mode the browser additionally receives the kernel boundary and a
4 GiB aggregate resident-memory cgroup ceiling. Its separate 2 TiB `RLIMIT_AS`
value only permits V8's large virtual-address reservation and is never used as
the resident-memory limit.

Linux is the reference daemon platform. A hostile-input deployment must run the
covered workers in required mode under the dedicated unprivileged reference
service. Logic engines, optional curl HTTP/3, local yt-dlp, and injected
providers must be isolated separately or disabled. macOS remains supported for
local development and library use and must not be represented as a hardened
environment for hostile browser or parser workloads.

Document and archive parsing crosses an ephemeral worker boundary. The request
payload contains bytes, a path suffix, canonical capability, and numeric limits;
it omits the host, query, auth reference, credential, and caller filesystem path.
The preferred Docling path additionally requires a canonical local model
manifest and independently configured expected bundle SHA-256; the parent and
child hash every bounded model file and reject identity changes. The parent
recomputes format evidence and validates parser identity, exact artifact
identity, schemas, locators, hashes, and remaining budgets. The document worker
and Pillow image decoder also install a Python audit hook that denies
Python-level sockets, process creation, filesystem mutation, common `ctypes`
foreign-function access, and reads outside reviewed
interpreter/package/model roots. That hook is only defense in depth against
native code; required Linux mode supplies the operating-system boundary for
these covered workers.

Git LFS resolution is a separate exact-origin provider boundary: Python supplies
only a sanitized target, canonical origin, object hash/size, deadline, and byte
ceiling, then rejects origin, type, size, or digest mismatches. PDF OCR providers
receive already acquired PDF bytes and must return bounded, page-located typed
output. The built-in yt-dlp worker receives no credentials or acquired private
body, uses a sanitized environment and fixed Python invocation, disables
configuration/plugins/cookies/downloads/external execution, restricts egress to
reviewed HTTPS host families with public-address DNS and identity responses, and
returns a strict URL-redacted schema. Required mode refuses local yt-dlp until
an allowlisting egress broker exists; production deployments must use such a
brokered isolated connector or leave it disabled. Other media providers have
runtime type/schema/size checks and generic error reporting, but providers that
receive content remain trusted processors for that content.

## Operational assumptions and deployment requirements

A secure v0.4 deployment assumes:

1. one trusted tenant and one administrative domain per daemon;
2. loopback binding, or an authenticating and authorizing TLS reverse proxy
   before any non-loopback exposure;
3. a dedicated unprivileged service account and a data directory readable only
   by that account and approved backup operators;
4. encrypted host storage and encrypted, access-controlled backups whenever
   authenticated fetching is enabled;
5. Linux required mode for every covered hostile-data worker, with logic, curl,
   local yt-dlp, and injected providers separately isolated or disabled;
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
| Cumulative wire, decompressed, redirect, deadline, and archive-member budgets | `tests/test_http_adapter.py`, `tests/test_v04_cache_archives.py`, `tests/test_v04_budget_accounting.py`, budget/conformance tests |
| Exact-origin authentication, redirect withholding, anonymous robots, expiry, and cache separation | `tests/test_v03_auth.py` |
| Session-provider validation, authorized refresh, and pure failure paths | `tests/test_v03_session_connector.py`, v0.3 runtime regression tests |
| Form approvals, one-shot consumption, redirect method semantics, and cookie handoff | `tests/test_v03_auth_flows.py`, `tests/test_v03_session_connector.py`, `tests/test_v03_runtime_regressions.py` |
| Public/execution plan separation plus plan, event, graph, and diagnostic sanitization | `tests/test_v03_security_regressions.py` |
| Browser offline routing, bounded rendering, page-state rejection | `tests/test_v02_browser.py`, browser conformance tests |
| Logic-engine timeout, output bounds, sensitive-fact rejection, invalid-plan fallback | logic-backend tests |
| Document worker identity/schema/locator checks, JSON/XML/OOXML bounds, exact-origin Git LFS, and scanned-PDF OCR fallback | `tests/test_v04_documents.py`, `tests/test_v04_document_providers_integration.py` |
| Archive worker traversal, link, nesting, member, expansion, ratio, timeout, and malformed-output limits | `tests/test_v04_cache_archives.py`, `tests/test_enma_invariants.py` |
| Media worker/provider timeout, output schema, TIFF/WebP structure, podcast byte/node/depth limits, missing dependency, metadata redaction, and lineage | `tests/test_v04_media.py`, `tests/test_v04_ytdlp.py` |
| Python worker audit denial for network, subprocess, `ctypes`, arbitrary host-file read/mutation, and limit changes | `tests/test_worker_audit.py` |
| Required-mode profile schema, fail-closed backend selection, minimal read-only mounts, bounded tmpfs declarations, and explicit degraded development status | `tests/test_worker_isolation.py` |
| Kernel-enforced read-only mounts, hidden host state, parser network denial, discriminating seccomp denial, cgroup CPU/PID/memory controls, bounded scratch, real required-profile Chromium launch, and cleanup | `tests/test_worker_isolation_linux.py`, mandatory `containment-linux` CI job |
| Cache fallback ordering, quality admission, exact representations, CAS hashing, authenticated/region isolation, snapshot integrity, revalidation/SWR, Wayback destination/budget policy, and crash-safe immutable writes | `tests/test_v04_cache_archives.py`, `tests/test_wayback.py`, `tests/test_v04_planning.py`, storage and ledger tests |
| Bounded JSON, XML, feed, OpenAPI, and GraphQL normalization | `tests/test_v03_api.py`, structured-API regression tests |
| SDK, REST, CLI, and MCP behavioral parity | `tests/test_v03_interfaces.py`, runtime conformance tests |

Release verification also runs the full test suite, Ruff, mypy, and
`git diff --check`. Security-sensitive changes to Clingo or Prolog require
golden-result, invalid-output, timeout, and pure-Python fallback coverage.

## Residual risk register

| Risk | Alpha rating | Required response |
|---|---:|---|
| REST or MCP exposed to untrusted clients without authentication or per-run/artifact authorization | High | Keep loopback-only or require an authenticating reverse proxy and network ACL |
| Required-mode Bubblewrap, libseccomp, kernel, or cgroup escape by hostile built-in parser/browser/media code | Medium–High | Keep the backend and kernel patched, preserve mandatory Linux enforcement CI, monitor hosts, and prefer stronger separately supervised OCI workers where warranted |
| Authenticated raw/derived artifacts stored without CAS encryption, ACL, retention, or secure deletion | High | Restrict/encrypt the data directory, define retention, and prevent untrusted interface access |
| Development-mode workers, logic workers, injected providers, and macOS processes do not receive the required Linux boundary | High | Never use development mode for hostile production input; isolate or disable injected/logic providers and keep release daemon mode `required` |
| Public HTTP content can be observed or modified in transit | Medium | Disable public HTTP for integrity- or confidentiality-sensitive work |
| Optional remote connectors, content-processing providers, and session providers are trusted processors | Medium | Review, pin, scope, monitor, and disable unless required |
| Third-party parser, browser, curl, Clingo, or Prolog supply-chain compromise | Medium | Pin dependencies, produce an SBOM/license report, scan, and update deliberately |
| CAS/SQLite growth can exhaust disk across otherwise bounded runs | Medium | Apply external filesystem quotas, monitoring, retention, and alerting |
| Content-address deduplication can confirm equality across auth scopes to a storage-level observer | Low–Medium | Restrict metadata/storage access; add scoped physical storage where needed |
| SQLite ledger is append-only by application convention, not cryptographically tamper-evident | Low–Medium | Restrict filesystem access and use external audit/backup controls when required |

No alpha control makes hostile native dependencies safe after full code
execution. Suspected compromise requires revoking credentials, stopping the
daemon, preserving the data directory for investigation, rotating provider
secrets, and rebuilding from trusted artifacts.

## Remaining v0.4 publication and post-v1 gates

The candidate implementation now has ephemeral document/archive workers,
bounded OCR/FFmpeg/FFprobe paths, archive adversarial controls, immutable
snapshot integrity, authentication partitioning, typed policy-aware remote
connector protocols, an exact locked preferred Docling path, shared network
admission, independent POSIX startup/runtime deadlines, and fail-closed Linux
per-worker containment profiles for the covered offline built-ins, backed by
Bubblewrap, cgroup v2, bounded tmpfs, libseccomp, read-only minimal mounts, and
default-deny networking.
The focused source-tree and separately unpacked development-wheel Docling 2.113 contract/content
subsets pass and bind the six-file model bundle plus wheel `RECORD` and digest. Publishing v0.4
still requires:

- rerunning that successful smoke from the final clean tagged wheel, tied to the root-owned
  read-only
  `docling-project/docling-layout-heron@8f39ad3c0b4c58e9c2d2c84a38465abf757272d8`
  reference bundle and expected canonical SHA-256
  `e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76`,
  plus retained release-environment evidence and human review of its exact files, notices, and
  redistribution terms;
- artifact-bound live smoke evidence tied to the exact installed yt-dlp
  version, plus dated Wayback endpoint/service smoke evidence;
- brokered, allowlisted egress for yt-dlp in required mode, or release wording
  that explicitly limits local yt-dlp to development mode;
- broader fuzzing and malformed-input corpora for every native parser boundary;
- exact version/license capture for optional binaries and versioned connectors, plus dated
  endpoint/service metadata for unversioned remote services, in the release evidence;
- artifact-level notice and redistribution legal review for dependencies recorded under explicit
  NVIDIA proprietary/EULA and pypdfium2 mixed-distribution LicenseRefs; the exact-version catalog
  already covers all 167 third-party identities in the current universal lock and regenerates the
  v0.4.0a0 candidate SPDX and dependency-license evidence. The published v0.3 artifacts remain
  immutable and are checked against their historical release profile;
- total storage quotas, retention, garbage collection, and crash-recovery
  exercises beyond immutable per-record writes;
- a passing mandatory `containment-linux` job on the release commit and
  verification of the delegated reference systemd unit on its target Linux
  distribution;
- documented encryption-at-rest and deletion expectations for filesystem, S3,
  SQLite, and Postgres implementations; and
- malware-scanning integration points where deployments require them.

Release administration is also unfinished: package metadata reports `0.4.0a0`, but the candidate is
untagged and unpublished. Reproducible candidate SPDX and dependency-license reports exist; clean
release-commit distributions, checksums, attestations, a tag, and published package/release
artifacts do not.

An authenticated artifact-delivery boundary and scoped physical storage remain
mandatory before any multi-user deployment.

Multi-tenant administration remains post-v1. Until an ADR explicitly changes
that decision, adding Postgres or S3 does not make a daemon multi-tenant.

## Maintenance

Update this threat model whenever a trust boundary, authentication flow,
storage protocol, executable worker, remote connector, artifact-delivery path,
or default policy changes. Each release should pair it with the dependency
license report, SPDX SBOM, adversarial security suite, and documented residual
risks.
