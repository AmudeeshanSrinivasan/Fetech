# Security policy

Fetech treats every target, redirect, document, browser page, archive, media file, and extracted
instruction as untrusted input.

## Runtime invariants

- Public network requests allow only HTTP and HTTPS; HTTPS is never downgraded.
- Loopback, private, link-local, reserved, multicast, unspecified, and cloud-metadata destinations
  are blocked by default before every request and redirect.
- Redirect targets are normalized and re-resolved per hop, cross-host concurrency limits follow the
  destination host, redirect loops are stopped before a repeated request, and HTTPS downgrades fail
  closed.
- Declared and streamed wire bytes are bounded independently from transparently decompressed bytes,
  preventing compressed responses from bypassing expansion limits.
- Attempt and deadline budgets are cumulative across the run. Adapter-reported wire-byte,
  decompressed-byte, archive-member, and browser-time consumption is subtracted before later work;
  configured model-token and monetary consumption use the same result accounting. Per-host
  concurrency and minimum request intervals apply to every redirect host. Crawl requests fetch a
  bounded `robots.txt` before the target and stop when its rules disallow the target; robots rules
  are never treated as authority.
- Explicit HTTP/3 requests use only HTTPS, pin curl to a Python-validated public address, require
  `--http3-only`, bound process time and output, and fail rather than negotiate an older protocol.
- URL credentials are rejected. Sensitive query values and headers are removed from diagnostics.
- Resolved credentials require an exact HTTPS origin. They are applied per validated request hop,
  stripped from cross-origin redirects, omitted from `robots.txt`, and never stored in shared HTTP
  client defaults or durable cookie state.
- Opaque references, credential header/cookie counts, individual values, and aggregate in-memory
  credential material are byte-bounded before use.
- Authenticated and public cache scopes are distinct. Authenticated keys contain a domain-separated
  digest of the opaque reference, not the reference or credential value.
- Requests and in-memory plans may contain only opaque authentication references. References are
  redacted from the event ledger and runtime graph; resolved headers, cookies, and tokens never enter
  plans, logs, events, graphs, artifacts, or Obsidian.
- Serialized authenticated plans, results, events, runtime graphs, and runtime-generated derived
  artifact documents redact every query value, including values under unknown parameter names. The
  raw normalized query remains only in the private in-memory transport view.
- Unknown references fail as `AUTH_REQUIRED`, provider outages fail as `DEPENDENCY_MISSING`, known
  expiry emits an `auth_expired` diagnostic, and authenticated HTTP/3 fails closed until a
  secret-safe transport channel exists.
- High-level session capabilities require a separate trusted `SessionProvider` descriptor. Python
  validates its capability, opaque reference, exact HTTPS origin, issuer/scopes, and connector
  identity before resolving or refreshing credential material.
- OAuth/SSO bearer refresh is descriptor-authorized, provider-mediated, and attempted at most once
  for GET or HEAD. Refresh references and material never enter plans or events; the ledger receives
  only sanitized lifecycle status.
- `PlanNode.requires_approval` is enforced centrally before adapter execution. Mutating forms also
  require a short-lived approval bound to the exact HTTPS action and method. Form fields and derived
  CSRF material remain ephemeral; they never enter plan parameters, request metadata, diagnostics,
  events, or submitted-body artifacts. In-memory proposal providers consume mutations once.
- A 303, or a 301/302 after POST, switches to GET and drops the body. Every body-preserving redirect,
  including same-origin 307/308, is blocked without a new exact-target approval.
- Approved form login may retain bounded Secure, exact-origin/path cookies across a same-origin
  301/302/303 redirect for one request chain. Cookies are destroyed on an origin change and scrubbed
  from returned responses.
- Private-workspace execution requires the explicit `private` privacy profile. SSO and private-workspace
  connectors are fail-closed and optional; they do not automate passwords, MFA, CAPTCHA, or IdP
  interaction.
- Structured API parsing occurs only after a successful HTTP acquisition. JSON nesting/nodes and
  XML nesting/nodes are bounded; duplicate JSON keys, non-finite values, XML DTD/entities, and
  OpenAPI YAML anchors/aliases are rejected.
- Named API connectors require exact approved official origins and recognizable response schemas.
  The explicit public arXiv HTTP endpoint remains subject to the ordinary public-HTTP policy.
  OpenAPI references, feed links, sitemap URLs, and pagination links are normalized as evidence but
  are not followed automatically by the API adapter.
- Document and archive parsing runs in ephemeral bounded workers over acquired bytes. The worker
  request protocol omits the host, query, credential, opaque auth reference, and caller target path;
  the optional Docling path adds only one validated local model-artifact directory and its
  independently configured expected bundle SHA-256. The runtime requires a canonical manifest,
  hashes every bounded file, and rejects a bundle mismatch before parser admission. Python
  independently validates format, parser identity, exact artifact identity, conversion status,
  page coverage, schema, locators, output, and remaining budgets before CAS admission. The document
  worker installs a Python audit hook before Docling imports that denies Python-level
  network/process operations, filesystem mutation, and reads outside reviewed
  interpreter/package/model roots. This is defense in depth, not operating-system containment:
  native code can bypass the hook. Linux required mode therefore adds the separate
  kernel-enforced, default-deny-network worker profile with a read-only model mount; development
  mode and macOS do not.
- The v0.4 reference Docling bundle is pinned to
  `docling-project/docling-layout-heron@8f39ad3c0b4c58e9c2d2c84a38465abf757272d8`
  and canonical SHA-256
  `e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76`.
  Configure both `FETECH_DOCLING_ARTIFACTS_PATH` and
  `FETECH_DOCLING_ARTIFACTS_SHA256` explicitly in production. If only the path is set through the
  environment, Fetech supplies the compiled v0.4 reference digest; that fallback admits only the
  exact reference bundle. Any other bundle requires an explicit independent digest. A digest read
  only from the selected model directory is not a trust anchor.
  Project-local copies and download caches belong under ignored `runtime-data/`. Production copies
  must be root-owned and read-only. The recorded `apache-2.0` model-card identifier is provenance,
  not legal approval; review the exact model files, notices, and redistribution terms before
  publishing a model bundle or container image.
- `github_raw` requires the exact `raw.githubusercontent.com` HTTPS origin. A Git LFS pointer can use
  only a configured resolver whose returned type, canonical origin, object size, SHA-256, and byte
  limit are rechecked. Textless PDF OCR can use only a configured provider whose page locators,
  page count, text type, and output bytes are validated; otherwise it remains checked-only
  `NEEDS_OCR`.
- Tesseract, FFmpeg, and FFprobe run through fixed-argument bounded subprocesses. Live transcript
  providers are injected explicitly, receive no runtime credentials, and return schema-validated
  bounded results. The optional built-in yt-dlp worker receives only a canonical public YouTube
  locator in a sanitized environment. It disables user configuration, cookies, plugins, downloads,
  external execution, JavaScript runtimes, and remote components; permits only HTTPS,
  identity-encoded responses from reviewed host families; validates public DNS results and every
  redirect; and enforces response, redirect, output, file, CPU, and time ceilings, plus a
  best-effort address-space ceiling on Linux. Python strips remote and signed URLs and validates the
  worker envelope again. Required mode refuses the local yt-dlp profile until an allowlisting
  egress broker exists. Providers that receive acquired bytes must still be trusted for that
  content; unexpected provider exception text is replaced by a generic diagnostic. The Pillow
  image worker uses the same Python audit defense after loading reviewed decoder plugins. Native
  media binaries rely on the required Linux boundary. Local yt-dlp remains development-only until
  an allowlisting egress broker can mediate it; production must use a separately isolated brokered
  connector or leave it disabled.
- POSIX development subprocesses start through an isolated, independently timed bootstrap that applies
  irreversible resource limits before `exec`; runtime communication receives only the remaining
  total wall budget, and timeout or cancellation terminates the process group. This is resource
  control, not syscall, mount, PID, or network isolation. Linux required mode adds delegated
  cgroup-v2 limits, explicit Bubblewrap namespaces, minimal read-only mounts, bounded tmpfs,
  `no_new_privileges`, libseccomp, inner readiness, and `cgroup.kill` cleanup for built-in
  document/archive/image/offline-browser/native-media workers.
- Primary HTTP and built-in Wayback resolution/request work uses one shared global/per-host
  admission and pacing scheduler. The yt-dlp subprocess consumes one shared operation slot, but
  its internal requests to multiple allowed hosts are not individually scheduled by the parent.
- PNG, GIF, JPEG, TIFF, and WebP images receive bounded structural validation. Podcast RSS is
  DTD/entity-free and bounded by input bytes, XML nodes, depth, and episodes; enclosure URLs are not
  followed automatically.
- Archive extraction rejects traversal, absolute paths, NULs, duplicates, links/devices, encrypted
  members, nested archives, excessive members, excessive expansion, and suspicious compression
  ratios at both worker and parent boundaries.
- Snapshot metadata is immutable, sanitized, authentication-partitioned, and integrity-checked
  against CAS on storage and lookup. Keys include language and region as well as URL,
  representation, authentication scope, policy profile, parser version, and relevant `Vary` values.
  Cache presence never implies authorization or truth.
- The built-in Internet Archive connector is used only for an explicit public, unauthenticated
  request. It validates DNS and every redirect, requires exact `archive.org`/`web.archive.org`
  HTTPS origins, streams within the remaining byte/deadline budget, and binds the capture locator
  to the requested original URL. Other third-party search-cache, archive, and CDN connectors are
  unavailable by default and require policy-aware injected providers. Python validates connector
  result type, source authority, HTTPS snapshot locator, byte bounds, quality, and
  capability-specific origin. Checked-only connector output cannot stop fallback acquisition.
- Native cache writes admit only accepted artifacts of the exact required representation; raw HTTP
  cannot populate browser, RAG-document, snippet, or search-result cache partitions. Cache-only
  plans require `rendered_html`, `clean_text`, or configured `search_results` producers first.
- CAPTCHA, paywall, login, cookie-wall, bot-block, and error pages cannot support accepted evidence.
- Reader and browser adapters never replace the original publisher URL as source authority.
- Remote readers are disabled by default. Enabling one requires an HTTPS operator template, an
  explicit request policy profile, a public unauthenticated target, and no sensitive query values.
- Browser reader mode receives only already-fetched HTML in a bounded subprocess. Playwright runs
  with JavaScript disabled, service workers blocked, offline mode enabled, and all requests aborted.
- Browser rendering uses a separate bounded subprocess with JavaScript enabled, but it remains
  offline, blocks service workers, and aborts every subresource. Selector waits, clicks, scrolling,
  cookie handling, screenshots, and SPA observations are bounded by request time/byte limits.
- Puppeteer and Selenium connectors are disabled by default. They require HTTPS operator endpoints,
  `policy_profile=allow_remote_browsers`, a public unauthenticated target, and no sensitive query
  values. They receive acquired HTML with `network_policy=offline`, never credentials.
- Search-provider discovery is disabled by default. It requires an HTTPS template and
  `policy_profile=allow_search_discovery`; returned URLs are normalized and same-domain/depth policy
  is reapplied before any fetch.
- Variant fetching is disabled for private, authenticated, or secret-bearing URLs. HTTPS downgrade
  candidates are never generated, and every selected variant is re-evaluated by the HTTP policy.
- Models may assist classification or semantic extraction but never determine policy or authorization.

## Python and logic-engine trust boundary

- Python is the final enforcement boundary for URL safety, DNS pins, redirects, authorization,
  approvals, budgets, isolation, cache scope, artifact acceptance, and adapter execution.
- Clingo may solve a finite, bounded planning problem. Its answer sets are proposals, not executable
  authority, and may reference only canonical capability IDs supplied by Python.
- Prolog may evaluate bounded rules over sanitized policy or provenance facts. A successful query is
  an explanation or recommendation, not permission to fetch or disclose data.
- Python validates every logic-engine result against typed schemas, the capability registry, allow and
  deny lists, dependency closure, and remaining budgets. Invalid, unknown, ambiguous, or timed-out
  results are rejected and trigger the safe pure-Python fallback or a typed failure.
- Logic processes receive no credentials, cookies, authorization headers, private response bodies, or
  unsanitized authenticated URLs. Opaque authentication references are not expanded into logic facts.
- Clingo and Prolog run with bounded input size, output size, solution count, CPU, and wall time. The
  local POSIX runner starts a separate process group and kills it on timeout or cancellation. Linux
  additionally applies an address-space limit; macOS does not currently provide that memory boundary
  through this runner.
- The local logic runner executes only checked-in rule programs with sanitized facts, but it is not a
  complete operating-system sandbox. Built-in browser, document, archive, image, and native-media
  subprocesses have separate Linux required-mode profiles; Clingo/Prolog and injected providers do
  not. Python audit hooks remain bypassable defense in depth. Production deployments must separately
  isolate or disable every enabled boundary not covered by a required profile.
- Prolog predicates capable of file, process, socket, package-loading, or dynamic code execution are
  outside the allowed rule surface. Clingo scripts and external functions are disabled by default.
- Absence or failure of a logic engine cannot disable a Python policy check or weaken a deny decision.

Rules, facts, answer sets, and explanations are sanitized before logging or provenance projection.
They are never copied automatically into Obsidian.

The implementation-grounded [threat model](docs/security-threat-model.md) records trust
boundaries, deployment assumptions, STRIDE analysis, platform isolation differences, and residual
risks. In particular, keep the single-tenant daemon on loopback or behind an authenticating and
authorizing reverse proxy, and treat the complete data directory as potentially confidential.

Report vulnerabilities privately to the project maintainers. Do not include credentials, private
URLs, or sensitive response bodies in reports.
