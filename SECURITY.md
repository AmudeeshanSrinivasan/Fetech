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
- URL credentials are rejected. Sensitive query values and headers are removed from diagnostics.
- Authenticated and public cache scopes are distinct.
- Credentials are opaque references and never enter plans, logs, graphs, artifacts, or Obsidian.
- Browser, document, OCR, archive, and media engines are expected to run in bounded workers.
- Archive extraction rejects traversal, links, nested archives, excessive members, excessive
  expansion, and suspicious compression ratios.
- CAPTCHA, paywall, login, cookie-wall, bot-block, and error pages cannot support accepted evidence.
- Reader and browser adapters never replace the original publisher URL as source authority.
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
- The local runner executes only checked-in rule programs with sanitized facts, but it is not a complete
  operating-system sandbox. Production workers must add container or service isolation that denies
  network access, shell execution, foreign-function loading, and unrestricted filesystem access.
- Prolog predicates capable of file, process, socket, package-loading, or dynamic code execution are
  outside the allowed rule surface. Clingo scripts and external functions are disabled by default.
- Absence or failure of a logic engine cannot disable a Python policy check or weaken a deny decision.

Rules, facts, answer sets, and explanations are sanitized before logging or provenance projection.
They are never copied automatically into Obsidian.

Report vulnerabilities privately to the project maintainers. Do not include credentials, private
URLs, or sensitive response bodies in reports.
