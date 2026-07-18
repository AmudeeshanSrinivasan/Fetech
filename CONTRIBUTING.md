# Contributing

Use Python 3.12 and `uv`. Python owns Fetech's public contracts, policy enforcement, resource budgets,
adapter execution, persistence, and interfaces. The default installation and deterministic planner
must work without Clingo, SWI-Prolog, or a model.

Clingo and Prolog contributions are welcome behind typed Python protocols:

- Clingo rules may select capabilities, satisfy dependencies, allocate reserved budgets, and optimize
  a plan. They return registered capability IDs and a schema-valid plan proposal.
- Prolog rules may express policy relationships, capability explanations, and provenance queries.
  They return bounded solutions over sanitized facts.
- Python validates all logic-engine inputs and outputs and remains the final authority. Logic engines
  must not access credentials, response bodies, the network, the shell, or unrestricted paths.
- Every logic change needs a golden fixture, malformed-output test, timeout/resource-limit test, and
  proof that the pure-Python fallback produces a safe plan or typed failure.

Every capability change must update its manifest entry, implementation, documentation, deterministic
fixture, failure semantics, and security constraints. Adding a Clingo predicate or Prolog rule does
not create a new capability ID. Live network tests must be opt-in; the default suite must remain
hermetic.

Discovery changes need frontier replay, page/depth/attempt budget, robots, and cross-domain tests.
Browser changes need missing-dependency, offline subresource, malformed-output, interaction-bound,
and connector policy tests. URL-variant changes must prove that no HTTPS downgrade or secret-bearing
cross-origin fetch can be produced.

Docling changes must preserve the exact optional dependency pin, run without implicit model
downloads or remote services, reject partial/timeout/error conversions, and retain the pypdf
fallback. Hermetic fake-contract tests are necessary but not release evidence: before publication,
run the artifact-bound smoke collector against the exact wheel and an immutable reviewed local
model-artifact bundle.

Run the repository verification commands in `AGENTS.md` before submitting changes. Generated
Graphify output and local runtime data must remain untracked.

Changes to the manifest, universal lock, license catalog, or v0.4 conformance document must verify
the immutable published v0.3 evidence and regenerate and check the explicitly unreleased v0.4.0a0
candidate evidence. Never regenerate published evidence from a later candidate lock:

```bash
uv run python scripts/generate_release_evidence.py --check-published
uv run python scripts/check_v04_release_readiness.py --check
uv run python scripts/generate_release_evidence.py \
  --overlay-profile scripts/release_v04_candidate.toml
uv run python scripts/generate_release_evidence.py \
  --overlay-profile scripts/release_v04_candidate.toml --check
```

The ordinary readiness `--check` confirms that the tracked candidate report is exact, including
truthful blockers. It does not mean the release is publishable. Only the final release environment
may run `--require-publishable`, and it must not provide or relabel evidence that did not actually
pass.

Use `uv sync --extra dev --extra logic` to exercise the Clingo adapter. SWI-Prolog conformance tests
run when `swipl` is available and otherwise skip without weakening the Python-only suite.
