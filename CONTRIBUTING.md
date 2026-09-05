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

Public contract, SDK, REST, CLI, or MCP changes must pass the frozen Beta compatibility gate:

```bash
uv run python scripts/check_beta_compatibility.py
uv run pytest tests/test_beta_compatibility.py
```

The gate rejects every unreviewed difference. Use `--write` only after reviewing the exact surface
change, supplying any required migration fixture, and making an explicit compatibility or contract
version decision. See [`docs/api-compatibility.md`](docs/api-compatibility.md).

Build or packaging changes must also pass the complete same-host reproducibility gate from a clean
Git worktree:

```bash
uv run python scripts/verify_reproducible_builds.py \
  --output /tmp/fetech-beta-reproducible-build.json
```

The gate performs clean wheel and source-distribution installs. Its `--skip-install-smoke` option is
for local comparison debugging only and is not valid CI or release evidence. See
[`docs/reproducible-builds.md`](docs/reproducible-builds.md) for the evidence boundary.

The v0.4.0a0 candidate is frozen. Beta changes must verify its recorded commit and artifact hashes;
they must not regenerate that candidate's evidence from later source. Published evidence is also
immutable:

```bash
uv run python scripts/generate_release_evidence.py --check-published
uv run python scripts/generate_release_evidence.py \
  --overlay-profile scripts/release_v05_beta.toml --check
uv run pytest tests/test_release_evidence.py
uv run pytest tests/test_beta_release_evidence.py
```

The current Beta evidence is generated and checked only under `scripts/release_v05_beta.toml`; it
does not alter the frozen v0.4 candidate. For a future explicitly unfrozen candidate, generate and
check evidence only under that candidate's own profile. An ordinary readiness `--check` confirms
that its tracked report is exact, including
truthful blockers; it does not mean a release is publishable. Only the final release environment
may run `--require-publishable`, and it must not provide or relabel evidence that did not actually
pass.

Release operators must follow [`docs/release-process.md`](docs/release-process.md). Target-systemd
and legal receipts require independently selected OpenSSH allowed-signers files; private signing
keys never enter the repository or CI. A GitHub Release and PyPI upload must be revalidated against
their live authoritative APIs and the exact artifact receipt before the candidate is described as
published.

Use `uv sync --extra dev --extra logic` to exercise the Clingo adapter. SWI-Prolog conformance tests
run when `swipl` is available and otherwise skip without weakening the Python-only suite.
