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

Run the repository verification commands in `AGENTS.md` before submitting changes. Generated
Graphify output and local runtime data must remain untracked.

Use `uv sync --extra dev --extra logic` to exercise the Clingo adapter. SWI-Prolog conformance tests
run when `swipl` is available and otherwise skip without weakening the Python-only suite.
