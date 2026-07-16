# ADR 0001: Python authority with optional Clingo and Prolog backends

- Status: accepted
- Date: 2026-07-17
- Decision owners: Fetech maintainers

Implementation note: the alpha now includes the pure-Python planner, bounded Clingo planner adapter,
and bounded SWI-Prolog reasoner. This ADR remains the governing boundary for all three.

## Context

Fetech needs deterministic capability planning, constraint handling, policy explanation, and
provenance queries while preserving a small install, stable Python API, and strict security boundary.
Clingo is well suited to finite planning and optimization. Prolog is well suited to declarative rules
and explanation queries. Making either engine the runtime authority would complicate packaging,
failure handling, and enforcement.

## Decision

Python 3.12 remains the required runtime and sole authority for contracts, policy enforcement,
authorization, budgets, adapters, storage, and evidence acceptance. The built-in pure-Python planner
is always available.

Clingo may be configured as an optional `PlannerBackend`. It receives bounded facts generated from a
validated registry and request and returns a plan proposal containing canonical capability IDs.

SWI-Prolog may be configured as an optional `ReasonerBackend`. It receives bounded sanitized facts and
returns explanations or query solutions. It never grants authorization or performs acquisition.

Python validates all inputs and outputs, applies time/resource/solution limits, records provenance,
and uses a deterministic safe fallback when a backend is absent or fails.

## Consequences

Benefits:

- planning constraints and explanations can remain declarative and testable;
- the core remains usable with only Python and `uv`;
- logic engines cannot bypass the established security boundary;
- alternative planners and reasoners can implement the same typed protocols.

Costs:

- generated facts and rulesets require versioning and conformance tests;
- subprocess or embedding boundaries require strict resource and capability restrictions;
- equivalent Python fallback behavior must be maintained;
- release SBOM and license checks must cover enabled logic-engine distributions.

## Rejected alternatives

- Replacing the Python planner with Clingo: rejected because deterministic operation must not require
  an optional executable.
- Using Prolog as the policy enforcement point: rejected because authorization and external effects
  remain in the typed Python boundary.
- Mixing both engines into one ruleset: rejected because planning optimization and explanatory
  reasoning have different contracts, limits, and failure semantics.
- Allowing models to generate executable rules during a fetch: rejected because runtime-generated
  rules are not reviewed, versioned, or reproducible.

## Acceptance tests

- Python-only installation produces a valid deterministic plan.
- Clingo and Python golden plans satisfy the same registry, policy, dependency, and budget invariants.
- Unknown capability IDs, malformed answers, multiple-answer ambiguity, and timeout paths fail safely.
- Prolog solutions are bounded, sanitized, reproducible, and cannot trigger external effects.
- Disabling or removing either engine cannot weaken a Python deny decision.
