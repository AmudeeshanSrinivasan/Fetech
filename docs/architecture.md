# Fetech architecture

Fetech is a Python-first, optionally polyglot content-acquisition runtime. Python 3.12 owns the public
interfaces and every security-sensitive effect. Clingo and SWI-Prolog are optional reasoning engines
behind typed protocols; neither is required for deterministic operation.

Implementation status: the alpha implements the Python runtime and deterministic planner, the Clingo
`PlannerBackend`, and the SWI-Prolog `ReasonerBackend`. Python is the default and fallback. The
Clingo executable may come from `fetech[logic]` or an explicitly configured path; SWI-Prolog remains
an explicitly installed system dependency.

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

## Language responsibilities

### Python

Python is required and authoritative. It owns:

- versioned Pydantic contracts and capability registry validation;
- URL normalization, DNS pinning, redirect checks, authorization, approvals, and budgets;
- per-hop redirect policy, redirect-loop detection, and separate wire/decompressed transfer budgets;
- deterministic classification and the safe baseline planner;
- HTTP, browser, API, document, media, archive, cache, and storage adapters;
- artifact normalization, quality assessment, provenance events, and result statuses;
- SDK, CLI, REST, SSE, MCP, SQLite/Postgres metadata, and CAS interfaces;
- validation of every Clingo answer set and Prolog solution.

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
[capability catalogue](capability-catalog.md).
