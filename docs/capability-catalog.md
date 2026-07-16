# Capability catalogue

The machine-readable source of truth is `capabilities/manifest.yaml`. It contains exactly 13
categories and 155 canonical capability IDs. A capability may be an executable operation, negotiated
transport feature, variant generator, extractor, format handler, detector, policy, connector, or
storage strategy. Only schedulable kinds become independent plan nodes; every kind remains observable
and testable.

The catalogue is language-neutral, while execution ownership is explicit:

- Python adapters own and enforce executable capability paths. Registration does not imply local
  availability: the conformance overlay labels each entry `native`, `optional`, or `planned`.
- Clingo may reason over manifest facts such as `capability/1`, dependencies, risk, availability,
  cost, and requested outputs to propose a feasible or optimized plan.
- Prolog may reason over policy, eligibility, aliases, provenance, and explanation relationships.
- Neither a Clingo predicate nor a Prolog predicate creates an additional capability. The canonical
  IDs and the 13/155 cardinality remain fixed until the manifest itself is deliberately versioned.
- Python rejects any logic result containing an unknown alias, unavailable implementation, forbidden
  capability, dependency cycle, unreserved budget, or schema violation.

| Category | Count | Closure |
| --- | ---: | --- |
| URL intake and canonicalisation | 2 | v0.1 |
| Security and policy | 8 | v0.1 |
| Discovery and crawling | 12 | v0.2 |
| HTTP transport and redirects | 21 | v0.1 |
| URL alternatives | 13 | v0.2 |
| Reader extraction | 10 | v0.1 |
| Browser rendering | 15 | v0.2 |
| Authentication and private sessions | 10 | v0.3 |
| Structured APIs and feeds | 13 | v0.3 |
| Documents and files | 14 | v0.4 |
| Images, audio, video, and media | 11 | v0.4 |
| Cache, snapshots, and archives | 11 | v0.4 |
| Validation, provenance, and observability | 15 | v0.1 |
| **Total** | **155** | **v0.4** |

Run `fetech capabilities` for the expanded runtime entries, including adapter ownership, aliases,
risk, reference, test identifier, and local dependency availability.

## v0.1 conformance state

The v0.1 set is cardinality-locked at 56 entries. The current alpha exposes 56 implementation paths:
51 native and five optional (HTTP/3 through an HTTP/3-enabled curl, `mozilla_readability`,
`trafilatura`, the explicitly configured `jina_reader`, and offline Playwright reader mode).
`closure_ready` is true. An HTTP/1.1 or HTTP/2 response does not prove HTTP/3 support;
the optional path requires `--http3-only` and verifies the negotiated protocol. In-process
browser extraction would violate the worker-isolation requirement, so browser reader mode runs in a
bounded offline subprocess and aborts every network request.

Policies, detectors, and negotiated transport features run inside their owning stage and emit a
`CapabilityOutcome`; they do not become artificial DAG nodes. Per-run statuses are `APPLIED`,
`OBSERVED`, `NOT_APPLICABLE`, `BLOCKED`, `DEPENDENCY_MISSING`, and `FAILED`.

## Logic projections

The optional logic backends receive generated, bounded projections of the manifest rather than
parsing YAML directly. Python normalizes aliases to canonical IDs before facts are generated. The
Clingo adapter currently proves the complete safe Python candidate plan against dependency,
availability, and deny constraints; later optimization rules may reduce a candidate set only after
shared conformance tests establish equivalent fallback coverage.

```text
manifest.yaml
  -> Python registry validation
  -> Clingo planning facts or Prolog reasoning facts
  -> bounded answer/solution
  -> Python schema and policy validation
  -> FetchPlan or typed fallback
```

Generated facts are disposable build/runtime artifacts. `capabilities/manifest.yaml` remains the sole
capability source of truth, and the Python planner remains the conformance baseline.
