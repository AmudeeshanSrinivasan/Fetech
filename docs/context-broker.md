# Bounded context broker

Fetech keeps repository structure, runtime history, and curated decisions in separate evidence
planes. `ContextBroker` selects only the planes relevant to a question and returns one typed
`ContextBundle`; it never loads an entire graph, repository, or Obsidian vault.

## Evidence planes

| Plane | Location | Authority | Retrieval |
| --- | --- | --- | --- |
| Repository architecture | `graphify-out/graph.json` | Repository source | Budgeted Graphify query followed by exact source windows |
| Runtime provenance | Configured daemon `runtime_graph_path` | SQLite event ledger | Budgeted Graphify query over the disposable runtime projection |
| Decisions and history | Explicitly configured QMD vault/index | Curated note and its provenance links | Lexical QMD query, at most three selected notes by default |
| Exact source | Repository-scoped files | Source file at the returned line | Bounded five-line window, never an unrestricted file read |

The runtime graph is not the repository graph and is never written under `graphify-out/`. Its graph
metadata says `authoritative = false` and identifies the event ledger as authority. Runtime event
nodes retain sanitized payloads, event/run identifiers, timestamps, actors, and `ledger://` source
locations. Projection writes are atomic, and the gateway serializes concurrent rebuilds so an older
snapshot cannot overwrite a newer one.

## Deterministic selection

No model is needed to route context. Bounded lexical signals select one or more needs:

- `code_architecture` queries the repository graph;
- `runtime_history` queries the runtime provenance graph;
- `decision_history` queries the configured QMD index;
- an ambiguous question defaults to code plus decision retrieval.

Only selected providers execute. A complete miss is retried once with a simplified bounded query,
then falls back to exact repository search. A code-graph result is marked `verified` only when its
reported line window still contains a question or graph-node term. Stale line locations therefore
cannot masquerade as confirmation; the broker performs a new exact search and leaves the stale graph
result unverified.

## Budgets and result contract

The default hard limits remain:

- repository and runtime Graphify queries: 1,200 tokens combined;
- QMD: at most 1,200 tokens and three selected notes;
- exact source: at most 2,000 tokens;
- complete selected excerpts: 4,000 tokens by default;
- explicit per-request ceiling: 8,000 tokens.

These are ceilings, not quotas. When code verification is selected, up to half the requested total
is reserved for exact source, within the 2,000-token source ceiling. If both graphs are selected,
they share the Graphify budget. Results are trimmed before return so `token_usage.total` and
`estimated_tokens` do not exceed `token_budget`.

Each source carries an excerpt SHA-256, freshness, provenance, selected graph nodes/paths, source
locations, and verification flag. Deduplication uses the source locator plus excerpt hash.
`provider_reports` always contains `code_graph`, `runtime_graph`, `qmd`, and `exact_source` outcomes,
distinguishing `SUCCEEDED`, `SKIPPED`, `EMPTY`, `UNAVAILABLE`, `TIMED_OUT`, `OUTPUT_LIMIT`, and
`FAILED`. Provider stderr and private prompt content are not copied into reports.

`freshness` on the bundle is the oldest available timestamp among selected evidence. The
`contradictions` field remains conservative: Fetech does not infer a contradiction merely because
two different excerpts exist.

## Interfaces

The same `ContextBundle` is available from:

- `await FetechClient.context(question, token_budget=...)`;
- `fetech context QUESTION [--runtime-graph PATH] [--vault PATH] [--tokens N]`;
- `POST /v1/context/search`;
- MCP `get_context`.

The daemon and MCP server bind the broker to the gateway's configured runtime graph. QMD access is
disabled unless `FETECH_OBSIDIAN_VAULT` or an explicit SDK/CLI vault is supplied. No context command
writes to Obsidian.

## Acceptance benchmark

`benchmarks/context-tasks.yaml` is the checked-in 100-task acceptance corpus. It contains 50 code,
20 runtime, 20 decision, and 10 cross-plane questions over a tracked repository corpus larger than
5,000 words. Suite loading verifies cardinality, unique questions, deterministic routing, evidence
expectations, and the full-document baseline before any provider is invoked.

Run the provider-independent structural gate with:

```bash
uv run python scripts/run_context_benchmark.py --validate-only
```

Run the measured benchmark against the current code graph and configured runtime graph with:

```bash
uv run python scripts/run_context_benchmark.py
```

Pass `--vault PATH --qmd-index NAME` only for an explicitly selected, already indexed decision
vault. Generated JSON and Markdown reports live under ignored `runtime-data/` by default. They
record task IDs, question hashes, per-task token counts, expected-evidence matches, provider
statuses, omitted candidates, and fallback reasons; questions, answers, excerpts, and provider
stderr are not copied into the report.

The harness enforces the 70% median token-reduction, 4,000-token bundle, 95% evidence-recall,
complete lineage, and zero broad-vault-return targets. Answer correctness is intentionally separate:
`--answer-evaluations FILE` accepts only a complete schema-2.0 set of boolean full-context and broker
outcomes bound to the exact suite, source commit, generation protocol, and blinded review packet.
Without that independent evaluation, the correctness gate is `NOT_MEASURED` and the report is
`INCOMPLETE`; evidence recall is never relabeled as answer correctness. Use `--enforce-targets` only
when every gate must pass. The complete operator/reviewer handoff is documented in
[`context-answer-evaluation.md`](context-answer-evaluation.md).

The full-vault-load observation covers material returned to `ContextBundle` and the three-note
ceiling. It does not claim visibility into a provider's private indexing implementation.
