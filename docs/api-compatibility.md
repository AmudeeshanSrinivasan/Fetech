# Beta API compatibility

Fetech freezes its Beta `v1` public surface in `compatibility/beta-v1.json`. The snapshot is
deterministic and contains:

- canonical serialization schemas and hashes for every public contract;
- top-level Python exports plus `FetechClient` and `FetchHandle` constructor/method signatures;
- REST methods, `/v1` paths, parameters, request bodies, response status codes and schemas;
- CLI commands, arguments, options, defaults, environment bindings and parameter constraints;
- MCP tool names, input schemas and result annotations.

Package version and generated timestamps are deliberately absent. A package version bump does not
change the `v1` protocol, and nondeterministic metadata cannot authorize a compatibility decision.
Descriptions and help prose are also outside this machine gate; invocation and data semantics are
inside it.

## Fail-closed check

Run:

```bash
uv run python scripts/check_beta_compatibility.py
```

The checker rebuilds all four interface surfaces without starting the daemon, opening the ledger,
or performing network activity. It compares JSON types, fields, list order and values exactly. A
removed or changed field is blocked, and an additive change is also blocked until it is reviewed.
This conservative behavior ensures that CI detects breaking changes; it does not claim to decide
whether every difference is semantically breaking.

The check requires the `server` and `mcp` extras because those optional interfaces must be present
to freeze their schemas. A missing, malformed, oversized, wrong-version or mismatched baseline
fails closed. GitHub CI runs the checker after the frozen dependency installation and before the
test suite.

## Intentional update

Only refresh the baseline after reviewing the exact contract, SDK, REST, CLI and MCP diff and
confirming either backward compatibility or an approved version/migration change:

```bash
uv run python scripts/check_beta_compatibility.py --write
uv run python scripts/check_beta_compatibility.py
uv run pytest tests/test_beta_compatibility.py
git diff -- compatibility/beta-v1.json
```

Commit the implementation, migration fixtures, compatibility rationale and regenerated baseline in
the same change. Never use `--write` merely to make CI green. Changes that remove fields, narrow
accepted values, add required inputs, change defaults, rename operations, or alter response shapes
require an explicit contract-version decision.

## Migration fixtures

`compatibility/fixtures/v0.4.0a0-contracts.json` preserves representative pre-Beta documents for
`FetchRequest`, `FetchPlan`, `Artifact` and `FetchResult`. Each omits `schema_version`, must normalize
to `1.0`, and must survive canonical serialization and validation. The same models reject an
explicit unknown version. These fixtures cover the supported omission migration; they do not
authorize arbitrary old or future shapes.

The baseline is a regression control, not proof that every external client remains compatible.
Release review still needs behavioral conformance, migration tests, dependency locking and human
assessment of intentional changes.
