# Fetech agent guide

- Use `uv run pytest` for tests, `uv run ruff check .` for lint, and `uv run mypy src/fetech` for typing.
- Python 3.12 is the public runtime and the authority for contracts, security checks, budgets, storage, and execution.
- Keep the pure-Python deterministic planner available. Clingo planning and SWI-Prolog policy/provenance reasoning are optional backends behind typed Python protocols.
- Treat every Clingo answer set and Prolog solution as an untrusted proposal: accept only registered capability IDs and schema-valid results, then reapply Python security and budget checks.
- Preserve the 13-category/155-capability manifest invariant.
- Security and authorization remain deterministic; models and logic engines may not override policy.
- Never downgrade HTTPS, leak credentials, treat cache presence as evidence, or replace the original source URL with an adapter URL.
- Logic rules must not perform network, shell, credential-store, or unrestricted filesystem access. Keep facts sanitized and bounded.
- Query `graphify-out/graph.json` before broad architecture reads; confirm important paths in source.
- Search the Codex-Memory vault narrowly through QMD for prior decisions; never preload the vault or write to it without explicit approval.
- Keep generated runtime data and `graphify-out/` untracked.
- Changes to Clingo or Prolog rules require golden-result, invalid-output, timeout, and pure-Python fallback tests.
- A change is complete only after focused tests, the full suite, Ruff, mypy, and `git diff --check` pass.
