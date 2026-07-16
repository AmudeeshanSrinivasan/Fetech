# ENMA extraction provenance

Fetech is standalone and has no ENMA runtime dependency. The initial contracts and safety invariants
were generalized from the user-owned ENMA worktree after its targeted fetch suites passed 30/30 on
2026-07-17. ENMA was not modified.

The extracted ENMA material is Python source and remains behavioral provenance for the Python
contracts, safety boundary, adapters, and test invariants listed below. Clingo and Prolog support is a
new Fetech architectural decision; it was not copied from ENMA and must not be attributed to the ENMA
files. Logic facts and rules must cite the Fetech manifest, contracts, ADRs, or ledger schema from which
they are generated.

| Source | SHA-256 |
| --- | --- |
| `schemas/fetch.py` | `202f53044a8c305592af5cc37d06d51106ed078de38f4ec1503bd748708f1658` |
| `tools/fetch_planning.py` | `b18b48ec3c2fe1f19226176653d62532bc6230a6f9cef014226565c86bc8f349` |
| `tools/web_runtime.py` | `beeb63dd0c34297b31c06c26a5af6baf99c1f45d47170e7ff759d43b7a361c69` |
| `tools/url_safety.py` | `3786229f72a0968772b056e197c7287e129474ee00aa2470d2d8fe5508f7daa4` |
| `tools/fetch_quality.py` | `8a96c52e51fb579d2e1d97ae9625a9f1692755ff8e6e4c6d4e026c871e0c4062` |
| `research/fetch/fetch_attempt_manager.py` | `5224e7ccccda476a52a0d04b0bb2e85911a6a37f822fc16ff6ead860e55d0951` |
| `research/fetch/authoritative_cache.py` | `4b03b3c3d01d842fcb81095c81549e9e9e4d71fba82177eb9a6753675136a117` |
| `research/fetch/browser_fetcher.py` | `d3c37d87c1485448a716fde409b29fff55d1874df843ec0ed77c1f0eaff5a7e9` |
| `research/fetch/official_discovery.py` | `3be5ec882c2c134e72f6dda10cfb25f11c40012d9f48866006ceecbf5b456910` |
| `core/document_parsing.py` | `ffb387e8b06c53d3712588afe23520e00de7c880f73f229a208fafe736e2a133` |
| `research/evidence_object_builder.py` | `118781eb2dc80580a696b024ccdf488b4507a99bb1197994e574f2968f213392` |

Future extraction records must identify the source language and transformation boundary. Python
ports retain source-path and SHA-256 evidence; generated Clingo facts retain the manifest version and
hash; generated Prolog facts retain the ledger/schema version and event identifiers. Generated facts,
answer sets, and solutions are derivatives rather than authoritative source records.
