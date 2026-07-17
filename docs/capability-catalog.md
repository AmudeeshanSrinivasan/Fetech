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

## v0.2 conformance state

The v0.2 set is cardinality-locked at 40 entries across discovery (12), URL alternatives (13), and
browser rendering (15). The overlay reports 36 native paths and four optional paths, with no planned
gaps. Optional paths are search-provider discovery, local Playwright/Chromium, and independently
configured Puppeteer and Selenium connectors. Optional means the implementation boundary ships but
its binary or operator endpoint is not part of the Apache core installation.

Discovery is owned by a schedulable bounded-frontier operation and emits outcomes for sitemap,
robots, internal, related, pagination, next-page, category/tag, official-domain, candidate-expansion,
depth-limit, domain-limit, and search-provider behavior. URL generators run inside the candidate
stage; they do not become artificial DAG nodes. HTTPS-to-HTTP is deliberately observable as
`BLOCKED`, never as a generated URL.

The browser stage returns `rendered_html`, `visible_text`, and optional `screenshot` artifacts. Local
Playwright rendering receives acquired HTML in a bounded subprocess, enables JavaScript, blocks
service workers, runs offline, and aborts subresources. Interaction capabilities are request-driven
and bounded. Puppeteer/Selenium connectors require explicit public policy and receive the same
offline contract. See [v0.2 conformance](v0.2-conformance.md) for failure and policy semantics.

## v0.3 conformance state

The v0.3 set is cardinality-locked at 23 entries: ten authentication/private-session capabilities and
13 structured API/feed capabilities. The overlay reports 21 native and two optional paths, no
planned gaps, and `closure_ready=true`. Together with v0.1 and v0.2 this yields 119 cumulative
implementation paths.

Static API-key, bearer, cookie, and connector authentication remain observable inside the HTTP owner
stage. High-level login/OAuth/SSO/private-workspace validation and CSRF/form operations use the
schedulable auth adapter. Core `SessionProvider` implementations make `login_session` and `oauth`
native provider-backed paths. `sso` and `private_workspace` remain optional because useful execution
requires an operator-provisioned identity or workspace connector; absence fails closed and does not
make the capability planned.

The thirteen API/feed paths use one schedulable structured adapter after HTTP acquisition. Generic
JSON/XML, REST, GraphQL, RSS, Atom, sitemap, and OpenAPI paths require format/schema evidence. GitHub,
Semantic Scholar, arXiv, OpenReview, and Crossref/OpenAlex additionally require exact official
origins and recognizable response envelopes. The adapter performs bounded parsing only, preserves
the raw parent artifact and original authority URL, and never follows OpenAPI references or
pagination links automatically.

### Authentication capability evidence

The reference anchors below are the stable targets used by the manifest. “Owner path” distinguishes
an independently scheduled auth node from credential features observed inside the HTTP stage.

| Capability | Status | Importable implementation | Planner/owner path |
| --- | --- | --- | --- |
| <a id="cookie-session"></a>`cookie_session` | native | `fetech.auth.CredentialProvider` | HTTP owner; exact-origin cookie injection |
| <a id="login-session"></a>`login_session` | native | `fetech.adapters.auth.AuthAdapter` | auth node → HTTP or approved form-cookie handoff |
| <a id="oauth"></a>`oauth` | native | `fetech.adapters.auth.AuthAdapter` | auth node → HTTP; typed session and refresh providers |
| <a id="api-key"></a>`api_key` | native | `fetech.auth.CredentialProvider` | HTTP owner; exact-origin header injection |
| <a id="bearer-token"></a>`bearer_token` | native | `fetech.auth.CredentialProvider` | HTTP owner; exact-origin bearer injection |
| <a id="csrf-token"></a>`csrf_token` | native | `fetech.auth_flows.extract_csrf_token` | HTTP → auth extraction node |
| <a id="form-submit"></a>`form_submit` | native | `fetech.adapters.auth.AuthAdapter` | HTTP/CSRF → approved auth mutation node |
| <a id="sso"></a>`sso` | optional | `fetech.adapters.auth.AuthAdapter` | auth node → HTTP; configured `SessionProvider` |
| <a id="connector-auth"></a>`connector_auth` | native | `fetech.auth.CredentialProvider` | observable inside the HTTP owner |
| <a id="private-workspace"></a>`private_workspace` | optional | `fetech.adapters.auth.AuthAdapter` | private-profile auth node → HTTP; configured connector |

### Structured API and feed capability evidence

All thirteen paths are native bounded parsers owned by
`fetech.adapters.api.StructuredAPIAdapter`. The deterministic planner schedules exactly one selected
structured capability after the HTTP acquisition node.

| Capability | Accepted evidence and owner path |
| --- | --- |
| <a id="rest"></a>`rest` | JSON or XML response evidence; HTTP → structured API owner |
| <a id="graphql"></a>`graphql` | GraphQL response envelope; HTTP → structured API owner |
| <a id="json-endpoint"></a>`json_endpoint` | JSON media type or syntax; HTTP → structured API owner |
| <a id="xml-endpoint"></a>`xml_endpoint` | DTD-free XML evidence; HTTP → structured API owner |
| <a id="rss"></a>`rss` | RSS root and required feed markers; HTTP → structured API owner |
| <a id="atom"></a>`atom` | namespaced Atom feed markers; HTTP → structured API owner |
| <a id="sitemap-xml"></a>`sitemap_xml` | sitemap `urlset` or `sitemapindex`; HTTP → structured API owner |
| <a id="openapi-discovery"></a>`openapi_discovery` | bounded OpenAPI JSON/YAML document; HTTP → structured API owner |
| <a id="github-api"></a>`github_api` | exact GitHub API origin and response envelope; HTTP → structured API owner |
| <a id="semantic-scholar-api"></a>`semantic_scholar_api` | exact Semantic Scholar route and response envelope; HTTP → structured API owner |
| <a id="arxiv-api"></a>`arxiv_api` | exact arXiv API route and Atom evidence; HTTP → structured API owner |
| <a id="openreview-api"></a>`openreview_api` | exact OpenReview origin and response envelope; HTTP → structured API owner |
| <a id="crossref-openalex-api"></a>`crossref_openalex_api` | exact Crossref/OpenAlex route and response envelope; HTTP → structured API owner |

See [the v0.3 authentication and API guide](v0.3-authentication-foundation.md) for the provider
contracts, approval model, parser limits, failure semantics, and verification surface.

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
