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

## v0.4 conformance state

The v0.4 set is cardinality-locked at 36 entries: 14 document/file paths, 11 media paths, and
11 cache/snapshot paths. Every path has an importable Apache-compatible core implementation or a
typed optional boundary. Native and optional are availability classifications, not permission:
Python still owns destination policy, authentication scope, resource budgets, artifact admission,
and provenance.

Hostile document and archive bytes cross ephemeral bounded Python worker processes. External OCR and
media tools run with fixed argument vectors, wall-time, output, file/CPU, and Linux-only
best-effort address-space limits. Live YouTube metadata and Internet Archive acquisition have
built-in optional yt-dlp and Wayback paths; other live media and snapshot services remain injected
protocols. Worker and provider outputs are revalidated and unexpected exceptions are sanitized.
Raw publisher artifacts remain parents of normalized artifacts, and archive/cache URLs never
replace the original authority URL. Development subprocesses are not an OS sandbox. Linux required
mode supplies the fail-closed boundary for the covered document, archive, image, offline-browser,
and native-media workers; release-commit Linux/systemd evidence remains a publication gate.
Primary HTTP and Wayback use shared request admission. Local yt-dlp uses process-level shared
admission in development, while required mode refuses it until its multi-host traffic has brokered
egress.

### Document and file capability evidence

The document-worker request protocol contains acquired bytes, a path suffix, a canonical capability,
and bounded numeric limits; it intentionally omits the host, query, credentials, opaque
authentication reference, and caller target path. An enabled preferred Docling parse adds one
validated local model-artifact directory and an independently configured expected bundle SHA-256.
The exact `docling-slim[convert-core,format-pdf,models-local]==2.113.0` dependency runs offline with
remote services, plugins, implicit downloads, OCR, enrichments, and generated images disabled. The
v0.4 reference is
`docling-project/docling-layout-heron@8f39ad3c0b4c58e9c2d2c84a38465abf757272d8`
with canonical bundle SHA-256
`e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76`.
Non-success, timeout/error, sparse, and incomplete conversions are rejected. The document worker
installs a Python audit hook before Docling imports that denies Python-level network/process
operations, filesystem mutation, and reads outside reviewed interpreter/package/model roots; the
Pillow image worker applies the same policy after loading reviewed decoder plugins. Native
extensions can bypass these hooks, native media tools do not receive them, and no child has a
kernel-enforced filesystem or network boundary in the core runtime.
Structured text parsers reject duplicate JSON keys and XML DTD/entity declarations; ZIP handling
rejects traversal, links, devices, nested archives, excessive members, expansion, and compression
ratios. Office and PDF engines are optional `fetech[documents]` dependencies.

| Capability | Status | Accepted evidence and owner path |
| --- | --- | --- |
| <a id="pdf"></a>`pdf` | optional | PDF signature → bounded document worker → `pypdf`; textless pages produce `NEEDS_OCR` unless a configured PDF OCR provider returns valid page-located text |
| <a id="scanned-pdf"></a>`scanned_pdf` | optional | Textless PDF → checked-only `NEEDS_OCR`, or bounded schema-validated output from an injected PDF OCR provider |
| <a id="docx"></a>`docx` | optional | Valid OOXML Word container → bounded `python-docx` parser |
| <a id="pptx"></a>`pptx` | optional | Valid OOXML presentation container → bounded `python-pptx` parser with slide locators |
| <a id="xlsx"></a>`xlsx` | optional | Valid OOXML workbook → bounded read-only `openpyxl` parser with sheet/row locators |
| <a id="csv"></a>`csv` | native | Bounded UTF-8/UTF-8-SIG CSV parser with row locators |
| <a id="txt"></a>`txt` | native | Bounded text normalization with stable line locators |
| <a id="markdown"></a>`markdown` | native | Bounded text-preserving Markdown normalization; fetched instructions remain untrusted |
| <a id="json-file"></a>`json_file` | native | Bounded JSON parser with duplicate-key, depth, number, and output checks |
| <a id="xml-file"></a>`xml_file` | native | DTD/entity-free bounded XML parser with element locators |
| <a id="zip-archive"></a>`zip_archive` | native | HTTP → bounded-worker `ArchiveAdapter`; immutable member artifacts retain the raw archive parent |
| <a id="github-raw"></a>`github_raw` | native | Exact `https://raw.githubusercontent.com` origin and bounded repository path → document router; GitHub remains publisher authority |
| <a id="git-lfs"></a>`git_lfs` | optional | Git LFS v1 pointer → configured exact-origin resolver; Python rechecks result type, origin, declared size, SHA-256, byte limit, and deadline |
| <a id="dataset-file"></a>`dataset_file` | native | Signature-first bounded routing to a registered file handler |

### Media capability evidence

Native image, subtitle, podcast, and EXIF readers are bounded parsers over already acquired bytes.
Tesseract, FFprobe, and FFmpeg run through reviewed subprocess boundaries. Live transcription
remains an injected provider protocol. Live YouTube lookup uses the built-in optional
`YTDLPMetadataWorker`, while pre-acquired yt-dlp-info documents can still be normalized offline.
Provider and worker return types, sizes, fields, finite numeric values, media types, source identity,
and consumed budgets are checked again by Python.

| Capability | Status | Accepted evidence and owner path |
| --- | --- | --- |
| <a id="image"></a>`image` | optional | Bounded header checks plus a full decode in `PillowImageValidationWorker` from `fetech[media]` → normalized image artifact |
| <a id="image-metadata"></a>`image_metadata` | optional | Bounded PNG/GIF/JPEG/TIFF/WebP header checks confirmed by the isolated Pillow decoder → dimensions and encoding fields |
| <a id="image-ocr"></a>`image_ocr` | optional | Acquired image → bounded `TesseractOCRWorker`; missing binary is `DEPENDENCY_MISSING` |
| <a id="screenshot-to-text"></a>`screenshot_to_text` | optional | Acquired screenshot → same bounded OCR boundary |
| <a id="video-metadata"></a>`video_metadata` | optional | Acquired media → bounded `FFprobeWorker` with schema-validated JSON output |
| <a id="audio-metadata"></a>`audio_metadata` | optional | Native bounded WAV header or bounded FFprobe for other codecs |
| <a id="transcript"></a>`transcript` | optional | Native bounded VTT/SRT/text parsing or injected schema-validated `TranscriptProvider` |
| <a id="youtube-metadata"></a>`youtube_metadata` | optional | Sanitized pre-acquired yt-dlp info JSON or built-in bounded `YTDLPMetadataWorker` from `fetech[media]`; exact HTTPS/public-DNS policy and URL-redacted metadata |
| <a id="podcast-feed"></a>`podcast_feed` | native | DTD/entity-free RSS parser with byte, XML-node, depth, and episode bounds; enclosure URLs are observed, never fetched automatically |
| <a id="thumbnail"></a>`thumbnail` | optional | Acquired video → bounded `FFmpegThumbnailWorker` |
| <a id="exif-metadata"></a>`exif_metadata` | native | Bounded TIFF/EXIF reader with GPS, owner, serial, user-comment, and MakerNote fields omitted |

### Cache, snapshot, and archive capability evidence

Native storage strategies use authentication-partitioned `CacheKey` values, immutable CAS bodies,
sanitized metadata, conditional validators, and deterministic freshness/stale-while-revalidate
semantics. The Internet Archive path has a built-in exact-host connector; other connector paths are
optional because they require an operator-provided service that reapplies URL policy and
byte/deadline limits. Cache keys include URL, representation,
authentication scope, policy profile, language, region, parser version, and relevant `Vary` values.
A cache hit is never treated as authorization or as independent evidence of truth.

Previous-snapshot and configured archive alternatives are tried after policy but before HTTP and
fall through on miss, failure, or checked-only quality. Local writes happen after extraction and
admit only an accepted artifact of the capability's exact representation. Connector bodies pass the
ordinary text/binary quality checks; checked-only responses are recorded as unsuccessful snapshots
and do not stop fallback acquisition.

| Capability | Status | Accepted evidence and owner path |
| --- | --- | --- |
| <a id="search-snippet-cache"></a>`search_snippet_cache` | native | Configured producer's validated `search_results` artifact, including bounded snippets → partitioned `SnapshotStore` |
| <a id="search-cache"></a>`search_cache` | native | Configured producer's validated `search_results` artifact → partitioned `SnapshotStore` |
| <a id="search-engine-cache-adapter"></a>`search_engine_cache_adapter` | optional | Configured policy-aware `SnapshotConnector` |
| <a id="alternate-search-cache-adapter"></a>`alternate_search_cache_adapter` | optional | Independently configured policy-aware `SnapshotConnector` |
| <a id="web-archive"></a>`web_archive` | optional | Configured archive connector; original URL remains source authority |
| <a id="internet-archive-snapshot"></a>`internet_archive_snapshot` | native | Explicit public request → bounded availability lookup on exact `archive.org` → exact-source `web.archive.org` raw capture; DNS and every redirect are policy-checked |
| <a id="local-snapshot"></a>`local_snapshot` | native | Acquired source/derived artifact → immutable local snapshot metadata |
| <a id="previous-successful-snapshot"></a>`previous_successful_snapshot` | native | Latest integrity-verified successful record in the exact cache partition |
| <a id="cdn-copy"></a>`cdn_copy` | optional | Configured policy-aware connector; HTTPS snapshot locator and byte hash required |
| <a id="browser-cache"></a>`browser_cache` | native | Planner-produced accepted `rendered_html` → exact representation/parser partition |
| <a id="rag-document-cache"></a>`rag_document_cache` | native | Planner-produced accepted `clean_text` → exact representation/parser partition |

See [v0.4 conformance](v0.4-conformance.md) for worker protocols, cache behavior, failure semantics,
and the release gate.

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
