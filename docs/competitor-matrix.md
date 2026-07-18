# Competitor and adjacent-runtime matrix

Research snapshot: **2026-07-17**

Released Fetech baseline: **v0.3.0a0**, tag commit `9a5da4dca170`

Candidate scope checked here: **unreleased v0.4.0a0 implementation**

This document positions Fetech against a deliberately small set of actively documented,
open-source acquisition, crawling, extraction, and archival runtimes. It is not a performance
benchmark and does not support a claim that Fetech is the first, most complete, or best runtime.

## Method and interpretation

- Only first-party project documentation, repositories, and license files were accepted as
  supporting evidence.
- The comparison describes documented scope, not every feature that may exist in source,
  third-party extensions, hosted products, or unreleased branches.
- “Not established” means the reviewed official material did not establish an equivalent
  capability. It does **not** mean the project cannot implement it or that an extension does not
  exist.
- Hosted and open-source editions are kept separate when the project does not publish a precise
  parity map.
- No competitor was installed, load-tested, security-audited, or run against Fetech’s conformance
  corpus for this review. Reliability, extraction quality, throughput, and total cost are therefore
  unranked.
- License labels reproduce the upstream project’s current statements. This is an engineering
  inventory, not legal advice; modified licenses and mixed-license repositories require review
  before redistribution.

Fetech’s own baseline is taken from its
[frozen capability catalogue](capability-catalog.md),
[v0.3 conformance report](v0.3-authentication-foundation.md),
[v0.4 candidate conformance report](v0.4-conformance.md), and
[Apache-2.0 license](../LICENSE). The tagged release contains 119/155 paths. The local v0.4
candidate adds 36 importable native or typed optional paths for 155/155, but it is not
credited as a published release, audited production runtime, or proof that optional tools and
connectors are installed.

## Scope matrix

| Project | Officially checked scope | Material overlap with Fetech | Different or not established in the checked scope | Upstream license statement |
| --- | --- | --- | --- | --- |
| **Fetech v0.3.0a0 + unreleased v0.4.0a0 candidate** | A Python SDK, CLI, REST daemon, and MCP surface over deterministic planning, policy checks, HTTP/browser/crawl acquisition, origin-scoped authentication, structured API/feed normalization, bounded document/archive subprocesses, bounded media tools/providers, built-in bounded yt-dlp metadata and exact-host Wayback connectors, immutable validated snapshots, typed artifacts, CAS, and an append-only event ledger. The [v0.3 report](v0.3-authentication-foundation.md) records 119 published paths; [v0.4 conformance](v0.4-conformance.md) records 36 candidate paths. | Reference baseline. Its distinguishing design target is one policy/result/provenance contract across independently implemented acquisition engines. | v0.4 is not tagged or published. Package metadata identifies `0.4.0a0`, but clean release-commit distributions/checksums, release-commit Linux/systemd evidence, complete artifact-bound optional-tool/service smoke, legal review of the exact model bundle and explicit NVIDIA/pypdfium2 LicenseRefs, brokered yt-dlp egress, broader parser fuzzing, total storage lifecycle controls, and competitor-scale throughput remain unproven. | [Apache-2.0](../LICENSE). |
| **Scrapy** | A Python crawling and scraping framework with an execution engine, scheduler, downloader, spiders, item pipelines, selectors, feed exports, concurrency controls, retries, caching, cookies, and domain-scoped Basic authentication. See the official [overview](https://docs.scrapy.org/en/latest/index.html), [architecture](https://docs.scrapy.org/en/latest/topics/architecture.html), and [downloader middleware](https://docs.scrapy.org/en/latest/topics/downloader-middleware.html). | Strong overlap in static HTTP acquisition, crawl frontiers, deduplication, politeness, retries, extraction, and extensibility. Its persistent job state also supports pause/resume workflows. | Scrapy’s official guidance prefers reproducing dynamic data requests and points to browser download handlers when a browser is required; a browser worker is not presented as the core execution path in the checked [dynamic-content guide](https://docs.scrapy.org/en/latest/topics/dynamic-content.html). The checked core docs do not establish Fetech-equivalent immutable artifact lineage, a cross-content canonical result, or built-in REST/MCP service parity. | [BSD-3-Clause](https://github.com/scrapy/scrapy/blob/master/LICENSE). |
| **Crawlee (JavaScript and Python)** | A programmable crawling/scraping library family with unified HTTP and Playwright crawling, retries, proxy and session management, request queues, datasets, key-value storage, and persistent crawl state. See the Python [introduction](https://crawlee.dev/python/docs/introduction), [crawler choices](https://crawlee.dev/python/docs/quick-start), [storage model](https://crawlee.dev/python/docs/guides/storages), and JavaScript [session management](https://crawlee.dev/js/docs/3.12/guides/session-management). | Broad execution-plane overlap: HTTP/browser selection, recursive crawling, concurrency, sessions/cookies, request routing, failure handling, and pluggable storage. | Crawlee is centered on developer-supplied request handlers and scraper logic. The checked docs do not establish a frozen cross-family capability registry, registered API/feed normalizers, policy-authoritative planning, or immutable resource-to-artifact event lineage equivalent to Fetech’s contracts. | The JavaScript project states [Apache-2.0](https://github.com/apify/crawlee/blob/master/LICENSE.md); the Python distribution also states [Apache-2.0](https://pypi.org/project/crawlee/). |
| **Crawl4AI** | A Python, browser-oriented crawler and scraper producing clean Markdown and structured extraction via CSS, XPath, or optional models. Official docs cover [core scope](https://docs.crawl4ai.com/), [bounded deep crawling](https://docs.crawl4ai.com/core/deep-crawling/), [authentication hooks](https://docs.crawl4ai.com/advanced/hooks-auth/), [session reuse](https://docs.crawl4ai.com/advanced/session-management/), and a self-hosted Docker API. | Strong overlap in dynamic acquisition, configurable crawling, page interactions, session reuse, Markdown generation, structured page extraction, caching, and optional model assistance. | The checked docs focus on web pages and LLM-ready extraction. They do not establish Fetech-equivalent registered API/feed families, authorization-independent policy authority, immutable event-ledger provenance, or typed partial results across heterogeneous content families. | The upstream [license file](https://github.com/unclecode/crawl4ai/blob/main/LICENSE) contains Apache License 2.0 text **plus a project-added attribution requirement** for distributions, publications, public uses, websites, and CLI output. It should not be recorded as an unmodified SPDX `Apache-2.0` dependency without legal review. |
| **Firecrawl** | An API-oriented web data system whose official surface includes search, scrape, crawl, map, browser interaction, Markdown/HTML/JSON output, screenshots, caching, and document parsing. See its [product introduction](https://docs.firecrawl.dev/introduction), [scrape API](https://docs.firecrawl.dev/api-reference/endpoint/scrape), and [document parsing](https://docs.firecrawl.dev/features/document-parsing). | Broad product-surface overlap in agent-facing web acquisition, dynamic interaction, crawling, structured page extraction, document conversion, API/SDK access, and MCP integration. | The repository explicitly says its hosted cloud has additional features, but the checked material does not provide a feature-by-feature [open-source versus cloud](https://github.com/firecrawl/firecrawl#open-source-vs-cloud) parity map. Hosted API documentation is therefore not evidence that every listed capability ships in the self-hosted core. The checked sources also do not establish Fetech-equivalent deterministic plan replay or immutable resource/artifact lineage. | The main repository is [primarily AGPL-3.0](https://github.com/firecrawl/firecrawl/blob/main/LICENSE); upstream states that SDKs and some UI components use MIT. The server must remain a separately deployed optional connector rather than an Apache-core dependency unless a later legal review establishes another compatible path. |
| **Apache Nutch** | A mature, highly extensible, Hadoop-backed batch crawler with pluggable fetching, parsing, scoring, and indexing. The official site documents [scale and plugins](https://nutch.apache.org/); its API documents HTTP/HTTPS and authentication protocols, RSS/Atom parsing, Tika-backed document parsing, and ZIP parsing in the [plugin catalogue](https://nutch.apache.org/documentation/javadoc/api/index.html). | Strong overlap in large crawl frontiers, URL filtering/normalization, protocol adapters, robots handling, authentication, feed/document parsing, and extensible acquisition. | Nutch is oriented toward batch crawling and search-index production rather than a per-request canonical fetch result. Its [security guidance](https://nutch.apache.org/documentation/security) says the legacy REST service lacked authentication/authorization and was removed in Nutch 1.23. The checked scope does not establish Fetech-equivalent SDK/REST/MCP parity, policy-safe public daemon defaults, or artifact-level event lineage. | [Apache-2.0](https://nutch.apache.org/download/). |
| **Browsertrix Crawler** | A single-container, high-fidelity browser crawler for web archiving. It runs parallel Brave/Puppeteer pages, supports scoped seeds, custom behaviors, screenshots, browser profiles and login, and produces WARC/WACZ captures. See the official [crawler overview](https://crawler.docs.browsertrix.com/), [outputs](https://crawler.docs.browsertrix.com/user-guide/outputs/), and [replay QA](https://crawler.docs.browsertrix.com/user-guide/qa/). | Strong overlap in browser execution, bounded crawl scope, authenticated browser state, screenshots, capture metadata, deduplication, archival outputs, and post-crawl quality checks. It remains a relevant archive/snapshot service candidate. | Its checked scope is archival capture and replay fidelity, not general API/feed normalization or a universal typed acquisition result. WARC/WACZ capture and replay QA remain richer than Fetech’s current snapshot records, while Fetech’s policy/structured-API contracts address a different layer. | [AGPL-3.0-or-later](https://github.com/webrecorder/browsertrix-crawler#license). It must remain separately deployed if connected to the Apache-licensed core. |

## Engineering conclusions

1. **Do not publish a “first universal open-source runtime” claim from this matrix.** The selected
   projects expose broad, overlapping functionality through different product boundaries, and this
   review neither exhausts the market nor runs cross-project conformance tests.
2. **Fetech’s credible distinction is architectural, not a raw feature-count victory.** Its current
   differentiator is the attempt to place deterministic policy, budgets, typed failures, normalized
   artifacts, and provenance around multiple acquisition families. The 155-entry catalogue is an
   internal conformance inventory, not a directly comparable competitor score.
3. **Scrapy, Crawlee, and Apache Nutch are potential engine or design references.** Their permissive
   upstream licenses are compatible candidates for technical evaluation, but dependency,
   transitive-license, maintenance, and security reviews are still required.
4. **Crawl4AI needs explicit license review.** Its license file adds an attribution condition after
   the Apache 2.0 text, so automated scanners that report only `Apache-2.0` would lose material
   information.
5. **Firecrawl and Browsertrix must remain service boundaries under current policy.** Their AGPL
   server code should not be bundled into Fetech’s Apache distribution. Scoped, separately deployed
   connectors can still be evaluated.
6. **Browsertrix is complementary rather than a like-for-like replacement.** Its WARC/WACZ and
   replay-QA depth is particularly relevant to v0.4 archive design, while Fetech supplies a broader
   request, policy, normalization, and provenance contract.

## Evidence ledger

### Supporting sources

- **Fetech:** [capability catalogue](capability-catalog.md),
  [v0.3 conformance](v0.3-authentication-foundation.md),
  [v0.4 candidate conformance](v0.4-conformance.md), [architecture](architecture.md), and
  [license](../LICENSE).
- **Scrapy:** [official documentation](https://docs.scrapy.org/en/latest/index.html),
  [architecture](https://docs.scrapy.org/en/latest/topics/architecture.html),
  [dynamic-content guidance](https://docs.scrapy.org/en/latest/topics/dynamic-content.html),
  [security guidance](https://docs.scrapy.org/en/latest/topics/security.html), and
  [license](https://github.com/scrapy/scrapy/blob/master/LICENSE).
- **Crawlee:** [Python introduction](https://crawlee.dev/python/docs/introduction),
  [Python storage guide](https://crawlee.dev/python/docs/guides/storages),
  [JavaScript session guide](https://crawlee.dev/js/docs/3.12/guides/session-management), and
  [JavaScript license](https://github.com/apify/crawlee/blob/master/LICENSE.md).
- **Crawl4AI:** [official documentation](https://docs.crawl4ai.com/),
  [deep crawling](https://docs.crawl4ai.com/core/deep-crawling/),
  [hooks and authentication](https://docs.crawl4ai.com/advanced/hooks-auth/),
  [session management](https://docs.crawl4ai.com/advanced/session-management/),
  [self-hosting](https://docs.crawl4ai.com/core/self-hosting/), and
  [license](https://github.com/unclecode/crawl4ai/blob/main/LICENSE).
- **Firecrawl:** [official introduction](https://docs.firecrawl.dev/introduction),
  [scrape API](https://docs.firecrawl.dev/api-reference/endpoint/scrape),
  [document parsing](https://docs.firecrawl.dev/features/document-parsing),
  [open-source repository boundary](https://github.com/firecrawl/firecrawl#open-source-vs-cloud),
  and [license](https://github.com/firecrawl/firecrawl/blob/main/LICENSE).
- **Apache Nutch:** [official project site](https://nutch.apache.org/),
  [plugin/API catalogue](https://nutch.apache.org/documentation/javadoc/api/index.html),
  [security guidance](https://nutch.apache.org/documentation/security), and
  [license statement](https://nutch.apache.org/download/).
- **Browsertrix Crawler:** [official documentation](https://crawler.docs.browsertrix.com/),
  [output formats](https://crawler.docs.browsertrix.com/user-guide/outputs/),
  [replay QA](https://crawler.docs.browsertrix.com/user-guide/qa/), and
  [repository/license](https://github.com/webrecorder/browsertrix-crawler).

### Checked but not used as supporting evidence

- [Firecrawl hosted API reference](https://docs.firecrawl.dev/api-reference/introduction) was
  inspected but was not used to infer self-hosted feature parity.
- The Crawl4AI changelog’s license summary was checked, but the
  [current license text](https://github.com/unclecode/crawl4ai/blob/main/LICENSE) is authoritative
  for this matrix.
- [Heritrix](https://github.com/internetarchive/heritrix3) was reviewed as an archival crawler but
  excluded to keep the comparison bounded; Apache Nutch and Browsertrix already represent the batch
  and high-fidelity archival ends of the selected set.

## Remaining uncertainty

- Upstream scope and licenses can change after the snapshot date.
- Firecrawl does not expose a complete, current open-source/cloud parity table in the checked
  sources.
- Crawl4AI’s extra attribution clause requires legal interpretation; this document intentionally
  avoids assigning it a plain SPDX identifier.
- No reviewed project publishes a manifest mapped one-to-one onto Fetech’s 155 internal capability
  IDs. A defensible numeric comparison would require an independent rubric, pinned versions,
  hermetic fixtures, security tests, and maintainer review.
