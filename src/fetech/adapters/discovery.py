"""Deterministic bounded crawl frontier and discovery feature projection."""

from __future__ import annotations

import asyncio
import json
import re
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.adapters.http import HTTPAdapter
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    CrawlReport,
    DiscoveredTarget,
    FetchAttempt,
    PageState,
    PlanNode,
    QualityAssessment,
)
from fetech.search import SearchProvider
from fetech.security import PolicyBlockedError, normalize_url, sanitize_url
from fetech.storage import build_artifact
from fetech.variants import generate_variants

_LOC = re.compile(r"<loc\b[^>]*>(.*?)</loc>", re.I | re.S)


@dataclass(frozen=True)
class _FrontierItem:
    url: str
    depth: int
    parent_url: str | None
    relation: str


class DiscoveryAdapter:
    def __init__(
        self,
        http: HTTPAdapter,
        *,
        batch_size: int = 4,
        search_provider: SearchProvider | None = None,
    ) -> None:
        self.http = http
        self.batch_size = max(1, batch_size)
        self.search_provider = search_provider

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        if node.capability_id != "depth_limited_crawl":
            raise AdapterExecutionError(f"discovery adapter cannot execute {node.capability_id}")
        if not context.resources or context.latest_artifact("raw") is None:
            raise AdapterExecutionError("crawl requires an acquired root resource")
        attempt_index = len(context.attempts)
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        root = normalize_url(context.request.target)
        root_host = _site_host(root)
        maximum_pages = min(
            context.request.budget.crawl_pages,
            1 + max(0, context.request.budget.attempts - len(context.attempts)),
        )
        seen = {root}
        frontier: deque[_FrontierItem] = deque()
        targets: list[DiscoveredTarget] = [
            DiscoveredTarget(
                url=sanitize_url(root),
                depth=0,
                relation="root",
                fetched=True,
                accepted=bool(context.artifacts[-1].quality.accepted),
            )
        ]
        counters = {
            "internal": 0,
            "related": 0,
            "pagination": 0,
            "next": 0,
            "category": 0,
            "sitemap": 0,
            "variants": 0,
            "domain_blocked": 0,
            "depth_blocked": 0,
            "search": 0,
            "search_configured": 0,
        }
        default_sitemap = normalize_url(urljoin(root, "/sitemap.xml"))
        self._enqueue(
            _FrontierItem(default_sitemap, 0, root, "sitemap"),
            frontier,
            seen,
            counters,
            root_host,
            context.request.budget.crawl_depth,
        )
        await self._discover_from_latest(context, root, 0, frontier, seen, counters, root_host)
        if (
            self.search_provider is not None
            and context.request.policy_profile == "allow_search_discovery"
            and context.request.privacy_profile == "public"
            and context.request.authentication_ref is None
        ):
            counters["search_configured"] = 1
            try:
                search_results = await self.search_provider.discover(
                    root_host,
                    maximum_results=min(20, maximum_pages),
                )
            except AdapterExecutionError as exc:
                context.record_outcome(
                    "search_provider_discovery",
                    CapabilityOutcomeStatus.FAILED,
                    "discovery",
                    reason=type(exc).__name__,
                )
            else:
                for candidate in search_results:
                    before = len(frontier)
                    self._enqueue(
                        _FrontierItem(candidate, 1, root, "search"),
                        frontier,
                        seen,
                        counters,
                        root_host,
                        context.request.budget.crawl_depth,
                    )
                    counters["search"] += int(len(frontier) > before)
        elif self.search_provider is not None:
            context.record_outcome(
                "search_provider_discovery",
                CapabilityOutcomeStatus.BLOCKED,
                "discovery",
                reason="search discovery requires an explicit public, unauthenticated policy",
            )
        pages_checked = 1
        pages_fetched = 1
        pages_failed = 0
        maximum_depth = 0

        while frontier and pages_checked < maximum_pages:
            remaining_slots = min(
                self.batch_size,
                maximum_pages - pages_checked,
                context.request.budget.attempts - len(context.attempts),
            )
            if remaining_slots <= 0:
                break
            batch = [frontier.popleft() for _ in range(min(remaining_slots, len(frontier)))]
            results = await asyncio.gather(
                *(self._fetch(item, context, len(batch)) for item in batch)
            )
            for item, subcontext, error in results:
                pages_checked += 1
                self._merge_context(context, subcontext)
                maximum_depth = max(maximum_depth, item.depth)
                if error is not None or not subcontext.resources:
                    pages_failed += 1
                    targets.append(
                        DiscoveredTarget(
                            url=sanitize_url(item.url),
                            depth=item.depth,
                            parent_url=sanitize_url(item.parent_url) if item.parent_url else None,
                            relation=item.relation,
                            failure_code=type(error).__name__ if error else "empty_response",
                        )
                    )
                    continue
                pages_fetched += 1
                artifact = subcontext.latest_artifact("raw")
                accepted = bool(artifact and artifact.quality.accepted)
                targets.append(
                    DiscoveredTarget(
                        url=sanitize_url(item.url),
                        depth=item.depth,
                        parent_url=sanitize_url(item.parent_url) if item.parent_url else None,
                        relation=item.relation,
                        fetched=True,
                        accepted=accepted,
                    )
                )
                await self._discover_from_latest(
                    subcontext,
                    item.url,
                    item.depth,
                    frontier,
                    seen,
                    counters,
                    root_host,
                )

        report = CrawlReport(
            root_url=sanitize_url(root),
            targets=tuple(targets),
            pages_fetched=pages_fetched,
            pages_failed=pages_failed,
            maximum_depth_reached=maximum_depth,
            frontier_omitted=len(frontier),
        )
        encoded = json.dumps(report.model_dump(mode="json"), indent=2, sort_keys=True).encode()
        uri, digest, size = await context.cas.put(encoded)
        quality = QualityAssessment(
            page_state=PageState.OK,
            score=1.0 if pages_fetched else 0.0,
            accepted=pages_fetched > 0,
            completeness=min(1.0, pages_fetched / max(1, maximum_pages)),
        )
        summary = build_artifact(
            role="primary",
            representation="crawl_report",
            media_type="application/json",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=context.resources[0],
            extractor="builtin-crawl/0.2",
            quality=quality,
            parents=tuple(context.artifacts),
            locators=tuple(f"url:{target.url}" for target in targets),
        )
        context.artifacts.append(summary)
        context.crawl_report = report
        context.accepted = quality.accepted
        context.attempts[attempt_index] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "parser": "bounded-frontier",
                "artifact_ids": (summary.artifact_id,),
            }
        )
        self._record_outcomes(context, counters, report)

    async def _fetch(
        self,
        item: _FrontierItem,
        context: ExecutionContext,
        batch_size: int,
    ) -> tuple[_FrontierItem, ExecutionContext, BaseException | None]:
        consumed_bytes = sum(
            int(attempt.consumed_budget.get("bytes", 0)) for attempt in context.attempts
        )
        consumed_decompressed = sum(
            int(attempt.consumed_budget.get("decompressed_bytes", 0))
            for attempt in context.attempts
        )
        remaining_bytes = max(1, context.request.budget.bytes - consumed_bytes)
        remaining_decompressed = max(
            1, context.request.budget.decompressed_bytes - consumed_decompressed
        )
        budget = context.request.budget.model_copy(
            update={
                "attempts": 1,
                "bytes": max(1, remaining_bytes // max(1, batch_size)),
                "decompressed_bytes": max(
                    1, remaining_decompressed // max(1, batch_size)
                ),
            }
        )
        request = context.request.model_copy(
            update={
                "target": item.url,
                "intent": "retrieve",
                "output_requirements": ("raw_html",),
                "budget": budget,
            }
        )
        subcontext = ExecutionContext(run_id=context.run_id, request=request, cas=context.cas)
        error: BaseException | None = None
        try:
            await self.http.execute(
                PlanNode(id=f"crawl:{item.depth}", capability_id="http_get", adapter="http"),
                subcontext,
            )
        except PolicyBlockedError as exc:
            subcontext.policy_decisions.extend(exc.decisions)
            error = exc
        except (AdapterExecutionError, ValueError) as exc:
            error = exc
        return item, subcontext, error

    async def _discover_from_latest(
        self,
        context: ExecutionContext,
        page_url: str,
        depth: int,
        frontier: deque[_FrontierItem],
        seen: set[str],
        counters: dict[str, int],
        root_host: str,
    ) -> None:
        artifact = context.latest_artifact("raw")
        if artifact is None:
            return
        body = await context.cas.get(
            artifact.cas_uri,
            maximum_bytes=context.request.budget.decompressed_bytes,
        )
        if artifact.media_type in {"text/html", "application/xhtml+xml"}:
            parser = _DiscoveryParser(page_url)
            parser.feed(body.decode("utf-8", errors="replace"))
            for candidate, relation in parser.links:
                admitted = self._enqueue(
                    _FrontierItem(candidate, depth + 1, page_url, relation),
                    frontier,
                    seen,
                    counters,
                    root_host,
                    context.request.budget.crawl_depth,
                )
                if admitted:
                    counters[relation] = counters.get(relation, 0) + 1
                    counters["variants"] += max(
                        0,
                        len(
                            generate_variants(
                                candidate,
                                language=context.request.language,
                                region=context.request.region,
                            )
                        )
                        - 1,
                    )
        elif artifact.media_type in {"application/xml", "text/xml"} or page_url.endswith(".xml"):
            for match in _LOC.finditer(body.decode("utf-8", errors="replace")):
                try:
                    candidate = normalize_url(urljoin(page_url, match.group(1).strip()))
                except ValueError:
                    continue
                admitted = self._enqueue(
                    _FrontierItem(candidate, depth + 1, page_url, "sitemap"),
                    frontier,
                    seen,
                    counters,
                    root_host,
                    context.request.budget.crawl_depth,
                )
                counters["sitemap"] += int(admitted)

    @staticmethod
    def _enqueue(
        item: _FrontierItem,
        frontier: deque[_FrontierItem],
        seen: set[str],
        counters: dict[str, int],
        root_host: str,
        maximum_depth: int,
    ) -> bool:
        try:
            candidate = normalize_url(item.url)
        except ValueError:
            return False
        if candidate in seen:
            return False
        if item.depth > maximum_depth:
            counters["depth_blocked"] += 1
            return False
        if _site_host(candidate) != root_host:
            counters["domain_blocked"] += 1
            return False
        seen.add(candidate)
        frontier.append(
            _FrontierItem(candidate, item.depth, item.parent_url, item.relation)
        )
        return True

    @staticmethod
    def _merge_context(context: ExecutionContext, subcontext: ExecutionContext) -> None:
        context.resources.extend(subcontext.resources)
        context.artifacts.extend(subcontext.artifacts)
        context.attempts.extend(subcontext.attempts)
        context.capability_outcomes.extend(subcontext.capability_outcomes)
        context.policy_decisions.extend(subcontext.policy_decisions)
        context.diagnostics.extend(subcontext.diagnostics)

    @staticmethod
    def _record_outcomes(
        context: ExecutionContext,
        counters: dict[str, int],
        report: CrawlReport,
    ) -> None:
        observations = {
            "sitemap_discovery": counters["sitemap"],
            "internal_link_discovery": counters["internal"],
            "related_link_discovery": counters["related"],
            "pagination_discovery": counters["pagination"],
            "next_page_discovery": counters["next"],
            "category_tag_discovery": counters["category"],
            "candidate_url_expansion": counters["variants"],
        }
        for capability_id, count in observations.items():
            context.record_outcome(
                capability_id,
                CapabilityOutcomeStatus.OBSERVED if count else CapabilityOutcomeStatus.NOT_APPLICABLE,
                "discovery",
                count=count,
            )
        context.record_outcome(
            "robots_discovery",
            CapabilityOutcomeStatus.APPLIED,
            "discovery",
            policy_checked=True,
        )
        context.record_outcome(
            "depth_limited_crawl",
            CapabilityOutcomeStatus.APPLIED,
            "discovery",
            maximum_depth=report.maximum_depth_reached,
            blocked=counters["depth_blocked"],
        )
        context.record_outcome(
            "domain_limited_crawl",
            CapabilityOutcomeStatus.APPLIED,
            "discovery",
            blocked=counters["domain_blocked"],
        )
        context.record_outcome(
            "official_domain_discovery",
            CapabilityOutcomeStatus.OBSERVED,
            "discovery",
            host=urlsplit(report.root_url).hostname or "",
        )
        if not any(
            outcome.capability_id == "search_provider_discovery"
            for outcome in context.capability_outcomes
        ):
            context.record_outcome(
                "search_provider_discovery",
                (
                    CapabilityOutcomeStatus.OBSERVED
                    if counters["search"]
                    else CapabilityOutcomeStatus.NOT_APPLICABLE
                ),
                "discovery",
                count=counters["search"],
                configured=bool(counters["search_configured"]),
            )


class _DiscoveryParser(HTMLParser):
    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.links: list[tuple[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() not in {"a", "link"}:
            return
        values = {key.lower(): value or "" for key, value in attrs}
        href = values.get("href")
        if not href:
            return
        relation_values = set(values.get("rel", "").lower().split())
        classes = set(values.get("class", "").lower().split())
        relation = "internal"
        if "next" in relation_values:
            relation = "next"
        elif relation_values & {"prev", "previous"} or "pagination" in classes:
            relation = "pagination"
        elif "related" in relation_values or "related" in classes:
            relation = "related"
        elif relation_values & {"tag", "category"} or classes & {"tag", "category"}:
            relation = "category"
        candidate = urljoin(self.base_url, href.strip())
        if urlsplit(candidate).scheme in {"http", "https"}:
            self.links.append((candidate, relation))


def _site_host(url: str) -> str:
    host = (urlsplit(url).hostname or "").lower().removeprefix("www.")
    return host
