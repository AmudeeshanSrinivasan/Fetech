from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from fetech.adapters.discovery import DiscoveryAdapter
from fetech.adapters.http import HTTPAdapter
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import CapabilityOutcomeStatus, FetchRequest, ResourceBudget, ResultStatus
from fetech.search import HTTPSearchProvider
from fetech.security import SafeURLPolicy


class FakeSearchProvider:
    def __init__(self) -> None:
        self.hosts: list[str] = []

    async def discover(self, host: str, *, maximum_results: int) -> tuple[str, ...]:
        self.hosts.append(host)
        assert maximum_results >= 1
        return (
            "https://example.com/from-search",
            "https://outside.example/ignored",
        )


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
        per_host_min_interval_seconds=0,
    )


def _public_policy(monkeypatch: pytest.MonkeyPatch) -> SafeURLPolicy:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    return policy


@pytest.mark.asyncio
async def test_bounded_crawl_returns_report_and_discovery_outcomes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_paths: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        fixtures = {
            "/robots.txt": "User-agent: *\nAllow: /\n",
            "/": """
                <main>A useful root page with enough fixture text for quality checks.</main>
                <a href="/article">Article</a>
                <a rel="next" href="/page/2">Next</a>
                <a rel="related" href="/related">Related</a>
                <a rel="tag" href="/topics/testing">Testing</a>
                <a href="https://outside.example/private">Outside</a>
            """,
            "/sitemap.xml": """
                <urlset><url><loc>https://example.com/from-sitemap</loc></url></urlset>
            """,
            "/article": "<main>Useful article body with deterministic crawl content.</main>",
            "/page/2": "<main>Useful second page with deterministic crawl content.</main>",
            "/related": "<main>Useful related page with deterministic crawl content.</main>",
            "/topics/testing": "<main>Useful category page with deterministic crawl content.</main>",
            "/from-sitemap": "<main>Useful sitemap page with deterministic crawl content.</main>",
        }
        body = fixtures.get(request.url.path, "not found")
        status = 200 if request.url.path in fixtures else 404
        media_type = "application/xml" if request.url.path.endswith(".xml") else "text/html"
        return httpx.Response(status, headers={"content-type": media_type}, text=body)

    gateway = UniversalFetchGateway(_settings(tmp_path))
    http = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["discovery"] = DiscoveryAdapter(http, batch_size=2)
    gateway.executor.adapters = gateway.adapters

    request = FetchRequest(
        target="https://example.com/",
        intent="crawl",
        budget=ResourceBudget(attempts=7, crawl_pages=5, crawl_depth=2),
    )
    plan = gateway.plan(request)
    assert [node.capability_id for node in plan.nodes][-1] == "depth_limited_crawl"

    result = await gateway.fetch(request)
    await gateway.close()

    assert result.status == ResultStatus.SUCCEEDED
    assert result.crawl_report is not None
    assert result.crawl_report.pages_fetched == 5
    assert result.crawl_report.maximum_depth_reached <= 2
    assert len(result.attempts) <= request.budget.attempts
    assert any(artifact.representation == "crawl_report" for artifact in result.artifacts)
    assert "https://outside.example/private" not in {
        target.url for target in result.crawl_report.targets
    }
    assert "/robots.txt" in requested_paths
    assert "/sitemap.xml" in requested_paths

    outcomes = {outcome.capability_id: outcome for outcome in result.capability_outcomes}
    assert outcomes["domain_limited_crawl"].status == CapabilityOutcomeStatus.APPLIED
    assert outcomes["depth_limited_crawl"].status == CapabilityOutcomeStatus.APPLIED
    assert outcomes["next_page_discovery"].status == CapabilityOutcomeStatus.OBSERVED
    assert outcomes["related_link_discovery"].status == CapabilityOutcomeStatus.OBSERVED
    assert outcomes["category_tag_discovery"].status == CapabilityOutcomeStatus.OBSERVED


@pytest.mark.asyncio
async def test_crawl_page_budget_counts_failed_fetches(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_paths: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requested_paths.append(request.url.path)
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        if request.url.path == "/":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text='<main>Useful root fixture content.</main><a href="/missing">Missing</a>',
            )
        return httpx.Response(404)

    gateway = UniversalFetchGateway(_settings(tmp_path))
    http = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["discovery"] = DiscoveryAdapter(http, batch_size=2)
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/",
            intent="crawl",
            budget=ResourceBudget(attempts=8, crawl_pages=2, crawl_depth=1),
        )
    )
    await gateway.close()

    assert result.crawl_report is not None
    assert result.crawl_report.pages_fetched == 1
    assert result.crawl_report.pages_failed == 1
    checked = [path for path in requested_paths if path not in {"/robots.txt", "/"}]
    assert len(checked) == 1


@pytest.mark.asyncio
async def test_configured_search_discovery_is_explicit_and_domain_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def respond(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nAllow: /\n")
        if request.url.path in {"/", "/from-search"}:
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text="<main>Useful searchable domain content for deterministic crawling.</main>",
            )
        return httpx.Response(404)

    search = FakeSearchProvider()
    gateway = UniversalFetchGateway(_settings(tmp_path))
    http = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["discovery"] = DiscoveryAdapter(
        http,
        search_provider=search,
    )
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/",
            intent="crawl",
            policy_profile="allow_search_discovery",
            budget=ResourceBudget(attempts=6, crawl_pages=4, crawl_depth=1),
        )
    )
    await gateway.close()

    assert search.hosts == ["example.com"]
    outcome = next(
        item
        for item in result.capability_outcomes
        if item.capability_id == "search_provider_discovery"
    )
    assert outcome.status == CapabilityOutcomeStatus.OBSERVED
    assert result.crawl_report is not None
    assert "https://outside.example/ignored" not in {
        target.url for target in result.crawl_report.targets
    }


@pytest.mark.asyncio
async def test_https_search_connector_validates_and_bounds_results(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_url = ""

    async def respond(request: httpx.Request) -> httpx.Response:
        nonlocal observed_url
        observed_url = str(request.url)
        return httpx.Response(
            200,
            json={
                "urls": [
                    "https://example.com/one",
                    "file:///etc/passwd",
                    "https://example.com/one",
                    "https://example.com/two",
                ]
            },
        )

    connector = HTTPSearchProvider(
        "https://search.example/discover?q={query}",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    results = await connector.discover("example.com", maximum_results=4)
    assert results == (
        "https://example.com/one",
        "https://example.com/two",
    )
    assert "site%3Aexample.com" in observed_url
