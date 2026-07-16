from __future__ import annotations

from pathlib import Path

import httpx
import pytest

from fetech.adapters.discovery import DiscoveryAdapter
from fetech.adapters.http import HTTPAdapter
from fetech.adapters.structured import OptionalAdapter
from fetech.adapters.variants import VariantAdapter
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import CapabilityOutcomeStatus, FetchRequest, ResultStatus
from fetech.security import SafeURLPolicy
from fetech.variants import generate_variant_map, generate_variants

VARIANT_CAPABILITIES = {
    "http_to_https",
    "https_to_http",
    "www_to_non_www",
    "non_www_to_www",
    "trailing_slash",
    "remove_trailing_slash",
    "clean_query_parameters",
    "canonical_url_variant",
    "mobile_variant",
    "amp_variant",
    "print_variant",
    "language_variant",
    "region_variant",
}


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


def test_all_registered_variant_generators_are_deterministic_and_never_downgrade() -> None:
    variants = generate_variant_map(
        "https://example.com/article/?utm_source=test&q=ok",
        language="EN",
        region="AU",
        canonical_url="https://example.com/canonical",
    )
    assert set(variants) == VARIANT_CAPABILITIES
    assert variants["https_to_http"] is None
    assert variants["clean_query_parameters"] == "https://example.com/article/?q=ok"
    assert variants["canonical_url_variant"] == "https://example.com/canonical"
    assert variants["language_variant"] == (
        "https://example.com/en/article/?utm_source=test&q=ok"
    )
    assert all(
        candidate is None or not candidate.startswith("http://")
        for candidate in variants.values()
    )
    assert all(not candidate.startswith("http://") for candidate in generate_variants(
        "https://example.com/article"
    ))
    assert generate_variant_map(
        "https://example.com/article",
        language="../private",
    )["language_variant"] is None


@pytest.mark.asyncio
async def test_variant_stage_emits_all_outcomes_and_uses_safe_quality_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_hosts: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requested_hosts.append(request.url.host)
        if request.url.host == "www.example.com":
            return httpx.Response(
                200,
                headers={"content-type": "text/html"},
                text=(
                    "<main>A complete alternative publisher page with useful deterministic "
                    "article content for extraction and quality validation.</main>"
                ),
            )
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=(
                '<link rel="canonical" href="https://example.com/canonical">'
                "<main>Please enable JavaScript</main>"
            ),
        )

    gateway = UniversalFetchGateway(_settings(tmp_path))
    http = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["discovery"] = DiscoveryAdapter(http)
    gateway.adapters["variants"] = VariantAdapter(http)
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(FetchRequest(target="https://example.com/article"))
    await gateway.close()

    assert result.status == ResultStatus.SUCCEEDED, result.model_dump_json(indent=2)
    assert "www.example.com" in requested_hosts
    assert any(artifact.representation == "url_candidates" for artifact in result.artifacts)
    outcomes = [
        outcome for outcome in result.capability_outcomes
        if outcome.capability_id in VARIANT_CAPABILITIES
    ]
    assert {outcome.capability_id for outcome in outcomes} >= VARIANT_CAPABILITIES
    downgrade = next(
        outcome for outcome in outcomes if outcome.capability_id == "https_to_http"
    )
    assert downgrade.status == CapabilityOutcomeStatus.BLOCKED
    selected = [
        outcome
        for outcome in outcomes
        if outcome.capability_id == "non_www_to_www"
        and outcome.status == CapabilityOutcomeStatus.APPLIED
    ]
    assert selected
    selected_resource = next(
        resource for resource in result.resources if resource.canonical_url.startswith("https://www.")
    )
    assert selected_resource.authority_url == "https://example.com/article"


@pytest.mark.asyncio
async def test_secret_bearing_target_never_fetches_url_alternatives(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requested_urls: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        requested_urls.append(str(request.url))
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<main>loading</main>",
        )

    gateway = UniversalFetchGateway(_settings(tmp_path))
    http = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["discovery"] = DiscoveryAdapter(http)
    gateway.adapters["variants"] = VariantAdapter(http)
    gateway.adapters["browser"] = OptionalAdapter("browser rendering", "browser")
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(
        FetchRequest(target="https://example.com/article?token=never-forward")
    )
    await gateway.close()

    assert len(requested_urls) == 1
    expansion = [
        outcome
        for outcome in result.capability_outcomes
        if outcome.capability_id == "candidate_url_expansion"
    ]
    assert expansion[-1].status == CapabilityOutcomeStatus.BLOCKED
