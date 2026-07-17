from __future__ import annotations

import base64
import json
from importlib.util import find_spec
from pathlib import Path

import httpx
import pytest

from fetech.adapters.base import AdapterDependencyError, AdapterExecutionError
from fetech.adapters.browser import BROWSER_CAPABILITIES, BrowserAdapter
from fetech.adapters.discovery import DiscoveryAdapter
from fetech.adapters.http import HTTPAdapter
from fetech.adapters.variants import VariantAdapter
from fetech.browser_render import (
    BrowserRenderResult,
    BrowserRenderWorker,
    RemoteBrowserConnector,
)
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.logic.process import ProcessResult
from fetech.models import CapabilityOutcomeStatus, FetchRequest, ResultStatus
from fetech.security import SafeURLPolicy


class FakeRenderer:
    def __init__(self) -> None:
        self.operations: frozenset[str] = frozenset()

    async def render(
        self,
        document: str,
        *,
        target: str,
        user_agent: str,
        timeout_seconds: float,
        maximum_bytes: int,
        operations: frozenset[str],
        wait_selector: str,
        scroll_steps: int,
    ) -> BrowserRenderResult:
        del document, target, user_agent, timeout_seconds, maximum_bytes, wait_selector
        self.operations = operations
        return BrowserRenderResult(
            html=(
                "<html><body><main>A rendered browser result with enough useful text for "
                "quality acceptance and deterministic interface conformance.</main></body></html>"
            ),
            visible_text=(
                "A rendered browser result with enough useful text for quality acceptance "
                "and deterministic interface conformance."
            ),
            screenshot=b"\x89PNG\r\n\x1a\nfixture",
            observations={
                "blocked_requests": 2,
                "selector_ready": True,
                "network_idle": True,
                "cookie_handled": 1,
                "expanded": 2,
                "scroll_steps": scroll_steps,
                "spa_route_changed": True,
            },
        )


@pytest.mark.skipif(find_spec("playwright") is not None, reason="Playwright is installed")
@pytest.mark.asyncio
async def test_local_browser_renderer_reports_missing_optional_dependency() -> None:
    with pytest.raises(AdapterDependencyError, match=r"fetech\[browser\]"):
        await BrowserRenderWorker().render(
            "<main>offline browser fixture</main>",
            target="https://example.com",
            user_agent="Fetech/test",
            timeout_seconds=3,
            maximum_bytes=10_000,
            operations=frozenset({"visible_text"}),
            wait_selector="body",
            scroll_steps=1,
        )


@pytest.mark.asyncio
async def test_browser_worker_exit_two_without_json_is_dependency_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def missing_worker(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
    ) -> ProcessResult:
        del arguments, stdin, timeout_seconds, memory_mb, maximum_output_bytes
        return ProcessResult(returncode=2, stdout=b"", stderr=b"private worker detail")

    monkeypatch.setattr("fetech.browser_render.run_bounded", missing_worker)
    with pytest.raises(AdapterDependencyError, match=r"installed Chromium binary") as caught:
        await BrowserRenderWorker().render(
            "<main>offline browser fixture</main>",
            target="https://example.com",
            user_agent="Fetech/test",
            timeout_seconds=3,
            maximum_bytes=10_000,
            operations=frozenset({"visible_text"}),
            wait_selector="body",
            scroll_steps=1,
        )
    assert "private worker detail" not in str(caught.value)


@pytest.mark.asyncio
async def test_browser_worker_crash_is_typed_bounded_and_does_not_leak_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_memory_mb = 0

    async def crashed_worker(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
    ) -> ProcessResult:
        del arguments, stdin, timeout_seconds, maximum_output_bytes
        nonlocal observed_memory_mb
        observed_memory_mb = memory_mb
        return ProcessResult(returncode=-9, stdout=b"", stderr=b"private worker detail")

    monkeypatch.setattr("fetech.browser_render.run_bounded", crashed_worker)
    with pytest.raises(AdapterExecutionError, match=r"exited without output") as caught:
        await BrowserRenderWorker().render(
            "<main>offline browser fixture</main>",
            target="https://example.com",
            user_agent="Fetech/test",
            timeout_seconds=3,
            maximum_bytes=10_000,
            operations=frozenset({"visible_text"}),
            wait_selector="body",
            scroll_steps=1,
        )
    assert observed_memory_mb == 16 * 1024
    assert "private worker detail" not in str(caught.value)


@pytest.mark.skipif(find_spec("playwright") is None, reason="Playwright is not installed")
@pytest.mark.asyncio
async def test_real_browser_worker_runs_inline_javascript_and_bounded_interactions() -> None:
    result = await BrowserRenderWorker().render(
        """
        <html><body>
          <button onclick="this.remove()">Accept all</button>
          <img src="http://127.0.0.1/private.png" alt="blocked private subresource">
          <details><summary>More</summary><p>Expanded details are visible.</p></details>
          <main id="loading">Loading</main>
          <script>
            const main = document.querySelector('main');
            main.id = 'ready';
            main.textContent = 'Rendered inline JavaScript produced useful deterministic content '
              + 'for the isolated browser worker and its quality validator.';
            history.pushState({}, '', '#rendered');
          </script>
        </body></html>
        """,
        target="https://example.com/article",
        user_agent="Fetech/test",
        timeout_seconds=10,
        maximum_bytes=5_000_000,
        operations=frozenset(
            {
                "visible_text",
                "screenshot",
                "wait_for_selector",
                "wait_for_network_idle",
                "scroll_to_load",
                "click_expand",
                "cookie_banner_handling",
                "lazy_loading",
                "spa_route_handling",
            }
        ),
        wait_selector="#ready",
        scroll_steps=2,
    )
    assert "Rendered inline JavaScript" in result.visible_text
    assert result.screenshot is not None and result.screenshot.startswith(b"\x89PNG")
    assert result.observations["selector_ready"] is True
    assert result.observations["cookie_handled"] == 1
    assert result.observations["expanded"] == 1
    assert result.observations["scroll_steps"] == 2
    assert result.observations["spa_route_changed"] is True
    assert int(result.observations["blocked_requests"]) >= 1


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
async def test_explicit_browser_plan_executes_all_requested_browser_operations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=(
                "<main>A useful original article with enough visible fixture text to avoid "
                "unnecessary URL-alternative requests.</main>"
            ),
        )

    requested_operations = tuple(
        capability_id
        for capability_id in BROWSER_CAPABILITIES
        if capability_id not in {"puppeteer", "selenium", "cdp"}
    )
    request = FetchRequest(
        target="https://example.com/article",
        output_requirements=requested_operations,
        metadata={"wait_selector": "main", "scroll_steps": "4"},
    )
    gateway = UniversalFetchGateway(_settings(tmp_path))
    http = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    renderer = FakeRenderer()
    gateway.adapters["http"] = http
    gateway.adapters["discovery"] = DiscoveryAdapter(http)
    gateway.adapters["variants"] = VariantAdapter(http)
    gateway.adapters["browser"] = BrowserAdapter(
        renderer,
        user_agent=gateway.settings.user_agent,
    )
    gateway.executor.adapters = gateway.adapters

    plan = gateway.plan(request)
    browser_node = next(node for node in plan.nodes if node.adapter == "browser")
    assert browser_node.capability_id == "playwright"
    assert browser_node.fallback_for is None

    result = await gateway.fetch(request)
    await gateway.close()

    assert result.status == ResultStatus.SUCCEEDED
    assert "screenshot" in renderer.operations
    assert {"wait_for_selector", "wait_for_network_idle", "lazy_loading"} <= renderer.operations
    assert any(artifact.representation == "rendered_html" for artifact in result.artifacts)
    assert any(artifact.representation == "visible_text" for artifact in result.artifacts)
    assert any(artifact.representation == "screenshot" for artifact in result.artifacts)
    browser_outcomes = {
        outcome.capability_id: outcome
        for outcome in result.capability_outcomes
        if outcome.capability_id in BROWSER_CAPABILITIES
    }
    assert set(browser_outcomes) == set(BROWSER_CAPABILITIES)
    assert browser_outcomes["playwright"].status == CapabilityOutcomeStatus.APPLIED
    assert browser_outcomes["puppeteer"].status == CapabilityOutcomeStatus.NOT_APPLICABLE
    assert browser_outcomes["selenium"].status == CapabilityOutcomeStatus.NOT_APPLICABLE
    assert browser_outcomes["screenshot"].status == CapabilityOutcomeStatus.APPLIED
    assert browser_outcomes["spa_route_handling"].details["spa_route_changed"] is True


def test_explicit_cdp_and_connector_engines_are_selected_by_the_planner(tmp_path: Path) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))
    for engine in ("cdp", "puppeteer", "selenium"):
        plan = gateway.plan(
            FetchRequest(
                target="https://example.com",
                output_requirements=(engine, "visible_text"),
            )
        )
        browser = next(node for node in plan.nodes if node.adapter == "browser")
        assert browser.capability_id == engine
        assert browser.fallback_for is None


@pytest.mark.asyncio
async def test_remote_browser_connector_is_https_bounded_and_offline_scoped(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_payload: dict[str, object] = {}

    async def respond(request: httpx.Request) -> httpx.Response:
        observed_payload.update(json.loads(request.content))
        return httpx.Response(
            200,
            json={
                "html": "<main>remote rendered document</main>",
                "visible_text": "remote rendered document",
                "screenshot": base64.b64encode(b"png").decode(),
                "observations": {"blocked_requests": 3},
            },
        )

    connector = RemoteBrowserConnector(
        "https://connector.example/render",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    result = await connector.render(
        "<main>publisher document</main>",
        target="https://example.com/article",
        user_agent="Fetech/test",
        timeout_seconds=5,
        maximum_bytes=10_000,
        operations=frozenset({"visible_text", "screenshot"}),
        wait_selector="main",
        scroll_steps=2,
    )
    assert result.screenshot == b"png"
    assert observed_payload["network_policy"] == "offline"
    assert observed_payload["target"] == "https://example.com/article"


@pytest.mark.asyncio
async def test_remote_browser_request_requires_explicit_public_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=(
                "<main>A useful static source remains available when the explicitly requested "
                "remote browser policy blocks connector execution.</main>"
            ),
        )

    remote = FakeRenderer()
    gateway = UniversalFetchGateway(_settings(tmp_path))
    http = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["http"] = http
    gateway.adapters["discovery"] = DiscoveryAdapter(http)
    gateway.adapters["variants"] = VariantAdapter(http)
    gateway.adapters["browser"] = BrowserAdapter(
        FakeRenderer(),
        remote_renderers={"puppeteer": remote},
    )
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/article",
            output_requirements=("puppeteer", "visible_text"),
        )
    )
    await gateway.close()

    assert result.status == ResultStatus.PARTIAL
    assert not remote.operations
    assert any(
        "explicit public, unauthenticated policy" in diagnostic.message
        for diagnostic in result.diagnostics
    )
