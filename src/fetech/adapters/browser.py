"""Browser rendering adapter with isolated local and optional connector engines."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime
from time import monotonic

from fetech.adapters.base import AdapterDependencyError, AdapterExecutionError, ExecutionContext
from fetech.browser_render import BrowserRenderer
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    PlanNode,
)
from fetech.quality import assess_text
from fetech.security import sanitize_url
from fetech.storage import build_artifact
from fetech.version import DEFAULT_USER_AGENT

BROWSER_CAPABILITIES = (
    "playwright",
    "puppeteer",
    "selenium",
    "cdp",
    "headless_dom",
    "visible_text",
    "screenshot",
    "wait_for_selector",
    "wait_for_network_idle",
    "scroll_to_load",
    "click_expand",
    "cookie_banner_handling",
    "lazy_loading",
    "javascript_rendering",
    "spa_route_handling",
)
_ENGINES = {"playwright", "puppeteer", "selenium", "cdp"}
_ALWAYS_APPLIED = {"headless_dom", "visible_text", "javascript_rendering"}


class BrowserAdapter:
    def __init__(
        self,
        local_renderer: BrowserRenderer,
        *,
        remote_renderers: Mapping[str, BrowserRenderer] | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        self.local_renderer = local_renderer
        self.remote_renderers = dict(remote_renderers or {})
        self.user_agent = user_agent

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        if node.capability_id not in _ENGINES:
            raise AdapterExecutionError(f"browser adapter cannot execute {node.capability_id}")
        raw = context.latest_artifact("raw")
        if raw is None or not context.resources:
            raise AdapterExecutionError("browser rendering requires an HTTP source artifact")
        if node.capability_id in {"puppeteer", "selenium"} and (
            context.request.policy_profile != "allow_remote_browsers"
            or context.request.privacy_profile != "public"
            or context.request.authentication_ref
            or sanitize_url(context.request.target) != context.request.target
        ):
            raise AdapterExecutionError(
                "remote browser connectors require an explicit public, unauthenticated policy"
            )
        renderer = self._renderer(node.capability_id)
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        started = monotonic()
        body = await context.cas.get(
            raw.cas_uri,
            maximum_bytes=context.request.budget.decompressed_bytes,
        )
        remaining_output_bytes = int(
            context.remaining_budget("decompressed_bytes")
        )
        remaining_browser_seconds = float(
            context.remaining_budget("browser_seconds")
        )
        context.require_budget("decompressed_bytes", 1)
        context.require_budget("browser_seconds", 0.001)
        operations = frozenset(context.request.output_requirements) & set(BROWSER_CAPABILITIES)
        operations = frozenset({*operations, *_ALWAYS_APPLIED})
        result = await renderer.render(
            body.decode("utf-8", errors="replace"),
            target=context.request.target,
            user_agent=self.user_agent,
            timeout_seconds=remaining_browser_seconds,
            maximum_bytes=remaining_output_bytes,
            operations=operations,
            wait_selector=context.request.metadata.get("wait_selector", "body"),
            scroll_steps=_bounded_int(context.request.metadata.get("scroll_steps"), 3, 1, 5),
        )
        quality = assess_text(
            result.visible_text,
            expected_language=context.request.language,
        )
        artifacts = []
        html_body = result.html.encode()
        text_body = result.visible_text.encode()
        screenshot_body = result.screenshot or b""
        total_output_bytes = len(html_body) + len(text_body) + len(screenshot_body)
        elapsed = monotonic() - started
        context.require_budget("decompressed_bytes", total_output_bytes)
        context.require_budget("browser_seconds", elapsed)
        html_uri, html_digest, html_size = await context.cas.put(html_body)
        rendered_html = build_artifact(
            role="derived",
            representation="rendered_html",
            media_type="text/html",
            cas_uri=html_uri,
            digest=html_digest,
            size=html_size,
            resource=context.resources[-1],
            extractor=f"{node.capability_id}-browser/0.2",
            quality=quality,
            parents=(raw,),
            locators=("document",),
        )
        context.artifacts.append(rendered_html)
        artifacts.append(rendered_html)
        text_uri, text_digest, text_size = await context.cas.put(text_body)
        visible_text = build_artifact(
            role="primary" if quality.accepted else "checked-only",
            representation="visible_text",
            media_type="text/plain",
            cas_uri=text_uri,
            digest=text_digest,
            size=text_size,
            resource=context.resources[-1],
            extractor=f"{node.capability_id}-visible-text/0.2",
            quality=quality,
            parents=(rendered_html,),
            locators=("document.body",),
        )
        context.artifacts.append(visible_text)
        artifacts.append(visible_text)
        if result.screenshot is not None:
            image_uri, image_digest, image_size = await context.cas.put(result.screenshot)
            screenshot = build_artifact(
                role="derived",
                representation="screenshot",
                media_type="image/png",
                cas_uri=image_uri,
                digest=image_digest,
                size=image_size,
                resource=context.resources[-1],
                extractor=f"{node.capability_id}-screenshot/0.2",
                quality=quality,
                parents=(rendered_html,),
                locators=("full-page",),
            )
            context.artifacts.append(screenshot)
            artifacts.append(screenshot)
        context.record_quality_outcomes(quality, stage="quality")
        context.accepted = context.accepted or quality.accepted
        self._record_outcomes(node.capability_id, operations, result.observations, context)
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "bytes_received": sum(artifact.size for artifact in artifacts),
                "parser": f"{node.capability_id}-browser",
                "artifact_ids": tuple(artifact.artifact_id for artifact in artifacts),
                "consumed_budget": {
                    "decompressed_bytes": sum(artifact.size for artifact in artifacts),
                    "browser_seconds": elapsed,
                },
            }
        )

    def _renderer(self, engine: str) -> BrowserRenderer:
        if engine in {"playwright", "cdp"}:
            return self.local_renderer
        try:
            return self.remote_renderers[engine]
        except KeyError as exc:
            raise AdapterDependencyError(
                f"{engine} requires a configured isolated browser connector"
            ) from exc

    @staticmethod
    def _record_outcomes(
        engine: str,
        operations: frozenset[str],
        observations: dict[str, str | int | float | bool | None],
        context: ExecutionContext,
    ) -> None:
        for capability_id in BROWSER_CAPABILITIES:
            status = CapabilityOutcomeStatus.NOT_APPLICABLE
            details: dict[str, str | int | float | bool | None] = {}
            if capability_id == engine:
                status = CapabilityOutcomeStatus.APPLIED
            elif capability_id == "playwright" and engine == "cdp":
                status = CapabilityOutcomeStatus.OBSERVED
                details["role"] = "CDP driver"
            elif capability_id in _ENGINES:
                pass
            elif capability_id in _ALWAYS_APPLIED or (
                capability_id == "screenshot" and capability_id in operations
            ):
                status = CapabilityOutcomeStatus.APPLIED
            elif capability_id in operations:
                status = CapabilityOutcomeStatus.APPLIED
                observation_key = {
                    "wait_for_selector": "selector_ready",
                    "wait_for_network_idle": "network_idle",
                    "scroll_to_load": "scroll_steps",
                    "click_expand": "expanded",
                    "cookie_banner_handling": "cookie_handled",
                    "lazy_loading": "scroll_steps",
                    "spa_route_handling": "spa_route_changed",
                }.get(capability_id)
                if observation_key:
                    details[observation_key] = observations.get(observation_key)
            context.record_outcome(capability_id, status, "browser", **details)
        blocked_requests = observations.get("blocked_requests", 0)
        context.record_outcome(
            "ssrf_private_ip_check",
            CapabilityOutcomeStatus.APPLIED,
            "browser",
            private_subresources_blocked=(
                int(blocked_requests) if isinstance(blocked_requests, (int, float)) else 0
            ),
        )


def _bounded_int(value: str | None, default: int, minimum: int, maximum: int) -> int:
    try:
        parsed = int(value) if value is not None else default
    except ValueError:
        return default
    return min(maximum, max(minimum, parsed))
