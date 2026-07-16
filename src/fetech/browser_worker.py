"""Ephemeral Playwright worker for offline reader-mode extraction."""

from __future__ import annotations

import asyncio
import base64
import json
import sys
from typing import Any


async def _extract(payload: dict[str, Any]) -> str:
    try:
        from playwright.async_api import (  # type: ignore[import-not-found,unused-ignore]
            Error,
            Route,
            async_playwright,
        )
    except ImportError as exc:
        raise _DependencyMissing from exc
    document = payload.get("document")
    if not isinstance(document, str):
        raise ValueError("document must be text")
    timeout_seconds = float(payload.get("timeout_seconds", 0))
    maximum_bytes = int(payload.get("maximum_bytes", 0))
    if timeout_seconds <= 0 or maximum_bytes <= 0:
        raise ValueError("worker budgets must be positive")

    async def abort_request(route: Route) -> None:
        await route.abort()

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-background-networking",
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--disable-sync",
                    "--metrics-recording-only",
                ],
            )
            try:
                context = await browser.new_context(
                    java_script_enabled=False,
                    service_workers="block",
                    user_agent=str(payload.get("user_agent", "Fetech/0.1")),
                )
                await context.set_offline(True)
                page = await context.new_page()
                await page.route("**/*", abort_request)
                await page.set_content(
                    document,
                    wait_until="domcontentloaded",
                    timeout=timeout_seconds * 1_000,
                )
                candidates: list[str] = []
                locator = page.locator("main, article")
                for index in range(min(await locator.count(), 100)):
                    candidates.append(await locator.nth(index).inner_text())
                if not candidates:
                    candidates.append(await page.locator("body").inner_text())
                text = max(candidates, key=len).strip()
                if len(text.encode()) > maximum_bytes:
                    raise ValueError("browser reader output exceeded the byte budget")
                return text
            finally:
                await browser.close()
    except Error as exc:
        if "Executable doesn't exist" in str(exc):
            raise _DependencyMissing from exc
        raise RuntimeError("browser extraction failed") from exc


async def _render(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        from playwright.async_api import (
            Error,
            Route,
            async_playwright,
        )
    except ImportError as exc:
        raise _DependencyMissing from exc
    document = payload.get("document")
    if not isinstance(document, str):
        raise ValueError("document must be text")
    timeout_seconds = float(payload.get("timeout_seconds", 0))
    maximum_bytes = int(payload.get("maximum_bytes", 0))
    operations = {
        str(value) for value in payload.get("operations", []) if isinstance(value, str)
    }
    if timeout_seconds <= 0 or maximum_bytes <= 0:
        raise ValueError("worker budgets must be positive")
    blocked_requests = 0

    async def abort_request(route: Route) -> None:
        nonlocal blocked_requests
        blocked_requests += 1
        await route.abort()

    try:
        async with async_playwright() as playwright:
            browser = await playwright.chromium.launch(
                headless=True,
                args=[
                    "--disable-background-networking",
                    "--disable-dev-shm-usage",
                    "--disable-extensions",
                    "--disable-sync",
                    "--metrics-recording-only",
                ],
            )
            try:
                context = await browser.new_context(
                    java_script_enabled=True,
                    service_workers="block",
                    user_agent=str(payload.get("user_agent", "Fetech/0.2")),
                )
                await context.set_offline(True)
                page = await context.new_page()
                await page.route("**/*", abort_request)
                history_before = await page.evaluate("history.length")
                url_before = page.url
                await page.set_content(
                    document,
                    wait_until="domcontentloaded",
                    timeout=timeout_seconds * 1_000,
                )
                selector_ready = False
                if "wait_for_selector" in operations:
                    selector = str(payload.get("wait_selector", "body"))
                    await page.wait_for_selector(
                        selector,
                        timeout=min(timeout_seconds, 10.0) * 1_000,
                    )
                    selector_ready = True
                network_idle = False
                if "wait_for_network_idle" in operations:
                    await page.wait_for_load_state(
                        "networkidle",
                        timeout=min(timeout_seconds, 10.0) * 1_000,
                    )
                    network_idle = True
                cookie_handled = 0
                if "cookie_banner_handling" in operations:
                    buttons = page.locator("button")
                    for index in range(min(await buttons.count(), 50)):
                        button = buttons.nth(index)
                        label = (await button.inner_text()).strip().casefold()
                        if label in {"accept", "accept all", "allow all", "reject", "reject all"}:
                            await button.click(timeout=1_000)
                            cookie_handled += 1
                            break
                expanded = 0
                if "click_expand" in operations:
                    expanders = page.locator(
                        "details:not([open]) > summary, button[aria-expanded='false']"
                    )
                    for index in range(min(await expanders.count(), 20)):
                        await expanders.nth(index).click(timeout=1_000)
                        expanded += 1
                scroll_steps = 0
                if operations & {"scroll_to_load", "lazy_loading"}:
                    for _ in range(min(5, max(1, int(payload.get("scroll_steps", 3))))):
                        await page.evaluate("window.scrollBy(0, Math.max(window.innerHeight, 600))")
                        await page.wait_for_timeout(50)
                        scroll_steps += 1
                html = await page.content()
                visible_text = (await page.locator("body").inner_text()).strip()
                history_after = await page.evaluate("history.length")
                url_after = page.url
                screenshot = b""
                if "screenshot" in operations:
                    screenshot = await page.screenshot(
                        full_page=True,
                        animations="disabled",
                        caret="hide",
                    )
                output_size = len(html.encode()) + len(visible_text.encode()) + len(screenshot)
                if output_size > maximum_bytes:
                    raise ValueError("browser render output exceeded the byte budget")
                return {
                    "html": html,
                    "visible_text": visible_text,
                    "screenshot": base64.b64encode(screenshot).decode() if screenshot else None,
                    "observations": {
                        "blocked_requests": blocked_requests,
                        "selector_ready": selector_ready,
                        "network_idle": network_idle,
                        "cookie_handled": cookie_handled,
                        "expanded": expanded,
                        "scroll_steps": scroll_steps,
                        "spa_route_changed": (
                            history_after != history_before or url_after != url_before
                        ),
                    },
                }
            finally:
                await browser.close()
    except Error as exc:
        if "Executable doesn't exist" in str(exc):
            raise _DependencyMissing from exc
        raise RuntimeError("browser rendering failed") from exc


class _DependencyMissing(RuntimeError):
    pass


def main() -> None:
    try:
        payload = json.loads(sys.stdin.buffer.read())
        if payload.get("mode") == "render":
            response = asyncio.run(_render(payload))
        else:
            response = {"text": asyncio.run(_extract(payload))}
    except _DependencyMissing:
        print(json.dumps({"error": "dependency_missing"}, separators=(",", ":")))
        raise SystemExit(2) from None
    except (ValueError, TypeError, RuntimeError):
        print(json.dumps({"error": "worker_failed"}, separators=(",", ":")))
        raise SystemExit(1) from None
    print(json.dumps(response, separators=(",", ":")))


if __name__ == "__main__":
    main()
