"""Ephemeral Playwright worker for offline reader-mode extraction."""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Any


async def _extract(payload: dict[str, Any]) -> str:
    try:
        from playwright.async_api import (  # type: ignore[import-not-found]
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


class _DependencyMissing(RuntimeError):
    pass


def main() -> None:
    try:
        payload = json.loads(sys.stdin.buffer.read())
        text = asyncio.run(_extract(payload))
    except _DependencyMissing:
        print(json.dumps({"error": "dependency_missing"}, separators=(",", ":")))
        raise SystemExit(2) from None
    except (ValueError, TypeError, RuntimeError):
        print(json.dumps({"error": "worker_failed"}, separators=(",", ":")))
        raise SystemExit(1) from None
    print(json.dumps({"text": text}, separators=(",", ":")))


if __name__ == "__main__":
    main()
