"""Bounded browser-render subprocess and connector contracts."""

from __future__ import annotations

import base64
import binascii
import json
import sys
from dataclasses import dataclass
from typing import Protocol

import httpx

from fetech.adapters.base import AdapterDependencyError, AdapterExecutionError
from fetech.browser_worker import BROWSER_WORKER_ADDRESS_SPACE_MB
from fetech.logic.base import LogicBackendError
from fetech.logic.process import run_bounded
from fetech.security import SafeURLPolicy, sanitize_url
from fetech.transport import PinnedAsyncHTTPTransport


@dataclass(frozen=True)
class BrowserRenderResult:
    html: str
    visible_text: str
    screenshot: bytes | None
    observations: dict[str, str | int | float | bool | None]


class BrowserRenderer(Protocol):
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
    ) -> BrowserRenderResult: ...


class BrowserRenderWorker:
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
        if timeout_seconds <= 0:
            raise AdapterExecutionError("browser rendering has no browser-time budget")
        worker_byte_limit = min(maximum_bytes, 50_000_000)
        if len(document.encode()) > worker_byte_limit:
            raise AdapterExecutionError("browser input exceeded the worker byte limit")
        payload = json.dumps(
            {
                "mode": "render",
                "document": document,
                "target": target,
                "user_agent": user_agent,
                "timeout_seconds": timeout_seconds,
                "maximum_bytes": worker_byte_limit,
                "operations": sorted(operations),
                "wait_selector": wait_selector,
                "scroll_steps": scroll_steps,
            },
            separators=(",", ":"),
        ).encode()
        try:
            process = await run_bounded(
                (sys.executable, "-m", "fetech.browser_worker"),
                payload,
                timeout_seconds=timeout_seconds,
                memory_mb=BROWSER_WORKER_ADDRESS_SPACE_MB,
                maximum_output_bytes=min(100_000_000, worker_byte_limit * 2 + 8_192),
            )
        except LogicBackendError as exc:
            raise AdapterExecutionError("bounded browser render process failed") from exc
        if process.returncode == 2:
            raise AdapterDependencyError(
                "playwright rendering requires fetech[browser] and an installed Chromium binary"
            )
        if not process.stdout:
            raise AdapterExecutionError("browser renderer exited without output")
        try:
            response = json.loads(process.stdout)
        except json.JSONDecodeError as exc:
            if process.returncode != 0:
                raise AdapterExecutionError("offline browser rendering failed") from exc
            raise AdapterExecutionError("browser renderer returned malformed output") from exc
        if not isinstance(response, dict):
            if process.returncode != 0:
                raise AdapterExecutionError("offline browser rendering failed")
            raise AdapterExecutionError("browser renderer response must be an object")
        if response.get("error") == "dependency_missing":
            raise AdapterDependencyError(
                "playwright rendering requires fetech[browser] and an installed Chromium binary"
            )
        if process.returncode != 0 or response.get("error"):
            raise AdapterExecutionError("offline browser rendering failed")
        return _parse_result(response, maximum_bytes=worker_byte_limit)


class RemoteBrowserConnector:
    """HTTPS connector for isolated Puppeteer or Selenium HTML rendering.

    The connector receives already acquired HTML and must not fetch the target
    itself. This keeps destination authorization in the Python runtime while
    allowing an independently deployed, license-compatible browser engine.
    """

    def __init__(
        self,
        endpoint: str,
        *,
        policy: SafeURLPolicy | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self.endpoint = endpoint
        self.policy = policy or SafeURLPolicy()
        self.transport = transport

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
        if not self.endpoint.startswith("https://"):
            raise AdapterExecutionError("remote browser connectors require HTTPS")
        endpoint, _ = await self.policy.evaluate(self.endpoint)
        host = httpx.URL(endpoint).host
        transport = self.transport or PinnedAsyncHTTPTransport(
            maximum_connections=1,
            maximum_keepalive_connections=0,
        )
        if isinstance(transport, PinnedAsyncHTTPTransport):
            transport.pin(host, self.policy.validated_addresses(host))
        payload = json.dumps(
            {
                "document": document,
                "target": sanitize_url(target),
                "user_agent": user_agent,
                "timeout_seconds": timeout_seconds,
                "maximum_bytes": maximum_bytes,
                "operations": sorted(operations),
                "wait_selector": wait_selector,
                "scroll_steps": scroll_steps,
                "network_policy": "offline",
            },
            separators=(",", ":"),
        ).encode()
        if len(payload) > maximum_bytes:
            raise AdapterExecutionError("remote browser request exceeded the byte budget")
        chunks: list[bytes] = []
        size = 0
        response_limit = min(100_000_000, maximum_bytes * 2 + 8_192)
        try:
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=timeout_seconds,
                headers={
                    "User-Agent": user_agent,
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                },
            ) as client, client.stream("POST", endpoint, content=payload) as response:
                if response.is_redirect:
                    raise AdapterExecutionError("remote browser connector redirects are forbidden")
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > response_limit:
                        raise AdapterExecutionError(
                            "remote browser connector exceeded the response byte budget"
                        )
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise AdapterExecutionError("remote browser connector request failed") from exc
        try:
            response_document = json.loads(b"".join(chunks))
        except json.JSONDecodeError as exc:
            raise AdapterExecutionError("remote browser connector returned malformed JSON") from exc
        return _parse_result(response_document, maximum_bytes=maximum_bytes)


def _parse_result(document: object, *, maximum_bytes: int) -> BrowserRenderResult:
    if not isinstance(document, dict):
        raise AdapterExecutionError("browser renderer response must be an object")
    html = document.get("html")
    visible_text = document.get("visible_text")
    observations = document.get("observations", {})
    encoded_screenshot = document.get("screenshot")
    if not isinstance(html, str) or not isinstance(visible_text, str):
        raise AdapterExecutionError("browser renderer omitted text outputs")
    if not isinstance(observations, dict) or not all(
        isinstance(key, str)
        and (value is None or isinstance(value, (str, int, float, bool)))
        for key, value in observations.items()
    ):
        raise AdapterExecutionError("browser renderer observations are invalid")
    screenshot: bytes | None = None
    if encoded_screenshot is not None:
        if not isinstance(encoded_screenshot, str):
            raise AdapterExecutionError("browser screenshot must be base64 text")
        try:
            screenshot = base64.b64decode(encoded_screenshot, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AdapterExecutionError("browser screenshot is not valid base64") from exc
    if len(html.encode()) + len(visible_text.encode()) + len(screenshot or b"") > maximum_bytes:
        raise AdapterExecutionError("browser renderer exceeded the byte budget")
    return BrowserRenderResult(
        html=html,
        visible_text=visible_text,
        screenshot=screenshot,
        observations=observations,
    )
