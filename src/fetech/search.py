"""Optional, policy-checked search-provider discovery connector."""

from __future__ import annotations

import json
from typing import Protocol
from urllib.parse import quote, urlsplit

import httpx

from fetech.adapters.base import AdapterExecutionError
from fetech.security import SafeURLPolicy, normalize_url, sanitize_url
from fetech.transport import PinnedAsyncHTTPTransport


class SearchProvider(Protocol):
    async def discover(self, host: str, *, maximum_results: int) -> tuple[str, ...]: ...


class HTTPSearchProvider:
    """Query an HTTPS JSON connector whose response is ``{"urls": [...]}``."""

    def __init__(
        self,
        template: str,
        *,
        policy: SafeURLPolicy | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        user_agent: str = "Fetech/0.2",
    ) -> None:
        if "{query}" not in template:
            raise ValueError("search provider template must contain {query}")
        self.template = template
        self.policy = policy or SafeURLPolicy()
        self.transport = transport
        self.user_agent = user_agent

    async def discover(self, host: str, *, maximum_results: int) -> tuple[str, ...]:
        query = quote(f"site:{host}", safe="")
        endpoint = self.template.replace("{query}", query)
        if not endpoint.startswith("https://"):
            raise AdapterExecutionError("search provider connectors require HTTPS")
        if sanitize_url(endpoint) != endpoint:
            raise AdapterExecutionError("search provider URLs cannot contain query secrets")
        endpoint, _ = await self.policy.evaluate(endpoint)
        endpoint_host = urlsplit(endpoint).hostname or ""
        transport = self.transport or PinnedAsyncHTTPTransport(
            maximum_connections=1,
            maximum_keepalive_connections=0,
        )
        if isinstance(transport, PinnedAsyncHTTPTransport):
            transport.pin(endpoint_host, self.policy.validated_addresses(endpoint_host))
        limit = min(1_000_000, max(4_096, maximum_results * 2_048))
        chunks: list[bytes] = []
        size = 0
        try:
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=10,
                headers={"User-Agent": self.user_agent, "Accept": "application/json"},
            ) as client, client.stream("GET", endpoint) as response:
                if response.is_redirect:
                    raise AdapterExecutionError("search provider redirects are forbidden")
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    if size > limit:
                        raise AdapterExecutionError("search provider response exceeded its byte limit")
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise AdapterExecutionError("search provider request failed") from exc
        try:
            document = json.loads(b"".join(chunks))
            values = document["urls"]
        except (json.JSONDecodeError, KeyError, TypeError) as exc:
            raise AdapterExecutionError("search provider returned malformed JSON") from exc
        if not isinstance(values, list):
            raise AdapterExecutionError("search provider urls must be a list")
        discovered: list[str] = []
        for value in values[:maximum_results]:
            if not isinstance(value, str):
                continue
            try:
                discovered.append(normalize_url(value))
            except ValueError:
                continue
        return tuple(dict.fromkeys(discovered))
