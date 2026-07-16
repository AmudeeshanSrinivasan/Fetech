"""HTTPX transport that connects only to policy-validated DNS addresses."""

from __future__ import annotations

import ssl
from collections.abc import AsyncIterable, Iterable
from types import TracebackType
from typing import cast

import httpcore
import httpx
from httpcore._backends.auto import AutoBackend
from httpcore._backends.base import SOCKET_OPTION
from httpx._transports.default import AsyncResponseStream, map_httpcore_exceptions


class PinnedNetworkBackend(httpcore.AsyncNetworkBackend):
    """Replace hostname resolution at connect time with validated address pins."""

    def __init__(self) -> None:
        self._backend = AutoBackend()
        self._pins: dict[str, tuple[str, ...]] = {}
        self._cursor: dict[str, int] = {}

    def pin(self, host: str, addresses: tuple[str, ...]) -> None:
        if not addresses:
            raise ValueError("at least one validated address is required")
        self._pins[host.lower().rstrip(".")] = addresses

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,
        local_address: str | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        key = host.lower().rstrip(".")
        addresses = self._pins.get(key)
        if not addresses:
            raise httpcore.ConnectError(f"destination {host} has no validated DNS pin")
        cursor = self._cursor.get(key, 0)
        address = addresses[cursor % len(addresses)]
        self._cursor[key] = cursor + 1
        return await self._backend.connect_tcp(
            address,
            port,
            timeout=timeout,
            local_address=local_address,
            socket_options=socket_options,
        )

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,
        socket_options: Iterable[SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        raise httpcore.ConnectError("Unix sockets are not valid URL targets")

    async def sleep(self, seconds: float) -> None:
        await self._backend.sleep(seconds)


class PinnedAsyncHTTPTransport(httpx.AsyncBaseTransport):
    """HTTPX/httpcore bridge with TLS hostname checks and pinned TCP destinations."""

    def __init__(
        self,
        *,
        verify: ssl.SSLContext | str | bool = True,
        http2: bool = True,
        maximum_connections: int = 20,
        maximum_keepalive_connections: int = 10,
    ) -> None:
        self.network_backend = PinnedNetworkBackend()
        ssl_context = httpx.create_ssl_context(verify=verify, trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=maximum_connections,
            max_keepalive_connections=maximum_keepalive_connections,
            http1=True,
            http2=http2,
            network_backend=self.network_backend,
        )

    def pin(self, host: str, addresses: tuple[str, ...]) -> None:
        self.network_backend.pin(host, addresses)

    async def __aenter__(self) -> PinnedAsyncHTTPTransport:
        await self._pool.__aenter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None = None,
        exc_value: BaseException | None = None,
        traceback: TracebackType | None = None,
    ) -> None:
        with map_httpcore_exceptions():
            await self._pool.__aexit__(exc_type, exc_value, traceback)

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if not isinstance(request.stream, httpx.AsyncByteStream):
            raise TypeError("pinned transport requires an async request stream")
        core_request = httpcore.Request(
            method=request.method,
            url=httpcore.URL(
                scheme=request.url.raw_scheme,
                host=request.url.raw_host,
                port=request.url.port,
                target=request.url.raw_path,
            ),
            headers=request.headers.raw,
            content=request.stream,
            extensions=request.extensions,
        )
        with map_httpcore_exceptions():
            response = await self._pool.handle_async_request(core_request)
        return httpx.Response(
            status_code=response.status,
            headers=response.headers,
            stream=AsyncResponseStream(cast(AsyncIterable[bytes], response.stream)),
            extensions=response.extensions,
        )

    async def aclose(self) -> None:
        await self._pool.aclose()
