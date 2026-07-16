from __future__ import annotations

from typing import Any

import httpcore
import pytest

from fetech.transport import PinnedNetworkBackend


class RecordingBackend:
    def __init__(self) -> None:
        self.host: str | None = None

    async def connect_tcp(self, host: str, port: int, **_: Any) -> Any:
        self.host = host
        return object()

    async def sleep(self, _: float) -> None:
        return None


@pytest.mark.asyncio
async def test_network_backend_connects_to_pin_not_hostname() -> None:
    backend = PinnedNetworkBackend()
    recording = RecordingBackend()
    backend._backend = recording  # type: ignore[assignment]
    backend.pin("example.com", ("93.184.216.34",))
    await backend.connect_tcp("example.com", 443)
    assert recording.host == "93.184.216.34"


@pytest.mark.asyncio
async def test_network_backend_fails_closed_without_pin() -> None:
    backend = PinnedNetworkBackend()
    with pytest.raises(httpcore.ConnectError, match="no validated DNS pin"):
        await backend.connect_tcp("example.com", 443)
