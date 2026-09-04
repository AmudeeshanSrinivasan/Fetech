"""Shared, deterministic scheduling for runtime-owned network connectors."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
from collections import OrderedDict, deque
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass

_DOMAIN_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")


class NetworkDeadlineExceededError(TimeoutError):
    """The scheduler's own queue or operation deadline was exhausted."""


@dataclass(eq=False, slots=True)
class _Waiter:
    host: str
    future: asyncio.Future[None]


class NetworkScheduler:
    """Apply global, per-host, deadline, and request-start interval limits.

    The gateway shares one instance across its HTTP, built-in yt-dlp, and
    built-in Wayback boundaries. Capacity is acquired atomically so a request
    waiting on a busy host cannot consume a global slot needed by another host.
    """

    def __init__(
        self,
        *,
        global_concurrency: int = 8,
        per_host_concurrency: int = 2,
        per_host_min_interval_seconds: float = 0.0,
        host_history_limit: int = 4096,
    ) -> None:
        if (
            isinstance(global_concurrency, bool)
            or not isinstance(global_concurrency, int)
            or global_concurrency <= 0
            or isinstance(per_host_concurrency, bool)
            or not isinstance(per_host_concurrency, int)
            or per_host_concurrency <= 0
            or isinstance(per_host_min_interval_seconds, bool)
            or not isinstance(per_host_min_interval_seconds, int | float)
            or not math.isfinite(per_host_min_interval_seconds)
            or per_host_min_interval_seconds < 0
            or isinstance(host_history_limit, bool)
            or not isinstance(host_history_limit, int)
            or host_history_limit <= 0
        ):
            raise ValueError("network scheduler limits are invalid")
        self.global_concurrency = global_concurrency
        self.per_host_concurrency = per_host_concurrency
        self.per_host_min_interval_seconds = float(
            per_host_min_interval_seconds
        )
        self.host_history_limit = host_history_limit
        self._active_global = 0
        self._active_by_host: dict[str, int] = {}
        self._last_started_at: OrderedDict[str, float] = OrderedDict()
        self._waiters: deque[_Waiter] = deque()
        self._loop: asyncio.AbstractEventLoop | None = None
        self._wake_handle: asyncio.TimerHandle | None = None

    @asynccontextmanager
    async def slot(
        self,
        host: str,
        *,
        deadline_seconds: float,
    ) -> AsyncIterator[None]:
        """Reserve shared capacity and keep it until the network operation ends."""

        normalized_host = _normalize_host(host)
        if (
            isinstance(deadline_seconds, bool)
            or not isinstance(deadline_seconds, int | float)
            or not math.isfinite(deadline_seconds)
            or deadline_seconds <= 0
        ):
            raise NetworkDeadlineExceededError(
                "network scheduling deadline is exhausted"
            )

        acquired = False
        deadline = asyncio.timeout(float(deadline_seconds))
        try:
            async with deadline:
                await self._acquire(normalized_host)
                acquired = True
                yield
        except TimeoutError:
            if deadline.expired():
                raise NetworkDeadlineExceededError(
                    "network scheduling deadline is exhausted"
                ) from None
            raise
        finally:
            if acquired:
                self._release(normalized_host)

    async def _acquire(self, host: str) -> None:
        loop = self._event_loop()
        waiter = _Waiter(host=host, future=loop.create_future())
        self._waiters.append(waiter)
        self._pump(loop)
        try:
            await waiter.future
        except BaseException:
            if waiter.future.done() and not waiter.future.cancelled():
                self._release(host)
            else:
                self._discard_waiter(waiter)
                self._pump(loop)
            raise

    def _release(self, host: str) -> None:
        """Release capacity synchronously so cancellation cannot interrupt it."""

        active = self._active_by_host.get(host, 0)
        if self._active_global <= 0 or active <= 0:
            raise RuntimeError("network scheduler capacity accounting underflow")
        self._active_global -= 1
        if active == 1:
            del self._active_by_host[host]
        else:
            self._active_by_host[host] = active - 1
        self._pump(self._event_loop())

    def _event_loop(self) -> asyncio.AbstractEventLoop:
        loop = asyncio.get_running_loop()
        if self._loop is None:
            self._loop = loop
        elif self._loop is not loop:
            if self._active_global or self._waiters:
                raise RuntimeError(
                    "network scheduler cannot span active event loops"
                )
            if self._wake_handle is not None:
                self._wake_handle.cancel()
                self._wake_handle = None
            self._last_started_at.clear()
            self._loop = loop
        return loop

    def _pump(self, loop: asyncio.AbstractEventLoop) -> None:
        """Admit the oldest currently eligible waiter without head-of-line blocking."""

        if self._wake_handle is not None:
            self._wake_handle.cancel()
            self._wake_handle = None
        self._discard_cancelled_waiters()

        while self._active_global < self.global_concurrency and self._waiters:
            now = loop.time()
            self._prune_host_history(now)
            selected, wake_at = self._next_eligible_waiter(now)
            if selected is None:
                if wake_at is not None:
                    self._wake_handle = loop.call_at(wake_at, self._wake)
                return

            waiter = self._waiters[selected]
            del self._waiters[selected]
            self._active_global += 1
            self._active_by_host[waiter.host] = (
                self._active_by_host.get(waiter.host, 0) + 1
            )
            if self.per_host_min_interval_seconds > 0:
                self._last_started_at[waiter.host] = now
                self._last_started_at.move_to_end(waiter.host)
            waiter.future.set_result(None)

    def _next_eligible_waiter(
        self,
        now: float,
    ) -> tuple[int | None, float | None]:
        wake_at: float | None = None
        for index, waiter in enumerate(self._waiters):
            if (
                self._active_by_host.get(waiter.host, 0)
                >= self.per_host_concurrency
            ):
                continue

            last_started_at = self._last_started_at.get(waiter.host)
            if (
                last_started_at is not None
                and last_started_at + self.per_host_min_interval_seconds > now
            ):
                host_ready_at = (
                    last_started_at + self.per_host_min_interval_seconds
                )
                wake_at = (
                    host_ready_at
                    if wake_at is None
                    else min(wake_at, host_ready_at)
                )
                continue

            if (
                self.per_host_min_interval_seconds > 0
                and waiter.host not in self._last_started_at
                and len(self._last_started_at) >= self.host_history_limit
            ):
                oldest_started_at = next(iter(self._last_started_at.values()))
                history_ready_at = (
                    oldest_started_at + self.per_host_min_interval_seconds
                )
                wake_at = (
                    history_ready_at
                    if wake_at is None
                    else min(wake_at, history_ready_at)
                )
                continue
            return index, wake_at
        return None, wake_at

    def _prune_host_history(self, now: float) -> None:
        if self.per_host_min_interval_seconds == 0:
            self._last_started_at.clear()
            return
        while self._last_started_at:
            host, started_at = next(iter(self._last_started_at.items()))
            if started_at + self.per_host_min_interval_seconds > now:
                return
            del self._last_started_at[host]

    def _discard_waiter(self, waiter: _Waiter) -> None:
        with suppress(ValueError):
            self._waiters.remove(waiter)

    def _discard_cancelled_waiters(self) -> None:
        self._waiters = deque(
            waiter for waiter in self._waiters if not waiter.future.cancelled()
        )

    def _wake(self) -> None:
        self._wake_handle = None
        if self._loop is not None:
            self._pump(self._loop)


def _normalize_host(host: str) -> str:
    if not isinstance(host, str):
        raise ValueError("network scheduler host is invalid")
    if not host or host != host.strip() or "%" in host:
        raise ValueError("network scheduler host is invalid")

    candidate = host
    bracketed = candidate.startswith("[") and candidate.endswith("]")
    if bracketed:
        candidate = candidate[1:-1]
    elif "[" in candidate or "]" in candidate:
        raise ValueError("network scheduler host is invalid")
    elif candidate.endswith("."):
        candidate = candidate[:-1]
        if candidate.endswith("."):
            raise ValueError("network scheduler host is invalid")

    try:
        address = ipaddress.ip_address(candidate)
    except ValueError:
        if bracketed:
            raise ValueError("network scheduler host is invalid") from None
        if ":" in candidate or re.fullmatch(r"[0-9.]+", candidate):
            raise ValueError("network scheduler host is invalid") from None
    else:
        if bracketed and address.version != 6:
            raise ValueError("network scheduler host is invalid")
        return address.compressed.casefold()

    try:
        normalized = candidate.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise ValueError("network scheduler host is invalid") from exc
    labels = normalized.split(".")
    if (
        not normalized
        or len(normalized) > 253
        or any(_DOMAIN_LABEL.fullmatch(label) is None for label in labels)
    ):
        raise ValueError("network scheduler host is invalid")
    return normalized


__all__ = ["NetworkDeadlineExceededError", "NetworkScheduler"]
