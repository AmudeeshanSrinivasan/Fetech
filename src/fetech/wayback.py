"""Bounded, policy-checked Internet Archive Wayback snapshot connector."""

from __future__ import annotations

import asyncio
import json
import math
import re
import time
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Protocol
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit

import httpx

from fetech.adapters.base import (
    AdapterBudgetExceededError,
    AdapterExecutionError,
    AdapterNotFoundError,
)
from fetech.adapters.cache import ArchivedSnapshot, SnapshotConnectorUsage
from fetech.scheduling import NetworkDeadlineExceededError, NetworkScheduler
from fetech.security import (
    PolicyBlockedError,
    SafeURLPolicy,
    normalize_url,
    sanitize_url,
)
from fetech.transport import PinnedAsyncHTTPTransport

_AVAILABILITY_ENDPOINT = "https://archive.org/wayback/available"
_AVAILABILITY_HOST = "archive.org"
_SNAPSHOT_HOST = "web.archive.org"
_MAX_AVAILABILITY_BYTES = 256_000
_MAX_REDIRECTS = 4
_MAX_HEADER_BYTES = 65_536
_MAX_HEADERS = 128
_MAX_ORIGINAL_URL_BYTES = 8_192
_MAX_REQUEST_URL_BYTES = 32_768
_CAPTURE_PATH = re.compile(
    r"^/web/(?P<timestamp>\d{14})(?P<modifier>[a-z_]+)?/"
    r"(?P<original>https?://.+)$",
    re.IGNORECASE,
)
_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_MEDIA_TYPE_VALUE = re.compile(
    r"^[!#$%&'*+\-.^_`|~0-9a-z]+/[!#$%&'*+\-.^_`|~0-9a-z]+$"
)
_SENSITIVE_QUERY_MARKERS = (
    "accesskey",
    "credential",
    "jwt",
    "password",
    "passwd",
    "secret",
    "session",
    "signature",
    "token",
)


@dataclass(frozen=True, slots=True)
class WaybackHTTPResponse:
    """One bounded response returned by the connector-owned HTTP boundary."""

    status_code: int
    url: str
    headers: Mapping[str, str]
    body: bytes


class WaybackHTTPClient(Protocol):
    """Minimal testable boundary for policy-checked Wayback requests."""

    async def get(
        self,
        url: str,
        *,
        allowed_host: str,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> WaybackHTTPResponse: ...


class PinnedWaybackHTTPClient:
    """Fetch exact Wayback hosts with redirect-by-redirect DNS validation."""

    def __init__(
        self,
        *,
        policy: SafeURLPolicy,
        user_agent: str,
        maximum_redirects: int = _MAX_REDIRECTS,
        scheduler: NetworkScheduler | None = None,
    ) -> None:
        if (
            not isinstance(user_agent, str)
            or not user_agent
            or user_agent != user_agent.strip()
            or len(user_agent) > 512
            or any(not 0x20 <= ord(character) <= 0x7E for character in user_agent)
        ):
            raise ValueError("Wayback user agent is invalid")
        if (
            isinstance(maximum_redirects, bool)
            or not isinstance(maximum_redirects, int)
            or maximum_redirects < 0
        ):
            raise ValueError("Wayback redirect bound cannot be negative")
        self.policy = policy
        self.user_agent = user_agent
        self.maximum_redirects = maximum_redirects
        self.scheduler = scheduler or NetworkScheduler()

    async def get(
        self,
        url: str,
        *,
        allowed_host: str,
        maximum_bytes: int,
        deadline_seconds: float,
        maximum_redirects: int | None = None,
        usage: SnapshotConnectorUsage | None = None,
    ) -> WaybackHTTPResponse:
        _validate_request_budget(maximum_bytes, deadline_seconds)
        active_usage = usage if usage is not None else SnapshotConnectorUsage()
        redirect_ceiling = (
            active_usage.redirects + self.maximum_redirects
            if maximum_redirects is None
            else maximum_redirects
        )
        _validate_redirect_budget(redirect_ceiling)
        try:
            async with asyncio.timeout(deadline_seconds):
                return await self._get_within_deadline(
                    url,
                    allowed_host=allowed_host,
                    maximum_bytes=maximum_bytes,
                    maximum_redirects=redirect_ceiling,
                    deadline_seconds=deadline_seconds,
                    usage=active_usage,
                )
        except NetworkDeadlineExceededError:
            raise
        except TimeoutError:
            raise NetworkDeadlineExceededError(
                "Wayback request exceeded its deadline"
            ) from None

    async def _get_within_deadline(
        self,
        url: str,
        *,
        allowed_host: str,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> WaybackHTTPResponse:
        expected_host = allowed_host.casefold().rstrip(".")
        current = _normalize_request_url(url)
        started = time.monotonic()
        previous: str | None = None

        for redirect_count in range(self.maximum_redirects + 1):
            remaining = deadline_seconds - (time.monotonic() - started)
            if remaining <= 0:
                raise NetworkDeadlineExceededError(
                    "Wayback request exceeded its deadline"
                )
            _require_exact_https_host(current, expected_host)
            host = (urlsplit(current).hostname or "").casefold().rstrip(".")
            try:
                async with self.scheduler.slot(
                    host,
                    deadline_seconds=remaining,
                ):
                    normalized, _ = await self.policy.evaluate(
                        current,
                        previous_url=previous,
                    )
                    normalized_host = (
                        urlsplit(normalized).hostname or ""
                    ).casefold().rstrip(".")
                    addresses = self.policy.validated_addresses(normalized_host)
                    if not addresses:
                        raise PolicyBlockedError(
                            "Wayback destination has no validated address pin"
                        )

                    transport = PinnedAsyncHTTPTransport()
                    transport.pin(normalized_host, addresses)
                    request_remaining = deadline_seconds - (
                        time.monotonic() - started
                    )
                    if request_remaining <= 0:
                        raise NetworkDeadlineExceededError(
                            "Wayback request exceeded its deadline"
                        )
                    async with (
                        httpx.AsyncClient(
                            transport=transport,
                            follow_redirects=False,
                            timeout=httpx.Timeout(request_remaining),
                            trust_env=False,
                            headers={
                                "Accept": (
                                    "application/json, text/html;q=0.9, "
                                    "*/*;q=0.1"
                                ),
                                "Accept-Encoding": "identity",
                                "User-Agent": self.user_agent,
                            },
                        ) as client,
                        client.stream("GET", normalized) as response,
                    ):
                        headers = _bounded_headers(response.headers)
                        if response.status_code in {301, 302, 303, 307, 308}:
                            usage.record(redirects=1)
                            if usage.redirects > maximum_redirects:
                                raise AdapterBudgetExceededError(
                                    "Wayback redirect budget exhausted"
                                )
                            location = headers.get("location")
                            if (
                                not location
                                or redirect_count >= self.maximum_redirects
                            ):
                                raise AdapterExecutionError(
                                    "Wayback redirect response is invalid"
                                )
                            previous = normalized
                            current = _normalize_request_url(
                                urljoin(normalized, location)
                            )
                            continue
                        encoding = headers.get(
                            "content-encoding",
                            "identity",
                        ).casefold()
                        if encoding not in {"", "identity"}:
                            raise AdapterExecutionError(
                                "Wayback response compression is not accepted"
                            )
                        transfer_encoding = headers.get(
                            "transfer-encoding",
                            "",
                        ).strip().casefold()
                        if transfer_encoding not in {"", "chunked"}:
                            raise AdapterExecutionError(
                                "Wayback response transfer encoding is not "
                                "accepted"
                            )
                        length = headers.get("content-length")
                        if length is not None and transfer_encoding:
                            raise AdapterExecutionError(
                                "Wayback response framing is ambiguous"
                            )
                        if length is not None:
                            try:
                                declared = int(length)
                            except ValueError as exc:
                                raise AdapterExecutionError(
                                    "Wayback response has an invalid content "
                                    "length"
                                ) from exc
                            if declared < 0 or declared > maximum_bytes:
                                raise AdapterBudgetExceededError(
                                    "Wayback response exceeds the byte budget"
                                )
                        body = await _read_bounded(
                            response,
                            maximum_bytes,
                            usage=usage,
                        )
                        try:
                            response_url = normalize_url(str(response.url))
                        except ValueError as exc:
                            raise AdapterExecutionError(
                                "Wayback transport returned an invalid response "
                                "URL"
                            ) from exc
                        return WaybackHTTPResponse(
                            status_code=response.status_code,
                            url=response_url,
                            headers=headers,
                            body=body,
                        )
            except (
                AdapterExecutionError,
                NetworkDeadlineExceededError,
                PolicyBlockedError,
            ):
                raise
            except httpx.TimeoutException as exc:
                raise NetworkDeadlineExceededError(
                    "Wayback request exceeded its deadline"
                ) from exc
            except httpx.HTTPError as exc:
                raise AdapterExecutionError("Wayback transport failed") from exc

        raise AdapterExecutionError("Wayback redirect bound was exhausted")


class WaybackSnapshotConnector:
    """Resolve and retrieve the closest public Wayback capture."""

    def __init__(
        self,
        *,
        policy: SafeURLPolicy,
        user_agent: str,
        client: WaybackHTTPClient | None = None,
        scheduler: NetworkScheduler | None = None,
    ) -> None:
        self.client = client or PinnedWaybackHTTPClient(
            policy=policy,
            user_agent=user_agent,
            scheduler=scheduler,
        )

    async def fetch_snapshot(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        deadline_seconds: float,
    ) -> ArchivedSnapshot:
        return await self.fetch_snapshot_with_usage(
            original_url,
            maximum_bytes=maximum_bytes,
            maximum_redirects=_MAX_REDIRECTS * 2,
            deadline_seconds=deadline_seconds,
            usage=SnapshotConnectorUsage(),
        )

    async def fetch_snapshot_with_usage(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> ArchivedSnapshot:
        _validate_request_budget(maximum_bytes, deadline_seconds)
        _validate_redirect_budget(maximum_redirects)
        if not isinstance(usage, SnapshotConnectorUsage):
            raise TypeError("Wayback usage ledger is invalid")
        try:
            async with asyncio.timeout(deadline_seconds):
                return await self._fetch_snapshot_within_deadline(
                    original_url,
                    maximum_bytes=maximum_bytes,
                    maximum_redirects=maximum_redirects,
                    deadline_seconds=deadline_seconds,
                    usage=usage,
                )
        except NetworkDeadlineExceededError:
            raise
        except TimeoutError:
            raise NetworkDeadlineExceededError(
                "Wayback connector exceeded its deadline"
            ) from None

    async def _fetch_snapshot_within_deadline(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> ArchivedSnapshot:
        try:
            original = normalize_url(original_url)
            original_size = len(original.encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise PolicyBlockedError("Wayback original URL is invalid") from exc
        if original_size > _MAX_ORIGINAL_URL_BYTES:
            raise PolicyBlockedError("Wayback original URL exceeds its length bound")
        if sanitize_url(original) != original or _has_sensitive_query_key(original):
            raise PolicyBlockedError(
                "Wayback lookup cannot receive sensitive URL query values"
            )
        started = time.monotonic()
        availability_url = (
            f"{_AVAILABILITY_ENDPOINT}?{urlencode({'url': original})}"
        )
        availability = await self.client.get(
            availability_url,
            allowed_host=_AVAILABILITY_HOST,
            maximum_bytes=min(_MAX_AVAILABILITY_BYTES, maximum_bytes),
            maximum_redirects=maximum_redirects,
            deadline_seconds=deadline_seconds,
            usage=usage,
        )
        if len(availability.body) > min(_MAX_AVAILABILITY_BYTES, maximum_bytes):
            raise AdapterBudgetExceededError(
                "Wayback availability response exceeds the byte budget"
            )
        if availability.status_code != 200:
            raise AdapterExecutionError("Wayback availability lookup failed")
        snapshot_url, captured_at = _parse_availability(
            availability.body,
            original=original,
        )
        remaining_bytes = maximum_bytes - len(availability.body)
        if remaining_bytes <= 0:
            raise AdapterBudgetExceededError(
                "Wayback availability lookup exhausted the byte budget"
            )

        remaining = deadline_seconds - (time.monotonic() - started)
        if remaining <= 0:
            raise NetworkDeadlineExceededError(
                "Wayback connector exceeded its deadline"
            )
        snapshot = await self.client.get(
            snapshot_url,
            allowed_host=_SNAPSHOT_HOST,
            maximum_bytes=remaining_bytes,
            maximum_redirects=maximum_redirects,
            deadline_seconds=remaining,
            usage=usage,
        )
        if snapshot.status_code != 200:
            if snapshot.status_code in {404, 410}:
                raise AdapterNotFoundError("Wayback snapshot is unavailable")
            raise AdapterExecutionError("Wayback snapshot retrieval failed")
        if len(snapshot.body) > remaining_bytes:
            raise AdapterBudgetExceededError(
                "Wayback snapshot exceeds the byte budget"
            )
        _validate_capture_url(
            snapshot.url,
            original=original,
            timestamp=captured_at.strftime("%Y%m%d%H%M%S"),
        )
        media_type = _media_type(snapshot.headers)
        return ArchivedSnapshot(
            original_url=original,
            snapshot_url=snapshot.url,
            body=snapshot.body,
            media_type=media_type,
            captured_at=captured_at,
            etag=_optional_validator(snapshot.headers.get("etag")),
            last_modified=_optional_validator(snapshot.headers.get("last-modified")),
            auxiliary_bytes=len(availability.body),
        )


async def _read_bounded(
    response: httpx.Response,
    maximum_bytes: int,
    *,
    usage: SnapshotConnectorUsage,
) -> bytes:
    chunks: list[bytes] = []
    size = 0
    async for chunk in response.aiter_raw():
        size += len(chunk)
        usage.record(
            wire_bytes=len(chunk),
            decompressed_bytes=len(chunk),
        )
        if size > maximum_bytes:
            raise AdapterBudgetExceededError("Wayback response exceeds the byte budget")
        chunks.append(chunk)
    return b"".join(chunks)


def _bounded_headers(headers: httpx.Headers) -> dict[str, str]:
    items = list(headers.multi_items())
    if len(items) > _MAX_HEADERS:
        raise AdapterExecutionError("Wayback response has too many headers")
    result: dict[str, str] = {}
    size = 0
    for key, value in items:
        encoded_size = _encoded_length(key) + _encoded_length(value)
        size += encoded_size
        if (
            size > _MAX_HEADER_BYTES
            or _HEADER_NAME.fullmatch(key) is None
            or any(
                (ord(character) < 32 and character != "\t")
                or ord(character) == 127
                for character in value
            )
        ):
            raise AdapterExecutionError("Wayback response headers are invalid")
        normalized = key.casefold()
        if normalized in result:
            result[normalized] = f"{result[normalized]}, {value}"
        else:
            result[normalized] = value
    return result


def _parse_availability(body: bytes, *, original: str) -> tuple[str, datetime]:
    if not body or len(body) > _MAX_AVAILABILITY_BYTES:
        raise AdapterExecutionError("Wayback availability response is invalid")
    try:
        document = json.loads(
            body,
            object_pairs_hook=_strict_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AdapterExecutionError(
            "Wayback availability response is malformed"
        ) from exc
    if not isinstance(document, dict):
        raise AdapterExecutionError("Wayback availability response must be an object")
    archived = document.get("archived_snapshots")
    if not isinstance(archived, dict):
        raise AdapterExecutionError("Wayback availability response omitted snapshots")
    closest = archived.get("closest")
    if closest is None:
        raise AdapterNotFoundError("no Wayback snapshot is available")
    if not isinstance(closest, dict):
        raise AdapterExecutionError("Wayback closest snapshot is invalid")
    available = closest.get("available")
    status = closest.get("status")
    timestamp = closest.get("timestamp")
    locator = closest.get("url")
    if (
        available is not True
        or (status != 200 and status != "200")
        or not isinstance(timestamp, str)
        or re.fullmatch(r"\d{14}", timestamp) is None
        or not isinstance(locator, str)
        or not locator
        or _encoded_length(locator) > _MAX_ORIGINAL_URL_BYTES
    ):
        raise AdapterNotFoundError("no usable Wayback snapshot is available")
    _validate_capture_url(
        locator,
        original=original,
        timestamp=timestamp,
        allow_http=True,
    )
    try:
        captured_at = datetime.strptime(timestamp, "%Y%m%d%H%M%S").replace(
            tzinfo=UTC
        )
    except ValueError as exc:
        raise AdapterExecutionError("Wayback capture timestamp is invalid") from exc
    return _canonical_capture_url(locator, timestamp=timestamp), captured_at


def _validate_capture_url(
    url: str,
    *,
    original: str,
    timestamp: str,
    allow_http: bool = False,
) -> None:
    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.casefold()
        host = (parsed.hostname or "").casefold().rstrip(".")
        port = parsed.port
    except ValueError as exc:
        raise AdapterExecutionError(
            "Wayback capture locator is not an exact archive origin"
        ) from exc
    if (
        scheme not in ({"http", "https"} if allow_http else {"https"})
        or host != _SNAPSHOT_HOST
        or parsed.username is not None
        or parsed.password is not None
        or parsed.fragment
        or port not in {None, 443 if scheme == "https" else 80}
    ):
        raise AdapterExecutionError("Wayback capture locator is not an exact archive origin")
    combined = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    match = _CAPTURE_PATH.fullmatch(combined)
    if match is None or match.group("timestamp") != timestamp:
        raise AdapterExecutionError("Wayback capture locator is malformed")
    if not allow_http and match.group("modifier") != "id_":
        raise AdapterExecutionError(
            "Wayback final capture locator is not in raw snapshot mode"
        )
    try:
        embedded = normalize_url(match.group("original"))
    except ValueError as exc:
        raise AdapterExecutionError(
            "Wayback capture locator omitted the original source"
        ) from exc
    if embedded != original:
        raise AdapterExecutionError(
            "Wayback capture locator changed the original source authority"
        )


def _canonical_capture_url(locator: str, *, timestamp: str) -> str:
    parsed = urlsplit(locator)
    combined = parsed.path + (f"?{parsed.query}" if parsed.query else "")
    match = _CAPTURE_PATH.fullmatch(combined)
    if match is None:
        raise AdapterExecutionError("Wayback capture locator is malformed")
    return (
        f"https://{_SNAPSHOT_HOST}/web/{timestamp}id_/"
        f"{match.group('original')}"
    )


def _require_exact_https_host(url: str, expected_host: str) -> None:
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").casefold().rstrip(".")
        port = parsed.port
        url_size = len(url.encode("utf-8"))
    except ValueError as exc:
        raise PolicyBlockedError(
            "Wayback requests require an exact HTTPS archive origin"
        ) from exc
    if (
        url_size > _MAX_REQUEST_URL_BYTES
        or parsed.scheme.casefold() != "https"
        or host != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise PolicyBlockedError("Wayback requests require an exact HTTPS archive origin")


def _strict_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON keys are forbidden")
        result[key] = value
    return result


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _media_type(headers: Mapping[str, str]) -> str:
    value = headers.get("content-type", "application/octet-stream")
    if not isinstance(value, str):
        raise AdapterExecutionError("Wayback snapshot media type is invalid")
    media_type = value.split(";", maxsplit=1)[0].strip().casefold()
    if (
        not media_type
        or len(media_type) > 255
        or "*" in media_type
        or _MEDIA_TYPE_VALUE.fullmatch(media_type) is None
    ):
        raise AdapterExecutionError("Wayback snapshot media type is invalid")
    return media_type


def _optional_validator(value: str | None) -> str | None:
    if value is None or not isinstance(value, str):
        return None
    candidate = value.strip()
    try:
        encoded_size = len(candidate.encode("utf-8"))
    except UnicodeError:
        return None
    if (
        not candidate
        or encoded_size > 1_024
        or any(ord(character) < 32 and character != "\t" for character in candidate)
    ):
        return None
    return candidate


def _validate_request_budget(
    maximum_bytes: int,
    deadline_seconds: float,
) -> None:
    if (
        isinstance(maximum_bytes, bool)
        or not isinstance(maximum_bytes, int)
        or maximum_bytes <= 0
        or isinstance(deadline_seconds, bool)
        or not isinstance(deadline_seconds, int | float)
        or not math.isfinite(deadline_seconds)
        or deadline_seconds <= 0
    ):
        raise AdapterBudgetExceededError("Wayback request has no remaining budget")


def _validate_redirect_budget(maximum_redirects: int) -> None:
    if (
        isinstance(maximum_redirects, bool)
        or not isinstance(maximum_redirects, int)
        or maximum_redirects < 0
    ):
        raise AdapterBudgetExceededError(
            "Wayback request has an invalid redirect budget"
        )


def _has_sensitive_query_key(url: str) -> bool:
    for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True):
        compact = re.sub(r"[^a-z0-9]", "", key.casefold())
        if any(marker in compact for marker in _SENSITIVE_QUERY_MARKERS):
            return True
    return False


def _normalize_request_url(url: str) -> str:
    try:
        return normalize_url(url)
    except (TypeError, ValueError) as exc:
        raise PolicyBlockedError(
            "Wayback requests require a valid HTTPS archive URL"
        ) from exc


def _encoded_length(value: str) -> int:
    try:
        return len(value.encode("utf-8"))
    except UnicodeError as exc:
        raise AdapterExecutionError("Wayback response text is invalid") from exc
