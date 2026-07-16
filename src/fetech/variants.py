"""Evidence-driven URL alternatives with a permanent no-downgrade rule."""

from __future__ import annotations

from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

TRACKING_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid"}
TRACKING_PREFIXES = ("utm_",)


def clean_query_parameters(url: str) -> str:
    parts = urlsplit(url)
    query = urlencode(
        [
            (key, value)
            for key, value in parse_qsl(parts.query, keep_blank_values=True)
            if key.lower() not in TRACKING_KEYS
            and not any(key.lower().startswith(prefix) for prefix in TRACKING_PREFIXES)
        ]
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def generate_variants(url: str, *, language: str | None = None, region: str | None = None) -> tuple[str, ...]:
    parts = urlsplit(url)
    candidates: list[str] = [url, clean_query_parameters(url)]
    if parts.scheme == "http":
        candidates.append(urlunsplit(("https", parts.netloc, parts.path, parts.query, "")))
    host = parts.hostname or ""
    if host.startswith("www."):
        candidates.append(
            urlunsplit((parts.scheme, parts.netloc.removeprefix("www."), parts.path, parts.query, ""))
        )
    elif host:
        candidates.append(urlunsplit((parts.scheme, f"www.{parts.netloc}", parts.path, parts.query, "")))
    if parts.path.endswith("/") and parts.path != "/":
        candidates.append(urlunsplit((parts.scheme, parts.netloc, parts.path.rstrip("/"), parts.query, "")))
    elif not parts.path.endswith("/"):
        candidates.append(urlunsplit((parts.scheme, parts.netloc, f"{parts.path}/", parts.query, "")))
    if language:
        candidates.append(
            urlunsplit((parts.scheme, parts.netloc, f"/{language}{parts.path}", parts.query, ""))
        )
    if region:
        candidates.append(
            urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode({"region": region}), ""))
        )
    return _deduplicate(candidate for candidate in candidates if not _downgrades(url, candidate))


def _downgrades(original: str, candidate: str) -> bool:
    return urlsplit(original).scheme == "https" and urlsplit(candidate).scheme == "http"


def _deduplicate(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))
