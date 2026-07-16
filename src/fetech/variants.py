"""Evidence-driven URL alternatives with a permanent no-downgrade rule."""

from __future__ import annotations

import re
from collections.abc import Iterable
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fetech.security import normalize_url

TRACKING_KEYS = {"fbclid", "gclid", "mc_cid", "mc_eid"}
TRACKING_PREFIXES = ("utm_",)
_LANGUAGE = re.compile(r"[A-Za-z]{2,8}(?:-[A-Za-z0-9]{1,8})*")


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


def generate_variant_map(
    url: str,
    *,
    language: str | None = None,
    region: str | None = None,
    canonical_url: str | None = None,
) -> dict[str, str | None]:
    """Return one normalized candidate per registered variant capability.

    ``https_to_http`` is deliberately represented by ``None``. Keeping the
    blocked capability in this map makes the policy result observable without
    ever constructing a downgrade candidate that another stage could fetch.
    """

    original = normalize_url(url)
    parts = urlsplit(original)
    host = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    clean = clean_query_parameters(original)
    without_www = host.removeprefix("www.")
    path_without_slash = parts.path.rstrip("/") or "/"
    valid_language = language if language and _LANGUAGE.fullmatch(language) else None
    language_path = (
        f"/{valid_language.lower()}"
        f"{parts.path if parts.path.startswith('/') else f'/{parts.path}'}"
        if valid_language
        else None
    )
    query = parse_qsl(parts.query, keep_blank_values=True)
    print_query = urlencode([*query, ("output", "1")])
    region_query = urlencode([*query, ("region", region)]) if region else None

    candidates: dict[str, str | None] = {
        "http_to_https": (
            urlunsplit(("https", parts.netloc, parts.path, parts.query, ""))
            if parts.scheme == "http"
            else None
        ),
        "https_to_http": None,
        "www_to_non_www": (
            urlunsplit((parts.scheme, f"{without_www}{port}", parts.path, parts.query, ""))
            if host.startswith("www.")
            else None
        ),
        "non_www_to_www": (
            urlunsplit((parts.scheme, f"www.{host}{port}", parts.path, parts.query, ""))
            if host and not host.startswith("www.")
            else None
        ),
        "trailing_slash": (
            urlunsplit((parts.scheme, parts.netloc, f"{parts.path}/", parts.query, ""))
            if not parts.path.endswith("/")
            else None
        ),
        "remove_trailing_slash": (
            urlunsplit((parts.scheme, parts.netloc, path_without_slash, parts.query, ""))
            if parts.path.endswith("/") and parts.path != "/"
            else None
        ),
        "clean_query_parameters": clean if clean != original else None,
        "canonical_url_variant": _safe_optional_url(canonical_url),
        "mobile_variant": (
            urlunsplit((parts.scheme, f"m.{without_www}{port}", parts.path, parts.query, ""))
            if host and not host.startswith("m.")
            else None
        ),
        "amp_variant": (
            urlunsplit(
                (
                    parts.scheme,
                    parts.netloc,
                    f"{parts.path.rstrip('/')}/amp",
                    parts.query,
                    "",
                )
            )
            if not parts.path.rstrip("/").endswith("/amp")
            else None
        ),
        "print_variant": urlunsplit(
            (parts.scheme, parts.netloc, parts.path, print_query, "")
        ),
        "language_variant": (
            urlunsplit((parts.scheme, parts.netloc, language_path, parts.query, ""))
            if language_path
            else None
        ),
        "region_variant": (
            urlunsplit((parts.scheme, parts.netloc, parts.path, region_query, ""))
            if region_query
            else None
        ),
    }
    return {
        capability_id: candidate
        if candidate is None or not _downgrades(original, candidate)
        else None
        for capability_id, candidate in candidates.items()
    }


def generate_variants(
    url: str,
    *,
    language: str | None = None,
    region: str | None = None,
    canonical_url: str | None = None,
) -> tuple[str, ...]:
    original = normalize_url(url)
    candidates = generate_variant_map(
        original,
        language=language,
        region=region,
        canonical_url=canonical_url,
    )
    return _deduplicate(
        candidate
        for candidate in (original, *candidates.values())
        if candidate is not None and not _downgrades(original, candidate)
    )


def _downgrades(original: str, candidate: str) -> bool:
    return urlsplit(original).scheme == "https" and urlsplit(candidate).scheme == "http"


def _deduplicate(values: Iterable[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(values))


def _safe_optional_url(candidate: str | None) -> str | None:
    if not candidate:
        return None
    try:
        return normalize_url(candidate)
    except ValueError:
        return None
