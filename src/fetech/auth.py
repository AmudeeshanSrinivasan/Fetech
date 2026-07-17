"""Opaque, exact-origin credential contracts for authenticated acquisition."""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urlsplit

SUPPORTED_AUTH_CAPABILITIES = frozenset({"api_key", "bearer_token", "cookie_session"})
MAX_CREDENTIAL_HEADERS = 32
MAX_CREDENTIAL_COOKIES = 64
MAX_CREDENTIAL_HEADER_VALUE_BYTES = 16 * 1024
MAX_CREDENTIAL_COOKIE_VALUE_BYTES = 4 * 1024
MAX_CREDENTIAL_MATERIAL_BYTES = 64 * 1024

_HEADER_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_VALUE = re.compile(r"^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$")
_FORBIDDEN_CREDENTIAL_HEADERS = frozenset(
    {
        "accept",
        "accept-language",
        "connection",
        "content-length",
        "content-type",
        "cookie",
        "host",
        "proxy-authenticate",
        "proxy-authorization",
        "range",
        "set-cookie",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "user-agent",
    }
)


class CredentialProviderError(RuntimeError):
    """Base error for a configured credential provider."""


class CredentialNotFoundError(CredentialProviderError):
    """The opaque reference is unknown to the configured provider."""


class CredentialProviderUnavailableError(CredentialProviderError):
    """The configured provider cannot currently resolve references."""


class CredentialProvider(Protocol):
    """Resolve an opaque reference without exposing secrets to public contracts."""

    async def resolve(self, reference: str) -> CredentialMaterial: ...


class RefreshableCredentialProvider(CredentialProvider, Protocol):
    """Optionally replace expired material without exposing refresh credentials."""

    async def refresh(self, reference: str) -> CredentialMaterial: ...


@dataclass(frozen=True, slots=True)
class CredentialMaterial:
    """Sensitive in-memory material restricted to one canonical HTTPS origin."""

    origin: str
    capability_id: str
    headers: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False, hash=False)
    cookies: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False, hash=False)
    expires_at: datetime | None = None

    def __post_init__(self) -> None:
        origin = canonical_origin(self.origin, origin_only=True)
        if not origin.startswith("https://"):
            raise ValueError("credential material must be scoped to an HTTPS origin")
        if self.capability_id not in SUPPORTED_AUTH_CAPABILITIES:
            raise ValueError("credential material uses an unsupported authentication capability")
        headers = _validated_headers(self.headers)
        cookies = _validated_cookies(self.cookies)
        if not headers and not cookies:
            raise ValueError("credential material must contain at least one header or cookie")
        if self.capability_id == "cookie_session" and not cookies:
            raise ValueError("cookie_session material must contain at least one cookie")
        if self.capability_id == "api_key" and not headers:
            raise ValueError("api_key material must contain at least one header")
        if self.capability_id == "bearer_token" and not any(
            name.lower() == "authorization" and value.lower().startswith("bearer ")
            for name, value in headers.items()
        ):
            raise ValueError("bearer_token material must contain a Bearer Authorization header")
        if self.expires_at is not None and self.expires_at.utcoffset() is None:
            raise ValueError("credential expiry must include a timezone")
        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "headers", MappingProxyType(headers))
        object.__setattr__(self, "cookies", MappingProxyType(cookies))

    @classmethod
    def bearer(
        cls,
        origin: str,
        token: str,
        *,
        expires_at: datetime | None = None,
    ) -> CredentialMaterial:
        if not token:
            raise ValueError("bearer token cannot be empty")
        return cls(
            origin=origin,
            capability_id="bearer_token",
            headers={"Authorization": f"Bearer {token}"},
            expires_at=expires_at,
        )

    @classmethod
    def api_key(
        cls,
        origin: str,
        value: str,
        *,
        header_name: str = "X-API-Key",
        expires_at: datetime | None = None,
    ) -> CredentialMaterial:
        return cls(
            origin=origin,
            capability_id="api_key",
            headers={header_name: value},
            expires_at=expires_at,
        )

    @classmethod
    def cookie_session(
        cls,
        origin: str,
        cookies: Mapping[str, str],
        *,
        expires_at: datetime | None = None,
    ) -> CredentialMaterial:
        return cls(
            origin=origin,
            capability_id="cookie_session",
            cookies=cookies,
            expires_at=expires_at,
        )

    @property
    def expired(self) -> bool:
        return self.expires_at is not None and datetime.now(UTC) >= self.expires_at.astimezone(UTC)

    def applies_to(self, url: str) -> bool:
        return canonical_origin(url) == self.origin

    def request_headers(self) -> dict[str, str]:
        """Return a short-lived per-request copy; callers must never persist it."""

        headers = dict(self.headers)
        if self.cookies:
            headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in self.cookies.items())
        return headers


class NullCredentialProvider:
    """Fail-closed default used when no credential store is configured."""

    async def resolve(self, reference: str) -> CredentialMaterial:
        del reference
        raise CredentialNotFoundError("authentication reference is unavailable")


class InMemoryCredentialProvider:
    """Explicit library/test provider; secrets remain process-local and repr-hidden."""

    def __init__(
        self,
        credentials: Mapping[str, CredentialMaterial],
        *,
        refreshed: Mapping[str, CredentialMaterial] | None = None,
    ) -> None:
        if any(not reference.strip() for reference in credentials):
            raise ValueError("authentication references cannot be blank")
        if refreshed is not None and any(not reference.strip() for reference in refreshed):
            raise ValueError("refresh references cannot be blank")
        self._credentials = dict(credentials)
        self._refreshed = dict(refreshed or {})

    async def resolve(self, reference: str) -> CredentialMaterial:
        try:
            return self._credentials[reference]
        except KeyError as exc:
            raise CredentialNotFoundError("authentication reference is unavailable") from exc

    async def refresh(self, reference: str) -> CredentialMaterial:
        try:
            material = self._refreshed.pop(reference)
        except KeyError as exc:
            raise CredentialNotFoundError("refresh material is unavailable") from exc
        self._credentials[reference] = material
        return material


def canonical_origin(url: str, *, origin_only: bool = False) -> str:
    """Normalize scheme, IDNA host, and effective port for exact-origin comparisons."""

    candidate = url.strip()
    parts = urlsplit(candidate)
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"}:
        raise ValueError("credential origins support only HTTP and HTTPS")
    if parts.username or parts.password:
        raise ValueError("credential origins cannot contain user information")
    if not parts.hostname:
        raise ValueError("credential origins require a hostname")
    if origin_only and (parts.path not in {"", "/"} or parts.query or parts.fragment):
        raise ValueError("credential scope must contain an origin only")
    host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    rendered_host = f"[{host}]" if ":" in host else host
    port = parts.port
    default_port = (scheme == "http" and port in {None, 80}) or (
        scheme == "https" and port in {None, 443}
    )
    return f"{scheme}://{rendered_host}" if default_port else f"{scheme}://{rendered_host}:{port}"


def authentication_cache_scope(authentication_ref: str | None) -> str:
    """Derive a deterministic partition without storing the raw opaque reference."""

    if authentication_ref is None:
        return "public"
    if not authentication_ref.strip():
        raise ValueError("authentication reference cannot be blank")
    digest = hashlib.sha256(
        b"fetech-authentication-scope-v1\0" + authentication_ref.encode("utf-8")
    ).hexdigest()
    return f"auth:sha256:{digest}"


def _validated_headers(headers: Mapping[str, str]) -> dict[str, str]:
    if len(headers) > MAX_CREDENTIAL_HEADERS:
        raise ValueError("credential material contains too many HTTP headers")
    validated: dict[str, str] = {}
    seen: set[str] = set()
    total_bytes = 0
    for name, value in headers.items():
        lowered = name.lower()
        if (
            len(name) > 256
            or _HEADER_NAME.fullmatch(name) is None
            or lowered in _FORBIDDEN_CREDENTIAL_HEADERS
        ):
            raise ValueError("credential material contains a forbidden HTTP header")
        value_bytes = len(value.encode("utf-8"))
        total_bytes += len(name.encode("ascii")) + value_bytes
        if (
            value_bytes > MAX_CREDENTIAL_HEADER_VALUE_BYTES
            or total_bytes > MAX_CREDENTIAL_MATERIAL_BYTES
        ):
            raise ValueError("credential material exceeds the HTTP header byte limit")
        if lowered in seen:
            raise ValueError("credential material contains duplicate HTTP header names")
        if not value or any(not 32 <= ord(character) <= 126 for character in value):
            raise ValueError("credential material contains an invalid HTTP header value")
        seen.add(lowered)
        validated[name] = value
    return validated


def _validated_cookies(cookies: Mapping[str, str]) -> dict[str, str]:
    if len(cookies) > MAX_CREDENTIAL_COOKIES:
        raise ValueError("credential material contains too many cookies")
    validated: dict[str, str] = {}
    total_bytes = 0
    for name, value in cookies.items():
        if (
            len(name) > 256
            or _HEADER_NAME.fullmatch(name) is None
            or _COOKIE_VALUE.fullmatch(value) is None
        ):
            raise ValueError("credential material contains an invalid cookie")
        value_bytes = len(value.encode("ascii"))
        total_bytes += len(name.encode("ascii")) + value_bytes
        if (
            value_bytes > MAX_CREDENTIAL_COOKIE_VALUE_BYTES
            or total_bytes > MAX_CREDENTIAL_MATERIAL_BYTES
        ):
            raise ValueError("credential material contains an invalid cookie")
        validated[name] = value
    return validated
