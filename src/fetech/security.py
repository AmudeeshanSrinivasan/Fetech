"""Fail-closed destination validation and redaction utilities."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fetech.models import FetchRequest, PolicyDecision

BLOCKED_HOSTNAMES = {"localhost", "localhost.localdomain", "metadata.google.internal"}
SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "code",
    "key",
    "password",
    "signature",
    "sig",
    "token",
}
DEFAULT_ALLOWED_PORTS = {80, 443}
_URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)
_URL_FIELD_NAMES = {
    "action",
    "authority_url",
    "candidate",
    "canonical_url",
    "destination",
    "normalized_target",
    "parent_url",
    "requested_url",
    "root_url",
    "source_url",
    "target",
    "url",
}


class PolicyBlockedError(PermissionError):
    def __init__(self, reason: str, decisions: tuple[PolicyDecision, ...] = ()) -> None:
        super().__init__(reason)
        self.reason = reason
        self.decisions = decisions


def sanitize_url(url: str, *, redact_query: bool = False) -> str:
    """Return a fragment-free URL safe for logs and public contracts.

    Ordinary public URLs retain non-sensitive query values. Callers handling an
    authenticated request must set ``redact_query`` so every query value is
    removed, including values whose parameter names are not in the static
    sensitive-key list.
    """

    parts = urlsplit(url)
    hostname = parts.hostname or ""
    port = f":{parts.port}" if parts.port else ""
    netloc = f"{hostname}{port}"
    query = urlencode(
        [
            (
                key,
                (
                    "[REDACTED]"
                    if redact_query or key.lower() in SENSITIVE_QUERY_KEYS
                    else value
                ),
            )
            for key, value in parse_qsl(parts.query)
        ]
    )
    return urlunsplit((parts.scheme, netloc, parts.path, query, ""))


def sanitize_url_for_request(url: str, request: FetchRequest) -> str:
    """Sanitize a URL according to whether the request carries authentication."""

    return sanitize_url(url, redact_query=request.authentication_ref is not None)


def sanitize_output_for_request(value: Any, request: FetchRequest, *, key: str = "") -> Any:
    """Recursively sanitize an externally visible document for a request.

    Authenticated targets treat every query value as sensitive. Besides known
    URL fields and URL-shaped substrings are scrubbed so exception messages and
    adapter details cannot leak a value under an unrecognized parameter name.
    """

    if isinstance(value, Mapping):
        return {
            str(child_key): sanitize_output_for_request(
                child,
                request,
                key=str(child_key),
            )
            for child_key, child in value.items()
        }
    if isinstance(value, tuple):
        return tuple(
            sanitize_output_for_request(child, request, key=key) for child in value
        )
    if isinstance(value, list):
        return [
            sanitize_output_for_request(child, request, key=key) for child in value
        ]
    if isinstance(value, Sequence) and not isinstance(value, str | bytes | bytearray):
        return [
            sanitize_output_for_request(child, request, key=key) for child in value
        ]
    if not isinstance(value, str):
        return value

    normalized_key = key.casefold().replace("-", "_").replace(" ", "_")
    if normalized_key in _URL_FIELD_NAMES or normalized_key.endswith("_url"):
        try:
            return sanitize_url_for_request(value, request)
        except ValueError:
            return "[REDACTED_INVALID_URL]"
    if request.authentication_ref is None:
        return value
    return sanitize_authenticated_text(value)


def sanitize_authenticated_text(value: str) -> str:
    """Scrub every query value from URL substrings in authenticated output."""

    def replace_url(match: re.Match[str]) -> str:
        candidate = match.group(0)
        trailing = ""
        while candidate and candidate[-1] in ".,;)]}":
            trailing = candidate[-1] + trailing
            candidate = candidate[:-1]
        try:
            return sanitize_url(candidate, redact_query=True) + trailing
        except ValueError:
            return "[REDACTED_INVALID_URL]" + trailing

    return _URL_IN_TEXT.sub(replace_url, value)


def normalize_url(target: str) -> str:
    candidate = target.strip()
    if not candidate:
        raise ValueError("target cannot be empty")
    parts = urlsplit(candidate)
    if parts.scheme.lower() not in {"http", "https"}:
        raise ValueError("only http and https URL targets are accepted")
    if parts.username or parts.password:
        raise ValueError("credentials in URLs are forbidden; use authentication_ref")
    if not parts.hostname:
        raise ValueError("target must include a hostname")
    host = parts.hostname.encode("idna").decode("ascii").lower().rstrip(".")
    port = parts.port
    default_port = (parts.scheme.lower() == "http" and port == 80) or (
        parts.scheme.lower() == "https" and port == 443
    )
    netloc = host if port is None or default_port else f"{host}:{port}"
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, ""))


def is_public_address(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return bool(ip.is_global and not ip.is_multicast and not ip.is_unspecified)


@dataclass(frozen=True)
class DestinationPolicy:
    allowed_ports: frozenset[int] = frozenset(DEFAULT_ALLOWED_PORTS)
    allow_public_http: bool = True
    blocked_threat_hostnames: frozenset[str] = frozenset()


class SafeURLPolicy:
    def __init__(self, policy: DestinationPolicy | None = None) -> None:
        self.policy = policy or DestinationPolicy()
        self._validated_addresses: dict[str, tuple[str, ...]] = {}

    async def evaluate(
        self, target: str, *, previous_url: str | None = None
    ) -> tuple[str, tuple[PolicyDecision, ...]]:
        try:
            normalized = normalize_url(target)
        except ValueError as exc:
            decision = PolicyDecision(policy_id="url_validation", allowed=False, reason=str(exc))
            raise PolicyBlockedError(str(exc), (decision,)) from exc
        parts = urlsplit(normalized)
        if previous_url:
            previous = urlsplit(previous_url)
            if previous.scheme == "https" and parts.scheme == "http":
                reason = "HTTPS downgrade redirects are forbidden"
                raise PolicyBlockedError(
                    reason,
                    (PolicyDecision(policy_id="redirect_security", allowed=False, reason=reason),),
                )
        if parts.scheme == "http" and not self.policy.allow_public_http:
            reason = "public HTTP is disabled by the selected policy"
            raise PolicyBlockedError(
                reason, (PolicyDecision(policy_id="url_validation", allowed=False, reason=reason),)
            )
        host = parts.hostname or ""
        if host in BLOCKED_HOSTNAMES or host.endswith(".localhost"):
            reason = "local and metadata hostnames are blocked"
            raise PolicyBlockedError(
                reason, (PolicyDecision(policy_id="ssrf_private_ip_check", allowed=False, reason=reason),)
            )
        if host in self.policy.blocked_threat_hostnames:
            reason = "destination is present in the configured malware/phishing deny-list"
            raise PolicyBlockedError(
                reason,
                (PolicyDecision(policy_id="malware_phishing_check", allowed=False, reason=reason),),
            )
        port = parts.port or (443 if parts.scheme == "https" else 80)
        if port not in self.policy.allowed_ports:
            reason = f"destination port {port} is not allowed"
            raise PolicyBlockedError(
                reason, (PolicyDecision(policy_id="ssrf_private_ip_check", allowed=False, reason=reason),)
            )
        addresses = await self._resolve(host, port)
        if not addresses:
            reason = "hostname did not resolve"
            raise PolicyBlockedError(
                reason, (PolicyDecision(policy_id="dns_resolution_check", allowed=False, reason=reason),)
            )
        blocked = [address for address in addresses if not is_public_address(address)]
        if blocked:
            reason = "destination resolved to a non-public address"
            raise PolicyBlockedError(
                reason, (PolicyDecision(policy_id="ssrf_private_ip_check", allowed=False, reason=reason),)
            )
        self._validated_addresses[host] = addresses
        decisions = (
            PolicyDecision(
                policy_id="url_validation",
                allowed=True,
                reason="valid HTTP(S) target",
                destination=sanitize_url(normalized),
            ),
            PolicyDecision(
                policy_id="dns_resolution_check",
                allowed=True,
                reason="hostname resolved",
                destination=sanitize_url(normalized),
            ),
            PolicyDecision(
                policy_id="ssrf_private_ip_check",
                allowed=True,
                reason="all resolved addresses are public",
                destination=sanitize_url(normalized),
            ),
            PolicyDecision(
                policy_id="malware_phishing_check",
                allowed=True,
                reason="destination is not in the configured threat deny-list",
                destination=sanitize_url(normalized),
            ),
        )
        return normalized, decisions

    def validated_addresses(self, host: str) -> tuple[str, ...]:
        return self._validated_addresses.get(host.lower().rstrip("."), ())

    async def _resolve(self, host: str, port: int) -> tuple[str, ...]:
        loop = asyncio.get_running_loop()
        try:
            records = await loop.getaddrinfo(host, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM)
        except socket.gaierror:
            return ()
        return tuple(sorted({str(record[4][0]) for record in records}))


def ensure_safe_redirect(previous_url: str, next_url: str) -> None:
    previous = urlsplit(previous_url)
    following = urlsplit(next_url)
    if previous.scheme == "https" and following.scheme == "http":
        raise PolicyBlockedError("HTTPS downgrade redirects are forbidden")
