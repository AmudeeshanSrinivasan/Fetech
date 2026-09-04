"""Bounded HTTP acquisition with redirect-by-redirect policy checks."""

from __future__ import annotations

import asyncio
import re
import time
from contextlib import AsyncExitStack
from dataclasses import dataclass
from datetime import UTC, datetime
from html.parser import HTMLParser
from typing import Literal
from urllib import robotparser
from urllib.parse import urljoin, urlsplit

import httpx

from fetech.adapters.base import (
    AdapterAuthExpiredError,
    AdapterAuthRequiredError,
    AdapterBudgetExceededError,
    AdapterDependencyError,
    AdapterExecutionError,
    AdapterNotFoundError,
    ExecutionContext,
)
from fetech.auth import (
    CredentialMaterial,
    CredentialNotFoundError,
    CredentialProvider,
    CredentialProviderError,
    CredentialProviderUnavailableError,
    NullCredentialProvider,
    canonical_origin,
)
from fetech.auth_flows import OriginScopedSession, SessionBindingError, SessionCapability
from fetech.http3 import CurlHTTP3Client
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    PlanNode,
    PolicyDecision,
    Resource,
)
from fetech.quality import assess_binary, assess_text
from fetech.scheduling import NetworkDeadlineExceededError, NetworkScheduler
from fetech.security import (
    PolicyBlockedError,
    SafeURLPolicy,
    sanitize_url,
    sanitize_url_for_request,
)
from fetech.storage import build_artifact
from fetech.transport import PinnedAsyncHTTPTransport

_EPHEMERAL_COOKIE_COUNT_LIMIT = 16
_EPHEMERAL_COOKIE_NAME_LIMIT = 128
_EPHEMERAL_COOKIE_VALUE_LIMIT = 4096
_EPHEMERAL_COOKIE_PATH_LIMIT = 1024
_EPHEMERAL_COOKIE_HEADER_LIMIT = 8192
_EPHEMERAL_SET_COOKIE_LIMIT = 16_384
_COOKIE_NAME = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_COOKIE_VALUE = re.compile(r"^[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]*$")


@dataclass(slots=True)
class _HTTPUsage:
    wire_bytes: int = 0
    decompressed_bytes: int = 0
    redirects: int = 0

    def observe(
        self,
        *,
        wire_bytes: int | None = None,
        decompressed_bytes: int | None = None,
        redirects: int | None = None,
    ) -> None:
        if wire_bytes is not None:
            self.wire_bytes = max(self.wire_bytes, wire_bytes)
        if decompressed_bytes is not None:
            self.decompressed_bytes = max(
                self.decompressed_bytes,
                decompressed_bytes,
            )
        if redirects is not None:
            self.redirects = max(self.redirects, redirects)


class HTTPAdapter:
    def __init__(
        self,
        *,
        user_agent: str,
        policy: SafeURLPolicy | None = None,
        credential_provider: CredentialProvider | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        global_concurrency: int = 8,
        per_host_concurrency: int = 2,
        per_host_min_interval_seconds: float = 0.0,
        http3_client: CurlHTTP3Client | None = None,
        scheduler: NetworkScheduler | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.policy = policy or SafeURLPolicy()
        self.credential_provider = credential_provider or NullCredentialProvider()
        self.transport = transport
        self.scheduler = scheduler or NetworkScheduler(
            global_concurrency=global_concurrency,
            per_host_concurrency=per_host_concurrency,
            per_host_min_interval_seconds=per_host_min_interval_seconds,
        )
        self._global_concurrency = self.scheduler.global_concurrency
        self._per_host_concurrency = self.scheduler.per_host_concurrency
        self._per_host_min_interval_seconds = (
            self.scheduler.per_host_min_interval_seconds
        )
        self.http3_client = http3_client or CurlHTTP3Client()

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        destination = context.request.target
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url_for_request(
                destination,
                context.request,
            ),
            status=AttemptStatus.RUNNING,
        )
        attempt_index = len(context.attempts)
        context.attempts.append(attempt)
        started = time.monotonic()
        usage = _HTTPUsage()
        try:
            response, body, wire_bytes = await self._request(
                destination,
                context,
                node,
                credential_mode=(
                    "anonymous"
                    if _anonymous_form_bootstrap(context)
                    else "request"
                ),
                usage=usage,
            )
            usage.observe(
                wire_bytes=wire_bytes,
                decompressed_bytes=(
                    len(body)
                    + int(response.extensions.get("fetech_auxiliary_bytes", 0))
                ),
                redirects=int(
                    response.extensions.get("fetech_redirect_count", 0)
                ),
            )
            media_type = (
                response.headers.get("content-type", "application/octet-stream").split(";", 1)[0].strip()
            )
            resource = Resource(
                canonical_url=sanitize_url_for_request(
                    str(response.url),
                    context.request,
                ),
                requested_url=sanitize_url_for_request(
                    context.request.target,
                    context.request,
                ),
                authority_url=sanitize_url_for_request(
                    context.request.target,
                    context.request,
                ),
                media_type=media_type,
                status_code=response.status_code,
            )
            quality = (
                assess_text(
                    body.decode(response.encoding or "utf-8", errors="replace"),
                    media_type=media_type,
                    expected_language=context.request.language,
                )
                if media_type.startswith("text/") or media_type in {"application/json", "application/xml"}
                else assess_binary(len(body), media_type=media_type)
            )
            uri, digest, size = await context.cas.put(body)
            artifact = build_artifact(
                role="source",
                representation="raw",
                media_type=media_type,
                cas_uri=uri,
                digest=digest,
                size=size,
                resource=resource,
                extractor="httpx/0.28",
                quality=quality,
            )
            context.resources.append(resource)
            context.artifacts.append(artifact)
            self._record_response_outcomes(context, response, body, media_type, digest, size)
            context.record_quality_outcomes(quality, stage="quality")
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.SUCCEEDED,
                    "finished_at": datetime.now(UTC),
                    "sanitized_destination": sanitize_url(str(response.url)),
                    "http_status": response.status_code,
                    "bytes_received": wire_bytes,
                    "artifact_ids": (artifact.artifact_id,),
                    "consumed_budget": {
                        "bytes": usage.wire_bytes,
                        "decompressed_bytes": usage.decompressed_bytes,
                        "redirects": usage.redirects,
                        "deadline_seconds": time.monotonic() - started,
                    },
                }
            )
        except PolicyBlockedError:
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "policy",
                    "bytes_received": usage.wire_bytes,
                    "consumed_budget": _http_consumed_budget(
                        usage,
                        elapsed_seconds=time.monotonic() - started,
                    ),
                }
            )
            raise
        except asyncio.CancelledError:
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.CANCELLED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "cancelled",
                    "bytes_received": usage.wire_bytes,
                    "consumed_budget": _http_consumed_budget(
                        usage,
                        elapsed_seconds=time.monotonic() - started,
                    ),
                }
            )
            raise
        except NetworkDeadlineExceededError:
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "budget_exhausted",
                    "bytes_received": usage.wire_bytes,
                    "warnings": ("HTTP deadline budget exhausted",),
                    "consumed_budget": _http_consumed_budget(
                        usage,
                        elapsed_seconds=time.monotonic() - started,
                    ),
                }
            )
            raise
        except AdapterExecutionError as exc:
            if isinstance(exc, AdapterAuthExpiredError):
                failure_code = "auth_expired"
            elif isinstance(exc, AdapterAuthRequiredError):
                failure_code = "auth_required"
            elif isinstance(exc, AdapterNotFoundError):
                failure_code = "not_found"
            elif isinstance(exc, AdapterBudgetExceededError):
                failure_code = "budget_exhausted"
            else:
                failure_code = type(exc).__name__
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": failure_code,
                    "warnings": (str(exc),),
                    "bytes_received": usage.wire_bytes,
                    "consumed_budget": _http_consumed_budget(
                        usage,
                        elapsed_seconds=time.monotonic() - started,
                    ),
                }
            )
            raise
        except httpx.TimeoutException as exc:
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "budget_exhausted",
                    "warnings": ("HTTP deadline budget exhausted",),
                    "bytes_received": usage.wire_bytes,
                    "consumed_budget": _http_consumed_budget(
                        usage,
                        elapsed_seconds=time.monotonic() - started,
                    ),
                }
            )
            raise NetworkDeadlineExceededError(
                "HTTP deadline budget exhausted"
            ) from exc
        except (httpx.HTTPError, UnicodeError) as exc:
            message = f"HTTP transport failed: {type(exc).__name__}"
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": type(exc).__name__,
                    "warnings": (message,),
                    "bytes_received": usage.wire_bytes,
                    "consumed_budget": _http_consumed_budget(
                        usage,
                        elapsed_seconds=time.monotonic() - started,
                    ),
                }
            )
            raise AdapterExecutionError(message) from exc

    async def _request(
        self,
        destination: str,
        context: ExecutionContext,
        node: PlanNode | None = None,
        *,
        method_override: str | None = None,
        body: bytes | None = None,
        extra_headers: dict[str, str] | None = None,
        allow_ephemeral_login_cookies: bool = False,
        credential_mode: Literal["request", "anonymous"] = "request",
        usage: _HTTPUsage | None = None,
    ) -> tuple[httpx.Response, bytes, int]:
        usage_tracker = usage or _HTTPUsage()
        request_started = time.monotonic()
        if credential_mode not in {"request", "anonymous"}:
            raise AdapterExecutionError("HTTP credential mode is unsupported")
        if allow_ephemeral_login_cookies and credential_mode != "anonymous":
            raise AdapterExecutionError(
                "ephemeral login cookie handoff requires anonymous credential mode"
            )
        if "http_3" in context.request.output_requirements:
            if allow_ephemeral_login_cookies:
                raise AdapterDependencyError(
                    "ephemeral login cookie handoff is unavailable over HTTP/3"
                )
            return await self._request_http3(
                destination,
                context,
                request_started=request_started,
                usage=usage_tracker,
            )
        maximum_wire_bytes = int(context.remaining_budget("bytes"))
        maximum_decompressed_bytes = int(
            context.remaining_budget("decompressed_bytes")
        )
        if maximum_wire_bytes <= 0 or maximum_decompressed_bytes <= 0:
            raise AdapterBudgetExceededError(
                "HTTP acquisition has no remaining byte budget"
            )
        timeout = httpx.Timeout(
            _remaining_http_deadline(
                request_started,
                context.request.budget.deadline_seconds,
            )
        )
        method, headers = self._request_spec(node, context)
        if method_override is not None:
            method = method_override.strip().upper()
            if method not in {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"}:
                raise AdapterExecutionError("HTTP method override is unsupported")
        if extra_headers:
            forbidden = {
                name.casefold()
                for name in extra_headers
                if name.casefold()
                not in {"accept", "content-type", "if-match", "if-none-match"}
            }
            if forbidden:
                raise AdapterExecutionError("ephemeral request contains a forbidden header")
            headers.update(extra_headers)
        if body is not None:
            if method in {"GET", "HEAD"}:
                raise AdapterExecutionError("request bodies are forbidden for safe retrieval methods")
            if len(body) > min(1_000_000, maximum_wire_bytes):
                raise AdapterExecutionError("request body exceeded the bounded upload limit")
        request_body = body
        current = destination
        previous: str | None = None
        visited: set[str] = set()
        redirect_statuses: list[int] = []
        robots_checked: set[str] = set()
        auxiliary_bytes = 0
        credential: CredentialMaterial | None = None
        credential_outcome_recorded = False
        refresh_attempted = False
        ephemeral_cookies: dict[tuple[str, str], _EphemeralCookie] = {}
        ephemeral_cookie_origin: str | None = None
        ephemeral_cookie_used = False
        transport = self._transport_for_request()
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers=headers,
            transport=transport,
        ) as client:
            for _ in range(context.request.budget.redirects + 1):
                raw_host = _scheduler_host(current)
                async with AsyncExitStack() as policy_stack:
                    await policy_stack.enter_async_context(
                        self.scheduler.slot(
                            raw_host,
                            deadline_seconds=_remaining_http_deadline(
                                request_started,
                                context.request.budget.deadline_seconds,
                            ),
                        )
                    )
                    current, decisions = await self.policy.evaluate(
                        current,
                        previous_url=previous,
                    )
                    context.policy_decisions.extend(decisions)
                    for decision in decisions:
                        context.record_outcome(
                            decision.policy_id,
                            (
                                CapabilityOutcomeStatus.APPLIED
                                if decision.allowed
                                else CapabilityOutcomeStatus.BLOCKED
                            ),
                            "security",
                            reason=decision.reason,
                        )
                    if (
                        credential_mode == "request"
                        and context.request.authentication_ref is not None
                        and credential is None
                    ):
                        cached_credential = context.sensitive_state.get(
                            "credential_material"
                        )
                        credential = (
                            cached_credential
                            if isinstance(cached_credential, CredentialMaterial)
                            else await self._resolve_credential(
                                context.request.authentication_ref
                            )
                        )
                        if not credential.applies_to(current):
                            reason = (
                                "credential scope does not match the initial target origin"
                            )
                            decision = PolicyDecision(
                                policy_id="credential_origin_scope",
                                allowed=False,
                                reason=reason,
                                destination=sanitize_url(current),
                            )
                            context.record_outcome(
                                "connector_auth",
                                CapabilityOutcomeStatus.BLOCKED,
                                "auth",
                                reason=reason,
                            )
                            raise PolicyBlockedError(reason, (decision,))
                        if credential.expired:
                            if credential.capability_id != "bearer_token":
                                raise AdapterAuthExpiredError(
                                    "credential material is expired"
                                )
                            credential = await self._refresh_credential(
                                context,
                                credential,
                                method=method,
                                already_attempted=refresh_attempted,
                            )
                            refresh_attempted = True
                            context.sensitive_state["credential_material"] = (
                                credential
                            )
                    if current in visited:
                        raise AdapterExecutionError("redirect loop detected")
                    visited.add(current)
                    host = urlsplit(current).hostname or ""
                    if isinstance(transport, PinnedAsyncHTTPTransport):
                        transport.pin(
                            host,
                            self.policy.validated_addresses(host),
                        )
                    parts = urlsplit(current)
                    origin = f"{parts.scheme}://{parts.netloc}"
                    if (
                        ephemeral_cookie_origin is not None
                        and canonical_origin(current) != ephemeral_cookie_origin
                    ):
                        ephemeral_cookies.clear()
                        ephemeral_cookie_origin = None
                    robots_fetched = (
                        context.request.intent == "crawl"
                        and origin not in robots_checked
                    )
                    if robots_fetched:
                        robots_checked.add(origin)
                        client.cookies.clear()
                        auxiliary_bytes += await self._enforce_robots(
                            client,
                            current,
                            context,
                            maximum_bytes=min(
                                512_000,
                                maximum_decompressed_bytes - auxiliary_bytes,
                            ),
                            consumed_before=auxiliary_bytes,
                            usage=usage_tracker,
                        )
                        # The policy/DNS reservation governed the robots request.
                        # The publisher request is a distinct start and receives
                        # its own host interval without resolving twice.
                        await policy_stack.aclose()
                    context.policy_decisions.append(
                        PolicyDecision(
                            policy_id="rate_limit_policy",
                            allowed=True,
                            reason=(
                                "per-host request interval and concurrency "
                                "policy applied"
                            ),
                            destination=sanitize_url(current),
                        )
                    )
                    context.record_outcome(
                        "rate_limit_policy",
                        CapabilityOutcomeStatus.APPLIED,
                        "security",
                        minimum_interval_seconds=self._per_host_min_interval_seconds,
                        concurrency=self._per_host_concurrency,
                    )
                    hop_headers = dict(headers)
                    credential_applied = (
                        credential is not None and credential.applies_to(current)
                    )
                    if credential_applied and credential is not None:
                        hop_headers.update(credential.request_headers())
                        context.policy_decisions.append(
                            PolicyDecision(
                                policy_id="credential_origin_scope",
                                allowed=True,
                                reason=(
                                    "credential material matched the exact "
                                    "request origin"
                                ),
                                destination=sanitize_url(current),
                            )
                        )
                        if not credential_outcome_recorded:
                            context.record_outcome(
                                credential.capability_id,
                                CapabilityOutcomeStatus.APPLIED,
                                "auth",
                                exact_origin=True,
                            )
                            context.record_outcome(
                                "connector_auth",
                                CapabilityOutcomeStatus.APPLIED,
                                "auth",
                                exact_origin=True,
                            )
                            credential_outcome_recorded = True
                    elif credential is not None:
                        context.policy_decisions.append(
                            PolicyDecision(
                                policy_id="credential_origin_scope",
                                allowed=True,
                                reason=(
                                    "credential material was withheld from a "
                                    "different redirect origin"
                                ),
                                destination=sanitize_url(current),
                            )
                        )
                        context.record_outcome(
                            "connector_auth",
                            CapabilityOutcomeStatus.NOT_APPLICABLE,
                            "auth",
                            reason=(
                                "redirect origin did not match credential scope"
                            ),
                        )
                    if (
                        allow_ephemeral_login_cookies
                        and ephemeral_cookie_origin == canonical_origin(current)
                    ):
                        cookie_header = _render_ephemeral_cookie_header(
                            ephemeral_cookies,
                            current,
                        )
                        if cookie_header is not None:
                            hop_headers["Cookie"] = cookie_header
                            ephemeral_cookie_used = True
                    client.cookies.clear()
                    async with AsyncExitStack() as request_stack:
                        if robots_fetched:
                            await request_stack.enter_async_context(
                                self.scheduler.slot(
                                    host,
                                    deadline_seconds=_remaining_http_deadline(
                                        request_started,
                                        context.request.budget.deadline_seconds,
                                    ),
                                )
                            )
                        response = await request_stack.enter_async_context(
                            client.stream(
                                method,
                                current,
                                headers=hop_headers,
                                content=request_body,
                            )
                        )
                        if response.is_redirect:
                            redirect_statuses.append(response.status_code)
                            usage_tracker.observe(
                                redirects=len(redirect_statuses),
                            )
                            location = response.headers.get("location")
                            if not location:
                                raise AdapterExecutionError(
                                    "redirect response omitted Location"
                                )
                            redirected = urljoin(current, location)
                            if (
                                allow_ephemeral_login_cookies
                                and response.status_code in {307, 308}
                            ):
                                raise _redirect_body_replay_error(redirected)
                            if response.status_code == 303 or (
                                response.status_code in {301, 302}
                                and method == "POST"
                            ):
                                method = "GET"
                                request_body = None
                                headers.pop("Content-Type", None)
                            elif request_body is not None:
                                raise _redirect_body_replay_error(redirected)
                            if allow_ephemeral_login_cookies:
                                if _same_exact_origin(current, redirected):
                                    ephemeral_cookies = (
                                        _capture_ephemeral_login_cookies(
                                            response,
                                            current,
                                            ephemeral_cookies,
                                        )
                                    )
                                    ephemeral_cookie_origin = (
                                        canonical_origin(current)
                                        if ephemeral_cookies
                                        else None
                                    )
                                else:
                                    ephemeral_cookies.clear()
                                    ephemeral_cookie_origin = None
                            previous, current = current, redirected
                            continue
                        if response.status_code in {404, 410}:
                            raise AdapterNotFoundError(
                                f"target returned HTTP {response.status_code}"
                            )
                        if (
                            response.status_code == 401
                            and credential_applied
                            and credential is not None
                            and credential.capability_id == "bearer_token"
                            and _reports_expired_credential(response)
                        ):
                            if (
                                context.request.authentication_ref is not None
                                and not refresh_attempted
                                and method in {"GET", "HEAD"}
                            ):
                                credential = await self._refresh_credential(
                                    context,
                                    credential,
                                    method=method,
                                    already_attempted=False,
                                )
                                context.sensitive_state["credential_material"] = (
                                    credential
                                )
                                credential_outcome_recorded = False
                                refresh_attempted = True
                                visited.remove(current)
                                continue
                            raise AdapterAuthExpiredError(
                                "credential material was rejected as expired"
                            )
                        if response.status_code in {401, 403}:
                            raise AdapterAuthRequiredError(
                                f"target returned HTTP {response.status_code}"
                            )
                        response.raise_for_status()
                        content_length = _content_length(response)
                        if (
                            content_length is not None
                            and content_length + auxiliary_bytes
                            > maximum_wire_bytes
                        ):
                            raise AdapterBudgetExceededError(
                                "response Content-Length exceeded the "
                                "remaining wire byte budget"
                            )
                        chunks: list[bytes] = []
                        decompressed_size = 0
                        async for chunk in response.aiter_bytes():
                            decompressed_size += len(chunk)
                            wire_size = max(
                                response.num_bytes_downloaded,
                                content_length or 0,
                            )
                            usage_tracker.observe(
                                wire_bytes=wire_size + auxiliary_bytes,
                                decompressed_bytes=decompressed_size
                                + auxiliary_bytes,
                                redirects=len(redirect_statuses),
                            )
                            if wire_size + auxiliary_bytes > maximum_wire_bytes:
                                raise AdapterBudgetExceededError(
                                    "response exceeded the remaining wire byte "
                                    "budget"
                                )
                            if (
                                decompressed_size + auxiliary_bytes
                                > maximum_decompressed_bytes
                            ):
                                raise AdapterBudgetExceededError(
                                    "response exceeded the remaining "
                                    "decompressed byte budget"
                                )
                            chunks.append(chunk)
                        wire_size = max(
                            response.num_bytes_downloaded,
                            content_length or 0,
                        )
                        usage_tracker.observe(
                            wire_bytes=wire_size + auxiliary_bytes,
                            decompressed_bytes=decompressed_size
                            + auxiliary_bytes,
                            redirects=len(redirect_statuses),
                        )
                        response.extensions["fetech_redirect_count"] = len(
                            redirect_statuses
                        )
                        response.extensions["fetech_redirect_statuses"] = tuple(
                            redirect_statuses
                        )
                        response.extensions["fetech_auxiliary_bytes"] = (
                            auxiliary_bytes
                        )
                        response.extensions[
                            "fetech_ephemeral_login_cookie_handoff"
                        ] = ephemeral_cookie_used
                        if allow_ephemeral_login_cookies:
                            _scrub_cookie_state(response)
                            client.cookies.clear()
                        return (
                            response,
                            b"".join(chunks),
                            wire_size + auxiliary_bytes,
                        )
            raise AdapterExecutionError("redirect budget exhausted")

    async def _request_http3(
        self,
        destination: str,
        context: ExecutionContext,
        *,
        request_started: float,
        usage: _HTTPUsage,
    ) -> tuple[httpx.Response, bytes, int]:
        if context.request.intent == "crawl":
            raise AdapterExecutionError("HTTP/3 crawling is not available before v0.2")
        current = destination
        previous: str | None = None
        visited: set[str] = set()
        redirect_statuses: list[int] = []
        transferred = 0
        maximum_wire_bytes = int(context.remaining_budget("bytes"))
        maximum_decompressed_bytes = int(
            context.remaining_budget("decompressed_bytes")
        )
        if maximum_wire_bytes <= 0 or maximum_decompressed_bytes <= 0:
            raise AdapterBudgetExceededError(
                "HTTP/3 acquisition has no remaining byte budget"
            )
        for _ in range(context.request.budget.redirects + 1):
            raw_host = _scheduler_host(current)
            async with self.scheduler.slot(
                raw_host,
                deadline_seconds=_remaining_http_deadline(
                    request_started,
                    context.request.budget.deadline_seconds,
                ),
            ):
                current, decisions = await self.policy.evaluate(
                    current,
                    previous_url=previous,
                )
                context.policy_decisions.extend(decisions)
                for decision in decisions:
                    context.record_outcome(
                        decision.policy_id,
                        CapabilityOutcomeStatus.APPLIED,
                        "security",
                        reason=decision.reason,
                    )
                if context.request.authentication_ref is not None:
                    context.record_outcome(
                        "connector_auth",
                        CapabilityOutcomeStatus.DEPENDENCY_MISSING,
                        "auth",
                        reason=(
                            "authenticated HTTP/3 transport is not implemented"
                        ),
                    )
                    raise AdapterDependencyError(
                        "authenticated HTTP/3 transport is unavailable"
                    )
                parts = urlsplit(current)
                if parts.scheme != "https":
                    raise AdapterExecutionError("HTTP/3 transport requires HTTPS")
                if current in visited:
                    raise AdapterExecutionError("redirect loop detected")
                visited.add(current)
                host = parts.hostname or ""
                addresses = self.policy.validated_addresses(host)
                if not addresses:
                    raise AdapterExecutionError(
                        "HTTP/3 transport has no validated destination address"
                    )
                context.policy_decisions.append(
                    PolicyDecision(
                        policy_id="rate_limit_policy",
                        allowed=True,
                        reason=(
                            "per-host request interval and concurrency policy "
                            "applied"
                        ),
                        destination=sanitize_url(current),
                    )
                )
                context.record_outcome(
                    "rate_limit_policy",
                    CapabilityOutcomeStatus.APPLIED,
                    "security",
                    minimum_interval_seconds=self._per_host_min_interval_seconds,
                    concurrency=self._per_host_concurrency,
                )
                remaining = min(
                    maximum_wire_bytes - transferred,
                    maximum_decompressed_bytes - transferred,
                )
                if remaining <= 0:
                    raise AdapterBudgetExceededError(
                        "HTTP/3 response exhausted the shared byte budget"
                    )
                result = await self.http3_client.fetch(
                    current,
                    address=addresses[0],
                    user_agent=self.user_agent,
                    timeout_seconds=_remaining_http_deadline(
                        request_started,
                        context.request.budget.deadline_seconds,
                    ),
                    maximum_bytes=remaining,
                )
            transferred += len(result.body)
            usage.observe(
                wire_bytes=transferred,
                decompressed_bytes=transferred,
            )
            if (
                transferred > maximum_wire_bytes
                or transferred > maximum_decompressed_bytes
            ):
                raise AdapterBudgetExceededError(
                    "HTTP/3 response exceeded the remaining shared byte budget"
                )
            if result.status_code in {301, 302, 303, 307, 308}:
                redirect_statuses.append(result.status_code)
                usage.observe(redirects=len(redirect_statuses))
                if not result.redirect_url:
                    raise AdapterExecutionError("HTTP/3 redirect omitted its destination")
                previous, current = current, urljoin(current, result.redirect_url)
                continue
            if result.status_code in {404, 410}:
                raise AdapterNotFoundError(f"target returned HTTP {result.status_code}")
            if result.status_code in {401, 403}:
                raise AdapterAuthRequiredError(f"target returned HTTP {result.status_code}")
            if result.status_code >= 400:
                raise AdapterExecutionError(f"target returned HTTP {result.status_code}")
            request = httpx.Request("GET", current)
            response = httpx.Response(
                result.status_code,
                headers={"content-type": result.media_type or "application/octet-stream"},
                content=result.body,
                request=request,
                extensions={
                    "http_version": b"HTTP/3",
                    "fetech_redirect_count": len(redirect_statuses),
                    "fetech_redirect_statuses": tuple(redirect_statuses),
                },
            )
            return response, result.body, transferred
        raise AdapterExecutionError("redirect budget exhausted")

    def _transport_for_request(self) -> httpx.AsyncBaseTransport:
        if self.transport is not None:
            return self.transport
        return PinnedAsyncHTTPTransport(
            maximum_connections=self._global_concurrency,
            maximum_keepalive_connections=self._global_concurrency,
        )

    async def _resolve_credential(self, reference: str) -> CredentialMaterial:
        try:
            material = await self.credential_provider.resolve(reference)
        except CredentialNotFoundError as exc:
            raise AdapterAuthRequiredError("authentication reference could not be resolved") from exc
        except CredentialProviderUnavailableError as exc:
            raise AdapterDependencyError("credential provider is unavailable") from exc
        except CredentialProviderError as exc:
            raise AdapterDependencyError("credential provider failed") from exc
        except Exception as exc:
            raise AdapterDependencyError("credential provider failed") from exc
        if not isinstance(material, CredentialMaterial):
            raise AdapterDependencyError("credential provider returned invalid material")
        return material

    async def _enforce_robots(
        self,
        client: httpx.AsyncClient,
        target: str,
        context: ExecutionContext,
        *,
        maximum_bytes: int,
        consumed_before: int,
        usage: _HTTPUsage,
    ) -> int:
        if maximum_bytes <= 0:
            raise AdapterBudgetExceededError(
                "robots policy exhausted the remaining decompressed byte budget"
            )
        parts = urlsplit(target)
        robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
        client.cookies.clear()
        try:
            async with client.stream("GET", robots_url) as response:
                if response.status_code != 200:
                    context.policy_decisions.append(
                        PolicyDecision(
                            policy_id="robots_policy_check",
                            allowed=True,
                            reason=(
                                f"robots.txt returned HTTP {response.status_code}; "
                                "policy allowed retrieval"
                            ),
                            destination=sanitize_url(target),
                        )
                    )
                    context.record_outcome(
                        "robots_policy_check",
                        CapabilityOutcomeStatus.APPLIED,
                        "security",
                        status_code=response.status_code,
                        allowed=True,
                    )
                    return 0
                chunks: list[bytes] = []
                size = 0
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    usage.observe(
                        wire_bytes=consumed_before
                        + max(response.num_bytes_downloaded, size),
                        decompressed_bytes=consumed_before + size,
                    )
                    if size > maximum_bytes:
                        raise AdapterExecutionError("robots.txt exceeded its bounded byte budget")
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            context.record_outcome(
                "robots_policy_check",
                CapabilityOutcomeStatus.FAILED,
                "security",
                reason=type(exc).__name__,
            )
            raise AdapterExecutionError("robots policy retrieval failed") from exc
        parser = robotparser.RobotFileParser(robots_url)
        parser.parse(b"".join(chunks).decode("utf-8", errors="replace").splitlines())
        allowed = parser.can_fetch(self.user_agent, target)
        decision = PolicyDecision(
            policy_id="robots_policy_check",
            allowed=allowed,
            reason="robots.txt permits retrieval" if allowed else "robots.txt disallows retrieval",
            destination=sanitize_url(target),
        )
        context.record_outcome(
            "robots_policy_check",
            CapabilityOutcomeStatus.APPLIED if allowed else CapabilityOutcomeStatus.BLOCKED,
            "security",
            allowed=allowed,
        )
        if not allowed:
            raise PolicyBlockedError(decision.reason, (decision,))
        context.policy_decisions.append(decision)
        return size

    def _request_spec(
        self, node: PlanNode | None, context: ExecutionContext
    ) -> tuple[str, dict[str, str]]:
        capability_id = node.capability_id if node else "http_get"
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        if capability_id == "http_head":
            return "HEAD", headers
        if capability_id == "http_post":
            approved = (
                "http_post" in context.request.approved_capabilities
                or context.request.metadata.get("http_post_approved", "").lower() == "true"
            )
            if not approved:
                reason = "http_post requires explicit approval"
                raise PolicyBlockedError(
                    reason,
                    (
                        PolicyDecision(
                            policy_id="http_post_approval",
                            allowed=False,
                            reason=reason,
                            destination=sanitize_url(context.request.target),
                        ),
                    ),
                )
            return "POST", headers
        if capability_id == "browser_header_http":
            headers.update(
                {
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                    "Accept-Language": context.request.language or "en-US,en;q=0.8",
                    "Sec-Fetch-Mode": "navigate",
                }
            )
            return "GET", headers
        if capability_id == "range_request":
            requested_range = context.request.metadata.get("range", "bytes=0-1023")
            if re.fullmatch(r"bytes=(?:\d+-\d*|-\d+)", requested_range) is None:
                raise AdapterExecutionError("range must be a single bounded HTTP bytes range")
            headers["Range"] = requested_range
            return "GET", headers
        return "GET", headers

    async def _refresh_credential(
        self,
        context: ExecutionContext,
        existing_material: CredentialMaterial,
        *,
        method: str,
        already_attempted: bool,
    ) -> CredentialMaterial:
        if already_attempted or method not in {"GET", "HEAD"}:
            raise AdapterAuthExpiredError("credential material is expired")
        session = context.sensitive_state.get("origin_scoped_session")
        reference = context.request.authentication_ref
        if (
            not isinstance(session, OriginScopedSession)
            or reference is None
            or session.authentication_ref != reference
            or session.capability_id
            not in {SessionCapability.OAUTH, SessionCapability.SSO}
            or session.refresh_ref is None
            or existing_material.capability_id != "bearer_token"
        ):
            raise AdapterAuthExpiredError("credential material is expired")
        try:
            session.validate_material_binding(existing_material)
        except SessionBindingError as exc:
            raise AdapterAuthRequiredError(
                "credential material does not match the configured session"
            ) from exc
        capability_id = session.capability_id.value
        refresh = getattr(self.credential_provider, "refresh", None)
        if not callable(refresh):
            raise AdapterAuthExpiredError("credential material is expired")
        context.record_runtime_event(
            "auth.refresh.started",
            "auth",
            capability_id=capability_id,
        )
        try:
            material = await refresh(session.refresh_ref)
        except CredentialProviderUnavailableError as exc:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=capability_id,
                reason="provider_unavailable",
            )
            raise AdapterDependencyError("credential provider is unavailable") from exc
        except (CredentialNotFoundError, CredentialProviderError) as exc:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=capability_id,
                reason="refresh_rejected",
            )
            raise AdapterAuthExpiredError("credential refresh was rejected") from exc
        except Exception as exc:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=capability_id,
                reason="provider_failed",
            )
            raise AdapterDependencyError("credential provider failed") from exc
        if not isinstance(material, CredentialMaterial):
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=capability_id,
                reason="invalid_material",
            )
            raise AdapterDependencyError("credential provider returned invalid material")
        if material.expired:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=capability_id,
                reason="expired_material",
            )
            raise AdapterAuthExpiredError("credential refresh returned expired material")
        try:
            session.validate_material_binding(material)
        except SessionBindingError as exc:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=capability_id,
                reason="invalid_binding",
            )
            raise AdapterAuthRequiredError(
                "refreshed credential does not match the configured session"
            ) from exc
        if material.capability_id != existing_material.capability_id:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=capability_id,
                reason="credential_type_changed",
            )
            raise AdapterAuthRequiredError(
                "refreshed credential changed authentication type"
            )
        context.record_outcome(
            capability_id,
            CapabilityOutcomeStatus.APPLIED,
            "auth",
            refreshed=True,
        )
        context.record_runtime_event(
            "auth.refresh.succeeded",
            "auth",
            capability_id=capability_id,
        )
        return material

    @staticmethod
    def _record_response_outcomes(
        context: ExecutionContext,
        response: httpx.Response,
        body: bytes,
        media_type: str,
        digest: str,
        size: int,
    ) -> None:
        context.record_outcome(
            "connectivity_check",
            CapabilityOutcomeStatus.APPLIED,
            "http",
            status_code=response.status_code,
        )
        context.record_outcome(
            "tls_certificate_check",
            (
                CapabilityOutcomeStatus.APPLIED
                if response.url.scheme == "https"
                else CapabilityOutcomeStatus.NOT_APPLICABLE
            ),
            "http",
            reason=(
                "TLS validation completed by the configured transport"
                if response.url.scheme == "https"
                else "plain HTTP target has no TLS certificate"
            ),
        )
        context.record_outcome(
            "content_type_probe",
            CapabilityOutcomeStatus.OBSERVED,
            "validation",
            media_type=media_type,
        )
        context.record_outcome(
            "file_size_probe",
            CapabilityOutcomeStatus.OBSERVED,
            "validation",
            size=size,
        )
        context.record_outcome(
            "streaming_response",
            CapabilityOutcomeStatus.APPLIED,
            "http",
            bounded=True,
        )
        is_chunked = "chunked" in response.headers.get("transfer-encoding", "").lower()
        context.record_outcome(
            "chunked_response",
            (
                CapabilityOutcomeStatus.OBSERVED
                if is_chunked
                else CapabilityOutcomeStatus.NOT_APPLICABLE
            ),
            "http",
        )
        version = response.http_version.upper().replace("HTTP/", "")
        observed_protocol = {"1.1": "http_1_1", "2": "http_2", "3": "http_3"}.get(version)
        for capability_id in ("http_1_1", "http_2", "http_3"):
            context.record_outcome(
                capability_id,
                (
                    CapabilityOutcomeStatus.OBSERVED
                    if capability_id == observed_protocol
                    else CapabilityOutcomeStatus.NOT_APPLICABLE
                ),
                "http",
                negotiated=response.http_version,
            )
        redirect_statuses = tuple(response.extensions.get("fetech_redirect_statuses", ()))
        for status_code, capability_id in {
            301: "redirect_301",
            302: "redirect_302",
            303: "redirect_303",
            307: "redirect_307",
            308: "redirect_308",
        }.items():
            context.record_outcome(
                capability_id,
                (
                    CapabilityOutcomeStatus.OBSERVED
                    if status_code in redirect_statuses
                    else CapabilityOutcomeStatus.NOT_APPLICABLE
                ),
                "http",
            )
        context.record_outcome(
            "redirect_chain",
            (
                CapabilityOutcomeStatus.OBSERVED
                if redirect_statuses
                else CapabilityOutcomeStatus.NOT_APPLICABLE
            ),
            "http",
            hops=len(redirect_statuses),
        )
        context.record_outcome(
            "redirect_loop_detection",
            CapabilityOutcomeStatus.APPLIED,
            "http",
            visited_urls=int(response.extensions.get("fetech_redirect_count", 0)) + 1,
        )
        context.record_outcome(
            "source_hash_comparison",
            CapabilityOutcomeStatus.OBSERVED,
            "validation",
            sha256=digest,
        )
        if media_type in {"text/html", "application/xhtml+xml"}:
            context.record_outcome(
                "raw_html",
                CapabilityOutcomeStatus.APPLIED,
                "reader",
                artifact="source",
            )
            parser = _NavigationParser(str(response.url))
            parser.feed(body.decode(response.encoding or "utf-8", errors="replace"))
            for capability_id in (
                "meta_refresh_redirect",
                "javascript_redirect",
                "canonical_redirect",
                "opengraph_url_redirect",
            ):
                candidate = parser.candidates.get(capability_id)
                context.record_outcome(
                    capability_id,
                    (
                        CapabilityOutcomeStatus.OBSERVED
                        if candidate
                        else CapabilityOutcomeStatus.NOT_APPLICABLE
                    ),
                    "http",
                    candidate=sanitize_url(candidate) if candidate else None,
                    followed=False,
                )


def _remaining_http_deadline(started: float, maximum_seconds: float) -> float:
    remaining = maximum_seconds - (time.monotonic() - started)
    if remaining <= 0:
        raise NetworkDeadlineExceededError("HTTP deadline budget exhausted")
    return remaining


def _scheduler_host(value: str) -> str:
    try:
        host = urlsplit(value).hostname or ""
    except ValueError as exc:
        raise AdapterExecutionError("HTTP destination is invalid") from exc
    if not host:
        raise AdapterExecutionError("HTTP destination has no hostname")
    return host


def _http_consumed_budget(
    usage: _HTTPUsage,
    *,
    elapsed_seconds: float,
) -> dict[str, int | float]:
    return {
        "bytes": usage.wire_bytes,
        "decompressed_bytes": usage.decompressed_bytes,
        "redirects": usage.redirects,
        "deadline_seconds": max(0.0, elapsed_seconds),
    }


@dataclass(frozen=True, slots=True)
class _EphemeralCookie:
    name: str
    value: str
    path: str


def _capture_ephemeral_login_cookies(
    response: httpx.Response,
    source_url: str,
    existing: dict[tuple[str, str], _EphemeralCookie],
) -> dict[tuple[str, str], _EphemeralCookie]:
    """Validate a redirect's cookies into request-local, exact-origin state."""

    set_cookie_headers = response.headers.get_list("set-cookie")
    if not set_cookie_headers:
        return existing
    if (
        len(set_cookie_headers) > _EPHEMERAL_COOKIE_COUNT_LIMIT
        or sum(len(value.encode("latin-1")) for value in set_cookie_headers)
        > _EPHEMERAL_SET_COOKIE_LIMIT
    ):
        raise AdapterExecutionError("ephemeral login cookie exceeded security bounds")

    parsed = list(response.cookies.jar)
    if len(parsed) != len(set_cookie_headers):
        raise AdapterExecutionError("ephemeral login cookie was malformed")

    parts = urlsplit(source_url)
    host = (parts.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
    if parts.scheme != "https" or not host:
        raise AdapterExecutionError("ephemeral login cookies require HTTPS")

    captured = dict(existing)
    now = time.time()
    for cookie in parsed:
        name = cookie.name
        value = cookie.value
        path = cookie.path or "/"
        domain = cookie.domain.lstrip(".").lower().rstrip(".")
        if value is None:
            raise AdapterExecutionError("ephemeral login cookie was malformed")
        if (
            not cookie.secure
            or domain != host
            or len(name) > _EPHEMERAL_COOKIE_NAME_LIMIT
            or len(value) > _EPHEMERAL_COOKIE_VALUE_LIMIT
            or len(path) > _EPHEMERAL_COOKIE_PATH_LIMIT
            or _COOKIE_NAME.fullmatch(name) is None
            or _COOKIE_VALUE.fullmatch(value) is None
            or not path.startswith("/")
            or any(ord(character) < 32 or ord(character) == 127 for character in path)
        ):
            raise AdapterExecutionError("ephemeral login cookie failed security validation")
        key = (name, path)
        if cookie.expires is not None and cookie.expires <= now:
            captured.pop(key, None)
        else:
            captured[key] = _EphemeralCookie(name=name, value=value, path=path)

    if len(captured) > _EPHEMERAL_COOKIE_COUNT_LIMIT:
        raise AdapterExecutionError("ephemeral login cookie exceeded security bounds")
    rendered_all = "; ".join(
        f"{cookie.name}={cookie.value}"
        for cookie in sorted(
            captured.values(),
            key=lambda cookie: (-len(cookie.path), cookie.name),
        )
    )
    if len(rendered_all.encode("ascii")) > _EPHEMERAL_COOKIE_HEADER_LIMIT:
        raise AdapterExecutionError("ephemeral login cookie exceeded security bounds")
    return captured


def _render_ephemeral_cookie_header(
    cookies: dict[tuple[str, str], _EphemeralCookie],
    target_url: str,
) -> str | None:
    target_path = urlsplit(target_url).path or "/"
    selected = sorted(
        (
            cookie
            for cookie in cookies.values()
            if _cookie_path_matches(cookie.path, target_path)
        ),
        key=lambda cookie: (-len(cookie.path), cookie.name),
    )
    if not selected:
        return None
    rendered = "; ".join(f"{cookie.name}={cookie.value}" for cookie in selected)
    if len(rendered.encode("ascii")) > _EPHEMERAL_COOKIE_HEADER_LIMIT:
        raise AdapterExecutionError("ephemeral login cookie exceeded security bounds")
    return rendered


def _cookie_path_matches(cookie_path: str, target_path: str) -> bool:
    if target_path == cookie_path:
        return True
    if not target_path.startswith(cookie_path):
        return False
    return cookie_path.endswith("/") or target_path[len(cookie_path)] == "/"


def _same_exact_origin(left: str, right: str) -> bool:
    try:
        return canonical_origin(left) == canonical_origin(right)
    except ValueError:
        return False


def _scrub_cookie_state(response: httpx.Response) -> None:
    """Remove ephemeral cookie material from the response object returned upstream."""

    response.headers.pop("set-cookie", None)
    response.request.headers.pop("cookie", None)
    response.cookies.clear()


def _redirect_body_replay_error(redirected: str) -> PolicyBlockedError:
    reason = (
        "a request cannot replay its body to a redirected target "
        "without a new exact-target approval"
    )
    return PolicyBlockedError(
        reason,
        (
            PolicyDecision(
                policy_id="redirect_body_replay",
                allowed=False,
                reason=reason,
                destination=sanitize_url(redirected),
            ),
        ),
    )


def _anonymous_form_bootstrap(context: ExecutionContext) -> bool:
    """Use an auth reference solely as a form-provider handle until login succeeds."""

    requested = set(context.request.output_requirements)
    authenticated_outputs = {
        "api_key",
        "bearer_token",
        "connector_auth",
        "cookie_session",
        "login_session",
        "oauth",
        "private_workspace",
        "sso",
    }
    return "form_submit" in requested and not (requested & authenticated_outputs)


class _NavigationParser(HTMLParser):
    _JAVASCRIPT_LOCATION = re.compile(
        r"(?:window\.)?location(?:\.href)?\s*=\s*['\"]([^'\"]+)['\"]",
        re.I,
    )

    def __init__(self, base_url: str) -> None:
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.candidates: dict[str, str] = {}
        self._in_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = {key.lower(): value or "" for key, value in attrs}
        if tag.lower() == "script":
            self._in_script = True
        if tag.lower() == "link" and "canonical" in values.get("rel", "").lower().split():
            self._record("canonical_redirect", values.get("href"))
        if tag.lower() != "meta":
            return
        if values.get("property", "").lower() == "og:url":
            self._record("opengraph_url_redirect", values.get("content"))
        if values.get("http-equiv", "").lower() == "refresh":
            match = re.search(r"(?:^|;)\s*url\s*=\s*['\"]?([^'\";]+)", values.get("content", ""), re.I)
            self._record("meta_refresh_redirect", match.group(1).strip() if match else None)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "script":
            self._in_script = False

    def handle_data(self, data: str) -> None:
        if not self._in_script:
            return
        match = self._JAVASCRIPT_LOCATION.search(data)
        self._record("javascript_redirect", match.group(1) if match else None)

    def _record(self, capability_id: str, candidate: str | None) -> None:
        if candidate and capability_id not in self.candidates:
            self.candidates[capability_id] = urljoin(self.base_url, candidate.strip())


def _content_length(response: httpx.Response) -> int | None:
    value = response.headers.get("content-length")
    if value is None:
        return None
    try:
        length = int(value)
    except ValueError as exc:
        raise AdapterExecutionError("response contained an invalid Content-Length") from exc
    if length < 0:
        raise AdapterExecutionError("response contained an invalid Content-Length")
    return length


def _reports_expired_credential(response: httpx.Response) -> bool:
    challenge = response.headers.get("www-authenticate", "").strip()
    if re.match(r"(?i)^bearer(?:\s|$)", challenge) is None:
        return False
    return (
        re.search(r'(?i)\berror\s*=\s*"?invalid_token"?', challenge) is not None
        or re.search(r'(?i)\berror\s*=\s*"?expired_token"?', challenge) is not None
        or (
            re.search(r"(?i)\berror_description\s*=", challenge) is not None
            and re.search(r"(?i)\b(?:expired|expiration)\b", challenge) is not None
        )
    )
