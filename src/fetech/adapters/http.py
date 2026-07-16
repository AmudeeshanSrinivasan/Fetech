"""Bounded HTTP acquisition with redirect-by-redirect policy checks."""

from __future__ import annotations

import asyncio
import re
from datetime import UTC, datetime
from html.parser import HTMLParser
from urllib import robotparser
from urllib.parse import urljoin, urlsplit

import httpx

from fetech.adapters.base import (
    AdapterAuthRequiredError,
    AdapterExecutionError,
    AdapterNotFoundError,
    ExecutionContext,
)
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
from fetech.security import PolicyBlockedError, SafeURLPolicy, sanitize_url
from fetech.storage import build_artifact
from fetech.transport import PinnedAsyncHTTPTransport


class HTTPAdapter:
    def __init__(
        self,
        *,
        user_agent: str,
        policy: SafeURLPolicy | None = None,
        transport: httpx.AsyncBaseTransport | None = None,
        global_concurrency: int = 8,
        per_host_concurrency: int = 2,
        per_host_min_interval_seconds: float = 0.0,
        http3_client: CurlHTTP3Client | None = None,
    ) -> None:
        self.user_agent = user_agent
        self.policy = policy or SafeURLPolicy()
        self.transport = transport
        self._global_concurrency = global_concurrency
        self._global_limit = asyncio.Semaphore(global_concurrency)
        self._per_host_concurrency = per_host_concurrency
        self._host_limits: dict[str, asyncio.Semaphore] = {}
        self._per_host_min_interval_seconds = max(0.0, per_host_min_interval_seconds)
        self._rate_locks: dict[str, asyncio.Lock] = {}
        self._last_request_at: dict[str, float] = {}
        self.http3_client = http3_client or CurlHTTP3Client()

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        destination = context.request.target
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(destination),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        started = datetime.now(UTC)
        try:
            response, body, wire_bytes = await self._request(destination, context, node)
            media_type = (
                response.headers.get("content-type", "application/octet-stream").split(";", 1)[0].strip()
            )
            resource = Resource(
                canonical_url=sanitize_url(str(response.url)),
                requested_url=sanitize_url(context.request.target),
                authority_url=sanitize_url(context.request.target),
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
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.SUCCEEDED,
                    "finished_at": datetime.now(UTC),
                    "sanitized_destination": sanitize_url(str(response.url)),
                    "http_status": response.status_code,
                    "bytes_received": wire_bytes,
                    "artifact_ids": (artifact.artifact_id,),
                    "consumed_budget": {
                        "bytes": wire_bytes,
                        "decompressed_bytes": size
                        + int(response.extensions.get("fetech_auxiliary_bytes", 0)),
                        "redirects": int(response.extensions.get("fetech_redirect_count", 0)),
                        "deadline_seconds": (datetime.now(UTC) - started).total_seconds(),
                    },
                }
            )
        except PolicyBlockedError:
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "policy",
                }
            )
            raise
        except AdapterExecutionError as exc:
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": type(exc).__name__,
                    "warnings": (str(exc),),
                }
            )
            raise
        except (httpx.HTTPError, UnicodeError) as exc:
            message = f"HTTP transport failed: {type(exc).__name__}"
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": type(exc).__name__,
                    "warnings": (message,),
                }
            )
            raise AdapterExecutionError(message) from exc

    async def _request(
        self,
        destination: str,
        context: ExecutionContext,
        node: PlanNode | None = None,
    ) -> tuple[httpx.Response, bytes, int]:
        if "http_3" in context.request.output_requirements:
            return await self._request_http3(destination, context)
        maximum_wire_bytes = context.request.budget.bytes
        maximum_decompressed_bytes = context.request.budget.decompressed_bytes
        timeout = httpx.Timeout(context.request.budget.deadline_seconds)
        method, headers = self._request_spec(node, context)
        current = destination
        previous: str | None = None
        visited: set[str] = set()
        redirect_statuses: list[int] = []
        robots_checked: set[str] = set()
        auxiliary_bytes = 0
        transport = self._transport_for_request()
        async with httpx.AsyncClient(
            follow_redirects=False,
            timeout=timeout,
            headers=headers,
            transport=transport,
        ) as client:
            for _ in range(context.request.budget.redirects + 1):
                current, decisions = await self.policy.evaluate(current, previous_url=previous)
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
                if current in visited:
                    raise AdapterExecutionError("redirect loop detected")
                visited.add(current)
                host = urlsplit(current).hostname or ""
                if isinstance(transport, PinnedAsyncHTTPTransport):
                    transport.pin(host, self.policy.validated_addresses(host))
                host_limit = self._host_limits.setdefault(host, asyncio.Semaphore(self._per_host_concurrency))
                parts = urlsplit(current)
                origin = f"{parts.scheme}://{parts.netloc}"
                if context.request.intent == "crawl" and origin not in robots_checked:
                    robots_checked.add(origin)
                    auxiliary_bytes += await self._enforce_robots(
                        client,
                        current,
                        context,
                        host,
                        host_limit,
                        maximum_bytes=min(512_000, maximum_decompressed_bytes - auxiliary_bytes),
                    )
                await self._apply_rate_limit(host)
                context.policy_decisions.append(
                    PolicyDecision(
                        policy_id="rate_limit_policy",
                        allowed=True,
                        reason="per-host request interval and concurrency policy applied",
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
                async with self._global_limit, host_limit, client.stream(method, current) as response:
                    if response.is_redirect:
                        redirect_statuses.append(response.status_code)
                        location = response.headers.get("location")
                        if not location:
                            raise AdapterExecutionError("redirect response omitted Location")
                        previous, current = current, urljoin(current, location)
                        continue
                    if response.status_code in {404, 410}:
                        raise AdapterNotFoundError(f"target returned HTTP {response.status_code}")
                    if response.status_code in {401, 403}:
                        raise AdapterAuthRequiredError(f"target returned HTTP {response.status_code}")
                    response.raise_for_status()
                    content_length = _content_length(response)
                    if content_length is not None and content_length + auxiliary_bytes > maximum_wire_bytes:
                        raise AdapterExecutionError("response Content-Length exceeded the wire byte budget")
                    chunks: list[bytes] = []
                    decompressed_size = 0
                    async for chunk in response.aiter_bytes():
                        decompressed_size += len(chunk)
                        wire_size = max(response.num_bytes_downloaded, content_length or 0)
                        if wire_size + auxiliary_bytes > maximum_wire_bytes:
                            raise AdapterExecutionError("response exceeded the wire byte budget")
                        if decompressed_size + auxiliary_bytes > maximum_decompressed_bytes:
                            raise AdapterExecutionError("response exceeded the decompressed byte budget")
                        chunks.append(chunk)
                    wire_size = max(response.num_bytes_downloaded, content_length or 0)
                    response.extensions["fetech_redirect_count"] = len(redirect_statuses)
                    response.extensions["fetech_redirect_statuses"] = tuple(redirect_statuses)
                    response.extensions["fetech_auxiliary_bytes"] = auxiliary_bytes
                    return response, b"".join(chunks), wire_size + auxiliary_bytes
            raise AdapterExecutionError("redirect budget exhausted")

    async def _request_http3(
        self,
        destination: str,
        context: ExecutionContext,
    ) -> tuple[httpx.Response, bytes, int]:
        if context.request.intent == "crawl":
            raise AdapterExecutionError("HTTP/3 crawling is not available before v0.2")
        current = destination
        previous: str | None = None
        visited: set[str] = set()
        redirect_statuses: list[int] = []
        transferred = 0
        for _ in range(context.request.budget.redirects + 1):
            current, decisions = await self.policy.evaluate(current, previous_url=previous)
            context.policy_decisions.extend(decisions)
            for decision in decisions:
                context.record_outcome(
                    decision.policy_id,
                    CapabilityOutcomeStatus.APPLIED,
                    "security",
                    reason=decision.reason,
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
                raise AdapterExecutionError("HTTP/3 transport has no validated destination address")
            host_limit = self._host_limits.setdefault(host, asyncio.Semaphore(self._per_host_concurrency))
            await self._apply_rate_limit(host)
            context.policy_decisions.append(
                PolicyDecision(
                    policy_id="rate_limit_policy",
                    allowed=True,
                    reason="per-host request interval and concurrency policy applied",
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
            remaining = context.request.budget.bytes - transferred
            if remaining <= 0:
                raise AdapterExecutionError("HTTP/3 response exhausted the wire byte budget")
            async with self._global_limit, host_limit:
                result = await self.http3_client.fetch(
                    current,
                    address=addresses[0],
                    user_agent=self.user_agent,
                    timeout_seconds=context.request.budget.deadline_seconds,
                    maximum_bytes=remaining,
                )
            transferred += len(result.body)
            if result.status_code in {301, 302, 303, 307, 308}:
                redirect_statuses.append(result.status_code)
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

    async def _apply_rate_limit(self, host: str) -> None:
        lock = self._rate_locks.setdefault(host, asyncio.Lock())
        async with lock:
            loop = asyncio.get_running_loop()
            wait_for = (
                self._last_request_at.get(host, 0.0)
                + self._per_host_min_interval_seconds
                - loop.time()
            )
            if wait_for > 0:
                await asyncio.sleep(wait_for)
            self._last_request_at[host] = loop.time()

    async def _enforce_robots(
        self,
        client: httpx.AsyncClient,
        target: str,
        context: ExecutionContext,
        host: str,
        host_limit: asyncio.Semaphore,
        *,
        maximum_bytes: int,
    ) -> int:
        if maximum_bytes <= 0:
            raise AdapterExecutionError("robots policy exhausted the decompressed byte budget")
        parts = urlsplit(target)
        robots_url = f"{parts.scheme}://{parts.netloc}/robots.txt"
        await self._apply_rate_limit(host)
        try:
            async with self._global_limit, host_limit, client.stream("GET", robots_url) as response:
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
            if context.request.metadata.get("http_post_approved", "").lower() != "true":
                reason = "http_post requires explicit http_post_approved metadata"
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
