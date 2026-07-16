"""Bounded HTTP acquisition with redirect-by-redirect policy checks."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from urllib.parse import urljoin, urlsplit

import httpx

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.models import AttemptStatus, FetchAttempt, PlanNode, Resource
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
    ) -> None:
        self.user_agent = user_agent
        self.policy = policy or SafeURLPolicy()
        self.transport = transport
        self._global_concurrency = global_concurrency
        self._global_limit = asyncio.Semaphore(global_concurrency)
        self._per_host_concurrency = per_host_concurrency
        self._host_limits: dict[str, asyncio.Semaphore] = {}

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
            response, body, wire_bytes = await self._request(destination, context)
            media_type = (
                response.headers.get("content-type", "application/octet-stream").split(";", 1)[0].strip()
            )
            resource = Resource(
                canonical_url=str(response.url),
                requested_url=context.request.target,
                authority_url=context.request.target,
                media_type=media_type,
                status_code=response.status_code,
            )
            quality = (
                assess_text(
                    body.decode(response.encoding or "utf-8", errors="replace"), media_type=media_type
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
                        "decompressed_bytes": size,
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
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": type(exc).__name__,
                    "warnings": (str(exc),),
                }
            )
            raise AdapterExecutionError(str(exc)) from exc

    async def _request(
        self,
        destination: str,
        context: ExecutionContext,
    ) -> tuple[httpx.Response, bytes, int]:
        maximum_wire_bytes = context.request.budget.bytes
        maximum_decompressed_bytes = context.request.budget.decompressed_bytes
        timeout = httpx.Timeout(context.request.budget.deadline_seconds)
        headers = {"User-Agent": self.user_agent, "Accept": "*/*"}
        current = destination
        previous: str | None = None
        visited: set[str] = set()
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
                if current in visited:
                    raise AdapterExecutionError("redirect loop detected")
                visited.add(current)
                host = urlsplit(current).hostname or ""
                if isinstance(transport, PinnedAsyncHTTPTransport):
                    transport.pin(host, self.policy.validated_addresses(host))
                host_limit = self._host_limits.setdefault(host, asyncio.Semaphore(self._per_host_concurrency))
                async with self._global_limit, host_limit, client.stream("GET", current) as response:
                    if response.is_redirect:
                        location = response.headers.get("location")
                        if not location:
                            raise AdapterExecutionError("redirect response omitted Location")
                        previous, current = current, urljoin(current, location)
                        continue
                    response.raise_for_status()
                    content_length = _content_length(response)
                    if content_length is not None and content_length > maximum_wire_bytes:
                        raise AdapterExecutionError("response Content-Length exceeded the wire byte budget")
                    chunks: list[bytes] = []
                    decompressed_size = 0
                    async for chunk in response.aiter_bytes():
                        decompressed_size += len(chunk)
                        wire_size = max(response.num_bytes_downloaded, content_length or 0)
                        if wire_size > maximum_wire_bytes:
                            raise AdapterExecutionError("response exceeded the wire byte budget")
                        if decompressed_size > maximum_decompressed_bytes:
                            raise AdapterExecutionError("response exceeded the decompressed byte budget")
                        chunks.append(chunk)
                    wire_size = max(response.num_bytes_downloaded, content_length or 0)
                    return response, b"".join(chunks), wire_size
            raise AdapterExecutionError("redirect budget exhausted")

    def _transport_for_request(self) -> httpx.AsyncBaseTransport:
        if self.transport is not None:
            return self.transport
        return PinnedAsyncHTTPTransport(
            maximum_connections=self._global_concurrency,
            maximum_keepalive_connections=self._global_concurrency,
        )


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
