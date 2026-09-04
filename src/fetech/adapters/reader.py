"""Static HTML and text normalization adapters."""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from html import unescape
from urllib.parse import quote, urlsplit

import httpx

from fetech.adapters.base import (
    AdapterBudgetExceededError,
    AdapterExecutionError,
    ExecutionContext,
)
from fetech.browser_reader import BrowserReaderWorker
from fetech.models import AttemptStatus, FetchAttempt, PlanNode
from fetech.quality import assess_text
from fetech.security import SafeURLPolicy, sanitize_url
from fetech.storage import build_artifact
from fetech.transport import PinnedAsyncHTTPTransport
from fetech.version import DEFAULT_USER_AGENT

_SCRIPT_STYLE = re.compile(r"<(script|style|noscript)\b[^>]*>.*?</\1>", re.I | re.S)
_TAGS = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")
_MAIN = re.compile(r"<(main|article)\b[^>]*>(.*?)</\1>", re.I | re.S)


class ReaderAdapter:
    def __init__(
        self,
        *,
        remote_reader_template: str | None = None,
        policy: SafeURLPolicy | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        remote_transport: httpx.AsyncBaseTransport | None = None,
        browser_reader: BrowserReaderWorker | None = None,
    ) -> None:
        self.remote_reader_template = remote_reader_template
        self.policy = policy or SafeURLPolicy()
        self.user_agent = user_agent
        self.remote_transport = remote_transport
        self.browser_reader = browser_reader or BrowserReaderWorker()

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        raw = context.latest_artifact("raw")
        normalized_document = (
            context.latest_artifact("document")
            if node.capability_id == "clean_text"
            else None
        )
        source = normalized_document or raw
        if source is None or not context.resources:
            raise AdapterExecutionError("reader requires an HTTP source artifact")
        resource = next(
            (
                candidate
                for candidate in reversed(context.resources)
                if candidate.resource_id == source.source_resource_id
            ),
            None,
        )
        if resource is None:
            raise AdapterExecutionError(
                "reader source resource is missing from the execution context"
            )
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        attempt_index = len(context.attempts) - 1
        remaining_output_bytes = int(context.remaining_budget("decompressed_bytes"))
        context.require_budget("decompressed_bytes", 1)
        body = await context.cas.get(
            source.cas_uri,
            maximum_bytes=source.size,
        )
        document = body.decode("utf-8", errors="replace")
        if node.capability_id == "jina_reader":
            remaining_wire_bytes = int(context.remaining_budget("bytes"))
            context.require_budget("bytes", 1)
            limiting_budget = (
                "wire"
                if remaining_wire_bytes < remaining_output_bytes
                else "decompressed"
            )
            text, parser, bytes_received = await self._remote_reader(
                context,
                attempt_index=attempt_index,
                maximum_bytes=min(
                    remaining_wire_bytes,
                    remaining_output_bytes,
                ),
                limiting_budget=limiting_budget,
            )
        elif node.capability_id == "browser_reader_mode":
            if raw is None:
                raise AdapterExecutionError(
                    "browser reader mode requires an HTTP source artifact"
                )
            text = await self.browser_reader.extract(
                document,
                target=context.request.target,
                user_agent=self.user_agent,
                timeout_seconds=context.request.budget.browser_seconds,
                maximum_bytes=remaining_output_bytes,
            )
            parser = "offline-browser-reader"
            bytes_received = len(text.encode())
        elif normalized_document is not None:
            text = _normalized_document_text(
                body,
                maximum_bytes=remaining_output_bytes,
            )
            parser = "normalized-document-reader"
            bytes_received = len(body)
        else:
            assert raw is not None
            text, parser = _extract(node.capability_id, document, raw.media_type)
            bytes_received = len(body)
        quality = assess_text(text, expected_language=context.request.language)
        encoded = text.encode("utf-8")
        context.require_budget("decompressed_bytes", len(encoded))
        uri, digest, size = await context.cas.put(encoded)
        duplicate = next(
            (artifact for artifact in context.artifacts if artifact.sha256 == digest),
            None,
        )
        if duplicate is not None:
            quality = quality.model_copy(update={"duplicate_of": duplicate.artifact_id})
        artifact = build_artifact(
            role="primary" if quality.accepted else "checked-only",
            representation="clean_text",
            media_type="text/plain",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor=f"{parser}/{node.capability_id}/0.1",
            quality=quality,
            parents=(source,),
            locators=("document",),
        )
        context.artifacts.append(artifact)
        context.record_quality_outcomes(quality, stage="quality")
        context.accepted = context.accepted or quality.accepted
        current_attempt = context.attempts[attempt_index]
        consumed_budget = dict(current_attempt.consumed_budget)
        consumed_budget["decompressed_bytes"] = (
            consumed_budget.get("decompressed_bytes", 0) + size
        )
        context.attempts[attempt_index] = current_attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "bytes_received": bytes_received,
                "parser": parser,
                "artifact_ids": (artifact.artifact_id,),
                "consumed_budget": consumed_budget,
            }
        )

    async def _remote_reader(
        self,
        context: ExecutionContext,
        *,
        attempt_index: int,
        maximum_bytes: int,
        limiting_budget: str,
    ) -> tuple[str, str, int]:
        from fetech.adapters.base import AdapterDependencyError

        if not self.remote_reader_template:
            raise AdapterDependencyError(
                "jina_reader requires a configured FETECH_JINA_READER_TEMPLATE"
            )
        if "{target}" not in self.remote_reader_template:
            raise AdapterExecutionError("Jina reader template must contain {target}")
        if context.request.privacy_profile != "public" or context.request.authentication_ref:
            raise AdapterExecutionError("remote readers cannot receive private or authenticated targets")
        if context.request.policy_profile != "allow_remote_readers":
            raise AdapterExecutionError("jina_reader requires policy_profile=allow_remote_readers")
        if sanitize_url(context.request.target) != context.request.target:
            raise AdapterExecutionError("remote readers cannot receive targets with sensitive query values")
        service_url = self.remote_reader_template.replace(
            "{target}", quote(context.request.target, safe="")
        )
        if urlsplit(service_url).scheme != "https":
            raise AdapterExecutionError("remote reader service must use HTTPS")
        service_url, decisions = await self.policy.evaluate(service_url)
        context.policy_decisions.extend(decisions)
        host = urlsplit(service_url).hostname or ""
        transport = self.remote_transport or PinnedAsyncHTTPTransport(
            maximum_connections=1,
            maximum_keepalive_connections=0,
        )
        if isinstance(transport, PinnedAsyncHTTPTransport):
            transport.pin(host, self.policy.validated_addresses(host))
        maximum_bytes = min(maximum_bytes, 50_000_000)
        chunks: list[bytes] = []
        size = 0
        try:
            async with httpx.AsyncClient(
                transport=transport,
                follow_redirects=False,
                timeout=context.request.budget.deadline_seconds,
                headers={"User-Agent": self.user_agent, "Accept": "text/plain"},
            ) as client, client.stream("GET", service_url) as response:
                if response.is_redirect:
                    raise AdapterExecutionError("remote reader redirects are not followed")
                response.raise_for_status()
                async for chunk in response.aiter_bytes():
                    size += len(chunk)
                    context.record_attempt_consumption(
                        attempt_index,
                        bytes=len(chunk),
                    )
                    if size > maximum_bytes:
                        raise AdapterBudgetExceededError(
                            f"remote reader exceeded the remaining {limiting_budget} "
                            "byte budget"
                        )
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise AdapterExecutionError("remote reader request failed") from exc
        return b"".join(chunks).decode("utf-8", errors="replace"), "jina-reader", size


def extract_visible_text(document: str) -> str:
    """Return deterministic visible text without running document scripts."""

    without_scripts = _SCRIPT_STYLE.sub(" ", document)
    without_tags = _TAGS.sub(" ", without_scripts)
    return _WHITESPACE.sub(" ", unescape(without_tags)).strip()


def _normalized_document_text(body: bytes, *, maximum_bytes: int) -> str:
    """Extract bounded text from Fetech's validated document representation."""

    try:
        document = json.loads(body)
        if not isinstance(document, dict):
            raise TypeError
        blocks = document.get("blocks")
        if not isinstance(blocks, list) or len(blocks) > 10_000:
            raise TypeError
        parts: list[str] = []
        size = 0
        for block in blocks:
            if not isinstance(block, dict):
                raise TypeError
            value: str | None = None
            if isinstance(block.get("text"), str):
                value = block["text"]
            elif isinstance(block.get("cells"), list):
                value = " ".join(
                    "" if cell is None else str(cell)
                    for cell in block["cells"]
                )
            elif "value" in block:
                value = json.dumps(
                    block["value"],
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                    allow_nan=False,
                )
            elif isinstance(block.get("locator"), str):
                value = block["locator"]
            if value is None:
                continue
            encoded_size = len(value.encode("utf-8"))
            size += encoded_size + (1 if parts else 0)
            if size > maximum_bytes:
                raise AdapterBudgetExceededError(
                    "normalized document text exceeds the remaining decompressed byte budget"
                )
            parts.append(value)
    except AdapterBudgetExceededError:
        raise
    except (TypeError, ValueError, json.JSONDecodeError) as exc:
        raise AdapterExecutionError(
            "reader received an invalid normalized document artifact"
        ) from exc
    return "\n".join(parts)


def _extract(capability_id: str, document: str, media_type: str) -> tuple[str, str]:
    is_html = media_type in {"text/html", "application/xhtml+xml"}
    if capability_id == "raw_html":
        return document, "raw-html"
    if not is_html:
        return document, "plain-text"
    if capability_id in {"clean_text", "boilerplate_removal"}:
        return extract_visible_text(document), "builtin-reader"
    if capability_id in {"main_article", "newspaper_style", "mercury_style"}:
        return extract_visible_text(_main_html(document)), "builtin-main-content"
    if capability_id == "mozilla_readability":
        try:
            from readability import Document  # type: ignore[import-untyped]
        except ImportError as exc:
            from fetech.adapters.base import AdapterDependencyError

            raise AdapterDependencyError(
                "mozilla_readability requires the fetech[web] extra"
            ) from exc
        return extract_visible_text(str(Document(document).summary())), "readability-lxml"
    if capability_id == "trafilatura":
        try:
            import trafilatura
        except ImportError as exc:
            from fetech.adapters.base import AdapterDependencyError

            raise AdapterDependencyError("trafilatura requires the fetech[web] extra") from exc
        extracted = trafilatura.extract(document)
        if not extracted:
            raise AdapterExecutionError("trafilatura found no usable content")
        return extracted, "trafilatura"
    raise AdapterExecutionError(f"reader cannot execute {capability_id}")


def _main_html(document: str) -> str:
    candidates = [match.group(2) for match in _MAIN.finditer(document)]
    return max(candidates, key=len) if candidates else document
