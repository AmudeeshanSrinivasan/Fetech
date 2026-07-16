"""Static HTML and text normalization adapters."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from html import unescape
from urllib.parse import quote, urlsplit

import httpx

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.browser_reader import BrowserReaderWorker
from fetech.models import AttemptStatus, FetchAttempt, PlanNode
from fetech.quality import assess_text
from fetech.security import SafeURLPolicy, sanitize_url
from fetech.storage import build_artifact
from fetech.transport import PinnedAsyncHTTPTransport

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
        user_agent: str = "Fetech/0.1",
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
        if raw is None or not context.resources:
            raise AdapterExecutionError("reader requires an HTTP source artifact")
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        body = await context.cas.get(
            raw.cas_uri, maximum_bytes=context.request.budget.decompressed_bytes
        )
        document = body.decode("utf-8", errors="replace")
        if node.capability_id == "jina_reader":
            text, parser, bytes_received = await self._remote_reader(context)
        elif node.capability_id == "browser_reader_mode":
            text = await self.browser_reader.extract(
                document,
                target=context.request.target,
                user_agent=self.user_agent,
                timeout_seconds=context.request.budget.browser_seconds,
                maximum_bytes=context.request.budget.decompressed_bytes,
            )
            parser = "offline-browser-reader"
            bytes_received = len(text.encode())
        else:
            text, parser = _extract(node.capability_id, document, raw.media_type)
            bytes_received = len(body)
        quality = assess_text(text, expected_language=context.request.language)
        encoded = text.encode("utf-8")
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
            resource=context.resources[-1],
            extractor=f"{parser}/{node.capability_id}/0.1",
            quality=quality,
            parents=(raw,),
            locators=("document",),
        )
        context.artifacts.append(artifact)
        context.record_quality_outcomes(quality, stage="quality")
        context.accepted = context.accepted or quality.accepted
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "bytes_received": bytes_received,
                "parser": parser,
                "artifact_ids": (artifact.artifact_id,),
            }
        )

    async def _remote_reader(self, context: ExecutionContext) -> tuple[str, str, int]:
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
        maximum_bytes = min(context.request.budget.decompressed_bytes, 50_000_000)
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
                    if size > maximum_bytes:
                        raise AdapterExecutionError("remote reader exceeded the byte budget")
                    chunks.append(chunk)
        except httpx.HTTPError as exc:
            raise AdapterExecutionError("remote reader request failed") from exc
        return b"".join(chunks).decode("utf-8", errors="replace"), "jina-reader", size


def extract_visible_text(document: str) -> str:
    """Return deterministic visible text without running document scripts."""

    without_scripts = _SCRIPT_STYLE.sub(" ", document)
    without_tags = _TAGS.sub(" ", without_scripts)
    return _WHITESPACE.sub(" ", unescape(without_tags)).strip()


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
