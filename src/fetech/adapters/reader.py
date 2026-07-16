"""Static HTML and text normalization adapters."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from html import unescape

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.models import AttemptStatus, FetchAttempt, PlanNode
from fetech.quality import assess_text
from fetech.security import sanitize_url
from fetech.storage import build_artifact

_SCRIPT_STYLE = re.compile(r"<(script|style|noscript)\b[^>]*>.*?</\1>", re.I | re.S)
_TAGS = re.compile(r"<[^>]+>")
_WHITESPACE = re.compile(r"\s+")


class ReaderAdapter:
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
        body = await context.cas.get(raw.cas_uri, maximum_bytes=context.request.budget.bytes)
        text = body.decode("utf-8", errors="replace")
        if raw.media_type in {"text/html", "application/xhtml+xml"}:
            text = _html_to_text(text)
        quality = assess_text(text, expected_language=context.request.language)
        encoded = text.encode("utf-8")
        uri, digest, size = await context.cas.put(encoded)
        artifact = build_artifact(
            role="primary" if quality.accepted else "checked-only",
            representation="clean_text",
            media_type="text/plain",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=context.resources[-1],
            extractor=f"builtin-reader/{node.capability_id}/0.1",
            quality=quality,
            parents=(raw,),
            locators=("document",),
        )
        context.artifacts.append(artifact)
        context.accepted = context.accepted or quality.accepted
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "bytes_received": len(body),
                "parser": "builtin-reader",
                "artifact_ids": (artifact.artifact_id,),
            }
        )


def _html_to_text(document: str) -> str:
    without_scripts = _SCRIPT_STYLE.sub(" ", document)
    without_tags = _TAGS.sub(" ", without_scripts)
    return _WHITESPACE.sub(" ", unescape(without_tags)).strip()
