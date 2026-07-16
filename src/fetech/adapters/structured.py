"""Structured data, document, media, and optional browser adapters."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fetech.adapters.base import AdapterDependencyError, AdapterExecutionError, ExecutionContext
from fetech.models import AttemptStatus, FetchAttempt, PlanNode
from fetech.quality import assess_text
from fetech.security import sanitize_url
from fetech.storage import build_artifact


class StructuredAdapter:
    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        raw = context.latest_artifact("raw")
        if raw is None or not context.resources:
            raise AdapterExecutionError("structured parsing requires a source artifact")
        body = await context.cas.get(raw.cas_uri, maximum_bytes=context.request.budget.bytes)
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        if node.capability_id == "json_endpoint":
            parsed = json.loads(body)
            encoded = json.dumps(parsed, indent=2, sort_keys=True, ensure_ascii=False).encode()
            representation, media_type = "json", "application/json"
        elif node.capability_id == "xml_endpoint":
            # XML remains byte-preserving here; hardened parsers belong to the optional XML adapter.
            encoded = body
            representation, media_type = "xml", "application/xml"
        else:
            encoded = body
            representation, media_type = node.capability_id, raw.media_type
        quality = assess_text(encoded.decode("utf-8", errors="replace"), media_type=media_type)
        uri, digest, size = await context.cas.put(encoded)
        artifact = build_artifact(
            role="primary" if quality.accepted else "checked-only",
            representation=representation,
            media_type=media_type,
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=context.resources[-1],
            extractor=f"builtin-structured/{node.capability_id}/0.1",
            quality=quality,
            parents=(raw,),
        )
        context.artifacts.append(artifact)
        context.accepted = context.accepted or quality.accepted
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "bytes_received": len(body),
                "parser": node.capability_id,
                "artifact_ids": (artifact.artifact_id,),
            }
        )


class OptionalAdapter:
    def __init__(self, feature: str, extra: str) -> None:
        self.feature = feature
        self.extra = extra

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.FAILED,
            finished_at=datetime.now(UTC),
            failure_code="dependency_missing",
            warnings=(f"install fetech[{self.extra}] to enable {self.feature}",),
        )
        context.attempts.append(attempt)
        raise AdapterDependencyError(attempt.warnings[0])
