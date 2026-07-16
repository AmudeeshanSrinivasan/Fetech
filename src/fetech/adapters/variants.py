"""Observable URL-candidate generation and bounded alternative acquisition."""

from __future__ import annotations

import json
from datetime import UTC, datetime

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.adapters.http import HTTPAdapter
from fetech.adapters.reader import extract_visible_text
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    PageState,
    PlanNode,
    QualityAssessment,
    ResourceBudget,
)
from fetech.quality import assess_text
from fetech.security import PolicyBlockedError, sanitize_url
from fetech.storage import build_artifact
from fetech.variants import generate_variant_map


class VariantAdapter:
    def __init__(self, http: HTTPAdapter) -> None:
        self.http = http

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        if node.capability_id != "candidate_url_expansion":
            raise AdapterExecutionError(f"variant adapter cannot execute {node.capability_id}")
        if not context.resources:
            raise AdapterExecutionError("URL alternatives require an acquired source resource")

        attempt_index = len(context.attempts)
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        canonical = _observed_candidate(context, "canonical_redirect")
        candidates = generate_variant_map(
            context.request.target,
            language=context.request.language,
            region=context.request.region,
            canonical_url=canonical,
        )
        sanitized = {
            capability_id: sanitize_url(candidate) if candidate else None
            for capability_id, candidate in candidates.items()
        }
        encoded = json.dumps(sanitized, indent=2, sort_keys=True).encode()
        uri, digest, size = await context.cas.put(encoded)
        parent = context.latest_artifact("raw")
        artifact = build_artifact(
            role="derived",
            representation="url_candidates",
            media_type="application/json",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=context.resources[0],
            extractor="builtin-variants/0.2",
            quality=QualityAssessment(
                page_state=PageState.OK,
                score=1.0,
                completeness=1.0,
                accepted=False,
            ),
            parents=(parent,) if parent else (),
            locators=tuple(
                f"capability:{capability_id}"
                for capability_id, candidate in candidates.items()
                if candidate
            ),
        )
        context.artifacts.append(artifact)
        for capability_id, candidate in candidates.items():
            if capability_id == "https_to_http":
                context.record_outcome(
                    capability_id,
                    CapabilityOutcomeStatus.BLOCKED,
                    "variants",
                    reason="HTTPS downgrade candidates are forbidden",
                )
            else:
                context.record_outcome(
                    capability_id,
                    (
                        CapabilityOutcomeStatus.OBSERVED
                        if candidate
                        else CapabilityOutcomeStatus.NOT_APPLICABLE
                    ),
                    "variants",
                    candidate=sanitize_url(candidate) if candidate else None,
                )
        context.record_outcome(
            "candidate_url_expansion",
            CapabilityOutcomeStatus.APPLIED,
            "variants",
            candidates=sum(candidate is not None for candidate in candidates.values()),
        )
        context.attempts[attempt_index] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "parser": "deterministic-variants",
                "artifact_ids": (artifact.artifact_id,),
            }
        )

        if (
            context.request.privacy_profile != "public"
            or context.request.authentication_ref
            or sanitize_url(context.request.target) != context.request.target
        ):
            context.record_outcome(
                "candidate_url_expansion",
                CapabilityOutcomeStatus.BLOCKED,
                "variants",
                reason="alternative fetching is disabled for private, authenticated, or secret URLs",
            )
            return
        if await _source_is_usable(context):
            return
        await self._try_candidates(context, candidates)

    async def _try_candidates(
        self,
        context: ExecutionContext,
        candidates: dict[str, str | None],
    ) -> None:
        attempted: set[str] = {context.request.target}
        for capability_id, candidate in candidates.items():
            if not candidate or candidate in attempted:
                continue
            if len(context.attempts) >= context.request.budget.attempts:
                return
            attempted.add(candidate)
            budget = _remaining_transfer_budget(context)
            if budget is None:
                return
            request = context.request.model_copy(
                update={
                    "target": candidate,
                    "intent": "retrieve",
                    "output_requirements": ("raw_html",),
                    "budget": budget,
                }
            )
            subcontext = ExecutionContext(
                run_id=context.run_id,
                request=request,
                cas=context.cas,
            )
            try:
                await self.http.execute(
                    PlanNode(
                        id=f"variant:{capability_id}",
                        capability_id="http_get",
                        adapter="http",
                    ),
                    subcontext,
                )
            except (AdapterExecutionError, PolicyBlockedError, ValueError) as exc:
                context.diagnostics.extend(subcontext.diagnostics)
                context.attempts.extend(subcontext.attempts)
                context.policy_decisions.extend(subcontext.policy_decisions)
                context.record_outcome(
                    capability_id,
                    CapabilityOutcomeStatus.FAILED,
                    "variants",
                    reason=type(exc).__name__,
                )
                continue
            for resource in subcontext.resources:
                context.resources.append(
                    resource.model_copy(
                        update={"authority_url": sanitize_url(context.request.target)}
                    )
                )
            context.artifacts.extend(subcontext.artifacts)
            context.attempts.extend(subcontext.attempts)
            context.capability_outcomes.extend(subcontext.capability_outcomes)
            context.policy_decisions.extend(subcontext.policy_decisions)
            context.diagnostics.extend(subcontext.diagnostics)
            raw = subcontext.latest_artifact("raw")
            if raw is not None and raw.quality.accepted:
                context.record_outcome(
                    capability_id,
                    CapabilityOutcomeStatus.APPLIED,
                    "variants",
                    selected=True,
                )
                return


def _observed_candidate(context: ExecutionContext, capability_id: str) -> str | None:
    for outcome in reversed(context.capability_outcomes):
        if outcome.capability_id != capability_id:
            continue
        candidate = outcome.details.get("candidate")
        if isinstance(candidate, str):
            return candidate
    return None


async def _source_is_usable(context: ExecutionContext) -> bool:
    raw = context.latest_artifact("raw")
    if raw is None:
        return False
    if raw.media_type not in {"text/html", "application/xhtml+xml"}:
        return raw.quality.accepted
    body = await context.cas.get(
        raw.cas_uri,
        maximum_bytes=context.request.budget.decompressed_bytes,
    )
    visible = extract_visible_text(body.decode("utf-8", errors="replace"))
    return assess_text(
        visible,
        expected_language=context.request.language,
    ).accepted


def _remaining_transfer_budget(context: ExecutionContext) -> ResourceBudget | None:
    consumed_bytes = sum(
        int(attempt.consumed_budget.get("bytes", 0)) for attempt in context.attempts
    )
    consumed_decompressed = sum(
        int(attempt.consumed_budget.get("decompressed_bytes", 0))
        for attempt in context.attempts
    )
    remaining_bytes = context.request.budget.bytes - consumed_bytes
    remaining_decompressed = context.request.budget.decompressed_bytes - consumed_decompressed
    if remaining_bytes <= 0 or remaining_decompressed <= 0:
        return None
    return context.request.budget.model_copy(
        update={
            "attempts": 1,
            "bytes": remaining_bytes,
            "decompressed_bytes": remaining_decompressed,
        }
    )
