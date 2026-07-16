"""Adapter protocol and execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from fetech.models import (
    Artifact,
    CapabilityOutcome,
    CapabilityOutcomeStatus,
    CrawlReport,
    Diagnostic,
    FetchAttempt,
    FetchRequest,
    PageState,
    PlanNode,
    PolicyDecision,
    QualityAssessment,
    Resource,
)
from fetech.storage import FileSystemCAS


@dataclass
class ExecutionContext:
    run_id: UUID
    request: FetchRequest
    cas: FileSystemCAS
    resources: list[Resource] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    attempts: list[FetchAttempt] = field(default_factory=list)
    capability_outcomes: list[CapabilityOutcome] = field(default_factory=list)
    policy_decisions: list[PolicyDecision] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    accepted: bool = False
    crawl_report: CrawlReport | None = None

    def latest_artifact(self, *representations: str) -> Artifact | None:
        allowed = set(representations)
        for artifact in reversed(self.artifacts):
            if not allowed or artifact.representation in allowed:
                return artifact
        return None

    def record_outcome(
        self,
        capability_id: str,
        status: CapabilityOutcomeStatus,
        stage: str,
        **details: str | int | float | bool | None,
    ) -> None:
        self.capability_outcomes.append(
            CapabilityOutcome(
                capability_id=capability_id,
                status=status,
                stage=stage,
                details=details,
            )
        )

    def record_quality_outcomes(self, quality: QualityAssessment, *, stage: str) -> None:
        detectors = {
            "paywall_detection": PageState.PAYWALL,
            "captcha_detection": PageState.CAPTCHA,
            "bot_block_detection": PageState.BOT_BLOCK,
            "login_wall_detection": PageState.LOGIN,
            "empty_page_detection": PageState.EMPTY,
            "error_page_detection": PageState.ERROR,
            "wrong_language_detection": PageState.WRONG_LANGUAGE,
        }
        for capability_id, page_state in detectors.items():
            self.record_outcome(
                capability_id,
                (
                    CapabilityOutcomeStatus.OBSERVED
                    if quality.page_state == page_state
                    else CapabilityOutcomeStatus.NOT_APPLICABLE
                ),
                stage,
                page_state=quality.page_state.value,
            )
        self.record_outcome(
            "duplicate_detection",
            (
                CapabilityOutcomeStatus.OBSERVED
                if quality.duplicate_of is not None
                else CapabilityOutcomeStatus.NOT_APPLICABLE
            ),
            stage,
            duplicate_of=str(quality.duplicate_of) if quality.duplicate_of else None,
        )
        self.record_outcome(
            "content_quality_validation",
            CapabilityOutcomeStatus.APPLIED,
            stage,
            accepted=quality.accepted,
            page_state=quality.page_state.value,
            score=quality.score,
        )


class Adapter(Protocol):
    async def execute(self, node: PlanNode, context: ExecutionContext) -> None: ...


class AdapterDependencyError(RuntimeError):
    pass


class AdapterExecutionError(RuntimeError):
    pass


class AdapterNotFoundError(AdapterExecutionError):
    pass


class AdapterAuthRequiredError(AdapterExecutionError):
    pass
