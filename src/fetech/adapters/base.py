"""Adapter protocol and execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol
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
    sensitive_state: dict[str, object] = field(default_factory=dict, repr=False)
    pending_events: list[tuple[str, str, dict[str, Any]]] = field(default_factory=list)

    def latest_artifact(self, *representations: str) -> Artifact | None:
        allowed = set(representations)
        for artifact in reversed(self.artifacts):
            if not allowed or artifact.representation in allowed:
                return artifact
        return None

    def consumed_budget(self, name: str) -> int | float:
        """Return cumulative adapter-reported consumption for one budget field."""

        return sum(
            attempt.consumed_budget.get(name, 0)
            for attempt in self.attempts
        )

    def remaining_budget(self, name: str) -> int | float:
        """Return the request ceiling minus cumulative consumption."""

        ceiling = getattr(self.request.budget, name)
        if not isinstance(ceiling, int | float):
            raise ValueError(f"unknown numeric budget field: {name}")
        return max(0, ceiling - self.consumed_budget(name))

    def require_budget(self, name: str, amount: int | float) -> None:
        if amount < 0:
            raise ValueError("budget consumption cannot be negative")
        if amount > self.remaining_budget(name):
            raise AdapterBudgetExceededError(f"{name} budget exhausted")

    def record_attempt_consumption(
        self,
        attempt_index: int,
        **consumption: int | float,
    ) -> None:
        """Record resources already consumed by an in-flight adapter attempt.

        External providers can return bytes that fail later validation. Those
        bytes still count against the run budget and must remain visible if the
        executor retries the node.
        """

        if not 0 <= attempt_index < len(self.attempts):
            raise IndexError("attempt index is outside the execution context")
        attempt = self.attempts[attempt_index]
        updated = dict(attempt.consumed_budget)
        for name, amount in consumption.items():
            ceiling = getattr(self.request.budget, name, None)
            if not isinstance(ceiling, int | float):
                raise ValueError(f"unknown numeric budget field: {name}")
            if amount < 0:
                raise ValueError("budget consumption cannot be negative")
            updated[name] = updated.get(name, 0) + amount
        self.attempts[attempt_index] = attempt.model_copy(
            update={"consumed_budget": updated}
        )

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

    def record_runtime_event(
        self,
        event_type: str,
        actor: str,
        **payload: str | int | float | bool | None,
    ) -> None:
        """Queue a sanitized adapter event for the executor-owned ledger boundary."""

        self.pending_events.append((event_type, actor, dict(payload)))


class Adapter(Protocol):
    async def execute(self, node: PlanNode, context: ExecutionContext) -> None: ...


class AdapterDependencyError(RuntimeError):
    pass


class AdapterExecutionError(RuntimeError):
    pass


class AdapterBudgetExceededError(AdapterExecutionError):
    """An adapter cannot proceed within the run's remaining shared budget."""


class AdapterNotFoundError(AdapterExecutionError):
    pass


class AdapterAuthRequiredError(AdapterExecutionError):
    pass


class AdapterAuthExpiredError(AdapterAuthRequiredError):
    """Resolved credential material is known to be expired."""
