"""Budget-aware DAG executor with early stopping and complete attempts."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from time import monotonic
from typing import Any
from uuid import UUID

from fetech.adapters.base import (
    Adapter,
    AdapterAuthExpiredError,
    AdapterAuthRequiredError,
    AdapterBudgetExceededError,
    AdapterDependencyError,
    AdapterExecutionError,
    AdapterNotFoundError,
    ExecutionContext,
)
from fetech.ledger import EventLedger
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    Diagnostic,
    FetchAttempt,
    FetchPlan,
    FetchResult,
    PlanNode,
    PolicyDecision,
    ProvenanceEvent,
    ResourceBudget,
    ResultStatus,
    RunState,
    utc_now,
)
from fetech.security import (
    PolicyBlockedError,
    sanitize_output_for_request,
    sanitize_url,
    sanitize_url_for_request,
)
from fetech.storage import FileSystemCAS


class ExecutionEngine:
    def __init__(self, *, adapters: dict[str, Adapter], cas: FileSystemCAS, ledger: EventLedger) -> None:
        self.adapters = adapters
        self.cas = cas
        self.ledger = ledger

    async def execute(self, run_id: UUID, plan: FetchPlan) -> FetchResult:
        execution_started = monotonic()
        execution_request = plan.execution_request
        await self.ledger.update_run(run_id, RunState.RUNNING)
        context = ExecutionContext(run_id=run_id, request=execution_request, cas=self.cas)
        root = await self._emit(
            run_id,
            "plan.started",
            "planner",
            {"plan_id": str(plan.plan_id), "classifier": plan.classifier},
        )
        completed: set[str] = set()
        dependency_missing = False
        policy_blocked = False
        budget_exhausted = False
        auth_required = False
        not_found = False
        failed = False
        for node in plan.nodes:
            if not set(node.dependencies).issubset(completed):
                context.diagnostics.append(
                    Diagnostic(code="dependency_skipped", message=f"{node.id} dependencies did not complete")
                )
                context.record_outcome(
                    node.capability_id,
                    CapabilityOutcomeStatus.NOT_APPLICABLE,
                    node.adapter,
                    reason="dependencies did not complete",
                )
                continue
            if context.accepted and node.fallback_for:
                context.record_outcome(
                    node.capability_id,
                    CapabilityOutcomeStatus.NOT_APPLICABLE,
                    node.adapter,
                    reason=f"accepted artifact made fallback for {node.fallback_for} unnecessary",
                )
                completed.add(node.id)
                continue
            adapter = self.adapters.get(node.adapter)
            if adapter is None:
                dependency_missing = True
                context.diagnostics.append(
                    Diagnostic(code="adapter_missing", message=f"no adapter registered for {node.adapter}")
                )
                context.record_outcome(
                    node.capability_id,
                    CapabilityOutcomeStatus.DEPENDENCY_MISSING,
                    node.adapter,
                    reason="adapter is not registered",
                )
                continue
            event = await self._emit(
                run_id,
                "attempt.started",
                node.adapter,
                {"capability_id": node.capability_id},
                (root.event_id,),
            )
            attempt_count = len(context.attempts)
            outcome_count = len(context.capability_outcomes)
            runtime_event_count = len(context.pending_events)
            try:
                self._enforce_approval(plan, node)
                remaining_deadline = plan.request.budget.deadline_seconds - (
                    monotonic() - execution_started
                )
                if remaining_deadline <= 0:
                    self._ensure_deadline_attempt_failed(
                        context,
                        node,
                        attempt_count,
                    )
                    raise BudgetExhaustedError("run deadline budget exhausted")
                async with asyncio.timeout(remaining_deadline):
                    await self._with_retries(adapter.execute, node, context, node.retry.maximum)
            except (AdapterBudgetExceededError, BudgetExhaustedError) as exc:
                budget_exhausted = True
                self._mark_running_attempt_failed(context, "budget_exhausted")
                context.diagnostics.append(Diagnostic(code="budget_exhausted", message=str(exc)))
                self._ensure_outcome(
                    context,
                    node,
                    outcome_count,
                    CapabilityOutcomeStatus.FAILED,
                    reason=str(exc),
                )
                await self._emit(
                    run_id,
                    "attempt.budget_exhausted",
                    node.adapter,
                    {"capability_id": node.capability_id},
                    (event.event_id,),
                )
                break
            except PolicyBlockedError as exc:
                policy_blocked = True
                self._mark_running_attempt_failed(context, "policy")
                context.policy_decisions.extend(exc.decisions)
                context.diagnostics.append(Diagnostic(code="policy_blocked", message=exc.reason))
                self._ensure_outcome(
                    context,
                    node,
                    outcome_count,
                    CapabilityOutcomeStatus.BLOCKED,
                    reason=exc.reason,
                )
                await self._emit(
                    run_id,
                    "attempt.blocked",
                    node.adapter,
                    {"capability_id": node.capability_id},
                    (event.event_id,),
                )
                break
            except AdapterDependencyError as exc:
                dependency_missing = True
                self._mark_running_attempt_failed(context, "dependency_missing")
                context.diagnostics.append(Diagnostic(code="dependency_missing", message=str(exc)))
                self._ensure_outcome(
                    context,
                    node,
                    outcome_count,
                    CapabilityOutcomeStatus.DEPENDENCY_MISSING,
                    reason=str(exc),
                )
                await self._emit(
                    run_id,
                    "attempt.unavailable",
                    node.adapter,
                    {"capability_id": node.capability_id},
                    (event.event_id,),
                )
                continue
            except AdapterAuthExpiredError:
                auth_required = True
                self._mark_running_attempt_failed(context, "auth_expired")
                message = "credential material is expired or was rejected as expired"
                context.diagnostics.append(Diagnostic(code="auth_expired", message=message))
                self._ensure_outcome(
                    context,
                    node,
                    outcome_count,
                    CapabilityOutcomeStatus.FAILED,
                    reason=message,
                )
                await self._emit(
                    run_id,
                    "attempt.auth_expired",
                    node.adapter,
                    {"capability_id": node.capability_id},
                    (event.event_id,),
                )
                break
            except AdapterAuthRequiredError:
                auth_required = True
                self._mark_running_attempt_failed(context, "auth_required")
                message = "authentication is required or the supplied material was rejected"
                context.diagnostics.append(Diagnostic(code="auth_required", message=message))
                self._ensure_outcome(
                    context,
                    node,
                    outcome_count,
                    CapabilityOutcomeStatus.FAILED,
                    reason=message,
                )
                await self._emit(
                    run_id,
                    "attempt.auth_required",
                    node.adapter,
                    {"capability_id": node.capability_id},
                    (event.event_id,),
                )
                break
            except AdapterNotFoundError as exc:
                not_found = True
                self._mark_running_attempt_failed(context, "not_found")
                context.diagnostics.append(Diagnostic(code="not_found", message=str(exc)))
                self._ensure_outcome(
                    context,
                    node,
                    outcome_count,
                    CapabilityOutcomeStatus.FAILED,
                    reason=str(exc),
                )
                await self._emit(
                    run_id,
                    "attempt.not_found",
                    node.adapter,
                    {"capability_id": node.capability_id},
                    (event.event_id,),
                )
                break
            except TimeoutError:
                budget_exhausted = True
                self._ensure_deadline_attempt_failed(
                    context,
                    node,
                    attempt_count,
                )
                context.diagnostics.append(
                    Diagnostic(
                        code="budget_exhausted",
                        message=f"{node.id} exhausted the deadline budget",
                    )
                )
                self._ensure_outcome(
                    context,
                    node,
                    outcome_count,
                    CapabilityOutcomeStatus.FAILED,
                    reason="deadline budget exhausted",
                )
                await self._emit(
                    run_id,
                    "attempt.budget_exhausted",
                    node.adapter,
                    {
                        "capability_id": node.capability_id,
                        "code": "budget_exhausted",
                    },
                    (event.event_id,),
                )
                break
            except (AdapterExecutionError, ValueError, json.JSONDecodeError) as exc:
                failed = True
                self._mark_running_attempt_failed(context, type(exc).__name__)
                context.diagnostics.append(
                    Diagnostic(code="adapter_failed", message=str(exc), retryable=False)
                )
                self._ensure_outcome(
                    context,
                    node,
                    outcome_count,
                    CapabilityOutcomeStatus.FAILED,
                    reason=str(exc),
                )
                await self._emit(
                    run_id,
                    "attempt.failed",
                    node.adapter,
                    {"capability_id": node.capability_id, "code": type(exc).__name__},
                    (event.event_id,),
                )
                continue
            finally:
                await self._flush_pending_events(
                    run_id,
                    context,
                    runtime_event_count,
                    event.event_id,
                )
            self._ensure_outcome(
                context,
                node,
                outcome_count,
                CapabilityOutcomeStatus.APPLIED,
            )
            completed.add(node.id)
            last_artifact = context.artifacts[-1] if context.artifacts else None
            payload = {"capability_id": node.capability_id}
            if last_artifact:
                payload["artifact_id"] = str(last_artifact.artifact_id)
            await self._emit(run_id, "attempt.finished", node.adapter, payload, (event.event_id,))
        context.record_outcome(
            "fetch_attempt_logging",
            CapabilityOutcomeStatus.APPLIED,
            "ledger",
            attempts=len(context.attempts),
        )
        context.record_outcome(
            "timeout_diagnostics",
            CapabilityOutcomeStatus.APPLIED,
            "executor",
            deadline_seconds=plan.request.budget.deadline_seconds,
        )
        if not any(
            outcome.capability_id == "cache_expiry_check"
            for outcome in context.capability_outcomes
        ):
            context.record_outcome(
                "cache_expiry_check",
                CapabilityOutcomeStatus.NOT_APPLICABLE,
                "cache",
                reason="no validated cache record was consulted",
            )
        status = self._status(
            context,
            policy_blocked,
            dependency_missing,
            budget_exhausted,
            auth_required,
            not_found,
            failed,
        )
        remaining_budget = self._remaining_budget(plan, context, execution_started)
        result = FetchResult(
            run_id=run_id,
            status=status,
            resources=tuple(context.resources),
            artifacts=tuple(context.artifacts),
            attempts=tuple(context.attempts),
            capability_outcomes=tuple(context.capability_outcomes),
            policy_decisions=tuple(context.policy_decisions),
            diagnostics=tuple(context.diagnostics),
            provenance_event_ids=tuple(event.event_id for event in await self.ledger.events(run_id)),
            remaining_budget=remaining_budget,
            crawl_report=context.crawl_report,
        )
        final = await self._emit(
            run_id, "run.finished", "executor", {"status": status.value}, (root.event_id,)
        )
        result = result.model_copy(
            update={"provenance_event_ids": (*result.provenance_event_ids, final.event_id)}
        )
        result = FetchResult.model_validate(
            sanitize_output_for_request(
                result.model_dump(mode="python"),
                execution_request,
            )
        )
        await self.ledger.update_run(run_id, RunState.FINISHED, result)
        return result

    @staticmethod
    def _enforce_approval(plan: FetchPlan, node: PlanNode) -> None:
        if not node.requires_approval:
            return
        request = plan.request
        legacy_approval = (
            request.metadata.get(f"{node.capability_id}_approved", "").casefold() == "true"
        )
        if node.capability_id in request.approved_capabilities or legacy_approval:
            return
        reason = f"{node.capability_id} requires explicit approval"
        raise PolicyBlockedError(
            reason,
            (
                PolicyDecision(
                    policy_id="capability_approval",
                    allowed=False,
                    reason=reason,
                    destination=sanitize_url(request.target),
                ),
            ),
        )

    async def _flush_pending_events(
        self,
        run_id: UUID,
        context: ExecutionContext,
        start: int,
        parent_event_id: UUID,
    ) -> None:
        for event_type, actor, payload in context.pending_events[start:]:
            await self._emit(run_id, event_type, actor, payload, (parent_event_id,))

    @staticmethod
    async def _with_retries(
        operation: Callable[[PlanNode, ExecutionContext], Awaitable[None]],
        node: PlanNode,
        context: ExecutionContext,
        maximum: int,
    ) -> None:
        error: AdapterExecutionError | None = None
        for _ in range(maximum + 1):
            if len(context.attempts) >= context.request.budget.attempts:
                raise BudgetExhaustedError("attempt budget exhausted")
            try:
                await operation(node, context)
                return
            except (
                AdapterAuthRequiredError,
                AdapterBudgetExceededError,
                AdapterNotFoundError,
            ):
                raise
            except AdapterExecutionError as exc:
                error = exc
        if error is not None:
            raise error

    @staticmethod
    def _status(
        context: ExecutionContext,
        policy_blocked: bool,
        dependency_missing: bool,
        budget_exhausted: bool,
        auth_required: bool,
        not_found: bool,
        failed: bool,
    ) -> ResultStatus:
        if context.accepted:
            return (
                ResultStatus.PARTIAL
                if failed or dependency_missing or budget_exhausted or auth_required
                else ResultStatus.SUCCEEDED
            )
        if policy_blocked:
            return ResultStatus.BLOCKED_BY_POLICY
        if auth_required:
            return ResultStatus.AUTH_REQUIRED
        if not_found:
            return ResultStatus.NOT_FOUND
        if budget_exhausted:
            return ResultStatus.BUDGET_EXHAUSTED
        if context.artifacts:
            return ResultStatus.PARTIAL if failed or dependency_missing else ResultStatus.LOW_QUALITY
        if dependency_missing:
            return ResultStatus.DEPENDENCY_MISSING
        return ResultStatus.FAILED

    @staticmethod
    def _ensure_outcome(
        context: ExecutionContext,
        node: PlanNode,
        outcome_count: int,
        status: CapabilityOutcomeStatus,
        **details: str | int | float | bool | None,
    ) -> None:
        if any(
            outcome.capability_id == node.capability_id
            for outcome in context.capability_outcomes[outcome_count:]
        ):
            return
        context.record_outcome(node.capability_id, status, node.adapter, **details)

    @staticmethod
    def _mark_running_attempt_failed(context: ExecutionContext, failure_code: str) -> None:
        if not context.attempts or context.attempts[-1].status != AttemptStatus.RUNNING:
            return
        context.attempts[-1] = context.attempts[-1].model_copy(
            update={
                "status": AttemptStatus.FAILED,
                "finished_at": utc_now(),
                "failure_code": failure_code,
            }
        )

    @staticmethod
    def _ensure_deadline_attempt_failed(
        context: ExecutionContext,
        node: PlanNode,
        attempt_count: int,
    ) -> None:
        if len(context.attempts) == attempt_count:
            finished_at = utc_now()
            context.attempts.append(
                FetchAttempt(
                    capability_id=node.capability_id,
                    sanitized_destination=sanitize_url_for_request(
                        context.request.target,
                        context.request,
                    ),
                    status=AttemptStatus.FAILED,
                    finished_at=finished_at,
                    failure_code="budget_exhausted",
                )
            )
            return

        attempt = context.attempts[-1]
        if attempt.status not in {
            AttemptStatus.CANCELLED,
            AttemptStatus.PLANNED,
            AttemptStatus.RUNNING,
        }:
            return
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.FAILED,
                "finished_at": utc_now(),
                "failure_code": "budget_exhausted",
            }
        )

    @staticmethod
    def _remaining_budget(
        plan: FetchPlan,
        context: ExecutionContext,
        execution_started: float,
    ) -> ResourceBudget:
        consumed_bytes = sum(
            int(attempt.consumed_budget.get("bytes", 0)) for attempt in context.attempts
        )
        consumed_decompressed = sum(
            int(attempt.consumed_budget.get("decompressed_bytes", 0))
            for attempt in context.attempts
        )
        consumed_redirects = sum(
            int(attempt.consumed_budget.get("redirects", 0)) for attempt in context.attempts
        )
        consumed_archive_members = sum(
            int(attempt.consumed_budget.get("archive_members", 0))
            for attempt in context.attempts
        )
        consumed_browser_seconds = sum(
            float(attempt.consumed_budget.get("browser_seconds", 0))
            for attempt in context.attempts
        )
        consumed_model_tokens = sum(
            int(attempt.consumed_budget.get("model_tokens", 0))
            for attempt in context.attempts
        )
        consumed_money = sum(
            float(attempt.consumed_budget.get("monetary_ceiling", 0))
            for attempt in context.attempts
        )
        budget = plan.request.budget
        return budget.model_copy(
            update={
                "deadline_seconds": max(
                    0.001, budget.deadline_seconds - (monotonic() - execution_started)
                ),
                "attempts": max(0, budget.attempts - len(context.attempts)),
                "redirects": max(0, budget.redirects - consumed_redirects),
                "bytes": max(0, budget.bytes - consumed_bytes),
                "decompressed_bytes": max(
                    0, budget.decompressed_bytes - consumed_decompressed
                ),
                "archive_members": max(
                    0, budget.archive_members - consumed_archive_members
                ),
                "browser_seconds": max(
                    0.0, budget.browser_seconds - consumed_browser_seconds
                ),
                "model_tokens": max(0, budget.model_tokens - consumed_model_tokens),
                "monetary_ceiling": max(
                    0.0, budget.monetary_ceiling - consumed_money
                ),
            }
        )

    async def _emit(
        self,
        run_id: UUID,
        event_type: str,
        actor: str,
        payload: dict[str, Any],
        parents: tuple[UUID, ...] = (),
    ) -> ProvenanceEvent:
        event = ProvenanceEvent(
            run_id=run_id,
            event_type=event_type,
            actor=actor,
            payload=payload,
            parent_event_ids=parents,
        )
        await self.ledger.append(event)
        return event


class BudgetExhaustedError(RuntimeError):
    """Raised before an adapter can exceed a reserved run budget."""
