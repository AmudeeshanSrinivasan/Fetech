"""Budget-aware DAG executor with early stopping and complete attempts."""

from __future__ import annotations

import asyncio
import json
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
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
    RetryRule,
    RunState,
    utc_now,
)
from fetech.security import (
    PolicyBlockedError,
    sanitize_output_for_request,
    sanitize_url,
    sanitize_url_for_request,
)
from fetech.storage import FileSystemCAS, StorageQuotaExceeded


@dataclass(frozen=True, slots=True)
class _NodeExecution:
    completed: bool = False
    dependency_missing: bool = False
    policy_blocked: bool = False
    budget_exhausted: bool = False
    auth_required: bool = False
    not_found: bool = False
    failed: bool = False
    stop: bool = False


@dataclass(frozen=True, slots=True)
class _ContextLengths:
    resources: int
    artifacts: int
    attempts: int
    capability_outcomes: int
    policy_decisions: int
    diagnostics: int
    pending_events: int
    accepted: bool

    @classmethod
    def capture(cls, context: ExecutionContext) -> _ContextLengths:
        return cls(
            resources=len(context.resources),
            artifacts=len(context.artifacts),
            attempts=len(context.attempts),
            capability_outcomes=len(context.capability_outcomes),
            policy_decisions=len(context.policy_decisions),
            diagnostics=len(context.diagnostics),
            pending_events=len(context.pending_events),
            accepted=context.accepted,
        )


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
        try:
            (
                policy_blocked,
                dependency_missing,
                budget_exhausted,
                auth_required,
                not_found,
                failed,
            ) = await self._execute_nodes(
                run_id,
                plan,
                context,
                root.event_id,
                execution_started,
            )
        except asyncio.CancelledError as exc:
            remaining_budget = self._remaining_budget(plan, context, execution_started)
            partial = FetchResult(
                run_id=run_id,
                status=ResultStatus.PARTIAL if context.artifacts else ResultStatus.FAILED,
                resources=tuple(context.resources),
                artifacts=tuple(context.artifacts),
                attempts=tuple(context.attempts),
                capability_outcomes=tuple(context.capability_outcomes),
                policy_decisions=tuple(context.policy_decisions),
                diagnostics=(
                    *context.diagnostics,
                    Diagnostic(code="run_cancelled", message="fetch execution was cancelled"),
                ),
                provenance_event_ids=tuple(
                    event.event_id for event in await self.ledger.events(run_id)
                ),
                remaining_budget=remaining_budget,
                crawl_report=context.crawl_report,
            )
            partial = FetchResult.model_validate(
                sanitize_output_for_request(
                    partial.model_dump(mode="python"),
                    execution_request,
                )
            )
            raise ExecutionCancelledError(partial, root.event_id) from exc
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
        if not any(outcome.capability_id == "cache_expiry_check" for outcome in context.capability_outcomes):
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
        final = ProvenanceEvent(
            run_id=run_id,
            event_type="run.finished",
            actor="executor",
            payload={"status": status.value},
            parent_event_ids=(root.event_id,),
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
        return await self._finish_result(final, result)

    async def _execute_nodes(
        self,
        run_id: UUID,
        plan: FetchPlan,
        context: ExecutionContext,
        root_event_id: UUID,
        execution_started: float,
    ) -> tuple[bool, bool, bool, bool, bool, bool]:
        completed: set[str] = set()
        dependency_missing = False
        policy_blocked = False
        budget_exhausted = False
        auth_required = False
        not_found = False
        failed = False
        node_index = 0
        while node_index < len(plan.nodes):
            node = plan.nodes[node_index]
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
                node_index += 1
                continue
            if context.accepted and node.fallback_for:
                context.record_outcome(
                    node.capability_id,
                    CapabilityOutcomeStatus.NOT_APPLICABLE,
                    node.adapter,
                    reason=f"accepted artifact made fallback for {node.fallback_for} unnecessary",
                )
                completed.add(node.id)
                node_index += 1
                continue
            batch = self._parallel_batch(
                plan.nodes,
                node_index,
                completed=completed,
                context=context,
            )
            if len(batch) > 1:
                baseline = _ContextLengths.capture(context)
                branch_contexts = self._parallel_contexts(context, len(batch))
                branch_results = await self._execute_parallel_batch(
                    run_id,
                    plan,
                    batch,
                    branch_contexts,
                    root_event_id,
                    execution_started,
                    baseline,
                )
                for branch_node, branch_context, branch_result in zip(
                    batch,
                    branch_contexts,
                    branch_results,
                    strict=True,
                ):
                    self._merge_parallel_context(context, branch_context, baseline)
                    if branch_result.completed:
                        completed.add(branch_node.id)
                    dependency_missing = dependency_missing or branch_result.dependency_missing
                    policy_blocked = policy_blocked or branch_result.policy_blocked
                    budget_exhausted = budget_exhausted or branch_result.budget_exhausted
                    auth_required = auth_required or branch_result.auth_required
                    not_found = not_found or branch_result.not_found
                    failed = failed or branch_result.failed
                node_index += len(batch)
                if any(result.stop for result in branch_results):
                    break
                continue

            node_result = await self._execute_node(
                run_id,
                plan,
                node,
                context,
                root_event_id,
                execution_started,
            )
            if node_result.completed:
                completed.add(node.id)
            dependency_missing = dependency_missing or node_result.dependency_missing
            policy_blocked = policy_blocked or node_result.policy_blocked
            budget_exhausted = budget_exhausted or node_result.budget_exhausted
            auth_required = auth_required or node_result.auth_required
            not_found = not_found or node_result.not_found
            failed = failed or node_result.failed
            node_index += 1
            if node_result.stop:
                break
        return (
            policy_blocked,
            dependency_missing,
            budget_exhausted,
            auth_required,
            not_found,
            failed,
        )

    async def _finish_result(
        self,
        event: ProvenanceEvent,
        result: FetchResult,
    ) -> FetchResult:
        finalizer = asyncio.create_task(self.ledger.finish_run(event, result))
        try:
            won = await asyncio.shield(finalizer)
        except asyncio.CancelledError:
            won = await finalizer
        if won:
            return result
        _, _, stored = await self.ledger.run_snapshot(result.run_id)
        if stored is None:
            raise RuntimeError(f"run {result.run_id} finished without a stored result")
        return stored

    async def _execute_node(
        self,
        run_id: UUID,
        plan: FetchPlan,
        node: PlanNode,
        context: ExecutionContext,
        root_event_id: UUID,
        execution_started: float,
    ) -> _NodeExecution:
        adapter = self.adapters.get(node.adapter)
        if adapter is None:
            context.diagnostics.append(
                Diagnostic(code="adapter_missing", message=f"no adapter registered for {node.adapter}")
            )
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.DEPENDENCY_MISSING,
                node.adapter,
                reason="adapter is not registered",
            )
            return _NodeExecution(dependency_missing=True)
        event = await self._emit(
            run_id,
            "attempt.started",
            node.adapter,
            {"capability_id": node.capability_id},
            (root_event_id,),
        )
        attempt_count = len(context.attempts)
        outcome_count = len(context.capability_outcomes)
        runtime_event_count = len(context.pending_events)
        try:
            self._enforce_approval(plan, node)
            remaining_deadline = plan.request.budget.deadline_seconds - (monotonic() - execution_started)
            if remaining_deadline <= 0:
                self._ensure_deadline_attempt_failed(context, node, attempt_count)
                raise BudgetExhaustedError("run deadline budget exhausted")
            async with asyncio.timeout(remaining_deadline):
                await self._with_retries(adapter.execute, node, context, node.retry)
        except (
            AdapterBudgetExceededError,
            BudgetExhaustedError,
            StorageQuotaExceeded,
        ) as exc:
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
            return _NodeExecution(budget_exhausted=True, stop=True)
        except PolicyBlockedError as exc:
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
            return _NodeExecution(policy_blocked=True, stop=True)
        except AdapterDependencyError as exc:
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
            return _NodeExecution(dependency_missing=True)
        except AdapterAuthExpiredError:
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
            return _NodeExecution(auth_required=True, stop=True)
        except AdapterAuthRequiredError:
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
            return _NodeExecution(auth_required=True, stop=True)
        except AdapterNotFoundError as exc:
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
            return _NodeExecution(not_found=True, stop=True)
        except TimeoutError:
            self._ensure_deadline_attempt_failed(context, node, attempt_count)
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
                {"capability_id": node.capability_id, "code": "budget_exhausted"},
                (event.event_id,),
            )
            return _NodeExecution(budget_exhausted=True, stop=True)
        except asyncio.CancelledError:
            cancellation_reason = context.sensitive_state.pop(
                "_parallel_cancellation_reason",
                "execution_cancelled",
            )
            self._mark_running_attempt_cancelled(context, str(cancellation_reason))
            self._ensure_outcome(
                context,
                node,
                outcome_count,
                CapabilityOutcomeStatus.NOT_APPLICABLE,
                reason=str(cancellation_reason),
            )
            await asyncio.shield(
                self._emit(
                    run_id,
                    "attempt.cancelled",
                    node.adapter,
                    {"capability_id": node.capability_id},
                    (event.event_id,),
                )
            )
            raise
        except (AdapterExecutionError, ValueError, json.JSONDecodeError) as exc:
            self._mark_running_attempt_failed(context, type(exc).__name__)
            context.diagnostics.append(Diagnostic(code="adapter_failed", message=str(exc), retryable=False))
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
            return _NodeExecution(failed=True)
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
        last_artifact = context.artifacts[-1] if context.artifacts else None
        payload = {"capability_id": node.capability_id}
        if last_artifact:
            payload["artifact_id"] = str(last_artifact.artifact_id)
        await self._emit(
            run_id,
            "attempt.finished",
            node.adapter,
            payload,
            (event.event_id,),
        )
        return _NodeExecution(completed=True)

    async def _execute_parallel_batch(
        self,
        run_id: UUID,
        plan: FetchPlan,
        nodes: tuple[PlanNode, ...],
        contexts: tuple[ExecutionContext, ...],
        root_event_id: UUID,
        execution_started: float,
        baseline: _ContextLengths,
    ) -> tuple[_NodeExecution, ...]:
        tasks = tuple(
            asyncio.create_task(
                self._execute_node(
                    run_id,
                    plan,
                    node,
                    context,
                    root_event_id,
                    execution_started,
                ),
                name=f"fetech:{run_id}:{node.id}",
            )
            for node, context in zip(nodes, contexts, strict=True)
        )
        task_indexes = {task: index for index, task in enumerate(tasks)}
        results: list[_NodeExecution | None] = [None] * len(tasks)
        pending = set(tasks)
        try:
            while pending:
                done, pending = await asyncio.wait(
                    pending,
                    return_when=asyncio.FIRST_COMPLETED,
                )
                cancel_pending = False
                accepted_winner = False
                for task in done:
                    index = task_indexes[task]
                    result = task.result()
                    results[index] = result
                    accepted_winner = accepted_winner or (
                        result.completed
                        and nodes[index].stop_on_acceptance
                        and not baseline.accepted
                        and contexts[index].accepted
                    )
                    cancel_pending = cancel_pending or result.stop
                if pending and (accepted_winner or cancel_pending):
                    losers = tuple(pending)
                    for task in losers:
                        index = task_indexes[task]
                        contexts[index].sensitive_state["_parallel_cancellation_reason"] = (
                            "early_stop" if accepted_winner else "parallel_sibling_stopped_execution"
                        )
                        task.cancel()
                    await asyncio.gather(*losers, return_exceptions=True)
                    for task in losers:
                        index = task_indexes[task]
                        if task.cancelled():
                            # A cancelled alternative resolves its dependency slot
                            # without being reported as an execution failure.
                            results[index] = _NodeExecution(completed=True)
                        else:
                            results[index] = task.result()
                    pending.clear()
        except BaseException:
            for task in tasks:
                if not task.done():
                    task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            raise
        if any(result is None for result in results):
            raise RuntimeError("parallel execution finished without a branch result")
        return tuple(result for result in results if result is not None)

    @staticmethod
    def _parallel_batch(
        nodes: tuple[PlanNode, ...],
        start: int,
        *,
        completed: set[str],
        context: ExecutionContext,
    ) -> tuple[PlanNode, ...]:
        first = nodes[start]
        if first.parallel_group is None or first.requires_approval:
            return (first,)
        remaining_attempts = context.request.budget.attempts - len(context.attempts)
        if remaining_attempts <= 1:
            return (first,)
        batch: list[PlanNode] = []
        for candidate in nodes[start:]:
            if (
                candidate.parallel_group != first.parallel_group
                or candidate.requires_approval
                or not set(candidate.dependencies).issubset(completed)
                or (context.accepted and candidate.fallback_for)
            ):
                break
            batch.append(candidate)
            if len(batch) >= remaining_attempts:
                break
        return tuple(batch) if batch else (first,)

    @staticmethod
    def _parallel_contexts(
        context: ExecutionContext,
        count: int,
    ) -> tuple[ExecutionContext, ...]:
        budgets = _partition_parallel_budgets(context, count)
        return tuple(
            ExecutionContext(
                run_id=context.run_id,
                request=context.request.model_copy(update={"budget": budget}),
                cas=context.cas,
                resources=list(context.resources),
                artifacts=list(context.artifacts),
                attempts=list(context.attempts),
                capability_outcomes=list(context.capability_outcomes),
                policy_decisions=list(context.policy_decisions),
                diagnostics=list(context.diagnostics),
                accepted=context.accepted,
                crawl_report=context.crawl_report,
                sensitive_state=dict(context.sensitive_state),
                pending_events=list(context.pending_events),
            )
            for budget in budgets
        )

    @staticmethod
    def _merge_parallel_context(
        context: ExecutionContext,
        branch: ExecutionContext,
        baseline: _ContextLengths,
    ) -> None:
        context.resources.extend(branch.resources[baseline.resources :])
        context.artifacts.extend(branch.artifacts[baseline.artifacts :])
        context.attempts.extend(branch.attempts[baseline.attempts :])
        context.capability_outcomes.extend(branch.capability_outcomes[baseline.capability_outcomes :])
        context.policy_decisions.extend(branch.policy_decisions[baseline.policy_decisions :])
        context.diagnostics.extend(branch.diagnostics[baseline.diagnostics :])
        context.pending_events.extend(branch.pending_events[baseline.pending_events :])
        context.accepted = context.accepted or branch.accepted
        if branch.crawl_report is not None:
            context.crawl_report = branch.crawl_report
        context.sensitive_state.update(branch.sensitive_state)

    @staticmethod
    def _enforce_approval(plan: FetchPlan, node: PlanNode) -> None:
        if not node.requires_approval:
            return
        request = plan.request
        legacy_approval = request.metadata.get(f"{node.capability_id}_approved", "").casefold() == "true"
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
        retry: RetryRule,
    ) -> None:
        error: AdapterExecutionError | None = None
        retryable_codes = {value.casefold() for value in retry.retryable_codes}
        for retry_index in range(retry.maximum + 1):
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
                retry_code = _adapter_retry_code(exc)
                if (
                    retry_index >= retry.maximum
                    or retry_code is None
                    or not _retry_code_allowed(retry_code, retryable_codes)
                ):
                    raise
                if retry.backoff_seconds > 0:
                    await asyncio.sleep(retry.backoff_seconds)
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
                if (
                    failed
                    or dependency_missing
                    or budget_exhausted
                    or auth_required
                    or policy_blocked
                    or not_found
                )
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
    def _mark_running_attempt_cancelled(
        context: ExecutionContext,
        failure_code: str,
    ) -> None:
        if not context.attempts or context.attempts[-1].status != AttemptStatus.RUNNING:
            return
        context.attempts[-1] = context.attempts[-1].model_copy(
            update={
                "status": AttemptStatus.CANCELLED,
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
        consumed_bytes = sum(int(attempt.consumed_budget.get("bytes", 0)) for attempt in context.attempts)
        consumed_decompressed = sum(
            int(attempt.consumed_budget.get("decompressed_bytes", 0)) for attempt in context.attempts
        )
        consumed_redirects = sum(
            int(attempt.consumed_budget.get("redirects", 0)) for attempt in context.attempts
        )
        consumed_archive_members = sum(
            int(attempt.consumed_budget.get("archive_members", 0)) for attempt in context.attempts
        )
        consumed_browser_seconds = sum(
            float(attempt.consumed_budget.get("browser_seconds", 0)) for attempt in context.attempts
        )
        consumed_model_tokens = sum(
            int(attempt.consumed_budget.get("model_tokens", 0)) for attempt in context.attempts
        )
        consumed_money = sum(
            float(attempt.consumed_budget.get("monetary_ceiling", 0)) for attempt in context.attempts
        )
        budget = plan.request.budget
        return budget.model_copy(
            update={
                "deadline_seconds": max(0.001, budget.deadline_seconds - (monotonic() - execution_started)),
                "attempts": max(0, budget.attempts - len(context.attempts)),
                "redirects": max(0, budget.redirects - consumed_redirects),
                "bytes": max(0, budget.bytes - consumed_bytes),
                "decompressed_bytes": max(0, budget.decompressed_bytes - consumed_decompressed),
                "archive_members": max(0, budget.archive_members - consumed_archive_members),
                "browser_seconds": max(0.0, budget.browser_seconds - consumed_browser_seconds),
                "model_tokens": max(0, budget.model_tokens - consumed_model_tokens),
                "monetary_ceiling": max(0.0, budget.monetary_ceiling - consumed_money),
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


class ExecutionCancelledError(asyncio.CancelledError):
    """Carry a sanitized partial result across the gateway cancellation boundary."""

    def __init__(self, result: FetchResult, parent_event_id: UUID) -> None:
        super().__init__("fetch execution was cancelled")
        self.result = result
        self.parent_event_id = parent_event_id


def _adapter_retry_code(error: AdapterExecutionError) -> str | None:
    explicit = getattr(error, "code", None)
    if isinstance(explicit, str) and explicit.strip():
        return explicit.casefold()
    current: BaseException | None = error
    while current is not None:
        if isinstance(current, TimeoutError):
            return "timeout"
        if isinstance(current, ConnectionError):
            return "connection"
        response = getattr(current, "response", None)
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and not isinstance(status_code, bool):
            return str(status_code)
        type_name = type(current).__name__.casefold()
        if "timeout" in type_name:
            return "timeout"
        if "connect" in type_name or "network" in type_name:
            return "connection"
        current = current.__cause__ or current.__context__
    message = str(error).casefold()
    if "timeout" in message or "timed out" in message:
        return "timeout"
    if "connection" in message or "connect failed" in message:
        return "connection"
    status_match = re.search(r"(?<!\d)([45]\d{2})(?!\d)", message)
    return status_match.group(1) if status_match else None


def _retry_code_allowed(code: str, allowed: set[str]) -> bool:
    normalized = code.casefold()
    if normalized in allowed:
        return True
    return normalized.isdigit() and normalized.startswith("5") and "5xx" in allowed


def _partition_parallel_budgets(
    context: ExecutionContext,
    count: int,
) -> tuple[ResourceBudget, ...]:
    if count <= 0:
        raise ValueError("parallel execution requires at least one branch")
    budget = context.request.budget
    updates: list[dict[str, int | float]] = [dict() for _ in range(count)]

    consumed_attempts = len(context.attempts)
    remaining_attempts = max(0, budget.attempts - consumed_attempts)
    attempt_share, attempt_remainder = divmod(remaining_attempts, count)
    for index in range(count):
        updates[index]["attempts"] = (
            consumed_attempts + attempt_share + (1 if index < attempt_remainder else 0)
        )

    integer_fields = (
        "redirects",
        "bytes",
        "decompressed_bytes",
        "archive_members",
        "model_tokens",
    )
    for field in integer_fields:
        ceiling = int(getattr(budget, field))
        consumed = int(context.consumed_budget(field))
        remaining = max(0, ceiling - consumed)
        share, remainder = divmod(remaining, count)
        for index in range(count):
            updates[index][field] = consumed + share + (1 if index < remainder else 0)

    for field in ("browser_seconds", "monetary_ceiling"):
        float_ceiling = float(getattr(budget, field))
        float_consumed = float(context.consumed_budget(field))
        float_share = max(0.0, float_ceiling - float_consumed) / count
        for update in updates:
            update[field] = float_consumed + float_share

    return tuple(budget.model_copy(update=update) for update in updates)
