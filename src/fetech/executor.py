"""Budget-aware DAG executor with early stopping and complete attempts."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Awaitable, Callable
from uuid import UUID

from fetech.adapters.base import Adapter, AdapterDependencyError, AdapterExecutionError, ExecutionContext
from fetech.ledger import EventLedger
from fetech.models import (
    Diagnostic,
    FetchPlan,
    FetchResult,
    PlanNode,
    ProvenanceEvent,
    ResultStatus,
    RunState,
)
from fetech.security import PolicyBlockedError
from fetech.storage import FileSystemCAS


class ExecutionEngine:
    def __init__(self, *, adapters: dict[str, Adapter], cas: FileSystemCAS, ledger: EventLedger) -> None:
        self.adapters = adapters
        self.cas = cas
        self.ledger = ledger

    async def execute(self, run_id: UUID, plan: FetchPlan) -> FetchResult:
        await self.ledger.update_run(run_id, RunState.RUNNING)
        context = ExecutionContext(run_id=run_id, request=plan.request, cas=self.cas)
        root = await self._emit(
            run_id,
            "plan.started",
            "planner",
            {"plan_id": str(plan.plan_id), "classifier": plan.classifier},
        )
        completed: set[str] = set()
        dependency_missing = False
        policy_blocked = False
        failed = False
        for node in plan.nodes:
            if not set(node.dependencies).issubset(completed):
                context.diagnostics.append(
                    Diagnostic(code="dependency_skipped", message=f"{node.id} dependencies did not complete")
                )
                continue
            if context.accepted and node.fallback_for:
                completed.add(node.id)
                continue
            adapter = self.adapters.get(node.adapter)
            if adapter is None:
                dependency_missing = True
                context.diagnostics.append(
                    Diagnostic(code="adapter_missing", message=f"no adapter registered for {node.adapter}")
                )
                continue
            event = await self._emit(
                run_id,
                "attempt.started",
                node.adapter,
                {"capability_id": node.capability_id},
                (root.event_id,),
            )
            try:
                async with asyncio.timeout(plan.request.budget.deadline_seconds):
                    await self._with_retries(adapter.execute, node, context, node.retry.maximum)
            except PolicyBlockedError as exc:
                policy_blocked = True
                context.policy_decisions.extend(exc.decisions)
                context.diagnostics.append(Diagnostic(code="policy_blocked", message=exc.reason))
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
                context.diagnostics.append(Diagnostic(code="dependency_missing", message=str(exc)))
                await self._emit(
                    run_id,
                    "attempt.unavailable",
                    node.adapter,
                    {"capability_id": node.capability_id},
                    (event.event_id,),
                )
                completed.add(node.id)
                continue
            except TimeoutError:
                failed = True
                context.diagnostics.append(
                    Diagnostic(code="deadline", message=f"{node.id} exceeded the deadline")
                )
                await self._emit(
                    run_id,
                    "attempt.failed",
                    node.adapter,
                    {"capability_id": node.capability_id, "code": "deadline"},
                    (event.event_id,),
                )
                break
            except (AdapterExecutionError, ValueError, json.JSONDecodeError) as exc:
                failed = True
                context.diagnostics.append(
                    Diagnostic(code="adapter_failed", message=str(exc), retryable=False)
                )
                await self._emit(
                    run_id,
                    "attempt.failed",
                    node.adapter,
                    {"capability_id": node.capability_id, "code": type(exc).__name__},
                    (event.event_id,),
                )
                completed.add(node.id)
                continue
            completed.add(node.id)
            last_artifact = context.artifacts[-1] if context.artifacts else None
            payload = {"capability_id": node.capability_id}
            if last_artifact:
                payload["artifact_id"] = str(last_artifact.artifact_id)
            await self._emit(run_id, "attempt.finished", node.adapter, payload, (event.event_id,))
        status = self._status(context, policy_blocked, dependency_missing, failed)
        result = FetchResult(
            run_id=run_id,
            status=status,
            resources=tuple(context.resources),
            artifacts=tuple(context.artifacts),
            attempts=tuple(context.attempts),
            policy_decisions=tuple(context.policy_decisions),
            diagnostics=tuple(context.diagnostics),
            provenance_event_ids=tuple(event.event_id for event in await self.ledger.events(run_id)),
            remaining_budget=plan.request.budget,
        )
        final = await self._emit(
            run_id, "run.finished", "executor", {"status": status.value}, (root.event_id,)
        )
        result = result.model_copy(
            update={"provenance_event_ids": (*result.provenance_event_ids, final.event_id)}
        )
        await self.ledger.update_run(run_id, RunState.FINISHED, result)
        return result

    @staticmethod
    async def _with_retries(
        operation: Callable[[PlanNode, ExecutionContext], Awaitable[None]],
        node: PlanNode,
        context: ExecutionContext,
        maximum: int,
    ) -> None:
        error: AdapterExecutionError | None = None
        for _ in range(maximum + 1):
            try:
                await operation(node, context)
                return
            except AdapterExecutionError as exc:
                error = exc
        if error is not None:
            raise error

    @staticmethod
    def _status(
        context: ExecutionContext, policy_blocked: bool, dependency_missing: bool, failed: bool
    ) -> ResultStatus:
        if context.accepted:
            return ResultStatus.SUCCEEDED
        if policy_blocked:
            return ResultStatus.BLOCKED_BY_POLICY
        if context.artifacts:
            return ResultStatus.PARTIAL if failed or dependency_missing else ResultStatus.LOW_QUALITY
        if dependency_missing:
            return ResultStatus.DEPENDENCY_MISSING
        return ResultStatus.FAILED

    async def _emit(
        self,
        run_id: UUID,
        event_type: str,
        actor: str,
        payload: dict[str, str],
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
