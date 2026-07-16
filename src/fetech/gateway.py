"""Universal gateway composing registry, planner, execution, and persistence."""

from __future__ import annotations

import asyncio
from contextlib import suppress
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fetech.adapters.archive import ArchiveAdapter
from fetech.adapters.base import Adapter
from fetech.adapters.documents import DocumentAdapter
from fetech.adapters.http import HTTPAdapter
from fetech.adapters.reader import ReaderAdapter
from fetech.adapters.structured import OptionalAdapter, StructuredAdapter
from fetech.config import Settings
from fetech.executor import ExecutionEngine
from fetech.ledger import EventLedger
from fetech.logic import LogicCoordinator, ReasoningResult
from fetech.logic.models import PlanProposal
from fetech.models import (
    Artifact,
    FetchPlan,
    FetchRequest,
    FetchResult,
    FetchRun,
    InspectionResult,
    ProvenanceEvent,
    RunState,
)
from fetech.planning import DeterministicPlanner, classify_target
from fetech.provenance import build_runtime_graph
from fetech.registry import CapabilityRegistry
from fetech.security import PolicyBlockedError, SafeURLPolicy, normalize_url
from fetech.storage import FileSystemCAS


class UniversalFetchGateway:
    def __init__(self, settings: Settings | None = None) -> None:
        self.settings = settings or Settings.from_environment()
        self.registry = CapabilityRegistry()
        self.planner = DeterministicPlanner(self.registry)
        self.logic = LogicCoordinator(self.settings, self.registry, self.planner)
        self.policy = SafeURLPolicy()
        self.ledger = EventLedger.sqlite(self.settings.database_path)
        self.cas = FileSystemCAS(self.settings.artifact_dir)
        self.adapters: dict[str, Adapter] = {
            "http": HTTPAdapter(
                user_agent=self.settings.user_agent,
                policy=self.policy,
                global_concurrency=self.settings.global_concurrency,
                per_host_concurrency=self.settings.per_host_concurrency,
            ),
            "reader": ReaderAdapter(),
            "api": StructuredAdapter(),
            "browser": OptionalAdapter("browser rendering", "browser"),
            "documents": DocumentAdapter(),
            "media": OptionalAdapter("media parsing", "media"),
            "cache": ArchiveAdapter(),
            "core": _CoreAdapter(),
        }
        self.executor = ExecutionEngine(adapters=self.adapters, cas=self.cas, ledger=self.ledger)
        self._tasks: dict[UUID, asyncio.Task[FetchResult]] = {}
        self._artifacts: dict[UUID, Artifact] = {}
        self._initialized = False

    async def initialize(self) -> None:
        if not self._initialized:
            await self.ledger.initialize()
            self._initialized = True

    async def close(self) -> None:
        running = [task for task in self._tasks.values() if not task.done()]
        for task in running:
            task.cancel()
        if running:
            await asyncio.gather(*running, return_exceptions=True)
        await self.ledger.close()
        self._initialized = False

    def plan(self, request: FetchRequest) -> FetchPlan:
        """Return the dependency-free deterministic Python plan."""
        return self.planner.plan(request)

    async def plan_async(self, request: FetchRequest) -> FetchPlan:
        """Return a plan from the configured backend with safe Python fallback."""
        return (await self.logic.plan(request)).plan

    async def explain_capability(
        self, capability_id: str, *, request: FetchRequest | None = None
    ) -> ReasoningResult:
        query = self.logic.capability_query(capability_id, request=request)
        return await self.logic.explain(query)

    async def inspect(self, request: FetchRequest) -> InspectionResult:
        normalized = normalize_url(request.target)
        family = classify_target(normalized, request.output_requirements)
        try:
            _, decisions = await self.policy.evaluate(normalized)
        except PolicyBlockedError as exc:
            decisions = exc.decisions
        plan = await self.plan_async(request)
        return InspectionResult(
            normalized_target=normalized,
            family=family,
            policy_decisions=decisions,
            suggested_capabilities=tuple(node.capability_id for node in plan.nodes),
        )

    async def submit(self, request: FetchRequest) -> FetchRun:
        await self.initialize()
        run_id = uuid4()
        submitted_at = datetime.now(UTC)
        await self.ledger.create_run(run_id, request.model_dump(mode="json"), submitted_at)
        try:
            proposal = await self.logic.plan(request)
        except Exception:
            await self.ledger.update_run(run_id, RunState.FINISHED)
            raise
        await self._record_plan(run_id, proposal)
        plan = proposal.plan
        task = asyncio.create_task(self._execute_and_project(run_id, plan), name=f"fetech:{run_id}")
        self._tasks[run_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(run_id, None))
        return FetchRun(run_id=run_id, state=RunState.QUEUED, submitted_at=submitted_at)

    async def fetch(self, request: FetchRequest) -> FetchResult:
        run = await self.submit(request)
        task = self._tasks[run.run_id]
        return await task

    async def get_run(self, run_id: UUID) -> FetchRun:
        await self.initialize()
        state, submitted_at, result = await self.ledger.run_snapshot(run_id)
        return FetchRun(run_id=run_id, state=state, submitted_at=submitted_at, result=result)

    async def wait(self, run_id: UUID) -> FetchResult:
        task = self._tasks.get(run_id)
        if task is not None:
            return await task
        snapshot = await self.get_run(run_id)
        if snapshot.result is None:
            raise RuntimeError(f"run {run_id} has no active task or stored result")
        return snapshot.result

    def get_artifact(self, artifact_id: UUID) -> Artifact:
        try:
            return self._artifacts[artifact_id]
        except KeyError as exc:
            raise KeyError(f"unknown artifact: {artifact_id}") from exc

    async def _execute_and_project(self, run_id: UUID, plan: FetchPlan) -> FetchResult:
        result = await self.executor.execute(run_id, plan)
        self._artifacts.update({artifact.artifact_id: artifact for artifact in result.artifacts})
        with suppress(OSError):
            await build_runtime_graph(self.ledger, self.settings.runtime_graph_path)
        return result

    async def _record_plan(self, run_id: UUID, proposal: PlanProposal) -> None:
        payload = {
            "backend": proposal.backend,
            "status": proposal.status.value,
            "classifier": proposal.plan.classifier,
        }
        if proposal.executable_version:
            payload["executable_version"] = proposal.executable_version
        if proposal.ruleset_sha256:
            payload["ruleset_sha256"] = proposal.ruleset_sha256
        if proposal.manifest_version:
            payload["manifest_version"] = proposal.manifest_version
        if proposal.manifest_sha256:
            payload["manifest_sha256"] = proposal.manifest_sha256
        if proposal.input_sha256:
            payload["input_sha256"] = proposal.input_sha256
        if proposal.result_sha256:
            payload["result_sha256"] = proposal.result_sha256
        if proposal.diagnostics:
            payload["diagnostic"] = "; ".join(proposal.diagnostics)
        await self.ledger.append(
            ProvenanceEvent(
                run_id=run_id,
                event_type="planning.completed",
                actor=proposal.backend,
                payload=payload,
            )
        )


class _CoreAdapter:
    async def execute(self, node: object, context: object) -> None:
        del node, context
