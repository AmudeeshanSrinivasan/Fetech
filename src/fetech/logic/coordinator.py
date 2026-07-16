"""Backend selection, Python validation, and fail-safe fallback."""

from __future__ import annotations

from fetech.config import Settings
from fetech.logic.base import LogicBackendError, PlannerBackend, ReasonerBackend
from fetech.logic.clingo_backend import ClingoPlannerBackend
from fetech.logic.models import BackendStatus, PlanProposal, ReasoningQuery, ReasoningResult
from fetech.logic.prolog_backend import PrologReasonerBackend
from fetech.logic.python_backend import PythonPlannerBackend, PythonReasonerBackend
from fetech.models import FetchPlan, FetchRequest
from fetech.planning import DeterministicPlanner
from fetech.registry import CapabilityRegistry


class LogicCoordinator:
    def __init__(
        self,
        settings: Settings,
        registry: CapabilityRegistry,
        deterministic_planner: DeterministicPlanner,
    ) -> None:
        self.settings = settings
        self.registry = registry
        self.deterministic_planner = deterministic_planner
        self.python_planner = PythonPlannerBackend()
        self.python_reasoner = PythonReasonerBackend()
        self.clingo_planner = ClingoPlannerBackend(
            executable=settings.clingo_executable,
            timeout_seconds=settings.logic_timeout_seconds,
            memory_mb=settings.logic_memory_mb,
            solution_limit=settings.logic_solution_limit,
        )
        self.prolog_reasoner = PrologReasonerBackend(
            executable=settings.prolog_executable,
            timeout_seconds=settings.logic_timeout_seconds,
            memory_mb=settings.logic_memory_mb,
        )

    async def plan(self, request: FetchRequest) -> PlanProposal:
        baseline = self.deterministic_planner.plan(request)
        backend = self._planner_backend()
        try:
            proposal = await backend.propose(request, baseline, self.registry)
            self._validate_plan(proposal.plan, request)
            return proposal
        except (LogicBackendError, ValueError) as exc:
            if not self.settings.logic_fallback or backend.name == "python":
                raise
            fallback = await self.python_planner.propose(request, baseline, self.registry)
            return fallback.model_copy(
                update={
                    "status": BackendStatus.FALLBACK,
                    "diagnostics": (f"{backend.name} fallback: {exc}",),
                    "plan": fallback.plan.model_copy(
                        update={
                            "warnings": (*fallback.plan.warnings, f"{backend.name} fallback: {exc}"),
                        }
                    ),
                }
            )

    async def explain(self, query: ReasoningQuery) -> ReasoningResult:
        backend = self._reasoner_backend()
        try:
            return await backend.explain(query)
        except LogicBackendError as exc:
            if not self.settings.logic_fallback or backend.name == "python":
                raise
            fallback = await self.python_reasoner.explain(query)
            return fallback.model_copy(
                update={
                    "status": BackendStatus.FALLBACK,
                    "diagnostics": (f"{backend.name} fallback: {exc}",),
                }
            )

    def capability_query(
        self,
        capability_id: str,
        *,
        request: FetchRequest | None = None,
    ) -> ReasoningQuery:
        entry = self.registry.get(capability_id)
        denied = request is not None and entry.id in request.deny_capabilities
        allowed_by_list = (
            request is None or not request.allow_capabilities or entry.id in request.allow_capabilities
        )
        return ReasoningQuery(
            capability_id=entry.id,
            allowed=not denied and allowed_by_list,
            available=entry.available,
            risk_class=entry.risk_class,
            dependencies=entry.dependencies,
        )

    def _planner_backend(self) -> PlannerBackend:
        if self.settings.planner_backend == "python":
            return self.python_planner
        if self.settings.planner_backend == "clingo":
            return self.clingo_planner
        raise ValueError(f"unsupported planner backend: {self.settings.planner_backend}")

    def _reasoner_backend(self) -> ReasonerBackend:
        if self.settings.reasoner_backend == "python":
            return self.python_reasoner
        if self.settings.reasoner_backend in {"prolog", "swi-prolog", "swipl"}:
            return self.prolog_reasoner
        raise ValueError(f"unsupported reasoner backend: {self.settings.reasoner_backend}")

    def _validate_plan(self, plan: FetchPlan, request: FetchRequest) -> None:
        baseline = self.deterministic_planner.plan(request)
        if plan.request != baseline.request:
            raise ValueError("logic plan changed the normalized fetch request")
        if not plan.deterministic:
            raise ValueError("logic plan disabled deterministic execution")
        if len(plan.nodes) != len({node.id for node in plan.nodes}):
            raise ValueError("logic plan contains duplicate node IDs")
        proposed_nodes = tuple(node.model_dump(mode="json") for node in plan.nodes)
        baseline_nodes = tuple(node.model_dump(mode="json") for node in baseline.nodes)
        if proposed_nodes != baseline_nodes:
            raise ValueError("logic plan changed the safe Python node structure or ordering")
        for node in plan.nodes:
            self.registry.get(node.capability_id)
            if node.capability_id in request.deny_capabilities:
                raise ValueError(f"logic plan selected denied capability {node.capability_id}")
