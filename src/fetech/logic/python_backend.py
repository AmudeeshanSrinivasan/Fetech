"""Dependency-free Python planner and explanation backends."""

from __future__ import annotations

from fetech.logic.models import BackendStatus, PlanProposal, ReasoningQuery, ReasoningResult
from fetech.models import FetchPlan, FetchRequest
from fetech.registry import CapabilityRegistry


class PythonPlannerBackend:
    name = "python"

    async def propose(
        self,
        request: FetchRequest,
        baseline: FetchPlan,
        registry: CapabilityRegistry,
    ) -> PlanProposal:
        del request, registry
        return PlanProposal(
            backend=self.name,
            status=BackendStatus.SUCCEEDED,
            plan=baseline.model_copy(update={"classifier": "python-rules-v1"}),
        )


class PythonReasonerBackend:
    name = "python"

    async def explain(self, query: ReasoningQuery) -> ReasoningResult:
        eligible = query.allowed and query.available
        reasons: list[str] = []
        if not query.allowed:
            reasons.append("capability is denied by the request policy")
        if not query.available:
            reasons.append("capability implementation is unavailable")
        if eligible:
            reasons.append("capability is registered, allowed, and available")
        if query.dependencies:
            reasons.append(f"dependencies: {', '.join(query.dependencies)}")
        return ReasoningResult(
            backend=self.name,
            status=BackendStatus.SUCCEEDED,
            capability_id=query.capability_id,
            conclusion="eligible" if eligible else "ineligible",
            eligible=eligible,
            reasons=tuple(reasons),
        )
