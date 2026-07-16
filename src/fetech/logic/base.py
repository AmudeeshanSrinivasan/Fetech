"""Protocols and failures for optional logic backends."""

from __future__ import annotations

from typing import Protocol

from fetech.logic.models import PlanProposal, ReasoningQuery, ReasoningResult
from fetech.models import FetchPlan, FetchRequest
from fetech.registry import CapabilityRegistry


class LogicBackendError(RuntimeError):
    """Base class for a bounded logic-backend failure."""


class BackendUnavailableError(LogicBackendError):
    pass


class BackendExecutionError(LogicBackendError):
    pass


class BackendOutputError(LogicBackendError):
    pass


class PlannerBackend(Protocol):
    name: str

    async def propose(
        self,
        request: FetchRequest,
        baseline: FetchPlan,
        registry: CapabilityRegistry,
    ) -> PlanProposal: ...


class ReasonerBackend(Protocol):
    name: str

    async def explain(self, query: ReasoningQuery) -> ReasoningResult: ...
