"""Optional Clingo and Prolog backends behind Python-owned contracts."""

from fetech.logic.coordinator import LogicCoordinator
from fetech.logic.models import ReasoningQuery, ReasoningResult

__all__ = ["LogicCoordinator", "ReasoningQuery", "ReasoningResult"]
