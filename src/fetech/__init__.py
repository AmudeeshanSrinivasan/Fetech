"""Fetech public Python API."""

from fetech.client import FetechClient
from fetech.logic.models import ReasoningQuery, ReasoningResult
from fetech.models import (
    Artifact,
    CapabilityOutcome,
    CapabilityOutcomeStatus,
    CrawlReport,
    DiscoveredTarget,
    FetchPlan,
    FetchRequest,
    FetchResult,
    ResourceBudget,
    ResultStatus,
)

__all__ = [
    "Artifact",
    "CapabilityOutcome",
    "CapabilityOutcomeStatus",
    "CrawlReport",
    "DiscoveredTarget",
    "FetchPlan",
    "FetchRequest",
    "FetchResult",
    "FetechClient",
    "ReasoningQuery",
    "ReasoningResult",
    "ResourceBudget",
    "ResultStatus",
]

__version__ = "0.2.0a0"
