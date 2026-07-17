"""Fetech public Python API."""

from fetech.auth import (
    CredentialMaterial,
    CredentialNotFoundError,
    CredentialProvider,
    CredentialProviderError,
    CredentialProviderUnavailableError,
    InMemoryCredentialProvider,
    RefreshableCredentialProvider,
)
from fetech.auth_flows import (
    FormSubmission,
    FormSubmissionApproval,
    FormSubmissionProvider,
    InMemoryFormSubmissionProvider,
    InMemorySessionProvider,
    NullSessionProvider,
    OriginScopedSession,
    PrivateWorkspaceTarget,
    SessionProvider,
    extract_csrf_token,
)
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
    "CredentialMaterial",
    "CredentialNotFoundError",
    "CredentialProvider",
    "CredentialProviderError",
    "CredentialProviderUnavailableError",
    "DiscoveredTarget",
    "FetchPlan",
    "FetchRequest",
    "FetchResult",
    "FetechClient",
    "FormSubmission",
    "FormSubmissionApproval",
    "FormSubmissionProvider",
    "InMemoryCredentialProvider",
    "InMemoryFormSubmissionProvider",
    "InMemorySessionProvider",
    "NullSessionProvider",
    "OriginScopedSession",
    "PrivateWorkspaceTarget",
    "ReasoningQuery",
    "ReasoningResult",
    "RefreshableCredentialProvider",
    "ResourceBudget",
    "ResultStatus",
    "SessionProvider",
    "extract_csrf_token",
]

__version__ = "0.3.0a0"
