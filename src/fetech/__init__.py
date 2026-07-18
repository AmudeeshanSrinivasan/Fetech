"""Fetech public Python API."""

from fetech.adapters.cache import ArchivedSnapshot, SnapshotConnector
from fetech.adapters.documents import (
    GitLFSResolvedObject,
    GitLFSResolver,
    GitLFSResolveRequest,
    PDFOCRPage,
    PDFOCRProvider,
)
from fetech.adapters.media import MediaAdapter, TranscriptProvider, YouTubeMetadataProvider
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
from fetech.wayback import WaybackSnapshotConnector

__all__ = [
    "ArchivedSnapshot",
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
    "GitLFSResolveRequest",
    "GitLFSResolvedObject",
    "GitLFSResolver",
    "InMemoryCredentialProvider",
    "InMemoryFormSubmissionProvider",
    "InMemorySessionProvider",
    "MediaAdapter",
    "NullSessionProvider",
    "OriginScopedSession",
    "PDFOCRPage",
    "PDFOCRProvider",
    "PrivateWorkspaceTarget",
    "ReasoningQuery",
    "ReasoningResult",
    "RefreshableCredentialProvider",
    "ResourceBudget",
    "ResultStatus",
    "SessionProvider",
    "SnapshotConnector",
    "TranscriptProvider",
    "WaybackSnapshotConnector",
    "YouTubeMetadataProvider",
    "extract_csrf_token",
]

__version__ = "0.3.0a0"
