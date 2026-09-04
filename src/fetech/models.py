"""Versioned public contracts shared by every Fetech interface."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, model_validator

_MAX_TARGET_BYTES = 16_384
_MAX_REQUEST_TEXT_BYTES = 4_096
_MAX_CAPABILITY_IDS = 256
_MAX_METADATA_ENTRIES = 128
_MAX_METADATA_VALUE_BYTES = 65_536
_MAX_METADATA_TOTAL_BYTES = 1_000_000


def utc_now() -> datetime:
    return datetime.now(UTC)


class ContractModel(BaseModel):
    model_config = ConfigDict(extra="forbid", use_enum_values=False)


class CapabilityKind(StrEnum):
    OPERATION = "operation"
    TRANSPORT_FEATURE = "transport_feature"
    VARIANT_GENERATOR = "variant_generator"
    EXTRACTOR = "extractor"
    FORMAT_HANDLER = "format_handler"
    DETECTOR = "detector"
    POLICY = "policy"
    CONNECTOR = "connector"
    STORAGE_STRATEGY = "storage_strategy"


class ImplementationStatus(StrEnum):
    NATIVE = "native"
    OPTIONAL = "optional"
    PLANNED = "planned"


class ResultStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    PARTIAL = "PARTIAL"
    BLOCKED_BY_POLICY = "BLOCKED_BY_POLICY"
    AUTH_REQUIRED = "AUTH_REQUIRED"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    LOW_QUALITY = "LOW_QUALITY"
    NOT_FOUND = "NOT_FOUND"
    FAILED = "FAILED"


class AttemptStatus(StrEnum):
    PLANNED = "PLANNED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    SKIPPED = "SKIPPED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class CapabilityOutcomeStatus(StrEnum):
    """Observable per-run disposition of a registered capability."""

    APPLIED = "APPLIED"
    OBSERVED = "OBSERVED"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    BLOCKED = "BLOCKED"
    DEPENDENCY_MISSING = "DEPENDENCY_MISSING"
    FAILED = "FAILED"


class RunState(StrEnum):
    QUEUED = "QUEUED"
    PLANNING = "PLANNING"
    RUNNING = "RUNNING"
    FINISHED = "FINISHED"


class ContextNeed(StrEnum):
    """Deterministic context families selected by the context broker."""

    CODE_ARCHITECTURE = "code_architecture"
    RUNTIME_HISTORY = "runtime_history"
    DECISION_HISTORY = "decision_history"


class ContextProviderStatus(StrEnum):
    """Observable outcome from one bounded context provider."""

    SUCCEEDED = "SUCCEEDED"
    SKIPPED = "SKIPPED"
    EMPTY = "EMPTY"
    UNAVAILABLE = "UNAVAILABLE"
    TIMED_OUT = "TIMED_OUT"
    OUTPUT_LIMIT = "OUTPUT_LIMIT"
    FAILED = "FAILED"


class PageState(StrEnum):
    OK = "OK"
    EMPTY = "EMPTY"
    LOGIN = "LOGIN"
    CAPTCHA = "CAPTCHA"
    BOT_BLOCK = "BOT_BLOCK"
    PAYWALL = "PAYWALL"
    ERROR = "ERROR"
    WRONG_LANGUAGE = "WRONG_LANGUAGE"
    NEEDS_OCR = "NEEDS_OCR"
    UNKNOWN = "UNKNOWN"


class CapabilityManifestEntry(ContractModel):
    id: str
    aliases: tuple[str, ...] = ()
    category: str
    category_name: str
    closure_release: str
    kind: CapabilityKind
    adapter: str
    risk_class: str
    inputs: tuple[str, ...] = ("target",)
    outputs: tuple[str, ...] = ("attempt",)
    dependencies: tuple[str, ...] = ()
    reference: str
    tests: tuple[str, ...]
    lifecycle_status: str = "registered"
    implementation_status: ImplementationStatus = ImplementationStatus.PLANNED
    implementation: str
    implementation_available: bool = False
    runtime_available: bool = False
    availability_reason: str = ""


class ResourceBudget(ContractModel):
    deadline_seconds: float = Field(default=30.0, gt=0, le=3600)
    attempts: int = Field(default=6, ge=0, le=100)
    redirects: int = Field(default=8, ge=0, le=30)
    bytes: int = Field(default=10_000_000, ge=0, le=2_000_000_000)
    decompressed_bytes: int = Field(default=50_000_000, ge=0, le=4_000_000_000)
    crawl_pages: int = Field(default=20, ge=1, le=100_000)
    crawl_depth: int = Field(default=2, ge=0, le=20)
    browser_seconds: float = Field(default=20.0, ge=0, le=1800)
    archive_members: int = Field(default=1_000, ge=1, le=1_000_000)
    archive_ratio: float = Field(default=100.0, ge=1, le=100_000)
    model_tokens: int = Field(default=0, ge=0, le=1_000_000)
    monetary_ceiling: float = Field(default=0.0, ge=0)


class FetchRequest(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    target: str = Field(min_length=1, max_length=_MAX_TARGET_BYTES)
    intent: str = Field(default="retrieve", min_length=1, max_length=256)
    output_requirements: tuple[str, ...] = Field(
        default=("clean_text",),
        max_length=_MAX_CAPABILITY_IDS,
    )
    authentication_ref: str | None = Field(default=None, min_length=1, max_length=2_048, repr=False)
    privacy_profile: Literal["public", "private"] = Field(
        default="public",
        description=(
            "Use 'public' for ordinary acquisition and 'private' for explicitly "
            "authorized private-workspace execution."
        ),
    )
    policy_profile: str = Field(default="default", min_length=1, max_length=256)
    freshness_seconds: int | None = Field(default=None, ge=0)
    language: str | None = Field(default=None, max_length=128)
    region: str | None = Field(default=None, max_length=128)
    allow_capabilities: frozenset[str] = Field(default=frozenset(), max_length=_MAX_CAPABILITY_IDS)
    deny_capabilities: frozenset[str] = Field(default=frozenset(), max_length=_MAX_CAPABILITY_IDS)
    approved_capabilities: frozenset[str] = Field(default=frozenset(), max_length=_MAX_CAPABILITY_IDS)
    budget: ResourceBudget = Field(default_factory=ResourceBudget)
    metadata: dict[str, str] = Field(
        default_factory=dict,
        max_length=_MAX_METADATA_ENTRIES,
    )

    @model_validator(mode="after")
    def capability_lists_do_not_overlap(self) -> FetchRequest:
        overlap = self.allow_capabilities & self.deny_capabilities
        if overlap:
            raise ValueError(f"capabilities cannot be both allowed and denied: {sorted(overlap)}")
        denied_approvals = self.approved_capabilities & self.deny_capabilities
        if denied_approvals:
            raise ValueError(
                "capabilities cannot be both approved and denied: "
                f"{sorted(denied_approvals)}"
            )
        if self.budget.attempts == 0:
            raise ValueError("request budget must allow at least one attempt")
        if self.budget.bytes == 0 or self.budget.decompressed_bytes == 0:
            raise ValueError("request byte budgets must be greater than zero")
        if self.authentication_ref is not None and not self.authentication_ref.strip():
            raise ValueError("authentication_ref cannot be blank")
        if (
            self.authentication_ref is not None
            and len(self.authentication_ref.encode("utf-8")) > 2_048
        ):
            raise ValueError("authentication_ref exceeds the bounded byte limit")
        _require_bounded_text(self.target, "target", _MAX_TARGET_BYTES)
        for label, value in (
            ("intent", self.intent),
            ("policy_profile", self.policy_profile),
            ("language", self.language),
            ("region", self.region),
        ):
            if value is not None:
                _require_bounded_text(value, label, _MAX_REQUEST_TEXT_BYTES)
        for label, values in (
            ("output_requirements", self.output_requirements),
            ("allow_capabilities", self.allow_capabilities),
            ("deny_capabilities", self.deny_capabilities),
            ("approved_capabilities", self.approved_capabilities),
        ):
            for value in values:
                _require_bounded_text(value, label, 256)
        metadata_bytes = 0
        for key, value in self.metadata.items():
            _require_bounded_text(key, "metadata key", 256)
            _require_bounded_text(value, "metadata value", _MAX_METADATA_VALUE_BYTES)
            metadata_bytes += len(key.encode("utf-8")) + len(value.encode("utf-8"))
        if metadata_bytes > _MAX_METADATA_TOTAL_BYTES:
            raise ValueError("metadata exceeds the bounded aggregate byte limit")
        return self


def _require_bounded_text(value: str, label: str, maximum_bytes: int) -> None:
    if len(value) > maximum_bytes or len(value.encode("utf-8")) > maximum_bytes:
        raise ValueError(f"{label} exceeds the bounded byte limit")
    if not value.strip():
        raise ValueError(f"{label} cannot be blank")


class RetryRule(ContractModel):
    maximum: int = Field(default=1, ge=0, le=10)
    backoff_seconds: float = Field(default=0.25, ge=0, le=60)
    retryable_codes: tuple[str, ...] = ("timeout", "connection", "429", "5xx")


class PlanNode(ContractModel):
    id: str
    capability_id: str
    adapter: str
    dependencies: tuple[str, ...] = ()
    parallel_group: str | None = None
    retry: RetryRule = Field(default_factory=RetryRule)
    fallback_for: str | None = None
    stop_on_acceptance: bool = False
    requires_approval: bool = False
    reserved_budget: dict[str, int | float] = Field(default_factory=dict)
    parameters: dict[str, Any] = Field(default_factory=dict)


class FetchPlan(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    plan_id: UUID = Field(default_factory=uuid4)
    request: FetchRequest
    nodes: tuple[PlanNode, ...]
    created_at: datetime = Field(default_factory=utc_now)
    deterministic: bool = True
    classifier: str = "rules-v1"
    warnings: tuple[str, ...] = ()
    _execution_request: FetchRequest | None = PrivateAttr(default=None)

    @property
    def execution_request(self) -> FetchRequest:
        """Return the non-persisted request used by adapters.

        Authenticated serialized plans intentionally cannot be replayed because
        their query values have been redacted. They must be rebound from a new
        in-memory request before execution.
        """

        if self._execution_request is not None:
            return self._execution_request
        if self.request.authentication_ref is not None:
            raise ValueError(
                "authenticated plan has no in-memory execution request; "
                "resubmit the original FetchRequest"
            )
        return self.request

    def bind_execution_request(self, request: FetchRequest) -> FetchPlan:
        """Bind raw transport input without adding it to model serialization."""

        from fetech.security import normalize_url, sanitize_url_for_request

        normalized = request.model_copy(
            update={"target": normalize_url(request.target)}
        )
        public_request = normalized.model_copy(
            update={
                "target": sanitize_url_for_request(
                    normalized.target,
                    normalized,
                )
            }
        )
        if public_request != self.request:
            raise ValueError(
                "execution request does not match the serialized fetch plan"
            )
        self._execution_request = normalized
        return self


class FetchAttempt(ContractModel):
    attempt_id: UUID = Field(default_factory=uuid4)
    capability_id: str
    adapter_version: str = "0.3.0a0"
    started_at: datetime = Field(default_factory=utc_now)
    finished_at: datetime | None = None
    sanitized_destination: str
    status: AttemptStatus = AttemptStatus.PLANNED
    http_status: int | None = None
    bytes_received: int = 0
    parser: str | None = None
    artifact_ids: tuple[UUID, ...] = ()
    failure_code: str | None = None
    warnings: tuple[str, ...] = ()
    consumed_budget: dict[str, int | float] = Field(default_factory=dict)


class Resource(ContractModel):
    resource_id: UUID = Field(default_factory=uuid4)
    canonical_url: str
    requested_url: str
    media_type: str | None = None
    status_code: int | None = None
    retrieved_at: datetime = Field(default_factory=utc_now)
    authority_url: str | None = None
    checked_only: bool = False


class QualityAssessment(ContractModel):
    page_state: PageState = PageState.UNKNOWN
    score: float = Field(default=0.0, ge=0.0, le=1.0)
    accepted: bool = False
    language: str | None = None
    completeness: float = Field(default=0.0, ge=0.0, le=1.0)
    duplicate_of: UUID | None = None
    reasons: tuple[str, ...] = ()


class Artifact(ContractModel):
    artifact_id: UUID = Field(default_factory=uuid4)
    role: str
    representation: str
    media_type: str
    schema_version: Literal["1.0"] = "1.0"
    cas_uri: str
    sha256: str
    size: int = Field(ge=0)
    source_resource_id: UUID
    parent_artifact_ids: tuple[UUID, ...] = ()
    extractor_version: str
    locators: tuple[str, ...] = ()
    quality: QualityAssessment = Field(default_factory=QualityAssessment)


class PolicyDecision(ContractModel):
    policy_id: str
    allowed: bool
    reason: str
    destination: str | None = None
    evaluated_at: datetime = Field(default_factory=utc_now)


class CapabilityOutcome(ContractModel):
    capability_id: str
    status: CapabilityOutcomeStatus
    stage: str
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)
    observed_at: datetime = Field(default_factory=utc_now)


class Diagnostic(ContractModel):
    code: str
    message: str
    retryable: bool = False
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class DiscoveredTarget(ContractModel):
    url: str
    depth: int = Field(ge=0)
    parent_url: str | None = None
    relation: str
    fetched: bool = False
    accepted: bool = False
    failure_code: str | None = None


class CrawlReport(ContractModel):
    root_url: str
    targets: tuple[DiscoveredTarget, ...]
    pages_fetched: int = Field(ge=0)
    pages_failed: int = Field(ge=0)
    maximum_depth_reached: int = Field(ge=0)
    frontier_omitted: int = Field(ge=0)


class FetchResult(ContractModel):
    schema_version: Literal["1.0"] = "1.0"
    run_id: UUID = Field(default_factory=uuid4)
    status: ResultStatus
    resources: tuple[Resource, ...] = ()
    artifacts: tuple[Artifact, ...] = ()
    attempts: tuple[FetchAttempt, ...] = ()
    capability_outcomes: tuple[CapabilityOutcome, ...] = ()
    policy_decisions: tuple[PolicyDecision, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    provenance_event_ids: tuple[UUID, ...] = ()
    remaining_budget: ResourceBudget = Field(default_factory=ResourceBudget)
    crawl_report: CrawlReport | None = None


class ProvenanceEvent(ContractModel):
    event_id: UUID = Field(default_factory=uuid4)
    run_id: UUID
    event_type: str
    timestamp: datetime = Field(default_factory=utc_now)
    actor: str
    payload: dict[str, Any] = Field(default_factory=dict)
    parent_event_ids: tuple[UUID, ...] = ()


class FetchRun(ContractModel):
    run_id: UUID
    state: RunState
    submitted_at: datetime
    result: FetchResult | None = None


class InspectionResult(ContractModel):
    normalized_target: str
    family: str
    media_type_hint: str | None = None
    policy_decisions: tuple[PolicyDecision, ...] = ()
    suggested_capabilities: tuple[str, ...] = ()


class ContextSource(ContractModel):
    source_type: str
    title: str
    locator: str
    excerpt: str
    score: float = Field(default=0.0, ge=0.0)
    freshness: datetime | None = None
    provenance: tuple[str, ...] = ()
    content_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_locations: tuple[str, ...] = ()
    graph_nodes: tuple[str, ...] = ()
    graph_paths: tuple[str, ...] = ()
    verified: bool = False


class ContextProviderReport(ContractModel):
    """Typed retrieval result without leaking provider stderr or prompt content."""

    provider: Literal["code_graph", "runtime_graph", "qmd", "exact_source"]
    status: ContextProviderStatus
    attempts: int = Field(default=0, ge=0, le=2)
    result_count: int = Field(default=0, ge=0)
    detail: str | None = Field(default=None, max_length=256)


class ContextTokenUsage(ContractModel):
    """Estimated excerpt tokens selected from each context plane."""

    code_graph: int = Field(default=0, ge=0)
    runtime_graph: int = Field(default=0, ge=0)
    qmd: int = Field(default=0, ge=0)
    exact_source: int = Field(default=0, ge=0)
    total: int = Field(default=0, ge=0)


class ContextBundle(ContractModel):
    question: str
    sources: tuple[ContextSource, ...]
    needs: tuple[ContextNeed, ...] = ()
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    contradictions: tuple[str, ...] = ()
    omitted_results: int = 0
    token_budget: int = 4_000
    estimated_tokens: int = 0
    fallback_reason: str | None = None
    provider_reports: tuple[ContextProviderReport, ...] = ()
    token_usage: ContextTokenUsage = Field(default_factory=ContextTokenUsage)
    freshness: datetime | None = None


class ContractDescriptor(ContractModel):
    """Stable identity for one public JSON contract."""

    name: str
    schema_version: Literal["1.0"] = "1.0"
    json_schema_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class ContractManifest(ContractModel):
    """Machine-readable contract inventory shared by every public interface."""

    schema_version: Literal["1.0"] = "1.0"
    api_version: Literal["v1"] = "v1"
    package_version: str
    contracts: tuple[ContractDescriptor, ...]
