"""Versioned public contracts shared by every Fetech interface."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator


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


class RunState(StrEnum):
    QUEUED = "QUEUED"
    PLANNING = "PLANNING"
    RUNNING = "RUNNING"
    FINISHED = "FINISHED"


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
    available: bool = True


class ResourceBudget(ContractModel):
    deadline_seconds: float = Field(default=30.0, gt=0, le=3600)
    attempts: int = Field(default=6, ge=1, le=100)
    redirects: int = Field(default=8, ge=0, le=30)
    bytes: int = Field(default=10_000_000, ge=1, le=2_000_000_000)
    decompressed_bytes: int = Field(default=50_000_000, ge=1, le=4_000_000_000)
    crawl_pages: int = Field(default=20, ge=1, le=100_000)
    crawl_depth: int = Field(default=2, ge=0, le=20)
    browser_seconds: float = Field(default=20.0, ge=0, le=1800)
    archive_members: int = Field(default=1_000, ge=1, le=1_000_000)
    archive_ratio: float = Field(default=100.0, ge=1, le=100_000)
    model_tokens: int = Field(default=0, ge=0, le=1_000_000)
    monetary_ceiling: float = Field(default=0.0, ge=0)


class FetchRequest(ContractModel):
    schema_version: str = "1.0"
    target: str
    intent: str = "retrieve"
    output_requirements: tuple[str, ...] = ("clean_text",)
    authentication_ref: str | None = None
    privacy_profile: str = "public"
    policy_profile: str = "default"
    freshness_seconds: int | None = Field(default=None, ge=0)
    language: str | None = None
    region: str | None = None
    allow_capabilities: frozenset[str] = frozenset()
    deny_capabilities: frozenset[str] = frozenset()
    budget: ResourceBudget = Field(default_factory=ResourceBudget)
    metadata: dict[str, str] = Field(default_factory=dict)

    @model_validator(mode="after")
    def capability_lists_do_not_overlap(self) -> FetchRequest:
        overlap = self.allow_capabilities & self.deny_capabilities
        if overlap:
            raise ValueError(f"capabilities cannot be both allowed and denied: {sorted(overlap)}")
        return self


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
    schema_version: str = "1.0"
    plan_id: UUID = Field(default_factory=uuid4)
    request: FetchRequest
    nodes: tuple[PlanNode, ...]
    created_at: datetime = Field(default_factory=utc_now)
    deterministic: bool = True
    classifier: str = "rules-v1"
    warnings: tuple[str, ...] = ()


class FetchAttempt(ContractModel):
    attempt_id: UUID = Field(default_factory=uuid4)
    capability_id: str
    adapter_version: str = "0.1.0"
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
    schema_version: str = "1.0"
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


class Diagnostic(ContractModel):
    code: str
    message: str
    retryable: bool = False
    details: dict[str, str | int | float | bool | None] = Field(default_factory=dict)


class FetchResult(ContractModel):
    schema_version: str = "1.0"
    run_id: UUID = Field(default_factory=uuid4)
    status: ResultStatus
    resources: tuple[Resource, ...] = ()
    artifacts: tuple[Artifact, ...] = ()
    attempts: tuple[FetchAttempt, ...] = ()
    policy_decisions: tuple[PolicyDecision, ...] = ()
    diagnostics: tuple[Diagnostic, ...] = ()
    provenance_event_ids: tuple[UUID, ...] = ()
    remaining_budget: ResourceBudget = Field(default_factory=ResourceBudget)


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


class ContextBundle(ContractModel):
    question: str
    sources: tuple[ContextSource, ...]
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    contradictions: tuple[str, ...] = ()
    omitted_results: int = 0
    token_budget: int = 4_000
    estimated_tokens: int = 0
    fallback_reason: str | None = None
