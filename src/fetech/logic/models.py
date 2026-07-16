"""Typed contracts crossing the Python/logic-engine boundary."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel, ConfigDict, Field, StrictBool, StrictInt, model_validator

from fetech.models import FetchPlan


class LogicModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class BackendStatus(StrEnum):
    SUCCEEDED = "SUCCEEDED"
    FALLBACK = "FALLBACK"
    UNAVAILABLE = "UNAVAILABLE"
    FAILED = "FAILED"


class PlanProposal(LogicModel):
    backend: str
    status: BackendStatus
    plan: FetchPlan
    executable_version: str | None = None
    ruleset_sha256: str | None = None
    manifest_version: str | None = None
    manifest_sha256: str | None = None
    input_sha256: str | None = None
    result_sha256: str | None = None
    diagnostics: tuple[str, ...] = ()


class ReasoningQuery(LogicModel):
    query_type: str = "capability_eligibility"
    capability_id: str = Field(min_length=1, max_length=128)
    allowed: bool = True
    available: bool = True
    risk_class: str = Field(default="low", max_length=32)
    dependencies: tuple[str, ...] = Field(default=(), max_length=64)
    facts: dict[str, StrictBool | StrictInt] = Field(default_factory=dict)

    @model_validator(mode="after")
    def bound_facts(self) -> ReasoningQuery:
        if len(self.facts) > 32:
            raise ValueError("reasoning facts are limited to 32 entries")
        invalid = [key for key in self.facts if not key.isidentifier() or len(key) > 64]
        if invalid:
            raise ValueError(f"invalid reasoning fact keys: {sorted(invalid)}")
        return self


class ReasoningResult(LogicModel):
    backend: str
    status: BackendStatus
    capability_id: str
    conclusion: str
    eligible: bool
    reasons: tuple[str, ...] = ()
    executable_version: str | None = None
    ruleset_sha256: str | None = None
    input_sha256: str | None = None
    result_sha256: str | None = None
    diagnostics: tuple[str, ...] = ()
