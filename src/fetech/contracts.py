"""Deterministic discovery metadata for Fetech's public contracts."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from pydantic import BaseModel

from fetech.logic.models import ReasoningQuery, ReasoningResult
from fetech.models import (
    Artifact,
    CapabilityManifestEntry,
    ContextBundle,
    ContextProviderReport,
    ContextSource,
    ContextTokenUsage,
    ContractDescriptor,
    ContractManifest,
    FailureCatalogue,
    FailureCodeDescriptor,
    FetchAttempt,
    FetchPlan,
    FetchRequest,
    FetchResult,
    FetchRun,
    InspectionResult,
    PlanNode,
    ProvenanceEvent,
    PublicError,
    PublicErrorDescriptor,
    Resource,
    ResourceBudget,
    ResultStatusDescriptor,
    ValidationIssue,
)
from fetech.version import __version__

_PUBLIC_CONTRACTS: tuple[type[BaseModel], ...] = (
    Artifact,
    CapabilityManifestEntry,
    ContextBundle,
    ContextProviderReport,
    ContextSource,
    ContextTokenUsage,
    ContractManifest,
    FailureCatalogue,
    FailureCodeDescriptor,
    FetchAttempt,
    FetchPlan,
    FetchRequest,
    FetchResult,
    FetchRun,
    InspectionResult,
    PlanNode,
    ProvenanceEvent,
    PublicError,
    PublicErrorDescriptor,
    Resource,
    ResourceBudget,
    ResultStatusDescriptor,
    ReasoningQuery,
    ReasoningResult,
    ValidationIssue,
)


def _schema_digest(model: type[BaseModel]) -> str:
    document = model.model_json_schema(mode="serialization")
    encoded = json.dumps(
        document,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def contract_manifest() -> ContractManifest:
    """Return the canonical, deterministic public-contract inventory."""

    descriptors = tuple(
        ContractDescriptor(
            name=model.__name__,
            json_schema_sha256=_schema_digest(model),
        )
        for model in sorted(_PUBLIC_CONTRACTS, key=lambda candidate: candidate.__name__)
    )
    return ContractManifest(
        package_version=__version__,
        contracts=descriptors,
    )


def _public_contract_schemas() -> dict[str, dict[str, Any]]:
    """Return fresh canonical serialization schemas for every public model."""

    return {
        model.__name__: model.model_json_schema(mode="serialization")
        for model in sorted(_PUBLIC_CONTRACTS, key=lambda candidate: candidate.__name__)
    }
