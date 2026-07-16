"""Adapter protocol and execution context."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Protocol
from uuid import UUID

from fetech.models import Artifact, Diagnostic, FetchAttempt, FetchRequest, PlanNode, PolicyDecision, Resource
from fetech.storage import FileSystemCAS


@dataclass
class ExecutionContext:
    run_id: UUID
    request: FetchRequest
    cas: FileSystemCAS
    resources: list[Resource] = field(default_factory=list)
    artifacts: list[Artifact] = field(default_factory=list)
    attempts: list[FetchAttempt] = field(default_factory=list)
    policy_decisions: list[PolicyDecision] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    accepted: bool = False

    def latest_artifact(self, *representations: str) -> Artifact | None:
        allowed = set(representations)
        for artifact in reversed(self.artifacts):
            if not allowed or artifact.representation in allowed:
                return artifact
        return None


class Adapter(Protocol):
    async def execute(self, node: PlanNode, context: ExecutionContext) -> None: ...


class AdapterDependencyError(RuntimeError):
    pass


class AdapterExecutionError(RuntimeError):
    pass
