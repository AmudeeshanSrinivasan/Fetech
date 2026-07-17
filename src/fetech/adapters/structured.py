"""Fail-closed adapter for capabilities that require an optional runtime extra."""

from __future__ import annotations

from datetime import UTC, datetime

from fetech.adapters.base import AdapterDependencyError, ExecutionContext
from fetech.models import AttemptStatus, FetchAttempt, PlanNode
from fetech.security import sanitize_url


class OptionalAdapter:
    def __init__(self, feature: str, extra: str) -> None:
        self.feature = feature
        self.extra = extra

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.FAILED,
            finished_at=datetime.now(UTC),
            failure_code="dependency_missing",
            warnings=(f"install fetech[{self.extra}] to enable {self.feature}",),
        )
        context.attempts.append(attempt)
        raise AdapterDependencyError(attempt.warnings[0])
