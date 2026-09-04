"""Append-only SQL event ledger and run snapshots."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID

from sqlalchemy import DateTime, Integer, String, Text, delete, func, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fetech.models import Artifact, FetchResult, ProvenanceEvent, RunState
from fetech.security import sanitize_authenticated_text, sanitize_url
from fetech.storage import StorageQuota

_LEDGER_WRITE_OVERHEAD = 64 * 1024


class Base(DeclarativeBase):
    pass


class EventRow(Base):
    __tablename__ = "provenance_events"

    sequence: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    event_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False, index=True)
    run_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    actor: Mapped[str] = mapped_column(String(200), nullable=False)
    payload_json: Mapped[str] = mapped_column(Text, nullable=False)
    parent_event_ids_json: Mapped[str] = mapped_column(Text, nullable=False)


class RunRow(Base):
    __tablename__ = "fetch_runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    state: Mapped[str] = mapped_column(String(30), nullable=False)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    request_json: Mapped[str] = mapped_column(Text, nullable=False)
    result_json: Mapped[str | None] = mapped_column(Text)


class RetiredRunRow(Base):
    __tablename__ = "retired_fetch_runs"

    run_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    submitted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    retired_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    result_sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    event_count: Mapped[int] = mapped_column(Integer, nullable=False)
    artifact_count: Mapped[int] = mapped_column(Integer, nullable=False)


@dataclass(frozen=True, slots=True)
class LedgerRetentionReport:
    runs_retired: int = 0
    events_retired: int = 0
    artifact_references_retired: int = 0


class EventLedger:
    def __init__(self, database_url: str, *, quota: StorageQuota | None = None) -> None:
        self.engine: AsyncEngine = create_async_engine(database_url)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self.quota = quota
        self._subscribers: dict[UUID, set[asyncio.Queue[ProvenanceEvent | None]]] = {}
        self._authenticated_runs: set[UUID] = set()

    @classmethod
    def sqlite(cls, path: Path, *, quota: StorageQuota | None = None) -> EventLedger:
        path = path.expanduser().resolve()
        if quota is not None and path != quota.root and quota.root not in path.parents:
            raise ValueError("ledger path must be contained by the quota root")
        path.parent.mkdir(parents=True, exist_ok=True)
        return cls(f"sqlite+aiosqlite:///{path}", quota=quota)

    async def initialize(self) -> None:
        if self.quota is None:
            async with self.engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
        else:
            async with self.quota.exclusive_maintenance(), self.engine.begin() as connection:
                await connection.run_sync(Base.metadata.create_all)
        async with self.sessions() as session:
            rows = (await session.scalars(select(RunRow))).all()
        for row in rows:
            try:
                request = json.loads(row.request_json)
            except (json.JSONDecodeError, TypeError):
                continue
            if request.get("authentication_ref") is not None:
                self._authenticated_runs.add(UUID(row.run_id))

    async def close(self) -> None:
        await self.engine.dispose()
        self._authenticated_runs.clear()

    async def create_run(
        self, run_id: UUID, request_document: dict[str, Any], submitted_at: datetime
    ) -> None:
        authenticated = request_document.get("authentication_ref") is not None
        sanitized_request = _sanitize_payload(
            request_document,
            authenticated=authenticated,
        )
        request_json = json.dumps(sanitized_request, sort_keys=True, default=str)
        async with _ledger_reservation(self.quota, len(request_json)), self.sessions() as session:
            if await session.get(RetiredRunRow, str(run_id)) is not None:
                raise ValueError("retired run identifiers cannot be reused")
            session.add(
                RunRow(
                    run_id=str(run_id),
                    state=RunState.QUEUED.value,
                    submitted_at=submitted_at,
                    request_json=request_json,
                )
            )
            await session.commit()
        if authenticated:
            self._authenticated_runs.add(run_id)

    async def update_run(self, run_id: UUID, state: RunState, result: FetchResult | None = None) -> None:
        result_json = (
            json.dumps(
                _sanitize_payload(
                    result.model_dump(mode="json"),
                    authenticated=run_id in self._authenticated_runs,
                )
                if result is not None
                else None,
                sort_keys=True,
                default=str,
            )
            if result is not None
            else None
        )
        async with _ledger_reservation(
            self.quota,
            len(result_json or ""),
        ), self.sessions() as session:
            row = await session.get(RunRow, str(run_id))
            if row is None:
                raise KeyError(f"unknown run: {run_id}")
            row.state = state.value
            if result_json is not None:
                row.result_json = result_json
            await session.commit()
        if state == RunState.FINISHED:
            for queue in self._subscribers.get(run_id, set()):
                queue.put_nowait(None)

    async def finish_run(
        self,
        event: ProvenanceEvent,
        result: FetchResult,
    ) -> bool:
        """Atomically persist one terminal event and result; the first finalizer wins."""

        if event.run_id != result.run_id:
            raise ValueError("terminal event and result must identify the same run")
        run_id = event.run_id
        authenticated = run_id in self._authenticated_runs
        payload = _sanitize_payload(event.payload, authenticated=authenticated)
        sanitized_event = event.model_copy(update={"payload": payload})
        result_json = json.dumps(
            _sanitize_payload(
                result.model_dump(mode="json"),
                authenticated=authenticated,
            ),
            sort_keys=True,
            default=str,
        )
        event_json = json.dumps(payload, sort_keys=True, default=str)
        parent_json = json.dumps([str(identifier) for identifier in event.parent_event_ids])
        reservation = len(result_json) + len(event_json) + len(parent_json)
        async with _ledger_reservation(self.quota, reservation), self.sessions() as session:
            outcome = cast(
                CursorResult[Any],
                await session.execute(
                    update(RunRow)
                    .where(
                        RunRow.run_id == str(run_id),
                        RunRow.state != RunState.FINISHED.value,
                    )
                    .values(
                        state=RunState.FINISHED.value,
                        result_json=result_json,
                    )
                )
            )
            if outcome.rowcount != 1:
                await session.rollback()
                if await session.get(RunRow, str(run_id)) is None:
                    raise KeyError(f"unknown run: {run_id}")
                return False
            session.add(
                EventRow(
                    event_id=str(event.event_id),
                    run_id=str(run_id),
                    event_type=event.event_type,
                    timestamp=event.timestamp,
                    actor=event.actor,
                    payload_json=event_json,
                    parent_event_ids_json=parent_json,
                )
            )
            await session.commit()
        for queue in self._subscribers.get(run_id, set()):
            queue.put_nowait(sanitized_event)
            queue.put_nowait(None)
        return True

    async def request_document(self, run_id: UUID) -> dict[str, Any]:
        """Return the sanitized request metadata retained for lifecycle recovery."""

        async with self.sessions() as session:
            row = await session.get(RunRow, str(run_id))
            if row is None:
                raise KeyError(f"unknown run: {run_id}")
            try:
                document = json.loads(row.request_json)
            except (json.JSONDecodeError, TypeError) as exc:
                raise ValueError(f"run {run_id} has malformed request metadata") from exc
        if not isinstance(document, dict):
            raise ValueError(f"run {run_id} has malformed request metadata")
        return document

    async def run_snapshot(self, run_id: UUID) -> tuple[RunState, datetime, FetchResult | None]:
        async with self.sessions() as session:
            row = await session.get(RunRow, str(run_id))
            if row is None:
                raise KeyError(f"unknown run: {run_id}")
            result = FetchResult.model_validate_json(row.result_json) if row.result_json else None
            return RunState(row.state), row.submitted_at, result

    async def append(self, event: ProvenanceEvent) -> None:
        payload = _sanitize_payload(
            event.payload,
            authenticated=event.run_id in self._authenticated_runs,
        )
        event_json = json.dumps(payload, sort_keys=True, default=str)
        parent_json = json.dumps([str(identifier) for identifier in event.parent_event_ids])
        async with _ledger_reservation(
            self.quota,
            len(event_json) + len(parent_json),
        ), self.sessions() as session:
            session.add(
                EventRow(
                    event_id=str(event.event_id),
                    run_id=str(event.run_id),
                    event_type=event.event_type,
                    timestamp=event.timestamp,
                    actor=event.actor,
                    payload_json=event_json,
                    parent_event_ids_json=parent_json,
                )
            )
            await session.commit()
        for queue in self._subscribers.get(event.run_id, set()):
            queue.put_nowait(event.model_copy(update={"payload": payload}))

    async def events(self, run_id: UUID) -> tuple[ProvenanceEvent, ...]:
        async with self.sessions() as session:
            rows = (
                await session.scalars(
                    select(EventRow).where(EventRow.run_id == str(run_id)).order_by(EventRow.sequence)
                )
            ).all()
        return tuple(_event_from_row(row) for row in rows)

    async def all_events(self) -> tuple[ProvenanceEvent, ...]:
        async with self.sessions() as session:
            rows = (await session.scalars(select(EventRow).order_by(EventRow.sequence))).all()
        return tuple(_event_from_row(row) for row in rows)

    async def unfinished_runs(
        self,
    ) -> tuple[tuple[UUID, RunState, datetime, dict[str, Any]], ...]:
        """Return durable non-terminal runs for deterministic startup recovery."""

        async with self.sessions() as session:
            rows = (
                await session.scalars(select(RunRow).where(RunRow.state != RunState.FINISHED.value))
            ).all()
        recovered: list[tuple[UUID, RunState, datetime, dict[str, Any]]] = []
        for row in rows:
            try:
                request_document = json.loads(row.request_json)
            except (json.JSONDecodeError, TypeError) as exc:
                raise ValueError(f"run {row.run_id} has malformed request metadata") from exc
            if not isinstance(request_document, dict):
                raise ValueError(f"run {row.run_id} has malformed request metadata")
            recovered.append(
                (
                    UUID(row.run_id),
                    RunState(row.state),
                    row.submitted_at,
                    request_document,
                )
            )
        return tuple(recovered)

    async def artifacts(self) -> tuple[Artifact, ...]:
        """Rebuild the artifact metadata projection from authoritative results."""

        async with self.sessions() as session:
            result_documents = (
                await session.scalars(select(RunRow.result_json).where(RunRow.result_json.is_not(None)))
            ).all()
        artifacts: dict[UUID, Artifact] = {}
        for document in result_documents:
            if document is None:
                continue
            result = FetchResult.model_validate_json(document)
            for artifact in result.artifacts:
                previous = artifacts.get(artifact.artifact_id)
                if previous is not None and previous != artifact:
                    raise ValueError(f"artifact {artifact.artifact_id} has conflicting ledger metadata")
                artifacts[artifact.artifact_id] = artifact
        return tuple(artifacts.values())

    async def retire_finished_runs(
        self,
        *,
        before: datetime,
        maximum_runs: int,
        retired_at: datetime | None = None,
    ) -> LedgerRetentionReport:
        """Apply explicit retention and leave immutable bounded tombstones."""

        if before.utcoffset() is None:
            raise ValueError("ledger retention cutoff must include a timezone")
        if not 1 <= maximum_runs <= 10_000:
            raise ValueError("ledger retention run bound is invalid")
        retired = retired_at or datetime.now(UTC)
        if retired.utcoffset() is None:
            raise ValueError("ledger retirement time must include a timezone")
        maintenance = (
            self.quota.exclusive_maintenance()
            if self.quota is not None
            else _ledger_reservation(None, 0)
        )
        async with maintenance, self.sessions() as session:
            rows = (
                await session.scalars(
                    select(RunRow)
                    .where(
                        RunRow.state == RunState.FINISHED.value,
                        RunRow.submitted_at <= before,
                    )
                    .order_by(RunRow.submitted_at, RunRow.run_id)
                    .limit(maximum_runs)
                )
            ).all()
            event_total = 0
            artifact_total = 0
            for row in rows:
                if await session.get(RetiredRunRow, row.run_id) is not None:
                    raise ValueError("ledger contains a live run with a retired identity")
                result_document = row.result_json or ""
                artifact_count = 0
                if result_document:
                    artifact_count = len(
                        FetchResult.model_validate_json(result_document).artifacts
                    )
                event_count = int(
                    await session.scalar(
                        select(func.count())
                        .select_from(EventRow)
                        .where(EventRow.run_id == row.run_id)
                    )
                    or 0
                )
                session.add(
                    RetiredRunRow(
                        run_id=row.run_id,
                        submitted_at=row.submitted_at,
                        retired_at=retired.astimezone(UTC),
                        result_sha256=hashlib.sha256(
                            result_document.encode("utf-8")
                        ).hexdigest(),
                        event_count=event_count,
                        artifact_count=artifact_count,
                    )
                )
                await session.execute(
                    delete(EventRow).where(EventRow.run_id == row.run_id)
                )
                await session.delete(row)
                event_total += event_count
                artifact_total += artifact_count
            await session.commit()
        for row in rows:
            self._authenticated_runs.discard(UUID(row.run_id))
        return LedgerRetentionReport(
            runs_retired=len(rows),
            events_retired=event_total,
            artifact_references_retired=artifact_total,
        )

    async def retired_run_exists(self, run_id: UUID) -> bool:
        async with self.sessions() as session:
            return await session.get(RetiredRunRow, str(run_id)) is not None

    async def stream(self, run_id: UUID) -> AsyncIterator[ProvenanceEvent]:
        queue: asyncio.Queue[ProvenanceEvent | None] = asyncio.Queue()
        self._subscribers.setdefault(run_id, set()).add(queue)
        try:
            seen: set[UUID] = set()
            for event in await self.events(run_id):
                seen.add(event.event_id)
                yield event
            state, _, _ = await self.run_snapshot(run_id)
            if state == RunState.FINISHED:
                while not queue.empty():
                    queued_event = queue.get_nowait()
                    if queued_event is None:
                        break
                    if queued_event.event_id not in seen:
                        seen.add(queued_event.event_id)
                        yield queued_event
                return
            while True:
                queued_event = await queue.get()
                if queued_event is None:
                    return
                if queued_event.event_id not in seen:
                    seen.add(queued_event.event_id)
                    yield queued_event
        finally:
            subscribers = self._subscribers.get(run_id)
            if subscribers is not None:
                subscribers.discard(queue)
                if not subscribers:
                    self._subscribers.pop(run_id, None)


def _event_from_row(row: EventRow) -> ProvenanceEvent:
    return ProvenanceEvent(
        event_id=UUID(row.event_id),
        run_id=UUID(row.run_id),
        event_type=row.event_type,
        timestamp=row.timestamp,
        actor=row.actor,
        payload=json.loads(row.payload_json),
        parent_event_ids=tuple(UUID(value) for value in json.loads(row.parent_event_ids_json)),
    )


@asynccontextmanager
async def _ledger_reservation(
    quota: StorageQuota | None,
    payload_bytes: int,
) -> AsyncIterator[None]:
    if quota is None:
        yield
        return
    async with quota.reserve(
        payload_bytes + _LEDGER_WRITE_OVERHEAD,
        use_ledger_headroom=True,
    ):
        yield


def _sanitize_payload(
    value: Any,
    *,
    key: str = "",
    authenticated: bool = False,
) -> Any:
    lowered_key = key.lower()
    normalized_key = lowered_key.replace("-", "_").replace(" ", "_")
    compact_key = normalized_key.replace("_", "")
    safe_token_metric = normalized_key in {
        "estimated_tokens",
        "graphify_tokens",
        "input_tokens",
        "model_tokens",
        "output_tokens",
        "qmd_tokens",
        "source_tokens",
        "token_budget",
        "token_limit",
        "token_usage",
        "tokens_used",
        "total_tokens",
    }
    auth_component = (
        normalized_key == "auth"
        or normalized_key.startswith("auth_")
        or normalized_key.endswith("_auth")
        or "_auth_" in normalized_key
    )
    if (
        normalized_key == "body"
        or auth_component
        or (not safe_token_metric and any(
                fragment in compact_key
                for fragment in (
                    "authentication",
                    "authorization",
                    "credential",
                    "apikey",
                    "token",
                    "cookie",
                    "password",
                    "secret",
                )
        ))
    ):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            str(child_key): _sanitize_payload(
                child,
                key=str(child_key),
                authenticated=authenticated,
            )
            for child_key, child in value.items()
        }
    if isinstance(value, list | tuple):
        return [
            _sanitize_payload(
                child,
                key=key,
                authenticated=authenticated,
            )
            for child in value
        ]
    if isinstance(value, str) and key.lower() in {
        "authority_url",
        "candidate",
        "canonical_url",
        "destination",
        "normalized_target",
        "parent_url",
        "requested_url",
        "root_url",
        "source_url",
        "target",
        "url",
    }:
        try:
            return sanitize_url(value, redact_query=authenticated)
        except ValueError:
            return "[REDACTED_INVALID_URL]"
    if isinstance(value, str) and authenticated:
        return sanitize_authenticated_text(value)
    return value
