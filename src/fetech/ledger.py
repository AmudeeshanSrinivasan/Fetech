"""Append-only SQL event ledger and run snapshots."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import UUID

from sqlalchemy import DateTime, Integer, String, Text, select
from sqlalchemy.ext.asyncio import AsyncEngine, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from fetech.models import FetchResult, ProvenanceEvent, RunState
from fetech.security import sanitize_authenticated_text, sanitize_url


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


class EventLedger:
    def __init__(self, database_url: str) -> None:
        self.engine: AsyncEngine = create_async_engine(database_url)
        self.sessions = async_sessionmaker(self.engine, expire_on_commit=False)
        self._subscribers: dict[UUID, set[asyncio.Queue[ProvenanceEvent | None]]] = {}
        self._authenticated_runs: set[UUID] = set()

    @classmethod
    def sqlite(cls, path: Path) -> EventLedger:
        path = path.expanduser().resolve()
        path.parent.mkdir(parents=True, exist_ok=True)
        return cls(f"sqlite+aiosqlite:///{path}")

    async def initialize(self) -> None:
        async with self.engine.begin() as connection:
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
        async with self.sessions() as session:
            session.add(
                RunRow(
                    run_id=str(run_id),
                    state=RunState.QUEUED.value,
                    submitted_at=submitted_at,
                    request_json=json.dumps(sanitized_request, sort_keys=True, default=str),
                )
            )
            await session.commit()
        if authenticated:
            self._authenticated_runs.add(run_id)

    async def update_run(self, run_id: UUID, state: RunState, result: FetchResult | None = None) -> None:
        async with self.sessions() as session:
            row = await session.get(RunRow, str(run_id))
            if row is None:
                raise KeyError(f"unknown run: {run_id}")
            row.state = state.value
            if result is not None:
                row.result_json = json.dumps(
                    _sanitize_payload(
                        result.model_dump(mode="json"),
                        authenticated=run_id in self._authenticated_runs,
                    ),
                    sort_keys=True,
                    default=str,
                )
            await session.commit()
        if state == RunState.FINISHED:
            for queue in self._subscribers.get(run_id, set()):
                queue.put_nowait(None)

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
        async with self.sessions() as session:
            session.add(
                EventRow(
                    event_id=str(event.event_id),
                    run_id=str(event.run_id),
                    event_type=event.event_type,
                    timestamp=event.timestamp,
                    actor=event.actor,
                    payload_json=json.dumps(payload, sort_keys=True, default=str),
                    parent_event_ids_json=json.dumps(
                        [str(identifier) for identifier in event.parent_event_ids]
                    ),
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

    async def stream(self, run_id: UUID) -> AsyncIterator[ProvenanceEvent]:
        for event in await self.events(run_id):
            yield event
        queue: asyncio.Queue[ProvenanceEvent | None] = asyncio.Queue()
        self._subscribers.setdefault(run_id, set()).add(queue)
        try:
            state, _, _ = await self.run_snapshot(run_id)
            if state == RunState.FINISHED:
                return
            while True:
                queued_event = await queue.get()
                if queued_event is None:
                    return
                yield queued_event
        finally:
            self._subscribers.get(run_id, set()).discard(queue)


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
