"""Shared v0.4 budget accounting across independent acquisition branches."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from fetech.adapters.cache import ArchivedSnapshot
from fetech.adapters.http import HTTPAdapter
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import FetchRequest, ResourceBudget, ResultStatus


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


@dataclass
class _LowQualityArchive:
    body: bytes
    maximums: list[int] = field(default_factory=list)

    async def fetch_snapshot(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        deadline_seconds: float,
    ) -> ArchivedSnapshot:
        del deadline_seconds
        self.maximums.append(maximum_bytes)
        return ArchivedSnapshot(
            original_url=original_url,
            snapshot_url=(
                "https://archive.example/snapshot/"
                "https://publisher.example/article"
            ),
            body=self.body,
            media_type="text/plain",
            captured_at=datetime(2026, 7, 17, tzinfo=UTC),
        )


@pytest.mark.asyncio
async def test_archive_and_http_share_one_cumulative_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    archived_body = b"Sign in with your password to continue to this archived page."
    http_body = b"Useful publisher response that cannot fit in the remaining budget."
    ceiling = len(archived_body) + len(http_body) - 1
    connector = _LowQualityArchive(archived_body)
    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        snapshot_connectors={"web_archive": connector},
    )

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    http_calls = 0

    async def respond(_: httpx.Request) -> httpx.Response:
        nonlocal http_calls
        http_calls += 1
        return httpx.Response(
            200,
            headers={
                "content-type": "text/plain",
                "content-length": str(len(http_body)),
            },
            content=http_body,
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://publisher.example/article",
            output_requirements=("web_archive",),
            budget=ResourceBudget(
                bytes=ceiling,
                decompressed_bytes=ceiling,
            ),
        )
    )

    assert result.status == ResultStatus.BUDGET_EXHAUSTED
    assert connector.maximums == [ceiling]
    assert http_calls == 1
    connector_attempt = next(
        attempt
        for attempt in result.attempts
        if attempt.capability_id == "web_archive"
    )
    assert connector_attempt.consumed_budget == {
        "bytes": len(archived_body),
        "decompressed_bytes": len(archived_body),
    }
    assert result.remaining_budget is not None
    assert result.remaining_budget.bytes == ceiling - len(archived_body)
    assert (
        result.remaining_budget.decompressed_bytes
        == ceiling - len(archived_body)
    )
    assert sum(
        int(attempt.consumed_budget.get("bytes", 0))
        for attempt in result.attempts
    ) <= ceiling
    await gateway.close()


@pytest.mark.asyncio
async def test_http_and_reader_share_one_cumulative_decompressed_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"Useful publisher text that the deterministic reader will normalize."
    ceiling = len(body) * 2 - 1
    gateway = UniversalFetchGateway(_settings(tmp_path))

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "text/plain",
                "content-length": str(len(body)),
            },
            content=body,
        )

    cas_writes: list[bytes] = []
    original_put = gateway.cas.put

    async def counted_put(value: bytes) -> tuple[str, str, int]:
        cas_writes.append(value)
        return await original_put(value)

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    monkeypatch.setattr(gateway.cas, "put", counted_put)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://publisher.example/article",
            output_requirements=("clean_text",),
            budget=ResourceBudget(
                bytes=ceiling,
                decompressed_bytes=ceiling,
            ),
        )
    )

    assert result.status == ResultStatus.BUDGET_EXHAUSTED
    assert "clean_text" not in {
        artifact.representation for artifact in result.artifacts
    }
    assert cas_writes.count(body) == 1
    reader_attempt = next(
        attempt
        for attempt in result.attempts
        if attempt.capability_id == "clean_text"
    )
    assert reader_attempt.failure_code == "budget_exhausted"
    assert result.remaining_budget is not None
    assert result.remaining_budget.decompressed_bytes == len(body) - 1
    await gateway.close()


@pytest.mark.asyncio
async def test_reader_records_derived_output_in_the_shared_decompressed_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    body = b"Useful publisher text with enough deterministic article content. " * 3
    ceiling = len(body) * 3
    gateway = UniversalFetchGateway(_settings(tmp_path))

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={
                "content-type": "text/plain",
                "content-length": str(len(body)),
            },
            content=body,
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://publisher.example/article",
            output_requirements=("clean_text",),
            budget=ResourceBudget(
                bytes=ceiling,
                decompressed_bytes=ceiling,
            ),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    reader_attempt = next(
        attempt
        for attempt in result.attempts
        if attempt.capability_id == "clean_text"
    )
    assert reader_attempt.consumed_budget == {
        "decompressed_bytes": len(body),
    }
    assert result.remaining_budget is not None
    assert result.remaining_budget.decompressed_bytes == ceiling - len(body) * 2
    await gateway.close()
