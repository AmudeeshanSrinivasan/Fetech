"""Focused provenance coverage for validated-cache freshness checks."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.adapters.cache import CacheAdapter, CacheDisposition, SnapshotStore
from fetech.executor import ExecutionEngine
from fetech.ledger import EventLedger
from fetech.models import (
    CapabilityOutcomeStatus,
    FetchPlan,
    FetchRequest,
    PageState,
    PlanNode,
    QualityAssessment,
    Resource,
    RetryRule,
)
from fetech.storage import CacheKey, FileSystemCAS, build_artifact


async def _seed_snapshot(
    store: SnapshotStore,
    request: FetchRequest,
    cas: FileSystemCAS,
    *,
    expires_at: datetime,
) -> None:
    resource = Resource(
        canonical_url=request.target,
        requested_url=request.target,
        authority_url=request.target,
        media_type="text/plain",
        status_code=200,
    )
    uri, digest, size = await cas.put(
        b"Validated cache fixture with deterministic freshness provenance."
    )
    artifact = build_artifact(
        role="primary",
        representation="clean_text",
        media_type="text/plain",
        cas_uri=uri,
        digest=digest,
        size=size,
        resource=resource,
        extractor="fixture-parser/1",
        quality=QualityAssessment(
            page_state=PageState.OK,
            score=1.0,
            accepted=True,
            completeness=1.0,
        ),
    )
    key = CacheKey.for_request(
        request,
        url=request.target,
        representation="clean_text",
        parser_version="fixture-parser/1",
    )
    await store.store(
        key,
        resource,
        artifact,
        request=request,
        source_capability="local_snapshot",
        stored_at=datetime.now(UTC) - timedelta(days=2),
        expires_at=expires_at,
    )


def _lookup_node(*, stale_seconds: int) -> PlanNode:
    return PlanNode(
        id="cache-lookup",
        capability_id="previous_successful_snapshot",
        adapter="cache",
        retry=RetryRule(maximum=0),
        parameters={
            "cache_operation": "lookup",
            "representation": "clean_text",
            "parser_version": "fixture-parser/1",
            "stale_while_revalidate_seconds": stale_seconds,
        },
    )


@pytest.mark.parametrize(
    (
        "disposition",
        "expiry_delta",
        "stale_seconds",
        "record_found",
        "fresh",
        "usable",
        "requires_revalidation",
    ),
    (
        (CacheDisposition.MISS, None, 0, False, False, False, False),
        (
            CacheDisposition.FRESH,
            timedelta(days=1),
            0,
            True,
            True,
            True,
            False,
        ),
        (
            CacheDisposition.STALE_WHILE_REVALIDATE,
            -timedelta(seconds=30),
            3_600,
            True,
            False,
            True,
            True,
        ),
        (
            CacheDisposition.REVALIDATE,
            -timedelta(hours=2),
            3_600,
            True,
            False,
            False,
            True,
        ),
    ),
)
@pytest.mark.asyncio
async def test_cache_lookup_records_bounded_freshness_provenance(
    tmp_path: Path,
    disposition: CacheDisposition,
    expiry_delta: timedelta | None,
    stale_seconds: int,
    record_found: bool,
    fresh: bool,
    usable: bool,
    requires_revalidation: bool,
) -> None:
    request = FetchRequest(target="https://example.com/cache-entry")
    cas = FileSystemCAS(tmp_path / "cas")
    store = SnapshotStore(tmp_path / "snapshots", cas)
    if expiry_delta is not None:
        await _seed_snapshot(
            store,
            request,
            cas,
            expires_at=datetime.now(UTC) + expiry_delta,
        )
    context = ExecutionContext(run_id=uuid4(), request=request, cas=cas)

    if disposition == CacheDisposition.MISS:
        with pytest.raises(AdapterExecutionError, match="validated cache miss"):
            await CacheAdapter(store).execute(
                _lookup_node(stale_seconds=stale_seconds),
                context,
            )
    else:
        await CacheAdapter(store).execute(
            _lookup_node(stale_seconds=stale_seconds),
            context,
        )

    outcomes = [
        outcome
        for outcome in context.capability_outcomes
        if outcome.capability_id == "cache_expiry_check"
    ]
    assert len(outcomes) == 1
    assert outcomes[0].status == CapabilityOutcomeStatus.APPLIED
    assert outcomes[0].stage == "cache"
    assert outcomes[0].details == {
        "disposition": disposition.value,
        "record_found": record_found,
        "fresh": fresh,
        "usable": usable,
        "requires_revalidation": requires_revalidation,
    }


@pytest.mark.asyncio
async def test_executor_preserves_cache_adapter_freshness_outcome(
    tmp_path: Path,
) -> None:
    request = FetchRequest(target="https://example.com/cache-entry")
    cas = FileSystemCAS(tmp_path / "cas")
    store = SnapshotStore(tmp_path / "snapshots", cas)
    await _seed_snapshot(
        store,
        request,
        cas,
        expires_at=datetime.now(UTC) + timedelta(days=1),
    )
    ledger = EventLedger.sqlite(tmp_path / "ledger.sqlite3")
    await ledger.initialize()
    run_id = uuid4()
    await ledger.create_run(
        run_id,
        request.model_dump(mode="json"),
        datetime.now(UTC),
    )
    engine = ExecutionEngine(
        adapters={"cache": CacheAdapter(store)},
        cas=cas,
        ledger=ledger,
    )

    try:
        result = await engine.execute(
            run_id,
            FetchPlan(
                request=request,
                nodes=(_lookup_node(stale_seconds=0),),
            ),
        )
    finally:
        await ledger.close()

    outcomes = [
        outcome
        for outcome in result.capability_outcomes
        if outcome.capability_id == "cache_expiry_check"
    ]
    assert len(outcomes) == 1
    assert outcomes[0].status == CapabilityOutcomeStatus.APPLIED
    assert outcomes[0].details["disposition"] == CacheDisposition.FRESH.value
    assert outcomes[0].details["fresh"] is True


@pytest.mark.asyncio
async def test_executor_defaults_cache_expiry_only_when_no_cache_was_consulted(
    tmp_path: Path,
) -> None:
    class NoopAdapter:
        async def execute(
            self,
            node: PlanNode,
            context: ExecutionContext,
        ) -> None:
            del node, context

    request = FetchRequest(target="https://example.com/no-cache")
    ledger = EventLedger.sqlite(tmp_path / "ledger.sqlite3")
    await ledger.initialize()
    run_id = uuid4()
    await ledger.create_run(
        run_id,
        request.model_dump(mode="json"),
        datetime.now(UTC),
    )
    engine = ExecutionEngine(
        adapters={"noop": NoopAdapter()},
        cas=FileSystemCAS(tmp_path / "cas"),
        ledger=ledger,
    )

    try:
        result = await engine.execute(
            run_id,
            FetchPlan(
                request=request,
                nodes=(
                    PlanNode(
                        id="noop",
                        capability_id="raw_html",
                        adapter="noop",
                        retry=RetryRule(maximum=0),
                    ),
                ),
            ),
        )
    finally:
        await ledger.close()

    outcomes = [
        outcome
        for outcome in result.capability_outcomes
        if outcome.capability_id == "cache_expiry_check"
    ]
    assert len(outcomes) == 1
    assert outcomes[0].status == CapabilityOutcomeStatus.NOT_APPLICABLE
    assert outcomes[0].details == {
        "reason": "no validated cache record was consulted"
    }
