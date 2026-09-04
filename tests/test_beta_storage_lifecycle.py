"""Storage quota, retention, garbage-collection, and crash-recovery coverage."""

from __future__ import annotations

import asyncio
import base64
import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from fetech.adapters.base import ExecutionContext
from fetech.adapters.cache import SnapshotStore
from fetech.adapters.documents import DocumentAdapter
from fetech.adapters.media import MediaAdapter
from fetech.config import Settings
from fetech.executor import ExecutionEngine
from fetech.gateway import UniversalFetchGateway
from fetech.ledger import EventLedger
from fetech.models import (
    Artifact,
    AttemptStatus,
    FetchPlan,
    FetchRequest,
    FetchResult,
    PlanNode,
    ProvenanceEvent,
    QualityAssessment,
    Resource,
    ResultStatus,
    RetryRule,
    RunState,
)
from fetech.provenance import build_runtime_graph
from fetech.storage import (
    CacheKey,
    FileSystemCAS,
    StorageLifecycleError,
    StorageQuota,
    StorageQuotaExceeded,
)


def _settings(root: Path, **changes: object) -> Settings:
    return replace(
        Settings.from_environment(),
        data_dir=root,
        database_path=root / "ledger.sqlite3",
        artifact_dir=root / "artifacts",
        runtime_graph_path=root / "runtime-graph" / "graph.json",
        **changes,
    )


async def _artifact(
    cas: FileSystemCAS,
    body: bytes,
    resource: Resource,
    *,
    media_type: str = "text/plain",
) -> Artifact:
    uri, digest, size = await cas.put(body)
    return Artifact(
        role="primary",
        representation="raw",
        media_type=media_type,
        cas_uri=uri,
        sha256=digest,
        size=size,
        source_resource_id=resource.resource_id,
        extractor_version="storage-lifecycle-test",
        quality=QualityAssessment(accepted=True),
    )


@pytest.mark.asyncio
async def test_global_quota_serializes_concurrent_cas_writes_and_preserves_deduplication(
    tmp_path: Path,
) -> None:
    quota = StorageQuota(
        tmp_path,
        1_048_576,
        ledger_headroom_bytes=65_536,
    )
    cas = FileSystemCAS(tmp_path / "artifacts", quota=quota)
    first_body = b"a" * 700_000
    first = await cas.put(first_body)

    outcomes = await asyncio.gather(
        cas.put(b"b" * 300_000),
        cas.put(b"c" * 300_000),
        return_exceptions=True,
    )

    assert sum(isinstance(item, StorageQuotaExceeded) for item in outcomes) == 2
    assert await cas.put(first_body) == first
    usage = await quota.usage()
    assert usage.bytes_used == len(first_body)
    assert usage.bytes_used <= quota.maximum_bytes - quota.ledger_headroom_bytes


@pytest.mark.asyncio
async def test_concurrent_identical_cas_writes_consume_quota_once(
    tmp_path: Path,
) -> None:
    quota = StorageQuota(
        tmp_path,
        1_048_576,
        ledger_headroom_bytes=65_536,
    )
    cas = FileSystemCAS(tmp_path / "artifacts", quota=quota)
    body = b"d" * 700_000

    first, second = await asyncio.gather(cas.put(body), cas.put(body))

    assert first == second
    usage = await quota.usage()
    assert usage.bytes_used == len(body)


@pytest.mark.asyncio
async def test_cas_startup_maintenance_recovers_staging_and_collects_only_old_orphans(
    tmp_path: Path,
) -> None:
    cas = FileSystemCAS(tmp_path / "artifacts")
    live_uri, live_digest, _ = await cas.put(b"live")
    _, orphan_digest, orphan_size = await cas.put(b"orphan")
    _, recent_digest, _ = await cas.put(b"recent")
    staging = cas._path(orphan_digest).parent / ".write-interrupted"
    staging.write_bytes(b"staged")
    old = datetime(2026, 1, 1, tzinfo=UTC)
    old_timestamp = old.timestamp() - 120
    os.utime(cas._path(orphan_digest), (old_timestamp, old_timestamp))
    os.utime(staging, (old_timestamp, old_timestamp))

    report = await cas.maintain(
        {live_uri},
        orphan_grace_seconds=60,
        now=old,
    )

    assert report.temporary_files_removed == 1
    assert report.orphan_files_removed == 1
    assert report.orphan_bytes_removed == orphan_size
    assert cas._path(live_digest).is_file()
    assert cas._path(recent_digest).is_file()
    assert not cas._path(orphan_digest).exists()
    assert not staging.exists()


@pytest.mark.asyncio
async def test_storage_inventory_rejects_symbolic_links_without_following_them(
    tmp_path: Path,
) -> None:
    cas = FileSystemCAS(tmp_path / "artifacts")
    outside = tmp_path / "outside"
    outside.write_bytes(b"sentinel")
    link = cas.root / "unsafe"
    try:
        link.symlink_to(outside)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is not supported")

    with pytest.raises(StorageLifecycleError, match="non-regular file"):
        await cas.maintain(set(), orphan_grace_seconds=0)

    assert outside.read_bytes() == b"sentinel"


def test_quota_bound_stores_reject_external_roots_before_creating_them(
    tmp_path: Path,
) -> None:
    quota = StorageQuota(tmp_path / "data", 1_048_576)
    external = tmp_path / "external"

    with pytest.raises(ValueError, match="CAS root"):
        FileSystemCAS(external / "artifacts", quota=quota)
    assert not external.exists()

    with pytest.raises(ValueError, match="ledger path"):
        EventLedger.sqlite(external / "ledger.sqlite3", quota=quota)
    assert not external.exists()

    cas = FileSystemCAS(quota.root / "artifacts", quota=quota)
    with pytest.raises(ValueError, match="snapshot root"):
        SnapshotStore(external / "snapshots", cas, quota=quota)
    assert not external.exists()


@pytest.mark.asyncio
async def test_snapshot_retention_removes_expired_metadata_and_keeps_live_references(
    tmp_path: Path,
) -> None:
    cas = FileSystemCAS(tmp_path / "artifacts")
    store = SnapshotStore(tmp_path / "snapshots", cas, maximum_records=2)
    request = FetchRequest(target="https://example.com/cache")
    resource = Resource(canonical_url=request.target, requested_url=request.target)
    old_artifact = await _artifact(cas, b"old", resource)
    live_artifact = await _artifact(cas, b"live", resource)
    now = datetime(2026, 1, 1, tzinfo=UTC)

    await store.store(
        CacheKey.for_request(
            request,
            url=request.target,
            representation="old",
            parser_version="1",
        ),
        resource,
        old_artifact,
        request=request,
        source_capability="local_snapshot",
        stored_at=now - timedelta(hours=2),
        expires_at=now - timedelta(hours=1),
    )
    await store.store(
        CacheKey.for_request(
            request,
            url=request.target,
            representation="live",
            parser_version="1",
        ),
        resource,
        live_artifact,
        request=request,
        source_capability="local_snapshot",
        stored_at=now,
        expires_at=now + timedelta(hours=1),
    )
    crash_file = store.root / ".snapshot.json.interrupted.tmp"
    crash_file.write_bytes(b"partial")

    report = await store.maintain(retention_seconds=60, now=now)

    assert report.temporary_files_removed == 1
    assert report.records_removed == 1
    assert report.retained_records == 1
    assert report.live_cas_uris == (live_artifact.cas_uri,)


@pytest.mark.asyncio
async def test_snapshot_record_limit_fails_before_publishing_more_metadata(
    tmp_path: Path,
) -> None:
    cas = FileSystemCAS(tmp_path / "artifacts")
    store = SnapshotStore(tmp_path / "snapshots", cas, maximum_records=1)
    request = FetchRequest(target="https://example.com/cache")
    resource = Resource(canonical_url=request.target, requested_url=request.target)
    artifact = await _artifact(cas, b"body", resource)
    first = CacheKey.for_request(
        request,
        url=request.target,
        representation="first",
        parser_version="1",
    )
    second = CacheKey.for_request(
        request,
        url=request.target,
        representation="second",
        parser_version="1",
    )
    await store.store(
        first,
        resource,
        artifact,
        request=request,
        source_capability="local_snapshot",
    )

    with pytest.raises(StorageQuotaExceeded, match="snapshot record quota"):
        await store.store(
            second,
            resource,
            artifact,
            request=request,
            source_capability="local_snapshot",
        )

    assert len(tuple(store.root.rglob("*.json"))) == 1


@pytest.mark.asyncio
async def test_repeated_snapshot_store_reuses_existing_record(
    tmp_path: Path,
) -> None:
    quota = StorageQuota(tmp_path, 1_048_576, ledger_headroom_bytes=65_536)
    cas = FileSystemCAS(tmp_path / "artifacts", quota=quota)
    store = SnapshotStore(tmp_path / "snapshots", cas, quota=quota)
    request = FetchRequest(target="https://example.com/cache")
    resource = Resource(canonical_url=request.target, requested_url=request.target)
    artifact = await _artifact(cas, b"body", resource)
    cache_identity = CacheKey.for_request(
        request,
        url=request.target,
        representation="raw",
        parser_version="1",
    )
    stored_at = datetime(2026, 1, 1, tzinfo=UTC)
    first_record = await store.store(
        cache_identity,
        resource,
        artifact,
        request=request,
        source_capability="local_snapshot",
        stored_at=stored_at,
    )
    usage = await quota.usage()
    normal_limit = quota.maximum_bytes - quota.ledger_headroom_bytes
    (tmp_path / "capacity-padding").write_bytes(
        b"f" * (normal_limit - usage.bytes_used)
    )

    second_record = await store.store(
        cache_identity,
        resource,
        artifact,
        request=request,
        source_capability="local_snapshot",
        stored_at=stored_at,
    )

    assert second_record == first_record
    assert (await quota.usage()).bytes_used == normal_limit


@pytest.mark.asyncio
async def test_ledger_retention_is_bounded_and_leaves_an_identity_tombstone(
    tmp_path: Path,
) -> None:
    ledger = EventLedger.sqlite(tmp_path / "ledger.sqlite3")
    await ledger.initialize()
    now = datetime(2026, 1, 1, tzinfo=UTC)
    request = FetchRequest(target="https://example.com/")
    old_id = uuid4()
    current_id = uuid4()
    for run_id, submitted_at in (
        (old_id, now - timedelta(days=30)),
        (current_id, now),
    ):
        await ledger.create_run(run_id, request.model_dump(mode="json"), submitted_at)
        result = FetchResult(
            run_id=run_id,
            status=ResultStatus.SUCCEEDED,
            remaining_budget=request.budget,
        )
        await ledger.finish_run(
            ProvenanceEvent(run_id=run_id, event_type="run.finished", actor="test"),
            result,
        )

    report = await ledger.retire_finished_runs(
        before=now - timedelta(days=7),
        maximum_runs=1,
        retired_at=now,
    )

    assert report.runs_retired == 1
    assert report.events_retired == 1
    assert await ledger.retired_run_exists(old_id)
    with pytest.raises(KeyError, match="unknown run"):
        await ledger.run_snapshot(old_id)
    with pytest.raises(ValueError, match="cannot be reused"):
        await ledger.create_run(old_id, request.model_dump(mode="json"), now)
    assert (await ledger.run_snapshot(current_id))[0] == RunState.FINISHED
    await ledger.close()


@pytest.mark.asyncio
async def test_gateway_startup_retires_old_runs_and_collects_crash_orphans(
    tmp_path: Path,
) -> None:
    settings = _settings(
        tmp_path,
        storage_run_retention_seconds=60,
        storage_snapshot_retention_seconds=0,
        storage_orphan_grace_seconds=0,
    )
    ledger = EventLedger.sqlite(settings.database_path)
    await ledger.initialize()
    cas = FileSystemCAS(settings.artifact_dir)
    request = FetchRequest(target="https://example.com/")
    resource = Resource(canonical_url=request.target, requested_url=request.target)
    artifact = await _artifact(cas, b"retired", resource)
    run_id = uuid4()
    old = datetime.now(UTC) - timedelta(days=30)
    await ledger.create_run(run_id, request.model_dump(mode="json"), old)
    await ledger.finish_run(
        ProvenanceEvent(run_id=run_id, event_type="run.finished", actor="test"),
        FetchResult(
            run_id=run_id,
            status=ResultStatus.SUCCEEDED,
            resources=(resource,),
            artifacts=(artifact,),
            remaining_budget=request.budget,
        ),
    )
    await ledger.close()
    _, orphan_digest, _ = await cas.put(b"crash orphan")
    old_timestamp = old.timestamp()
    os.utime(cas._path(artifact.sha256), (old_timestamp, old_timestamp))
    os.utime(cas._path(orphan_digest), (old_timestamp, old_timestamp))
    crash_file = tmp_path / "snapshots" / ".snapshot.json.interrupted.tmp"
    crash_file.parent.mkdir(parents=True)
    crash_file.write_bytes(b"partial")

    gateway = UniversalFetchGateway(settings)
    await gateway.initialize()

    report = gateway.storage_maintenance_report
    assert report is not None
    assert report.ledger.runs_retired == 1
    assert report.ledger.artifact_references_retired == 1
    assert report.snapshots.temporary_files_removed == 1
    assert report.cas.orphan_files_removed == 2
    assert await gateway.ledger.retired_run_exists(run_id)
    assert not cas._path(artifact.sha256).exists()
    assert not cas._path(orphan_digest).exists()
    await gateway.close()


class _QuotaWritingAdapter:
    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        await context.cas.put(b"q" * 100)


class _ImageValidator:
    async def validate(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_input_bytes: int,
        maximum_pixels: int,
    ) -> dict[str, object]:
        assert body
        assert timeout_seconds > 0
        assert maximum_input_bytes > 0
        assert maximum_pixels > 0
        return {"format": "PNG", "height": 1, "width": 1}


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("target", "media_type", "body", "node", "adapter"),
    (
        (
            "https://example.com/note.txt",
            "text/plain",
            b"bounded plain text document",
            PlanNode(id="document", capability_id="txt", adapter="documents"),
            DocumentAdapter(),
        ),
        (
            "https://example.com/image.png",
            "image/png",
            base64.b64decode(
                "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwC"
                "AAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
            ),
            PlanNode(id="media", capability_id="image_metadata", adapter="media"),
            MediaAdapter(image_validator=_ImageValidator()),
        ),
    ),
)
async def test_normalizers_preserve_typed_storage_quota_exhaustion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    media_type: str,
    body: bytes,
    node: PlanNode,
    adapter: DocumentAdapter | MediaAdapter,
) -> None:
    cas = FileSystemCAS(tmp_path / node.adapter)
    resource = Resource(
        canonical_url=target,
        requested_url=target,
        authority_url=target,
        media_type=media_type,
        status_code=200,
    )
    raw = await _artifact(cas, body, resource, media_type=media_type)
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target=target),
        cas=cas,
        resources=[resource],
        artifacts=[raw],
    )

    async def reject_write(_: bytes) -> tuple[str, str, int]:
        raise StorageQuotaExceeded("data-directory quota does not permit this write")

    monkeypatch.setattr(cas, "put", reject_write)

    with pytest.raises(StorageQuotaExceeded, match="does not permit"):
        await adapter.execute(node, context)

    assert context.attempts[-1].status == AttemptStatus.FAILED
    assert context.attempts[-1].failure_code == "budget_exhausted"


@pytest.mark.asyncio
async def test_storage_full_result_is_typed_and_ledger_headroom_can_finalize_it(
    tmp_path: Path,
) -> None:
    settings = _settings(tmp_path, storage_max_bytes=1_048_576)
    gateway = UniversalFetchGateway(settings)
    await gateway.initialize()
    request = FetchRequest(target="https://example.com/")
    run_id = uuid4()
    await gateway.ledger.create_run(
        run_id,
        request.model_dump(mode="json"),
        datetime.now(UTC),
    )
    usage = await gateway.storage_quota.usage()
    normal_limit = (
        gateway.storage_quota.maximum_bytes
        - gateway.storage_quota.ledger_headroom_bytes
    )
    filler_size = normal_limit - usage.bytes_used - 50
    assert filler_size > 0
    (tmp_path / "quota-filler").write_bytes(b"f" * filler_size)
    plan = FetchPlan(
        request=request,
        nodes=(
            PlanNode(
                id="quota",
                capability_id="plain_http",
                adapter="quota",
                    retry=RetryRule(maximum=0),
            ),
        ),
    )
    engine = ExecutionEngine(
        adapters={"quota": _QuotaWritingAdapter()},
        cas=gateway.cas,
        ledger=gateway.ledger,
    )

    result = await engine.execute(run_id, plan)

    assert result.status == ResultStatus.BUDGET_EXHAUSTED
    assert any(item.code == "budget_exhausted" for item in result.diagnostics)
    assert (await gateway.ledger.run_snapshot(run_id))[0] == RunState.FINISHED
    await gateway.close()


@pytest.mark.asyncio
async def test_runtime_graph_quota_failure_preserves_the_previous_projection(
    tmp_path: Path,
) -> None:
    quota = StorageQuota(
        tmp_path,
        1_048_576,
        ledger_headroom_bytes=65_536,
    )
    ledger = EventLedger.sqlite(tmp_path / "ledger.sqlite3", quota=quota)
    await ledger.initialize()
    request = FetchRequest(target="https://example.com/")
    run_id = uuid4()
    await ledger.create_run(
        run_id,
        request.model_dump(mode="json"),
        datetime.now(UTC),
    )
    await ledger.finish_run(
        ProvenanceEvent(run_id=run_id, event_type="run.finished", actor="test"),
        FetchResult(
            run_id=run_id,
            status=ResultStatus.SUCCEEDED,
            remaining_budget=request.budget,
        ),
    )
    output = tmp_path / "runtime-graph" / "graph.json"
    output.parent.mkdir()
    output.write_bytes(b"old\n")
    usage = await quota.usage()
    normal_limit = quota.maximum_bytes - quota.ledger_headroom_bytes
    filler_size = normal_limit - usage.bytes_used - 1
    assert filler_size > 0
    (tmp_path / "quota-filler").write_bytes(b"f" * filler_size)

    with pytest.raises(StorageQuotaExceeded, match="does not permit"):
        await build_runtime_graph(ledger, output, quota=quota)

    assert output.read_bytes() == b"old\n"
    assert not tuple(output.parent.glob(".*.tmp"))
    await ledger.close()


def test_storage_lifecycle_environment_is_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FETECH_STORAGE_MAX_BYTES", "2097152")
    monkeypatch.setenv("FETECH_STORAGE_RUN_RETENTION_SECONDS", "3600")
    monkeypatch.setenv("FETECH_STORAGE_MAX_SNAPSHOT_RECORDS", "123")

    settings = Settings.from_environment()

    assert settings.storage_max_bytes == 2_097_152
    assert settings.storage_run_retention_seconds == 3_600
    assert settings.storage_max_snapshot_records == 123

    monkeypatch.setenv("FETECH_STORAGE_MAX_BYTES", "not-an-integer")
    with pytest.raises(ValueError, match="must be an integer"):
        Settings.from_environment()
