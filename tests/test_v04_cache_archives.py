"""v0.4 conformance and adversarial tests for cache, snapshots, and archives."""

from __future__ import annotations

import asyncio
import io
import stat
import tarfile
import zipfile
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import pytest

from fetech.adapters.archive import (
    ArchiveAdapter,
    ArchiveLimits,
    ArchiveParseWorker,
    _extract_members,
)
from fetech.adapters.base import (
    AdapterBudgetExceededError,
    AdapterDependencyError,
    AdapterExecutionError,
    ExecutionContext,
)
from fetech.adapters.cache import (
    CACHE_CAPABILITIES,
    CONNECTOR_CAPABILITIES,
    STORAGE_CAPABILITIES,
    ArchivedSnapshot,
    CacheAdapter,
    CacheDisposition,
    SnapshotConnectorUsage,
    SnapshotIntegrityError,
    SnapshotStore,
    _write_immutable,
)
from fetech.logic.base import BackendExecutionError
from fetech.logic.process import ProcessResult
from fetech.models import (
    Artifact,
    AttemptStatus,
    FetchAttempt,
    FetchRequest,
    PageState,
    PlanNode,
    QualityAssessment,
    Resource,
    ResourceBudget,
)
from fetech.registry import CapabilityRegistry
from fetech.security import PolicyBlockedError, SafeURLPolicy
from fetech.storage import CacheKey, FileSystemCAS, build_artifact


@dataclass
class _FixtureConnector:
    snapshot_url: str
    calls: list[tuple[str, int, float]] = field(default_factory=list)

    async def fetch_snapshot(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        deadline_seconds: float,
    ) -> ArchivedSnapshot:
        self.calls.append((original_url, maximum_bytes, deadline_seconds))
        return ArchivedSnapshot(
            original_url=original_url,
            snapshot_url=self.snapshot_url,
            body=(
                b"Archived fixture body with enough useful deterministic text "
                b"to pass the normal page-state and content-quality checks."
            ),
            media_type="text/plain",
            captured_at=datetime(2026, 1, 2, tzinfo=UTC),
            etag='"fixture-etag"',
            last_modified="Fri, 02 Jan 2026 00:00:00 GMT",
        )


@dataclass
class _UsageReportingFixtureConnector:
    snapshot_url: str
    body: bytes
    wire_bytes: int
    decompressed_bytes: int

    async def fetch_snapshot(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        deadline_seconds: float,
    ) -> ArchivedSnapshot:
        del original_url, maximum_bytes, deadline_seconds
        raise AssertionError("the usage-reporting boundary must be selected")

    async def fetch_snapshot_with_usage(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> ArchivedSnapshot:
        del maximum_bytes, maximum_redirects, deadline_seconds
        usage.record(
            wire_bytes=self.wire_bytes,
            decompressed_bytes=self.decompressed_bytes,
        )
        return ArchivedSnapshot(
            original_url=original_url,
            snapshot_url=self.snapshot_url,
            body=self.body,
            media_type="text/plain",
            captured_at=datetime(2026, 1, 2, tzinfo=UTC),
        )


def _node(
    capability_id: str,
    *,
    parameters: dict[str, object] | None = None,
) -> PlanNode:
    return PlanNode(
        id=f"cache-{capability_id}",
        capability_id=capability_id,
        adapter="cache",
        parameters=parameters or {},
    )


async def _context(
    tmp_path: Path,
    *,
    request: FetchRequest | None = None,
    representation: str = "clean_text",
    parser_version: str = "fixture-parser/1",
    with_artifact: bool = True,
) -> ExecutionContext:
    active_request = request or FetchRequest(target="https://example.com/article")
    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=active_request,
        cas=cas,
    )
    if not with_artifact:
        return context
    resource = Resource(
        canonical_url=active_request.target,
        requested_url=active_request.target,
        authority_url=active_request.target,
        media_type="text/plain",
        status_code=200,
    )
    uri, digest, size = await cas.put(b"validated fixture body")
    artifact = build_artifact(
        role="primary",
        representation=representation,
        media_type="text/plain",
        cas_uri=uri,
        digest=digest,
        size=size,
        resource=resource,
        extractor=parser_version,
        quality=QualityAssessment(
            page_state=PageState.OK,
            score=1.0,
            accepted=True,
            completeness=1.0,
        ),
    )
    context.resources.append(resource)
    context.artifacts.append(artifact)
    context.accepted = True
    return context


def _zip_bytes(entries: list[tuple[str, bytes]]) -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, body in entries:
            archive.writestr(name, body)
    return stream.getvalue()


def test_cache_capability_set_is_exactly_the_manifest_category() -> None:
    registry = CapabilityRegistry()
    manifest_ids = {
        entry.id
        for entry in registry
        if entry.category == "cache" and entry.closure_release == "v0.4"
    }

    assert len(CACHE_CAPABILITIES) == 11
    assert len(STORAGE_CAPABILITIES) == 6
    assert len(CONNECTOR_CAPABILITIES) == 5
    assert manifest_ids == CACHE_CAPABILITIES


@pytest.mark.parametrize(
    ("capability_id", "representation"),
    (
        ("search_snippet_cache", "search_results"),
        ("search_cache", "search_results"),
        ("local_snapshot", "clean_text"),
        ("browser_cache", "rendered_html"),
        ("rag_document_cache", "clean_text"),
    ),
)
async def test_native_storage_strategies_store_only_validated_immutable_artifacts(
    tmp_path: Path,
    capability_id: str,
    representation: str,
) -> None:
    context = await _context(tmp_path, representation=representation)
    store = SnapshotStore(tmp_path / "snapshots", context.cas)
    adapter = CacheAdapter(store)

    await adapter.execute(
        _node(capability_id, parameters={"ttl_seconds": 60}),
        context,
    )

    assert context.attempts[-1].status == AttemptStatus.SUCCEEDED
    assert context.capability_outcomes[-1].capability_id == capability_id
    assert context.capability_outcomes[-1].details["immutable"] is True
    assert context.attempts[-1].consumed_budget == {}
    assert list((tmp_path / "snapshots").rglob("*.json"))


async def test_previous_successful_snapshot_restores_the_exact_partition(
    tmp_path: Path,
) -> None:
    source = await _context(tmp_path)
    store = SnapshotStore(tmp_path / "snapshots", source.cas)
    adapter = CacheAdapter(store)
    await adapter.execute(
        _node(
            "local_snapshot",
            parameters={"representation": "clean_text", "parser_version": "fixture-parser/1"},
        ),
        source,
    )

    restored = await _context(tmp_path, with_artifact=False)
    await adapter.execute(
        _node(
            "previous_successful_snapshot",
            parameters={"representation": "clean_text", "parser_version": "fixture-parser/1"},
        ),
        restored,
    )

    assert restored.accepted
    assert restored.artifacts[-1].sha256 == source.artifacts[-1].sha256
    assert restored.resources[-1].authority_url == "https://example.com/article"
    assert restored.capability_outcomes[-1].details["disposition"] == "FRESH"


async def test_previous_snapshot_lookup_reapplies_destination_policy(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source = await _context(tmp_path)
    store = SnapshotStore(tmp_path / "snapshots", source.cas)
    await CacheAdapter(store).execute(
        _node(
            "local_snapshot",
            parameters={
                "representation": "clean_text",
                "parser_version": "fixture-parser/1",
            },
        ),
        source,
    )
    policy = SafeURLPolicy()

    async def private(_: str, __: int) -> tuple[str, ...]:
        return ("10.0.0.8",)

    monkeypatch.setattr(policy, "_resolve", private)
    restored = await _context(tmp_path, with_artifact=False)
    adapter = CacheAdapter(store, policy=policy)

    with pytest.raises(PolicyBlockedError, match="non-public"):
        await adapter.execute(
            _node(
                "previous_successful_snapshot",
                parameters={
                    "representation": "clean_text",
                    "parser_version": "fixture-parser/1",
                },
            ),
            restored,
        )

    assert restored.artifacts == []
    assert restored.attempts[-1].failure_code == "policy"


@pytest.mark.parametrize(
    "capability_id",
    (
        "search_snippet_cache",
        "search_cache",
        "browser_cache",
        "rag_document_cache",
    ),
)
async def test_typed_caches_reject_a_mismatched_raw_artifact(
    tmp_path: Path,
    capability_id: str,
) -> None:
    context = await _context(tmp_path, representation="raw")
    adapter = CacheAdapter(SnapshotStore(tmp_path / "snapshots", context.cas))

    with pytest.raises(AdapterExecutionError, match="requires an accepted"):
        await adapter.execute(_node(capability_id), context)

    assert context.attempts[-1].status == AttemptStatus.FAILED
    assert context.capability_outcomes[-1].status.value == "FAILED"
    assert not list((tmp_path / "snapshots").rglob("*.json"))


async def test_typed_cache_representation_cannot_be_overridden(
    tmp_path: Path,
) -> None:
    context = await _context(tmp_path, representation="raw")
    adapter = CacheAdapter(SnapshotStore(tmp_path / "snapshots", context.cas))

    with pytest.raises(AdapterExecutionError, match="requires a clean_text"):
        await adapter.execute(
            _node("rag_document_cache", parameters={"representation": "raw"}),
            context,
        )

    assert not list((tmp_path / "snapshots").rglob("*.json"))


@pytest.mark.parametrize("capability_id", sorted(CONNECTOR_CAPABILITIES))
async def test_optional_connectors_preserve_original_authority_and_store_snapshot(
    tmp_path: Path,
    capability_id: str,
) -> None:
    snapshot_url = (
        "https://web.archive.org/web/20260102000000/https://example.com/article"
        if capability_id == "internet_archive_snapshot"
        else f"https://cache.example/{capability_id}/snapshot"
    )
    connector = _FixtureConnector(snapshot_url)
    context = await _context(tmp_path, with_artifact=False)
    store = SnapshotStore(tmp_path / "snapshots", context.cas)
    adapter = CacheAdapter(store, connectors={capability_id: connector})

    await adapter.execute(_node(capability_id), context)

    assert connector.calls == [
        (
            "https://example.com/article",
            context.request.budget.bytes,
            context.request.budget.deadline_seconds,
        )
    ]
    assert context.resources[-1].canonical_url == "https://example.com/article"
    assert context.resources[-1].authority_url == "https://example.com/article"
    assert context.resources[-1].requested_url == snapshot_url
    assert context.artifacts[-1].quality.accepted
    assert context.attempts[-1].status == AttemptStatus.SUCCEEDED
    assert context.attempts[-1].consumed_budget == {
        "bytes": context.artifacts[-1].size,
        "decompressed_bytes": context.artifacts[-1].size,
    }
    assert list((tmp_path / "snapshots").rglob("*.json"))


async def test_connector_receives_and_consumes_only_remaining_body_budgets(
    tmp_path: Path,
) -> None:
    request = FetchRequest(
        target="https://example.com/article",
        budget=ResourceBudget(bytes=500, decompressed_bytes=400),
    )
    context = await _context(tmp_path, request=request, with_artifact=False)
    context.attempts.append(
        FetchAttempt(
            capability_id="http_get",
            sanitized_destination=request.target,
            status=AttemptStatus.SUCCEEDED,
            consumed_budget={"bytes": 100, "decompressed_bytes": 250},
        )
    )
    connector = _FixtureConnector("https://cache.example/snapshot")
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", context.cas),
        connectors={"web_archive": connector},
    )

    await adapter.execute(_node("web_archive"), context)

    assert connector.calls == [
        ("https://example.com/article", 150, request.budget.deadline_seconds)
    ]
    assert context.attempts[-1].consumed_budget == {
        "bytes": context.artifacts[-1].size,
        "decompressed_bytes": context.artifacts[-1].size,
    }


async def test_connector_body_must_fit_wire_and_decompressed_remaining_budgets(
    tmp_path: Path,
) -> None:
    request = FetchRequest(
        target="https://example.com/article",
        budget=ResourceBudget(bytes=500, decompressed_bytes=50),
    )
    context = await _context(tmp_path, request=request, with_artifact=False)
    connector = _FixtureConnector("https://cache.example/snapshot")
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", context.cas),
        connectors={"web_archive": connector},
    )

    with pytest.raises(AdapterBudgetExceededError, match="decompressed_bytes"):
        await adapter.execute(_node("web_archive"), context)

    assert connector.calls == [
        ("https://example.com/article", 50, request.budget.deadline_seconds)
    ]
    assert not context.accepted
    assert not list((tmp_path / "snapshots").rglob("*.json"))


async def test_usage_reporting_connector_cannot_underreport_returned_body(
    tmp_path: Path,
) -> None:
    body = b"acquired snapshot body whose complete usage must remain observable"
    context = await _context(tmp_path, with_artifact=False)
    connector = _UsageReportingFixtureConnector(
        "https://cache.example/snapshot",
        body,
        wire_bytes=1,
        decompressed_bytes=1,
    )
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", context.cas),
        connectors={"web_archive": connector},
    )

    with pytest.raises(
        AdapterExecutionError,
        match="configured snapshot connector failed",
    ):
        await adapter.execute(_node("web_archive"), context)

    assert context.attempts[-1].consumed_budget == {
        "bytes": len(body),
        "decompressed_bytes": len(body),
    }
    assert context.resources == []
    assert context.artifacts == []
    assert not list((tmp_path / "cas").rglob("*"))
    assert not list((tmp_path / "snapshots").rglob("*.json"))


async def test_usage_reporting_connector_oversize_body_is_charged_before_rejection(
    tmp_path: Path,
) -> None:
    body = b"x" * 65
    request = FetchRequest(
        target="https://example.com/article",
        budget=ResourceBudget(bytes=64, decompressed_bytes=64),
    )
    context = await _context(tmp_path, request=request, with_artifact=False)
    connector = _UsageReportingFixtureConnector(
        "https://cache.example/snapshot",
        body,
        wire_bytes=0,
        decompressed_bytes=0,
    )
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", context.cas),
        connectors={"web_archive": connector},
    )

    with pytest.raises(AdapterBudgetExceededError, match="bytes budget exhausted"):
        await adapter.execute(_node("web_archive"), context)

    assert context.attempts[-1].consumed_budget == {
        "bytes": len(body),
        "decompressed_bytes": len(body),
    }
    assert context.resources == []
    assert context.artifacts == []
    assert not list((tmp_path / "cas").rglob("*"))
    assert not list((tmp_path / "snapshots").rglob("*.json"))


async def test_missing_optional_internet_archive_provider_is_typed(
    tmp_path: Path,
) -> None:
    context = await _context(tmp_path, with_artifact=False)
    adapter = CacheAdapter(SnapshotStore(tmp_path / "snapshots", context.cas))

    with pytest.raises(AdapterDependencyError):
        await adapter.execute(_node("internet_archive_snapshot"), context)

    assert context.attempts[-1].failure_code == "dependency_missing"
    assert context.capability_outcomes[-1].status.value == "DEPENDENCY_MISSING"


async def test_connector_low_quality_is_checked_only_and_not_a_successful_snapshot(
    tmp_path: Path,
) -> None:
    connector = _FixtureConnector("https://cache.example/login")

    async def low_quality(
        original_url: str,
        *,
        maximum_bytes: int,
        deadline_seconds: float,
    ) -> ArchivedSnapshot:
        del maximum_bytes, deadline_seconds
        return ArchivedSnapshot(
            original_url=original_url,
            snapshot_url=connector.snapshot_url,
            body=b"Sign in with your password",
            media_type="text/html",
            captured_at=datetime(2026, 1, 2, tzinfo=UTC),
        )

    connector.fetch_snapshot = low_quality  # type: ignore[method-assign]
    context = await _context(tmp_path, with_artifact=False)
    store = SnapshotStore(tmp_path / "snapshots", context.cas)
    adapter = CacheAdapter(store, connectors={"web_archive": connector})

    await adapter.execute(_node("web_archive"), context)

    artifact = context.artifacts[-1]
    assert artifact.role == "checked-only"
    assert artifact.quality.page_state == PageState.LOGIN
    assert not artifact.quality.accepted
    assert not context.accepted
    assert context.capability_outcomes[-1].details["accepted"] is False
    key = CacheKey.for_request(
        context.request,
        url=context.request.target,
        representation=artifact.representation,
        parser_version=artifact.extractor_version,
    )
    assert await store.latest_successful(key) is None
    assert context.pending_events[-1][0] == "snapshot_connector_checked_only"


async def test_malformed_connector_result_is_a_sanitized_typed_failure(
    tmp_path: Path,
) -> None:
    class MalformedConnector:
        async def fetch_snapshot(
            self,
            original_url: str,
            *,
            maximum_bytes: int,
            deadline_seconds: float,
        ) -> object:
            del original_url, maximum_bytes, deadline_seconds
            return {"body": "private malformed connector detail"}

    context = await _context(tmp_path, with_artifact=False)
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", context.cas),
        connectors={"web_archive": MalformedConnector()},  # type: ignore[dict-item]
    )

    with pytest.raises(AdapterExecutionError) as caught:
        await adapter.execute(_node("web_archive"), context)

    assert str(caught.value) == "configured snapshot connector returned an invalid result"
    assert "private malformed connector detail" not in str(caught.value)
    assert context.attempts[-1].status == AttemptStatus.FAILED
    assert not context.accepted


async def test_invalid_connector_body_remains_charged_and_cannot_be_reacquired(
    tmp_path: Path,
) -> None:
    body = b"body acquired from a connector with invalid source authority"

    class WrongAuthorityConnector:
        calls = 0

        async def fetch_snapshot(
            self,
            original_url: str,
            *,
            maximum_bytes: int,
            deadline_seconds: float,
        ) -> ArchivedSnapshot:
            del original_url, maximum_bytes, deadline_seconds
            self.calls += 1
            return ArchivedSnapshot(
                original_url="https://different.example/article",
                snapshot_url="https://cache.example/snapshot",
                body=body,
                media_type="text/plain",
                captured_at=datetime(2026, 1, 2, tzinfo=UTC),
            )

    request = FetchRequest(
        target="https://example.com/article",
        budget=ResourceBudget(
            bytes=len(body),
            decompressed_bytes=len(body),
        ),
    )
    context = await _context(tmp_path, request=request, with_artifact=False)
    connector = WrongAuthorityConnector()
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", context.cas),
        connectors={"web_archive": connector},
    )

    with pytest.raises(AdapterExecutionError, match="source authority"):
        await adapter.execute(_node("web_archive"), context)

    assert context.attempts[-1].consumed_budget == {
        "bytes": len(body),
        "decompressed_bytes": len(body),
    }
    with pytest.raises(AdapterBudgetExceededError, match="bytes"):
        await adapter.execute(_node("web_archive"), context)
    assert connector.calls == 1


async def test_public_connectors_cannot_receive_private_or_authenticated_targets(
    tmp_path: Path,
) -> None:
    request = FetchRequest(
        target="https://example.com/private?unknown=secret-value",
        authentication_ref="vault://opaque/private",
        privacy_profile="private",
    )
    context = await _context(tmp_path, request=request, with_artifact=False)
    connector = _FixtureConnector("https://cache.example/snapshot")
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", context.cas),
        connectors={"web_archive": connector},
    )

    with pytest.raises(PermissionError):
        await adapter.execute(_node("web_archive"), context)

    assert connector.calls == []
    assert "secret-value" not in context.attempts[-1].sanitized_destination
    assert context.attempts[-1].failure_code == "policy"


async def test_authenticated_snapshot_metadata_is_redacted_and_cache_isolated(
    tmp_path: Path,
) -> None:
    private_request = FetchRequest(
        target="https://example.com/private?unknown=secret-value",
        authentication_ref="vault://opaque/private",
        privacy_profile="private",
    )
    context = await _context(tmp_path, request=private_request)
    context.artifacts[-1] = context.artifacts[-1].model_copy(
        update={
            "locators": (
                "https://example.com/private?unknown=secret-value",
            ),
            "quality": context.artifacts[-1].quality.model_copy(
                update={
                    "reasons": (
                        "derived from https://example.com/private?unknown=secret-value",
                    )
                }
            ),
        }
    )
    store = SnapshotStore(tmp_path / "snapshots", context.cas)
    private_key = CacheKey.for_request(
        private_request,
        url=private_request.target,
        representation="clean_text",
        parser_version="fixture-parser/1",
    )
    await store.store(
        private_key,
        context.resources[-1],
        context.artifacts[-1],
        request=private_request,
        source_capability="local_snapshot",
    )

    metadata = b"".join(path.read_bytes() for path in (tmp_path / "snapshots").rglob("*.json"))
    assert b"secret-value" not in metadata
    assert b"vault://opaque/private" not in metadata
    assert b"auth:sha256:" in metadata

    public_request = FetchRequest(target=private_request.target)
    public_key = CacheKey.for_request(
        public_request,
        url=public_request.target,
        representation="clean_text",
        parser_version="fixture-parser/1",
    )
    assert (await store.lookup(public_key)).disposition == CacheDisposition.MISS
    assert (await store.lookup(private_key)).disposition == CacheDisposition.FRESH


async def test_cache_key_is_partitioned_by_region(tmp_path: Path) -> None:
    request_au = FetchRequest(target="https://example.com/article", region="AU")
    request_us = request_au.model_copy(update={"region": "US"})
    context = await _context(tmp_path, request=request_au)
    store = SnapshotStore(tmp_path / "snapshots", context.cas)
    key_au = CacheKey.for_request(
        request_au,
        url=request_au.target,
        representation="clean_text",
        parser_version="fixture-parser/1",
    )
    key_us = CacheKey.for_request(
        request_us,
        url=request_us.target,
        representation="clean_text",
        parser_version="fixture-parser/1",
    )
    await store.store(
        key_au,
        context.resources[-1],
        context.artifacts[-1],
        request=request_au,
        source_capability="local_snapshot",
    )

    assert key_au.region == "AU"
    assert key_au.digest != key_us.digest
    assert (await store.lookup(key_au)).disposition == CacheDisposition.FRESH
    assert (await store.lookup(key_us)).disposition == CacheDisposition.MISS


async def test_public_archive_connector_rejects_sensitive_query_credentials(
    tmp_path: Path,
) -> None:
    request = FetchRequest(
        target="https://example.com/article?access_token=secret-value",
    )
    context = await _context(tmp_path, request=request, with_artifact=False)
    connector = _FixtureConnector("https://cache.example/snapshot")
    adapter = CacheAdapter(
        SnapshotStore(tmp_path / "snapshots", context.cas),
        connectors={"web_archive": connector},
    )

    with pytest.raises(PermissionError, match="sensitive URL query"):
        await adapter.execute(_node("web_archive"), context)

    assert connector.calls == []


async def test_revalidation_and_stale_while_revalidate_are_explicit(
    tmp_path: Path,
) -> None:
    context = await _context(tmp_path)
    store = SnapshotStore(tmp_path / "snapshots", context.cas)
    key = CacheKey.for_request(
        context.request,
        url=context.request.target,
        representation="clean_text",
        parser_version="fixture-parser/1",
    )
    start = datetime(2026, 1, 1, tzinfo=UTC)
    record = await store.store(
        key,
        context.resources[-1],
        context.artifacts[-1],
        request=context.request,
        source_capability="local_snapshot",
        stored_at=start,
        expires_at=start + timedelta(seconds=10),
        etag='"v1"',
        last_modified="Thu, 01 Jan 2026 00:00:00 GMT",
    )

    assert (await store.lookup(key, now=start + timedelta(seconds=5))).disposition == (
        CacheDisposition.FRESH
    )
    stale = await store.lookup(
        key,
        now=start + timedelta(seconds=15),
        stale_while_revalidate_seconds=10,
    )
    assert stale.disposition == CacheDisposition.STALE_WHILE_REVALIDATE
    assert stale.usable and stale.requires_revalidation
    expired = await store.lookup(
        key,
        now=start + timedelta(seconds=21),
        stale_while_revalidate_seconds=10,
    )
    assert expired.disposition == CacheDisposition.REVALIDATE
    assert not expired.usable
    assert store.conditional_headers(record) == {
        "If-None-Match": '"v1"',
        "If-Modified-Since": "Thu, 01 Jan 2026 00:00:00 GMT",
    }

    refreshed = await store.record_not_modified(
        key,
        record,
        request=context.request,
        ttl_seconds=60,
        checked_at=start + timedelta(seconds=30),
    )
    assert refreshed.artifact.sha256 == record.artifact.sha256
    assert (
        await store.lookup(key, now=start + timedelta(seconds=50))
    ).disposition == CacheDisposition.FRESH


async def test_snapshot_lookup_rejects_cas_corruption(tmp_path: Path) -> None:
    context = await _context(tmp_path)
    store = SnapshotStore(tmp_path / "snapshots", context.cas)
    key = CacheKey.for_request(
        context.request,
        url=context.request.target,
        representation="clean_text",
        parser_version="fixture-parser/1",
    )
    artifact = context.artifacts[-1]
    await store.store(
        key,
        context.resources[-1],
        artifact,
        request=context.request,
        source_capability="local_snapshot",
    )
    digest = artifact.sha256
    cas_path = context.cas.root / digest[:2] / digest[2:4] / digest
    cas_path.write_bytes(b"tampered")

    with pytest.raises(SnapshotIntegrityError, match=r"size|SHA-256"):
        await store.lookup(key)


async def test_unvalidated_or_checked_only_artifacts_never_enter_cache(
    tmp_path: Path,
) -> None:
    context = await _context(tmp_path)
    original = context.artifacts[-1]
    context.artifacts[-1] = original.model_copy(
        update={
            "role": "checked-only",
            "quality": original.quality.model_copy(update={"accepted": False}),
        }
    )
    adapter = CacheAdapter(SnapshotStore(tmp_path / "snapshots", context.cas))

    with pytest.raises(AdapterExecutionError, match="validated accepted"):
        await adapter.execute(_node("local_snapshot"), context)

    assert not list((tmp_path / "snapshots").rglob("*.json"))


@pytest.mark.parametrize(
    ("entries", "members", "expanded", "ratio", "message"),
    (
        ([("../escape.txt", b"x")], 5, 100, 10, "traversal"),
        ([("..\\escape.txt", b"x")], 5, 100, 10, "invalid"),
        ([("a.txt", b"a"), ("b.txt", b"b")], 1, 100, 10, "member limit"),
        ([("large.txt", b"x" * 50)], 5, 10, 100, "expanded-byte"),
        ([("large.txt", b"0" * 10_000)], 5, 20_000, 2, "compression ratio"),
        ([("A.txt", b"a"), ("a.TXT", b"b")], 5, 100, 10, "duplicate"),
    ),
)
def test_zip_security_limits_fail_closed(
    entries: list[tuple[str, bytes]],
    members: int,
    expanded: int,
    ratio: float,
    message: str,
) -> None:
    body = _zip_bytes(entries)

    with pytest.raises(ValueError, match=message):
        _extract_members(
            body,
            maximum_members=members,
            maximum_expanded=expanded,
            maximum_ratio=ratio,
        )


def test_zip_symlink_and_content_disguised_nested_archive_are_rejected() -> None:
    symlink_stream = io.BytesIO()
    with zipfile.ZipFile(symlink_stream, "w") as archive:
        link = zipfile.ZipInfo("link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(link, "target")
    with pytest.raises(ValueError, match="symlinks"):
        _extract_members(
            symlink_stream.getvalue(),
            maximum_members=5,
            maximum_expanded=1_000,
            maximum_ratio=100,
        )

    nested = _zip_bytes([("inner.txt", b"safe")])
    disguised = _zip_bytes([("payload.bin", nested)])
    with pytest.raises(ValueError, match="nested archives"):
        _extract_members(
            disguised,
            maximum_members=5,
            maximum_expanded=10_000,
            maximum_ratio=100,
        )


def test_tar_symlinks_are_rejected() -> None:
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w") as archive:
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "target"
        archive.addfile(link)

    with pytest.raises(ValueError, match="links and devices"):
        _extract_members(
            stream.getvalue(),
            maximum_members=5,
            maximum_expanded=1_000,
            maximum_ratio=100,
        )


async def test_real_archive_worker_is_ephemeral_and_returns_bounded_members() -> None:
    body = _zip_bytes([("folder/file.txt", b"worker fixture")])

    members = await ArchiveParseWorker(memory_mb=256).extract(
        body,
        limits=ArchiveLimits(
            maximum_members=5,
            maximum_expanded=1_000,
            maximum_ratio=100,
        ),
        timeout_seconds=5,
    )

    assert members == [("folder/file.txt", b"worker fixture")]


async def test_empty_safe_archive_is_checked_only_and_not_accepted(
    tmp_path: Path,
) -> None:
    body = _zip_bytes([])
    request = FetchRequest(target="https://example.com/empty.zip")
    context = ExecutionContext(
        run_id=uuid4(),
        request=request,
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    resource = Resource(
        canonical_url=request.target,
        requested_url=request.target,
        authority_url=request.target,
        media_type="application/zip",
        status_code=200,
    )
    uri, digest, size = await context.cas.put(body)
    context.resources.append(resource)
    context.artifacts.append(
        build_artifact(
            role="source",
            representation="raw",
            media_type="application/zip",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor="fixture-http/1",
            quality=QualityAssessment(
                page_state=PageState.OK,
                score=1.0,
                accepted=True,
                completeness=1.0,
            ),
        )
    )

    await ArchiveAdapter().execute(
        PlanNode(id="archive", capability_id="zip_archive", adapter="archive"),
        context,
    )

    manifest = context.artifacts[-1]
    assert manifest.representation == "archive_manifest"
    assert manifest.role == "checked-only"
    assert manifest.quality.page_state == PageState.EMPTY
    assert not manifest.quality.accepted
    assert not context.accepted
    assert context.attempts[-1].consumed_budget["archive_members"] == 0


async def test_archive_worker_timeout_and_invalid_output_are_typed_and_redacted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def timed_out(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        raise BackendExecutionError("private worker detail")

    monkeypatch.setattr("fetech.adapters.archive.run_bounded", timed_out)
    worker = ArchiveParseWorker()
    limits = ArchiveLimits(maximum_members=5, maximum_expanded=1_000, maximum_ratio=100)
    with pytest.raises(AdapterExecutionError) as caught:
        await worker.extract(b"not-an-archive", limits=limits, timeout_seconds=0.1)
    assert str(caught.value) == "bounded archive extraction process failed"
    assert "private worker detail" not in str(caught.value)

    async def malformed(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        return ProcessResult(returncode=0, stdout=b"{not-json", stderr=b"private stderr")

    monkeypatch.setattr("fetech.adapters.archive.run_bounded", malformed)
    with pytest.raises(AdapterExecutionError) as malformed_caught:
        await worker.extract(b"not-an-archive", limits=limits, timeout_seconds=1)
    assert str(malformed_caught.value) == "archive worker returned malformed output"
    assert "private stderr" not in str(malformed_caught.value)


async def test_snapshot_record_contract_rejects_inconsistent_artifact_source(
    tmp_path: Path,
) -> None:
    resource = Resource(
        canonical_url="https://example.com/",
        requested_url="https://example.com/",
    )
    cas = FileSystemCAS(tmp_path / "cas")
    uri, digest, size = await cas.put(b"")
    artifact = Artifact(
        role="primary",
        representation="clean_text",
        media_type="text/plain",
        cas_uri=uri,
        sha256=digest,
        size=size,
        source_resource_id=uuid4(),
        extractor_version="fixture",
        quality=QualityAssessment(accepted=True),
    )
    request = FetchRequest(target="https://example.com/")
    key = CacheKey.for_request(
        request,
        url=request.target,
        representation="clean_text",
        parser_version="fixture",
    )

    with pytest.raises(SnapshotIntegrityError, match="does not belong"):
        await SnapshotStore(tmp_path / "snapshots", cas).store(
            key,
            resource,
            artifact,
            request=request,
            source_capability="local_snapshot",
        )


def test_immutable_metadata_publish_never_exposes_partial_data_after_sync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "partition" / "snapshot.json"

    def fail_data_sync(_: int) -> None:
        raise OSError("simulated process failure before publication")

    monkeypatch.setattr("fetech.adapters.cache.os.fsync", fail_data_sync)

    with pytest.raises(OSError, match="simulated process failure"):
        _write_immutable(target, b'{"complete":true}')

    assert not target.exists()
    assert not list(target.parent.glob("*.tmp"))


async def test_immutable_metadata_concurrent_publish_is_collision_safe(
    tmp_path: Path,
) -> None:
    target = tmp_path / "partition" / "snapshot.json"
    first = b'{"writer":"first","complete":true}'
    second = b'{"writer":"second","complete":true}'

    results = await asyncio.gather(
        asyncio.to_thread(_write_immutable, target, first),
        asyncio.to_thread(_write_immutable, target, second),
        return_exceptions=True,
    )

    assert sum(result is None for result in results) == 1
    collisions = [
        result for result in results if isinstance(result, SnapshotIntegrityError)
    ]
    assert len(collisions) == 1
    assert str(collisions[0]) == "immutable snapshot metadata collision"
    assert target.read_bytes() in {first, second}
    assert not list(target.parent.glob("*.tmp"))
