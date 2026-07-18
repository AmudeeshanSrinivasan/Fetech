"""Validated cache, immutable snapshots, and policy-aware archive connectors.

The adapter never performs network I/O itself. Remote cache and archive
providers, including the gateway's built-in Wayback implementation, sit behind
:class:`SnapshotConnector`, keeping destination policy, redirect validation,
and transport limits at the connector boundary. Snapshot metadata contains
only sanitized resource URLs, hashed cache keys, and opaque
authenticated-scope hashes.
"""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol, cast, runtime_checkable

from fetech.adapters.base import (
    AdapterBudgetExceededError,
    AdapterDependencyError,
    AdapterExecutionError,
    AdapterNotFoundError,
    ExecutionContext,
)
from fetech.models import (
    Artifact,
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    FetchRequest,
    PlanNode,
    Resource,
)
from fetech.quality import assess_binary, assess_text
from fetech.security import (
    PolicyBlockedError,
    SafeURLPolicy,
    normalize_url,
    sanitize_output_for_request,
    sanitize_url,
    sanitize_url_for_request,
)
from fetech.storage import (
    CacheKey,
    CASIntegrityError,
    FileSystemCAS,
    build_artifact,
)

CACHE_CAPABILITIES = frozenset(
    {
        "search_snippet_cache",
        "search_cache",
        "search_engine_cache_adapter",
        "alternate_search_cache_adapter",
        "web_archive",
        "internet_archive_snapshot",
        "local_snapshot",
        "previous_successful_snapshot",
        "cdn_copy",
        "browser_cache",
        "rag_document_cache",
    }
)

STORAGE_CAPABILITIES = frozenset(
    {
        "search_snippet_cache",
        "search_cache",
        "local_snapshot",
        "previous_successful_snapshot",
        "browser_cache",
        "rag_document_cache",
    }
)

CONNECTOR_CAPABILITIES = CACHE_CAPABILITIES - STORAGE_CAPABILITIES

_REPRESENTATIONS = {
    "search_snippet_cache": "search_results",
    "search_cache": "search_results",
    "search_engine_cache_adapter": "search_results",
    "alternate_search_cache_adapter": "search_results",
    "web_archive": "archived_snapshot",
    "internet_archive_snapshot": "internet_archive_snapshot",
    "cdn_copy": "cdn_snapshot",
    "browser_cache": "rendered_html",
    "rag_document_cache": "clean_text",
}

_DEFAULT_TTL_SECONDS = 3_600
_MAX_TTL_SECONDS = 365 * 24 * 60 * 60
_MAX_METADATA_BYTES = 1_000_000
_MAX_RECORDS_PER_KEY = 10_000


class SnapshotIntegrityError(AdapterExecutionError):
    """A snapshot's immutable body or metadata does not match its declaration."""


class CacheDisposition(StrEnum):
    MISS = "MISS"
    FRESH = "FRESH"
    STALE_WHILE_REVALIDATE = "STALE_WHILE_REVALIDATE"
    REVALIDATE = "REVALIDATE"


@dataclass(frozen=True, slots=True)
class ArchivedSnapshot:
    """Bounded result returned by an optional, policy-aware connector."""

    original_url: str
    snapshot_url: str
    body: bytes
    media_type: str
    captured_at: datetime
    etag: str | None = None
    last_modified: str | None = None
    auxiliary_bytes: int = 0

    def __post_init__(self) -> None:
        original = normalize_url(self.original_url)
        snapshot = normalize_url(self.snapshot_url)
        if not snapshot.startswith("https://"):
            raise ValueError("snapshot connector URLs must use HTTPS")
        if self.captured_at.utcoffset() is None:
            raise ValueError("snapshot capture time must include a timezone")
        if not self.body:
            raise ValueError("snapshot connector returned an empty body")
        if not self.media_type.strip() or len(self.media_type) > 255:
            raise ValueError("snapshot media type is invalid")
        if (
            isinstance(self.auxiliary_bytes, bool)
            or not isinstance(self.auxiliary_bytes, int)
            or self.auxiliary_bytes < 0
        ):
            raise ValueError("snapshot auxiliary byte count is invalid")
        object.__setattr__(self, "original_url", original)
        object.__setattr__(self, "snapshot_url", snapshot)
        object.__setattr__(self, "captured_at", self.captured_at.astimezone(UTC))


class SnapshotConnector(Protocol):
    """Optional connector contract.

    Implementations must apply Fetech destination policy to every request and
    redirect, enforce ``maximum_bytes`` while streaming, and must not persist
    credentials or response bodies outside the supplied artifact store.
    """

    async def fetch_snapshot(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        deadline_seconds: float,
    ) -> ArchivedSnapshot: ...


@dataclass(slots=True)
class SnapshotConnectorUsage:
    """Mutable, bounded usage ledger shared with a reporting connector."""

    wire_bytes: int = 0
    decompressed_bytes: int = 0
    redirects: int = 0

    def record(
        self,
        *,
        wire_bytes: int = 0,
        decompressed_bytes: int = 0,
        redirects: int = 0,
    ) -> None:
        values = (wire_bytes, decompressed_bytes, redirects)
        if any(
            isinstance(value, bool) or not isinstance(value, int) or value < 0
            for value in values
        ):
            raise ValueError("snapshot connector usage must be non-negative integers")
        self.wire_bytes += wire_bytes
        self.decompressed_bytes += decompressed_bytes
        self.redirects += redirects


@runtime_checkable
class UsageReportingSnapshotConnector(Protocol):
    """Optional trusted connector boundary with failure-safe usage reporting."""

    async def fetch_snapshot_with_usage(
        self,
        original_url: str,
        *,
        maximum_bytes: int,
        maximum_redirects: int,
        deadline_seconds: float,
        usage: SnapshotConnectorUsage,
    ) -> ArchivedSnapshot: ...


class InternetArchiveProvider(SnapshotConnector, Protocol):
    """Compatibility boundary for overriding the built-in Wayback connector."""


@dataclass(frozen=True, slots=True)
class SnapshotRecord:
    snapshot_id: str
    key_digest: str
    authentication_scope: str
    source_capability: str
    resource: Resource
    artifact: Artifact
    stored_at: datetime
    expires_at: datetime | None
    etag: str | None = None
    last_modified: str | None = None
    successful: bool = True

    def fresh_at(self, now: datetime) -> bool:
        _require_aware(now, "cache lookup time")
        return self.expires_at is None or self.expires_at > now.astimezone(UTC)


@dataclass(frozen=True, slots=True)
class CacheLookup:
    disposition: CacheDisposition
    record: SnapshotRecord | None = None
    usable: bool = False
    requires_revalidation: bool = False


class SnapshotStore:
    """Filesystem metadata index backed by an immutable content-addressed store."""

    def __init__(self, root: Path, cas: FileSystemCAS) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.cas = cas

    async def store(
        self,
        key: CacheKey,
        resource: Resource,
        artifact: Artifact,
        *,
        request: FetchRequest,
        source_capability: str,
        stored_at: datetime | None = None,
        expires_at: datetime | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
        successful: bool = True,
    ) -> SnapshotRecord:
        """Store immutable sanitized metadata after checking the referenced CAS body."""

        supplied_now = stored_at or datetime.now(UTC)
        _require_aware(supplied_now, "snapshot storage time")
        now = supplied_now.astimezone(UTC)
        if expires_at is not None:
            _require_aware(expires_at, "snapshot expiry")
            expires_at = expires_at.astimezone(UTC)
        _validate_validator(etag, "ETag")
        _validate_validator(last_modified, "Last-Modified")
        if source_capability not in CACHE_CAPABILITIES:
            raise ValueError("snapshot source capability is not registered")

        await _verify_artifact(self.cas, artifact)
        sanitized_resource = resource.model_copy(
            update={
                "canonical_url": sanitize_url_for_request(resource.canonical_url, request),
                "requested_url": sanitize_url_for_request(resource.requested_url, request),
                "authority_url": (
                    sanitize_url_for_request(resource.authority_url, request)
                    if resource.authority_url
                    else None
                ),
            }
        )
        sanitized_artifact = Artifact.model_validate(
            sanitize_output_for_request(
                artifact.model_dump(mode="json"),
                request,
            )
        )
        if artifact.source_resource_id != resource.resource_id:
            raise SnapshotIntegrityError("artifact does not belong to the supplied resource")
        snapshot_id = hashlib.sha256(
            (
                "fetech-snapshot-v1\0"
                + key.digest
                + "\0"
                + artifact.sha256
                + "\0"
                + now.isoformat()
                + "\0"
                + source_capability
            ).encode("utf-8")
        ).hexdigest()
        record = SnapshotRecord(
            snapshot_id=snapshot_id,
            key_digest=key.digest,
            authentication_scope=key.authentication_scope,
            source_capability=source_capability,
            resource=sanitized_resource,
            artifact=sanitized_artifact,
            stored_at=now,
            expires_at=expires_at,
            etag=etag,
            last_modified=last_modified,
            successful=successful,
        )
        document = _record_document(record)
        encoded = json.dumps(
            document,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        if len(encoded) > _MAX_METADATA_BYTES:
            raise SnapshotIntegrityError("snapshot metadata exceeds the storage bound")
        path = self._record_path(key.digest, snapshot_id)
        await asyncio.to_thread(_write_immutable, path, encoded)
        return record

    async def latest_successful(self, key: CacheKey) -> SnapshotRecord | None:
        records = await self._records(key)
        candidates = [record for record in records if record.successful]
        if not candidates:
            return None
        selected = max(candidates, key=lambda record: (record.stored_at, record.snapshot_id))
        await _verify_artifact(self.cas, selected.artifact)
        return selected

    async def lookup(
        self,
        key: CacheKey,
        *,
        now: datetime | None = None,
        stale_while_revalidate_seconds: int = 0,
    ) -> CacheLookup:
        if not 0 <= stale_while_revalidate_seconds <= _MAX_TTL_SECONDS:
            raise ValueError("stale-while-revalidate seconds are outside the allowed bound")
        current = now or datetime.now(UTC)
        _require_aware(current, "cache lookup time")
        current = current.astimezone(UTC)
        record = await self.latest_successful(key)
        if record is None:
            return CacheLookup(CacheDisposition.MISS)
        if record.fresh_at(current):
            return CacheLookup(CacheDisposition.FRESH, record, usable=True)
        assert record.expires_at is not None
        stale_until = record.expires_at + timedelta(seconds=stale_while_revalidate_seconds)
        if stale_while_revalidate_seconds and current <= stale_until:
            return CacheLookup(
                CacheDisposition.STALE_WHILE_REVALIDATE,
                record,
                usable=True,
                requires_revalidation=True,
            )
        return CacheLookup(
            CacheDisposition.REVALIDATE,
            record,
            requires_revalidation=True,
        )

    async def record_not_modified(
        self,
        key: CacheKey,
        record: SnapshotRecord,
        *,
        request: FetchRequest,
        ttl_seconds: int,
        checked_at: datetime | None = None,
        etag: str | None = None,
        last_modified: str | None = None,
    ) -> SnapshotRecord:
        ttl = _bounded_seconds(ttl_seconds, "cache TTL")
        current = checked_at or datetime.now(UTC)
        _require_aware(current, "revalidation time")
        current = current.astimezone(UTC)
        if record.key_digest != key.digest:
            raise SnapshotIntegrityError("revalidation record does not match the cache key")
        return await self.store(
            key,
            record.resource,
            record.artifact,
            request=request,
            source_capability=record.source_capability,
            stored_at=current,
            expires_at=current + timedelta(seconds=ttl),
            etag=etag if etag is not None else record.etag,
            last_modified=(
                last_modified if last_modified is not None else record.last_modified
            ),
        )

    def conditional_headers(self, record: SnapshotRecord) -> dict[str, str]:
        headers: dict[str, str] = {}
        if record.etag:
            headers["If-None-Match"] = record.etag
        if record.last_modified:
            headers["If-Modified-Since"] = record.last_modified
        return headers

    def _record_path(self, key_digest: str, snapshot_id: str) -> Path:
        _require_digest(key_digest, "cache key")
        _require_digest(snapshot_id, "snapshot")
        directory = self.root / key_digest[:2] / key_digest
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        return directory / f"{snapshot_id}.json"

    async def _records(self, key: CacheKey) -> tuple[SnapshotRecord, ...]:
        _require_digest(key.digest, "cache key")
        directory = self.root / key.digest[:2] / key.digest
        if not directory.exists():
            return ()
        if directory.is_symlink() or not directory.is_dir():
            raise SnapshotIntegrityError("snapshot partition must be a regular directory")
        paths = await asyncio.to_thread(lambda: sorted(directory.glob("*.json")))
        if len(paths) > _MAX_RECORDS_PER_KEY:
            raise SnapshotIntegrityError("snapshot record count exceeds the lookup bound")
        records: list[SnapshotRecord] = []
        for path in paths:
            if path.is_symlink() or not path.is_file():
                raise SnapshotIntegrityError("snapshot metadata must be a regular file")
            encoded = await asyncio.to_thread(_read_bounded, path, _MAX_METADATA_BYTES)
            record = _parse_record(encoded)
            if (
                record.key_digest != key.digest
                or record.authentication_scope != key.authentication_scope
            ):
                raise SnapshotIntegrityError("snapshot metadata does not match the cache partition")
            records.append(record)
        return tuple(records)


class CacheAdapter:
    """Execute all 11 cache/snapshot/archive manifest capabilities."""

    def __init__(
        self,
        store: SnapshotStore,
        *,
        connectors: Mapping[str, SnapshotConnector] | None = None,
        policy: SafeURLPolicy | None = None,
    ) -> None:
        invalid = set(connectors or {}) - CONNECTOR_CAPABILITIES
        if invalid:
            raise ValueError(f"unknown cache connectors: {sorted(invalid)}")
        self.store = store
        self.connectors = dict(connectors or {})
        self.policy = policy

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            adapter_version="0.4.0a0",
            sanitized_destination=sanitize_url_for_request(
                context.request.target,
                context.request,
            ),
            status=AttemptStatus.RUNNING,
        )
        index = len(context.attempts)
        context.attempts.append(attempt)
        try:
            if node.capability_id not in CACHE_CAPABILITIES:
                raise AdapterExecutionError(
                    f"cache adapter cannot execute {node.capability_id}"
                )
            if self.policy is not None:
                _, decisions = await self.policy.evaluate(
                    normalize_url(context.request.target)
                )
                context.policy_decisions.extend(decisions)
                for decision in decisions:
                    context.record_outcome(
                        decision.policy_id,
                        CapabilityOutcomeStatus.APPLIED,
                        "security",
                        reason=decision.reason,
                    )
            if node.capability_id in CONNECTOR_CAPABILITIES:
                artifact = await self._execute_connector(
                    node,
                    context,
                    attempt_index=index,
                )
                parser = f"configured-{node.capability_id}"
            else:
                artifact = await self._execute_storage(node, context)
                parser = "validated-snapshot-cache"
            current_attempt = context.attempts[index]
            context.attempts[index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.SUCCEEDED,
                    "finished_at": datetime.now(UTC),
                    "bytes_received": artifact.size,
                    "parser": parser,
                    "artifact_ids": (artifact.artifact_id,),
                }
            )
        except AdapterDependencyError:
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.DEPENDENCY_MISSING,
                "cache",
                reason="configured connector is unavailable",
            )
            current_attempt = context.attempts[index]
            context.attempts[index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "dependency_missing",
                }
            )
            raise
        except AdapterBudgetExceededError as exc:
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "cache",
                reason=str(exc),
            )
            current_attempt = context.attempts[index]
            context.attempts[index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "budget_exhausted",
                    "warnings": (str(exc),),
                }
            )
            raise
        except TimeoutError:
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "cache",
                reason="snapshot connector deadline budget exhausted",
            )
            current_attempt = context.attempts[index]
            context.attempts[index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "budget_exhausted",
                    "warnings": (
                        "snapshot connector deadline budget exhausted",
                    ),
                }
            )
            raise
        except PolicyBlockedError:
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.BLOCKED,
                "cache",
                reason="third-party cache connectors require a public unauthenticated request",
            )
            current_attempt = context.attempts[index]
            context.attempts[index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "policy",
                }
            )
            raise
        except (AdapterExecutionError, SnapshotIntegrityError) as exc:
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "cache",
                reason=str(exc),
            )
            current_attempt = context.attempts[index]
            context.attempts[index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": _failure_code(exc),
                    "warnings": (str(exc),),
                }
            )
            raise

    async def _execute_storage(
        self,
        node: PlanNode,
        context: ExecutionContext,
    ) -> Artifact:
        operation = str(node.parameters.get("cache_operation", "")).strip().lower()
        latest = context.latest_artifact()
        if not operation:
            operation = (
                "lookup"
                if node.capability_id == "previous_successful_snapshot" or latest is None
                else "store"
            )
        if operation not in {"store", "lookup", "not_modified"}:
            raise AdapterExecutionError("cache operation must be store, lookup, or not_modified")
        representation = _representation(node, latest)
        if operation == "store":
            resource, artifact = _validated_source(
                context,
                representation=representation,
            )
            parser_version = _parser_version(node, artifact)
            key = CacheKey.for_request(
                context.request,
                url=normalize_url(context.request.target),
                representation=representation,
                parser_version=parser_version,
                vary=_vary_values(node),
            )
            ttl = _ttl_seconds(node, context)
            now = datetime.now(UTC)
            await self.store.store(
                key,
                resource,
                artifact,
                request=context.request,
                source_capability=node.capability_id,
                stored_at=now,
                expires_at=now + timedelta(seconds=ttl),
                etag=_optional_parameter(node, "etag"),
                last_modified=_optional_parameter(node, "last_modified"),
            )
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.APPLIED,
                "cache",
                operation="store",
                key_digest=key.digest,
                authentication_scope=key.authentication_scope,
                immutable=True,
            )
            context.record_runtime_event(
                "snapshot_stored",
                "cache",
                capability_id=node.capability_id,
                key_digest=key.digest,
                artifact_sha256=artifact.sha256,
            )
            context.accepted = True
            return artifact

        parser_version = _parser_version(node, latest)
        key = CacheKey.for_request(
            context.request,
            url=normalize_url(context.request.target),
            representation=representation,
            parser_version=parser_version,
            vary=_vary_values(node),
        )
        stale_seconds = _parameter_seconds(node, "stale_while_revalidate_seconds", 0)
        lookup = await self.store.lookup(
            key,
            stale_while_revalidate_seconds=stale_seconds,
        )
        context.record_outcome(
            "cache_expiry_check",
            CapabilityOutcomeStatus.APPLIED,
            "cache",
            disposition=lookup.disposition.value,
            record_found=lookup.record is not None,
            fresh=lookup.disposition == CacheDisposition.FRESH,
            usable=lookup.usable,
            requires_revalidation=lookup.requires_revalidation,
        )
        if lookup.record is None:
            raise AdapterExecutionError("validated cache miss")
        record = lookup.record
        if operation == "not_modified":
            ttl = _ttl_seconds(node, context)
            record = await self.store.record_not_modified(
                key,
                record,
                request=context.request,
                ttl_seconds=ttl,
                etag=_optional_parameter(node, "etag"),
                last_modified=_optional_parameter(node, "last_modified"),
            )
            disposition = "NOT_MODIFIED"
        else:
            disposition = lookup.disposition.value
            if (
                lookup.disposition == CacheDisposition.REVALIDATE
                and node.capability_id != "previous_successful_snapshot"
            ):
                raise AdapterExecutionError("cache entry requires revalidation")
        _merge_snapshot(context, record)
        if lookup.requires_revalidation:
            context.record_runtime_event(
                "cache_revalidation_required",
                "cache",
                capability_id=node.capability_id,
                key_digest=key.digest,
                disposition=lookup.disposition.value,
            )
        context.record_outcome(
            node.capability_id,
            CapabilityOutcomeStatus.APPLIED,
            "cache",
            operation=operation,
            disposition=disposition,
            key_digest=key.digest,
            authentication_scope=key.authentication_scope,
        )
        return record.artifact

    async def _execute_connector(
        self,
        node: PlanNode,
        context: ExecutionContext,
        *,
        attempt_index: int,
    ) -> Artifact:
        if (
            context.request.authentication_ref is not None
            or context.request.privacy_profile != "public"
        ):
            raise PolicyBlockedError(
                "third-party cache connectors require a public unauthenticated request"
            )
        connector = self.connectors.get(node.capability_id)
        if connector is None:
            raise AdapterDependencyError(
                f"{node.capability_id} requires a configured snapshot connector"
            )
        target = normalize_url(context.request.target)
        if sanitize_url(target) != target:
            raise PolicyBlockedError(
                "third-party cache connectors cannot receive sensitive URL query values"
            )
        remaining_wire_bytes = int(context.remaining_budget("bytes"))
        remaining_decompressed_bytes = int(
            context.remaining_budget("decompressed_bytes")
        )
        context.require_budget("bytes", 1)
        context.require_budget("decompressed_bytes", 1)
        maximum_body_bytes = min(
            remaining_wire_bytes,
            remaining_decompressed_bytes,
        )
        usage_connector = (
            cast(UsageReportingSnapshotConnector, connector)
            if isinstance(connector, UsageReportingSnapshotConnector)
            else None
        )
        usage_reporting = usage_connector is not None
        try:
            if usage_connector is not None:
                usage = SnapshotConnectorUsage()
                remaining_redirects = int(context.remaining_budget("redirects"))
                try:
                    result = await usage_connector.fetch_snapshot_with_usage(
                        target,
                        maximum_bytes=maximum_body_bytes,
                        maximum_redirects=remaining_redirects,
                        deadline_seconds=_remaining_connector_deadline(context),
                        usage=usage,
                    )
                    _reconcile_connector_result_usage(
                        result,
                        usage=usage,
                        maximum_body_bytes=maximum_body_bytes,
                    )
                finally:
                    _charge_connector_usage(
                        context,
                        attempt_index=attempt_index,
                        usage=usage,
                        remaining_wire_bytes=remaining_wire_bytes,
                        remaining_decompressed_bytes=remaining_decompressed_bytes,
                        remaining_redirects=remaining_redirects,
                    )
            else:
                result = await connector.fetch_snapshot(
                    target,
                    maximum_bytes=maximum_body_bytes,
                    deadline_seconds=context.request.budget.deadline_seconds,
                )
        except (
            AdapterBudgetExceededError,
            AdapterDependencyError,
            AdapterNotFoundError,
            PolicyBlockedError,
            TimeoutError,
        ):
            raise
        except Exception as exc:
            raise AdapterExecutionError("configured snapshot connector failed") from exc
        if (
            not usage_reporting
            and isinstance(result, ArchivedSnapshot)
            and type(result.body) is bytes
        ):
            consumed_bytes = len(result.body) + result.auxiliary_bytes
            context.record_attempt_consumption(
                attempt_index,
                bytes=consumed_bytes,
                decompressed_bytes=consumed_bytes,
            )
            if consumed_bytes > remaining_wire_bytes:
                raise AdapterBudgetExceededError("bytes budget exhausted")
            if consumed_bytes > remaining_decompressed_bytes:
                raise AdapterBudgetExceededError(
                    "decompressed_bytes budget exhausted"
                )
        snapshot = _validated_connector_snapshot(result)
        if normalize_url(snapshot.original_url) != target:
            raise AdapterExecutionError("snapshot connector changed the original source authority")
        if node.capability_id == "internet_archive_snapshot":
            archive_host = sanitize_url(snapshot.snapshot_url).split("/", maxsplit=3)[2]
            if archive_host != "web.archive.org":
                raise AdapterExecutionError(
                    "Internet Archive snapshots must originate from web.archive.org"
                )
        uri, digest, size = await context.cas.put(snapshot.body)
        resource = Resource(
            canonical_url=sanitize_url_for_request(target, context.request),
            requested_url=sanitize_url_for_request(snapshot.snapshot_url, context.request),
            authority_url=sanitize_url_for_request(target, context.request),
            media_type=snapshot.media_type,
            status_code=200,
            retrieved_at=snapshot.captured_at,
        )
        quality = (
            assess_text(
                snapshot.body.decode("utf-8", errors="replace"),
                media_type=snapshot.media_type,
                expected_language=context.request.language,
            )
            if _is_textual(snapshot.media_type)
            else assess_binary(len(snapshot.body), media_type=snapshot.media_type)
        )
        artifact = build_artifact(
            role="primary" if quality.accepted else "checked-only",
            representation=_REPRESENTATIONS[node.capability_id],
            media_type=snapshot.media_type,
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor=f"configured-cache-connector/{node.capability_id}/0.4",
            quality=quality,
            locators=(f"captured:{snapshot.captured_at.isoformat()}",),
        )
        context.resources.append(resource)
        context.artifacts.append(artifact)
        context.accepted = context.accepted or quality.accepted
        context.record_quality_outcomes(quality, stage="cache")
        key = CacheKey.for_request(
            context.request,
            url=target,
            representation=artifact.representation,
            parser_version=artifact.extractor_version,
        )
        ttl = _ttl_seconds(node, context)
        now = datetime.now(UTC)
        await self.store.store(
            key,
            resource,
            artifact,
            request=context.request,
            source_capability=node.capability_id,
            stored_at=now,
            expires_at=now + timedelta(seconds=ttl),
            etag=snapshot.etag,
            last_modified=snapshot.last_modified,
            successful=quality.accepted,
        )
        context.record_outcome(
            node.capability_id,
            CapabilityOutcomeStatus.APPLIED,
            "cache",
            operation="connector",
            original_authority_preserved=True,
            accepted=quality.accepted,
            page_state=quality.page_state.value,
            key_digest=key.digest,
        )
        context.record_runtime_event(
            (
                "snapshot_connector_succeeded"
                if quality.accepted
                else "snapshot_connector_checked_only"
            ),
            "cache",
            capability_id=node.capability_id,
            key_digest=key.digest,
            artifact_sha256=artifact.sha256,
        )
        return artifact


async def _verify_artifact(cas: FileSystemCAS, artifact: Artifact) -> None:
    expected_uri = f"cas://sha256/{artifact.sha256}"
    if artifact.cas_uri != expected_uri:
        raise SnapshotIntegrityError("artifact CAS URI and SHA-256 disagree")
    try:
        body = await cas.get(artifact.cas_uri, maximum_bytes=artifact.size)
    except CASIntegrityError as exc:
        raise SnapshotIntegrityError(
            "snapshot artifact size or SHA-256 verification failed"
        ) from exc
    except (OSError, ValueError) as exc:
        raise SnapshotIntegrityError("snapshot artifact is unavailable or exceeds its bound") from exc
    if len(body) != artifact.size:
        raise SnapshotIntegrityError("snapshot artifact size does not match metadata")
    if hashlib.sha256(body).hexdigest() != artifact.sha256:
        raise SnapshotIntegrityError("snapshot artifact SHA-256 verification failed")


def _validated_source(
    context: ExecutionContext,
    *,
    representation: str,
) -> tuple[Resource, Artifact]:
    artifact = context.latest_artifact(representation)
    if artifact is None or not context.resources:
        raise AdapterExecutionError(
            f"cache storage requires an accepted {representation} artifact"
        )
    if not artifact.quality.accepted or artifact.role == "checked-only":
        raise AdapterExecutionError("only validated accepted artifacts may enter the cache")
    for resource in reversed(context.resources):
        if resource.resource_id == artifact.source_resource_id:
            return resource, artifact
    raise SnapshotIntegrityError("artifact source resource is absent from the execution context")


def _merge_snapshot(context: ExecutionContext, record: SnapshotRecord) -> None:
    if all(item.resource_id != record.resource.resource_id for item in context.resources):
        context.resources.append(record.resource)
    if all(item.artifact_id != record.artifact.artifact_id for item in context.artifacts):
        context.artifacts.append(record.artifact)
    context.accepted = context.accepted or record.artifact.quality.accepted


def _representation(node: PlanNode, artifact: Artifact | None) -> str:
    configured = node.parameters.get("representation")
    required = _REPRESENTATIONS.get(node.capability_id)
    if configured is not None:
        if not isinstance(configured, str) or not configured.strip() or len(configured) > 200:
            raise AdapterExecutionError("cache representation parameter is invalid")
        selected = configured.strip()
        if required is not None and selected != required:
            raise AdapterExecutionError(
                f"{node.capability_id} requires a {required} artifact"
            )
        return selected
    if required is not None:
        return required
    if artifact is not None:
        return artifact.representation
    raise AdapterExecutionError("snapshot lookup requires an explicit representation")


def _validated_connector_snapshot(value: object) -> ArchivedSnapshot:
    if not isinstance(value, ArchivedSnapshot):
        raise AdapterExecutionError(
            "configured snapshot connector returned an invalid result"
        )
    if type(value.body) is not bytes:
        raise AdapterExecutionError(
            "configured snapshot connector returned an invalid result"
        )
    try:
        return ArchivedSnapshot(
            original_url=value.original_url,
            snapshot_url=value.snapshot_url,
            body=value.body,
            media_type=value.media_type,
            captured_at=value.captured_at,
            etag=value.etag,
            last_modified=value.last_modified,
        )
    except (AttributeError, TypeError, ValueError) as exc:
        raise AdapterExecutionError(
            "configured snapshot connector returned an invalid result"
        ) from exc


def _remaining_connector_deadline(context: ExecutionContext) -> float:
    if not context.attempts:
        return context.request.budget.deadline_seconds
    execution_started = min(
        attempt.started_at.astimezone(UTC) for attempt in context.attempts
    )
    elapsed = max(
        0.0,
        (datetime.now(UTC) - execution_started).total_seconds(),
    )
    remaining = context.request.budget.deadline_seconds - elapsed
    if remaining <= 0:
        raise AdapterBudgetExceededError("deadline budget exhausted")
    return remaining


def _charge_connector_usage(
    context: ExecutionContext,
    *,
    attempt_index: int,
    usage: SnapshotConnectorUsage,
    remaining_wire_bytes: int,
    remaining_decompressed_bytes: int,
    remaining_redirects: int,
) -> None:
    values = (usage.wire_bytes, usage.decompressed_bytes, usage.redirects)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in values
    ):
        raise AdapterExecutionError(
            "configured snapshot connector returned invalid usage"
        )
    consumption = {
        name: value
        for name, value in {
            "bytes": usage.wire_bytes,
            "decompressed_bytes": usage.decompressed_bytes,
            "redirects": usage.redirects,
        }.items()
        if value
    }
    if consumption:
        context.record_attempt_consumption(attempt_index, **consumption)
    if usage.wire_bytes > remaining_wire_bytes:
        raise AdapterBudgetExceededError("bytes budget exhausted")
    if usage.decompressed_bytes > remaining_decompressed_bytes:
        raise AdapterBudgetExceededError("decompressed_bytes budget exhausted")
    if usage.redirects > remaining_redirects:
        raise AdapterBudgetExceededError("redirects budget exhausted")


def _reconcile_connector_result_usage(
    result: object,
    *,
    usage: SnapshotConnectorUsage,
    maximum_body_bytes: int,
) -> None:
    """Reject dishonest reporting while preserving a conservative usage floor."""

    if not isinstance(result, ArchivedSnapshot) or type(result.body) is not bytes:
        return
    values = (usage.wire_bytes, usage.decompressed_bytes, usage.redirects)
    if any(
        isinstance(value, bool) or not isinstance(value, int) or value < 0
        for value in values
    ):
        return

    body_bytes = len(result.body)
    accounted_body_bytes = body_bytes + result.auxiliary_bytes
    underreported = (
        usage.wire_bytes < accounted_body_bytes
        or usage.decompressed_bytes < accounted_body_bytes
    )
    usage.wire_bytes = max(usage.wire_bytes, accounted_body_bytes)
    usage.decompressed_bytes = max(
        usage.decompressed_bytes,
        accounted_body_bytes,
    )
    if body_bytes > maximum_body_bytes:
        raise AdapterBudgetExceededError(
            "snapshot connector body exceeds the remaining byte budget"
        )
    if underreported:
        raise AdapterExecutionError(
            "configured snapshot connector under-reported body usage"
        )


def _is_textual(media_type: str) -> bool:
    normalized = media_type.casefold()
    return normalized.startswith("text/") or normalized in {
        "application/atom+xml",
        "application/json",
        "application/rss+xml",
        "application/xhtml+xml",
        "application/xml",
    }


def _parser_version(node: PlanNode, artifact: Artifact | None) -> str:
    configured = node.parameters.get("parser_version")
    if configured is not None:
        if not isinstance(configured, str) or not configured.strip() or len(configured) > 200:
            raise AdapterExecutionError("cache parser_version parameter is invalid")
        return configured.strip()
    if artifact is not None:
        return artifact.extractor_version
    raise AdapterExecutionError("snapshot lookup requires an explicit parser_version")


def _vary_values(node: PlanNode) -> tuple[tuple[str, str], ...]:
    configured = node.parameters.get("vary", ())
    if configured in (None, ()):
        return ()
    if (
        not isinstance(configured, list | tuple)
        or len(configured) > 32
        or any(
            not isinstance(pair, list | tuple)
            or len(pair) != 2
            or not all(isinstance(item, str) for item in pair)
            for pair in configured
        )
    ):
        raise AdapterExecutionError("cache Vary parameters are invalid")
    normalized = tuple(sorted((str(pair[0]).lower(), str(pair[1])) for pair in configured))
    if any(len(name) > 256 or len(value) > 8_192 for name, value in normalized):
        raise AdapterExecutionError("cache Vary parameters exceed the allowed bound")
    return normalized


def _ttl_seconds(node: PlanNode, context: ExecutionContext) -> int:
    default = (
        context.request.freshness_seconds
        if context.request.freshness_seconds is not None
        else _DEFAULT_TTL_SECONDS
    )
    return _parameter_seconds(node, "ttl_seconds", default, minimum=0)


def _parameter_seconds(
    node: PlanNode,
    name: str,
    default: int,
    *,
    minimum: int = 0,
) -> int:
    value = node.parameters.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise AdapterExecutionError(f"{name} must be an integer")
    if not minimum <= value <= _MAX_TTL_SECONDS:
        raise AdapterExecutionError(f"{name} is outside the allowed bound")
    return value


def _bounded_seconds(value: int, label: str) -> int:
    if isinstance(value, bool) or not 0 <= value <= _MAX_TTL_SECONDS:
        raise ValueError(f"{label} is outside the allowed bound")
    return value


def _optional_parameter(node: PlanNode, name: str) -> str | None:
    value = node.parameters.get(name)
    if value is None:
        return None
    if not isinstance(value, str):
        raise AdapterExecutionError(f"{name} must be a string")
    _validate_validator(value, name)
    return value


def _validate_validator(value: str | None, label: str) -> None:
    if value is not None and (
        not value.strip()
        or len(value.encode("utf-8")) > 8_192
        or "\r" in value
        or "\n" in value
    ):
        raise ValueError(f"{label} cache validator is invalid")


def _record_document(record: SnapshotRecord) -> dict[str, Any]:
    return {
        "schema_version": "1.0",
        "snapshot_id": record.snapshot_id,
        "key_digest": record.key_digest,
        "authentication_scope": record.authentication_scope,
        "source_capability": record.source_capability,
        "resource": record.resource.model_dump(mode="json"),
        "artifact": record.artifact.model_dump(mode="json"),
        "stored_at": record.stored_at.isoformat(),
        "expires_at": record.expires_at.isoformat() if record.expires_at else None,
        "etag": record.etag,
        "last_modified": record.last_modified,
        "successful": record.successful,
    }


def _parse_record(encoded: bytes) -> SnapshotRecord:
    try:
        document = json.loads(encoded)
        if not isinstance(document, dict) or document.get("schema_version") != "1.0":
            raise ValueError("unsupported snapshot metadata")
        if not isinstance(document.get("successful"), bool):
            raise ValueError("snapshot success marker must be boolean")
        stored_at = datetime.fromisoformat(str(document["stored_at"]))
        _require_aware(stored_at, "snapshot storage time")
        expires_at = (
            datetime.fromisoformat(str(document["expires_at"]))
            if document.get("expires_at") is not None
            else None
        )
        if expires_at is not None:
            _require_aware(expires_at, "snapshot expiry")
        record = SnapshotRecord(
            snapshot_id=str(document["snapshot_id"]),
            key_digest=str(document["key_digest"]),
            authentication_scope=str(document["authentication_scope"]),
            source_capability=str(document["source_capability"]),
            resource=Resource.model_validate(document["resource"]),
            artifact=Artifact.model_validate(document["artifact"]),
            stored_at=stored_at.astimezone(UTC),
            expires_at=expires_at.astimezone(UTC) if expires_at is not None else None,
            etag=str(document["etag"]) if document.get("etag") is not None else None,
            last_modified=(
                str(document["last_modified"])
                if document.get("last_modified") is not None
                else None
            ),
            successful=document["successful"],
        )
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SnapshotIntegrityError("snapshot metadata is malformed") from exc
    _require_digest(record.snapshot_id, "snapshot")
    _require_digest(record.key_digest, "cache key")
    if record.source_capability not in CACHE_CAPABILITIES:
        raise SnapshotIntegrityError("snapshot metadata names an unknown capability")
    _require_aware(record.stored_at, "snapshot storage time")
    if record.expires_at is not None:
        _require_aware(record.expires_at, "snapshot expiry")
    _validate_validator(record.etag, "ETag")
    _validate_validator(record.last_modified, "Last-Modified")
    return record


def _write_immutable(path: Path, encoded: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    published = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError:
            if _read_existing_immutable(path) != encoded:
                raise SnapshotIntegrityError(
                    "immutable snapshot metadata collision"
                ) from None
        else:
            _fsync_directory(path.parent)
            published = True
    finally:
        temporary_path.unlink(missing_ok=True)
        if published:
            _fsync_directory(path.parent)


def _read_existing_immutable(path: Path) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_NONBLOCK"):
        flags |= os.O_NONBLOCK
    try:
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise SnapshotIntegrityError(
            "immutable snapshot metadata path is unsafe"
        ) from exc
    try:
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise SnapshotIntegrityError(
                "immutable snapshot metadata path is unsafe"
            )
        with os.fdopen(descriptor, "rb", closefd=False) as handle:
            body = handle.read(_MAX_METADATA_BYTES + 1)
    finally:
        os.close(descriptor)
    if len(body) > _MAX_METADATA_BYTES:
        raise SnapshotIntegrityError("snapshot metadata exceeds the read bound")
    return body


def _fsync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    unsupported = {
        errno.EBADF,
        errno.EINVAL,
        getattr(errno, "ENOTSUP", errno.EINVAL),
        getattr(errno, "EOPNOTSUPP", errno.EINVAL),
    }
    try:
        descriptor = os.open(directory, flags)
    except OSError as exc:
        if exc.errno in unsupported:
            return
        raise
    try:
        try:
            os.fsync(descriptor)
        except OSError as exc:
            if exc.errno not in unsupported:
                raise
    finally:
        os.close(descriptor)


def _read_bounded(path: Path, maximum_bytes: int) -> bytes:
    with path.open("rb") as handle:
        body = handle.read(maximum_bytes + 1)
    if len(body) > maximum_bytes:
        raise SnapshotIntegrityError("snapshot metadata exceeds the read bound")
    return body


def _require_digest(value: str, label: str) -> None:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SnapshotIntegrityError(f"{label} digest is invalid")


def _require_aware(value: datetime, label: str) -> None:
    if value.utcoffset() is None:
        raise ValueError(f"{label} must include a timezone")


def _failure_code(exc: BaseException) -> str:
    if isinstance(exc, AdapterNotFoundError):
        return "not_found"
    if isinstance(exc, SnapshotIntegrityError):
        return "snapshot_integrity"
    message = str(exc)
    if "miss" in message:
        return "cache_miss"
    if "revalidation" in message:
        return "cache_revalidation_required"
    return "cache_error"
