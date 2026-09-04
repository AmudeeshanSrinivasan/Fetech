"""Bounded retention, crash recovery, and garbage collection for local storage."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from fetech.adapters.cache import SnapshotMaintenanceReport, SnapshotStore
from fetech.ledger import EventLedger, LedgerRetentionReport
from fetech.storage import (
    CASMaintenanceReport,
    FileSystemCAS,
    StorageQuota,
    StorageUsage,
)


@dataclass(frozen=True, slots=True)
class StorageLifecyclePolicy:
    run_retention_seconds: int = 0
    snapshot_retention_seconds: int = 7 * 24 * 60 * 60
    orphan_grace_seconds: int = 24 * 60 * 60
    maximum_snapshot_records: int = 100_000
    maximum_retired_runs_per_startup: int = 1_000
    maximum_scan_entries: int = 200_000

    def __post_init__(self) -> None:
        durations = (
            self.run_retention_seconds,
            self.snapshot_retention_seconds,
            self.orphan_grace_seconds,
        )
        if any(
            isinstance(value, bool)
            or not isinstance(value, int)
            or not 0 <= value <= 10 * 365 * 24 * 60 * 60
            for value in durations
        ):
            raise ValueError("storage lifecycle duration is outside the allowed bound")
        if not 1 <= self.maximum_snapshot_records <= 1_000_000:
            raise ValueError("snapshot record limit is outside the allowed bound")
        if not 1 <= self.maximum_retired_runs_per_startup <= 10_000:
            raise ValueError("ledger retirement batch limit is outside the allowed bound")
        if not 1 <= self.maximum_scan_entries <= 1_000_000:
            raise ValueError("storage scan entry bound is outside the allowed bound")


@dataclass(frozen=True, slots=True)
class StorageMaintenanceReport:
    started_at: datetime
    finished_at: datetime
    ledger: LedgerRetentionReport
    snapshots: SnapshotMaintenanceReport
    cas: CASMaintenanceReport
    usage: StorageUsage


class LocalStorageLifecycle:
    """Own startup-only lifecycle maintenance for one single-tenant daemon."""

    def __init__(
        self,
        *,
        ledger: EventLedger,
        cas: FileSystemCAS,
        snapshots: SnapshotStore,
        quota: StorageQuota,
        policy: StorageLifecyclePolicy,
    ) -> None:
        if (
            ledger.quota is not quota
            or cas.quota is not quota
            or snapshots.quota is not quota
        ):
            raise ValueError("storage lifecycle components must share one quota")
        if snapshots.maximum_records != policy.maximum_snapshot_records:
            raise ValueError("snapshot store and lifecycle limits must agree")
        self.ledger = ledger
        self.cas = cas
        self.snapshots = snapshots
        self.quota = quota
        self.policy = policy

    async def maintain(self, *, now: datetime | None = None) -> StorageMaintenanceReport:
        current = now or datetime.now(UTC)
        if current.utcoffset() is None:
            raise ValueError("storage maintenance time must include a timezone")
        current = current.astimezone(UTC)
        ledger_report = LedgerRetentionReport()
        if self.policy.run_retention_seconds:
            ledger_report = await self.ledger.retire_finished_runs(
                before=current - timedelta(seconds=self.policy.run_retention_seconds),
                maximum_runs=self.policy.maximum_retired_runs_per_startup,
                retired_at=current,
            )
        snapshot_report = await self.snapshots.maintain(
            retention_seconds=self.policy.snapshot_retention_seconds,
            now=current,
            maximum_entries=self.policy.maximum_scan_entries,
        )
        ledger_artifacts = await self.ledger.artifacts()
        live_uris = {
            *(artifact.cas_uri for artifact in ledger_artifacts),
            *snapshot_report.live_cas_uris,
        }
        cas_report = await self.cas.maintain(
            live_uris,
            orphan_grace_seconds=self.policy.orphan_grace_seconds,
            now=current,
            maximum_entries=self.policy.maximum_scan_entries,
        )
        usage = await self.quota.ensure_available(use_ledger_headroom=True)
        return StorageMaintenanceReport(
            started_at=current,
            finished_at=datetime.now(UTC),
            ledger=ledger_report,
            snapshots=snapshot_report,
            cas=cas_report,
            usage=usage,
        )
