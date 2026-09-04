"""Runtime configuration with safe single-tenant defaults."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from fetech.docling_artifacts import DOCLING_REFERENCE_BUNDLE_SHA256
from fetech.version import DEFAULT_USER_AGENT


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    database_path: Path
    artifact_dir: Path
    runtime_graph_path: Path
    user_agent: str = DEFAULT_USER_AGENT
    global_concurrency: int = 8
    per_host_concurrency: int = 2
    per_host_min_interval_seconds: float = 0.1
    planner_backend: str = "python"
    reasoner_backend: str = "python"
    logic_fallback: bool = True
    logic_timeout_seconds: float = 3.0
    logic_memory_mb: int = 512
    logic_solution_limit: int = 1
    clingo_executable: str = "clingo"
    prolog_executable: str = "swipl"
    jina_reader_template: str | None = None
    puppeteer_connector_url: str | None = None
    selenium_connector_url: str | None = None
    search_provider_template: str | None = None
    docling_artifacts_path: Path | None = None
    docling_artifacts_sha256: str | None = None
    docling_worker_memory_mb: int = 4_096
    worker_isolation_mode: str = "development"
    worker_bwrap_executable: Path = Path("/usr/bin/bwrap")
    worker_cgroup_root: Path | None = None
    browser_artifacts_path: Path | None = None
    storage_max_bytes: int = 10 * 1024 * 1024 * 1024
    storage_run_retention_seconds: int = 0
    storage_snapshot_retention_seconds: int = 7 * 24 * 60 * 60
    storage_orphan_grace_seconds: int = 24 * 60 * 60
    storage_max_snapshot_records: int = 100_000
    storage_max_retired_runs_per_startup: int = 1_000
    storage_max_scan_entries: int = 200_000

    @classmethod
    def from_environment(cls) -> Settings:
        data_dir = Path(os.environ.get("FETECH_DATA_DIR", ".fetech")).expanduser().resolve()
        raw_docling_artifacts_path = os.environ.get(
            "FETECH_DOCLING_ARTIFACTS_PATH"
        )
        raw_docling_artifacts_sha256 = os.environ.get(
            "FETECH_DOCLING_ARTIFACTS_SHA256"
        )
        raw_worker_cgroup_root = os.environ.get("FETECH_WORKER_CGROUP_ROOT")
        raw_browser_artifacts_path = os.environ.get(
            "FETECH_BROWSER_ARTIFACTS_PATH"
        )
        return cls(
            data_dir=data_dir,
            database_path=data_dir / "ledger.sqlite3",
            artifact_dir=data_dir / "artifacts",
            runtime_graph_path=data_dir / "runtime-graphify" / "graph.json",
            user_agent=os.environ.get(
                "FETECH_USER_AGENT",
                DEFAULT_USER_AGENT,
            ),
            global_concurrency=max(1, int(os.environ.get("FETECH_GLOBAL_CONCURRENCY", "8"))),
            per_host_concurrency=max(1, int(os.environ.get("FETECH_PER_HOST_CONCURRENCY", "2"))),
            per_host_min_interval_seconds=max(
                0.0, float(os.environ.get("FETECH_PER_HOST_MIN_INTERVAL_SECONDS", "0.1"))
            ),
            planner_backend=os.environ.get("FETECH_PLANNER_BACKEND", "python").lower(),
            reasoner_backend=os.environ.get("FETECH_REASONER_BACKEND", "python").lower(),
            logic_fallback=os.environ.get("FETECH_LOGIC_FALLBACK", "true").lower()
            not in {"0", "false", "no"},
            logic_timeout_seconds=max(0.1, float(os.environ.get("FETECH_LOGIC_TIMEOUT_SECONDS", "3"))),
            logic_memory_mb=max(64, int(os.environ.get("FETECH_LOGIC_MEMORY_MB", "512"))),
            logic_solution_limit=max(1, int(os.environ.get("FETECH_LOGIC_SOLUTION_LIMIT", "1"))),
            clingo_executable=os.environ.get("FETECH_CLINGO_EXECUTABLE", "clingo"),
            prolog_executable=os.environ.get("FETECH_PROLOG_EXECUTABLE", "swipl"),
            jina_reader_template=os.environ.get("FETECH_JINA_READER_TEMPLATE"),
            puppeteer_connector_url=os.environ.get("FETECH_PUPPETEER_CONNECTOR_URL"),
            selenium_connector_url=os.environ.get("FETECH_SELENIUM_CONNECTOR_URL"),
            search_provider_template=os.environ.get("FETECH_SEARCH_PROVIDER_TEMPLATE"),
            docling_artifacts_path=(
                Path(raw_docling_artifacts_path).expanduser()
                if raw_docling_artifacts_path
                else None
            ),
            docling_artifacts_sha256=(
                raw_docling_artifacts_sha256
                or DOCLING_REFERENCE_BUNDLE_SHA256
                if raw_docling_artifacts_path
                else None
            ),
            docling_worker_memory_mb=min(
                8_192,
                max(
                    1_024,
                    int(
                        os.environ.get(
                            "FETECH_DOCLING_WORKER_MEMORY_MB",
                            "4096",
                        )
                    ),
                ),
            ),
            worker_isolation_mode=os.environ.get(
                "FETECH_WORKER_ISOLATION_MODE",
                "development",
            ).lower(),
            worker_bwrap_executable=Path(
                os.environ.get(
                    "FETECH_WORKER_BWRAP_EXECUTABLE",
                    "/usr/bin/bwrap",
                )
            ).expanduser(),
            worker_cgroup_root=(
                Path(raw_worker_cgroup_root).expanduser()
                if raw_worker_cgroup_root
                else None
            ),
            browser_artifacts_path=(
                Path(raw_browser_artifacts_path).expanduser()
                if raw_browser_artifacts_path
                else None
            ),
            storage_max_bytes=_bounded_environment_integer(
                "FETECH_STORAGE_MAX_BYTES",
                10 * 1024 * 1024 * 1024,
                minimum=1024 * 1024,
                maximum=10 * 1024 * 1024 * 1024 * 1024,
            ),
            storage_run_retention_seconds=_bounded_environment_integer(
                "FETECH_STORAGE_RUN_RETENTION_SECONDS",
                0,
                minimum=0,
                maximum=10 * 365 * 24 * 60 * 60,
            ),
            storage_snapshot_retention_seconds=_bounded_environment_integer(
                "FETECH_STORAGE_SNAPSHOT_RETENTION_SECONDS",
                7 * 24 * 60 * 60,
                minimum=0,
                maximum=10 * 365 * 24 * 60 * 60,
            ),
            storage_orphan_grace_seconds=_bounded_environment_integer(
                "FETECH_STORAGE_ORPHAN_GRACE_SECONDS",
                24 * 60 * 60,
                minimum=0,
                maximum=10 * 365 * 24 * 60 * 60,
            ),
            storage_max_snapshot_records=_bounded_environment_integer(
                "FETECH_STORAGE_MAX_SNAPSHOT_RECORDS",
                100_000,
                minimum=1,
                maximum=1_000_000,
            ),
            storage_max_retired_runs_per_startup=_bounded_environment_integer(
                "FETECH_STORAGE_MAX_RETIRED_RUNS_PER_STARTUP",
                1_000,
                minimum=1,
                maximum=10_000,
            ),
            storage_max_scan_entries=_bounded_environment_integer(
                "FETECH_STORAGE_MAX_SCAN_ENTRIES",
                200_000,
                minimum=1,
                maximum=1_000_000,
            ),
        )


def _bounded_environment_integer(
    name: str,
    default: int,
    *,
    minimum: int,
    maximum: int,
) -> int:
    raw = os.environ.get(name, str(default))
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer") from exc
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} is outside the allowed bound")
    return value
