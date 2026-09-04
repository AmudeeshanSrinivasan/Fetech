from __future__ import annotations

import configparser
from pathlib import Path

UNIT_PATH = (
    Path(__file__).resolve().parents[1] / "deploy" / "systemd" / "fetech.service.example"
)


def _load_unit() -> configparser.ConfigParser:
    parser = configparser.ConfigParser(interpolation=None, strict=False)
    parser.optionxform = str
    with UNIT_PATH.open(encoding="utf-8") as unit_file:
        parser.read_file(unit_file)
    return parser


def _service_environment() -> set[str]:
    section: str | None = None
    values: set[str] = set()
    for raw_line in UNIT_PATH.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif section == "Service" and line.startswith("Environment="):
            values.add(line.removeprefix("Environment="))
    return values


def test_reference_unit_runs_as_dedicated_fetech_service() -> None:
    service = _load_unit()["Service"]

    assert service["Type"] == "simple"
    assert service["User"] == "fetech"
    assert service["Group"] == "fetech"
    assert service["WorkingDirectory"] == "/var/lib/fetech"
    assert service["ExecStart"] == "/opt/fetech/.venv/bin/fetech-daemon"
    assert service["ReadWritePaths"] == "/var/lib/fetech"
    assert {
        "FETECH_STORAGE_MAX_BYTES=10737418240",
        "FETECH_STORAGE_RUN_RETENTION_SECONDS=0",
        "FETECH_STORAGE_SNAPSHOT_RETENTION_SECONDS=604800",
        "FETECH_STORAGE_ORPHAN_GRACE_SECONDS=86400",
        "FETECH_STORAGE_MAX_SNAPSHOT_RECORDS=100000",
        "FETECH_STORAGE_MAX_RETIRED_RUNS_PER_STARTUP=1000",
        "FETECH_STORAGE_MAX_SCAN_ENTRIES=200000",
        "FETECH_WORKER_ISOLATION_MODE=required",
        "FETECH_WORKER_CGROUP_ROOT=/sys/fs/cgroup",
        "FETECH_BROWSER_ARTIFACTS_PATH=/opt/fetech/browser-artifacts",
        "FETECH_DOCLING_ARTIFACTS_PATH=/opt/fetech/docling-models/2.113.0",
        (
            "FETECH_DOCLING_ARTIFACTS_SHA256="
            "e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76"
        ),
    } <= _service_environment()


def test_reference_unit_delegates_only_required_worker_controllers() -> None:
    service = _load_unit()["Service"]

    assert service["Delegate"] == "cpu memory pids"
    assert service["DelegateSubgroup"] == "daemon"
    assert service["ProtectControlGroups"] == "private"


def test_reference_unit_preserves_security_critical_protections() -> None:
    service = _load_unit()["Service"]

    expected = {
        "UMask": "0077",
        "NoNewPrivileges": "yes",
        "PrivateTmp": "yes",
        "PrivateDevices": "yes",
        "ProtectSystem": "strict",
        "ProtectHome": "yes",
        # These settings must remain compatible with Bubblewrap's nested
        # mount/proc namespace setup. See the reference unit comments.
        "ProtectKernelTunables": "no",
        "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "no",
        "ProtectClock": "yes",
        "RestrictSUIDSGID": "no",
        "RestrictRealtime": "yes",
        "LockPersonality": "yes",
        "RemoveIPC": "yes",
        # AF_NETLINK is required by Bubblewrap to initialize loopback inside a
        # worker's private network namespace. Keep packet sockets excluded.
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6 AF_NETLINK",
        "SystemCallArchitectures": "native",
    }

    assert {directive: service[directive] for directive in expected} == expected
    assert service["CapabilityBoundingSet"] == ""
    assert service["AmbientCapabilities"] == ""
