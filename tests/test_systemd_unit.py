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
        "FETECH_WORKER_ISOLATION_MODE=required",
        "FETECH_WORKER_CGROUP_ROOT=/sys/fs/cgroup",
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
        "ProtectKernelTunables": "yes",
        "ProtectKernelModules": "yes",
        "ProtectKernelLogs": "yes",
        "ProtectClock": "yes",
        "RestrictSUIDSGID": "yes",
        "RestrictRealtime": "yes",
        "LockPersonality": "yes",
        "RemoveIPC": "yes",
        "RestrictAddressFamilies": "AF_UNIX AF_INET AF_INET6",
        "SystemCallArchitectures": "native",
    }

    assert {directive: service[directive] for directive in expected} == expected
    assert service["CapabilityBoundingSet"] == ""
    assert service["AmbientCapabilities"] == ""
