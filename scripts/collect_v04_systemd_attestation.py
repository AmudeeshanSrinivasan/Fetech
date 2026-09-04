#!/usr/bin/env python3
"""Collect unsigned, canonical systemd 257+ target evidence for Fetech v0.4.

Run this command as root on the actual deployment host after installing and
starting the exact reference unit.  The collector never accesses credentials,
cookies, fetched bodies, or service journals.  Sign its output separately with
the deployment attestor's OpenSSH key.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shlex
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final

from release_attestation_common import (
    TARGET_VERSION,
    ReleaseAttestationError,
    bounded_text,
    canonical_json,
    load_release_artifacts,
    mapping,
    principal_text,
    run_command,
    sequence,
    sha256_file,
    utc_now_text,
)
from verify_v04_systemd_attestation import (
    _EXPECTED_ENVIRONMENT,
    _EXPECTED_PROPERTIES,
    DOCLING_SHA256,
    RECEIPT_FILENAME,
    REFERENCE_UNIT,
    SCHEMA,
)

from fetech.docling_artifacts import (
    DoclingArtifactBundleError,
    verify_docling_artifact_bundle,
)

_SYSTEMD_VERSION = re.compile(r"systemd\s+(?P<version>[0-9]+)(?:\s|\Z)")
_CAPABILITY_URL: Final = "http://127.0.0.1:8787/v1/capabilities"
_DOCLING_ARTIFACTS_PATH: Final = Path("/opt/fetech/docling-models/2.113.0")
_MAX_HTTP_BYTES: Final = 4 * 1024 * 1024
_SHOW_PROPERTIES: Final = (
    *_EXPECTED_PROPERTIES,
    "ActiveState",
    "SubState",
    "MainPID",
)


class SystemdCollectionError(ReleaseAttestationError):
    """A sanitized target collection failure."""


def _fail(message: str) -> None:
    raise SystemdCollectionError(message)


def _os_release() -> tuple[str, str]:
    values: dict[str, str] = {}
    try:
        lines = Path("/etc/os-release").read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemdCollectionError("/etc/os-release is unavailable") from exc
    for line in lines:
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, raw_value = line.split("=", 1)
        if key in {"ID", "VERSION_ID"}:
            try:
                parsed = shlex.split(raw_value, posix=True)
            except ValueError as exc:
                raise SystemdCollectionError("/etc/os-release is malformed") from exc
            if len(parsed) != 1:
                _fail("/etc/os-release contains an invalid release value")
            values[key] = bounded_text(parsed[0], f"os-release {key}", 128)
    if set(values) != {"ID", "VERSION_ID"}:
        _fail("/etc/os-release must provide ID and VERSION_ID")
    return values["ID"], values["VERSION_ID"]


def _systemd_version() -> int:
    _, output = run_command(("systemd", "--version"), "systemd version inspection")
    match = _SYSTEMD_VERSION.search(output.splitlines()[0] if output else "")
    if match is None:
        _fail("systemd returned an invalid version")
    version = int(match.group("version"))
    if version < 257:
        _fail("the target must run systemd 257 or newer")
    return version


def _virtualization() -> str:
    container_code, _ = run_command(
        ("systemd-detect-virt", "--container"),
        "container detection",
        accepted_codes=frozenset({0, 1}),
    )
    if container_code == 0:
        _fail("a container or nested systemd lab is not a deployment-host attestation")
    _, value = run_command(
        ("systemd-detect-virt",),
        "virtualization detection",
        accepted_codes=frozenset({0, 1}),
    )
    return bounded_text(value or "none", "virtualization", 128)


def _systemctl_properties(service_name: str) -> tuple[dict[str, str], str, str, int]:
    arguments = ["systemctl", "show", service_name, "--no-pager"]
    for name in _SHOW_PROPERTIES:
        arguments.extend(("--property", name))
    _, output = run_command(tuple(arguments), "effective systemd property inspection")
    values: dict[str, str] = {}
    for line in output.splitlines():
        if "=" not in line:
            _fail("systemctl show returned malformed output")
        name, value = line.split("=", 1)
        if name in values:
            _fail("systemctl show returned duplicate properties")
        if len(value.encode("utf-8")) > 256 or any(
            ord(character) < 32 or ord(character) == 127 for character in value
        ):
            _fail(f"systemd property {name} is invalid")
        values[name] = value
    if set(values) != set(_SHOW_PROPERTIES):
        _fail("systemctl show did not return every required property")
    properties = {name: values[name] for name in _EXPECTED_PROPERTIES}
    if properties != _EXPECTED_PROPERTIES:
        _fail("effective systemd properties do not match the reference unit")
    if values["ActiveState"] != "active" or values["SubState"] != "running":
        _fail("fetech.service is not active and running")
    try:
        main_pid = int(values["MainPID"])
    except ValueError as exc:
        raise SystemdCollectionError("service MainPID is invalid") from exc
    if main_pid <= 1:
        _fail("service MainPID is invalid")
    return properties, values["ActiveState"], values["SubState"], main_pid


def _systemctl_environment(service_name: str) -> list[str]:
    _, output = run_command(
        ("systemctl", "show", service_name, "--no-pager", "--property", "Environment", "--value"),
        "effective systemd environment inspection",
    )
    try:
        environment = set(shlex.split(output, posix=True))
    except ValueError as exc:
        raise SystemdCollectionError("systemctl returned an invalid environment") from exc
    missing = set(_EXPECTED_ENVIRONMENT) - environment
    if missing:
        _fail("effective service environment is missing a required release value")
    return list(_EXPECTED_ENVIRONMENT)


def _bubblewrap_version() -> str:
    if os.geteuid() != 0:
        _fail("target attestation collection must run as root")
    _, output = run_command(
        ("runuser", "--user", "fetech", "--", "/usr/bin/bwrap", "--version"),
        "unprivileged Bubblewrap inspection",
    )
    if "bubblewrap" not in output.lower():
        _fail("Bubblewrap returned an invalid version")
    return bounded_text(output, "Bubblewrap version", 128)


def _docling_bundle_digest() -> str:
    try:
        bundle = verify_docling_artifact_bundle(
            _DOCLING_ARTIFACTS_PATH,
            expected_sha256=DOCLING_SHA256,
        )
    except (OSError, DoclingArtifactBundleError) as exc:
        raise SystemdCollectionError(
            "installed Docling artifact bundle does not match the release trust anchor"
        ) from exc
    return bundle.bundle_sha256


def _capability_counts() -> tuple[int, int]:
    request = urllib.request.Request(
        _CAPABILITY_URL,
        headers={"Accept": "application/json", "User-Agent": "Fetech-release-attestor/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status != 200:
                _fail("daemon capability endpoint did not return HTTP 200")
            if response.geturl() != _CAPABILITY_URL:
                _fail("daemon capability endpoint redirected unexpectedly")
            payload = response.read(_MAX_HTTP_BYTES + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise SystemdCollectionError("daemon capability endpoint is unavailable") from exc
    if len(payload) > _MAX_HTTP_BYTES:
        _fail("daemon capability response is oversized")
    try:
        document = mapping(json.loads(payload.decode("utf-8", errors="strict")), "capability response")
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SystemdCollectionError("daemon capability response is invalid") from exc
    category_count = document.get("category_count")
    capability_count = document.get("capability_count")
    if category_count != 13 or capability_count != 155:
        _fail("daemon capability endpoint does not expose the 13/155 registry")
    return 13, 155


def _artifact_digests(receipt: Mapping[str, object]) -> tuple[str, str]:
    digests: dict[str, str] = {}
    for raw in sequence(receipt.get("artifacts"), "release artifacts"):
        artifact = mapping(raw, "release artifact")
        kind = artifact.get("kind")
        digest = artifact.get("sha256")
        if kind in {"wheel", "sdist"} and isinstance(digest, str):
            digests[kind] = digest
    if set(digests) != {"wheel", "sdist"}:
        _fail("release artifact receipt is incomplete")
    return digests["wheel"], digests["sdist"]


def build_attestation(
    *,
    source_commit: str,
    collected_at: str,
    target_label: str,
    attestor_principal: str,
    platform_evidence: Mapping[str, object],
    artifact_evidence: Mapping[str, object],
    service_evidence: Mapping[str, object],
) -> dict[str, object]:
    """Build the canonical document from already validated collection facts."""

    return {
        "schema": SCHEMA,
        "version": TARGET_VERSION,
        "source_commit": source_commit,
        "collected_at": collected_at,
        "target_label": bounded_text(target_label, "target label", 128),
        "attestor_principal": principal_text(attestor_principal, "attestor principal"),
        "platform": dict(platform_evidence),
        "artifacts": dict(artifact_evidence),
        "service": dict(service_evidence),
    }


def collect(
    project_root: Path,
    artifact_dir: Path,
    installed_unit: Path,
    *,
    target_label: str,
    attestor_principal: str,
) -> dict[str, object]:
    if not sys.platform.startswith("linux"):
        _fail("systemd target evidence can only be collected on Linux")
    try:
        pid1 = Path("/proc/1/comm").read_text(encoding="ascii").strip()
    except (OSError, UnicodeDecodeError) as exc:
        raise SystemdCollectionError("PID 1 identity is unavailable") from exc
    if pid1 != "systemd":
        _fail("PID 1 must be systemd")
    if not Path("/sys/fs/cgroup/cgroup.controllers").is_file():
        _fail("unified cgroup v2 controllers are unavailable")

    release_receipt = load_release_artifacts(project_root, artifact_dir)
    source_commit = str(release_receipt["source_commit"])
    reference_digest, _ = sha256_file(
        project_root / REFERENCE_UNIT,
        "reference systemd unit",
        maximum_bytes=128 * 1024,
    )
    installed_digest, _ = sha256_file(
        installed_unit,
        "installed systemd unit",
        maximum_bytes=128 * 1024,
    )
    if installed_digest != reference_digest:
        _fail("installed systemd unit does not match the release reference unit")
    run_command(("systemd-analyze", "verify", str(installed_unit)), "systemd unit verification")
    run_command(
        ("systemd-analyze", "security", "--no-pager", "fetech.service"),
        "systemd security analysis",
    )
    properties, active_state, sub_state, main_pid = _systemctl_properties("fetech.service")
    environment = _systemctl_environment("fetech.service")
    category_count, capability_count = _capability_counts()
    os_id, os_version_id = _os_release()
    wheel_digest, sdist_digest = _artifact_digests(release_receipt)
    artifact_receipt_digest, _ = sha256_file(
        artifact_dir / f"fetech-{TARGET_VERSION}-artifacts.json",
        "release artifact receipt",
        maximum_bytes=512 * 1024,
    )
    return build_attestation(
        source_commit=source_commit,
        collected_at=utc_now_text(),
        target_label=target_label,
        attestor_principal=attestor_principal,
        platform_evidence={
            "os_id": os_id,
            "os_version_id": os_version_id,
            "kernel_release": bounded_text(platform.release(), "kernel release", 256),
            "architecture": bounded_text(platform.machine(), "architecture", 128),
            "virtualization": _virtualization(),
            "systemd_version": _systemd_version(),
            "pid1": "systemd",
            "cgroup_v2": True,
            "containerized": False,
        },
        artifact_evidence={
            "artifact_receipt_sha256": artifact_receipt_digest,
            "wheel_sha256": wheel_digest,
            "sdist_sha256": sdist_digest,
            "unit_sha256": installed_digest,
            "docling_bundle_sha256": _docling_bundle_digest(),
        },
        service_evidence={
            "unit_name": "fetech.service",
            "systemd_verify_passed": True,
            "systemd_security_completed": True,
            "active_state": active_state,
            "sub_state": sub_state,
            "main_pid": main_pid,
            "bubblewrap_version": _bubblewrap_version(),
            "capability_category_count": category_count,
            "capability_count": capability_count,
            "required_properties": properties,
            "required_environment": environment,
        },
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument(
        "--installed-unit",
        type=Path,
        default=Path("/etc/systemd/system/fetech.service"),
    )
    parser.add_argument("--target-label", required=True)
    parser.add_argument("--attestor-principal", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.name != RECEIPT_FILENAME or args.output.is_symlink():
            _fail(f"output must use canonical filename {RECEIPT_FILENAME}")
        document = collect(
            args.project_root.resolve(strict=True),
            args.artifact_dir.resolve(strict=True),
            args.installed_unit,
            target_label=args.target_label,
            attestor_principal=args.attestor_principal,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(canonical_json(document))
    except (OSError, ReleaseAttestationError) as exc:
        print(f"systemd attestation collection failed: {exc}", file=sys.stderr)
        return 1
    print(canonical_json(document).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
