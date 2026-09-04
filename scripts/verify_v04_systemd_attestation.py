#!/usr/bin/env python3
"""Verify a signed systemd 257+ target attestation for Fetech v0.4."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Mapping, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Final

from release_attestation_common import (
    TARGET_VERSION,
    ReleaseAttestationError,
    allowed_signers_path,
    bounded_text,
    canonical_json,
    commit_text,
    exact_fields,
    load_canonical_json,
    load_release_artifacts,
    mapping,
    positive_integer,
    principal_text,
    sequence,
    sha256_file,
    sha256_text,
    timestamp_text,
    verify_ssh_signature,
)

SCHEMA: Final = "fetech.v0.4.systemd-target-attestation.v1"
RECEIPT_FILENAME: Final = f"fetech-v{TARGET_VERSION}-systemd-attestation.json"
SIGNATURE_FILENAME: Final = f"{RECEIPT_FILENAME}.sig"
SIGNATURE_NAMESPACE: Final = "fetech-systemd-attestation-v1"
ALLOWED_SIGNERS_ENV: Final = "FETECH_SYSTEMD_ATTESTORS_FILE"
REFERENCE_UNIT: Final = Path("deploy/systemd/fetech.service.example")
DOCLING_SHA256: Final = (
    "e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76"
)
MAX_AGE: Final = timedelta(days=14)

_TOP_LEVEL_FIELDS: Final = {
    "schema",
    "version",
    "source_commit",
    "collected_at",
    "target_label",
    "attestor_principal",
    "platform",
    "artifacts",
    "service",
}
_PLATFORM_FIELDS: Final = {
    "os_id",
    "os_version_id",
    "kernel_release",
    "architecture",
    "virtualization",
    "systemd_version",
    "pid1",
    "cgroup_v2",
    "containerized",
}
_ARTIFACT_FIELDS: Final = {
    "artifact_receipt_sha256",
    "wheel_sha256",
    "sdist_sha256",
    "unit_sha256",
    "docling_bundle_sha256",
}
_SERVICE_FIELDS: Final = {
    "unit_name",
    "systemd_verify_passed",
    "systemd_security_completed",
    "active_state",
    "sub_state",
    "main_pid",
    "bubblewrap_version",
    "capability_category_count",
    "capability_count",
    "required_properties",
    "required_environment",
}
_EXPECTED_PROPERTIES: Final[dict[str, str]] = {
    "FragmentPath": "/etc/systemd/system/fetech.service",
    "DropInPaths": "",
    "User": "fetech",
    "Group": "fetech",
    "NoNewPrivileges": "yes",
    "PrivateTmp": "yes",
    "PrivateDevices": "yes",
    "ProtectSystem": "strict",
    "ProtectHome": "yes",
    "ProtectControlGroups": "private",
    "Delegate": "yes",
    "DelegateSubgroup": "daemon",
    "MemoryMax": "6442450944",
    "TasksMax": "768",
}
_EXPECTED_ENVIRONMENT: Final = (
    "FETECH_WORKER_ISOLATION_MODE=required",
    "FETECH_WORKER_BWRAP_EXECUTABLE=/usr/bin/bwrap",
    "FETECH_WORKER_CGROUP_ROOT=/sys/fs/cgroup",
    "FETECH_BROWSER_ARTIFACTS_PATH=/opt/fetech/browser-artifacts",
    "FETECH_DOCLING_ARTIFACTS_PATH=/opt/fetech/docling-models/2.113.0",
    f"FETECH_DOCLING_ARTIFACTS_SHA256={DOCLING_SHA256}",
)


class SystemdAttestationError(ReleaseAttestationError):
    """A sanitized target-attestation failure."""


def _fail(message: str) -> None:
    raise SystemdAttestationError(message)


def _bool(value: object, label: str, expected: bool) -> bool:
    if not isinstance(value, bool) or value is not expected:
        _fail(f"{label} must be {str(expected).lower()}")
    return value


def _validate_platform(value: object) -> dict[str, object]:
    platform = mapping(value, "platform")
    exact_fields(platform, _PLATFORM_FIELDS, "platform")
    systemd_version = positive_integer(platform.get("systemd_version"), "systemd version")
    if systemd_version < 257:
        _fail("target systemd must be version 257 or newer")
    if bounded_text(platform.get("pid1"), "PID 1", 32) != "systemd":
        _fail("target PID 1 must be systemd")
    _bool(platform.get("cgroup_v2"), "cgroup_v2", True)
    _bool(platform.get("containerized"), "containerized", False)
    for field in (
        "os_id",
        "os_version_id",
        "kernel_release",
        "architecture",
        "virtualization",
    ):
        bounded_text(platform.get(field), field, 256)
    return dict(platform)


def _validate_artifacts(
    value: object,
    *,
    project_root: Path,
    artifact_dir: Path,
    release_receipt: Mapping[str, object],
) -> dict[str, str]:
    artifacts = mapping(value, "attested artifacts")
    exact_fields(artifacts, _ARTIFACT_FIELDS, "attested artifacts")
    actual_receipt_sha, _ = sha256_file(
        artifact_dir / f"fetech-{TARGET_VERSION}-artifacts.json",
        "release artifact receipt",
        maximum_bytes=512 * 1024,
    )
    expected: dict[str, str] = {
        "artifact_receipt_sha256": actual_receipt_sha,
        "unit_sha256": sha256_file(
            project_root / REFERENCE_UNIT,
            "reference systemd unit",
            maximum_bytes=128 * 1024,
        )[0],
        "docling_bundle_sha256": DOCLING_SHA256,
    }
    for raw in sequence(release_receipt.get("artifacts"), "release artifacts"):
        artifact = mapping(raw, "release artifact")
        kind = bounded_text(artifact.get("kind"), "release artifact kind", 32)
        if kind in {"wheel", "sdist"}:
            expected[f"{kind}_sha256"] = sha256_text(
                artifact.get("sha256"), f"{kind} digest"
            )
    if set(expected) != _ARTIFACT_FIELDS:
        _fail("release artifact receipt is incomplete")
    for field, expected_digest in expected.items():
        if sha256_text(artifacts.get(field), field) != expected_digest:
            _fail(f"attested {field} does not match the release candidate")
    return expected


def _validate_service(value: object) -> dict[str, object]:
    service = mapping(value, "service evidence")
    exact_fields(service, _SERVICE_FIELDS, "service evidence")
    if bounded_text(service.get("unit_name"), "unit name", 128) != "fetech.service":
        _fail("attestation must cover fetech.service")
    _bool(service.get("systemd_verify_passed"), "systemd verify", True)
    _bool(service.get("systemd_security_completed"), "systemd security", True)
    if service.get("active_state") != "active" or service.get("sub_state") != "running":
        _fail("reference daemon was not active and running")
    positive_integer(service.get("main_pid"), "service main PID")
    bubblewrap = bounded_text(service.get("bubblewrap_version"), "Bubblewrap version", 128)
    if "bubblewrap" not in bubblewrap.lower():
        _fail("Bubblewrap version evidence is invalid")
    if positive_integer(service.get("capability_category_count"), "category count") != 13:
        _fail("daemon did not expose 13 capability categories")
    if positive_integer(service.get("capability_count"), "capability count") != 155:
        _fail("daemon did not expose 155 capabilities")

    properties = mapping(service.get("required_properties"), "required properties")
    if properties != _EXPECTED_PROPERTIES:
        _fail("effective systemd properties do not match the reference contract")
    environment = sequence(service.get("required_environment"), "required environment")
    if environment != list(_EXPECTED_ENVIRONMENT):
        _fail("effective service environment does not match the reference contract")
    return dict(service)


def validate_attestation(
    document: Mapping[str, object],
    *,
    project_root: Path,
    artifact_dir: Path,
    now: datetime | None = None,
) -> dict[str, object]:
    """Validate canonical target facts and exact local release bindings."""

    exact_fields(document, _TOP_LEVEL_FIELDS, "systemd attestation")
    if document.get("schema") != SCHEMA or document.get("version") != TARGET_VERSION:
        _fail("systemd attestation schema or version is invalid")
    release_receipt = load_release_artifacts(project_root, artifact_dir)
    if commit_text(document.get("source_commit"), "attested source commit") != release_receipt.get(
        "source_commit"
    ):
        _fail("systemd attestation is not bound to the release commit")
    _, collected_at = timestamp_text(document.get("collected_at"), "collected_at")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if collected_at > current + timedelta(minutes=5) or current - collected_at > MAX_AGE:
        _fail("systemd attestation is future-dated or older than 14 days")
    bounded_text(document.get("target_label"), "target label", 128)
    principal_text(document.get("attestor_principal"), "attestor principal")
    _validate_platform(document.get("platform"))
    _validate_artifacts(
        document.get("artifacts"),
        project_root=project_root,
        artifact_dir=artifact_dir,
        release_receipt=release_receipt,
    )
    _validate_service(document.get("service"))
    return dict(document)


def verify_attestation(
    project_root: Path,
    artifact_dir: Path,
    receipt_path: Path,
    signature_path: Path,
    allowed_signers: Path,
) -> dict[str, object]:
    if receipt_path.name != RECEIPT_FILENAME or signature_path.name != SIGNATURE_FILENAME:
        _fail("systemd receipt or signature filename is not canonical")
    document = load_canonical_json(receipt_path, "systemd attestation")
    validated = validate_attestation(
        document,
        project_root=project_root,
        artifact_dir=artifact_dir,
    )
    verify_ssh_signature(
        receipt_path,
        signature_path,
        allowed_signers,
        principal=principal_text(validated.get("attestor_principal"), "attestor principal"),
        namespace=SIGNATURE_NAMESPACE,
        expected_payload=canonical_json(validated),
    )
    return validated


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--artifact-dir", type=Path, required=True)
    parser.add_argument("--receipt", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--allowed-signers", type=Path)
    args = parser.parse_args(argv)
    try:
        receipt = args.receipt or args.artifact_dir / RECEIPT_FILENAME
        signature = args.signature or args.artifact_dir / SIGNATURE_FILENAME
        signers = args.allowed_signers or allowed_signers_path(
            ALLOWED_SIGNERS_ENV, "systemd attestor trust file"
        )
        document = verify_attestation(
            args.project_root.resolve(strict=True),
            args.artifact_dir.resolve(strict=True),
            receipt,
            signature,
            signers,
        )
    except (OSError, ReleaseAttestationError) as exc:
        print(f"systemd attestation verification failed: {exc}", file=sys.stderr)
        return 1
    print(canonical_json(document).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
