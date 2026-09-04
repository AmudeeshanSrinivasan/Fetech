#!/usr/bin/env python3
"""Create or verify a signed human legal-approval receipt for Fetech v0.4.

The command cannot decide whether a reviewer is qualified and cannot grant
legal approval.  The release owner selects the reviewer independently, places
their public key in an external OpenSSH allowed-signers file, and the reviewer
signs the exact canonical approval bytes.
"""

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
    principal_text,
    sequence,
    sha256_file,
    sha256_text,
    timestamp_text,
    utc_now_text,
    verify_ssh_signature,
)

SCHEMA: Final = "fetech.v0.4.legal-approval.v1"
RECEIPT_FILENAME: Final = f"fetech-v{TARGET_VERSION}-legal-approval.json"
SIGNATURE_FILENAME: Final = f"{RECEIPT_FILENAME}.sig"
SIGNATURE_NAMESPACE: Final = "fetech-legal-approval-v1"
ALLOWED_SIGNERS_ENV: Final = "FETECH_LEGAL_REVIEWERS_FILE"
SCOPE: Final = "fetech-wheel-and-sdist-only"
MAX_AGE: Final = timedelta(days=90)
SBOM_PATH: Final = Path(f"release/fetech-{TARGET_VERSION}-candidate.spdx.json")
LICENSE_REPORT_PATH: Final = Path(
    f"release/dependency-licenses-{TARGET_VERSION}-candidate.md"
)
REQUIRED_COMPONENTS: Final = (
    "docling-layout-heron-model",
    "nvidia-linux-dependencies",
    "pypdfium2-pdfium",
    "playwright-chromium",
    "ffmpeg-ffprobe",
    "tesseract",
)

_TOP_LEVEL_FIELDS: Final = {
    "schema",
    "version",
    "source_commit",
    "reviewed_at",
    "decision",
    "distribution_scope",
    "external_artifacts_bundled",
    "reviewer",
    "approval_reference",
    "jurisdictions",
    "artifacts",
    "component_decisions",
    "conditions",
}
_REVIEWER_FIELDS: Final = {"principal", "name", "organization", "role"}
_ARTIFACT_FIELDS: Final = {
    "wheel_sha256",
    "sdist_sha256",
    "spdx_sha256",
    "dependency_license_report_sha256",
}


class LegalApprovalError(ReleaseAttestationError):
    """A sanitized legal-approval verification failure."""


def _fail(message: str) -> None:
    raise LegalApprovalError(message)


def _release_digests(
    project_root: Path,
    artifact_dir: Path,
    release_receipt: Mapping[str, object],
) -> dict[str, str]:
    result: dict[str, str] = {
        "spdx_sha256": sha256_file(
            project_root / SBOM_PATH,
            "candidate SPDX report",
            maximum_bytes=32 * 1024 * 1024,
        )[0],
        "dependency_license_report_sha256": sha256_file(
            project_root / LICENSE_REPORT_PATH,
            "candidate dependency-license report",
            maximum_bytes=32 * 1024 * 1024,
        )[0],
    }
    for raw in sequence(release_receipt.get("artifacts"), "release artifacts"):
        artifact = mapping(raw, "release artifact")
        kind = bounded_text(artifact.get("kind"), "release artifact kind", 32)
        if kind in {"wheel", "sdist"}:
            result[f"{kind}_sha256"] = sha256_text(
                artifact.get("sha256"), f"{kind} digest"
            )
    if set(result) != _ARTIFACT_FIELDS:
        _fail("release evidence is incomplete")
    return result


def build_approval(
    *,
    source_commit: str,
    reviewed_at: str,
    reviewer_principal: str,
    reviewer_name: str,
    reviewer_organization: str,
    reviewer_role: str,
    approval_reference: str,
    jurisdictions: Sequence[str],
    artifacts: Mapping[str, str],
) -> dict[str, object]:
    """Build an approval document for an authorized human reviewer to sign."""

    if not jurisdictions or len(jurisdictions) > 16:
        _fail("one to sixteen review jurisdictions are required")
    safe_jurisdictions = [
        bounded_text(value, f"jurisdiction {index}", 128)
        for index, value in enumerate(jurisdictions)
    ]
    if len(safe_jurisdictions) != len(set(safe_jurisdictions)):
        _fail("review jurisdictions must be unique")
    return {
        "schema": SCHEMA,
        "version": TARGET_VERSION,
        "source_commit": commit_text(source_commit, "source commit"),
        "reviewed_at": reviewed_at,
        "decision": "approved",
        "distribution_scope": SCOPE,
        "external_artifacts_bundled": False,
        "reviewer": {
            "principal": principal_text(reviewer_principal, "reviewer principal"),
            "name": bounded_text(reviewer_name, "reviewer name", 256),
            "organization": bounded_text(
                reviewer_organization, "reviewer organization", 256
            ),
            "role": bounded_text(reviewer_role, "reviewer role", 256),
        },
        "approval_reference": bounded_text(
            approval_reference, "approval reference", 512
        ),
        "jurisdictions": safe_jurisdictions,
        "artifacts": dict(artifacts),
        "component_decisions": [
            {"component": component, "decision": "approved"}
            for component in REQUIRED_COMPONENTS
        ],
        "conditions": [],
    }


def create_approval(
    project_root: Path,
    artifact_dir: Path,
    *,
    reviewer_principal: str,
    reviewer_name: str,
    reviewer_organization: str,
    reviewer_role: str,
    approval_reference: str,
    jurisdictions: Sequence[str],
) -> dict[str, object]:
    release_receipt = load_release_artifacts(project_root, artifact_dir)
    return build_approval(
        source_commit=str(release_receipt["source_commit"]),
        reviewed_at=utc_now_text(),
        reviewer_principal=reviewer_principal,
        reviewer_name=reviewer_name,
        reviewer_organization=reviewer_organization,
        reviewer_role=reviewer_role,
        approval_reference=approval_reference,
        jurisdictions=jurisdictions,
        artifacts=_release_digests(
            project_root,
            artifact_dir,
            release_receipt,
        ),
    )


def validate_approval(
    document: Mapping[str, object],
    *,
    project_root: Path,
    artifact_dir: Path,
    now: datetime | None = None,
) -> dict[str, object]:
    exact_fields(document, _TOP_LEVEL_FIELDS, "legal approval")
    if document.get("schema") != SCHEMA or document.get("version") != TARGET_VERSION:
        _fail("legal approval schema or version is invalid")
    release_receipt = load_release_artifacts(project_root, artifact_dir)
    if commit_text(document.get("source_commit"), "approved source commit") != release_receipt.get(
        "source_commit"
    ):
        _fail("legal approval is not bound to the release commit")
    _, reviewed_at = timestamp_text(document.get("reviewed_at"), "reviewed_at")
    current = (now or datetime.now(UTC)).astimezone(UTC)
    if reviewed_at > current + timedelta(minutes=5) or current - reviewed_at > MAX_AGE:
        _fail("legal approval is future-dated or older than 90 days")
    if document.get("decision") != "approved":
        _fail("human legal decision is not approved")
    if document.get("distribution_scope") != SCOPE:
        _fail("legal approval does not cover the wheel-and-sdist release scope")
    if document.get("external_artifacts_bundled") is not False:
        _fail("legal approval must reflect that external artifacts are not bundled")

    reviewer = mapping(document.get("reviewer"), "reviewer")
    exact_fields(reviewer, _REVIEWER_FIELDS, "reviewer")
    principal_text(reviewer.get("principal"), "reviewer principal")
    for field in ("name", "organization", "role"):
        bounded_text(reviewer.get(field), f"reviewer {field}", 256)
    bounded_text(document.get("approval_reference"), "approval reference", 512)

    jurisdictions = sequence(document.get("jurisdictions"), "jurisdictions")
    if not jurisdictions or len(jurisdictions) > 16:
        _fail("legal approval must identify its jurisdiction scope")
    normalized_jurisdictions = [
        bounded_text(value, f"jurisdiction {index}", 128)
        for index, value in enumerate(jurisdictions)
    ]
    if len(normalized_jurisdictions) != len(set(normalized_jurisdictions)):
        _fail("legal approval jurisdictions are duplicated")

    artifacts = mapping(document.get("artifacts"), "legal approval artifacts")
    exact_fields(artifacts, _ARTIFACT_FIELDS, "legal approval artifacts")
    expected_digests = _release_digests(project_root, artifact_dir, release_receipt)
    for field, expected_digest in expected_digests.items():
        if sha256_text(artifacts.get(field), field) != expected_digest:
            _fail(f"legal approval {field} does not match the release candidate")

    raw_decisions = sequence(document.get("component_decisions"), "component decisions")
    decisions: list[tuple[str, str]] = []
    for index, value in enumerate(raw_decisions):
        decision = mapping(value, f"component decision {index}")
        exact_fields(decision, {"component", "decision"}, f"component decision {index}")
        decisions.append(
            (
                bounded_text(decision.get("component"), "component", 128),
                bounded_text(decision.get("decision"), "component decision", 32),
            )
        )
    if decisions != [(component, "approved") for component in REQUIRED_COMPONENTS]:
        _fail("legal approval does not approve every required component review")
    if sequence(document.get("conditions"), "conditions"):
        _fail("conditional legal approval does not close the release gate")
    return dict(document)


def verify_approval(
    project_root: Path,
    artifact_dir: Path,
    receipt_path: Path,
    signature_path: Path,
    allowed_signers: Path,
) -> dict[str, object]:
    if receipt_path.name != RECEIPT_FILENAME or signature_path.name != SIGNATURE_FILENAME:
        _fail("legal approval receipt or signature filename is not canonical")
    document = load_canonical_json(receipt_path, "legal approval")
    validated = validate_approval(
        document,
        project_root=project_root,
        artifact_dir=artifact_dir,
    )
    reviewer = mapping(validated.get("reviewer"), "reviewer")
    verify_ssh_signature(
        receipt_path,
        signature_path,
        allowed_signers,
        principal=principal_text(reviewer.get("principal"), "reviewer principal"),
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
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--create", action="store_true")
    mode.add_argument("--receipt", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--allowed-signers", type=Path)
    parser.add_argument("--reviewer-principal")
    parser.add_argument("--reviewer-name")
    parser.add_argument("--reviewer-organization")
    parser.add_argument("--reviewer-role")
    parser.add_argument("--approval-reference")
    parser.add_argument("--jurisdiction", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve(strict=True)
        artifact_dir = args.artifact_dir.resolve(strict=True)
        if args.create:
            required = {
                "--reviewer-principal": args.reviewer_principal,
                "--reviewer-name": args.reviewer_name,
                "--reviewer-organization": args.reviewer_organization,
                "--reviewer-role": args.reviewer_role,
                "--approval-reference": args.approval_reference,
            }
            missing = [flag for flag, value in required.items() if not value]
            if missing or not args.jurisdiction or args.output is None:
                _fail("approval creation is missing required reviewer fields or --output")
            if args.output.name != RECEIPT_FILENAME or args.output.is_symlink():
                _fail(f"approval output must use canonical filename {RECEIPT_FILENAME}")
            document = create_approval(
                root,
                artifact_dir,
                reviewer_principal=str(args.reviewer_principal),
                reviewer_name=str(args.reviewer_name),
                reviewer_organization=str(args.reviewer_organization),
                reviewer_role=str(args.reviewer_role),
                approval_reference=str(args.approval_reference),
                jurisdictions=args.jurisdiction,
            )
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_bytes(canonical_json(document))
        else:
            if args.output is not None:
                _fail("--output is only valid with --create")
            assert args.receipt is not None
            signature = args.signature or args.artifact_dir / SIGNATURE_FILENAME
            signers = args.allowed_signers or allowed_signers_path(
                ALLOWED_SIGNERS_ENV, "legal reviewer trust file"
            )
            document = verify_approval(
                root,
                artifact_dir,
                args.receipt,
                signature,
                signers,
            )
    except (OSError, ReleaseAttestationError) as exc:
        print(f"legal approval verification failed: {exc}", file=sys.stderr)
        return 1
    print(canonical_json(document).decode("utf-8"), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
