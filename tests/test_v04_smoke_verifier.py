"""Adversarial tests for the fail-closed v0.4 smoke-evidence verifier."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fetech_v04_smoke_verifier",
    ROOT / "scripts" / "verify_v04_smoke_evidence.py",
)
assert SPEC is not None and SPEC.loader is not None
verifier = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = verifier
SPEC.loader.exec_module(verifier)
assert isinstance(verifier, ModuleType)


def _git(root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ("git", "-C", str(root), *arguments),
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def _canonical_write(path: Path, document: dict[str, Any]) -> None:
    path.write_text(
        json.dumps(document, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _release_case(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, Any]]:
    project = tmp_path / "project"
    project.mkdir()
    (project / "uv.lock").write_text(
        'version = 1\n\n[[package]]\nname = "fetech"\nversion = "0.4.0a0"\n',
        encoding="utf-8",
    )
    (project / "source.txt").write_text("release source\n", encoding="utf-8")
    _git(project, "init", "-q")
    _git(project, "config", "user.email", "tests@example.invalid")
    _git(project, "config", "user.name", "Fetech Tests")
    _git(project, "add", "uv.lock", "source.txt")
    _git(project, "commit", "-qm", "release source")
    commit = _git(project, "rev-parse", "HEAD")

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir()
    wheel = artifacts / verifier.WHEEL_FILENAME
    wheel.write_bytes(b"bounded release wheel fixture")
    wheel_sha256 = hashlib.sha256(wheel.read_bytes()).hexdigest()
    lock_sha256 = hashlib.sha256((project / "uv.lock").read_bytes()).hexdigest()

    checks: list[dict[str, str]] = []
    for check_id in verifier.REQUIRED_CHECK_IDS:
        check = {"id": check_id, "status": "passed"}
        if check_id == "artifact:wheel":
            check.update(
                {
                    "detail": verifier.WHEEL_FILENAME,
                    "sha256": wheel_sha256,
                    "version": verifier.TARGET_VERSION,
                }
            )
        elif check_id == "package:fetech":
            check["version"] = verifier.TARGET_VERSION
        elif check_id == "artifact:docling-models":
            check.update(
                {
                    "detail": "reviewed local model bundle",
                    "sha256": verifier.DOCLING_REFERENCE_BUNDLE_SHA256,
                    "version": verifier.DOCLING_VERSION,
                }
            )
        elif check_id in {"package:docling-slim", "smoke:docling"}:
            check["version"] = verifier.DOCLING_VERSION
        elif check_id == "source:git":
            check.update({"detail": "clean", "version": commit})
        elif check_id == "lock:uv":
            check["sha256"] = lock_sha256
        elif check_id == "smoke:wayback":
            check["service"] = verifier.WAYBACK_SERVICE
        elif check_id == "smoke:yt-dlp":
            check["service"] = verifier.YTDLP_SERVICE
        checks.append(check)

    evidence: dict[str, Any] = {
        "checks": checks,
        "generated_at": "2026-07-18T01:02:03+00:00",
        "network_smoke_requested": True,
        "platform": {
            "machine": "x86_64",
            "python": "3.12.11",
            "system": "Linux",
            "system_release": "6.12.0",
        },
        "schema": verifier.SCHEMA,
    }
    evidence_path = artifacts / verifier.EVIDENCE_FILENAME
    _canonical_write(evidence_path, evidence)
    return project, evidence_path, wheel, evidence


def _check_by_id(document: dict[str, Any], check_id: str) -> dict[str, Any]:
    return next(check for check in document["checks"] if check["id"] == check_id)


def test_complete_evidence_is_bound_to_current_source_lock_and_wheel(
    tmp_path: Path,
) -> None:
    project, evidence_path, wheel, _ = _release_case(tmp_path)

    receipt = verifier.verify_smoke_evidence(project, evidence_path, wheel)

    assert receipt["schema"] == verifier.SCHEMA
    assert receipt["source_commit"] == _git(project, "rev-parse", "HEAD")
    assert receipt["wheel_sha256"] == hashlib.sha256(wheel.read_bytes()).hexdigest()


@pytest.mark.parametrize("status", ["failed", "skipped", "missing"])
def test_failed_skipped_or_missing_status_is_rejected(
    tmp_path: Path,
    status: str,
) -> None:
    project, evidence_path, wheel, evidence = _release_case(tmp_path)
    _check_by_id(evidence, "smoke:wayback")["status"] = status
    _canonical_write(evidence_path, evidence)

    with pytest.raises(
        verifier.SmokeEvidenceError,
        match="required smoke check did not pass",
    ):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)


@pytest.mark.parametrize("mode", ["missing", "extra", "duplicate"])
def test_check_inventory_must_be_exact_and_unique(
    tmp_path: Path,
    mode: str,
) -> None:
    project, evidence_path, wheel, evidence = _release_case(tmp_path)
    if mode == "missing":
        evidence["checks"] = evidence["checks"][1:]
    elif mode == "extra":
        evidence["checks"].append({"id": "smoke:invented", "status": "passed"})
        evidence["checks"].sort(key=lambda check: check["id"])
    else:
        evidence["checks"].insert(1, dict(evidence["checks"][0]))
    _canonical_write(evidence_path, evidence)

    with pytest.raises(verifier.SmokeEvidenceError):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)


def test_duplicate_json_keys_and_noncanonical_json_are_rejected(
    tmp_path: Path,
) -> None:
    project, evidence_path, wheel, evidence = _release_case(tmp_path)
    canonical = evidence_path.read_text(encoding="utf-8")
    evidence_path.write_text(
        canonical.replace(
            '  "schema": "fetech.v0.4.smoke-evidence.v2"',
            (
                '  "schema": "fetech.v0.4.smoke-evidence.v2",\n'
                '  "schema": "fetech.v0.4.smoke-evidence.v2"'
            ),
        ),
        encoding="utf-8",
    )
    with pytest.raises(verifier.SmokeEvidenceError, match="duplicate JSON key"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    evidence_path.write_text(json.dumps(evidence), encoding="utf-8")
    with pytest.raises(verifier.SmokeEvidenceError, match="canonical JSON"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)


def test_symlinked_evidence_or_wheel_is_rejected(tmp_path: Path) -> None:
    project, evidence_path, wheel, _ = _release_case(tmp_path)
    real_evidence = evidence_path.with_name("real-smoke.json")
    evidence_path.rename(real_evidence)
    evidence_path.symlink_to(real_evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="symlinks"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    evidence_path.unlink()
    evidence_path.write_bytes(real_evidence.read_bytes())
    real_wheel = wheel.with_name("real-wheel.whl")
    wheel.rename(real_wheel)
    wheel.symlink_to(real_wheel)
    with pytest.raises(verifier.SmokeEvidenceError, match="symlinks"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)


def test_stale_source_lock_or_wheel_binding_is_rejected(tmp_path: Path) -> None:
    project, evidence_path, wheel, evidence = _release_case(tmp_path)

    _git(project, "commit", "--allow-empty", "-qm", "new release commit")
    with pytest.raises(verifier.SmokeEvidenceError, match="source:git"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    source_check = _check_by_id(evidence, "source:git")
    source_check["version"] = _git(project, "rev-parse", "HEAD")
    (project / "uv.lock").write_text("version = 1\n# changed\n", encoding="utf-8")
    _git(project, "add", "uv.lock")
    _git(project, "commit", "-qm", "update lock")
    source_check["version"] = _git(project, "rev-parse", "HEAD")
    _canonical_write(evidence_path, evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="lock:uv"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    lock_check = _check_by_id(evidence, "lock:uv")
    lock_check["sha256"] = hashlib.sha256(
        (project / "uv.lock").read_bytes()
    ).hexdigest()
    _canonical_write(evidence_path, evidence)
    wheel.write_bytes(b"changed release wheel")
    with pytest.raises(verifier.SmokeEvidenceError, match="artifact:wheel"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)


def test_exact_fetech_docling_and_live_network_proof_are_required(
    tmp_path: Path,
) -> None:
    project, evidence_path, wheel, evidence = _release_case(tmp_path)
    evidence["network_smoke_requested"] = False
    _canonical_write(evidence_path, evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="live network"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    evidence["network_smoke_requested"] = True
    _check_by_id(evidence, "package:fetech")["version"] = "0.3.0a0"
    _canonical_write(evidence_path, evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="package:fetech"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    _check_by_id(evidence, "package:fetech")["version"] = verifier.TARGET_VERSION
    _check_by_id(evidence, "smoke:docling")["version"] = "2.112.0"
    _canonical_write(evidence_path, evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="smoke:docling"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    _check_by_id(evidence, "smoke:docling")["version"] = verifier.DOCLING_VERSION
    _check_by_id(evidence, "smoke:wayback")["service"] = "https://example.invalid"
    _canonical_write(evidence_path, evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="exact service locator"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)


def test_invalid_timestamp_oversized_text_and_unknown_fields_are_rejected(
    tmp_path: Path,
) -> None:
    project, evidence_path, wheel, evidence = _release_case(tmp_path)
    evidence["generated_at"] = "2026-07-18T01:02:03+10:00"
    _canonical_write(evidence_path, evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="UTC timestamp"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    evidence["generated_at"] = "2026-07-18T01:02:03+00:00"
    evidence["platform"]["system_release"] = "x" * 257
    _canonical_write(evidence_path, evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="bounded"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)

    evidence["platform"]["system_release"] = "6.12.0"
    _check_by_id(evidence, "smoke:browser")["unexpected"] = "claim"
    _canonical_write(evidence_path, evidence)
    with pytest.raises(verifier.SmokeEvidenceError, match="unsupported fields"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)


def test_dirty_current_source_is_rejected_even_when_head_matches(
    tmp_path: Path,
) -> None:
    project, evidence_path, wheel, _ = _release_case(tmp_path)
    (project / "source.txt").write_text("dirty source\n", encoding="utf-8")

    with pytest.raises(verifier.SmokeEvidenceError, match="not clean"):
        verifier.verify_smoke_evidence(project, evidence_path, wheel)
