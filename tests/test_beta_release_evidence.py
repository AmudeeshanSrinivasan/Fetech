"""Beta SPDX and dependency-license evidence remains exact and unreleased."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_release_evidence.py"
SPEC = importlib.util.spec_from_file_location("fetech_beta_release_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

PROFILE = ROOT / "scripts" / "release_v05_beta.toml"
CATALOG = ROOT / "scripts" / "release_license_catalog.toml"
SPDX = ROOT / "release" / "fetech-0.5.0b1-beta.spdx.json"
LICENSE_REPORT = ROOT / "release" / "dependency-licenses-0.5.0b1-beta.md"


def _inputs_and_overlay():
    inputs = MODULE.load_release_inputs(ROOT / "pyproject.toml", ROOT / "uv.lock", CATALOG)
    overlay = MODULE.load_development_overlay(
        ROOT,
        PROFILE,
        package_version=str(inputs.project["version"]),
    )
    return inputs, overlay


def test_beta_evidence_profile_binds_current_cross_platform_surface() -> None:
    inputs, overlay = _inputs_and_overlay()
    profile = tomllib.loads(PROFILE.read_text(encoding="utf-8"))["overlay"]
    declared_inputs = tuple(profile["evidence_inputs"])

    assert (
        overlay.identifier,
        overlay.title,
        overlay.package_version,
        overlay.status,
        overlay.closure_release,
        overlay.capability_count,
        overlay.cumulative_capability_count,
    ) == (
        "v0.5.0b1-beta",
        "v0.5.0b1 Beta candidate",
        "0.5.0b1",
        "unreleased-candidate",
        "v0.4",
        36,
        155,
    )
    assert len(inputs.packages) == 168
    assert {
        ".github/workflows/ci.yml",
        "capabilities/manifest.yaml",
        "compatibility/beta-v1.json",
        "docs/beta-development.md",
        "docs/releases/v0.5.0b1.md",
        "scripts/check_beta_compatibility.py",
        "scripts/generate_release_evidence.py",
        "scripts/release_license_catalog.toml",
        "scripts/verify_reproducible_builds.py",
        "src/fetech/compatibility.py",
        "src/fetech/context.py",
        "src/fetech/contracts.py",
        "src/fetech/failures.py",
        "src/fetech/storage_lifecycle.py",
        "tests/test_beta_compatibility.py",
        "tests/test_beta_release_evidence.py",
        "tests/test_beta_reproducible_builds.py",
    } <= set(declared_inputs)
    assert "tests/test_worker_isolation_linux.py" not in declared_inputs

    expected_hashes = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (
            PROFILE,
            *(ROOT / relative_path for relative_path in declared_inputs),
        )
    }
    assert dict(overlay.input_hashes) == expected_hashes


def test_beta_spdx_and_license_report_are_current_and_sanitized(tmp_path: Path) -> None:
    inputs, overlay = _inputs_and_overlay()
    version, expected_spdx, expected_report = MODULE.render_release_evidence(
        ROOT / "pyproject.toml",
        ROOT / "uv.lock",
        CATALOG,
        overlay,
    )
    document = json.loads(expected_spdx)
    root_package = next(
        package
        for package in document["packages"]
        if package["SPDXID"] == MODULE.SPDX_ROOT_ID
    )

    assert version == "0.5.0b1"
    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["name"] == "fetech-v0.5.0b1-beta-universal-lock"
    assert document["creationInfo"] == {
        "created": "2026-09-05T00:00:00Z",
        "creators": ["Tool: fetech-release-evidence-generator/2"],
    }
    assert root_package["versionInfo"] == "0.5.0b1"
    assert root_package["externalRefs"][0]["referenceLocator"] == (
        "pkg:pypi/fetech@0.5.0b1"
    )
    assert len(document["packages"]) == len(inputs.packages) + 1
    assert "not a published-release SBOM" in root_package["comment"]
    assert "Third-party locked packages: **168**" in expected_report
    assert "Declared AGPL expressions: **0**" in expected_report
    assert "The 100-task context-efficiency acceptance benchmark has not been completed." in (
        expected_report
    )
    assert "Platform-specific deployment attestations" in expected_report
    assert "--overlay-profile scripts/release_v05_beta.toml --check" in expected_report

    assert SPDX.read_text(encoding="utf-8") == expected_spdx
    assert LICENSE_REPORT.read_text(encoding="utf-8") == expected_report
    combined = expected_spdx + expected_report
    assert str(ROOT) not in combined
    assert str(Path.home()) not in combined
    assert "file://" not in combined.lower()
    assert "authorization:" not in combined.lower()
    assert "cookie:" not in combined.lower()

    generated = MODULE.generate(
        ROOT,
        tmp_path,
        check=False,
        overlay_profile=PROFILE,
    )
    assert generated == (
        tmp_path / SPDX.name,
        tmp_path / LICENSE_REPORT.name,
    )
    assert generated[0].read_text(encoding="utf-8") == expected_spdx
    assert generated[1].read_text(encoding="utf-8") == expected_report
    assert MODULE.generate(
        ROOT,
        tmp_path,
        check=True,
        overlay_profile=PROFILE,
    ) == generated


def test_ci_verifies_beta_evidence_without_regenerating_it() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    assert "Verify Beta release evidence" in workflow
    assert (
        "--overlay-profile scripts/release_v05_beta.toml --check" in workflow
    )
    assert "tests/test_beta_release_evidence.py -q" in workflow
