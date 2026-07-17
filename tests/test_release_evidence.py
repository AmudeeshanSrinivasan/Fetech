"""Release evidence must remain deterministic, complete, and sanitized."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "generate_release_evidence.py"
SPEC = importlib.util.spec_from_file_location("fetech_release_evidence", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

SPDX_DOCUMENT_ID = MODULE.SPDX_DOCUMENT_ID
SPDX_ROOT_ID = MODULE.SPDX_ROOT_ID
build_spdx_document = MODULE.build_spdx_document
generate = MODULE.generate
load_release_inputs = MODULE.load_release_inputs
render_release_evidence = MODULE.render_release_evidence

PROJECT = ROOT / "pyproject.toml"
LOCK = ROOT / "uv.lock"
CATALOG = ROOT / "scripts" / "release_license_catalog.toml"
RELEASE = ROOT / "release"


def _inputs():
    return load_release_inputs(PROJECT, LOCK, CATALOG)


def test_license_catalog_exactly_covers_the_universal_lock() -> None:
    inputs = _inputs()

    assert len(inputs.packages) == 113
    assert len(inputs.licenses) == 113
    assert all(inputs.scopes.values())
    assert all(
        expression and expression != "NOASSERTION"
        for expression in inputs.licenses.values()
    )
    assert not any("AGPL" in expression.upper() for expression in inputs.licenses.values())


def test_spdx_document_has_valid_ids_relationships_and_source_hashes() -> None:
    inputs = _inputs()
    document = build_spdx_document(inputs)

    assert document["spdxVersion"] == "SPDX-2.3"
    assert document["dataLicense"] == "CC0-1.0"
    assert document["SPDXID"] == SPDX_DOCUMENT_ID
    assert document["documentDescribes"] == [SPDX_ROOT_ID]
    assert inputs.lock_sha256 in document["documentNamespace"]
    extracted = {
        item["licenseId"]: item for item in document["hasExtractedLicensingInfos"]
    }
    assert extracted == {
        "LicenseRef-BSD-Unknown": {
            "licenseId": "LicenseRef-BSD-Unknown",
            "extractedText": "BSD License",
            "name": "Unidentified BSD license variant",
            "seeAlsos": ["https://pypi.org/project/sgmllib3k/1.0.0/"],
            "comment": (
                "The package metadata contains only the short reference “BSD License”; "
                "it does not identify the clause variant."
            ),
        }
    }

    packages = document["packages"]
    assert len(packages) == len(inputs.packages) + 1
    package_ids = {package["SPDXID"] for package in packages}
    assert len(package_ids) == len(packages)
    assert SPDX_ROOT_ID in package_ids
    assert all(
        package["licenseDeclared"] != "NOASSERTION"
        for package in packages
    )
    external_only = {
        "swi-prolog",
        "curl",
        "ffmpeg",
        "chromium",
        "firefox",
        "webkit",
    }
    assert not external_only & {package["name"].lower() for package in packages}
    assert all(
        relationship["spdxElementId"] in package_ids | {SPDX_DOCUMENT_ID}
        and relationship["relatedSpdxElement"] in package_ids
        for relationship in document["relationships"]
    )

    expected_hashes = {}
    for package in inputs.packages:
        artifact = package.get("sdist")
        if artifact is None and package.get("wheels"):
            artifact = package["wheels"][0]
        if artifact and str(artifact.get("hash", "")).startswith("sha256:"):
            expected_hashes[
                (str(package["name"]).lower().replace("_", "-"), str(package["version"]))
            ] = str(artifact["hash"]).removeprefix("sha256:")
    actual_hashes = {
        (package["name"], package["versionInfo"]): package["checksums"][0]["checksumValue"]
        for package in packages
        if package.get("checksums")
    }
    assert actual_hashes == expected_hashes


def test_tracked_release_evidence_is_reproducible_and_sanitized(tmp_path: Path) -> None:
    version, expected_spdx, expected_report = render_release_evidence(
        PROJECT,
        LOCK,
        CATALOG,
    )
    tracked_spdx = RELEASE / f"fetech-{version}.spdx.json"
    tracked_report = RELEASE / "dependency-licenses.md"

    assert tracked_spdx.read_text(encoding="utf-8") == expected_spdx
    assert tracked_report.read_text(encoding="utf-8") == expected_report
    assert json.loads(expected_spdx)["name"] == f"fetech-{version}-universal-lock"
    assert "## Separately installed and future runtime tools" in expected_report
    assert "https://www.swi-prolog.org/license.html" in expected_report
    assert "https://curl.se/docs/copyright.html" in expected_report
    assert "https://playwright.dev/python/docs/browsers" in expected_report
    assert "https://ffmpeg.org/legal.html" in expected_report

    generated_paths = generate(ROOT, tmp_path, check=False)
    assert generated_paths == (
        tmp_path / f"fetech-{version}.spdx.json",
        tmp_path / "dependency-licenses.md",
    )
    assert generated_paths[0].read_text(encoding="utf-8") == expected_spdx
    assert generated_paths[1].read_text(encoding="utf-8") == expected_report

    combined = expected_spdx + expected_report
    forbidden = (
        str(ROOT),
        str(Path.home()),
        "file://",
        "vault://",
        "authorization:",
        "cookie:",
    )
    assert not any(value.lower() in combined.lower() for value in forbidden)


def test_check_mode_rejects_missing_or_stale_artifacts(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing generated artifact"):
        generate(ROOT, tmp_path, check=True)

    generate(ROOT, tmp_path, check=False)
    report = tmp_path / "dependency-licenses.md"
    report.write_text("stale\n", encoding="utf-8")

    with pytest.raises(ValueError, match="generated artifact is stale"):
        generate(ROOT, tmp_path, check=True)
