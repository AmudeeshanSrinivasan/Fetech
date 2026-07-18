"""Release evidence must remain deterministic, complete, and sanitized."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tomllib
from dataclasses import replace
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
build_license_report = MODULE.build_license_report
build_spdx_document = MODULE.build_spdx_document
generate = MODULE.generate
load_development_overlay = MODULE.load_development_overlay
load_published_evidence_profile = MODULE.load_published_evidence_profile
load_release_inputs = MODULE.load_release_inputs
manifest_capability_counts = MODULE._manifest_capability_counts
main = MODULE.main
render_release_evidence = MODULE.render_release_evidence
verify_published_release_evidence = MODULE.verify_published_release_evidence

PROJECT = ROOT / "pyproject.toml"
LOCK = ROOT / "uv.lock"
CATALOG = ROOT / "scripts" / "release_license_catalog.toml"
RELEASE = ROOT / "release"
V04_OVERLAY = ROOT / "scripts" / "release_v04_candidate.toml"
PUBLISHED_PROFILE = ROOT / "scripts" / "release_published.toml"


def _inputs():
    return load_release_inputs(PROJECT, LOCK, CATALOG)


def test_license_catalog_exactly_covers_the_universal_lock() -> None:
    inputs = _inputs()

    assert len(inputs.packages) == 167
    assert len(inputs.licenses) == 167
    assert all(inputs.scopes.values())
    assert all(
        expression and expression != "NOASSERTION"
        for expression in inputs.licenses.values()
    )
    assert not any("AGPL" in expression.upper() for expression in inputs.licenses.values())


def test_release_inputs_support_marker_selected_multiple_versions(
    tmp_path: Path,
) -> None:
    project = tmp_path / "pyproject.toml"
    lock = tmp_path / "uv.lock"
    catalog = tmp_path / "catalog.toml"
    project.write_text(
        '[project]\nname = "fetech"\nversion = "0.3.0a0"\n',
        encoding="utf-8",
    )
    lock.write_text(
        """
version = 1
revision = 3

[[package]]
name = "fetech"
version = "0.3.0a0"
dependencies = [{ name = "selector" }]

[[package]]
name = "selector"
version = "1.0"
dependencies = [
  { name = "transformers", version = "1.0", marker = "sys_platform == 'darwin'" },
  { name = "transformers", version = "2.0", marker = "sys_platform != 'darwin'" },
]

[[package]]
name = "transformers"
version = "1.0"

[[package]]
name = "transformers"
version = "2.0"
""".lstrip(),
        encoding="utf-8",
    )
    catalog.write_text(
        """
[packages]
"selector==1.0" = "MIT"
"transformers==1.0" = "Apache-2.0"
"transformers==2.0" = "Apache-2.0"
""".lstrip(),
        encoding="utf-8",
    )

    inputs = load_release_inputs(project, lock, catalog)
    document = build_spdx_document(inputs)

    assert set(inputs.scopes) == {
        "selector==1.0",
        "transformers==1.0",
        "transformers==2.0",
    }
    assert {
        (package["name"], package["versionInfo"])
        for package in document["packages"]
        if package["name"] == "transformers"
    } == {("transformers", "1.0"), ("transformers", "2.0")}


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
    assert extracted["LicenseRef-BSD-Unknown"] == {
        "licenseId": "LicenseRef-BSD-Unknown",
        "extractedText": "BSD License",
        "name": "Unidentified BSD license variant",
        "seeAlsos": ["https://pypi.org/project/sgmllib3k/1.0.0/"],
        "comment": (
            "The package metadata contains only the short reference “BSD License”; "
            "it does not identify the clause variant."
        ),
    }
    expected_license_refs = {
        "LicenseRef-NVIDIA-CUDNN-SLA",
        "LicenseRef-NVIDIA-CUDA-13.0-EULA",
        "LicenseRef-NVIDIA-CUDA-13.3-EULA",
        "LicenseRef-NVIDIA-NVSHMEM-SDK",
        "LicenseRef-NVIDIA-SOFTWARE-LICENSE",
        "LicenseRef-nvidia-cublas-13.1.1.3-Proprietary",
        "LicenseRef-nvidia-cuda-cupti-13.0.85-Proprietary",
        "LicenseRef-nvidia-cuda-nvrtc-13.0.88-Proprietary",
        "LicenseRef-nvidia-cufft-12.0.0.61-Proprietary",
        "LicenseRef-nvidia-cufile-1.15.1.6-Proprietary",
        "LicenseRef-nvidia-curand-10.4.0.35-Proprietary",
        "LicenseRef-nvidia-cusolver-12.0.4.66-Proprietary",
        "LicenseRef-nvidia-cusparse-12.6.3.3-Proprietary",
        "LicenseRef-nvidia-cusparselt-cu13-0.8.1-Proprietary",
        "LicenseRef-pypdfium2-5.12.1-Mixed",
        "LicenseRef-BSD-Unknown",
    }
    assert extracted.keys() == expected_license_refs
    assert all(
        item["licenseId"] == license_id
        and item["extractedText"]
        and item["name"]
        and item["seeAlsos"]
        and item["comment"]
        for license_id, item in extracted.items()
    )

    packages = document["packages"]
    assert len(packages) == len(inputs.packages) + 1
    package_ids = {package["SPDXID"] for package in packages}
    assert len(package_ids) == len(packages)
    assert SPDX_ROOT_ID in package_ids
    assert all(
        package["licenseDeclared"] != "NOASSERTION"
        for package in packages
    )
    packages_by_name = {package["name"]: package for package in packages}
    proprietary_package_refs = {
        "nvidia-cublas": "LicenseRef-nvidia-cublas-13.1.1.3-Proprietary",
        "nvidia-cuda-cupti": "LicenseRef-nvidia-cuda-cupti-13.0.85-Proprietary",
        "nvidia-cuda-nvrtc": "LicenseRef-nvidia-cuda-nvrtc-13.0.88-Proprietary",
        "nvidia-cufft": "LicenseRef-nvidia-cufft-12.0.0.61-Proprietary",
        "nvidia-cufile": "LicenseRef-nvidia-cufile-1.15.1.6-Proprietary",
        "nvidia-curand": "LicenseRef-nvidia-curand-10.4.0.35-Proprietary",
        "nvidia-cusolver": "LicenseRef-nvidia-cusolver-12.0.4.66-Proprietary",
        "nvidia-cusparse": "LicenseRef-nvidia-cusparse-12.6.3.3-Proprietary",
        "nvidia-cusparselt-cu13": (
            "LicenseRef-nvidia-cusparselt-cu13-0.8.1-Proprietary"
        ),
    }
    assert len(set(proprietary_package_refs.values())) == len(
        proprietary_package_refs
    )
    for package_name, license_ref in proprietary_package_refs.items():
        package = packages_by_name[package_name]
        assert package["licenseDeclared"] == license_ref
        assert extracted[license_ref]["seeAlsos"] == [
            f"https://pypi.org/project/{package_name}/{package['versionInfo']}/"
        ]
        assert package_name in extracted[license_ref]["name"]
    assert packages_by_name["nvidia-cusparselt-cu13"]["licenseDeclared"] != (
        packages_by_name["nvidia-cublas"]["licenseDeclared"]
    )
    assert packages_by_name["cuda-toolkit"]["licenseDeclared"] == (
        "LicenseRef-NVIDIA-CUDA-13.0-EULA"
    )
    assert packages_by_name["nvidia-cuda-runtime"]["licenseDeclared"] == (
        "LicenseRef-NVIDIA-CUDA-13.0-EULA"
    )
    assert packages_by_name["nvidia-nvjitlink"]["licenseDeclared"] == (
        "LicenseRef-NVIDIA-CUDA-13.3-EULA"
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


def test_published_v03_evidence_is_immutable_valid_and_sanitized() -> None:
    published = load_published_evidence_profile(ROOT, PUBLISHED_PROFILE)
    assert len(published) == 1
    release = published[0]
    assert (
        release.version,
        release.tag,
        release.generator,
        release.lock_sha256,
        release.third_party_package_count,
    ) == (
        "0.3.0a0",
        "v0.3.0a0",
        "fetech-release-evidence-generator/1",
        "b0f149e119743287a45a95405ffd417005b395c7b810e42a9da8edc152d364ea",
        113,
    )

    verified = verify_published_release_evidence(
        ROOT,
        PUBLISHED_PROFILE,
        RELEASE,
    )
    assert verified == (
        RELEASE / "fetech-0.3.0a0.spdx.json",
        RELEASE / "dependency-licenses.md",
    )
    expected_spdx = verified[0].read_text(encoding="utf-8")
    expected_report = verified[1].read_text(encoding="utf-8")
    document = json.loads(expected_spdx)
    assert document["name"] == "fetech-0.3.0a0-universal-lock"
    assert release.lock_sha256 in document["documentNamespace"]
    assert "## Separately installed and future runtime tools" in expected_report
    assert "https://www.swi-prolog.org/license.html" in expected_report
    assert "https://curl.se/docs/copyright.html" in expected_report
    assert "https://playwright.dev/python/docs/browsers" in expected_report
    assert "https://ffmpeg.org/legal.html" in expected_report

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


def test_published_evidence_rejects_hash_and_internal_metadata_drift(
    tmp_path: Path,
) -> None:
    profile = tmp_path / "release_published.toml"
    profile.write_text(PUBLISHED_PROFILE.read_text(encoding="utf-8"), encoding="utf-8")
    spdx = tmp_path / "fetech-0.3.0a0.spdx.json"
    report = tmp_path / "dependency-licenses.md"
    spdx.write_bytes((RELEASE / spdx.name).read_bytes())
    report.write_bytes((RELEASE / report.name).read_bytes())
    report.write_text("stale\n", encoding="utf-8")

    with pytest.raises(ValueError, match="published evidence hash mismatch"):
        verify_published_release_evidence(tmp_path, profile, tmp_path)

    report.write_bytes((RELEASE / report.name).read_bytes())
    document = json.loads(spdx.read_text(encoding="utf-8"))
    document["name"] = "forged-release"
    forged_spdx = json.dumps(document, indent=2, sort_keys=True) + "\n"
    spdx.write_text(forged_spdx, encoding="utf-8")
    forged_digest = hashlib.sha256(forged_spdx.encode("utf-8")).hexdigest()
    profile.write_text(
        PUBLISHED_PROFILE.read_text(encoding="utf-8").replace(
            "65b0f06ec381427a833466bd6211d94ef908791999dfad88f03158d06a85e70c",
            forged_digest,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="published SPDX document metadata mismatch"):
        verify_published_release_evidence(tmp_path, profile, tmp_path)


def test_published_profile_rejects_unbounded_artifact_paths(tmp_path: Path) -> None:
    profile = tmp_path / "release_published.toml"
    profile.write_text(
        PUBLISHED_PROFILE.read_text(encoding="utf-8").replace(
            'spdx_filename = "fetech-0.3.0a0.spdx.json"',
            'spdx_filename = "../fetech-0.3.0a0.spdx.json"',
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match=r"bounded \.spdx\.json basename"):
        load_published_evidence_profile(tmp_path, profile)


def test_cli_refuses_to_overwrite_published_evidence(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    (tmp_path / "pyproject.toml").write_text(
        '[project]\nname = "fetech"\nversion = "0.3.0a0"\n',
        encoding="utf-8",
    )
    profile = scripts / "release_published.toml"
    profile.write_bytes(PUBLISHED_PROFILE.read_bytes())

    with pytest.raises(
        ValueError,
        match=r"published version 0\.3\.0a0 is immutable",
    ):
        main(
            (
                "--project-root",
                str(tmp_path),
                "--published-profile",
                str(profile),
            )
        )

    assert main(("--check-published",)) == 0


def test_cli_requires_explicit_overlay_for_the_unpublished_candidate(
    tmp_path: Path,
) -> None:
    with pytest.raises(
        ValueError,
        match="unpublished package versions require an explicit unpublished overlay",
    ):
        main(("--output-dir", str(tmp_path)))

    assert not tuple(tmp_path.iterdir())


def test_check_mode_rejects_missing_or_stale_artifacts(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="missing generated artifact"):
        generate(ROOT, tmp_path, check=True)

    historical_report = tmp_path / "dependency-licenses.md"
    historical_report.write_text("immutable historical evidence\n", encoding="utf-8")
    generate(ROOT, tmp_path, check=False)
    report = tmp_path / "dependency-licenses-0.4.0a0.md"
    assert historical_report.read_text(encoding="utf-8") == (
        "immutable historical evidence\n"
    )
    report.write_text("stale\n", encoding="utf-8")

    with pytest.raises(ValueError, match="generated artifact is stale"):
        generate(ROOT, tmp_path, check=True)


def test_v04_candidate_overlay_is_reproducible_without_relabeling_package(
    tmp_path: Path,
) -> None:
    inputs = _inputs()
    overlay = load_development_overlay(
        ROOT,
        V04_OVERLAY,
        package_version=str(inputs.project["version"]),
    )
    version, expected_spdx, expected_report = render_release_evidence(
        PROJECT,
        LOCK,
        CATALOG,
        overlay,
    )
    document = json.loads(expected_spdx)
    root_package = next(
        package
        for package in document["packages"]
        if package["SPDXID"] == SPDX_ROOT_ID
    )

    assert version == "0.4.0a0"
    assert overlay.profile_path == "scripts/release_v04_candidate.toml"
    assert overlay.identifier == "v0.4.0a0-candidate"
    assert overlay.status == "unreleased-candidate"
    assert document["name"] == "fetech-v0.4.0a0-candidate-universal-lock"
    assert document["creationInfo"] == {
        "created": "2026-07-18T00:00:00Z",
        "creators": ["Tool: fetech-release-evidence-generator/2"],
    }
    assert root_package["versionInfo"] == version
    assert root_package["externalRefs"][0]["referenceLocator"] == (
        "pkg:pypi/fetech@0.4.0a0"
    )
    package_names = {package["name"] for package in document["packages"]}
    assert "yt-dlp" in package_names
    assert "docling-slim" in package_names
    assert "docling" not in package_names
    assert "not a published-release SBOM" in root_package["comment"]
    assert "unbundled executables" in document["comment"]

    profile_document = tomllib.loads(V04_OVERLAY.read_text(encoding="utf-8"))
    declared_inputs = tuple(profile_document["overlay"]["evidence_inputs"])
    required_bound_inputs = {
        "scripts/generate_release_evidence.py",
        "scripts/release_published.toml",
        "src/fetech/adapters/archive.py",
        "src/fetech/adapters/cache.py",
        "src/fetech/adapters/documents.py",
        "src/fetech/adapters/media.py",
        "src/fetech/archive_worker.py",
        "src/fetech/document_worker.py",
        "src/fetech/image_worker.py",
        "src/fetech/scheduling.py",
        "src/fetech/wayback.py",
        "src/fetech/worker_audit.py",
        "src/fetech/worker_isolation.py",
        "src/fetech/worker_isolation_bootstrap.py",
        "src/fetech/yt_dlp.py",
        "src/fetech/yt_dlp_worker.py",
        "tests/test_network_scheduling.py",
        "tests/test_release_evidence.py",
        "tests/test_storage_cas.py",
        "tests/test_v04_capability_matrix.py",
        "tests/test_v04_documents.py",
        "tests/test_v04_media.py",
        "tests/test_v04_smoke_evidence.py",
        "tests/test_v04_ytdlp.py",
        "tests/test_wayback.py",
        "tests/test_worker_audit.py",
        "tests/test_worker_isolation.py",
        "tests/test_worker_isolation_linux.py",
    }
    assert required_bound_inputs <= set(declared_inputs)
    expected_input_hashes = {
        path.relative_to(ROOT).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in (
            V04_OVERLAY,
            *(ROOT / configured_path for configured_path in declared_inputs),
        )
    }
    assert dict(overlay.input_hashes) == expected_input_hashes
    assert all(digest in expected_spdx for digest in expected_input_hashes.values())
    assert all(digest in expected_report for digest in expected_input_hashes.values())
    overlay_digest = hashlib.sha256(
        "\n".join(
            f"{path}\0{digest}" for path, digest in overlay.input_hashes
        ).encode("utf-8")
    ).hexdigest()
    assert document["documentNamespace"].endswith(
        f"{inputs.lock_sha256}-{overlay_digest}"
    )
    assert "Overlay capabilities: **36**" in expected_report
    assert "Cumulative registered capabilities: **155**" in expected_report
    assert "## Publication gaps" in expected_report
    assert "Docling" in expected_report
    assert "Tesseract OCR" in expected_report
    assert "FFmpeg and FFprobe" in expected_report
    assert (
        "--overlay-profile scripts/release_v04_candidate.toml --check"
        in expected_report
    )

    tracked_paths = (
        RELEASE / overlay.spdx_filename,
        RELEASE / overlay.license_report_filename,
    )
    assert tracked_paths[0].read_text(encoding="utf-8") == expected_spdx
    assert tracked_paths[1].read_text(encoding="utf-8") == expected_report

    generated_paths = generate(
        ROOT,
        tmp_path,
        check=False,
        overlay_profile=V04_OVERLAY,
    )
    assert generated_paths == (
        tmp_path / "fetech-0.4.0a0-candidate.spdx.json",
        tmp_path / "dependency-licenses-0.4.0a0-candidate.md",
    )
    assert generated_paths[0].read_text(encoding="utf-8") == expected_spdx
    assert generated_paths[1].read_text(encoding="utf-8") == expected_report
    assert generate(
        ROOT,
        tmp_path,
        check=True,
        overlay_profile=V04_OVERLAY,
    ) == generated_paths

    combined = expected_spdx + expected_report
    assert str(ROOT) not in combined
    assert str(Path.home()) not in combined


def _write_overlay_fixture(
    root: Path,
    *,
    capability_count: int = 36,
    cumulative_capability_count: int = 155,
    profile_path: str = "overlay.toml",
    identifier: str = "v0.4-development",
    title: str = "v0.4 development overlay",
    package_version: str = "0.3.0a0",
    status: str = "unreleased-development",
    spdx_filename: str = "overlay.spdx.json",
    license_report_filename: str = "overlay.md",
    evidence_inputs: tuple[str, ...] = ("capabilities/manifest.yaml",),
) -> Path:
    manifest = root / "capabilities" / "manifest.yaml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        (ROOT / "capabilities" / "manifest.yaml").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    profile = root / profile_path
    profile.parent.mkdir(parents=True, exist_ok=True)
    configured_inputs = ", ".join(f'"{value}"' for value in evidence_inputs)
    profile.write_text(
        "\n".join(
            [
                "[overlay]",
                f'identifier = "{identifier}"',
                f'title = "{title}"',
                f'package_version = "{package_version}"',
                f'status = "{status}"',
                'created = "2026-07-18T00:00:00Z"',
                'closure_release = "v0.4"',
                f"capability_count = {capability_count}",
                f"cumulative_capability_count = {cumulative_capability_count}",
                f'spdx_filename = "{spdx_filename}"',
                f'license_report_filename = "{license_report_filename}"',
                f"evidence_inputs = [{configured_inputs}]",
                'publication_gaps = ["Not a published release."]',
                "",
                "[[external_components]]",
                'name = "Example tool"',
                'status = "Installed separately."',
                'license_observation = "Not bundled."',
                'required_review = "Review before redistribution."',
                'source_url = "https://example.com/license"',
            ]
        ),
        encoding="utf-8",
    )
    return profile


def test_unreleased_candidate_overlay_is_explicit_and_uses_loaded_profile_path(
    tmp_path: Path,
) -> None:
    profile = _write_overlay_fixture(
        tmp_path,
        profile_path="scripts/release_v04_candidate.toml",
        identifier="v0.4.0a0-candidate",
        title="0.4.0a0 release candidate",
        package_version="0.4.0a0",
        status="unreleased-candidate",
        spdx_filename="fetech-0.4.0a0-candidate.spdx.json",
        license_report_filename="dependency-licenses-0.4.0a0-candidate.md",
    )
    overlay = load_development_overlay(
        tmp_path,
        profile,
        package_version="0.4.0a0",
    )

    assert overlay.profile_path == "scripts/release_v04_candidate.toml"
    assert (
        overlay.identifier,
        overlay.package_version,
        overlay.status,
        overlay.spdx_filename,
        overlay.license_report_filename,
    ) == (
        "v0.4.0a0-candidate",
        "0.4.0a0",
        "unreleased-candidate",
        "fetech-0.4.0a0-candidate.spdx.json",
        "dependency-licenses-0.4.0a0-candidate.md",
    )

    inputs = _inputs()
    candidate_inputs = replace(
        inputs,
        project={**inputs.project, "version": "0.4.0a0"},
    )
    document = build_spdx_document(candidate_inputs, overlay)
    report = build_license_report(candidate_inputs, overlay)
    root_package = next(
        package
        for package in document["packages"]
        if package["SPDXID"] == SPDX_ROOT_ID
    )

    assert document["name"] == "fetech-v0.4.0a0-candidate-universal-lock"
    assert root_package["versionInfo"] == "0.4.0a0"
    assert root_package["externalRefs"][0]["referenceLocator"] == (
        "pkg:pypi/fetech@0.4.0a0"
    )
    assert "not a published-release SBOM" in root_package["comment"]
    assert "deterministic unreleased engineering evidence" in report
    assert "not\na published-release license report" in report
    assert "### Hashed unpublished-overlay inputs" in report
    assert (
        "--overlay-profile scripts/release_v04_candidate.toml --check"
        in report
    )


def test_overlay_rejects_a_status_that_could_claim_publication(tmp_path: Path) -> None:
    profile = _write_overlay_fixture(tmp_path, status="published")

    with pytest.raises(
        ValueError,
        match=(
            "overlay status must be unreleased-development or "
            "unreleased-candidate"
        ),
    ):
        load_development_overlay(
            tmp_path,
            profile,
            package_version="0.3.0a0",
        )


def test_overlay_rejects_generated_output_as_a_hashed_input(tmp_path: Path) -> None:
    profile = _write_overlay_fixture(
        tmp_path,
        evidence_inputs=(
            "capabilities/manifest.yaml",
            "release/overlay.spdx.json",
        ),
    )

    with pytest.raises(
        ValueError,
        match="evidence_inputs must not include generated output filenames",
    ):
        load_development_overlay(
            tmp_path,
            profile,
            package_version="0.3.0a0",
        )


def test_v04_overlay_counts_are_derived_from_the_canonical_manifest() -> None:
    assert manifest_capability_counts(
        ROOT / "capabilities" / "manifest.yaml",
        "v0.4",
    ) == (36, 155)
    overlay = load_development_overlay(
        ROOT,
        V04_OVERLAY,
        package_version=str(_inputs().project["version"]),
    )
    assert (
        overlay.closure_release,
        overlay.capability_count,
        overlay.cumulative_capability_count,
    ) == ("v0.4", 36, 155)


@pytest.mark.parametrize(
    ("capability_count", "cumulative_capability_count", "message"),
    [
        (35, 155, "capability_count 35 does not match manifest v0.4 count 36"),
        (36, 154, "cumulative_capability_count 154 does not match manifest count 155"),
    ],
)
def test_v04_overlay_rejects_counts_that_drift_from_the_manifest(
    tmp_path: Path,
    capability_count: int,
    cumulative_capability_count: int,
    message: str,
) -> None:
    profile = _write_overlay_fixture(
        tmp_path,
        capability_count=capability_count,
        cumulative_capability_count=cumulative_capability_count,
    )

    with pytest.raises(ValueError, match=message):
        load_development_overlay(
            tmp_path,
            profile,
            package_version="0.3.0a0",
        )


def test_candidate_overlay_rejects_a_package_version_relabel(tmp_path: Path) -> None:
    profile = _write_overlay_fixture(
        tmp_path,
        identifier="v0.4.0a0-candidate",
        title="0.4.0a0 release candidate",
        package_version="0.4.0a0",
        status="unreleased-candidate",
    )

    with pytest.raises(ValueError, match="cannot relabel the package"):
        load_development_overlay(
            tmp_path,
            profile,
            package_version="0.3.0a0",
        )
