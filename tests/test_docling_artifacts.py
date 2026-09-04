"""Content-bound Docling model-bundle manifest tests."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from types import ModuleType

import pytest

from fetech.docling_artifacts import (
    DOCLING_ARTIFACT_MANIFEST,
    DoclingArtifactBundleError,
    DoclingArtifactModel,
    inspect_docling_artifact_bundle,
    verify_docling_artifact_bundle,
    write_docling_artifact_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
PROVISION_SPEC = importlib.util.spec_from_file_location(
    "fetech_provision_docling_artifacts",
    ROOT / "scripts" / "provision_docling_artifacts.py",
)
assert PROVISION_SPEC is not None and PROVISION_SPEC.loader is not None
provisioning = importlib.util.module_from_spec(PROVISION_SPEC)
PROVISION_SPEC.loader.exec_module(provisioning)
assert isinstance(provisioning, ModuleType)


def _model(root: Path) -> DoclingArtifactModel:
    evidence = root / "docling-project--docling-layout-heron" / "README.md"
    evidence.parent.mkdir(parents=True)
    evidence.write_text("---\nlicense: apache-2.0\n---\n", encoding="utf-8")
    (evidence.parent / "config.json").write_text("{}", encoding="utf-8")
    (evidence.parent / "model.safetensors").write_bytes(b"reviewed-weights")
    revision = "a" * 40
    return DoclingArtifactModel(
        repository="docling-project/docling-layout-heron",
        revision=revision,
        license="apache-2.0",
        license_evidence_path=(
            "docling-project--docling-layout-heron/README.md"
        ),
        source_url=(
            "https://huggingface.co/docling-project/"
            f"docling-layout-heron/tree/{revision}"
        ),
    )


def test_unmanifested_bundle_identity_is_portable_and_content_bound(
    tmp_path: Path,
) -> None:
    first = tmp_path / "first"
    second = tmp_path / "second"
    for root in (first, second):
        nested = root / "nested"
        nested.mkdir(parents=True)
        (nested / "weights.bin").write_bytes(b"same")

    first_id = inspect_docling_artifact_bundle(first).bundle_sha256
    second_id = inspect_docling_artifact_bundle(second).bundle_sha256
    assert first_id == second_id

    (second / "nested" / "weights.bin").write_bytes(b"changed")
    assert inspect_docling_artifact_bundle(second).bundle_sha256 != first_id


def test_reviewed_manifest_round_trip_binds_models_files_and_license(
    tmp_path: Path,
) -> None:
    root = tmp_path / "models"
    root.mkdir()
    model = _model(root)

    written = write_docling_artifact_manifest(root, models=(model,))
    observed = inspect_docling_artifact_bundle(root, require_manifest=True)

    assert (root / DOCLING_ARTIFACT_MANIFEST).is_file()
    assert observed == written
    assert observed.manifest_present
    assert observed.models == (model,)
    assert observed.total_bytes > 0
    assert len(observed.bundle_sha256) == 64


def test_bundle_verification_requires_an_independent_expected_digest(
    tmp_path: Path,
) -> None:
    root = tmp_path / "models"
    root.mkdir()
    written = write_docling_artifact_manifest(
        root,
        models=(_model(root),),
    )

    assert (
        verify_docling_artifact_bundle(
            root,
            expected_sha256=written.bundle_sha256,
        )
        == written
    )
    with pytest.raises(
        DoclingArtifactBundleError,
        match="expected SHA-256",
    ):
        verify_docling_artifact_bundle(root, expected_sha256="0" * 64)
    with pytest.raises(
        DoclingArtifactBundleError,
        match="expected Docling artifact SHA-256",
    ):
        verify_docling_artifact_bundle(root, expected_sha256="not-a-digest")


def test_provisioned_bundle_tree_is_made_read_only(tmp_path: Path) -> None:
    root = tmp_path / "models"
    nested = root / "nested"
    nested.mkdir(parents=True)
    model = nested / "weights.bin"
    model.write_bytes(b"weights")

    provisioning._make_tree_read_only(root)

    assert root.stat().st_mode & 0o777 == 0o555
    assert nested.stat().st_mode & 0o777 == 0o555
    assert model.stat().st_mode & 0o777 == 0o444

    provisioning._make_tree_owner_writable(root)
    assert root.stat().st_mode & 0o200
    assert nested.stat().st_mode & 0o200
    assert model.stat().st_mode & 0o200


def test_reviewed_manifest_rejects_modified_or_unexpected_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "models"
    root.mkdir()
    model = _model(root)
    write_docling_artifact_manifest(root, models=(model,))
    model_path = (
        root
        / "docling-project--docling-layout-heron"
        / "model.safetensors"
    )
    model_path.write_bytes(b"tampered")

    with pytest.raises(DoclingArtifactBundleError, match="reviewed manifest"):
        inspect_docling_artifact_bundle(root, require_manifest=True)

    model_path.write_bytes(b"reviewed-weights")
    (root / "unexpected.bin").write_bytes(b"not-reviewed")
    with pytest.raises(DoclingArtifactBundleError, match="reviewed manifest"):
        inspect_docling_artifact_bundle(root, require_manifest=True)


def test_bundle_rejects_symbolic_links(tmp_path: Path) -> None:
    root = tmp_path / "models"
    root.mkdir()
    external = tmp_path / "external.bin"
    external.write_bytes(b"outside")
    (root / "linked.bin").symlink_to(external)

    with pytest.raises(DoclingArtifactBundleError, match=r"linked.*special"):
        inspect_docling_artifact_bundle(root)


def test_bundle_rejects_hardlinked_files(tmp_path: Path) -> None:
    root = tmp_path / "models"
    root.mkdir()
    external = tmp_path / "external.bin"
    external.write_bytes(b"shared inode")
    os.link(external, root / "hardlinked.bin")

    with pytest.raises(DoclingArtifactBundleError, match=r"linked.*special"):
        inspect_docling_artifact_bundle(root)


def test_manifest_requires_present_license_evidence(tmp_path: Path) -> None:
    root = tmp_path / "models"
    root.mkdir()
    model = _model(root)
    invalid = DoclingArtifactModel(
        repository=model.repository,
        revision=model.revision,
        license=model.license,
        license_evidence_path="missing-LICENSE",
        source_url=model.source_url,
    )

    with pytest.raises(DoclingArtifactBundleError, match="license evidence"):
        write_docling_artifact_manifest(root, models=(invalid,))
