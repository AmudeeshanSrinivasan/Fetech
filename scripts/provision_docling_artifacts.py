#!/usr/bin/env python3
"""Provision the exact offline model bundle used by Fetech's Docling PDF path."""

from __future__ import annotations

import argparse
import hmac
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _ROOT / "src"
if str(_SOURCE_ROOT) not in sys.path:
    sys.path.insert(0, str(_SOURCE_ROOT))

from fetech.docling_artifacts import (  # noqa: E402
    DOCLING_REFERENCE_BUNDLE_SHA256,
    DOCLING_REFERENCE_MODEL_LICENSE,
    DOCLING_REFERENCE_MODEL_REPOSITORY,
    DOCLING_REFERENCE_MODEL_REVISION,
    DOCLING_SLIM_VERSION,
    DoclingArtifactModel,
    verify_docling_artifact_bundle,
    write_docling_artifact_manifest,
)

_REPOSITORY = DOCLING_REFERENCE_MODEL_REPOSITORY
_MODEL_FOLDER = "docling-project--docling-layout-heron"
_EXPECTED_LICENSE = DOCLING_REFERENCE_MODEL_LICENSE
_LICENSE_EVIDENCE = f"{_MODEL_FOLDER}/README.md"


def _license_from_model_info(info: Any) -> str | None:
    card_data = getattr(info, "card_data", None)
    if card_data is None:
        return None
    value = (
        card_data.get("license")
        if isinstance(card_data, dict)
        else getattr(card_data, "license", None)
    )
    return value if isinstance(value, str) else None


def provision(
    output_dir: Path,
    *,
    cache_dir: Path,
    revision: str,
    expected_sha256: str,
) -> dict[str, object]:
    from huggingface_hub import HfApi, snapshot_download

    output_dir = output_dir.expanduser().absolute()
    cache_dir = cache_dir.expanduser().absolute()
    if (
        len(revision) != 40
        or any(character not in "0123456789abcdef" for character in revision)
        or len(expected_sha256) != 64
        or any(
            character not in "0123456789abcdef"
            for character in expected_sha256
        )
    ):
        raise ValueError(
            "reviewed model revision or expected bundle SHA-256 is invalid"
        )
    if output_dir.exists():
        raise ValueError(
            "output directory already exists; verify or choose a new immutable path"
        )
    output_dir.parent.mkdir(parents=True, exist_ok=True)
    cache_dir.mkdir(parents=True, exist_ok=True)

    info = HfApi().model_info(
        _REPOSITORY,
        revision=revision,
        files_metadata=True,
    )
    resolved_revision = getattr(info, "sha", None)
    observed_license = _license_from_model_info(info)
    if (
        not isinstance(resolved_revision, str)
        or len(resolved_revision) != 40
        or any(character not in "0123456789abcdef" for character in resolved_revision)
    ):
        raise ValueError("Hugging Face did not return an immutable model revision")
    if resolved_revision != revision:
        raise ValueError("resolved model revision does not match the requested revision")
    if observed_license != _EXPECTED_LICENSE:
        raise ValueError(
            "published model license does not match the reviewed Apache-2.0 identifier"
        )

    snapshot = Path(
        snapshot_download(
            repo_id=_REPOSITORY,
            revision=resolved_revision,
            cache_dir=cache_dir,
        )
    )
    staging = Path(
        tempfile.mkdtemp(
            prefix=f".{output_dir.name}.",
            dir=output_dir.parent,
        )
    )
    published = False
    try:
        model_dir = staging / _MODEL_FOLDER
        shutil.copytree(snapshot, model_dir, symlinks=False)
        model = DoclingArtifactModel(
            repository=_REPOSITORY,
            revision=resolved_revision,
            license=_EXPECTED_LICENSE,
            license_evidence_path=_LICENSE_EVIDENCE,
            source_url=(
                f"https://huggingface.co/{_REPOSITORY}/tree/{resolved_revision}"
            ),
        )
        bundle = write_docling_artifact_manifest(staging, models=(model,))
        if not hmac.compare_digest(bundle.bundle_sha256, expected_sha256):
            raise ValueError(
                "downloaded model bundle does not match the reviewed SHA-256"
            )
        staging.rename(output_dir)
        published = True
        _make_tree_read_only(output_dir)
        bundle = verify_docling_artifact_bundle(
            output_dir,
            expected_sha256=expected_sha256,
        )
    except BaseException:
        failed_root = output_dir if published else staging
        _make_tree_owner_writable(failed_root)
        shutil.rmtree(failed_root, ignore_errors=True)
        raise
    return {
        "bundle_sha256": bundle.bundle_sha256,
        "docling_slim_version": DOCLING_SLIM_VERSION,
        "file_count": len(bundle.files),
        "license": _EXPECTED_LICENSE,
        "model_repository": _REPOSITORY,
        "model_revision": resolved_revision,
        "output_dir": str(output_dir),
        "total_bytes": bundle.total_bytes,
    }


def verify(
    output_dir: Path,
    *,
    expected_sha256: str,
) -> dict[str, object]:
    output_dir = output_dir.expanduser().resolve(strict=True)
    bundle = verify_docling_artifact_bundle(
        output_dir,
        expected_sha256=expected_sha256,
    )
    return {
        "bundle_sha256": bundle.bundle_sha256,
        "docling_slim_version": DOCLING_SLIM_VERSION,
        "file_count": len(bundle.files),
        "models": [
            {
                "license": model.license,
                "repository": model.repository,
                "revision": model.revision,
                "source_url": model.source_url,
            }
            for model in bundle.models
        ],
        "output_dir": str(output_dir),
        "total_bytes": bundle.total_bytes,
    }


def _make_tree_read_only(root: Path) -> None:
    """Remove write bits after publication; release deployments still need root ownership."""

    for directory, directory_names, file_names in os.walk(
        root,
        topdown=False,
        followlinks=False,
    ):
        directory_path = Path(directory)
        for name in file_names:
            (directory_path / name).chmod(0o444)
        for name in directory_names:
            (directory_path / name).chmod(0o555)
        directory_path.chmod(0o555)


def _make_tree_owner_writable(root: Path) -> None:
    if not root.exists():
        return
    for directory, directory_names, file_names in os.walk(
        root,
        topdown=True,
        followlinks=False,
    ):
        directory_path = Path(directory)
        directory_path.chmod(
            directory_path.stat(follow_symlinks=False).st_mode | 0o700
        )
        for name in directory_names:
            path = directory_path / name
            path.chmod(path.stat(follow_symlinks=False).st_mode | 0o700)
        for name in file_names:
            path = directory_path / name
            path.chmod(path.stat(follow_symlinks=False).st_mode | 0o600)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("runtime-data/docling-models/2.113.0"),
        help="new project-local model root (must not already exist)",
    )
    parser.add_argument(
        "--cache-dir",
        type=Path,
        default=Path("runtime-data/docling-download-cache"),
        help="ignored Hugging Face transfer cache",
    )
    parser.add_argument(
        "--revision",
        default=DOCLING_REFERENCE_MODEL_REVISION,
        help="exact reviewed Hugging Face commit",
    )
    parser.add_argument(
        "--expected-sha256",
        default=DOCLING_REFERENCE_BUNDLE_SHA256,
        help="independent expected SHA-256 for the final canonical bundle",
    )
    parser.add_argument(
        "--verify-only",
        action="store_true",
        help="validate an existing manifest and every reviewed file without network access",
    )
    arguments = parser.parse_args()
    result = (
        verify(
            arguments.output_dir,
            expected_sha256=arguments.expected_sha256,
        )
        if arguments.verify_only
        else provision(
            arguments.output_dir,
            cache_dir=arguments.cache_dir,
            revision=arguments.revision,
            expected_sha256=arguments.expected_sha256,
        )
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
