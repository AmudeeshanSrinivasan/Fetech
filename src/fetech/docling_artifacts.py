"""Content-bound manifests for explicitly provisioned Docling model bundles."""

from __future__ import annotations

import hmac
import json
import os
import re
import stat
import unicodedata
from collections.abc import Iterable
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import urlsplit

DOCLING_ARTIFACT_MANIFEST = "fetech-docling-bundle.v1.json"
DOCLING_ARTIFACT_SCHEMA = "fetech.docling-artifact-bundle.v1"
DOCLING_SLIM_VERSION = "2.113.0"
DOCLING_COMPONENT_VERSIONS = (
    ("docling-core", "2.87.1"),
    ("docling-ibm-models", "3.13.3"),
    ("docling-parse", "7.8.0"),
    ("docling-slim", DOCLING_SLIM_VERSION),
)
DOCLING_REFERENCE_BUNDLE_SHA256 = (
    "e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76"
)
DOCLING_REFERENCE_MODEL_REPOSITORY = (
    "docling-project/docling-layout-heron"
)
DOCLING_REFERENCE_MODEL_REVISION = (
    "8f39ad3c0b4c58e9c2d2c84a38465abf757272d8"
)
DOCLING_REFERENCE_MODEL_LICENSE = "apache-2.0"

_MAX_ARTIFACT_FILES = 4_096
_MAX_ARTIFACT_BYTES = 16 * 1024 * 1024 * 1024
_MAX_ARTIFACT_FILE_BYTES = 8 * 1024 * 1024 * 1024
_MAX_ARTIFACT_DIRECTORIES = 1_024
_MAX_ARTIFACT_DEPTH = 16
_MAX_ARTIFACT_PATH_BYTES = 1_024
_MAX_MANIFEST_BYTES = 2 * 1024 * 1024
_HASH_CHUNK_BYTES = 1024 * 1024
_SHA256_HEX = re.compile(r"[0-9a-f]{64}\Z")
_HF_REVISION = re.compile(r"[0-9a-f]{40,64}\Z")
_MODEL_REPOSITORY = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]{0,95}/[A-Za-z0-9][A-Za-z0-9._-]{0,95}\Z"
)
_LICENSE_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}\Z")


class DoclingArtifactBundleError(ValueError):
    """The configured model bundle is unsafe, malformed, or changed."""


@dataclass(frozen=True, slots=True)
class DoclingArtifactFile:
    path: str
    size: int
    sha256: str

    def as_dict(self) -> dict[str, object]:
        return {"path": self.path, "sha256": self.sha256, "size": self.size}


@dataclass(frozen=True, slots=True)
class DoclingArtifactModel:
    repository: str
    revision: str
    license: str
    license_evidence_path: str
    source_url: str

    def as_dict(self) -> dict[str, str]:
        return {
            "license": self.license,
            "license_evidence_path": self.license_evidence_path,
            "repository": self.repository,
            "revision": self.revision,
            "source_url": self.source_url,
        }


@dataclass(frozen=True, slots=True)
class DoclingArtifactBundle:
    bundle_sha256: str
    files: tuple[DoclingArtifactFile, ...]
    models: tuple[DoclingArtifactModel, ...]
    total_bytes: int
    manifest_present: bool


def build_docling_artifact_manifest(
    root: Path,
    *,
    models: tuple[DoclingArtifactModel, ...],
) -> dict[str, object]:
    """Build a deterministic manifest for an already downloaded model tree."""

    if not models:
        raise DoclingArtifactBundleError(
            "Docling artifact manifest requires at least one model"
        )
    files = _scan_artifact_files(root, exclude_manifest=True)
    file_paths = {item.path for item in files}
    for model in models:
        _validate_model(model, file_paths=file_paths)
    total_bytes = sum(item.size for item in files)
    return {
        "docling_slim_version": DOCLING_SLIM_VERSION,
        "file_count": len(files),
        "files": [item.as_dict() for item in files],
        "models": [
            model.as_dict()
            for model in sorted(models, key=lambda item: item.repository)
        ],
        "schema": DOCLING_ARTIFACT_SCHEMA,
        "total_bytes": total_bytes,
    }


def write_docling_artifact_manifest(
    root: Path,
    *,
    models: tuple[DoclingArtifactModel, ...],
) -> DoclingArtifactBundle:
    """Write and immediately revalidate a canonical bundle manifest."""

    manifest_path = root / DOCLING_ARTIFACT_MANIFEST
    if manifest_path.exists() or manifest_path.is_symlink():
        raise DoclingArtifactBundleError(
            "Docling artifact manifest already exists"
        )
    manifest = build_docling_artifact_manifest(root, models=models)
    manifest_path.write_bytes(_canonical_json(manifest) + b"\n")
    return inspect_docling_artifact_bundle(root, require_manifest=True)


def inspect_docling_artifact_bundle(
    root: Path,
    *,
    require_manifest: bool = False,
) -> DoclingArtifactBundle:
    """Validate a bounded model tree and return its portable content identity."""

    manifest_path = root / DOCLING_ARTIFACT_MANIFEST
    if manifest_path.is_symlink():
        raise DoclingArtifactBundleError(
            "Docling artifact manifest cannot be a symbolic link"
        )
    if not manifest_path.exists():
        if require_manifest:
            raise DoclingArtifactBundleError(
                "Docling artifact bundle requires a reviewed manifest"
            )
        files = _scan_artifact_files(root, exclude_manifest=False)
        total_bytes = sum(item.size for item in files)
        payload = {
            "files": [item.as_dict() for item in files],
            "schema": "fetech.docling-artifact-content.v1",
            "total_bytes": total_bytes,
        }
        return DoclingArtifactBundle(
            bundle_sha256=sha256(_canonical_json(payload)).hexdigest(),
            files=files,
            models=(),
            total_bytes=total_bytes,
            manifest_present=False,
        )

    try:
        root_metadata = root.stat(follow_symlinks=False)
        manifest_metadata = manifest_path.lstat()
    except OSError as exc:
        raise DoclingArtifactBundleError(
            "Docling artifact manifest is unavailable"
        ) from exc
    if (
        not stat.S_ISDIR(root_metadata.st_mode)
        or not stat.S_ISREG(manifest_metadata.st_mode)
        or manifest_metadata.st_dev != root_metadata.st_dev
        or manifest_metadata.st_nlink != 1
        or not 0 < manifest_metadata.st_size <= _MAX_MANIFEST_BYTES
    ):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest is unsafe or exceeds its byte limit"
        )
    try:
        raw_manifest = _read_regular_file(
            manifest_path,
            manifest_metadata,
            maximum_bytes=_MAX_MANIFEST_BYTES,
        )
        manifest = json.loads(raw_manifest)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise DoclingArtifactBundleError(
            "Docling artifact manifest is invalid"
        ) from exc
    if raw_manifest != _canonical_json(manifest) + b"\n":
        raise DoclingArtifactBundleError(
            "Docling artifact manifest is not canonical"
        )
    normalized, expected_files, models = _validate_manifest(manifest)
    observed_files = _scan_artifact_files(root, exclude_manifest=True)
    if observed_files != expected_files:
        raise DoclingArtifactBundleError(
            "Docling artifact files do not match the reviewed manifest"
        )
    return DoclingArtifactBundle(
        bundle_sha256=sha256(_canonical_json(normalized)).hexdigest(),
        files=observed_files,
        models=models,
        total_bytes=sum(item.size for item in observed_files),
        manifest_present=True,
    )


def verify_docling_artifact_bundle(
    root: Path,
    *,
    expected_sha256: str,
) -> DoclingArtifactBundle:
    """Validate a manifest-bound tree against an independent trust anchor."""

    if (
        not isinstance(expected_sha256, str)
        or _SHA256_HEX.fullmatch(expected_sha256) is None
    ):
        raise DoclingArtifactBundleError(
            "expected Docling artifact SHA-256 is invalid"
        )
    bundle = inspect_docling_artifact_bundle(root, require_manifest=True)
    if not hmac.compare_digest(bundle.bundle_sha256, expected_sha256):
        raise DoclingArtifactBundleError(
            "Docling artifact bundle does not match the expected SHA-256"
        )
    return bundle


def docling_artifact_root_identity(root: Path) -> str:
    """Return a local object identity for cheap path-replacement detection."""

    try:
        metadata = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise DoclingArtifactBundleError(
            "Docling artifact root is unavailable"
        ) from exc
    if not stat.S_ISDIR(metadata.st_mode):
        raise DoclingArtifactBundleError(
            "Docling artifact root is not a directory"
        )
    payload = "\0".join(
        (
            "fetech-docling-artifact-root-v1",
            str(metadata.st_dev),
            str(metadata.st_ino),
            str(metadata.st_mode),
            str(metadata.st_uid),
            str(metadata.st_gid),
            str(metadata.st_mtime_ns),
        )
    ).encode("ascii")
    return sha256(payload).hexdigest()


def _scan_artifact_files(
    root: Path,
    *,
    exclude_manifest: bool,
) -> tuple[DoclingArtifactFile, ...]:
    try:
        root_metadata = root.stat(follow_symlinks=False)
    except OSError as exc:
        raise DoclingArtifactBundleError(
            "Docling artifact root is unavailable"
        ) from exc
    if not stat.S_ISDIR(root_metadata.st_mode):
        raise DoclingArtifactBundleError(
            "Docling artifact root is not a directory"
        )

    records: list[DoclingArtifactFile] = []
    total_bytes = 0
    directory_count = 0
    try:
        for directory, directory_names, file_names in os.walk(
            root,
            topdown=True,
            followlinks=False,
        ):
            directory_names.sort()
            file_names.sort()
            directory_path = Path(directory)
            relative_directory = directory_path.relative_to(root)
            directory_count += 1
            if (
                directory_count > _MAX_ARTIFACT_DIRECTORIES
                or len(relative_directory.parts) > _MAX_ARTIFACT_DEPTH
            ):
                raise DoclingArtifactBundleError(
                    "Docling artifact tree exceeds its directory bounds"
                )
            for name in directory_names:
                metadata = (directory_path / name).lstat()
                if (
                    not stat.S_ISDIR(metadata.st_mode)
                    or metadata.st_dev != root_metadata.st_dev
                ):
                    raise DoclingArtifactBundleError(
                        "Docling artifact tree contains a linked, special, or cross-device directory"
                    )
            for name in file_names:
                file_path = directory_path / name
                relative_path = file_path.relative_to(root).as_posix()
                if exclude_manifest and relative_path == DOCLING_ARTIFACT_MANIFEST:
                    continue
                _validate_relative_path(relative_path)
                metadata = file_path.lstat()
                if (
                    not stat.S_ISREG(metadata.st_mode)
                    or metadata.st_dev != root_metadata.st_dev
                    or metadata.st_nlink != 1
                    or metadata.st_size > _MAX_ARTIFACT_FILE_BYTES
                ):
                    raise DoclingArtifactBundleError(
                        "Docling artifact tree contains a linked, special, cross-device, or oversized file"
                    )
                total_bytes += metadata.st_size
                if (
                    len(records) >= _MAX_ARTIFACT_FILES
                    or total_bytes > _MAX_ARTIFACT_BYTES
                ):
                    raise DoclingArtifactBundleError(
                        "Docling artifact tree exceeds its review bounds"
                    )
                records.append(
                    DoclingArtifactFile(
                        path=relative_path,
                        size=metadata.st_size,
                        sha256=_hash_regular_file(file_path, metadata),
                    )
                )
    except OSError as exc:
        raise DoclingArtifactBundleError(
            "Docling artifact tree could not be inspected"
        ) from exc
    _validate_unique_portable_paths(item.path for item in records)
    return tuple(records)


def _hash_regular_file(path: Path, expected: os.stat_result) -> str:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    digest = sha256()
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != expected.st_dev
            or opened.st_ino != expected.st_ino
            or opened.st_size != expected.st_size
            or opened.st_nlink != 1
        ):
            raise DoclingArtifactBundleError(
                "Docling artifact file changed during inspection"
            )
        while chunk := os.read(descriptor, _HASH_CHUNK_BYTES):
            digest.update(chunk)
        completed = os.fstat(descriptor)
        if (
            completed.st_size != opened.st_size
            or completed.st_mtime_ns != opened.st_mtime_ns
            or completed.st_ino != opened.st_ino
            or completed.st_dev != opened.st_dev
            or completed.st_nlink != 1
        ):
            raise DoclingArtifactBundleError(
                "Docling artifact file changed during inspection"
            )
    finally:
        os.close(descriptor)
    return digest.hexdigest()


def _read_regular_file(
    path: Path,
    expected: os.stat_result,
    *,
    maximum_bytes: int,
) -> bytes:
    flags = os.O_RDONLY
    if hasattr(os, "O_BINARY"):
        flags |= os.O_BINARY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    content = bytearray()
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_dev != expected.st_dev
            or opened.st_ino != expected.st_ino
            or opened.st_size != expected.st_size
            or opened.st_nlink != 1
        ):
            raise DoclingArtifactBundleError(
                "Docling artifact manifest changed during inspection"
            )
        while chunk := os.read(descriptor, min(_HASH_CHUNK_BYTES, maximum_bytes + 1)):
            content.extend(chunk)
            if len(content) > maximum_bytes:
                raise DoclingArtifactBundleError(
                    "Docling artifact manifest exceeds its byte limit"
                )
        completed = os.fstat(descriptor)
        if (
            completed.st_size != opened.st_size
            or completed.st_mtime_ns != opened.st_mtime_ns
            or completed.st_ino != opened.st_ino
            or completed.st_dev != opened.st_dev
            or completed.st_nlink != 1
        ):
            raise DoclingArtifactBundleError(
                "Docling artifact manifest changed during inspection"
            )
    finally:
        os.close(descriptor)
    return bytes(content)


def _validate_manifest(
    value: Any,
) -> tuple[
    dict[str, object],
    tuple[DoclingArtifactFile, ...],
    tuple[DoclingArtifactModel, ...],
]:
    required = {
        "docling_slim_version",
        "file_count",
        "files",
        "models",
        "schema",
        "total_bytes",
    }
    if not isinstance(value, dict) or set(value) != required:
        raise DoclingArtifactBundleError(
            "Docling artifact manifest schema is invalid"
        )
    if (
        value["schema"] != DOCLING_ARTIFACT_SCHEMA
        or value["docling_slim_version"] != DOCLING_SLIM_VERSION
    ):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest version is unsupported"
        )
    raw_files = value["files"]
    raw_models = value["models"]
    if not isinstance(raw_files, list) or not isinstance(raw_models, list):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest inventory is invalid"
        )
    files = tuple(_parse_file(item) for item in raw_files)
    if not files or tuple(sorted(files, key=lambda item: item.path)) != files:
        raise DoclingArtifactBundleError(
            "Docling artifact manifest files must be sorted and non-empty"
        )
    paths = [item.path for item in files]
    if len(set(paths)) != len(paths):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest contains duplicate paths"
        )
    _validate_unique_portable_paths(paths)
    if (
        value["file_count"] != len(files)
        or value["total_bytes"] != sum(item.size for item in files)
    ):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest totals are invalid"
        )
    models = tuple(_parse_model(item, file_paths=set(paths)) for item in raw_models)
    if (
        not models
        or tuple(sorted(models, key=lambda item: item.repository)) != models
        or len({item.repository for item in models}) != len(models)
    ):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest models are invalid"
        )
    normalized = {
        "docling_slim_version": DOCLING_SLIM_VERSION,
        "file_count": len(files),
        "files": [item.as_dict() for item in files],
        "models": [item.as_dict() for item in models],
        "schema": DOCLING_ARTIFACT_SCHEMA,
        "total_bytes": sum(item.size for item in files),
    }
    return normalized, files, models


def _parse_file(value: Any) -> DoclingArtifactFile:
    if not isinstance(value, dict) or set(value) != {"path", "sha256", "size"}:
        raise DoclingArtifactBundleError(
            "Docling artifact manifest file entry is invalid"
        )
    path = value["path"]
    size = value["size"]
    digest = value["sha256"]
    if (
        not isinstance(path, str)
        or not isinstance(size, int)
        or isinstance(size, bool)
        or size < 0
        or not isinstance(digest, str)
        or _SHA256_HEX.fullmatch(digest) is None
    ):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest file entry is invalid"
        )
    _validate_relative_path(path)
    return DoclingArtifactFile(path=path, size=size, sha256=digest)


def _parse_model(
    value: Any,
    *,
    file_paths: set[str],
) -> DoclingArtifactModel:
    if not isinstance(value, dict):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest model entry is invalid"
        )
    try:
        model = DoclingArtifactModel(
            repository=value["repository"],
            revision=value["revision"],
            license=value["license"],
            license_evidence_path=value["license_evidence_path"],
            source_url=value["source_url"],
        )
    except (KeyError, TypeError) as exc:
        raise DoclingArtifactBundleError(
            "Docling artifact manifest model entry is invalid"
        ) from exc
    if set(value) != set(model.as_dict()):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest model entry is invalid"
        )
    _validate_model(model, file_paths=file_paths)
    return model


def _validate_model(
    model: DoclingArtifactModel,
    *,
    file_paths: set[str],
) -> None:
    if not all(
        isinstance(value, str)
        for value in (
            model.repository,
            model.revision,
            model.license,
            model.license_evidence_path,
            model.source_url,
        )
    ):
        raise DoclingArtifactBundleError(
            "Docling artifact model provenance is invalid"
        )
    split = urlsplit(model.source_url)
    expected_source_path = f"/{model.repository}/tree/{model.revision}"
    if (
        _MODEL_REPOSITORY.fullmatch(model.repository) is None
        or _HF_REVISION.fullmatch(model.revision) is None
        or _LICENSE_ID.fullmatch(model.license) is None
        or split.scheme != "https"
        or split.hostname != "huggingface.co"
        or split.username is not None
        or split.password is not None
        or split.path.rstrip("/") != expected_source_path
        or split.query
        or split.fragment
    ):
        raise DoclingArtifactBundleError(
            "Docling artifact model provenance is invalid"
        )
    _validate_relative_path(model.license_evidence_path)
    if model.license_evidence_path not in file_paths:
        raise DoclingArtifactBundleError(
            "Docling artifact license evidence is missing"
        )


def _validate_relative_path(value: str) -> None:
    candidate = PurePosixPath(value)
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or unicodedata.normalize("NFC", value) != value
        or any(unicodedata.category(character).startswith("C") for character in value)
        or len(value.encode("utf-8")) > _MAX_ARTIFACT_PATH_BYTES
        or candidate.is_absolute()
        or value != candidate.as_posix()
        or any(part in {"", ".", ".."} for part in candidate.parts)
        or value == DOCLING_ARTIFACT_MANIFEST
    ):
        raise DoclingArtifactBundleError(
            "Docling artifact manifest path is invalid"
        )


def _validate_unique_portable_paths(values: Iterable[str]) -> None:
    observed: set[str] = set()
    for value in values:
        folded = unicodedata.normalize("NFC", value).casefold()
        if folded in observed:
            raise DoclingArtifactBundleError(
                "Docling artifact paths collide on a portable filesystem"
            )
        observed.add(folded)


def _canonical_json(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
