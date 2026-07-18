#!/usr/bin/env python3
"""Verify the exact v0.4 wheel, sdist, and SHA-256 release assets.

The verifier deliberately derives trust from a clean Git checkout and the
artifact bytes.  It never treats a receipt or checksum file's mere presence as
evidence.  The returned receipt is deterministic, bounded, and contains no
absolute paths.
"""

from __future__ import annotations

import argparse
import base64
import configparser
import csv
import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from email.message import Message
from email.parser import Parser
from pathlib import Path, PurePosixPath
from typing import Final

TARGET_VERSION: Final = "0.4.0a0"
PROJECT_NAME: Final = "fetech"
WHEEL_FILENAME: Final = f"fetech-{TARGET_VERSION}-py3-none-any.whl"
SDIST_FILENAME: Final = f"fetech-{TARGET_VERSION}.tar.gz"
CHECKSUMS_FILENAME: Final = "SHA256SUMS"
RECEIPT_SCHEMA: Final = "fetech.v0.4.release-artifacts.v1"

_MAX_ARTIFACT_BYTES: Final = 256_000_000
_MAX_ARCHIVE_MEMBER_BYTES: Final = 64_000_000
_MAX_ARCHIVE_EXPANDED_BYTES: Final = 512_000_000
_MAX_ARCHIVE_MEMBERS: Final = 10_000
_MAX_METADATA_BYTES: Final = 2_000_000
_MAX_CHECKSUM_BYTES: Final = 4_096
_MAX_GIT_OUTPUT_BYTES: Final = 8_000_000
_COMMIT_ID = re.compile(r"(?:[0-9a-f]{40}|[0-9a-f]{64})\Z")
_REQUIREMENT = re.compile(
    r"""
    \A\s*
    (?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)
    (?:\[(?P<extras>[A-Za-z0-9._,-]+)\])?
    (?P<specifier>[^;]*?)
    (?:\s*;\s*(?P<marker>.+))?
    \s*\Z
    """,
    re.VERBOSE,
)
_SPECIFIER = re.compile(r"(===|~=|==|!=|<=|>=|<|>)\s*([^,\s]+)\Z")


class ArtifactVerificationError(ValueError):
    """A sanitized release-artifact verification failure."""


@dataclass(frozen=True)
class _FileState:
    size: int
    sha256: str
    device: int
    inode: int
    mode: int
    modified_ns: int
    changed_ns: int


def _fail(message: str) -> ArtifactVerificationError:
    return ArtifactVerificationError(message)


def _regular_file(path: Path, label: str, *, maximum_bytes: int) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        raise _fail(f"{label} must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        size = resolved.stat().st_size
    except OSError as exc:
        raise _fail(f"{label} is unavailable") from exc
    if not resolved.is_file() or size < 0 or size > maximum_bytes:
        raise _fail(f"{label} is not a bounded regular file")
    return resolved


def _capture_file(
    path: Path,
    *,
    maximum_bytes: int,
    copy_to: Path | None = None,
) -> _FileState:
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
    except OSError as exc:
        raise _fail("artifact could not be opened safely") from exc
    try:
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size < 0 or before.st_size > maximum_bytes:
                raise _fail("artifact is not a bounded regular file")
            destination = copy_to.open("xb") if copy_to is not None else None
            try:
                digest = hashlib.sha256()
                consumed = 0
                while chunk := stream.read(1_048_576):
                    consumed += len(chunk)
                    if consumed > maximum_bytes:
                        raise _fail("artifact exceeds its byte bound")
                    digest.update(chunk)
                    if destination is not None:
                        destination.write(chunk)
            finally:
                if destination is not None:
                    destination.close()
            after = os.fstat(stream.fileno())
    except ArtifactVerificationError:
        raise
    except OSError as exc:
        raise _fail("artifact could not be captured") from exc
    identity_before = (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    )
    identity_after = (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identity_before != identity_after or consumed != before.st_size:
        raise _fail("artifact changed while it was being captured")
    return _FileState(
        size=consumed,
        sha256=digest.hexdigest(),
        device=before.st_dev,
        inode=before.st_ino,
        mode=before.st_mode,
        modified_ns=before.st_mtime_ns,
        changed_ns=before.st_ctime_ns,
    )


def _assert_file_unchanged(
    path: Path,
    expected: _FileState,
    *,
    maximum_bytes: int,
) -> None:
    observed = _capture_file(path, maximum_bytes=maximum_bytes)
    if not hmac.compare_digest(observed.sha256, expected.sha256) or observed != expected:
        raise _fail("release artifact changed during verification")


def _git_output(project_root: Path, *arguments: str) -> bytes:
    try:
        process = subprocess.run(
            ("git", "-C", str(project_root), *arguments),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _fail("Git source verification did not complete") from exc
    if (
        process.returncode != 0
        or len(process.stdout) > _MAX_GIT_OUTPUT_BYTES
        or len(process.stderr) > _MAX_GIT_OUTPUT_BYTES
    ):
        raise _fail("Git source verification failed")
    return process.stdout


def _source_identity(project_root: Path) -> tuple[str, frozenset[str]]:
    try:
        top_level = Path(
            _git_output(project_root, "rev-parse", "--show-toplevel").decode("utf-8", errors="strict").strip()
        ).resolve(strict=True)
    except (OSError, UnicodeDecodeError) as exc:
        raise _fail("Git returned an invalid worktree root") from exc
    if top_level != project_root:
        raise _fail("project root must be the Git worktree root")
    commit = (
        _git_output(project_root, "rev-parse", "--verify", "HEAD^{commit}")
        .decode("ascii", errors="strict")
        .strip()
    )
    if _COMMIT_ID.fullmatch(commit) is None:
        raise _fail("Git returned an invalid commit identity")
    status = _git_output(
        project_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        "--",
    )
    if status:
        raise _fail("release artifacts require a clean Git source tree")
    raw_paths = _git_output(
        project_root,
        "ls-tree",
        "-r",
        "--name-only",
        "-z",
        commit,
    )
    try:
        decoded = raw_paths.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise _fail("tracked source paths are not valid UTF-8") from exc
    paths = decoded.split("\0")
    if paths and paths[-1] == "":
        paths.pop()
    if not paths or len(paths) != len(set(paths)):
        raise _fail("tracked source inventory is empty or ambiguous")
    for path in paths:
        _safe_archive_path(path)
    return commit, frozenset(paths)


def _git_blob(project_root: Path, commit: str, relative_path: str) -> bytes:
    try:
        return _git_output(
            project_root,
            "cat-file",
            "blob",
            f"{commit}:{relative_path}",
        )
    except ArtifactVerificationError as exc:
        raise _fail("a committed release source blob is unavailable") from exc


def _load_project_metadata(
    project_root: Path,
    commit: str,
    tracked_paths: frozenset[str],
    expected_version: str,
) -> tuple[Mapping[str, object], Mapping[str, object]]:
    try:
        project_document = tomllib.loads(
            _source_bytes(
                project_root,
                commit,
                tracked_paths,
                "pyproject.toml",
            ).decode("utf-8", errors="strict")
        )
        lock_document = tomllib.loads(
            _source_bytes(
                project_root,
                commit,
                tracked_paths,
                "uv.lock",
            ).decode("utf-8", errors="strict")
        )
        project = project_document["project"]
        packages = lock_document["package"]
    except (UnicodeDecodeError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise _fail("package or lock metadata is unavailable or invalid") from exc
    if (
        not isinstance(project, dict)
        or project.get("name") != PROJECT_NAME
        or project.get("version") != expected_version
        or not isinstance(packages, list)
    ):
        raise _fail("project metadata does not identify the target Fetech release")
    root_versions = [
        package.get("version")
        for package in packages
        if isinstance(package, dict) and package.get("name") == PROJECT_NAME
    ]
    if root_versions != [expected_version]:
        raise _fail("the lock has no unique target-version Fetech root package")
    return project_document, project


def _safe_archive_path(value: str) -> PurePosixPath:
    if not value or "\x00" in value or "\\" in value:
        raise _fail("archive contains an unsafe member path")
    raw_parts = value.split("/")
    if any(part in {"", ".", ".."} for part in raw_parts):
        raise _fail("archive contains an unsafe member path")
    path = PurePosixPath(*raw_parts)
    if path.as_posix() != value:
        raise _fail("archive contains a non-canonical member path")
    return path


def _source_bytes(
    project_root: Path,
    commit: str,
    tracked_paths: frozenset[str],
    relative_path: str,
) -> bytes:
    if relative_path not in tracked_paths:
        raise _fail("a packaged source file is not present in the committed tree")
    _safe_archive_path(relative_path)
    payload = _git_blob(project_root, commit, relative_path)
    if len(payload) > _MAX_ARCHIVE_MEMBER_BYTES:
        raise _fail("a packaged source file exceeds its byte bound")
    return payload


def _wheel_source_mapping(tracked_paths: frozenset[str]) -> dict[str, str]:
    mapping = {path.removeprefix("src/"): path for path in tracked_paths if path.startswith("src/fetech/")}
    if "capabilities/manifest.yaml" in tracked_paths:
        mapping["fetech/data/manifest.yaml"] = "capabilities/manifest.yaml"
    if "fetech/__init__.py" not in mapping or "fetech/data/manifest.yaml" not in mapping:
        raise _fail("the tracked wheel source inventory is incomplete")
    return mapping


def _zip_payloads(wheel: Path) -> dict[str, bytes]:
    try:
        with zipfile.ZipFile(wheel) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if not infos or len(infos) > _MAX_ARCHIVE_MEMBERS or len(names) != len(set(names)):
                raise _fail("wheel member inventory is empty, duplicated, or oversized")
            total = 0
            payloads: dict[str, bytes] = {}
            canonical_names: set[str] = set()
            for info in infos:
                canonical_name = _safe_archive_path(info.filename).as_posix()
                if canonical_name in canonical_names:
                    raise _fail("wheel contains canonically duplicate member paths")
                canonical_names.add(canonical_name)
                mode = (info.external_attr >> 16) & 0o170000
                if (
                    info.is_dir()
                    or mode not in {0, stat.S_IFREG}
                    or info.flag_bits & 0x1
                    or info.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
                ):
                    raise _fail("wheel contains a non-regular, encrypted, or unsupported member")
                if info.file_size < 0 or info.file_size > _MAX_ARCHIVE_MEMBER_BYTES:
                    raise _fail("wheel member exceeds its byte bound")
                total += info.file_size
                if total > _MAX_ARCHIVE_EXPANDED_BYTES:
                    raise _fail("wheel expanded content exceeds its byte bound")
                payload = archive.read(info)
                if len(payload) != info.file_size:
                    raise _fail("wheel member size changed while reading")
                payloads[info.filename] = payload
    except ArtifactVerificationError:
        raise
    except Exception as exc:
        raise _fail("wheel is not a valid bounded ZIP archive") from exc
    return payloads


def _metadata_message(payload: bytes, label: str) -> Message[str, str]:
    if len(payload) > _MAX_METADATA_BYTES:
        raise _fail(f"{label} exceeds its byte bound")
    try:
        message = Parser().parsestr(payload.decode("utf-8", errors="strict"))
    except Exception as exc:
        raise _fail(f"{label} is not valid UTF-8 metadata") from exc
    if message.defects or message.is_multipart():
        raise _fail(f"{label} contains malformed metadata")
    return message


def _header_values(message: Message[str, str], name: str) -> tuple[str, ...]:
    values = message.get_all(name, [])
    if values is None:
        return ()
    if any(not isinstance(value, str) for value in values):
        raise _fail(f"package metadata contains an invalid {name} field")
    return tuple(values)


def _single_header(
    message: Message[str, str],
    name: str,
    *,
    required: bool,
) -> str | None:
    values = _header_values(message, name)
    if len(values) > 1 or (required and len(values) != 1):
        raise _fail(f"package metadata must contain a unique {name} field")
    return values[0] if values else None


def _normalize_distribution_name(value: str) -> str:
    normalized = re.sub(r"[-_.]+", "-", value).casefold()
    if not normalized:
        raise _fail("package metadata contains an invalid distribution name")
    return normalized


def _normalize_marker(value: str) -> str:
    marker = value.strip().replace('"', "'")
    marker = re.sub(r"\s*(===|==|!=|<=|>=|<|>)\s*", r" \1 ", marker)
    marker = re.sub(r"\s+", " ", marker)
    marker = re.sub(
        r"\bextra\s*==\s*'([^']+)'",
        lambda match: f"extra == '{_normalize_distribution_name(match.group(1))}'",
        marker,
        flags=re.IGNORECASE,
    )
    return marker


def _requirement_key(
    value: str,
    *,
    optional_extra: str | None = None,
) -> tuple[str, tuple[str, ...], tuple[str, ...], str]:
    match = _REQUIREMENT.fullmatch(value)
    if match is None:
        raise _fail("package metadata contains an unsupported requirement")
    name = _normalize_distribution_name(match.group("name"))
    extras_raw = match.group("extras")
    extras = (
        tuple(sorted(_normalize_distribution_name(extra.strip()) for extra in extras_raw.split(",")))
        if extras_raw
        else ()
    )
    specifier_raw = match.group("specifier").strip()
    if specifier_raw.startswith("(") and specifier_raw.endswith(")"):
        specifier_raw = specifier_raw[1:-1].strip()
    specifiers: list[str] = []
    if specifier_raw:
        for raw_specifier in specifier_raw.split(","):
            specifier = _SPECIFIER.fullmatch(raw_specifier.strip())
            if specifier is None:
                raise _fail("package metadata contains an unsupported requirement")
            specifiers.append(f"{specifier.group(1)}{specifier.group(2)}")
    marker = _normalize_marker(match.group("marker") or "")
    if optional_extra is not None:
        normalized_extra = _normalize_distribution_name(optional_extra)
        extra_marker = f"extra == '{normalized_extra}'"
        marker = f"({marker}) and {extra_marker}" if marker else extra_marker
    return name, extras, tuple(sorted(specifiers)), marker


def _string_list(value: object, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise _fail(f"project metadata contains an invalid {label} field")
    return tuple(value)


def _verify_core_metadata(
    message: Message[str, str],
    project: Mapping[str, object],
    expected_version: str,
) -> None:
    if _single_header(message, "Metadata-Version", required=True) != "2.4":
        raise _fail("package metadata uses an unexpected metadata version")
    name = _single_header(message, "Name", required=True)
    version = _single_header(message, "Version", required=True)
    if name is None or _normalize_distribution_name(name) != PROJECT_NAME or version != expected_version:
        raise _fail("package metadata identifies a different project or version")

    expected_summary = project.get("description")
    if expected_summary is not None and not isinstance(expected_summary, str):
        raise _fail("project metadata contains an invalid description")
    if _single_header(message, "Summary", required=False) != expected_summary:
        raise _fail("package summary differs from project metadata")

    expected_requires_python = project.get("requires-python")
    if expected_requires_python is not None and not isinstance(expected_requires_python, str):
        raise _fail("project metadata contains an invalid requires-python field")
    if _single_header(message, "Requires-Python", required=False) != expected_requires_python:
        raise _fail("package Python requirement differs from project metadata")

    expected_keywords = tuple(sorted(_string_list(project.get("keywords"), "keywords")))
    keywords_header = _single_header(message, "Keywords", required=False)
    actual_keywords = (
        tuple(sorted(part.strip() for part in keywords_header.split(",") if part.strip()))
        if keywords_header is not None
        else ()
    )
    if actual_keywords != expected_keywords:
        raise _fail("package keywords differ from project metadata")

    expected_classifiers = Counter(_string_list(project.get("classifiers"), "classifiers"))
    if Counter(_header_values(message, "Classifier")) != expected_classifiers:
        raise _fail("package classifiers differ from project metadata")

    license_data = project.get("license")
    expected_license_files: tuple[str, ...] = ()
    if license_data is not None:
        if not isinstance(license_data, dict):
            raise _fail("project metadata contains an invalid license field")
        license_file = license_data.get("file")
        if license_file is not None:
            if not isinstance(license_file, str):
                raise _fail("project metadata contains an invalid license file")
            _safe_archive_path(license_file)
            expected_license_files = (license_file,)
    if _header_values(message, "License-File") != expected_license_files:
        raise _fail("package license files differ from project metadata")

    expected_requirements: Counter[tuple[str, tuple[str, ...], tuple[str, ...], str]] = Counter()
    for requirement in _string_list(project.get("dependencies"), "dependencies"):
        expected_requirements[_requirement_key(requirement)] += 1

    optional_dependencies = project.get("optional-dependencies")
    if optional_dependencies is None:
        optional_dependencies = {}
    if not isinstance(optional_dependencies, dict):
        raise _fail("project metadata contains invalid optional dependencies")
    expected_extras: set[str] = set()
    for raw_extra, raw_requirements in optional_dependencies.items():
        if not isinstance(raw_extra, str):
            raise _fail("project metadata contains an invalid optional dependency group")
        extra = _normalize_distribution_name(raw_extra)
        if extra in expected_extras:
            raise _fail("project metadata contains colliding optional dependency groups")
        expected_extras.add(extra)
        for requirement in _string_list(
            raw_requirements,
            f"optional dependency group {raw_extra}",
        ):
            expected_requirements[_requirement_key(requirement, optional_extra=extra)] += 1

    provided_extras = tuple(
        _normalize_distribution_name(value) for value in _header_values(message, "Provides-Extra")
    )
    if len(provided_extras) != len(set(provided_extras)) or set(provided_extras) != expected_extras:
        raise _fail("package extras differ from project metadata")
    actual_requirements = Counter(
        _requirement_key(value) for value in _header_values(message, "Requires-Dist")
    )
    if actual_requirements != expected_requirements:
        raise _fail("package dependency metadata differs from project metadata")


def _verify_wheel_record(payloads: Mapping[str, bytes], record_name: str) -> None:
    try:
        rows = list(
            csv.reader(
                payloads[record_name].decode("utf-8", errors="strict").splitlines(),
                strict=True,
            )
        )
    except (KeyError, UnicodeDecodeError, csv.Error) as exc:
        raise _fail("wheel RECORD is unavailable or malformed") from exc
    if any(len(row) != 3 for row in rows):
        raise _fail("wheel RECORD contains a malformed row")
    names = [row[0] for row in rows]
    if len(names) != len(set(names)) or set(names) != set(payloads):
        raise _fail("wheel RECORD does not exactly cover wheel members")
    for name, encoded_hash, encoded_size in rows:
        _safe_archive_path(name)
        if name == record_name:
            if encoded_hash or encoded_size:
                raise _fail("wheel RECORD must leave its own hash and size empty")
            continue
        payload = payloads[name]
        if not encoded_size.isdecimal() or int(encoded_size) != len(payload):
            raise _fail("wheel RECORD member size is invalid")
        if not encoded_hash.startswith("sha256="):
            raise _fail("wheel RECORD member lacks a SHA-256 digest")
        expected = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        if not hmac.compare_digest(encoded_hash.removeprefix("sha256="), expected):
            raise _fail("wheel RECORD member digest is invalid")


def _verify_entry_points(payload: bytes, project: Mapping[str, object]) -> None:
    scripts = project.get("scripts")
    if not isinstance(scripts, dict) or not scripts:
        raise _fail("project scripts are unavailable")
    expected = {
        str(name): str(target)
        for name, target in scripts.items()
        if isinstance(name, str) and isinstance(target, str)
    }
    parser = configparser.ConfigParser(interpolation=None)
    try:
        parser.read_string(payload.decode("utf-8", errors="strict"))
        actual = dict(parser.items("console_scripts"))
    except (UnicodeDecodeError, configparser.Error, KeyError) as exc:
        raise _fail("wheel entry points are invalid") from exc
    if actual != expected:
        raise _fail("wheel entry points differ from project metadata")


def _verify_wheel(
    project_root: Path,
    wheel: Path,
    commit: str,
    tracked_paths: frozenset[str],
    project: Mapping[str, object],
    expected_version: str,
) -> bytes:
    payloads = _zip_payloads(wheel)
    dist_info = f"fetech-{expected_version}.dist-info"
    metadata_name = f"{dist_info}/METADATA"
    wheel_name = f"{dist_info}/WHEEL"
    entry_points_name = f"{dist_info}/entry_points.txt"
    license_name = f"{dist_info}/licenses/LICENSE"
    record_name = f"{dist_info}/RECORD"
    source_mapping = _wheel_source_mapping(tracked_paths)
    expected_members = set(source_mapping) | {
        metadata_name,
        wheel_name,
        entry_points_name,
        license_name,
        record_name,
    }
    if set(payloads) != expected_members:
        raise _fail("wheel members differ from the exact release inventory")
    for member, source in source_mapping.items():
        if not hmac.compare_digest(
            payloads[member],
            _source_bytes(project_root, commit, tracked_paths, source),
        ):
            raise _fail("wheel package bytes differ from the clean source tree")

    metadata_payload = payloads[metadata_name]
    metadata = _metadata_message(metadata_payload, "wheel METADATA")
    _verify_core_metadata(metadata, project, expected_version)
    wheel_metadata = _metadata_message(payloads[wheel_name], "wheel WHEEL metadata")
    if (
        _single_header(wheel_metadata, "Wheel-Version", required=True) != "1.0"
        or _single_header(wheel_metadata, "Root-Is-Purelib", required=True) != "true"
        or _header_values(wheel_metadata, "Tag") != ("py3-none-any",)
        or not _single_header(wheel_metadata, "Generator", required=True)
    ):
        raise _fail("wheel compatibility metadata is not the exact py3-none-any profile")
    _verify_entry_points(payloads[entry_points_name], project)
    if not hmac.compare_digest(
        payloads[license_name],
        _source_bytes(project_root, commit, tracked_paths, "LICENSE"),
    ):
        raise _fail("wheel license bytes differ from the clean source tree")
    _verify_wheel_record(payloads, record_name)
    return metadata_payload


def _selected_sdist_sources(
    project_document: Mapping[str, object],
    tracked_paths: frozenset[str],
) -> frozenset[str]:
    try:
        includes = project_document["tool"]["hatch"]["build"]["targets"]["sdist"]["include"]  # type: ignore[index]
    except (KeyError, TypeError) as exc:
        raise _fail("Hatch sdist include metadata is unavailable") from exc
    if not isinstance(includes, list) or not includes:
        raise _fail("Hatch sdist include metadata is invalid")
    selected: set[str] = set()
    for raw_include in includes:
        if not isinstance(raw_include, str) or not raw_include.startswith("/"):
            raise _fail("Hatch sdist includes must be absolute project patterns")
        relative = raw_include.removeprefix("/").rstrip("/")
        _safe_archive_path(relative)
        selected.update(path for path in tracked_paths if path == relative or path.startswith(f"{relative}/"))
    # Hatch includes the repository ignore file as build metadata.
    if ".gitignore" in tracked_paths:
        selected.add(".gitignore")
    if not selected or "pyproject.toml" not in selected:
        raise _fail("the tracked sdist source inventory is incomplete")
    return frozenset(selected)


def _tar_payloads(sdist: Path, top_level: str) -> tuple[dict[str, bytes], bytes]:
    payloads: dict[str, bytes] = {}
    package_info: bytes | None = None
    seen: set[str] = set()
    total = 0
    member_count = 0
    try:
        with tarfile.open(sdist, mode="r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > _MAX_ARCHIVE_MEMBERS:
                    raise _fail("sdist member inventory is oversized")
                path = _safe_archive_path(member.name)
                canonical_name = path.as_posix()
                if canonical_name in seen:
                    raise _fail("sdist contains duplicate member paths")
                seen.add(canonical_name)
                if not path.parts or path.parts[0] != top_level:
                    raise _fail("sdist contains a member outside its release root")
                if member.isdir():
                    continue
                if not member.isfile():
                    raise _fail("sdist contains a link, device, or special member")
                if member.size < 0 or member.size > _MAX_ARCHIVE_MEMBER_BYTES:
                    raise _fail("sdist member exceeds its byte bound")
                total += member.size
                if total > _MAX_ARCHIVE_EXPANDED_BYTES:
                    raise _fail("sdist expanded content exceeds its byte bound")
                stream = archive.extractfile(member)
                if stream is None:
                    raise _fail("sdist member could not be read")
                payload = stream.read(_MAX_ARCHIVE_MEMBER_BYTES + 1)
                if len(payload) != member.size:
                    raise _fail("sdist member size changed while reading")
                relative = PurePosixPath(*path.parts[1:]).as_posix()
                if relative == "PKG-INFO":
                    if package_info is not None:
                        raise _fail("sdist contains duplicate package metadata")
                    package_info = payload
                else:
                    if relative in payloads:
                        raise _fail("sdist contains canonically duplicate member paths")
                    payloads[relative] = payload
    except ArtifactVerificationError:
        raise
    except Exception as exc:
        raise _fail("sdist is not a valid bounded gzip tar archive") from exc
    if member_count == 0:
        raise _fail("sdist member inventory is empty")
    if package_info is None:
        raise _fail("sdist PKG-INFO is missing")
    return payloads, package_info


def _verify_sdist(
    project_root: Path,
    sdist: Path,
    commit: str,
    tracked_paths: frozenset[str],
    project_document: Mapping[str, object],
    project: Mapping[str, object],
    expected_version: str,
) -> bytes:
    top_level = f"fetech-{expected_version}"
    payloads, package_info = _tar_payloads(sdist, top_level)
    expected_sources = _selected_sdist_sources(project_document, tracked_paths)
    if set(payloads) != set(expected_sources):
        raise _fail("sdist members differ from the exact tracked release inventory")
    for source in expected_sources:
        if not hmac.compare_digest(
            payloads[source],
            _source_bytes(project_root, commit, tracked_paths, source),
        ):
            raise _fail("sdist bytes differ from the clean source tree")
    metadata = _metadata_message(package_info, "sdist PKG-INFO")
    _verify_core_metadata(metadata, project, expected_version)
    return package_info


def _verify_checksums(
    checksums: Path,
    expected: Mapping[str, str],
) -> None:
    try:
        text = checksums.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise _fail("SHA256SUMS is not bounded UTF-8 text") from exc
    rendered = "".join(f"{expected[filename]}  {filename}\n" for filename in (WHEEL_FILENAME, SDIST_FILENAME))
    if text != rendered:
        raise _fail("SHA256SUMS is not the canonical exact two-artifact manifest")


def _artifact_input(
    project_root: Path,
    supplied: Path | None,
    default: Path,
) -> Path:
    if supplied is None:
        return project_root / default
    expanded = supplied.expanduser()
    return expanded if expanded.is_absolute() else project_root / expanded


def verify_release_artifacts(
    project_root: Path,
    *,
    wheel_path: Path | None = None,
    sdist_path: Path | None = None,
    checksums_path: Path | None = None,
    expected_version: str = TARGET_VERSION,
) -> dict[str, object]:
    """Verify release assets and return their deterministic sanitized receipt."""

    root = project_root.resolve(strict=True)
    if not root.is_dir():
        raise _fail("project root is unavailable")
    expected_wheel_name = f"fetech-{expected_version}-py3-none-any.whl"
    expected_sdist_name = f"fetech-{expected_version}.tar.gz"
    if expected_wheel_name != WHEEL_FILENAME or expected_sdist_name != SDIST_FILENAME:
        raise _fail("only the canonical v0.4.0a0 artifact identity is accepted")

    wheel = _regular_file(
        _artifact_input(root, wheel_path, Path("dist") / WHEEL_FILENAME),
        "wheel",
        maximum_bytes=_MAX_ARTIFACT_BYTES,
    )
    sdist = _regular_file(
        _artifact_input(root, sdist_path, Path("dist") / SDIST_FILENAME),
        "sdist",
        maximum_bytes=_MAX_ARTIFACT_BYTES,
    )
    checksums = _regular_file(
        _artifact_input(root, checksums_path, Path("dist") / CHECKSUMS_FILENAME),
        "SHA256SUMS",
        maximum_bytes=_MAX_CHECKSUM_BYTES,
    )
    if wheel.name != WHEEL_FILENAME or sdist.name != SDIST_FILENAME or checksums.name != CHECKSUMS_FILENAME:
        raise _fail("release artifact filenames are not canonical")

    commit, tracked_paths = _source_identity(root)
    project_document, project = _load_project_metadata(
        root,
        commit,
        tracked_paths,
        expected_version,
    )
    with tempfile.TemporaryDirectory(prefix="fetech-release-artifacts-") as temporary:
        snapshot_root = Path(temporary)
        wheel_snapshot = snapshot_root / WHEEL_FILENAME
        sdist_snapshot = snapshot_root / SDIST_FILENAME
        checksums_snapshot = snapshot_root / CHECKSUMS_FILENAME
        wheel_state = _capture_file(
            wheel,
            maximum_bytes=_MAX_ARTIFACT_BYTES,
            copy_to=wheel_snapshot,
        )
        sdist_state = _capture_file(
            sdist,
            maximum_bytes=_MAX_ARTIFACT_BYTES,
            copy_to=sdist_snapshot,
        )
        checksums_state = _capture_file(
            checksums,
            maximum_bytes=_MAX_CHECKSUM_BYTES,
            copy_to=checksums_snapshot,
        )
        _verify_checksums(
            checksums_snapshot,
            {
                WHEEL_FILENAME: wheel_state.sha256,
                SDIST_FILENAME: sdist_state.sha256,
            },
        )
        wheel_metadata = _verify_wheel(
            root,
            wheel_snapshot,
            commit,
            tracked_paths,
            project,
            expected_version,
        )
        sdist_metadata = _verify_sdist(
            root,
            sdist_snapshot,
            commit,
            tracked_paths,
            project_document,
            project,
            expected_version,
        )
        if not hmac.compare_digest(wheel_metadata, sdist_metadata):
            raise _fail("wheel and sdist core metadata differ")

        _assert_file_unchanged(
            wheel,
            wheel_state,
            maximum_bytes=_MAX_ARTIFACT_BYTES,
        )
        _assert_file_unchanged(
            sdist,
            sdist_state,
            maximum_bytes=_MAX_ARTIFACT_BYTES,
        )
        _assert_file_unchanged(
            checksums,
            checksums_state,
            maximum_bytes=_MAX_CHECKSUM_BYTES,
        )
    final_commit, final_paths = _source_identity(root)
    if final_commit != commit or final_paths != tracked_paths:
        raise _fail("Git source identity changed during verification")
    return {
        "schema": RECEIPT_SCHEMA,
        "project": PROJECT_NAME,
        "version": expected_version,
        "source_commit": commit,
        "artifacts": [
            {
                "kind": "wheel",
                "filename": WHEEL_FILENAME,
                "size": wheel_state.size,
                "sha256": wheel_state.sha256,
            },
            {
                "kind": "sdist",
                "filename": SDIST_FILENAME,
                "size": sdist_state.size,
                "sha256": sdist_state.sha256,
            },
        ],
        "checksums": {
            "filename": CHECKSUMS_FILENAME,
            "size": checksums_state.size,
            "sha256": checksums_state.sha256,
        },
    }


def render_receipt(receipt: Mapping[str, object]) -> str:
    """Return canonical deterministic JSON for a verified receipt."""

    return f"{json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=False)}\n"


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--wheel", type=Path)
    parser.add_argument("--sdist", type=Path)
    parser.add_argument("--checksums", type=Path)
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    try:
        receipt = verify_release_artifacts(
            arguments.project_root,
            wheel_path=arguments.wheel,
            sdist_path=arguments.sdist,
            checksums_path=arguments.checksums,
        )
        rendered = render_receipt(receipt)
        if arguments.output is None:
            sys.stdout.write(rendered)
        else:
            arguments.output.parent.mkdir(parents=True, exist_ok=True)
            arguments.output.write_text(rendered, encoding="utf-8")
    except (ArtifactVerificationError, OSError) as exc:
        print(f"release artifact verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
