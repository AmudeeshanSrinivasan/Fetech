#!/usr/bin/env python3
"""Build Fetech twice from clean source and emit reproducibility evidence."""

from __future__ import annotations

import argparse
import base64
import csv
import gzip
import hashlib
import hmac
import io
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
import zipfile
from collections.abc import Mapping, Sequence
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from typing import Final

RECEIPT_SCHEMA: Final = "fetech.beta.reproducible-build.v1"
PROJECT_NAME: Final = "fetech"
_MAX_ARTIFACT_BYTES: Final = 256_000_000
_MAX_ARCHIVE_MEMBER_BYTES: Final = 64_000_000
_MAX_ARCHIVE_EXPANDED_BYTES: Final = 512_000_000
_MAX_ARCHIVE_MEMBERS: Final = 10_000
_MAX_COMMAND_OUTPUT_BYTES: Final = 2_000_000
_MAX_SOURCE_BYTES: Final = 256_000_000
_COMMIT_ID = re.compile(r"[0-9a-f]{40,64}\Z")


class ReproducibleBuildError(ValueError):
    """A sanitized reproducible-build verification failure."""


def _fail(message: str) -> ReproducibleBuildError:
    return ReproducibleBuildError(message)


def _run(
    command: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str] | None = None,
    timeout_seconds: float = 300,
) -> bytes:
    try:
        result = subprocess.run(
            tuple(command),
            cwd=cwd,
            env=dict(environment) if environment is not None else None,
            check=False,
            capture_output=True,
            timeout=timeout_seconds,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise _fail("reproducible-build command did not complete") from exc
    if (
        len(result.stdout) > _MAX_COMMAND_OUTPUT_BYTES
        or len(result.stderr) > _MAX_COMMAND_OUTPUT_BYTES
    ):
        raise _fail("reproducible-build command output exceeded its bound")
    if result.returncode != 0:
        raise _fail("reproducible-build command failed")
    return result.stdout


def _git(project_root: Path, *arguments: str) -> bytes:
    return _run(("git", "-C", str(project_root), *arguments), cwd=project_root, timeout_seconds=30)


def _source_identity(project_root: Path) -> tuple[str, int]:
    try:
        top_level = Path(
            _git(project_root, "rev-parse", "--show-toplevel")
            .decode("utf-8", errors="strict")
            .strip()
        ).resolve(strict=True)
        commit = (
            _git(project_root, "rev-parse", "--verify", "HEAD^{commit}")
            .decode("ascii", errors="strict")
            .strip()
        )
        epoch_text = (
            _git(project_root, "show", "-s", "--format=%ct", commit)
            .decode("ascii", errors="strict")
            .strip()
        )
        epoch = int(epoch_text)
    except (OSError, UnicodeError, ValueError) as exc:
        raise _fail("Git source identity is unavailable") from exc
    if top_level != project_root or _COMMIT_ID.fullmatch(commit) is None or epoch <= 0:
        raise _fail("Git source identity is invalid")
    if _git(project_root, "status", "--porcelain=v1", "--untracked-files=all"):
        raise _fail("reproducible builds require a clean Git source tree")
    return commit, epoch


def _safe_archive_path(value: str, *, allow_directory: bool = False) -> PurePosixPath:
    selected = value[:-1] if allow_directory and value.endswith("/") else value
    if not selected or "\x00" in selected or "\\" in selected:
        raise _fail("build artifact contains an unsafe member path")
    parts = selected.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise _fail("build artifact contains an unsafe member path")
    path = PurePosixPath(*parts)
    if path.is_absolute() or path.as_posix() != selected:
        raise _fail("build artifact contains a non-canonical member path")
    return path


def _project_metadata(project_root: Path) -> tuple[str, str]:
    try:
        document = tomllib.loads((project_root / "pyproject.toml").read_text(encoding="utf-8"))
        project = document["project"]
        name = project["name"]
        version = project["version"]
    except (OSError, UnicodeError, KeyError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise _fail("project metadata is unavailable or invalid") from exc
    if name != PROJECT_NAME or not isinstance(version, str) or not version:
        raise _fail("project metadata does not identify Fetech")
    safe_version_characters = (
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-"
    )
    if any(character not in safe_version_characters for character in version):
        raise _fail("project version is not a canonical artifact component")
    return name, version


def _tracked_paths(project_root: Path) -> tuple[str, ...]:
    raw = _git(project_root, "ls-files", "-z")
    try:
        paths = raw.decode("utf-8", errors="strict").split("\0")
    except UnicodeError as exc:
        raise _fail("tracked source paths are not valid UTF-8") from exc
    if paths and paths[-1] == "":
        paths.pop()
    if not paths or len(paths) != len(set(paths)):
        raise _fail("tracked source inventory is empty or ambiguous")
    for path in paths:
        _safe_archive_path(path)
    return tuple(paths)


def _copy_tracked_source(project_root: Path, destination: Path) -> None:
    total = 0
    for relative in _tracked_paths(project_root):
        source = project_root / relative
        try:
            source_state = source.lstat()
        except OSError as exc:
            raise _fail("tracked source file is unavailable") from exc
        if not stat.S_ISREG(source_state.st_mode):
            raise _fail("tracked source contains a non-regular file")
        total += source_state.st_size
        if source_state.st_size < 0 or total > _MAX_SOURCE_BYTES:
            raise _fail("tracked source exceeds the copy bound")
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copyfile(source, target, follow_symlinks=False)
            target.chmod(0o755 if source_state.st_mode & stat.S_IXUSR else 0o644)
        except OSError as exc:
            raise _fail("tracked source could not be copied") from exc


def _regular_artifact(path: Path, expected_name: str) -> tuple[int, str]:
    if path.name != expected_name or path.is_symlink():
        raise _fail("build artifact filename or type is invalid")
    try:
        state = path.stat()
    except OSError as exc:
        raise _fail("build artifact is unavailable") from exc
    if not stat.S_ISREG(state.st_mode) or not 0 < state.st_size <= _MAX_ARTIFACT_BYTES:
        raise _fail("build artifact is not a bounded regular file")
    digest = hashlib.sha256()
    consumed = 0
    try:
        with path.open("rb") as stream:
            while chunk := stream.read(1_048_576):
                consumed += len(chunk)
                if consumed > _MAX_ARTIFACT_BYTES:
                    raise _fail("build artifact exceeds its byte bound")
                digest.update(chunk)
    except OSError as exc:
        raise _fail("build artifact could not be read") from exc
    if consumed != state.st_size:
        raise _fail("build artifact changed while it was read")
    return consumed, digest.hexdigest()


def _member_mode(
    raw_mode: int,
    *,
    directory: bool,
    allow_implicit_regular: bool = False,
) -> int:
    file_type = stat.S_IFMT(raw_mode)
    expected_type = stat.S_IFDIR if directory else stat.S_IFREG
    implicit_regular = allow_implicit_regular and not directory and file_type == 0
    if file_type != expected_type and not implicit_regular:
        raise _fail("build artifact contains a special member")
    permissions = stat.S_IMODE(raw_mode)
    if not permissions & stat.S_IRUSR or permissions & (stat.S_IWGRP | stat.S_IWOTH):
        raise _fail("build artifact member permissions are unsafe")
    return permissions


def _zip_timestamp(source_date_epoch: int) -> tuple[int, int, int, int, int, int]:
    minimum_zip_epoch = 315_532_800
    fields = list(time.gmtime(max(source_date_epoch, minimum_zip_epoch))[:6])
    fields[5] -= fields[5] % 2
    return tuple(fields)  # type: ignore[return-value]


def _record_digest(payload: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode("ascii")


def _verify_wheel_record(
    payloads: Mapping[str, bytes],
    *,
    record_name: str,
) -> None:
    try:
        rows = list(csv.reader(io.StringIO(payloads[record_name].decode("utf-8"), newline="")))
    except (UnicodeError, csv.Error) as exc:
        raise _fail("wheel RECORD is malformed") from exc
    if len(rows) != len(payloads):
        raise _fail("wheel RECORD does not cover every member exactly once")
    recorded: set[str] = set()
    for row in rows:
        if len(row) != 3:
            raise _fail("wheel RECORD row is malformed")
        name, digest, raw_size = row
        _safe_archive_path(name)
        if name in recorded or name not in payloads:
            raise _fail("wheel RECORD member identity is invalid")
        recorded.add(name)
        if name == record_name:
            if digest or raw_size:
                raise _fail("wheel RECORD self-entry must omit hash and size")
            continue
        expected_digest = f"sha256={_record_digest(payloads[name])}"
        if not hmac.compare_digest(digest, expected_digest) or raw_size != str(len(payloads[name])):
            raise _fail("wheel RECORD hash or size is invalid")
    if recorded != set(payloads):
        raise _fail("wheel RECORD inventory is incomplete")


def _verify_package_identity(payload: bytes, *, version: str) -> None:
    try:
        metadata = BytesParser().parsebytes(payload)
    except (TypeError, ValueError) as exc:
        raise _fail("package metadata is malformed") from exc
    if metadata.get("Name") != PROJECT_NAME or metadata.get("Version") != version:
        raise _fail("package metadata identifies a different build")


def _verify_wheel(path: Path, *, version: str, source_date_epoch: int) -> dict[str, object]:
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            if not infos or len(infos) > _MAX_ARCHIVE_MEMBERS:
                raise _fail("wheel member inventory is invalid")
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                raise _fail("wheel contains duplicate member names")
            expected_timestamp = _zip_timestamp(source_date_epoch)
            payloads: dict[str, bytes] = {}
            expanded = 0
            for info in infos:
                directory = info.is_dir()
                _safe_archive_path(info.filename, allow_directory=directory)
                if info.date_time != expected_timestamp:
                    raise _fail("wheel member timestamp does not match SOURCE_DATE_EPOCH")
                _member_mode(
                    info.external_attr >> 16,
                    directory=directory,
                    allow_implicit_regular=True,
                )
                if info.file_size < 0 or info.file_size > _MAX_ARCHIVE_MEMBER_BYTES:
                    raise _fail("wheel member exceeds its byte bound")
                expanded += info.file_size
                if expanded > _MAX_ARCHIVE_EXPANDED_BYTES:
                    raise _fail("wheel expanded size exceeds its bound")
                if not directory:
                    payload = archive.read(info)
                    if len(payload) != info.file_size:
                        raise _fail("wheel member size contradicts its directory entry")
                    payloads[info.filename] = payload
    except (OSError, RuntimeError, zipfile.BadZipFile) as exc:
        raise _fail("wheel is malformed or unreadable") from exc

    dist_info = f"{PROJECT_NAME}-{version}.dist-info"
    metadata_name = f"{dist_info}/METADATA"
    record_name = f"{dist_info}/RECORD"
    if metadata_name not in payloads or record_name not in payloads:
        raise _fail("wheel omitted canonical metadata or RECORD")
    _verify_package_identity(payloads[metadata_name], version=version)
    _verify_wheel_record(payloads, record_name=record_name)
    return {
        "member_count": len(infos),
        "expanded_bytes": expanded,
        "inventory_sha256": hashlib.sha256("\n".join(names).encode()).hexdigest(),
        "record_verified": True,
        "timestamp_epoch": source_date_epoch,
    }


def _verify_sdist(path: Path, *, version: str, source_date_epoch: int) -> dict[str, object]:
    try:
        with path.open("rb") as stream:
            header = stream.read(10)
        if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
            raise _fail("sdist is not canonical gzip data")
        if int.from_bytes(header[4:8], "little") != source_date_epoch:
            raise _fail("sdist gzip timestamp does not match SOURCE_DATE_EPOCH")
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            if not members or len(members) > _MAX_ARCHIVE_MEMBERS:
                raise _fail("sdist member inventory is invalid")
            names = [member.name for member in members]
            if len(names) != len(set(names)):
                raise _fail("sdist contains duplicate member names")
            prefix = f"{PROJECT_NAME}-{version}/"
            expanded = 0
            payloads: dict[str, bytes] = {}
            for member in members:
                _safe_archive_path(member.name, allow_directory=member.isdir())
                if not member.name.startswith(prefix) or member.mtime != source_date_epoch:
                    raise _fail("sdist member source identity is invalid")
                if not (member.isfile() or member.isdir()):
                    raise _fail("sdist contains a link or special member")
                member_type = stat.S_IFDIR if member.isdir() else stat.S_IFREG
                _member_mode(
                    member_type | member.mode,
                    directory=member.isdir(),
                )
                if member.size < 0 or member.size > _MAX_ARCHIVE_MEMBER_BYTES:
                    raise _fail("sdist member exceeds its byte bound")
                expanded += member.size
                if expanded > _MAX_ARCHIVE_EXPANDED_BYTES:
                    raise _fail("sdist expanded size exceeds its bound")
                if member.isfile():
                    extracted = archive.extractfile(member)
                    if extracted is None:
                        raise _fail("sdist member could not be read")
                    payload = extracted.read(member.size + 1)
                    if len(payload) != member.size:
                        raise _fail("sdist member size contradicts its header")
                    payloads[member.name] = payload
    except (gzip.BadGzipFile, OSError, tarfile.TarError) as exc:
        raise _fail("sdist is malformed or unreadable") from exc

    metadata_name = f"{PROJECT_NAME}-{version}/PKG-INFO"
    project_name = f"{PROJECT_NAME}-{version}/pyproject.toml"
    if metadata_name not in payloads or project_name not in payloads:
        raise _fail("sdist omitted canonical package metadata or pyproject.toml")
    _verify_package_identity(payloads[metadata_name], version=version)
    return {
        "member_count": len(members),
        "expanded_bytes": expanded,
        "inventory_sha256": hashlib.sha256("\n".join(names).encode()).hexdigest(),
        "timestamp_epoch": source_date_epoch,
    }


def verify_artifact_pair(
    first_directory: Path,
    second_directory: Path,
    *,
    version: str,
    source_date_epoch: int,
) -> dict[str, object]:
    """Verify two build directories and return deterministic artifact evidence."""

    wheel_name = f"{PROJECT_NAME}-{version}-py3-none-any.whl"
    sdist_name = f"{PROJECT_NAME}-{version}.tar.gz"
    expected = {wheel_name, sdist_name}
    try:
        first_names = {path.name for path in first_directory.iterdir()}
        second_names = {path.name for path in second_directory.iterdir()}
    except OSError as exc:
        raise _fail("build output directory is unavailable") from exc
    if first_names != expected or second_names != expected:
        raise _fail("build output inventory is not the canonical wheel and sdist pair")

    artifacts: list[dict[str, object]] = []
    summaries: dict[str, dict[str, object]] = {}
    for kind, filename in (("wheel", wheel_name), ("sdist", sdist_name)):
        first = first_directory / filename
        second = second_directory / filename
        first_size, first_digest = _regular_artifact(first, filename)
        second_size, second_digest = _regular_artifact(second, filename)
        if first_size != second_size or not hmac.compare_digest(first_digest, second_digest):
            raise _fail(f"independent {kind} builds are not byte-for-byte identical")
        summary = (
            _verify_wheel(first, version=version, source_date_epoch=source_date_epoch)
            if kind == "wheel"
            else _verify_sdist(first, version=version, source_date_epoch=source_date_epoch)
        )
        second_summary = (
            _verify_wheel(second, version=version, source_date_epoch=source_date_epoch)
            if kind == "wheel"
            else _verify_sdist(second, version=version, source_date_epoch=source_date_epoch)
        )
        if summary != second_summary:
            raise _fail(f"independent {kind} archive inventories differ")
        summaries[kind] = summary
        artifacts.append(
            {
                "kind": kind,
                "filename": filename,
                "size": first_size,
                "sha256": first_digest,
            }
        )
    return {
        "artifacts": artifacts,
        "archive_invariants": {
            "byte_for_byte_identical": True,
            "member_order_identical": True,
            "source_date_epoch_enforced": True,
            "wheel_record_verified": True,
        },
        "archive_summaries": summaries,
    }


def _build_once(
    uv_executable: str,
    source: Path,
    output: Path,
    *,
    source_date_epoch: int,
) -> None:
    environment = dict(os.environ)
    environment.update(
        {
            "PYTHONHASHSEED": "0",
            "SOURCE_DATE_EPOCH": str(source_date_epoch),
            "UV_NO_PROGRESS": "1",
        }
    )
    _run(
        (
            uv_executable,
            "build",
            "--no-create-gitignore",
            "--out-dir",
            str(output),
            str(source),
        ),
        cwd=source,
        environment=environment,
    )


def _smoke_install(
    uv_executable: str,
    artifact: Path,
    environment_root: Path,
    *,
    version: str,
) -> None:
    environment = dict(os.environ)
    environment.update({"PYTHONHASHSEED": "0", "UV_NO_PROGRESS": "1"})
    _run(
        (uv_executable, "venv", "--python", sys.executable, str(environment_root)),
        cwd=environment_root.parent,
        environment=environment,
    )
    python = environment_root / ("Scripts/python.exe" if os.name == "nt" else "bin/python")
    _run(
        (uv_executable, "pip", "install", "--python", str(python), str(artifact)),
        cwd=environment_root.parent,
        environment=environment,
    )
    code = """
from importlib.metadata import version
from importlib.resources import files
import fetech
from fetech.models import FetchRequest

expected = __import__("sys").argv[1]
assert version("fetech") == expected
assert fetech.__version__ == expected
manifest = files("fetech").joinpath("data/manifest.yaml").read_text(encoding="utf-8")
assert "categories:" in manifest
assert FetchRequest(target="https://example.com").schema_version == "1.0"
"""
    _run(
        (str(python), "-I", "-c", code, version),
        cwd=environment_root.parent,
        environment=environment,
        timeout_seconds=60,
    )


def collect_reproducible_build_evidence(
    project_root: Path,
    *,
    uv_executable: str,
    run_install_smoke: bool = True,
) -> dict[str, object]:
    """Perform two clean builds, verify them, and return a bounded receipt."""

    root = project_root.resolve(strict=True)
    if not root.is_dir():
        raise _fail("project root is unavailable")
    commit, source_date_epoch = _source_identity(root)
    project, version = _project_metadata(root)
    uv_path = shutil.which(uv_executable)
    if uv_path is None:
        raise _fail("uv executable is unavailable")
    uv_version = _run((uv_path, "--version"), cwd=root, timeout_seconds=30).decode(
        "utf-8", errors="strict"
    ).strip()
    if not uv_version.startswith("uv ") or len(uv_version) > 128:
        raise _fail("uv returned an invalid version")

    with tempfile.TemporaryDirectory(prefix="fetech-reproducible-build-") as temporary:
        workspace = Path(temporary)
        source_a = workspace / "source-a"
        source_b = workspace / "source-b"
        build_a = workspace / "build-a"
        build_b = workspace / "build-b"
        for directory in (source_a, source_b, build_a, build_b):
            directory.mkdir()
        _copy_tracked_source(root, source_a)
        _copy_tracked_source(root, source_b)
        _build_once(uv_path, source_a, build_a, source_date_epoch=source_date_epoch)
        _build_once(uv_path, source_b, build_b, source_date_epoch=source_date_epoch)
        evidence = verify_artifact_pair(
            build_a,
            build_b,
            version=version,
            source_date_epoch=source_date_epoch,
        )
        smoke: dict[str, str] = {"wheel": "not_run", "sdist": "not_run"}
        if run_install_smoke:
            raw_artifacts = evidence.get("artifacts")
            if not isinstance(raw_artifacts, list):
                raise _fail("reproducible-build evidence omitted its artifact inventory")
            artifact_by_kind = {
                str(item["kind"]): build_a / str(item["filename"])
                for item in raw_artifacts
                if isinstance(item, dict)
            }
            if set(artifact_by_kind) != {"wheel", "sdist"}:
                raise _fail("reproducible-build evidence has an invalid artifact inventory")
            for kind in ("wheel", "sdist"):
                _smoke_install(
                    uv_path,
                    artifact_by_kind[kind],
                    workspace / f"install-{kind}",
                    version=version,
                )
                smoke[kind] = "passed"

    final_identity = _source_identity(root)
    if final_identity != (commit, source_date_epoch):
        raise _fail("Git source identity changed during reproducible-build verification")
    return {
        "schema": RECEIPT_SCHEMA,
        "project": project,
        "version": version,
        "source_commit": commit,
        "source_date_epoch": source_date_epoch,
        "builder": {
            "frontend": uv_version,
            "python": platform.python_version(),
        },
        **evidence,
        "clean_install_smoke": smoke,
    }


def render_receipt(receipt: Mapping[str, object]) -> str:
    return json.dumps(
        receipt,
        indent=2,
        sort_keys=True,
        ensure_ascii=True,
        allow_nan=False,
    ) + "\n"


def _write_receipt(path: Path, content: str) -> None:
    selected = path.expanduser()
    if selected.is_symlink():
        raise _fail("receipt output must not be a symlink")
    try:
        selected.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{selected.name}.",
            dir=selected.parent,
        )
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, selected)
    except OSError as exc:
        raise _fail("receipt output could not be written atomically") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    parser.add_argument("--uv-executable", default="uv")
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--skip-install-smoke",
        action="store_true",
        help="comparison-only development mode; CI must not use this option",
    )
    arguments = parser.parse_args(argv)
    try:
        receipt = collect_reproducible_build_evidence(
            arguments.project_root,
            uv_executable=arguments.uv_executable,
            run_install_smoke=not arguments.skip_install_smoke,
        )
        rendered = render_receipt(receipt)
        if arguments.output is not None:
            _write_receipt(arguments.output, rendered)
        sys.stdout.write(rendered)
    except (ReproducibleBuildError, UnicodeError) as exc:
        print(str(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
