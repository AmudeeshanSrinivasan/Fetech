"""Shared bounded primitives for v0.4 release attestations.

This module deliberately uses only the Python standard library.  Release
receipts are not authority by themselves: callers must either re-query the
authoritative service or verify an OpenSSH signature against an independently
selected allowed-signers file.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import stat
import subprocess
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, NoReturn

TARGET_VERSION: Final = "0.4.0a0"
PROJECT_NAME: Final = "fetech"
WHEEL_FILENAME: Final = f"fetech-{TARGET_VERSION}-py3-none-any.whl"
SDIST_FILENAME: Final = f"fetech-{TARGET_VERSION}.tar.gz"
CHECKSUMS_FILENAME: Final = "SHA256SUMS"
ARTIFACT_RECEIPT_FILENAME: Final = f"fetech-{TARGET_VERSION}-artifacts.json"

COMMIT_PATTERN: Final = re.compile(r"[0-9a-f]{40}\Z")
SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
PRINCIPAL_PATTERN: Final = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.@+-]{0,127}\Z")
_MAX_JSON_BYTES: Final = 512 * 1024
_MAX_TEXT_BYTES: Final = 2_048
_MAX_FILE_BYTES: Final = 256_000_000
_MAX_COMMAND_BYTES: Final = 128 * 1024


class ReleaseAttestationError(ValueError):
    """A bounded, sanitized release-attestation failure."""


def fail(message: str) -> NoReturn:
    raise ReleaseAttestationError(message)


def bounded_text(
    value: object,
    label: str,
    maximum_bytes: int = _MAX_TEXT_BYTES,
) -> str:
    """Return bounded single-line printable text."""

    if not isinstance(value, str):
        fail(f"{label} must be text")
    try:
        encoded = value.encode("utf-8", errors="strict")
    except UnicodeEncodeError as exc:
        raise ReleaseAttestationError(
            f"{label} must be bounded single-line text"
        ) from exc
    if not value or len(encoded) > maximum_bytes or not value.isprintable():
        fail(f"{label} must be bounded single-line text")
    return value


def exact_fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    """Reject missing and invented fields."""

    if set(value) != expected:
        fail(f"{label} has invalid fields")


def mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        fail(f"{label} must be an object")
    return value


def sequence(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        fail(f"{label} must be an array")
    return value


def positive_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        fail(f"{label} must be a positive integer")
    return value


def sha256_text(value: object, label: str) -> str:
    text = bounded_text(value, label, 64)
    if SHA256_PATTERN.fullmatch(text) is None:
        fail(f"{label} must be a lowercase SHA-256 digest")
    return text


def commit_text(value: object, label: str) -> str:
    text = bounded_text(value, label, 40)
    if COMMIT_PATTERN.fullmatch(text) is None:
        fail(f"{label} must be a full lowercase Git commit")
    return text


def principal_text(value: object, label: str) -> str:
    text = bounded_text(value, label, 128)
    if PRINCIPAL_PATTERN.fullmatch(text) is None:
        fail(f"{label} is invalid")
    return text


def timestamp_text(value: object, label: str) -> tuple[str, datetime]:
    text = bounded_text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReleaseAttestationError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        fail(f"{label} must include a timezone")
    return text, parsed.astimezone(UTC)


def utc_now_text() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def canonical_json(document: Mapping[str, object]) -> bytes:
    return (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("utf-8")


def load_canonical_json(
    path: Path,
    label: str,
    *,
    maximum_bytes: int = _MAX_JSON_BYTES,
) -> dict[str, object]:
    resolved = regular_file(path, label, maximum_bytes=maximum_bytes)
    try:
        payload = resolved.read_bytes()
        decoded = json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: fail(
                f"{label} contains non-finite value {value}"
            ),
        )
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReleaseAttestationError(f"{label} is not valid UTF-8 JSON") from exc
    document = mapping(decoded, label)
    if payload != canonical_json(document):
        fail(f"{label} is not canonical JSON")
    return dict(document)


def regular_file(path: Path, label: str, *, maximum_bytes: int) -> Path:
    candidate = path.expanduser()
    if candidate.is_symlink():
        fail(f"{label} must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
        status = resolved.stat()
    except OSError as exc:
        raise ReleaseAttestationError(f"{label} is unavailable") from exc
    if (
        not stat.S_ISREG(status.st_mode)
        or status.st_size <= 0
        or status.st_size > maximum_bytes
    ):
        fail(f"{label} must be a bounded regular file")
    return resolved


def sha256_file(
    path: Path,
    label: str,
    *,
    maximum_bytes: int = _MAX_FILE_BYTES,
) -> tuple[str, int]:
    resolved = regular_file(path, label, maximum_bytes=maximum_bytes)
    digest = hashlib.sha256()
    consumed = 0
    try:
        descriptor = os.open(
            resolved,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        with os.fdopen(descriptor, "rb") as stream:
            before = os.fstat(stream.fileno())
            while chunk := stream.read(1_048_576):
                consumed += len(chunk)
                if consumed > maximum_bytes:
                    fail(f"{label} exceeds its byte limit")
                digest.update(chunk)
            after = os.fstat(stream.fileno())
    except OSError as exc:
        raise ReleaseAttestationError(f"{label} could not be read safely") from exc
    identities = (
        before.st_dev,
        before.st_ino,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ), (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )
    if identities[0] != identities[1] or consumed != before.st_size:
        fail(f"{label} changed while it was read")
    return digest.hexdigest(), consumed


def run_command(
    arguments: tuple[str, ...],
    label: str,
    *,
    timeout: int = 60,
    accepted_codes: frozenset[int] = frozenset({0}),
) -> tuple[int, str]:
    """Run a fixed argv command and return bounded UTF-8 stdout."""

    try:
        process = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            timeout=timeout,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseAttestationError(f"{label} did not complete") from exc
    if (
        process.returncode not in accepted_codes
        or len(process.stdout) > _MAX_COMMAND_BYTES
        or len(process.stderr) > _MAX_COMMAND_BYTES
    ):
        fail(f"{label} failed")
    try:
        output = process.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise ReleaseAttestationError(f"{label} returned invalid UTF-8") from exc
    return process.returncode, output


def clean_repository_commit(project_root: Path) -> str:
    root = project_root.resolve(strict=True)
    _, top_level = run_command(
        ("git", "-C", str(root), "rev-parse", "--show-toplevel"),
        "Git root inspection",
        timeout=15,
    )
    if Path(top_level).resolve(strict=True) != root:
        fail("project root must be the Git worktree root")
    _, status = run_command(
        (
            "git",
            "-C",
            str(root),
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
        ),
        "Git status inspection",
        timeout=15,
    )
    if status:
        fail("release attestation requires a clean Git worktree")
    _, commit = run_command(
        ("git", "-C", str(root), "rev-parse", "HEAD"),
        "Git commit inspection",
        timeout=15,
    )
    return commit_text(commit, "source commit")


def load_release_artifacts(
    project_root: Path,
    artifact_dir: Path,
    *,
    require_clean_head: bool = True,
) -> dict[str, object]:
    """Validate the compact release receipt against exact local bytes."""

    root = project_root.resolve(strict=True)
    directory = artifact_dir.resolve(strict=True)
    receipt_path = directory / ARTIFACT_RECEIPT_FILENAME
    receipt = load_canonical_json(receipt_path, "release artifact receipt")
    exact_fields(
        receipt,
        {"schema", "project", "version", "source_commit", "artifacts", "checksums"},
        "release artifact receipt",
    )
    if receipt.get("schema") != "fetech.v0.4.release-artifacts.v1":
        fail("release artifact receipt schema is invalid")
    if receipt.get("project") != PROJECT_NAME or receipt.get("version") != TARGET_VERSION:
        fail("release artifact receipt project or version is invalid")
    source_commit = commit_text(receipt.get("source_commit"), "artifact source commit")
    if require_clean_head and clean_repository_commit(root) != source_commit:
        fail("release artifacts are not bound to the clean local HEAD")

    raw_artifacts = sequence(receipt.get("artifacts"), "release artifacts")
    if len(raw_artifacts) != 2:
        fail("release artifact receipt must contain exactly two distributions")
    expected = {
        WHEEL_FILENAME: "wheel",
        SDIST_FILENAME: "sdist",
    }
    observed: dict[str, dict[str, object]] = {}
    for index, value in enumerate(raw_artifacts):
        artifact = mapping(value, f"release artifact {index}")
        exact_fields(artifact, {"filename", "kind", "sha256", "size"}, f"release artifact {index}")
        filename = bounded_text(artifact.get("filename"), "artifact filename", 256)
        if filename not in expected or filename in observed:
            fail("release artifact receipt contains an unexpected distribution")
        if artifact.get("kind") != expected[filename]:
            fail("release artifact kind is invalid")
        digest = sha256_text(artifact.get("sha256"), "artifact digest")
        size = positive_integer(artifact.get("size"), "artifact size")
        actual_digest, actual_size = sha256_file(
            directory / filename,
            f"release artifact {filename}",
        )
        if digest != actual_digest or size != actual_size:
            fail("release artifact receipt does not match distribution bytes")
        observed[filename] = dict(artifact)
    if set(observed) != set(expected):
        fail("release artifact receipt is incomplete")

    checksums = mapping(receipt.get("checksums"), "checksums receipt")
    exact_fields(checksums, {"filename", "sha256", "size"}, "checksums receipt")
    if checksums.get("filename") != CHECKSUMS_FILENAME:
        fail("checksum filename is invalid")
    checksums_digest, checksums_size = sha256_file(
        directory / CHECKSUMS_FILENAME,
        "release checksums",
        maximum_bytes=4_096,
    )
    if (
        sha256_text(checksums.get("sha256"), "checksums digest") != checksums_digest
        or positive_integer(checksums.get("size"), "checksums size") != checksums_size
    ):
        fail("checksum receipt does not match SHA256SUMS")
    expected_lines = [
        f"{observed[name]['sha256']}  {name}" for name in (WHEEL_FILENAME, SDIST_FILENAME)
    ]
    try:
        checksum_lines = (directory / CHECKSUMS_FILENAME).read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ReleaseAttestationError("SHA256SUMS is not valid ASCII") from exc
    if checksum_lines != expected_lines:
        fail("SHA256SUMS is not canonical or does not match the distributions")
    return receipt


def allowed_signers_path(environment_name: str, label: str) -> Path:
    value = os.environ.get(environment_name)
    if not value:
        fail(f"{environment_name} must name the independently managed {label}")
    path = regular_file(Path(value), label, maximum_bytes=64 * 1024)
    try:
        mode = path.stat().st_mode
    except OSError as exc:
        raise ReleaseAttestationError(f"{label} metadata is unavailable") from exc
    if mode & 0o022:
        fail(f"{label} must not be group- or world-writable")
    return path


def verify_ssh_signature(
    receipt_path: Path,
    signature_path: Path,
    allowed_signers: Path,
    *,
    principal: str,
    namespace: str,
    expected_payload: bytes | None = None,
) -> None:
    """Verify a detached OpenSSH signature over exact canonical receipt bytes."""

    receipt = regular_file(receipt_path, "signed receipt", maximum_bytes=_MAX_JSON_BYTES)
    signature = regular_file(signature_path, "receipt signature", maximum_bytes=64 * 1024)
    signers = regular_file(allowed_signers, "allowed signers", maximum_bytes=64 * 1024)
    safe_principal = principal_text(principal, "signature principal")
    safe_namespace = bounded_text(namespace, "signature namespace", 128)
    try:
        payload = receipt.read_bytes()
        if expected_payload is not None and not hmac.compare_digest(
            payload, expected_payload
        ):
            fail("signed receipt changed after validation")
        process = subprocess.run(
            (
                "ssh-keygen",
                "-Y",
                "verify",
                "-f",
                str(signers),
                "-I",
                safe_principal,
                "-n",
                safe_namespace,
                "-s",
                str(signature),
            ),
            input=payload,
            check=False,
            capture_output=True,
            timeout=30,
            env={**os.environ, "LC_ALL": "C", "LANG": "C"},
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ReleaseAttestationError("OpenSSH signature verification did not complete") from exc
    if (
        process.returncode != 0
        or len(process.stdout) > _MAX_COMMAND_BYTES
        or len(process.stderr) > _MAX_COMMAND_BYTES
    ):
        fail("OpenSSH signature verification failed")
