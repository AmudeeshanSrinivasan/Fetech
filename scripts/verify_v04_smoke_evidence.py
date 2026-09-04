#!/usr/bin/env python3
"""Fail closed unless retained v0.4 smoke evidence is release-bound and complete."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime, timedelta
from pathlib import Path
from typing import Final, NoReturn

TARGET_VERSION: Final = "0.4.0a0"
DOCLING_VERSION: Final = "2.113.0"
SCHEMA: Final = "fetech.v0.4.smoke-evidence.v2"
EVIDENCE_FILENAME: Final = f"fetech-v{TARGET_VERSION}-smoke.json"
WHEEL_FILENAME: Final = f"fetech-{TARGET_VERSION}-py3-none-any.whl"
DOCLING_REFERENCE_BUNDLE_SHA256: Final = (
    "e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76"
)
WAYBACK_SERVICE: Final = (
    "https://archive.org/wayback/available and https://web.archive.org"
)
YTDLP_SERVICE: Final = "YouTube HTTPS metadata endpoints via yt-dlp"

REQUIRED_PACKAGE_DISTRIBUTIONS: Final = (
    "fetech",
    "docling-slim",
    "openpyxl",
    "pillow",
    "playwright",
    "pypdf",
    "python-docx",
    "python-pptx",
    "selenium",
    "yt-dlp",
)
REQUIRED_EXECUTABLES: Final = ("ffmpeg", "ffprobe", "tesseract")
REQUIRED_CHECK_IDS: Final = tuple(
    sorted(
        {
            *(f"package:{name}" for name in REQUIRED_PACKAGE_DISTRIBUTIONS),
            *(f"executable:{name}" for name in REQUIRED_EXECUTABLES),
            "artifact:docling-models",
            "artifact:wheel",
            "lock:uv",
            "source:git",
            "smoke:browser",
            "smoke:docling",
            "smoke:ffmpeg",
            "smoke:ffprobe",
            "smoke:tesseract",
            "smoke:wayback",
            "smoke:yt-dlp",
        }
    )
)

_TOP_LEVEL_FIELDS: Final = {
    "schema",
    "generated_at",
    "platform",
    "network_smoke_requested",
    "checks",
}
_PLATFORM_FIELDS: Final = {"machine", "python", "system", "system_release"}
_CHECK_FIELDS: Final = {"id", "status", "version", "detail", "service", "sha256"}
_SHA256_PATTERN: Final = re.compile(r"[0-9a-f]{64}\Z")
_MAX_EVIDENCE_BYTES: Final = 512 * 1024
_MAX_WHEEL_BYTES: Final = 500_000_000
_MAX_LOCK_BYTES: Final = 100_000_000
_MAX_PLATFORM_TEXT_BYTES: Final = 256
_MAX_VERSION_BYTES: Final = 512
_MAX_DETAIL_BYTES: Final = 4_096
_MAX_SERVICE_BYTES: Final = 2_048
_MAX_GIT_OUTPUT_BYTES: Final = 64 * 1024


class SmokeEvidenceError(ValueError):
    """The retained smoke evidence does not prove the release gate."""


def _fail(message: str) -> NoReturn:
    raise SmokeEvidenceError(message)


def _absolute_without_symlinks(path: Path, label: str) -> Path:
    absolute = Path(os.path.abspath(path.expanduser()))
    try:
        resolved = absolute.resolve(strict=True)
    except OSError as exc:
        raise SmokeEvidenceError(f"{label} is unavailable") from exc
    if resolved != absolute:
        _fail(f"{label} path cannot contain symlinks")
    return resolved


def _read_regular_file(path: Path, label: str, maximum_bytes: int) -> bytes:
    resolved = _absolute_without_symlinks(path, label)
    try:
        before = resolved.stat()
    except OSError as exc:
        raise SmokeEvidenceError(f"{label} is unavailable") from exc
    if not resolved.is_file() or before.st_size < 0 or before.st_size > maximum_bytes:
        _fail(f"{label} is not a bounded regular file")
    try:
        payload = resolved.read_bytes()
        after = resolved.stat()
    except OSError as exc:
        raise SmokeEvidenceError(f"{label} could not be read") from exc
    if (
        len(payload) != before.st_size
        or before.st_dev != after.st_dev
        or before.st_ino != after.st_ino
        or before.st_size != after.st_size
        or before.st_mtime_ns != after.st_mtime_ns
    ):
        _fail(f"{label} changed while it was being verified")
    return payload


def _sha256_file(path: Path, label: str, maximum_bytes: int) -> str:
    return hashlib.sha256(_read_regular_file(path, label, maximum_bytes)).hexdigest()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            _fail(f"smoke evidence contains duplicate JSON key: {key}")
        document[key] = value
    return document


def _reject_constant(value: str) -> NoReturn:
    _fail(f"smoke evidence contains non-finite JSON value: {value}")


def _load_evidence(path: Path) -> dict[str, object]:
    if path.name != EVIDENCE_FILENAME:
        _fail(f"smoke evidence must use the canonical filename {EVIDENCE_FILENAME}")
    payload = _read_regular_file(path, "smoke evidence", _MAX_EVIDENCE_BYTES)
    try:
        text = payload.decode("utf-8", errors="strict")
        document = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SmokeEvidenceError(
            "smoke evidence is not bounded canonical UTF-8 JSON"
        ) from exc
    if not isinstance(document, dict):
        _fail("smoke evidence must be a JSON object")
    canonical = (
        json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode()
    if payload != canonical:
        _fail("smoke evidence is not in canonical JSON form")
    return document


def _exact_fields(
    value: Mapping[str, object],
    expected: set[str],
    label: str,
) -> None:
    actual = set(value)
    missing = expected - actual
    extra = actual - expected
    if missing or extra:
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("extra " + ", ".join(sorted(extra)))
        _fail(f"{label} has invalid fields: {'; '.join(details)}")


def _bounded_text(
    value: object,
    label: str,
    maximum_bytes: int,
    *,
    allow_empty: bool = False,
) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be text")
    encoded = value.encode("utf-8")
    if (
        (not value and not allow_empty)
        or len(encoded) > maximum_bytes
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _fail(f"{label} must be bounded single-line text")
    return value


def _validate_timestamp(value: object) -> None:
    text = _bounded_text(value, "generated_at", 40)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SmokeEvidenceError("generated_at must be a valid UTC timestamp") from exc
    if parsed.tzinfo is None or parsed.utcoffset() != timedelta(0):
        _fail("generated_at must be a valid UTC timestamp")


def _validate_platform(value: object) -> None:
    if not isinstance(value, dict):
        _fail("platform must be an object")
    _exact_fields(value, _PLATFORM_FIELDS, "platform")
    for field in sorted(_PLATFORM_FIELDS):
        _bounded_text(
            value[field],
            f"platform.{field}",
            _MAX_PLATFORM_TEXT_BYTES,
        )


def _validate_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or _SHA256_PATTERN.fullmatch(value) is None:
        _fail(f"{label} must be a lowercase SHA-256 digest")
    return value


def _validate_checks(value: object) -> dict[str, Mapping[str, object]]:
    if not isinstance(value, list):
        _fail("checks must be an array")
    checks: dict[str, Mapping[str, object]] = {}
    encountered: list[str] = []
    for index, check in enumerate(value):
        if not isinstance(check, dict):
            _fail(f"checks[{index}] must be an object")
        unknown = set(check) - _CHECK_FIELDS
        if unknown:
            _fail(
                f"checks[{index}] contains unsupported fields: "
                + ", ".join(sorted(unknown))
            )
        if "id" not in check or "status" not in check:
            _fail(f"checks[{index}] must contain id and status")
        check_id = _bounded_text(check["id"], f"checks[{index}].id", 80)
        if check_id in checks:
            _fail(f"duplicate smoke check ID: {check_id}")
        if check["status"] != "passed":
            _fail(f"required smoke check did not pass: {check_id}")
        for field, maximum in (
            ("version", _MAX_VERSION_BYTES),
            ("detail", _MAX_DETAIL_BYTES),
            ("service", _MAX_SERVICE_BYTES),
        ):
            if field in check:
                _bounded_text(check[field], f"{check_id}.{field}", maximum)
        if "sha256" in check:
            _validate_sha256(check["sha256"], f"{check_id}.sha256")
        checks[check_id] = check
        encountered.append(check_id)

    actual = set(checks)
    required = set(REQUIRED_CHECK_IDS)
    if actual != required:
        missing = required - actual
        extra = actual - required
        details = []
        if missing:
            details.append("missing " + ", ".join(sorted(missing)))
        if extra:
            details.append("extra " + ", ".join(sorted(extra)))
        _fail("smoke evidence has an invalid check inventory: " + "; ".join(details))
    if encountered != list(REQUIRED_CHECK_IDS):
        _fail("smoke checks must use canonical ID order")
    return checks


def _run_git(project_root: Path, *arguments: str) -> bytes:
    try:
        completed = subprocess.run(
            ("git", "-C", str(project_root), *arguments),
            check=False,
            capture_output=True,
            timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise SmokeEvidenceError("Git source verification did not complete") from exc
    if (
        completed.returncode != 0
        or len(completed.stdout) > _MAX_GIT_OUTPUT_BYTES
        or len(completed.stderr) > _MAX_GIT_OUTPUT_BYTES
    ):
        _fail("Git source verification failed")
    return completed.stdout


def _source_identity(project_root: Path) -> str:
    top_level = _run_git(project_root, "rev-parse", "--show-toplevel")
    try:
        git_root = Path(top_level.decode("utf-8", errors="strict").strip()).resolve(
            strict=True
        )
    except (OSError, UnicodeDecodeError) as exc:
        raise SmokeEvidenceError("Git source root is invalid") from exc
    if git_root != project_root:
        _fail("project root is not the Git repository root")
    commit = _run_git(project_root, "rev-parse", "--verify", "HEAD").decode(
        "ascii",
        errors="strict",
    ).strip()
    if not commit or any(character not in "0123456789abcdef" for character in commit):
        _fail("Git HEAD is invalid")
    status = _run_git(
        project_root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
    )
    if status:
        _fail("Git source tree is not clean")
    return commit


def verify_smoke_evidence(
    project_root: Path,
    evidence_path: Path,
    wheel_path: Path,
) -> dict[str, str]:
    """Validate complete smoke evidence against current source, lock, and wheel."""

    root = _absolute_without_symlinks(project_root, "project root")
    evidence = _load_evidence(evidence_path)
    _exact_fields(evidence, _TOP_LEVEL_FIELDS, "smoke evidence")
    if evidence["schema"] != SCHEMA:
        _fail(f"smoke evidence schema must be {SCHEMA}")
    if evidence["network_smoke_requested"] is not True:
        _fail("complete smoke evidence must request live network checks")
    _validate_timestamp(evidence["generated_at"])
    _validate_platform(evidence["platform"])
    checks = _validate_checks(evidence["checks"])

    if wheel_path.name != WHEEL_FILENAME:
        _fail(f"wheel must use the canonical filename {WHEEL_FILENAME}")
    wheel_sha256 = _sha256_file(wheel_path, "release wheel", _MAX_WHEEL_BYTES)
    lock_sha256 = _sha256_file(root / "uv.lock", "uv.lock", _MAX_LOCK_BYTES)
    source_commit = _source_identity(root)

    wheel_check = checks["artifact:wheel"]
    if (
        wheel_check.get("version") != TARGET_VERSION
        or wheel_check.get("detail") != WHEEL_FILENAME
        or wheel_check.get("sha256") != wheel_sha256
    ):
        _fail("artifact:wheel is not bound to the exact release wheel")
    if checks["package:fetech"].get("version") != TARGET_VERSION:
        _fail(f"package:fetech must report exact version {TARGET_VERSION}")

    for check_id in (
        "artifact:docling-models",
        "package:docling-slim",
        "smoke:docling",
    ):
        if checks[check_id].get("version") != DOCLING_VERSION:
            _fail(f"{check_id} must report exact version {DOCLING_VERSION}")
    if (
        checks["artifact:docling-models"].get("sha256")
        != DOCLING_REFERENCE_BUNDLE_SHA256
    ):
        _fail("artifact:docling-models does not match the reviewed reference bundle")

    source_check = checks["source:git"]
    if (
        source_check.get("version") != source_commit
        or source_check.get("detail") != "clean"
    ):
        _fail("source:git is not bound to clean current HEAD")
    if checks["lock:uv"].get("sha256") != lock_sha256:
        _fail("lock:uv is not bound to the current lock file")
    expected_services = {
        "smoke:wayback": WAYBACK_SERVICE,
        "smoke:yt-dlp": YTDLP_SERVICE,
    }
    for check_id, expected_service in expected_services.items():
        if checks[check_id].get("service") != expected_service:
            _fail(f"{check_id} must retain its exact service locator")

    return {
        "schema": SCHEMA,
        "source_commit": source_commit,
        "lock_sha256": lock_sha256,
        "wheel_sha256": wheel_sha256,
    }


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--evidence", type=Path, required=True)
    parser.add_argument("--wheel", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    try:
        receipt = verify_smoke_evidence(
            arguments.project_root,
            arguments.evidence,
            arguments.wheel,
        )
    except (OSError, SmokeEvidenceError, UnicodeError) as exc:
        print(f"v0.4 smoke evidence verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
