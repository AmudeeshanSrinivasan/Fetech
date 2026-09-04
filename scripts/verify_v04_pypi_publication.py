#!/usr/bin/env python3
"""Verify PyPI published the exact approved Fetech v0.4 distributions."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final
from urllib.parse import urlparse

from release_attestation_common import (
    PROJECT_NAME,
    SDIST_FILENAME,
    TARGET_VERSION,
    WHEEL_FILENAME,
    ReleaseAttestationError,
    bounded_text,
    load_release_artifacts,
    mapping,
    positive_integer,
    sequence,
    sha256_text,
    timestamp_text,
)

PYPI_URL: Final = f"https://pypi.org/pypi/{PROJECT_NAME}/{TARGET_VERSION}/json"
_MAX_RESPONSE_BYTES: Final = 8 * 1024 * 1024
_EXPECTED_TYPES: Final = {
    WHEEL_FILENAME: "bdist_wheel",
    SDIST_FILENAME: "sdist",
}


class PyPIPublicationError(ReleaseAttestationError):
    """A sanitized PyPI publication verification failure."""


def _fail(message: str) -> None:
    raise PyPIPublicationError(message)


def fetch_pypi_document() -> Mapping[str, object]:
    request = urllib.request.Request(
        PYPI_URL,
        headers={"Accept": "application/json", "User-Agent": "Fetech-release-verifier/1"},
        method="GET",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            if response.status != 200 or response.geturl() != PYPI_URL:
                _fail("PyPI release endpoint did not return the canonical response")
            payload = response.read(_MAX_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError) as exc:
        raise PyPIPublicationError("PyPI release query failed") from exc
    if len(payload) > _MAX_RESPONSE_BYTES:
        _fail("PyPI release response is oversized")
    try:
        decoded = json.loads(payload.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise PyPIPublicationError("PyPI release response is invalid JSON") from exc
    return mapping(decoded, "PyPI release response")


def _expected_distributions(release_receipt: Mapping[str, object]) -> dict[str, dict[str, object]]:
    expected: dict[str, dict[str, object]] = {}
    for raw in sequence(release_receipt.get("artifacts"), "release artifacts"):
        artifact = mapping(raw, "release artifact")
        filename = bounded_text(artifact.get("filename"), "artifact filename", 256)
        if filename not in _EXPECTED_TYPES or filename in expected:
            _fail("release artifact receipt has an invalid distribution inventory")
        expected[filename] = {
            "sha256": sha256_text(artifact.get("sha256"), "artifact digest"),
            "size": positive_integer(artifact.get("size"), "artifact size"),
            "packagetype": _EXPECTED_TYPES[filename],
        }
    if set(expected) != set(_EXPECTED_TYPES):
        _fail("release artifact receipt is incomplete")
    return expected


def verify_document(
    document: Mapping[str, object],
    *,
    release_receipt: Mapping[str, object],
) -> dict[str, object]:
    info = mapping(document.get("info"), "PyPI project information")
    if str(info.get("name", "")).lower() != PROJECT_NAME or info.get("version") != TARGET_VERSION:
        _fail("PyPI project name or version is invalid")
    expected = _expected_distributions(release_receipt)
    raw_urls = sequence(document.get("urls"), "PyPI release files")
    files: dict[str, Mapping[str, object]] = {}
    for index, value in enumerate(raw_urls):
        distribution = mapping(value, f"PyPI release file {index}")
        filename = bounded_text(distribution.get("filename"), "PyPI filename", 256)
        if filename in files:
            _fail("PyPI release contains duplicate filenames")
        files[filename] = distribution
    if set(files) != set(expected):
        _fail("PyPI release file inventory does not match the approved distributions")

    verified: list[dict[str, object]] = []
    for filename in (WHEEL_FILENAME, SDIST_FILENAME):
        distribution = files[filename]
        approved = expected[filename]
        if distribution.get("packagetype") != approved["packagetype"]:
            _fail("PyPI distribution type is invalid")
        if distribution.get("yanked") is not False:
            _fail("PyPI distribution is yanked")
        digests = mapping(distribution.get("digests"), "PyPI distribution digests")
        digest = sha256_text(digests.get("sha256"), "PyPI SHA-256")
        if digest != approved["sha256"]:
            _fail("PyPI distribution digest does not match approved bytes")
        size = positive_integer(distribution.get("size"), "PyPI distribution size")
        if size != approved["size"]:
            _fail("PyPI distribution size does not match approved bytes")
        url = bounded_text(distribution.get("url"), "PyPI distribution URL", 2_048)
        parsed = urlparse(url)
        try:
            port = parsed.port
        except ValueError as exc:
            raise PyPIPublicationError("PyPI distribution URL has an invalid port") from exc
        if (
            parsed.scheme != "https"
            or parsed.hostname != "files.pythonhosted.org"
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or parsed.query
            or parsed.fragment
            or not parsed.path.endswith(f"/{filename}")
        ):
            _fail("PyPI distribution URL is not the canonical HTTPS file host")
        upload_time, _ = timestamp_text(
            distribution.get("upload_time_iso_8601"), "PyPI upload timestamp"
        )
        verified.append(
            {
                "filename": filename,
                "sha256": digest,
                "size": size,
                "url": url,
                "upload_time": upload_time,
            }
        )
    return {
        "project": PROJECT_NAME,
        "version": TARGET_VERSION,
        "project_url": f"https://pypi.org/project/{PROJECT_NAME}/{TARGET_VERSION}/",
        "distributions": verified,
    }


def verify_publication(
    project_root: Path,
    artifact_dir: Path,
    document: Mapping[str, object] | None = None,
) -> dict[str, object]:
    release_receipt = load_release_artifacts(project_root, artifact_dir)
    return verify_document(
        document or fetch_pypi_document(),
        release_receipt=release_receipt,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--artifact-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        document = verify_publication(
            args.project_root.resolve(strict=True),
            args.artifact_dir.resolve(strict=True),
        )
    except (OSError, ReleaseAttestationError) as exc:
        print(f"PyPI publication verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
