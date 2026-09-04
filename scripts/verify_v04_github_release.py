#!/usr/bin/env python3
"""Verify the signed tag and exact GitHub Release assets for Fetech v0.4."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final
from urllib.parse import quote

from release_attestation_common import (
    ARTIFACT_RECEIPT_FILENAME,
    CHECKSUMS_FILENAME,
    SDIST_FILENAME,
    TARGET_VERSION,
    WHEEL_FILENAME,
    ReleaseAttestationError,
    bounded_text,
    commit_text,
    load_release_artifacts,
    mapping,
    positive_integer,
    run_command,
    sequence,
    sha256_file,
)

TAG: Final = f"v{TARGET_VERSION}"
API_VERSION: Final = "2022-11-28"
SYSTEMD_RECEIPT: Final = f"fetech-v{TARGET_VERSION}-systemd-attestation.json"
LEGAL_RECEIPT: Final = f"fetech-v{TARGET_VERSION}-legal-approval.json"
REQUIRED_ASSET_LOCATIONS: Final[dict[str, str]] = {
    WHEEL_FILENAME: "dist",
    SDIST_FILENAME: "dist",
    CHECKSUMS_FILENAME: "dist",
    ARTIFACT_RECEIPT_FILENAME: "dist",
    f"fetech-v{TARGET_VERSION}-smoke.json": "dist",
    f"fetech-v{TARGET_VERSION}-github-ci.json": "dist",
    SYSTEMD_RECEIPT: "dist",
    f"{SYSTEMD_RECEIPT}.sig": "dist",
    LEGAL_RECEIPT: "dist",
    f"{LEGAL_RECEIPT}.sig": "dist",
    f"fetech-{TARGET_VERSION}-candidate.spdx.json": "release",
    f"dependency-licenses-{TARGET_VERSION}-candidate.md": "release",
}

_HTTPS_REMOTE = re.compile(
    r"https://github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?\Z"
)
_SSH_REMOTE = re.compile(
    r"(?:ssh://git@github\.com/|git@github\.com:)(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?\Z"
)
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")


class GitHubReleaseError(ReleaseAttestationError):
    """A sanitized GitHub Release verification failure."""


def _fail(message: str) -> None:
    raise GitHubReleaseError(message)


def _repository_from_origin(project_root: Path) -> str:
    _, remote = run_command(
        ("git", "-C", str(project_root), "remote", "get-url", "origin"),
        "GitHub origin inspection",
        timeout=15,
    )
    for pattern in (_HTTPS_REMOTE, _SSH_REMOTE):
        match = pattern.fullmatch(remote)
        if match is not None:
            repository = match.group("repository")
            if _REPOSITORY.fullmatch(repository) is not None:
                return repository
    _fail("origin is not a canonical GitHub repository URL")


def _gh_json(endpoint: str) -> Mapping[str, object]:
    if not endpoint.startswith("repos/") or any(
        character in endpoint for character in ("\x00", "\r", "\n")
    ):
        _fail("GitHub API endpoint is invalid")
    environment = {
        **os.environ,
        "GH_PROMPT_DISABLED": "1",
        "GH_NO_UPDATE_NOTIFIER": "1",
    }
    try:
        process = subprocess.run(
            (
                "gh",
                "api",
                "--hostname",
                "github.com",
                "--method",
                "GET",
                "--header",
                "Accept: application/vnd.github+json",
                "--header",
                f"X-GitHub-Api-Version: {API_VERSION}",
                endpoint,
            ),
            check=False,
            capture_output=True,
            timeout=60,
            env=environment,
        )
        if process.returncode != 0 or len(process.stdout) > 8 * 1024 * 1024:
            _fail("GitHub Release query failed")
        decoded = json.loads(process.stdout.decode("utf-8", errors="strict"))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise GitHubReleaseError("GitHub Release query returned invalid data") from exc
    return mapping(decoded, "GitHub API response")


def _tag_commit(repository: str) -> str:
    encoded_tag = quote(TAG, safe="")
    reference = _gh_json(f"repos/{repository}/git/ref/tags/{encoded_tag}")
    tag_reference = mapping(reference.get("object"), "tag reference object")
    if bounded_text(tag_reference.get("type"), "tag object type", 32) != "tag":
        _fail("release tag must be an annotated signed tag")
    tag_sha = commit_text(tag_reference.get("sha"), "tag object SHA")
    tag_document = _gh_json(f"repos/{repository}/git/tags/{tag_sha}")
    verification = mapping(tag_document.get("verification"), "tag verification")
    if verification.get("verified") is not True or verification.get("reason") != "valid":
        _fail("GitHub does not report a valid signature for the release tag")
    target = mapping(tag_document.get("object"), "annotated tag target")
    if bounded_text(target.get("type"), "tag target type", 32) != "commit":
        _fail("release tag does not point directly to a commit")
    return commit_text(target.get("sha"), "tag target SHA")


def _expected_assets(project_root: Path, artifact_dir: Path) -> dict[str, tuple[str, int]]:
    expected: dict[str, tuple[str, int]] = {}
    for filename, location in REQUIRED_ASSET_LOCATIONS.items():
        path = artifact_dir / filename if location == "dist" else project_root / location / filename
        expected[filename] = sha256_file(path, f"release asset {filename}", maximum_bytes=256_000_000)
    return expected


def verify_release(project_root: Path, artifact_dir: Path) -> dict[str, object]:
    release_receipt = load_release_artifacts(project_root, artifact_dir)
    expected_commit = commit_text(
        release_receipt.get("source_commit"), "artifact source commit"
    )
    repository = _repository_from_origin(project_root)
    if _tag_commit(repository) != expected_commit:
        _fail("remote release tag does not resolve to the artifact source commit")
    release = _gh_json(f"repos/{repository}/releases/tags/{quote(TAG, safe='')}")
    if release.get("tag_name") != TAG:
        _fail("GitHub Release tag is invalid")
    if release.get("draft") is not False or release.get("prerelease") is not True:
        _fail("GitHub Release must be a published prerelease")
    release_id = positive_integer(release.get("id"), "release ID")
    release_url = bounded_text(release.get("html_url"), "release URL", 512)
    if release_url != f"https://github.com/{repository}/releases/tag/{TAG}":
        _fail("GitHub Release URL is invalid")
    published_at = bounded_text(release.get("published_at"), "release publication time", 64)

    raw_assets = sequence(release.get("assets"), "GitHub Release assets")
    assets: dict[str, Mapping[str, object]] = {}
    for index, value in enumerate(raw_assets):
        asset = mapping(value, f"GitHub Release asset {index}")
        name = bounded_text(asset.get("name"), "GitHub Release asset name", 256)
        if name in assets:
            _fail("GitHub Release contains duplicate asset names")
        assets[name] = asset
    expected_assets = _expected_assets(project_root, artifact_dir)
    if set(assets) != set(expected_assets):
        _fail("GitHub Release asset inventory does not match the approved inventory")
    verified_assets: list[dict[str, object]] = []
    for name in REQUIRED_ASSET_LOCATIONS:
        asset = assets[name]
        if asset.get("state") != "uploaded":
            _fail("a required GitHub Release asset is not uploaded")
        expected_digest, expected_size = expected_assets[name]
        if asset.get("digest") != f"sha256:{expected_digest}":
            _fail("a GitHub Release asset digest does not match local approved bytes")
        if positive_integer(asset.get("size"), "GitHub Release asset size") != expected_size:
            _fail("a GitHub Release asset size does not match local approved bytes")
        verified_assets.append(
            {"name": name, "sha256": expected_digest, "size": expected_size}
        )
    return {
        "repository": repository,
        "tag": TAG,
        "source_commit": expected_commit,
        "release_id": release_id,
        "release_url": release_url,
        "published_at": published_at,
        "assets": verified_assets,
    }


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
        document = verify_release(
            args.project_root.resolve(strict=True),
            args.artifact_dir.resolve(strict=True),
        )
    except (OSError, ReleaseAttestationError) as exc:
        print(f"GitHub Release verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
