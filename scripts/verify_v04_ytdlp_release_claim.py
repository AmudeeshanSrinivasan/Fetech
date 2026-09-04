#!/usr/bin/env python3
"""Verify the committed v0.4 local yt-dlp containment scope and wording."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Final, NoReturn

SCHEMA: Final = "fetech.v0.4.ytdlp-release-claim.v1"
CANONICAL_CLAIM: Final = (
    "Fetech permits local yt-dlp only in development mode; required mode refuses "
    "it until brokered, allowlisted egress is configured."
)
SOURCE_PATHS: Final = (
    "src/fetech/yt_dlp.py",
    "src/fetech/worker_isolation.py",
)
DOCUMENT_PATHS: Final = (
    "README.md",
    "docs/releases/v0.4.0a0.md",
    "docs/security-threat-model.md",
    "docs/deployment-containment.md",
    "docs/capability-catalog.md",
    "docs/competitor-matrix.md",
)

_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_MAX_GIT_BYTES: Final = 4 * 1024 * 1024
_MAX_FILE_BYTES: Final = 2 * 1024 * 1024


class YTDLPClaimError(ValueError):
    """The committed source or documentation does not prove the narrow claim."""


def _fail(message: str) -> NoReturn:
    raise YTDLPClaimError(message)


def _git_bytes(project_root: Path, *arguments: str, maximum_bytes: int) -> bytes:
    try:
        process = subprocess.run(
            ("git", "-C", str(project_root), *arguments),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise YTDLPClaimError("Git source inspection did not complete") from exc
    if (
        process.returncode != 0
        or len(process.stdout) > maximum_bytes
        or len(process.stderr) > _MAX_GIT_BYTES
    ):
        _fail("Git source inspection failed")
    return process.stdout


def _repository_root(project_root: Path) -> Path:
    root = project_root.resolve(strict=True)
    repository_root = _git_bytes(
        root,
        "rev-parse",
        "--show-toplevel",
        maximum_bytes=_MAX_GIT_BYTES,
    ).decode("utf-8", errors="strict").strip()
    if Path(repository_root).resolve() != root:
        _fail("project root must be the Git worktree root")
    return root


def working_sources(project_root: Path) -> dict[str, str]:
    """Read the bounded tracked source tree for deterministic report projection."""

    root = _repository_root(project_root)
    sources: dict[str, str] = {}
    for path in (*SOURCE_PATHS, *DOCUMENT_PATHS):
        tracked = _git_bytes(
            root,
            "ls-files",
            "--error-unmatch",
            "--",
            path,
            maximum_bytes=4_096,
        ).decode("utf-8", errors="strict").strip()
        if tracked != path:
            _fail(f"release-claim source {path} is not tracked")
        candidate = root / path
        if candidate.is_symlink():
            _fail(f"release-claim source {path} cannot be a symlink")
        try:
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(root)
        except (OSError, ValueError) as exc:
            raise YTDLPClaimError(
                f"release-claim source {path} is unavailable"
            ) from exc
        if resolved != candidate:
            _fail(f"release-claim source {path} path cannot contain symlinks")
        try:
            flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
                os, "O_NOFOLLOW", 0
            )
            descriptor = os.open(resolved, flags)
            with os.fdopen(descriptor, "rb") as stream:
                before = os.fstat(stream.fileno())
                payload = stream.read(_MAX_FILE_BYTES + 1)
                after = os.fstat(stream.fileno())
        except (OSError, ValueError) as exc:
            raise YTDLPClaimError(
                f"release-claim source {path} is unavailable"
            ) from exc
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
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size < 0
            or before.st_size > _MAX_FILE_BYTES
            or len(payload) != before.st_size
            or identity_before != identity_after
        ):
            _fail(f"release-claim source {path} is not a stable bounded file")
        try:
            sources[path] = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise YTDLPClaimError(f"release-claim source {path} is not UTF-8") from exc
    return sources


def committed_sources(project_root: Path) -> tuple[str, dict[str, str]]:
    """Read the required files from HEAD of a clean exact-root worktree."""

    root = _repository_root(project_root)
    status = _git_bytes(
        root,
        "status",
        "--porcelain=v1",
        "--untracked-files=all",
        maximum_bytes=_MAX_GIT_BYTES,
    )
    if status:
        _fail("yt-dlp release-claim verification requires a clean worktree")
    commit = _git_bytes(
        root,
        "rev-parse",
        "HEAD",
        maximum_bytes=128,
    ).decode("ascii", errors="strict").strip()
    if _COMMIT.fullmatch(commit) is None:
        _fail("HEAD is not a full lowercase commit ID")

    sources: dict[str, str] = {}
    for path in (*SOURCE_PATHS, *DOCUMENT_PATHS):
        payload = _git_bytes(
            root,
            "show",
            f"{commit}:{path}",
            maximum_bytes=_MAX_FILE_BYTES,
        )
        try:
            sources[path] = payload.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise YTDLPClaimError(f"committed file {path} is not UTF-8") from exc
    return commit, sources


def _is_attribute(node: ast.AST, owner: str, attribute: str) -> bool:
    return (
        isinstance(node, ast.Attribute)
        and node.attr == attribute
        and isinstance(node.value, ast.Name)
        and node.value.id == owner
    )


def _call_name(node: ast.AST, name: str) -> bool:
    return isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == name


def _verify_yt_dlp_launcher(source: str) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise YTDLPClaimError("committed yt-dlp launcher is not valid Python") from exc
    valid_calls = []
    for node in ast.walk(tree):
        if not _call_name(node, "run_bounded"):
            continue
        isolation_keywords = [
            keyword.value for keyword in node.keywords if keyword.arg == "isolation"
        ]
        if len(isolation_keywords) != 1:
            continue
        isolation = isolation_keywords[0]
        if (
            isinstance(isolation, ast.Call)
            and isinstance(isolation.func, ast.Attribute)
            and isolation.func.attr == "request"
            and len(isolation.args) == 1
            and _is_attribute(
                isolation.args[0],
                "WorkerIsolationProfile",
                "MEDIA_YTDLP_NETWORK",
            )
        ):
            valid_calls.append(node)
    if len(valid_calls) != 1:
        _fail("yt-dlp must use exactly one bounded network isolation profile")


def _assignment_value(tree: ast.Module, name: str) -> ast.AST:
    matches: list[ast.AST] = []
    for node in tree.body:
        assigned = (
            isinstance(node, ast.Assign)
            and any(
                isinstance(target, ast.Name) and target.id == name
                for target in node.targets
            )
        ) or (
            isinstance(node, ast.AnnAssign)
            and isinstance(node.target, ast.Name)
            and node.target.id == name
        )
        if assigned:
            if node.value is None:
                _fail(f"worker isolation source must assign {name}")
            matches.append(node.value)
    if len(matches) != 1:
        _fail(f"worker isolation source must define exactly one {name}")
    return matches[0]


def _literal_keyword(call: ast.Call, name: str) -> object:
    values = [keyword.value for keyword in call.keywords if keyword.arg == name]
    if len(values) != 1 or not isinstance(values[0], ast.Constant):
        _fail(f"yt-dlp isolation profile must set {name} explicitly")
    return values[0].value


def _verify_isolation_policy(source: str) -> None:
    try:
        tree = ast.parse(source)
    except SyntaxError as exc:
        raise YTDLPClaimError("committed worker isolation policy is not valid Python") from exc
    profiles = _assignment_value(tree, "_PROFILES")
    if not isinstance(profiles, ast.Dict):
        _fail("worker isolation profile table must be a dictionary")
    matching_profiles: list[ast.Call] = []
    for key, value in zip(profiles.keys, profiles.values, strict=True):
        if _is_attribute(key, "WorkerIsolationProfile", "MEDIA_YTDLP_NETWORK"):
            if not _call_name(value, "_ProfileLimits"):
                _fail("yt-dlp isolation profile limits are invalid")
            matching_profiles.append(value)
    if len(matching_profiles) != 1:
        _fail("worker isolation policy must define exactly one yt-dlp profile")
    profile = matching_profiles[0]
    if _literal_keyword(profile, "network_denied") is not False:
        _fail("yt-dlp network profile must state that it needs network access")
    if _literal_keyword(profile, "required_mode_supported") is not False:
        _fail("yt-dlp network profile must remain unsupported in required mode")

    prepare_methods = [
        node
        for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == "prepare"
    ]
    if len(prepare_methods) != 1:
        _fail("worker isolation runtime must define exactly one prepare method")
    fail_closed = False
    for node in ast.walk(prepare_methods[0]):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        unsupported = (
            isinstance(test, ast.UnaryOp)
            and isinstance(test.op, ast.Not)
            and isinstance(test.operand, ast.Attribute)
            and test.operand.attr == "required_mode_supported"
        )
        if not unsupported:
            continue
        for child in ast.walk(node):
            if not isinstance(child, ast.Raise) or not isinstance(child.exc, ast.Call):
                continue
            if not _call_name(child.exc, "BackendExecutionError"):
                continue
            rendered = ast.unparse(child.exc)
            if "requires brokered egress in required mode" in rendered:
                fail_closed = True
    if not fail_closed:
        _fail("required mode must fail closed before yt-dlp worker execution")


def verify_sources(sources: Mapping[str, str]) -> dict[str, str]:
    """Verify source enforcement and exact release wording from supplied files."""

    expected_paths = set((*SOURCE_PATHS, *DOCUMENT_PATHS))
    if set(sources) != expected_paths:
        _fail("yt-dlp claim verifier received an incomplete source set")
    _verify_yt_dlp_launcher(sources["src/fetech/yt_dlp.py"])
    _verify_isolation_policy(sources["src/fetech/worker_isolation.py"])
    for path in DOCUMENT_PATHS:
        if sources[path].count(CANONICAL_CLAIM) != 1:
            _fail(f"{path} must contain the canonical yt-dlp release claim exactly once")
    return {
        path: hashlib.sha256(sources[path].encode("utf-8")).hexdigest()
        for path in sorted(sources)
    }


def build_receipt(commit: str, sources: Mapping[str, str]) -> dict[str, object]:
    """Return a deterministic source-bound verification receipt."""

    if _COMMIT.fullmatch(commit) is None:
        _fail("source commit is invalid")
    hashes = verify_sources(sources)
    return {
        "schema": SCHEMA,
        "source_commit": commit,
        "canonical_claim": CANONICAL_CLAIM,
        "files": [
            {"path": path, "sha256": digest}
            for path, digest in hashes.items()
        ],
        "required_mode_supported": False,
    }


def build_source_tree_receipt(sources: Mapping[str, str]) -> dict[str, object]:
    """Return deterministic evidence for the current tracked source-tree bytes."""

    hashes = verify_sources(sources)
    return {
        "schema": SCHEMA,
        "verification_scope": "tracked-source-tree",
        "canonical_claim": CANONICAL_CLAIM,
        "files": [
            {"path": path, "sha256": digest}
            for path, digest in hashes.items()
        ],
        "required_mode_supported": False,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument(
        "--require-committed",
        action="store_true",
        help="require a clean worktree and verify the exact files stored in HEAD",
    )
    args = parser.parse_args(argv)
    try:
        if args.require_committed:
            commit, sources = committed_sources(args.project_root)
            receipt = build_receipt(commit, sources)
        else:
            receipt = build_source_tree_receipt(working_sources(args.project_root))
    except (OSError, UnicodeDecodeError, YTDLPClaimError) as exc:
        print(f"yt-dlp release-claim verification failed: {exc}", file=sys.stderr)
        return 1
    print(json.dumps(receipt, indent=2, sort_keys=True, ensure_ascii=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
