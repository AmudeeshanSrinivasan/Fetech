#!/usr/bin/env python3
"""Collect or revalidate exact-commit GitHub Actions evidence for v0.4.

The receipt is not trusted by itself. Verification derives the repository and
commit from a clean local checkout, fetches the referenced workflow run and
jobs through ``gh api``, and requires the canonical receipt bytes to match that
live GitHub state. Pull-request runs never satisfy the release gate.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path
from typing import Final, NoReturn

TARGET_VERSION: Final = "0.4.0a0"
SCHEMA: Final = "fetech.v0.4.github-ci-attestation.v1"
RECEIPT_FILENAME: Final = f"fetech-v{TARGET_VERSION}-github-ci.json"
WORKFLOW_NAME: Final = "CI"
WORKFLOW_PATH: Final = ".github/workflows/ci.yml"
API_VERSION: Final = "2022-11-28"
REQUIRED_JOB_STEPS: Final[dict[str, tuple[str, ...]]] = {
    "verify": (
        "Verify checked-out commit identity",
        "Install uv",
        "Install all capability extras",
        "Install Chromium for browser conformance",
        "Verify lock",
        "Lint",
        "Type check",
        "Test",
        "Coverage report",
        "Verify clean diff",
        "Verify release evidence",
        "Build and verify candidate distributions",
    ),
    "containment-linux": (
        "Verify checked-out commit identity",
        "Install uv and containment dependencies",
        "Enable reviewed Bubblewrap AppArmor profile",
        "Install test environment",
        "Install reviewed Chromium test bundle",
        "Verify containment tools",
        "Run required Linux containment enforcement",
    ),
}

_COMMIT = re.compile(r"[0-9a-f]{40}\Z")
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_HTTPS_REMOTE = re.compile(
    r"https://github\.com/(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?\Z"
)
_SSH_REMOTE = re.compile(
    r"(?:ssh://git@github\.com/|git@github\.com:)(?P<repository>[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?)(?:\.git)?\Z"
)
_MAX_API_BYTES: Final = 4 * 1024 * 1024
_MAX_RECEIPT_BYTES: Final = 256 * 1024
_MAX_GIT_BYTES: Final = 64 * 1024
_MAX_TEXT_BYTES: Final = 2_048
_TOP_LEVEL_FIELDS: Final = {
    "schema",
    "repository",
    "default_branch",
    "source_commit",
    "workflow_name",
    "workflow_path",
    "run_id",
    "run_attempt",
    "event",
    "conclusion",
    "run_url",
    "run_updated_at",
    "jobs",
}
_JOB_FIELDS: Final = {"name", "job_id", "conclusion", "job_url", "required_steps"}


class CIAttestationError(ValueError):
    """A sanitized CI-attestation verification failure."""


def _fail(message: str) -> NoReturn:
    raise CIAttestationError(message)


def _bounded_text(value: object, label: str, maximum_bytes: int = _MAX_TEXT_BYTES) -> str:
    if not isinstance(value, str):
        _fail(f"{label} must be text")
    if (
        not value
        or len(value.encode("utf-8")) > maximum_bytes
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
    ):
        _fail(f"{label} must be bounded single-line text")
    return value


def _positive_integer(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        _fail(f"{label} must be a positive integer")
    return value


def _exact_fields(value: Mapping[str, object], expected: set[str], label: str) -> None:
    if set(value) != expected:
        _fail(f"{label} has invalid fields")


def _timestamp(value: object, label: str) -> str:
    text = _bounded_text(value, label, 64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CIAttestationError(f"{label} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        _fail(f"{label} must include a timezone")
    return text


def _repository_name(value: object, label: str) -> str:
    text = _bounded_text(value, label, 256)
    if _REPOSITORY.fullmatch(text) is None:
        _fail(f"{label} is invalid")
    return text


def _commit_id(value: object, label: str) -> str:
    text = _bounded_text(value, label, 64)
    if _COMMIT.fullmatch(text) is None:
        _fail(f"{label} must be a full lowercase commit ID")
    return text


def _mapping(value: object, label: str) -> Mapping[str, object]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return value


def _sequence(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return value


def _github_url(value: object, repository: str, suffix: str, label: str) -> str:
    text = _bounded_text(value, label, 512)
    expected_prefix = f"https://github.com/{repository}/actions/{suffix}"
    if text != expected_prefix and not text.startswith(f"{expected_prefix}/"):
        _fail(f"{label} is not the expected GitHub Actions URL")
    return text


def _repository_from_remote(remote: str) -> str:
    for pattern in (_HTTPS_REMOTE, _SSH_REMOTE):
        match = pattern.fullmatch(remote.strip())
        if match is not None:
            return _repository_name(match.group("repository"), "origin repository")
    _fail("origin must be an HTTPS or SSH GitHub repository URL")


def _git_output(project_root: Path, *arguments: str) -> str:
    try:
        process = subprocess.run(
            ("git", "-C", str(project_root), *arguments),
            check=False,
            capture_output=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CIAttestationError("Git repository inspection did not complete") from exc
    if (
        process.returncode != 0
        or len(process.stdout) > _MAX_GIT_BYTES
        or len(process.stderr) > _MAX_GIT_BYTES
    ):
        _fail("Git repository inspection failed")
    try:
        return process.stdout.decode("utf-8", errors="strict").strip()
    except UnicodeDecodeError as exc:
        raise CIAttestationError("Git repository output was not UTF-8") from exc


def repository_context(project_root: Path) -> tuple[str, str]:
    """Return the GitHub repository and HEAD of a clean exact-root checkout."""

    root = project_root.resolve(strict=True)
    if Path(_git_output(root, "rev-parse", "--show-toplevel")).resolve() != root:
        _fail("project root must be the Git worktree root")
    if _git_output(root, "status", "--porcelain=v1", "--untracked-files=all"):
        _fail("CI attestation requires a clean source worktree")
    commit = _commit_id(_git_output(root, "rev-parse", "HEAD"), "source commit")
    repository = _repository_from_remote(_git_output(root, "remote", "get-url", "origin"))
    return repository, commit


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            _fail(f"JSON contains duplicate key: {key}")
        result[key] = value
    return result


def _load_json_bytes(payload: bytes, label: str, maximum_bytes: int) -> object:
    if not payload or len(payload) > maximum_bytes:
        _fail(f"{label} is empty or oversized")
    try:
        return json.loads(
            payload.decode("utf-8", errors="strict"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda value: _fail(
                f"{label} contains non-finite value {value}"
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CIAttestationError(f"{label} is not valid UTF-8 JSON") from exc


def _gh_api(endpoint: str) -> object:
    if not endpoint.startswith("repos/") or any(
        character in endpoint for character in ("\x00", "\r", "\n")
    ):
        _fail("GitHub API endpoint is invalid")
    environment = os.environ.copy()
    environment["GH_PROMPT_DISABLED"] = "1"
    environment["GH_NO_UPDATE_NOTIFIER"] = "1"
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
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise CIAttestationError("GitHub Actions evidence query did not complete") from exc
    if (
        process.returncode != 0
        or len(process.stdout) > _MAX_API_BYTES
        or len(process.stderr) > _MAX_API_BYTES
    ):
        _fail("GitHub Actions evidence query failed")
    return _load_json_bytes(process.stdout, "GitHub API response", _MAX_API_BYTES)


def fetch_github_documents(
    repository: str,
    run_id: int,
) -> tuple[Mapping[str, object], Mapping[str, object], Mapping[str, object]]:
    """Fetch the bounded repository, workflow-run, and job documents."""

    safe_repository = _repository_name(repository, "repository")
    safe_run_id = _positive_integer(run_id, "run_id")
    repository_document = _mapping(
        _gh_api(f"repos/{safe_repository}"),
        "repository response",
    )
    run_document = _mapping(
        _gh_api(f"repos/{safe_repository}/actions/runs/{safe_run_id}"),
        "workflow-run response",
    )
    jobs_document = _mapping(
        _gh_api(
            f"repos/{safe_repository}/actions/runs/{safe_run_id}/jobs?per_page=100"
        ),
        "workflow-jobs response",
    )
    return repository_document, run_document, jobs_document


def _successful_job(
    raw_job: Mapping[str, object],
    *,
    repository: str,
    commit: str,
    run_id: int,
    job_name: str,
    required_steps: tuple[str, ...],
) -> dict[str, object]:
    if _bounded_text(raw_job.get("name"), "job name", 256) != job_name:
        _fail(f"required job {job_name} has an invalid name")
    if _commit_id(raw_job.get("head_sha"), f"{job_name} head_sha") != commit:
        _fail(f"required job {job_name} does not target the source commit")
    if raw_job.get("status") != "completed" or raw_job.get("conclusion") != "success":
        _fail(f"required job {job_name} did not complete successfully")
    job_id = _positive_integer(raw_job.get("id"), f"{job_name} job_id")
    job_url = _github_url(
        raw_job.get("html_url"),
        repository,
        f"runs/{run_id}/job/{job_id}",
        f"{job_name} job_url",
    )
    raw_steps = _sequence(raw_job.get("steps"), f"{job_name} steps")
    named_steps: dict[str, Mapping[str, object]] = {}
    for index, raw_step in enumerate(raw_steps):
        step = _mapping(raw_step, f"{job_name} step {index}")
        name = _bounded_text(step.get("name"), f"{job_name} step name", 256)
        if name in named_steps:
            _fail(f"required job {job_name} contains duplicate step names")
        named_steps[name] = step
    for step_name in required_steps:
        step = named_steps.get(step_name)
        if step is None:
            _fail(f"required job {job_name} is missing step {step_name}")
        if step.get("status") != "completed" or step.get("conclusion") != "success":
            _fail(f"required job {job_name} step {step_name} did not succeed")
    return {
        "name": job_name,
        "job_id": job_id,
        "conclusion": "success",
        "job_url": job_url,
        "required_steps": list(required_steps),
    }


def build_attestation(
    *,
    expected_repository: str,
    expected_commit: str,
    expected_run_id: int,
    repository_document: Mapping[str, object],
    run_document: Mapping[str, object],
    jobs_document: Mapping[str, object],
) -> dict[str, object]:
    """Validate GitHub API documents and return the canonical receipt."""

    repository = _repository_name(expected_repository, "expected repository")
    commit = _commit_id(expected_commit, "expected commit")
    run_id = _positive_integer(expected_run_id, "expected run_id")
    if _repository_name(repository_document.get("full_name"), "repository full_name") != repository:
        _fail("GitHub repository identity does not match origin")
    default_branch = _bounded_text(
        repository_document.get("default_branch"),
        "default_branch",
        256,
    )
    if _positive_integer(run_document.get("id"), "workflow run_id") != run_id:
        _fail("workflow run ID does not match the requested run")
    run_repository = _mapping(run_document.get("repository"), "workflow repository")
    if _repository_name(run_repository.get("full_name"), "workflow repository full_name") != repository:
        _fail("workflow run belongs to a different repository")
    if run_document.get("name") != WORKFLOW_NAME or run_document.get("path") != WORKFLOW_PATH:
        _fail("workflow run is not the canonical CI workflow")
    if run_document.get("event") != "push":
        _fail("release CI evidence must come from a push run")
    if run_document.get("head_branch") != default_branch:
        _fail("release CI evidence must run on the default branch")
    if _commit_id(run_document.get("head_sha"), "workflow head_sha") != commit:
        _fail("workflow run does not target the source commit")
    if run_document.get("status") != "completed" or run_document.get("conclusion") != "success":
        _fail("workflow run did not complete successfully")
    run_attempt = _positive_integer(run_document.get("run_attempt"), "run_attempt")
    run_url = _github_url(
        run_document.get("html_url"),
        repository,
        f"runs/{run_id}",
        "run_url",
    )
    run_updated_at = _timestamp(run_document.get("updated_at"), "run_updated_at")

    total_count = jobs_document.get("total_count")
    if not isinstance(total_count, int) or isinstance(total_count, bool) or total_count < 0:
        _fail("workflow jobs total_count must be a non-negative integer")
    raw_jobs = _sequence(jobs_document.get("jobs"), "workflow jobs")
    if total_count != len(raw_jobs) or total_count > 100:
        _fail("workflow jobs response must be complete and bounded")
    jobs_by_name: dict[str, Mapping[str, object]] = {}
    for index, raw_job in enumerate(raw_jobs):
        job = _mapping(raw_job, f"workflow job {index}")
        name = _bounded_text(job.get("name"), f"workflow job {index} name", 256)
        if name in REQUIRED_JOB_STEPS:
            if name in jobs_by_name:
                _fail(f"workflow contains duplicate required job {name}")
            jobs_by_name[name] = job
    if set(jobs_by_name) != set(REQUIRED_JOB_STEPS):
        _fail("workflow is missing a required release job")
    jobs = [
        _successful_job(
            jobs_by_name[name],
            repository=repository,
            commit=commit,
            run_id=run_id,
            job_name=name,
            required_steps=required_steps,
        )
        for name, required_steps in REQUIRED_JOB_STEPS.items()
    ]
    return {
        "schema": SCHEMA,
        "repository": repository,
        "default_branch": default_branch,
        "source_commit": commit,
        "workflow_name": WORKFLOW_NAME,
        "workflow_path": WORKFLOW_PATH,
        "run_id": run_id,
        "run_attempt": run_attempt,
        "event": "push",
        "conclusion": "success",
        "run_url": run_url,
        "run_updated_at": run_updated_at,
        "jobs": jobs,
    }


def render_attestation(document: Mapping[str, object]) -> str:
    """Render canonical deterministic JSON."""

    return f"{json.dumps(document, indent=2, sort_keys=True, ensure_ascii=True)}\n"


def _load_receipt(path: Path) -> dict[str, object]:
    if path.name != RECEIPT_FILENAME or path.is_symlink():
        _fail(f"CI receipt must use canonical filename {RECEIPT_FILENAME}")
    try:
        resolved = path.resolve(strict=True)
        payload = resolved.read_bytes()
    except OSError as exc:
        raise CIAttestationError("CI receipt is unavailable") from exc
    document = _load_json_bytes(payload, "CI receipt", _MAX_RECEIPT_BYTES)
    receipt = _mapping(document, "CI receipt")
    _exact_fields(receipt, _TOP_LEVEL_FIELDS, "CI receipt")
    if receipt.get("schema") != SCHEMA:
        _fail("CI receipt schema is invalid")
    if payload != render_attestation(receipt).encode("utf-8"):
        _fail("CI receipt is not canonical JSON")
    jobs = _sequence(receipt.get("jobs"), "CI receipt jobs")
    if len(jobs) != len(REQUIRED_JOB_STEPS):
        _fail("CI receipt must contain the exact required jobs")
    for index, raw_job in enumerate(jobs):
        job = _mapping(raw_job, f"CI receipt job {index}")
        _exact_fields(job, _JOB_FIELDS, f"CI receipt job {index}")
    return dict(receipt)


def collect_attestation(project_root: Path, run_id: int) -> dict[str, object]:
    """Collect a canonical receipt for a clean local release commit."""

    repository, commit = repository_context(project_root)
    repository_document, run_document, jobs_document = fetch_github_documents(
        repository,
        run_id,
    )
    return build_attestation(
        expected_repository=repository,
        expected_commit=commit,
        expected_run_id=run_id,
        repository_document=repository_document,
        run_document=run_document,
        jobs_document=jobs_document,
    )


def verify_receipt(project_root: Path, receipt_path: Path) -> dict[str, object]:
    """Re-query GitHub and require the receipt to match the live run exactly."""

    receipt = _load_receipt(receipt_path)
    repository, commit = repository_context(project_root)
    if receipt.get("repository") != repository or receipt.get("source_commit") != commit:
        _fail("CI receipt is not bound to the clean local source commit")
    run_id = _positive_integer(receipt.get("run_id"), "CI receipt run_id")
    observed = collect_attestation(project_root, run_id)
    if receipt != observed:
        _fail("CI receipt does not match current GitHub Actions evidence")
    return observed


def _write_receipt(path: Path, document: Mapping[str, object]) -> None:
    if path.name != RECEIPT_FILENAME or path.is_symlink():
        _fail(f"CI receipt output must use canonical filename {RECEIPT_FILENAME}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(render_attestation(document), encoding="utf-8")
    except OSError as exc:
        raise CIAttestationError("CI receipt could not be written") from exc


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--run-id", type=int, help="collect this GitHub Actions run")
    mode.add_argument("--receipt", type=Path, help="revalidate an existing receipt")
    parser.add_argument("--output", type=Path, help="canonical receipt output path")
    args = parser.parse_args(argv)
    try:
        root = args.project_root.resolve(strict=True)
        if args.run_id is not None:
            if args.output is None:
                _fail("--output is required when collecting a CI receipt")
            document = collect_attestation(root, args.run_id)
            _write_receipt(args.output, document)
        else:
            if args.output is not None:
                _fail("--output cannot be used while verifying a CI receipt")
            assert args.receipt is not None
            document = verify_receipt(root, args.receipt)
    except (CIAttestationError, OSError) as exc:
        print(f"CI attestation verification failed: {exc}", file=sys.stderr)
        return 1
    print(render_attestation(document), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
