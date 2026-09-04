from __future__ import annotations

import copy
import importlib.util
import sys
from collections import Counter
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_v04_ci_attestation.py"
SPEC = importlib.util.spec_from_file_location("fetech_v04_ci_attestation", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CIAttestationError = MODULE.CIAttestationError
REQUIRED_JOB_STEPS = MODULE.REQUIRED_JOB_STEPS
build_attestation = MODULE.build_attestation
render_attestation = MODULE.render_attestation

REPOSITORY = "AmudeeshanSrinivasan/Fetech"
COMMIT = "a" * 40
RUN_ID = 12345


def _documents() -> tuple[dict[str, object], dict[str, object], dict[str, object]]:
    repository = {"full_name": REPOSITORY, "default_branch": "main"}
    run = {
        "id": RUN_ID,
        "repository": {"full_name": REPOSITORY},
        "name": "CI",
        "path": ".github/workflows/ci.yml",
        "event": "push",
        "head_branch": "main",
        "head_sha": COMMIT,
        "status": "completed",
        "conclusion": "success",
        "run_attempt": 1,
        "html_url": f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}",
        "updated_at": "2026-09-04T00:00:00Z",
    }
    jobs = []
    for offset, (name, required_steps) in enumerate(REQUIRED_JOB_STEPS.items(), 1):
        jobs.append(
            {
                "id": RUN_ID + offset,
                "name": name,
                "head_sha": COMMIT,
                "status": "completed",
                "conclusion": "success",
                "html_url": (
                    f"https://github.com/{REPOSITORY}/actions/runs/{RUN_ID}/job/"
                    f"{RUN_ID + offset}"
                ),
                "steps": [
                    {"name": step, "status": "completed", "conclusion": "success"}
                    for step in required_steps
                ],
            }
        )
    return repository, run, {"total_count": len(jobs), "jobs": jobs}


def _build(
    documents: tuple[dict[str, object], dict[str, object], dict[str, object]],
) -> dict[str, object]:
    repository, run, jobs = documents
    return build_attestation(
        expected_repository=REPOSITORY,
        expected_commit=COMMIT,
        expected_run_id=RUN_ID,
        repository_document=repository,
        run_document=run,
        jobs_document=jobs,
    )


def test_builds_canonical_exact_commit_default_branch_attestation() -> None:
    receipt = _build(_documents())

    assert receipt["schema"] == "fetech.v0.4.github-ci-attestation.v1"
    assert receipt["source_commit"] == COMMIT
    assert receipt["event"] == "push"
    assert receipt["default_branch"] == "main"
    assert [job["name"] for job in receipt["jobs"]] == list(REQUIRED_JOB_STEPS)
    assert render_attestation(receipt).endswith("\n")


def test_workflow_contains_every_release_critical_named_step() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(
        encoding="utf-8"
    )

    expected = Counter(
        step
        for required_steps in REQUIRED_JOB_STEPS.values()
        for step in required_steps
    )
    lines = workflow.splitlines()
    for step, count in expected.items():
        assert lines.count(f"      - name: {step}") == count


@pytest.mark.parametrize(
    ("field", "value", "message"),
    (
        ("event", "pull_request", "must come from a push run"),
        ("head_branch", "agent/complete-v04-runtime", "default branch"),
        ("head_sha", "b" * 40, "source commit"),
        ("conclusion", "failure", "did not complete successfully"),
        ("path", ".github/workflows/other.yml", "canonical CI workflow"),
    ),
)
def test_rejects_non_release_workflow_runs(
    field: str,
    value: str,
    message: str,
) -> None:
    documents = _documents()
    documents[1][field] = value

    with pytest.raises(CIAttestationError, match=message):
        _build(documents)


def test_rejects_missing_failing_or_wrong_commit_required_job() -> None:
    documents = _documents()
    jobs = documents[2]["jobs"]
    assert isinstance(jobs, list)
    jobs[0]["head_sha"] = "b" * 40
    with pytest.raises(CIAttestationError, match="does not target"):
        _build(documents)

    documents = _documents()
    jobs = documents[2]["jobs"]
    assert isinstance(jobs, list)
    jobs.pop()
    documents[2]["total_count"] = len(jobs)
    with pytest.raises(CIAttestationError, match="missing a required release job"):
        _build(documents)

    documents = _documents()
    jobs = documents[2]["jobs"]
    assert isinstance(jobs, list)
    steps = jobs[0]["steps"]
    assert isinstance(steps, list)
    steps[0]["conclusion"] = "failure"
    with pytest.raises(CIAttestationError, match=r"step .* did not succeed"):
        _build(documents)


def test_rejects_truncated_job_page_and_duplicate_required_jobs() -> None:
    documents = _documents()
    documents[2]["total_count"] = 101
    with pytest.raises(CIAttestationError, match="complete and bounded"):
        _build(documents)

    documents = _documents()
    jobs = documents[2]["jobs"]
    assert isinstance(jobs, list)
    jobs.append(copy.deepcopy(jobs[0]))
    documents[2]["total_count"] = len(jobs)
    with pytest.raises(CIAttestationError, match="duplicate required job"):
        _build(documents)


def test_remote_parser_accepts_github_https_and_ssh_only() -> None:
    parse = MODULE._repository_from_remote

    assert parse(f"https://github.com/{REPOSITORY}.git") == REPOSITORY
    assert parse(f"git@github.com:{REPOSITORY}.git") == REPOSITORY
    with pytest.raises(CIAttestationError, match="GitHub repository URL"):
        parse("https://example.com/owner/repository.git")


def test_json_parser_rejects_duplicate_keys() -> None:
    with pytest.raises(CIAttestationError, match="duplicate key"):
        MODULE._load_json_bytes(b'{"run_id":1,"run_id":2}', "test", 100)


def test_receipt_is_revalidated_against_live_github_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    documents = _documents()
    receipt = _build(documents)
    receipt_path = tmp_path / MODULE.RECEIPT_FILENAME
    receipt_path.write_text(render_attestation(receipt), encoding="utf-8")
    monkeypatch.setattr(
        MODULE,
        "repository_context",
        lambda project_root: (REPOSITORY, COMMIT),
    )
    monkeypatch.setattr(
        MODULE,
        "fetch_github_documents",
        lambda repository, run_id: documents,
    )

    assert MODULE.verify_receipt(tmp_path, receipt_path) == receipt

    changed = copy.deepcopy(documents)
    changed[1]["run_attempt"] = 2
    monkeypatch.setattr(
        MODULE,
        "fetch_github_documents",
        lambda repository, run_id: changed,
    )
    with pytest.raises(CIAttestationError, match="does not match current"):
        MODULE.verify_receipt(tmp_path, receipt_path)


def test_receipt_requires_canonical_filename_fields_and_bytes(tmp_path: Path) -> None:
    receipt = _build(_documents())
    wrong_name = tmp_path / "ci.json"
    wrong_name.write_text(render_attestation(receipt), encoding="utf-8")
    with pytest.raises(CIAttestationError, match="canonical filename"):
        MODULE._load_receipt(wrong_name)

    receipt["invented"] = "passed"
    receipt_path = tmp_path / MODULE.RECEIPT_FILENAME
    receipt_path.write_text(render_attestation(receipt), encoding="utf-8")
    with pytest.raises(CIAttestationError, match="invalid fields"):
        MODULE._load_receipt(receipt_path)
