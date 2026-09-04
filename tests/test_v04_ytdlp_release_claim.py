from __future__ import annotations

import importlib.util
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_v04_ytdlp_release_claim.py"
SPEC = importlib.util.spec_from_file_location("fetech_v04_ytdlp_claim", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CANONICAL_CLAIM = MODULE.CANONICAL_CLAIM
DOCUMENT_PATHS = MODULE.DOCUMENT_PATHS
SOURCE_PATHS = MODULE.SOURCE_PATHS
YTDLPClaimError = MODULE.YTDLPClaimError
verify_sources = MODULE.verify_sources


def _sources() -> dict[str, str]:
    return {
        path: (ROOT / path).read_text(encoding="utf-8")
        for path in (*SOURCE_PATHS, *DOCUMENT_PATHS)
    }


def test_current_source_and_docs_prove_narrowed_ytdlp_claim() -> None:
    hashes = verify_sources(_sources())

    assert set(hashes) == set((*SOURCE_PATHS, *DOCUMENT_PATHS))
    assert all(len(digest) == 64 for digest in hashes.values())


def test_rejects_missing_or_duplicated_canonical_claim() -> None:
    sources = _sources()
    sources[DOCUMENT_PATHS[0]] = sources[DOCUMENT_PATHS[0]].replace(
        CANONICAL_CLAIM,
        "",
    )
    with pytest.raises(YTDLPClaimError, match=r"must contain.*exactly once"):
        verify_sources(sources)

    sources = _sources()
    sources[DOCUMENT_PATHS[0]] += f"\n{CANONICAL_CLAIM}\n"
    with pytest.raises(YTDLPClaimError, match=r"must contain.*exactly once"):
        verify_sources(sources)


def test_rejects_launcher_profile_drift() -> None:
    sources = _sources()
    sources["src/fetech/yt_dlp.py"] = sources["src/fetech/yt_dlp.py"].replace(
        "WorkerIsolationProfile.MEDIA_YTDLP_NETWORK",
        "WorkerIsolationProfile.MEDIA_NATIVE_OFFLINE",
    )

    with pytest.raises(YTDLPClaimError, match="bounded network isolation profile"):
        verify_sources(sources)


def test_rejects_required_mode_policy_drift() -> None:
    sources = _sources()
    sources["src/fetech/worker_isolation.py"] = sources[
        "src/fetech/worker_isolation.py"
    ].replace("required_mode_supported=False", "required_mode_supported=True")

    with pytest.raises(YTDLPClaimError, match="unsupported in required mode"):
        verify_sources(sources)


def test_rejects_missing_fail_closed_prepare_branch() -> None:
    sources = _sources()
    sources["src/fetech/worker_isolation.py"] = sources[
        "src/fetech/worker_isolation.py"
    ].replace(
        "requires brokered egress in required mode",
        "cannot execute",
    )

    with pytest.raises(YTDLPClaimError, match="must fail closed"):
        verify_sources(sources)


def test_cli_source_reader_requires_clean_committed_files(tmp_path: Path) -> None:
    for path, content in _sources().items():
        destination = tmp_path / path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(content, encoding="utf-8")
    subprocess.run(("git", "init", "-q"), cwd=tmp_path, check=True)
    subprocess.run(("git", "add", "--all"), cwd=tmp_path, check=True)
    subprocess.run(
        (
            "git",
            "-c",
            "user.name=Fetech Tests",
            "-c",
            "user.email=fetech-tests@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-q",
            "-m",
            "test fixture",
        ),
        cwd=tmp_path,
        check=True,
    )

    commit, sources = MODULE.committed_sources(tmp_path)
    assert len(commit) == 40
    assert sources == _sources()

    (tmp_path / DOCUMENT_PATHS[0]).write_text("dirty\n", encoding="utf-8")
    with pytest.raises(YTDLPClaimError, match="clean worktree"):
        MODULE.committed_sources(tmp_path)
    dirty_sources = MODULE.working_sources(tmp_path)
    assert dirty_sources[DOCUMENT_PATHS[0]] == "dirty\n"
    with pytest.raises(YTDLPClaimError, match="canonical yt-dlp release claim"):
        MODULE.verify_sources(dirty_sources)
