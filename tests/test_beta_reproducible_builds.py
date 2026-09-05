"""Hermetic tests for Beta reproducible-build evidence."""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import importlib.util
import io
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "verify_reproducible_builds.py"
SPEC = importlib.util.spec_from_file_location("fetech_reproducible_builds", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ReproducibleBuildError = MODULE.ReproducibleBuildError
render_receipt = MODULE.render_receipt
verify_artifact_pair = MODULE.verify_artifact_pair

VERSION = "0.5.0b1"
EPOCH = 1_788_524_216
WHEEL_NAME = f"fetech-{VERSION}-py3-none-any.whl"
SDIST_NAME = f"fetech-{VERSION}.tar.gz"


def _record(payloads: dict[str, bytes], record_name: str) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for name, payload in payloads.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        writer.writerow((name, f"sha256={digest}", str(len(payload))))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode()


def _wheel(
    directory: Path,
    *,
    epoch: int = EPOCH,
    corrupt_record: bool = False,
    special_member: bool = False,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / WHEEL_NAME
    dist_info = f"fetech-{VERSION}.dist-info"
    payloads = {
        "fetech/__init__.py": f'__version__ = "{VERSION}"\n'.encode(),
        f"{dist_info}/METADATA": (
            f"Metadata-Version: 2.4\nName: fetech\nVersion: {VERSION}\n\n"
        ).encode(),
        f"{dist_info}/WHEEL": b"Wheel-Version: 1.0\nTag: py3-none-any\n\n",
    }
    record_name = f"{dist_info}/RECORD"
    payloads[record_name] = _record(payloads, record_name)
    if corrupt_record:
        payloads[record_name] = payloads[record_name].replace(b"sha256=", b"sha256=bad", 1)
    with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for index, (name, payload) in enumerate(payloads.items()):
            info = zipfile.ZipInfo(name, MODULE._zip_timestamp(epoch))
            info.create_system = 3
            file_type = stat.S_IFLNK if special_member and index == 0 else 0
            info.external_attr = (file_type | 0o644) << 16
            archive.writestr(info, payload)
    return path


def _sdist(directory: Path, *, epoch: int = EPOCH, mode: int = 0o644) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    top = f"fetech-{VERSION}"
    payloads = {
        f"{top}/PKG-INFO": (
            f"Metadata-Version: 2.4\nName: fetech\nVersion: {VERSION}\n\n"
        ).encode(),
        f"{top}/pyproject.toml": (
            f'[project]\nname = "fetech"\nversion = "{VERSION}"\n'
        ).encode(),
        f"{top}/src/fetech/__init__.py": f'__version__ = "{VERSION}"\n'.encode(),
    }
    tar_payload = io.BytesIO()
    with tarfile.open(fileobj=tar_payload, mode="w", format=tarfile.PAX_FORMAT) as archive:
        for name, payload in payloads.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = mode
            info.mtime = epoch
            archive.addfile(info, io.BytesIO(payload))
    output = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=epoch) as compressed:
        compressed.write(tar_payload.getvalue())
    path = directory / SDIST_NAME
    path.write_bytes(output.getvalue())
    return path


def _pair(root: Path, **changes: object) -> tuple[Path, Path]:
    first = root / "first"
    second = root / "second"
    _wheel(first, **{key: value for key, value in changes.items() if key != "mode"})
    _wheel(second, **{key: value for key, value in changes.items() if key != "mode"})
    _sdist(first, **{key: value for key, value in changes.items() if key in {"epoch", "mode"}})
    _sdist(second, **{key: value for key, value in changes.items() if key in {"epoch", "mode"}})
    return first, second


def test_identical_builds_produce_deterministic_bounded_evidence(tmp_path: Path) -> None:
    first, second = _pair(tmp_path)

    evidence = verify_artifact_pair(
        first,
        second,
        version=VERSION,
        source_date_epoch=EPOCH,
    )

    assert [item["filename"] for item in evidence["artifacts"]] == [
        WHEEL_NAME,
        SDIST_NAME,
    ]
    assert evidence["archive_invariants"] == {
        "byte_for_byte_identical": True,
        "member_order_identical": True,
        "source_date_epoch_enforced": True,
        "wheel_record_verified": True,
    }
    receipt = {
        "schema": MODULE.RECEIPT_SCHEMA,
        "version": VERSION,
        **evidence,
    }
    assert render_receipt(receipt) == render_receipt(receipt)
    assert str(tmp_path) not in render_receipt(receipt)


def test_byte_difference_between_independent_builds_fails_closed(tmp_path: Path) -> None:
    first, second = _pair(tmp_path)
    with (second / WHEEL_NAME).open("ab") as stream:
        stream.write(b"nondeterministic")

    with pytest.raises(ReproducibleBuildError, match="not byte-for-byte identical"):
        verify_artifact_pair(
            first,
            second,
            version=VERSION,
            source_date_epoch=EPOCH,
        )


def test_archive_timestamps_must_match_source_date_epoch(tmp_path: Path) -> None:
    first, second = _pair(tmp_path, epoch=EPOCH + 2)

    with pytest.raises(ReproducibleBuildError, match="timestamp"):
        verify_artifact_pair(
            first,
            second,
            version=VERSION,
            source_date_epoch=EPOCH,
        )


def test_wheel_record_hashes_are_revalidated(tmp_path: Path) -> None:
    first, second = _pair(tmp_path, corrupt_record=True)

    with pytest.raises(ReproducibleBuildError, match="RECORD hash or size"):
        verify_artifact_pair(
            first,
            second,
            version=VERSION,
            source_date_epoch=EPOCH,
        )


def test_archive_member_permissions_reject_group_writable_files(tmp_path: Path) -> None:
    first, second = _pair(tmp_path, mode=0o664)

    with pytest.raises(ReproducibleBuildError, match="permissions"):
        verify_artifact_pair(
            first,
            second,
            version=VERSION,
            source_date_epoch=EPOCH,
        )


def test_wheel_rejects_explicit_link_or_special_member(tmp_path: Path) -> None:
    first, second = _pair(tmp_path, special_member=True)

    with pytest.raises(ReproducibleBuildError, match="special member"):
        verify_artifact_pair(
            first,
            second,
            version=VERSION,
            source_date_epoch=EPOCH,
        )


def _git(root: Path, *arguments: str) -> str:
    return subprocess.run(
        ("git", *arguments),
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def test_source_identity_rejects_a_dirty_or_untracked_tree(tmp_path: Path) -> None:
    (tmp_path / "tracked.txt").write_text("clean\n", encoding="utf-8")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "tests@example.invalid")
    _git(tmp_path, "config", "user.name", "Fetech tests")
    _git(tmp_path, "add", "tracked.txt")
    _git(tmp_path, "commit", "-q", "-m", "fixture")

    commit, epoch = MODULE._source_identity(tmp_path.resolve())
    assert len(commit) == 40
    assert epoch > 0

    (tmp_path / "untracked.txt").write_text("dirty\n", encoding="utf-8")
    with pytest.raises(ReproducibleBuildError, match="clean Git source tree"):
        MODULE._source_identity(tmp_path.resolve())


def test_beta_ci_enforces_complete_reproducible_build_evidence() -> None:
    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")

    assert "branches: [main, beta]" in workflow
    assert "Verify reproducible Beta distributions" in workflow
    assert (
        "uv run --no-sync python scripts/verify_reproducible_builds.py \\\n"
        '            --output "$RUNNER_TEMP/fetech-beta-reproducible-build.json"'
    ) in workflow
    assert "--skip-install-smoke" not in workflow
    assert "uses: actions/upload-artifact@v7" in workflow
    assert "path: ${{ runner.temp }}/fetech-beta-reproducible-build.json" in workflow
    assert "archive: false" in workflow
    assert "if-no-files-found: error" in workflow
