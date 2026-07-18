"""Hermetic verification for the exact v0.4 distribution assets."""

from __future__ import annotations

import base64
import csv
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
SCRIPT = ROOT / "scripts" / "verify_v04_release_artifacts.py"
SPEC = importlib.util.spec_from_file_location("fetech_release_artifacts", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

ArtifactVerificationError = MODULE.ArtifactVerificationError
CHECKSUMS_FILENAME = MODULE.CHECKSUMS_FILENAME
SDIST_FILENAME = MODULE.SDIST_FILENAME
WHEEL_FILENAME = MODULE.WHEEL_FILENAME
render_receipt = MODULE.render_receipt
verify_release_artifacts = MODULE.verify_release_artifacts


def _run(root: Path, *arguments: str) -> str:
    process = subprocess.run(
        arguments,
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    )
    return process.stdout.strip()


def _project(root: Path) -> str:
    files = {
        ".gitignore": "dist/\n",
        "LICENSE": "Apache-2.0 fixture\n",
        "capabilities/manifest.yaml": "categories: []\n",
        "src/fetech/__init__.py": '__version__ = "0.4.0a0"\n',
        "src/fetech/runtime.py": "VALUE = 42\n",
        "pyproject.toml": """\
[build-system]
requires = ["hatchling>=1.25"]
build-backend = "hatchling.build"

[project]
name = "fetech"
version = "0.4.0a0"
license = { file = "LICENSE" }

[project.scripts]
fetech = "fetech.cli:app"
fetech-daemon = "fetech.daemon:main"
fetech-context-mcp = "fetech.mcp_server:main"

[tool.hatch.build.targets.sdist]
include = ["/src", "/capabilities", "/pyproject.toml", "/uv.lock", "/LICENSE"]
""",
        "uv.lock": """\
version = 1

[[package]]
name = "fetech"
version = "0.4.0a0"
""",
    }
    for relative, content in files.items():
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
    _run(root, "git", "init", "-q")
    _run(root, "git", "config", "user.email", "tests@example.invalid")
    _run(root, "git", "config", "user.name", "Fetech tests")
    _run(root, "git", "add", ".")
    _run(root, "git", "commit", "-q", "-m", "fixture")
    return _run(root, "git", "rev-parse", "HEAD")


def _record(payloads: dict[str, bytes], record_name: str) -> bytes:
    output = io.StringIO()
    writer = csv.writer(output, lineterminator="\n")
    for name, payload in payloads.items():
        digest = base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()
        writer.writerow((name, f"sha256={digest}", str(len(payload))))
    writer.writerow((record_name, "", ""))
    return output.getvalue().encode()


def _metadata(*extra_headers: str) -> bytes:
    return (
        "\n".join(
            (
                "Metadata-Version: 2.4",
                "Name: fetech",
                "Version: 0.4.0a0",
                "License-File: LICENSE",
                *extra_headers,
                "",
                "",
            )
        )
    ).encode()


def _wheel(
    root: Path,
    *,
    corrupt_record: bool = False,
    mutate_source: bool = False,
    metadata_headers: tuple[str, ...] = (),
    wheel_headers: tuple[str, ...] = (),
    special_member_mode: bool = False,
) -> Path:
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    wheel = dist / WHEEL_FILENAME
    dist_info = "fetech-0.4.0a0.dist-info"
    source = (root / "src/fetech/__init__.py").read_bytes()
    if mutate_source:
        source += b"# stale wheel\n"
    payloads = {
        "fetech/__init__.py": source,
        "fetech/runtime.py": (root / "src/fetech/runtime.py").read_bytes(),
        "fetech/data/manifest.yaml": (root / "capabilities/manifest.yaml").read_bytes(),
        f"{dist_info}/METADATA": _metadata(*metadata_headers),
        f"{dist_info}/WHEEL": (
            b"Wheel-Version: 1.0\nGenerator: fixture\n"
            b"Root-Is-Purelib: true\nTag: py3-none-any\n"
            + "".join(f"{header}\n" for header in wheel_headers).encode()
        ),
        f"{dist_info}/entry_points.txt": (
            b"[console_scripts]\n"
            b"fetech = fetech.cli:app\n"
            b"fetech-daemon = fetech.daemon:main\n"
            b"fetech-context-mcp = fetech.mcp_server:main\n"
        ),
        f"{dist_info}/licenses/LICENSE": (root / "LICENSE").read_bytes(),
    }
    record_name = f"{dist_info}/RECORD"
    payloads[record_name] = _record(payloads, record_name)
    if corrupt_record:
        payloads[record_name] = payloads[record_name].replace(
            b"sha256=",
            b"sha256=invalid",
            1,
        )
    with zipfile.ZipFile(wheel, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for name, payload in payloads.items():
            if special_member_mode and name == "fetech/runtime.py":
                info = zipfile.ZipInfo(name)
                info.external_attr = (stat.S_IFIFO | 0o644) << 16
                archive.writestr(info, payload)
            else:
                archive.writestr(name, payload)
    return wheel


def _sdist(
    root: Path,
    *,
    extra_member: str | None = None,
    metadata_headers: tuple[str, ...] = (),
) -> Path:
    dist = root / "dist"
    dist.mkdir(exist_ok=True)
    sdist = dist / SDIST_FILENAME
    top = "fetech-0.4.0a0"
    included = (
        ".gitignore",
        "LICENSE",
        "capabilities/manifest.yaml",
        "pyproject.toml",
        "src/fetech/__init__.py",
        "src/fetech/runtime.py",
        "uv.lock",
    )
    payloads = {f"{top}/{relative}": (root / relative).read_bytes() for relative in included}
    payloads[f"{top}/PKG-INFO"] = _metadata(*metadata_headers)
    if extra_member is not None:
        payloads[extra_member] = b"unexpected"
    with tarfile.open(sdist, "w:gz") as archive:
        for name, payload in payloads.items():
            info = tarfile.TarInfo(name)
            info.size = len(payload)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(payload))
    return sdist


def _checksums(root: Path, wheel: Path, sdist: Path) -> Path:
    checksums = root / "dist" / CHECKSUMS_FILENAME
    checksums.write_text(
        "".join(
            (
                f"{hashlib.sha256(wheel.read_bytes()).hexdigest()}  {wheel.name}\n",
                f"{hashlib.sha256(sdist.read_bytes()).hexdigest()}  {sdist.name}\n",
            )
        ),
        encoding="utf-8",
    )
    return checksums


def _assets(root: Path) -> tuple[Path, Path, Path, str]:
    commit = _project(root)
    wheel = _wheel(root)
    sdist = _sdist(root)
    return wheel, sdist, _checksums(root, wheel, sdist), commit


def test_exact_artifacts_produce_a_deterministic_sanitized_receipt(
    tmp_path: Path,
) -> None:
    wheel, sdist, checksums, commit = _assets(tmp_path)

    receipt = verify_release_artifacts(
        tmp_path,
        wheel_path=wheel,
        sdist_path=sdist,
        checksums_path=checksums,
    )
    rendered = render_receipt(receipt)

    assert receipt["source_commit"] == commit
    assert receipt["version"] == "0.4.0a0"
    assert [item["filename"] for item in receipt["artifacts"]] == [
        WHEEL_FILENAME,
        SDIST_FILENAME,
    ]
    assert rendered == render_receipt(
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )
    )
    assert str(tmp_path) not in rendered
    relative = verify_release_artifacts(
        tmp_path,
        wheel_path=Path("dist") / wheel.name,
        sdist_path=Path("dist") / sdist.name,
        checksums_path=Path("dist") / checksums.name,
    )
    assert relative == receipt


def test_checksum_manifest_is_exact_and_recomputed(tmp_path: Path) -> None:
    wheel, sdist, checksums, _ = _assets(tmp_path)
    checksums.write_text(
        f"{'0' * 64}  {wheel.name}\n{hashlib.sha256(sdist.read_bytes()).hexdigest()}  {sdist.name}\n",
        encoding="utf-8",
    )

    with pytest.raises(ArtifactVerificationError, match="canonical exact"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_wheel_bytes_must_match_the_clean_commit(tmp_path: Path) -> None:
    _project(tmp_path)
    wheel = _wheel(tmp_path, mutate_source=True)
    sdist = _sdist(tmp_path)
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="clean source tree"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_wheel_rejects_corrupt_record_and_duplicate_members(tmp_path: Path) -> None:
    _project(tmp_path)
    wheel = _wheel(tmp_path, corrupt_record=True)
    sdist = _sdist(tmp_path)
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="RECORD member digest"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )

    wheel = _wheel(tmp_path)
    with (
        pytest.warns(UserWarning, match="Duplicate name"),
        zipfile.ZipFile(wheel, "a") as archive,
    ):
        archive.writestr("fetech/runtime.py", b"duplicate")
    checksums = _checksums(tmp_path, wheel, sdist)
    with pytest.raises(ArtifactVerificationError, match="duplicated"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_sdist_rejects_members_outside_the_release_root(tmp_path: Path) -> None:
    _project(tmp_path)
    wheel = _wheel(tmp_path)
    sdist = _sdist(tmp_path, extra_member="../escape")
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="unsafe member path"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_sdist_rejects_untracked_content_inside_the_release_root(
    tmp_path: Path,
) -> None:
    _project(tmp_path)
    wheel = _wheel(tmp_path)
    sdist = _sdist(
        tmp_path,
        extra_member="fetech-0.4.0a0/runtime-data/private.bin",
    )
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="exact tracked"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_release_verification_refuses_a_dirty_source_tree(tmp_path: Path) -> None:
    wheel, sdist, checksums, _ = _assets(tmp_path)
    (tmp_path / "src/fetech/runtime.py").write_text("VALUE = 99\n", encoding="utf-8")

    with pytest.raises(ArtifactVerificationError, match="clean Git source tree"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_release_artifacts_must_not_be_symlinks(tmp_path: Path) -> None:
    wheel, sdist, checksums, _ = _assets(tmp_path)
    linked = tmp_path / "linked" / WHEEL_FILENAME
    linked.parent.mkdir()
    linked.symlink_to(wheel)

    with pytest.raises(ArtifactVerificationError, match="must not be a symlink"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=linked,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_dependency_metadata_must_match_pyproject(tmp_path: Path) -> None:
    _project(tmp_path)
    wheel = _wheel(
        tmp_path,
        metadata_headers=("Requires-Dist: malicious-package>=1",),
    )
    sdist = _sdist(tmp_path)
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="dependency metadata"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_wheel_and_sdist_core_metadata_must_be_identical(tmp_path: Path) -> None:
    _project(tmp_path)
    wheel = _wheel(tmp_path)
    sdist = _sdist(tmp_path, metadata_headers=("Author: injected",))
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="core metadata differ"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


@pytest.mark.parametrize(
    "alias",
    (
        "fetech-0.4.0a0/src//fetech/runtime.py",
        "fetech-0.4.0a0/src/./fetech/runtime.py",
    ),
)
def test_sdist_rejects_raw_path_aliases(tmp_path: Path, alias: str) -> None:
    _project(tmp_path)
    wheel = _wheel(tmp_path)
    sdist = _sdist(tmp_path, extra_member=alias)
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="unsafe member path"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_committed_blobs_override_assume_unchanged_worktree_bytes(
    tmp_path: Path,
) -> None:
    _project(tmp_path)
    _run(
        tmp_path,
        "git",
        "update-index",
        "--assume-unchanged",
        "src/fetech/runtime.py",
    )
    (tmp_path / "src/fetech/runtime.py").write_text("VALUE = 99\n", encoding="utf-8")
    assert _run(tmp_path, "git", "status", "--porcelain") == ""
    wheel = _wheel(tmp_path)
    sdist = _sdist(tmp_path)
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="clean source tree"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


@pytest.mark.parametrize(
    ("wheel_headers", "message"),
    (
        (("Tag: cp312-cp312-any",), "exact py3-none-any"),
        (("Root-Is-Purelib: true",), "unique Root-Is-Purelib"),
    ),
)
def test_wheel_metadata_must_be_unique_and_exact(
    tmp_path: Path,
    wheel_headers: tuple[str, ...],
    message: str,
) -> None:
    _project(tmp_path)
    wheel = _wheel(tmp_path, wheel_headers=wheel_headers)
    sdist = _sdist(tmp_path)
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match=message):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_wheel_rejects_special_file_mode(tmp_path: Path) -> None:
    _project(tmp_path)
    wheel = _wheel(tmp_path, special_member_mode=True)
    sdist = _sdist(tmp_path)
    checksums = _checksums(tmp_path, wheel, sdist)

    with pytest.raises(ArtifactVerificationError, match="non-regular"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )


def test_artifact_mutation_during_verification_is_detected(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    wheel, sdist, checksums, _ = _assets(tmp_path)
    verify_wheel = MODULE._verify_wheel

    def mutate_original(*args: object, **kwargs: object) -> bytes:
        metadata = verify_wheel(*args, **kwargs)
        wheel.write_bytes(wheel.read_bytes() + b"changed")
        return metadata

    monkeypatch.setattr(MODULE, "_verify_wheel", mutate_original)
    with pytest.raises(ArtifactVerificationError, match="changed during verification"):
        verify_release_artifacts(
            tmp_path,
            wheel_path=wheel,
            sdist_path=sdist,
            checksums_path=checksums,
        )
