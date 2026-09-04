from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from fetech.logic.process import run_bounded

_ADVERSARIAL_PROBE = r"""
import ctypes
import json
import os
import resource
import socket
import subprocess
import sys

import fetech.worker_audit as worker_audit


def blocked(operation):
    try:
        operation()
    except PermissionError:
        return True
    return False


allowed_file, foreign_file, write_target, escape_link = sys.argv[1:]
allowed_dir = os.path.dirname(allowed_file)
foreign_dir = os.path.dirname(foreign_file)
allowed_fd = os.open(allowed_dir, os.O_RDONLY)
worker_audit.install_worker_audit_hook(
    additional_read_roots=(allowed_dir,)
)

with open(worker_audit.__file__, "rb") as runtime_source:
    runtime_read = bool(runtime_source.read(1))
with open(allowed_file, "rb") as reviewed_fixture:
    reviewed_read = reviewed_fixture.read() == b"reviewed"

checks = {
    "allowed_list_directory": sorted(os.listdir(allowed_dir)),
    "allowed_scan_directory": sorted(entry.name for entry in os.scandir(allowed_dir)),
    "ctypes": blocked(lambda: ctypes.CDLL(None)),
    "default_list_directory": blocked(lambda: os.listdir()),
    "empty_list_directory": blocked(lambda: os.listdir("")),
    "fd_list_directory": blocked(lambda: os.listdir(allowed_fd)),
    "foreign_list_directory": blocked(lambda: os.listdir(foreign_dir)),
    "foreign_scan_directory": blocked(lambda: os.scandir(foreign_dir)),
    "foreign_read": blocked(lambda: open(foreign_file, "rb")),
    "foreign_remove": blocked(lambda: os.remove(foreign_file)),
    "network": blocked(lambda: socket.socket()),
    "resource_change": blocked(
        lambda: resource.setrlimit(
            resource.RLIMIT_NOFILE,
            resource.getrlimit(resource.RLIMIT_NOFILE),
        )
    ),
    "runtime_read": runtime_read,
    "reviewed_read": reviewed_read,
    "symlink_escape_list_directory": blocked(lambda: os.listdir(escape_link)),
    "subprocess": blocked(
        lambda: subprocess.run(
            (sys.executable, "-c", "pass"),
            check=False,
        )
    ),
    "write_in_allowed_root": blocked(lambda: open(write_target, "wb")),
}
os.close(allowed_fd)
sys.stdout.write(json.dumps(checks, sort_keys=True))
"""

_NATIVE_INITIALIZATION_PROBE = r"""
import ctypes
import json
import mmap
import os
import sys
import tempfile

import fetech.worker_audit as worker_audit


def blocked(operation):
    try:
        operation()
    except PermissionError:
        return True
    return False


foreign_dir = sys.argv[1]
scratch = tempfile.mkdtemp(prefix="fetech-audit-native-")
os.chmod(scratch, 0o700)
guard = worker_audit.install_worker_audit_hook(
    allow_reviewed_native_initialization=True,
    private_scratch_root=scratch,
)
initialization_file = os.path.join(scratch, "initialization.bin")
with open(initialization_file, "wb") as stream:
    stream.write(b"reviewed")
native_loaded_during_initialization = ctypes.CDLL(None) is not None
foreign_write_during_initialization = blocked(
    lambda: open(os.path.join(foreign_dir, "escape.bin"), "wb")
)

guard.seal_native_initialization()
checks = {
    "cleanup_was_idempotent": False,
    "ctypes_after_seal": blocked(lambda: ctypes.CDLL(None)),
    "foreign_write_during_initialization": foreign_write_during_initialization,
    "mmap_after_seal": blocked(lambda: mmap.mmap(-1, 1)),
    "native_loaded_during_initialization": native_loaded_during_initialization,
    "scratch_write_after_seal": blocked(
        lambda: open(os.path.join(scratch, "after-seal.bin"), "wb")
    ),
}
guard.cleanup_private_scratch()
guard.cleanup_private_scratch()
checks["cleanup_was_idempotent"] = not os.path.exists(scratch)
sys.stdout.write(json.dumps(checks, sort_keys=True))
"""


@pytest.mark.asyncio
async def test_installed_worker_audit_hook_denies_python_side_effects(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    foreign = tmp_path / "foreign"
    allowed.mkdir()
    foreign.mkdir()
    allowed_file = allowed / "reviewed.bin"
    foreign_file = foreign / "private.txt"
    write_target = allowed / "must-not-exist.txt"
    escape_link = allowed / "escape"
    allowed_file.write_bytes(b"reviewed")
    foreign_file.write_text("sensitive", encoding="utf-8")
    escape_link.symlink_to(foreign, target_is_directory=True)

    result = await run_bounded(
        (
            sys.executable,
            "-c",
            _ADVERSARIAL_PROBE,
            str(allowed_file),
            str(foreign_file),
            str(write_target),
            str(escape_link),
        ),
        b"",
        timeout_seconds=5,
        memory_mb=256,
        maximum_output_bytes=8_192,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert json.loads(result.stdout) == {
        "allowed_list_directory": ["escape", "reviewed.bin"],
        "allowed_scan_directory": ["escape", "reviewed.bin"],
        "ctypes": True,
        "default_list_directory": True,
        "empty_list_directory": True,
        "fd_list_directory": True,
        "foreign_list_directory": True,
        "foreign_scan_directory": True,
        "foreign_read": True,
        "foreign_remove": True,
        "network": True,
        "resource_change": True,
        "reviewed_read": True,
        "runtime_read": True,
        "subprocess": True,
        "symlink_escape_list_directory": True,
        "write_in_allowed_root": True,
    }
    assert foreign_file.read_text(encoding="utf-8") == "sensitive"
    assert not write_target.exists()


@pytest.mark.asyncio
async def test_reviewed_native_initialization_is_one_shot_and_cleanup_is_exact(
    tmp_path: Path,
) -> None:
    foreign = tmp_path / "foreign"
    foreign.mkdir()

    result = await run_bounded(
        (
            sys.executable,
            "-c",
            _NATIVE_INITIALIZATION_PROBE,
            str(foreign),
        ),
        b"",
        timeout_seconds=5,
        memory_mb=256,
        maximum_output_bytes=8_192,
    )

    assert result.returncode == 0, result.stderr.decode("utf-8", errors="replace")
    assert json.loads(result.stdout) == {
        "cleanup_was_idempotent": True,
        "ctypes_after_seal": True,
        "foreign_write_during_initialization": True,
        "mmap_after_seal": True,
        "native_loaded_during_initialization": True,
        "scratch_write_after_seal": True,
    }
    assert list(foreign.iterdir()) == []
