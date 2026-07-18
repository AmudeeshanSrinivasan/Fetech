from __future__ import annotations

import errno
import json
import os
import socket
import sys
from pathlib import Path

import pytest

from fetech.browser_render import BrowserRenderWorker
from fetech.logic.process import run_bounded
from fetech.worker_isolation import (
    WorkerIsolationMode,
    WorkerIsolationProfile,
    WorkerIsolationRuntime,
)

pytestmark = [
    pytest.mark.linux_containment,
    pytest.mark.skipif(
        not sys.platform.startswith("linux"),
        reason="Linux kernel containment is required",
    ),
]


def _required_runtime() -> WorkerIsolationRuntime:
    runtime = WorkerIsolationRuntime.from_environment()
    assert runtime.mode is WorkerIsolationMode.REQUIRED
    runtime.validate_required_backend()
    return runtime


@pytest.mark.asyncio
async def test_linux_parser_profile_enforces_mount_network_scratch_and_seccomp(
    tmp_path: Path,
) -> None:
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    fixture = allowed / "fixture.txt"
    fixture.write_text("reviewed fixture", encoding="utf-8")
    hidden = tmp_path / "hidden-secret.txt"
    hidden.write_text("must stay outside", encoding="utf-8")

    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen()
    port = listener.getsockname()[1]
    probe = """
import ctypes, errno, json, os, pathlib, socket, sys
allowed = pathlib.Path(sys.argv[1])
hidden = pathlib.Path(sys.argv[2])
result = {"read": allowed.read_text(), "hidden": hidden.exists()}
try:
    allowed.write_text("changed")
except OSError:
    result["read_only"] = True
else:
    result["read_only"] = False
scratch = pathlib.Path("/tmp/probe")
scratch.write_text("private scratch")
result["scratch"] = scratch.read_text()
client = socket.socket()
client.settimeout(0.2)
try:
    client.connect(("127.0.0.1", int(sys.argv[3])))
except OSError:
    result["network_denied"] = True
else:
    result["network_denied"] = False
libc = ctypes.CDLL(None, use_errno=True)
mount_result = libc.mount(b"none", b"/tmp", b"tmpfs", 0, None)
result["mount_denied"] = mount_result == -1 and ctypes.get_errno() == errno.EPERM
class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]
source = ctypes.create_string_buffer(b"x")
destination = ctypes.create_string_buffer(1)
local = IOVec(ctypes.addressof(destination), 1)
remote = IOVec(ctypes.addressof(source), 1)
libc.process_vm_readv.argtypes = [
    ctypes.c_int,
    ctypes.POINTER(IOVec),
    ctypes.c_ulong,
    ctypes.POINTER(IOVec),
    ctypes.c_ulong,
    ctypes.c_ulong,
]
libc.process_vm_readv.restype = ctypes.c_ssize_t
ctypes.set_errno(0)
read_result = libc.process_vm_readv(
    os.getpid(), ctypes.byref(local), 1, ctypes.byref(remote), 1, 0
)
result["seccomp_denied"] = (
    read_result == -1 and ctypes.get_errno() == errno.EPERM
)
print(json.dumps(result, sort_keys=True))
"""
    try:
        result = await run_bounded(
            (
                sys.executable,
                "-I",
                "-B",
                "-c",
                probe,
                str(fixture),
                str(hidden),
                str(port),
            ),
            b"",
            timeout_seconds=10,
            memory_mb=768,
            maximum_output_bytes=8_192,
            maximum_file_bytes=2_000_000,
            isolation=_required_runtime().request(
                WorkerIsolationProfile.ARCHIVE_PARSER,
                read_only_paths=(allowed,),
            ),
        )
    finally:
        listener.close()

    assert result.returncode == 0
    assert result.containment == "linux_enforced"
    assert json.loads(result.stdout) == {
        "hidden": False,
        "mount_denied": True,
        "network_denied": True,
        "read": "reviewed fixture",
        "read_only": True,
        "seccomp_denied": True,
        "scratch": "private scratch",
    }
    assert fixture.read_text(encoding="utf-8") == "reviewed fixture"
    assert hidden.read_text(encoding="utf-8") == "must stay outside"


@pytest.mark.asyncio
async def test_linux_parser_scratch_has_an_aggregate_tmpfs_ceiling() -> None:
    probe = """
import errno, json, pathlib
chunk = b"x" * (1024 * 1024)
written = 0
try:
    for index in range(96):
        pathlib.Path(f"/tmp/{index}").write_bytes(chunk)
        written += len(chunk)
except OSError as exc:
    print(json.dumps({"written": written, "errno": exc.errno}))
else:
    raise SystemExit(3)
"""
    result = await run_bounded(
        (sys.executable, "-I", "-B", "-c", probe),
        b"",
        timeout_seconds=10,
        memory_mb=768,
        maximum_output_bytes=1_024,
        maximum_file_bytes=2 * 1024 * 1024,
        isolation=_required_runtime().request(
            WorkerIsolationProfile.ARCHIVE_PARSER
        ),
    )

    assert result.returncode == 0
    outcome = json.loads(result.stdout)
    assert outcome["errno"] == errno.ENOSPC
    assert 48 * 1024 * 1024 <= outcome["written"] <= 64 * 1024 * 1024


@pytest.mark.asyncio
async def test_linux_parser_cgroup_pid_ceiling_and_cleanup() -> None:
    root = _required_runtime().cgroup_root
    assert root is not None
    before = set(root.glob("fetech-worker-*"))
    probe = """
import subprocess, sys
children = []
try:
    for _ in range(64):
        children.append(subprocess.Popen([sys.executable, "-c", "import time;time.sleep(10)"]))
except OSError:
    print(len(children))
else:
    raise SystemExit(3)
finally:
    for child in children:
        child.kill()
"""
    result = await run_bounded(
        (sys.executable, "-I", "-B", "-c", probe),
        b"",
        timeout_seconds=10,
        memory_mb=768,
        maximum_output_bytes=1_024,
        isolation=_required_runtime().request(
            WorkerIsolationProfile.ARCHIVE_PARSER
        ),
    )

    assert result.returncode == 0
    assert 4 <= int(result.stdout) < 16
    assert set(root.glob("fetech-worker-*")) == before


@pytest.mark.asyncio
async def test_linux_parser_cgroup_memory_ceiling_is_not_browser_address_space() -> None:
    probe = """
import os
blocks = []
os.write(1, b"allocation-started\\n")
try:
    for _ in range(20):
        blocks.append(bytearray(32 * 1024 * 1024))
except MemoryError:
    os.write(1, b"rlimit-as\\n")
else:
    os.write(1, b"unbounded\\n")
"""
    result = await run_bounded(
        (sys.executable, "-I", "-B", "-c", probe),
        b"",
        timeout_seconds=10,
        # This is deliberately above the archive profile's 512 MiB aggregate
        # resident-memory ceiling.
        memory_mb=1_024,
        maximum_output_bytes=1_024,
        isolation=_required_runtime().request(
            WorkerIsolationProfile.ARCHIVE_PARSER
        ),
    )

    assert result.returncode != 0
    assert result.stdout == b"allocation-started\n"
    assert result.containment == "linux_enforced"


@pytest.mark.asyncio
async def test_linux_parser_cgroup_controls_are_exact_and_cleanup() -> None:
    runtime = _required_runtime()
    prepared = runtime.prepare(
        runtime.request(WorkerIsolationProfile.ARCHIVE_PARSER),
        (sys.executable, "-c", "raise AssertionError('must not execute')"),
        timeout_seconds=5,
        address_space_mb=768,
        maximum_file_bytes=1_024,
    )
    assert prepared.cgroup is not None
    path = prepared.cgroup.path
    try:
        assert (path / "memory.max").read_text().strip() == str(512 * 1024 * 1024)
        assert (path / "pids.max").read_text().strip() == "16"
        assert (path / "cpu.max").read_text().strip() == "100000 100000"
        if (path / "memory.swap.max").exists():
            assert (path / "memory.swap.max").read_text().strip() == "0"
    finally:
        await prepared.close()

    assert not path.exists()


@pytest.mark.asyncio
async def test_linux_required_browser_profile_launches_real_chromium() -> None:
    artifacts = Path(os.environ["FETECH_BROWSER_ARTIFACTS_PATH"]).resolve(strict=True)
    result = await BrowserRenderWorker(
        isolation=_required_runtime(),
        browser_artifacts_path=artifacts,
    ).render(
        """
        <main id="ready">Loading</main>
        <script>
          document.querySelector("main").textContent =
            "Chromium executed inside the required Fetech worker boundary.";
        </script>
        """,
        target="https://example.com/containment-fixture",
        user_agent="Fetech/containment-test",
        timeout_seconds=20,
        maximum_bytes=5_000_000,
        operations=frozenset({"visible_text", "wait_for_selector"}),
        wait_selector="#ready",
        scroll_steps=1,
    )

    assert "inside the required Fetech worker boundary" in result.visible_text
