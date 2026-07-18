from __future__ import annotations

import asyncio
import sys
from pathlib import Path
from typing import cast

import pytest

import fetech.logic.process as process_module
import fetech.worker_isolation as isolation_module
import fetech.worker_isolation_bootstrap as isolation_bootstrap
from fetech.logic.base import BackendExecutionError
from fetech.logic.process import run_bounded
from fetech.worker_isolation import (
    PreparedWorkerIsolation,
    WorkerIsolationMode,
    WorkerIsolationProfile,
    WorkerIsolationRequest,
    WorkerIsolationRuntime,
)
from fetech.yt_dlp import YTDLPMetadataWorker, YTDLPProviderError


def _required_prepared(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    profile: WorkerIsolationProfile = WorkerIsolationProfile.DOCUMENT_PARSER,
) -> tuple[PreparedWorkerIsolation, Path, Path, Path]:
    package_root = tmp_path / "package"
    python_root = tmp_path / "python"
    model_root = tmp_path / "models"
    data_dir = tmp_path / "data"
    cgroup_root = tmp_path / "cgroups"
    for path in (package_root, python_root, model_root, data_dir, cgroup_root):
        path.mkdir()
    monkeypatch.setattr(isolation_module.sys, "platform", "linux")
    monkeypatch.setattr(isolation_module.sys, "prefix", str(python_root))

    def create_cgroup(
        cls: type[object],
        root: Path,
        *,
        memory_max_bytes: int,
        pids_max: int,
        cpu_quota: int,
        cpu_period: int,
    ) -> object:
        del cls
        assert root == cgroup_root
        assert min(memory_max_bytes, pids_max, cpu_quota, cpu_period) > 0
        return isolation_module._CgroupLease(tmp_path / "worker-cgroup")

    monkeypatch.setattr(
        isolation_module,
        "_validate_trusted_executable",
        lambda _: None,
    )
    monkeypatch.setattr(
        isolation_module,
        "_validate_cgroup_root",
        lambda _: None,
    )
    monkeypatch.setattr(
        isolation_module,
        "_system_mount_arguments",
        lambda: ("--ro-bind", "/usr", "/usr"),
    )
    monkeypatch.setattr(
        isolation_module._CgroupLease,
        "create",
        classmethod(create_cgroup),
    )
    runtime = WorkerIsolationRuntime(
        mode=WorkerIsolationMode.REQUIRED,
        bubblewrap_executable=Path("/usr/bin/bwrap"),
        cgroup_root=cgroup_root,
        package_root=package_root,
        data_dir=data_dir,
    )
    prepared = runtime.prepare(
        runtime.request(profile, read_only_paths=(model_root,)),
        (sys.executable, "-c", "print('isolated')"),
        timeout_seconds=5,
        address_space_mb=512,
        maximum_file_bytes=4_096,
    )
    return prepared, package_root, model_root, data_dir


def _read_only_bindings(arguments: tuple[str, ...]) -> tuple[tuple[Path, Path], ...]:
    bindings: list[tuple[Path, Path]] = []
    for index, argument in enumerate(arguments):
        if argument == "--ro-bind":
            bindings.append((Path(arguments[index + 1]), Path(arguments[index + 2])))
    return tuple(bindings)


def test_required_profile_command_is_minimal_read_only_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    prepared, package_root, model_root, data_dir = _required_prepared(
        tmp_path,
        monkeypatch,
    )

    arguments = prepared.launch_arguments(status_fd=23)
    bindings = _read_only_bindings(arguments)
    sources = {source for source, _ in bindings}

    assert arguments[0] == "/usr/bin/bwrap"
    assert {
        "--unshare-user",
        "--unshare-pid",
        "--unshare-ipc",
        "--unshare-uts",
        "--unshare-cgroup",
        "--unshare-net",
        "--disable-userns",
        "--die-with-parent",
        "--new-session",
        "--clearenv",
    }.issubset(arguments)
    assert (
        arguments[arguments.index("--cap-drop")],
        arguments[arguments.index("--cap-drop") + 1],
    ) == ("--cap-drop", "ALL")
    assert (
        arguments[arguments.index("--json-status-fd")],
        arguments[arguments.index("--json-status-fd") + 1],
    ) == ("--json-status-fd", "23")
    assert Path("/") not in sources
    assert Path.home() not in sources
    assert data_dir not in sources
    assert not any(
        source == data_dir or data_dir.is_relative_to(source)
        for source in sources
    )
    assert {package_root, model_root, Path(sys.prefix), Path("/usr")}.issubset(
        sources
    )
    assert all(source == destination for source, destination in bindings)

    tmpfs = arguments.index("--tmpfs")
    assert arguments[tmpfs - 4 : tmpfs + 2] == (
        "--perms",
        "0700",
        "--size",
        str(128 * 1024 * 1024),
        "--tmpfs",
        "/tmp",
    )
    shared_memory_tmpfs = arguments.index("--tmpfs", tmpfs + 1)
    assert arguments[shared_memory_tmpfs - 4 : shared_memory_tmpfs + 2] == (
        "--perms",
        "1777",
        "--size",
        str(64 * 1024 * 1024),
        "--tmpfs",
        "/dev/shm",
    )
    assert arguments[arguments.index("--chdir") + 1] == "/tmp"
    assert arguments[-3:] == (sys.executable, "-c", "print('isolated')")


@pytest.mark.asyncio
async def test_development_profile_reports_explicit_unsandboxed_status() -> None:
    runtime = WorkerIsolationRuntime(mode=WorkerIsolationMode.DEVELOPMENT)

    result = await run_bounded(
        (sys.executable, "-c", "print('development')"),
        b"",
        timeout_seconds=3,
        memory_mb=256,
        maximum_output_bytes=1_024,
        isolation=runtime.request(WorkerIsolationProfile.ARCHIVE_PARSER),
    )

    assert result.returncode == 0
    assert result.stdout.strip() == b"development"
    assert result.containment == "development_unsandboxed"


@pytest.mark.asyncio
async def test_required_mode_fails_before_spawn_on_non_linux(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    package_root.mkdir()
    runtime = WorkerIsolationRuntime(
        mode=WorkerIsolationMode.REQUIRED,
        package_root=package_root,
    )
    spawned = False

    async def must_not_spawn(*args: object, **kwargs: object) -> None:
        del args, kwargs
        nonlocal spawned
        spawned = True

    monkeypatch.setattr(isolation_module.sys, "platform", "darwin")
    monkeypatch.setattr(
        process_module.asyncio,
        "create_subprocess_exec",
        must_not_spawn,
    )

    with pytest.raises(BackendExecutionError, match="only on Linux"):
        await run_bounded(
            (sys.executable, "-c", "raise AssertionError('must not run')"),
            b"",
            timeout_seconds=1,
            memory_mb=128,
            isolation=runtime.request(WorkerIsolationProfile.ARCHIVE_PARSER),
        )

    assert not spawned


@pytest.mark.asyncio
async def test_required_mode_fails_before_spawn_when_bubblewrap_is_missing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package_root = tmp_path / "package"
    cgroup_root = tmp_path / "cgroup"
    package_root.mkdir()
    cgroup_root.mkdir()
    runtime = WorkerIsolationRuntime(
        mode=WorkerIsolationMode.REQUIRED,
        bubblewrap_executable=tmp_path / "missing-bwrap",
        cgroup_root=cgroup_root,
        package_root=package_root,
    )
    spawned = False

    async def must_not_spawn(*args: object, **kwargs: object) -> None:
        del args, kwargs
        nonlocal spawned
        spawned = True

    monkeypatch.setattr(isolation_module.sys, "platform", "linux")
    monkeypatch.setattr(
        process_module.asyncio,
        "create_subprocess_exec",
        must_not_spawn,
    )

    with pytest.raises(BackendExecutionError, match="executable is unavailable"):
        await run_bounded(
            (sys.executable, "-c", "raise AssertionError('must not run')"),
            b"",
            timeout_seconds=1,
            memory_mb=128,
            isolation=runtime.request(WorkerIsolationProfile.ARCHIVE_PARSER),
        )

    assert not spawned


@pytest.mark.asyncio
async def test_ytdlp_network_profile_is_refused_in_required_mode_before_spawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = WorkerIsolationRuntime(mode=WorkerIsolationMode.REQUIRED)
    spawned = False

    def backend_is_valid(_: WorkerIsolationRuntime) -> None:
        return None

    async def must_not_spawn(*args: object, **kwargs: object) -> None:
        del args, kwargs
        nonlocal spawned
        spawned = True

    monkeypatch.setattr(
        WorkerIsolationRuntime,
        "validate_required_backend",
        backend_is_valid,
    )
    monkeypatch.setattr("fetech.yt_dlp._distribution_version", lambda _: "test")
    monkeypatch.setattr(
        process_module.asyncio,
        "create_subprocess_exec",
        must_not_spawn,
    )

    with pytest.raises(
        YTDLPProviderError,
        match="bounded yt-dlp metadata worker failed",
    ) as caught:
        await YTDLPMetadataWorker(isolation=runtime).metadata(
            "https://www.youtube.com/watch?v=fixture",
            timeout_seconds=1,
            maximum_output_bytes=1_024,
            maximum_network_bytes=1_024,
            maximum_redirects=1,
        )

    assert isinstance(caught.value.__cause__, BackendExecutionError)
    assert "requires brokered egress" in str(caught.value.__cause__)
    assert not spawned


def test_bubblewrap_status_requires_a_positive_integer_child_pid() -> None:
    process_module._validate_bubblewrap_status(b'{"child-pid":123}\n')


@pytest.mark.parametrize(
    "status",
    [
        b"",
        b"not-json",
        b"[]",
        b"{}",
        b'{"child-pid":true}',
        b'{"child-pid":"123"}',
        b'{"child-pid":0}',
        b'{"child-pid":-1}',
    ],
)
def test_bubblewrap_status_rejects_missing_or_invalid_child_pid(
    status: bytes,
) -> None:
    with pytest.raises(BackendExecutionError, match="Bubblewrap"):
        process_module._validate_bubblewrap_status(status)


def test_profile_table_is_total_positive_and_network_fail_closed() -> None:
    assert set(isolation_module._PROFILES) == set(WorkerIsolationProfile)
    for profile, limits in isolation_module._PROFILES.items():
        assert min(
            limits.scratch_bytes,
            limits.shared_memory_bytes,
            limits.pids_max,
            limits.cpu_quota,
            limits.cpu_period,
        ) > 0
        assert limits.shared_memory_bytes <= limits.scratch_bytes
        if limits.required_mode_supported:
            assert limits.network_denied
        else:
            assert profile is WorkerIsolationProfile.MEDIA_YTDLP_NETWORK


def test_browser_seccomp_profile_preserves_only_nested_namespace_setup() -> None:
    browser_denied = set(isolation_bootstrap._denied_syscalls("browser_offline"))
    parser_denied = set(isolation_bootstrap._denied_syscalls("archive_parser"))

    assert {"bpf", "keyctl", "process_vm_readv", "ptrace"} <= browser_denied
    assert {"mount", "setns", "unshare"} <= parser_denied
    assert {"mount", "setns", "unshare"}.isdisjoint(browser_denied)


def test_required_backend_enables_delegated_cgroup_controllers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "delegated"
    root.mkdir()
    (root / "cgroup.controllers").write_text("cpu io memory pids\n")
    subtree_control = root / "cgroup.subtree_control"
    subtree_control.write_text("cpu\n")
    writes: list[str] = []

    def enable_controllers(path: Path, value: str) -> None:
        assert path == subtree_control
        writes.append(value)
        path.write_text("cpu memory pids\n")

    monkeypatch.setattr(isolation_module, "_write_control", enable_controllers)

    isolation_module._validate_cgroup_root(root)

    assert writes == ["+memory +pids"]


def test_required_backend_rejects_missing_delegated_cgroup_controller(
    tmp_path: Path,
) -> None:
    root = tmp_path / "delegated"
    root.mkdir()
    (root / "cgroup.controllers").write_text("cpu memory\n")
    (root / "cgroup.subtree_control").write_text("cpu memory\n")

    with pytest.raises(BackendExecutionError, match="expose cpu, memory and pids"):
        isolation_module._validate_cgroup_root(root)


@pytest.mark.asyncio
async def test_cgroup_cleanup_failure_remains_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = tmp_path / "fetech-worker-fixture"
    path.mkdir()
    lease = isolation_module._CgroupLease(path)
    attempts = 0

    def write_control(_: Path, __: str) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise BackendExecutionError("forced cleanup failure")

    monkeypatch.setattr(isolation_module, "_write_control", write_control)
    monkeypatch.setattr(isolation_module, "_cgroup_populated", lambda _: False)

    with pytest.raises(BackendExecutionError, match="forced cleanup failure"):
        await lease.close()

    assert not lease.closed
    assert path.exists()

    await lease.close()

    assert lease.closed
    assert not path.exists()


@pytest.mark.asyncio
async def test_cleanup_failure_is_not_hidden_by_worker_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class FailingPrepared:
        enforced = True
        status = "linux_enforced"

        async def close(self) -> None:
            raise BackendExecutionError("forced cgroup cleanup failure")

    def prepare(
        runtime: WorkerIsolationRuntime,
        request: WorkerIsolationRequest,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
        address_space_mb: int,
        maximum_file_bytes: int,
    ) -> PreparedWorkerIsolation:
        del (
            runtime,
            request,
            arguments,
            timeout_seconds,
            address_space_mb,
            maximum_file_bytes,
        )
        return cast(PreparedWorkerIsolation, FailingPrepared())

    async def fail_spawn(*args: object, **kwargs: object) -> None:
        del args, kwargs
        raise BackendExecutionError("forced worker startup failure")

    monkeypatch.setattr(WorkerIsolationRuntime, "prepare", prepare)
    monkeypatch.setattr(process_module, "_spawn_posix_limited", fail_spawn)
    runtime = WorkerIsolationRuntime()

    with pytest.raises(
        BackendExecutionError,
        match="forced cgroup cleanup failure",
    ) as caught:
        await run_bounded(
            (sys.executable, "-c", "raise AssertionError"),
            b"",
            timeout_seconds=1,
            memory_mb=128,
            isolation=runtime.request(WorkerIsolationProfile.ARCHIVE_PARSER),
        )

    assert isinstance(caught.value.__cause__, BackendExecutionError)
    assert "forced worker startup failure" in str(caught.value.__cause__)


@pytest.mark.asyncio
async def test_cancellation_cannot_abandon_cgroup_cleanup() -> None:
    started = asyncio.Event()
    release = asyncio.Event()
    closed = False

    class BlockingPrepared:
        async def close(self) -> None:
            nonlocal closed
            started.set()
            await release.wait()
            closed = True

    task = asyncio.create_task(
        process_module._close_prepared_without_abandoning(
            cast(PreparedWorkerIsolation, BlockingPrepared())
        )
    )
    await started.wait()
    task.cancel()
    await asyncio.sleep(0)

    assert not task.done()
    assert not closed

    release.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert closed


def test_request_schema_accepts_only_reviewed_paths_and_environment(
    tmp_path: Path,
) -> None:
    runtime = WorkerIsolationRuntime()
    reviewed = tmp_path / "reviewed"
    reviewed.mkdir()

    request = runtime.request(
        WorkerIsolationProfile.BROWSER_OFFLINE,
        read_only_paths=(reviewed,),
        environment=(("PLAYWRIGHT_BROWSERS_PATH", str(reviewed)),),
    )

    assert request.profile is WorkerIsolationProfile.BROWSER_OFFLINE
    assert request.read_only_paths == (reviewed,)
    assert request.environment == (("PLAYWRIGHT_BROWSERS_PATH", str(reviewed)),)


def test_request_schema_rejects_unknown_profile() -> None:
    runtime = WorkerIsolationRuntime()

    with pytest.raises(ValueError, match="unknown worker isolation profile"):
        WorkerIsolationRequest(
            runtime=runtime,
            profile=cast(WorkerIsolationProfile, "unknown"),
        )


def test_request_schema_rejects_unsafe_read_only_roots(
    tmp_path: Path,
) -> None:
    runtime = WorkerIsolationRuntime()
    reviewed = tmp_path / "reviewed"
    reviewed.mkdir()
    linked = tmp_path / "linked"
    linked.symlink_to(reviewed, target_is_directory=True)
    missing = (tmp_path / "missing").absolute()

    invalid_roots = (
        cast(tuple[Path, ...], (str(reviewed),)),
        (Path("relative"),),
        (missing,),
        (linked,),
        (Path("/"),),
        (reviewed, reviewed),
    )
    for roots in invalid_roots:
        with pytest.raises((TypeError, ValueError)):
            runtime.request(
                WorkerIsolationProfile.DOCUMENT_PARSER,
                read_only_paths=roots,
            )


@pytest.mark.parametrize(
    "environment",
    [
        (("UNREVIEWED", "/tmp"),),
        (("PLAYWRIGHT_BROWSERS_PATH", ""),),
        (("PLAYWRIGHT_BROWSERS_PATH", "bad\x00value"),),
        (
            ("PLAYWRIGHT_BROWSERS_PATH", "/first"),
            ("PLAYWRIGHT_BROWSERS_PATH", "/second"),
        ),
    ],
)
def test_request_schema_rejects_unsafe_environment(
    environment: tuple[tuple[str, str], ...],
) -> None:
    runtime = WorkerIsolationRuntime()

    with pytest.raises(ValueError, match="environment is invalid"):
        runtime.request(
            WorkerIsolationProfile.BROWSER_OFFLINE,
            environment=environment,
        )


def test_request_schema_rejects_environment_path_outside_read_only_roots(
    tmp_path: Path,
) -> None:
    runtime = WorkerIsolationRuntime()
    reviewed = tmp_path / "reviewed"
    other = tmp_path / "other"
    reviewed.mkdir()
    other.mkdir()

    with pytest.raises(ValueError, match="must match a read-only root"):
        runtime.request(
            WorkerIsolationProfile.BROWSER_OFFLINE,
            read_only_paths=(reviewed,),
            environment=(("PLAYWRIGHT_BROWSERS_PATH", str(other)),),
        )
