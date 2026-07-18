"""Fail-closed Linux containment profiles for hostile-data workers.

The ordinary development backend intentionally preserves the portable
``run_bounded`` behaviour.  Required mode is Linux-only and composes:

* an operator-delegated cgroup-v2 subtree for aggregate CPU, memory and PID
  ceilings;
* Bubblewrap user, mount, PID, IPC, UTS, cgroup and (for parser profiles)
  network namespaces;
* a minimal read-only filesystem assembled from reviewed runtime roots;
* bounded private tmpfs mounts; and
* an inner bootstrap that installs strict rlimits and a reviewed seccomp
  denylist before the target worker can read its input.

No required-mode failure is retried through the development backend.
"""

from __future__ import annotations

import asyncio
import os
import stat
import sys
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Final
from uuid import uuid4

from fetech.logic.base import BackendExecutionError

_CGROUP_CONTROLLERS: Final = frozenset({"cpu", "memory", "pids"})
_DEVELOPMENT_STATUS: Final = "development_unsandboxed"
_ENFORCED_STATUS: Final = "linux_enforced"
_SYSTEM_ROOTS: Final = (Path("/usr"), Path("/bin"), Path("/sbin"), Path("/lib"), Path("/lib64"))
_SAFE_INNER_ENVIRONMENT: Final = frozenset({"PLAYWRIGHT_BROWSERS_PATH"})
_CGROUP_PREFIX: Final = "fetech-worker-"


class WorkerIsolationMode(StrEnum):
    """Runtime containment policy."""

    DEVELOPMENT = "development"
    REQUIRED = "required"


class WorkerIsolationProfile(StrEnum):
    """Canonical immutable worker profiles."""

    DOCUMENT_PARSER = "document_parser"
    ARCHIVE_PARSER = "archive_parser"
    IMAGE_DECODER = "image_decoder"
    BROWSER_OFFLINE = "browser_offline"
    MEDIA_NATIVE_OFFLINE = "media_native_offline"
    MEDIA_YTDLP_NETWORK = "media_ytdlp_network"


@dataclass(frozen=True, slots=True)
class _ProfileLimits:
    network_denied: bool
    scratch_bytes: int
    shared_memory_bytes: int
    pids_max: int
    resident_memory_mb: int | None
    cpu_quota: int
    cpu_period: int = 100_000
    disable_nested_user_namespaces: bool = True
    required_mode_supported: bool = True


_PROFILES: Final = {
    WorkerIsolationProfile.DOCUMENT_PARSER: _ProfileLimits(
        network_denied=True,
        scratch_bytes=128 * 1024 * 1024,
        shared_memory_bytes=64 * 1024 * 1024,
        pids_max=32,
        resident_memory_mb=None,
        cpu_quota=100_000,
    ),
    WorkerIsolationProfile.ARCHIVE_PARSER: _ProfileLimits(
        network_denied=True,
        scratch_bytes=64 * 1024 * 1024,
        shared_memory_bytes=16 * 1024 * 1024,
        pids_max=16,
        resident_memory_mb=512,
        cpu_quota=100_000,
    ),
    WorkerIsolationProfile.IMAGE_DECODER: _ProfileLimits(
        network_denied=True,
        scratch_bytes=64 * 1024 * 1024,
        shared_memory_bytes=32 * 1024 * 1024,
        pids_max=16,
        resident_memory_mb=512,
        cpu_quota=100_000,
    ),
    WorkerIsolationProfile.BROWSER_OFFLINE: _ProfileLimits(
        network_denied=True,
        scratch_bytes=1024 * 1024 * 1024,
        shared_memory_bytes=512 * 1024 * 1024,
        pids_max=256,
        # Chromium/V8 reserves a very large virtual address range.  Keep this
        # aggregate resident-memory ceiling separate from RLIMIT_AS.
        resident_memory_mb=4_096,
        cpu_quota=200_000,
        disable_nested_user_namespaces=False,
    ),
    WorkerIsolationProfile.MEDIA_NATIVE_OFFLINE: _ProfileLimits(
        network_denied=True,
        scratch_bytes=128 * 1024 * 1024,
        shared_memory_bytes=32 * 1024 * 1024,
        pids_max=32,
        resident_memory_mb=1_024,
        cpu_quota=100_000,
    ),
    WorkerIsolationProfile.MEDIA_YTDLP_NETWORK: _ProfileLimits(
        network_denied=False,
        scratch_bytes=128 * 1024 * 1024,
        shared_memory_bytes=32 * 1024 * 1024,
        pids_max=32,
        resident_memory_mb=768,
        cpu_quota=100_000,
        # A shared host network would provide unrestricted egress.  Required
        # mode must wait for the separately supervised allowlisting broker.
        required_mode_supported=False,
    ),
}


@dataclass(frozen=True, slots=True)
class WorkerIsolationRequest:
    """One immutable profile selection plus narrowly scoped read-only inputs."""

    runtime: WorkerIsolationRuntime = field(compare=False, repr=False)
    profile: WorkerIsolationProfile
    read_only_paths: tuple[Path, ...] = ()
    environment: tuple[tuple[str, str], ...] = ()

    def __post_init__(self) -> None:
        if self.profile not in _PROFILES:
            raise ValueError("unknown worker isolation profile")
        _validate_read_only_paths(self.read_only_paths)
        resolved_roots = {
            path.resolve(strict=True) for path in self.read_only_paths
        }
        names: set[str] = set()
        for name, value in self.environment:
            if (
                name not in _SAFE_INNER_ENVIRONMENT
                or name in names
                or not value
                or "\x00" in value
            ):
                raise ValueError("worker isolation environment is invalid")
            names.add(name)
        for _, value in self.environment:
            environment_path = Path(value)
            try:
                resolved_environment_path = environment_path.resolve(strict=True)
            except OSError as exc:
                raise ValueError(
                    "worker isolation environment path is unavailable"
                ) from exc
            if (
                not environment_path.is_absolute()
                or resolved_environment_path not in resolved_roots
            ):
                raise ValueError(
                    "worker isolation environment path must match a read-only root"
                )


@dataclass(frozen=True, slots=True)
class WorkerIsolationRuntime:
    """Trusted configuration shared by built-in worker launchers."""

    mode: WorkerIsolationMode = WorkerIsolationMode.DEVELOPMENT
    bubblewrap_executable: Path = Path("/usr/bin/bwrap")
    cgroup_root: Path | None = None
    package_root: Path = field(
        default_factory=lambda: Path(__file__).resolve().parents[1]
    )
    data_dir: Path | None = None

    @classmethod
    def from_environment(cls) -> WorkerIsolationRuntime:
        raw_mode = os.environ.get(
            "FETECH_WORKER_ISOLATION_MODE",
            WorkerIsolationMode.DEVELOPMENT.value,
        ).lower()
        try:
            mode = WorkerIsolationMode(raw_mode)
        except ValueError as exc:
            raise ValueError(
                "FETECH_WORKER_ISOLATION_MODE must be development or required"
            ) from exc
        raw_cgroup_root = os.environ.get("FETECH_WORKER_CGROUP_ROOT")
        raw_data_dir = os.environ.get("FETECH_DATA_DIR")
        return cls(
            mode=mode,
            bubblewrap_executable=Path(
                os.environ.get(
                    "FETECH_WORKER_BWRAP_EXECUTABLE",
                    "/usr/bin/bwrap",
                )
            ),
            cgroup_root=Path(raw_cgroup_root) if raw_cgroup_root else None,
            data_dir=Path(raw_data_dir).expanduser().resolve() if raw_data_dir else None,
        )

    def request(
        self,
        profile: WorkerIsolationProfile,
        *,
        read_only_paths: tuple[Path, ...] = (),
        environment: tuple[tuple[str, str], ...] = (),
    ) -> WorkerIsolationRequest:
        return WorkerIsolationRequest(
            profile=profile,
            read_only_paths=read_only_paths,
            environment=environment,
            runtime=self,
        )

    def validate_required_backend(self) -> None:
        """Reject an incomplete required-mode deployment before worker input."""

        if self.mode is WorkerIsolationMode.DEVELOPMENT:
            return
        if not sys.platform.startswith("linux") or os.name != "posix":
            raise BackendExecutionError(
                "required worker containment is available only on Linux"
            )
        _validate_trusted_executable(self.bubblewrap_executable)
        if self.cgroup_root is None:
            raise BackendExecutionError(
                "required worker containment needs a delegated cgroup-v2 root"
            )
        _validate_cgroup_root(self.cgroup_root)
        _validate_runtime_root(self.package_root, label="package")

    def prepare(
        self,
        request: WorkerIsolationRequest,
        arguments: tuple[str, ...],
        *,
        timeout_seconds: float,
        address_space_mb: int,
        maximum_file_bytes: int,
    ) -> PreparedWorkerIsolation:
        if self.mode is WorkerIsolationMode.DEVELOPMENT:
            return PreparedWorkerIsolation.development(arguments, request.profile)

        self.validate_required_backend()
        profile = _PROFILES[request.profile]
        if not profile.required_mode_supported:
            raise BackendExecutionError(
                f"{request.profile.value} requires brokered egress in required mode"
            )
        assert self.cgroup_root is not None
        roots = _reviewed_read_only_roots(
            package_root=self.package_root,
            explicit=request.read_only_paths,
            data_dir=self.data_dir,
        )
        memory_mb = profile.resident_memory_mb or address_space_mb
        lease = _CgroupLease.create(
            self.cgroup_root,
            memory_max_bytes=memory_mb * 1024 * 1024,
            pids_max=profile.pids_max,
            cpu_quota=profile.cpu_quota,
            cpu_period=profile.cpu_period,
        )
        return PreparedWorkerIsolation(
            original_arguments=arguments,
            profile=request.profile,
            limits=profile,
            bubblewrap_executable=self.bubblewrap_executable,
            read_only_roots=roots,
            environment=request.environment,
            cgroup=lease,
            timeout_seconds=timeout_seconds,
            address_space_bytes=address_space_mb * 1024 * 1024,
            maximum_file_bytes=maximum_file_bytes,
            status=_ENFORCED_STATUS,
        )


@dataclass(slots=True)
class PreparedWorkerIsolation:
    """Prepared launch state whose cgroup must be closed exactly once."""

    original_arguments: tuple[str, ...]
    profile: WorkerIsolationProfile
    limits: _ProfileLimits | None
    bubblewrap_executable: Path | None
    read_only_roots: tuple[Path, ...]
    environment: tuple[tuple[str, str], ...]
    cgroup: _CgroupLease | None
    timeout_seconds: float
    address_space_bytes: int
    maximum_file_bytes: int
    status: str

    @classmethod
    def development(
        cls,
        arguments: tuple[str, ...],
        profile: WorkerIsolationProfile,
    ) -> PreparedWorkerIsolation:
        return cls(
            original_arguments=arguments,
            profile=profile,
            limits=None,
            bubblewrap_executable=None,
            read_only_roots=(),
            environment=(),
            cgroup=None,
            timeout_seconds=0,
            address_space_bytes=0,
            maximum_file_bytes=0,
            status=_DEVELOPMENT_STATUS,
        )

    @property
    def enforced(self) -> bool:
        return self.status == _ENFORCED_STATUS

    @property
    def process_limit(self) -> int | None:
        return self.limits.pids_max if self.limits is not None else None

    @property
    def cgroup_procs_path(self) -> Path | None:
        return self.cgroup.procs_path if self.cgroup is not None else None

    def launch_arguments(self, *, status_fd: int) -> tuple[str, ...]:
        if not self.enforced:
            return self.original_arguments
        assert self.bubblewrap_executable is not None
        assert self.limits is not None
        bootstrap = Path(__file__).with_name("worker_isolation_bootstrap.py")
        arguments: list[str] = [
            str(self.bubblewrap_executable),
            "--unshare-user",
            "--unshare-pid",
            "--unshare-ipc",
            "--unshare-uts",
            "--unshare-cgroup",
        ]
        if self.limits.network_denied:
            arguments.append("--unshare-net")
        if self.limits.disable_nested_user_namespaces:
            arguments.append("--disable-userns")
        arguments.extend(
            (
                "--die-with-parent",
                "--new-session",
                "--cap-drop",
                "ALL",
                "--uid",
                str(os.getuid()),
                "--gid",
                str(os.getgid()),
                "--hostname",
                f"fetech-{self.profile.value}",
                "--clearenv",
                "--setenv",
                "PATH",
                "/usr/local/bin:/usr/bin:/bin",
                "--setenv",
                "LANG",
                "C.UTF-8",
                "--setenv",
                "LC_ALL",
                "C.UTF-8",
                "--setenv",
                "HOME",
                "/tmp/home",
                "--setenv",
                "PWD",
                "/tmp",
                "--setenv",
                "TMPDIR",
                "/tmp",
                "--setenv",
                "XDG_CACHE_HOME",
                "/tmp/cache",
                "--setenv",
                "XDG_CONFIG_HOME",
                "/tmp/config",
                "--setenv",
                "PYTHONPATH",
                str(Path(__file__).resolve().parents[1]),
            )
        )
        for name, value in self.environment:
            arguments.extend(("--setenv", name, value))
        arguments.extend(_system_mount_arguments())
        for root in self.read_only_roots:
            arguments.extend(("--ro-bind", str(root), str(root)))
        arguments.extend(
            (
                "--proc",
                "/proc",
                "--dev",
                "/dev",
                "--perms",
                "0700",
                "--size",
                str(self.limits.scratch_bytes),
                "--tmpfs",
                "/tmp",
                "--perms",
                "1777",
                "--size",
                str(self.limits.shared_memory_bytes),
                "--tmpfs",
                "/dev/shm",
                "--dir",
                "/tmp/home",
                "--chmod",
                "0700",
                "/tmp/home",
                "--dir",
                "/tmp/cache",
                "--chmod",
                "0700",
                "/tmp/cache",
                "--dir",
                "/tmp/config",
                "--chmod",
                "0700",
                "/tmp/config",
                "--chdir",
                "/tmp",
                "--json-status-fd",
                str(status_fd),
                "--",
                sys.executable,
                "-I",
                "-B",
                str(bootstrap),
                self.profile.value,
                str(max(1, int(self.timeout_seconds))),
                str(self.address_space_bytes),
                str(self.maximum_file_bytes),
                str(self.limits.pids_max),
                "--",
                *self.original_arguments,
            )
        )
        return tuple(arguments)

    async def close(self) -> None:
        if self.cgroup is not None:
            await self.cgroup.close()


@dataclass(slots=True)
class _CgroupLease:
    path: Path
    closed: bool = False

    @classmethod
    def create(
        cls,
        root: Path,
        *,
        memory_max_bytes: int,
        pids_max: int,
        cpu_quota: int,
        cpu_period: int,
    ) -> _CgroupLease:
        if min(memory_max_bytes, pids_max, cpu_quota, cpu_period) <= 0:
            raise ValueError("cgroup worker limits must be positive")
        path = root / f"{_CGROUP_PREFIX}{uuid4().hex}"
        try:
            path.mkdir(mode=0o700)
            _write_control(path / "memory.max", str(memory_max_bytes))
            if (path / "memory.swap.max").exists():
                _write_control(path / "memory.swap.max", "0")
            if (path / "memory.oom.group").exists():
                _write_control(path / "memory.oom.group", "1")
            _write_control(path / "pids.max", str(pids_max))
            _write_control(path / "cpu.max", f"{cpu_quota} {cpu_period}")
            if not (path / "cgroup.kill").exists():
                raise BackendExecutionError(
                    "delegated cgroup does not expose cgroup.kill"
                )
        except BaseException as exc:
            _remove_empty_cgroup(path)
            if isinstance(exc, BackendExecutionError):
                raise
            raise BackendExecutionError(
                "failed to create the required worker cgroup"
            ) from exc
        return cls(path=path)

    @property
    def procs_path(self) -> Path:
        return self.path / "cgroup.procs"

    async def close(self) -> None:
        if self.closed:
            return
        if not self.path.exists():
            self.closed = True
            return
        try:
            _write_control(self.path / "cgroup.kill", "1")
            for _ in range(100):
                if not _cgroup_populated(self.path):
                    break
                await asyncio.sleep(0.01)
            else:
                raise BackendExecutionError(
                    "worker cgroup remained populated after forced cleanup"
                )
            self.path.rmdir()
        except FileNotFoundError as exc:
            if not self.path.exists():
                self.closed = True
                return
            raise BackendExecutionError(
                "worker cgroup disappeared during cleanup"
            ) from exc
        except OSError as exc:
            raise BackendExecutionError(
                "failed to remove the worker cgroup"
            ) from exc
        self.closed = True


def _validate_read_only_paths(paths: tuple[Path, ...]) -> None:
    normalized: set[Path] = set()
    for path in paths:
        if not isinstance(path, Path):
            raise TypeError("worker read-only mounts must be pathlib.Path values")
        if "\x00" in str(path) or not path.is_absolute():
            raise ValueError("worker read-only mounts must be absolute")
        try:
            if path.is_symlink():
                raise ValueError("worker read-only mount roots cannot be symlinks")
            resolved = path.resolve(strict=True)
        except OSError as exc:
            raise ValueError("worker read-only mount root does not exist") from exc
        if resolved == Path(resolved.anchor) or resolved in normalized:
            raise ValueError("worker read-only mount roots must be unique and non-root")
        normalized.add(resolved)


def _validate_trusted_executable(path: Path) -> None:
    if not path.is_absolute() or "\x00" in str(path):
        raise BackendExecutionError(
            "required Bubblewrap executable must be an absolute path"
        )
    try:
        if path.is_symlink():
            raise BackendExecutionError(
                "required Bubblewrap executable cannot be a symlink"
            )
        metadata = path.stat()
    except OSError as exc:
        raise BackendExecutionError(
            "required Bubblewrap executable is unavailable"
        ) from exc
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        or not os.access(path, os.X_OK)
    ):
        raise BackendExecutionError(
            "required Bubblewrap executable is not root-owned and immutable"
        )
    for parent in path.parents:
        try:
            parent_metadata = parent.stat()
        except OSError as exc:
            raise BackendExecutionError(
                "required Bubblewrap executable ancestry is unavailable"
            ) from exc
        if (
            not stat.S_ISDIR(parent_metadata.st_mode)
            or parent_metadata.st_uid != 0
            or parent_metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise BackendExecutionError(
                "required Bubblewrap executable ancestry is not root-owned and immutable"
            )


def _validate_cgroup_root(path: Path) -> None:
    if not path.is_absolute() or "\x00" in str(path):
        raise BackendExecutionError("delegated cgroup root must be absolute")
    try:
        if path.is_symlink() or not path.is_dir():
            raise BackendExecutionError(
                "delegated cgroup root is not a real directory"
            )
        controllers = set((path / "cgroup.controllers").read_text().split())
    except OSError as exc:
        raise BackendExecutionError(
            "delegated cgroup-v2 controls are unavailable"
        ) from exc
    if not _CGROUP_CONTROLLERS.issubset(controllers):
        raise BackendExecutionError(
            "delegated cgroup root must expose cpu, memory and pids"
        )
    if not os.access(path, os.W_OK | os.X_OK):
        raise BackendExecutionError("delegated cgroup root is not writable")
    subtree_control = path / "cgroup.subtree_control"
    try:
        enabled = set(subtree_control.read_text().split())
    except OSError as exc:
        raise BackendExecutionError(
            "delegated cgroup-v2 controls are unavailable"
        ) from exc
    missing = _CGROUP_CONTROLLERS - enabled
    if missing:
        _write_control(
            subtree_control,
            " ".join(f"+{controller}" for controller in sorted(missing)),
        )
        try:
            enabled = set(subtree_control.read_text().split())
        except OSError as exc:
            raise BackendExecutionError(
                "failed to verify delegated cgroup controllers"
            ) from exc
    if not _CGROUP_CONTROLLERS.issubset(enabled):
        raise BackendExecutionError(
            "delegated cgroup root could not enable cpu, memory and pids"
        )


def _validate_runtime_root(path: Path, *, label: str) -> Path:
    try:
        if path.is_symlink():
            raise BackendExecutionError(f"{label} runtime root cannot be a symlink")
        resolved = path.resolve(strict=True)
    except OSError as exc:
        raise BackendExecutionError(f"{label} runtime root is unavailable") from exc
    if resolved == Path(resolved.anchor) or not resolved.is_dir():
        raise BackendExecutionError(f"{label} runtime root must be a non-root directory")
    return resolved


def _reviewed_read_only_roots(
    *,
    package_root: Path,
    explicit: tuple[Path, ...],
    data_dir: Path | None,
) -> tuple[Path, ...]:
    candidates = [
        _validate_runtime_root(package_root, label="package"),
        _validate_runtime_root(Path(sys.prefix), label="Python"),
        _validate_runtime_root(Path(sys.base_prefix), label="base Python"),
    ]
    candidates.extend(path.resolve(strict=True) for path in explicit)
    forbidden = data_dir.resolve() if data_dir is not None else None
    roots: list[Path] = []
    for candidate in sorted(set(candidates), key=lambda value: (len(value.parts), str(value))):
        if forbidden is not None and (
            candidate == forbidden
            or forbidden.is_relative_to(candidate)
            or candidate.is_relative_to(forbidden)
        ):
            raise BackendExecutionError(
                "worker read-only roots cannot expose the daemon data directory"
            )
        if any(candidate.is_relative_to(existing) for existing in roots):
            continue
        roots.append(candidate)
    return tuple(roots)


def _system_mount_arguments() -> tuple[str, ...]:
    arguments: list[str] = []
    for path in _SYSTEM_ROOTS:
        if not path.exists() and not path.is_symlink():
            continue
        if path.is_symlink():
            target = os.readlink(path)
            if "\x00" in target or (target.startswith("/") and not target.startswith("/usr/")):
                raise BackendExecutionError("unsafe system runtime symlink")
            arguments.extend(("--symlink", target.removeprefix("/"), str(path)))
        elif path.is_dir():
            arguments.extend(("--ro-bind", str(path), str(path)))
    arguments.extend(("--dir", "/etc"))
    for path in (
        Path("/etc/ld.so.cache"),
        Path("/etc/ld.so.conf"),
        Path("/etc/ld.so.conf.d"),
        Path("/etc/fonts"),
    ):
        if path.exists():
            arguments.extend(("--ro-bind", str(path), str(path)))
    return tuple(arguments)


def _write_control(path: Path, value: str) -> None:
    try:
        path.write_text(f"{value}\n", encoding="ascii")
    except OSError as exc:
        raise BackendExecutionError(
            f"failed to apply cgroup control {path.name}"
        ) from exc


def _cgroup_populated(path: Path) -> bool:
    try:
        fields = dict(
            line.split(maxsplit=1)
            for line in (path / "cgroup.events").read_text().splitlines()
            if " " in line
        )
    except OSError as exc:
        raise BackendExecutionError("failed to read worker cgroup state") from exc
    return fields.get("populated") != "0"


def _remove_empty_cgroup(path: Path) -> None:
    try:
        if path.exists() and not _cgroup_populated(path):
            path.rmdir()
    except (BackendExecutionError, OSError):
        pass


__all__ = [
    "PreparedWorkerIsolation",
    "WorkerIsolationMode",
    "WorkerIsolationProfile",
    "WorkerIsolationRequest",
    "WorkerIsolationRuntime",
]
