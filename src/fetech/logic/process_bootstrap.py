"""POSIX limit bootstrap for :func:`fetech.logic.process.run_bounded`.

This file is executed directly with isolated Python. It intentionally avoids
importing the ``fetech`` package so resource limits are installed before the
optional worker or native tool starts importing parser dependencies.
"""

from __future__ import annotations

import os
import sys
from contextlib import suppress

STARTUP_MARKER = b"fetech-limits-ready-v1\n"
_EXEC_FAILURE_MARKER = b"fetech-exec-failed-v1\n"


def main(arguments: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if arguments is None else arguments)
    if len(values) < 9 or values[7] != "--":
        return 125
    try:
        ready_fd = int(values[0])
        cpu_seconds = int(values[1])
        memory_bytes = int(values[2])
        file_bytes = int(values[3])
        process_limit = int(values[4])
    except ValueError:
        return 125
    cgroup_procs_path = values[5]
    pass_readiness = values[6]
    command = values[8:]
    if (
        ready_fd < 0
        or min(cpu_seconds, memory_bytes, file_bytes) <= 0
        or process_limit < 0
        or cgroup_procs_path == ""
        or pass_readiness not in {"0", "1"}
        or not command
    ):
        return 125

    try:
        if cgroup_procs_path != "-":
            _join_cgroup(cgroup_procs_path)
        _set_limits(
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            file_bytes=file_bytes,
            process_limit=process_limit or None,
            strict=pass_readiness == "1",
        )
        if pass_readiness == "0":
            os.write(ready_fd, STARTUP_MARKER)
        # Successful exec closes the readiness descriptor, so the parent knows
        # the fixed target executable has replaced this bootstrap. A failed
        # exec appends a failure marker before closing it.
        os.set_inheritable(ready_fd, pass_readiness == "1")
        os.execvpe(command[0], command, os.environ)
    except OSError:
        with suppress(OSError):
            os.write(ready_fd, _EXEC_FAILURE_MARKER)
        return 127
    finally:
        with suppress(OSError):
            os.close(ready_fd)


def _join_cgroup(cgroup_procs_path: str) -> None:
    if (
        "\x00" in cgroup_procs_path
        or not os.path.isabs(cgroup_procs_path)
        or os.path.basename(cgroup_procs_path) != "cgroup.procs"
    ):
        raise OSError("invalid worker cgroup path")
    flags = os.O_WRONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(cgroup_procs_path, flags)
    try:
        os.write(descriptor, f"{os.getpid()}\n".encode("ascii"))
    finally:
        os.close(descriptor)


def _set_limits(
    *,
    cpu_seconds: int,
    memory_bytes: int,
    file_bytes: int,
    process_limit: int | None,
    strict: bool,
) -> None:
    try:
        import resource
    except ImportError:
        if strict:
            raise OSError("required resource limits are unavailable") from None
        return
    _set_process_limit(resource.RLIMIT_CPU, cpu_seconds, strict=strict)
    if hasattr(resource, "RLIMIT_CORE"):
        _set_process_limit(resource.RLIMIT_CORE, 0, strict=strict)
    if hasattr(resource, "RLIMIT_FSIZE"):
        _set_process_limit(resource.RLIMIT_FSIZE, file_bytes, strict=strict)
    if hasattr(resource, "RLIMIT_NOFILE"):
        _set_process_limit(resource.RLIMIT_NOFILE, 256, strict=strict)
    if process_limit is not None:
        if not hasattr(resource, "RLIMIT_NPROC"):
            if strict:
                raise OSError("required process limit is unavailable")
        else:
            _set_process_limit(resource.RLIMIT_NPROC, process_limit, strict=strict)
    # macOS does not reliably enforce RLIMIT_AS for these workers. Linux gets
    # this process-local ceiling; required covered workers additionally receive
    # a separate aggregate cgroup memory ceiling.
    if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
        _set_process_limit(resource.RLIMIT_AS, memory_bytes, strict=strict)
    elif strict:
        raise OSError("required address-space limit is unavailable")


def _set_process_limit(resource_id: int, requested: int, *, strict: bool) -> None:
    import resource

    try:
        _, hard = resource.getrlimit(resource_id)
        limit = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
        resource.setrlimit(resource_id, (limit, limit))
        current = resource.getrlimit(resource_id)
        if current[0] > limit or current[1] > limit:
            raise OSError("resource limit attestation failed")
    except (OSError, ValueError):
        if strict:
            raise


if __name__ == "__main__":
    raise SystemExit(main())
