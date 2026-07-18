"""Inner Linux containment bootstrap executed inside Bubblewrap.

This file is invoked with isolated Python and deliberately avoids importing the
``fetech`` package.  It installs strict rlimits and a libseccomp denylist,
attests readiness on stdout, then replaces itself with the fixed worker target.
"""

from __future__ import annotations

import ctypes
import errno
import os
import sys
from contextlib import suppress

READY_MARKER = b"fetech-isolation-ready-v1\n"
EXEC_FAILURE_MARKER = b"fetech-isolation-exec-failed-v1\n"
_SCMP_ACT_ALLOW = 0x7FFF0000
_SCMP_ACT_ERRNO = 0x00050000
_PR_SET_NO_NEW_PRIVS = 38

_COMMON_DENIED_SYSCALLS = (
    "acct",
    "add_key",
    "bpf",
    "delete_module",
    "finit_module",
    "init_module",
    "io_pgetevents",
    "io_setup",
    "io_submit",
    "ioperm",
    "iopl",
    "kcmp",
    "keyctl",
    "kexec_file_load",
    "kexec_load",
    "lookup_dcookie",
    "mount",
    "move_mount",
    "name_to_handle_at",
    "open_by_handle_at",
    "open_tree",
    "perf_event_open",
    "pivot_root",
    "process_vm_readv",
    "process_vm_writev",
    "ptrace",
    "quotactl",
    "reboot",
    "request_key",
    "setns",
    "swapoff",
    "swapon",
    "sysfs",
    "umount2",
    "userfaultfd",
)
_PARSER_ONLY_DENIED_SYSCALLS = ("unshare",)
_BROWSER_NAMESPACE_SYSCALLS = frozenset(
    {
        "mount",
        "move_mount",
        "open_tree",
        "pivot_root",
        "setns",
        "umount2",
    }
)
_REQUIRED_RESOLVED_SYSCALLS = frozenset(
    {
        "bpf",
        "keyctl",
        "perf_event_open",
        "process_vm_readv",
        "ptrace",
    }
)


def main(arguments: list[str] | None = None) -> int:
    values = list(sys.argv[1:] if arguments is None else arguments)
    if len(values) < 7 or values[5] != "--":
        return 125
    profile = values[0]
    try:
        cpu_seconds = int(values[1])
        memory_bytes = int(values[2])
        file_bytes = int(values[3])
        process_limit = int(values[4])
    except ValueError:
        return 125
    command = values[6:]
    if (
        profile
        not in {
            "archive_parser",
            "browser_offline",
            "document_parser",
            "image_decoder",
            "media_native_offline",
        }
        or min(cpu_seconds, memory_bytes, file_bytes, process_limit) <= 0
        or not command
    ):
        return 125
    try:
        _set_limits(
            cpu_seconds=cpu_seconds,
            memory_bytes=memory_bytes,
            file_bytes=file_bytes,
        )
        _install_seccomp(profile=profile)
        os.write(sys.stdout.fileno(), READY_MARKER)
        sys.stdout.flush()
        os.execvpe(command[0], command, os.environ)
    except OSError:
        with suppress(OSError):
            os.write(sys.stdout.fileno(), EXEC_FAILURE_MARKER)
        return 127
    except Exception:
        with suppress(OSError):
            os.write(sys.stdout.fileno(), EXEC_FAILURE_MARKER)
        return 125


def _set_limits(
    *,
    cpu_seconds: int,
    memory_bytes: int,
    file_bytes: int,
) -> None:
    import resource

    _set_process_limit(resource.RLIMIT_CPU, cpu_seconds)
    if hasattr(resource, "RLIMIT_CORE"):
        _set_process_limit(resource.RLIMIT_CORE, 0)
    if hasattr(resource, "RLIMIT_FSIZE"):
        _set_process_limit(resource.RLIMIT_FSIZE, file_bytes)
    if hasattr(resource, "RLIMIT_NOFILE"):
        _set_process_limit(resource.RLIMIT_NOFILE, 256)
    # RLIMIT_NPROC is account-wide, not per worker, and would make one worker's
    # behavior depend on unrelated processes owned by the daemon UID. The
    # delegated cgroup's pids.max is the authoritative per-worker ceiling.
    if not hasattr(resource, "RLIMIT_AS"):
        raise RuntimeError("Linux address-space limit is unavailable")
    _set_process_limit(resource.RLIMIT_AS, memory_bytes)


def _set_process_limit(resource_id: int, requested: int) -> None:
    import resource

    _, hard = resource.getrlimit(resource_id)
    limit = requested if hard == resource.RLIM_INFINITY else min(requested, hard)
    resource.setrlimit(resource_id, (limit, limit))
    current_soft, current_hard = resource.getrlimit(resource_id)
    if current_soft > limit or current_hard > limit:
        raise RuntimeError("worker rlimit attestation failed")


def _install_seccomp(*, profile: str) -> None:
    library = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    library.seccomp_init.argtypes = [ctypes.c_uint32]
    library.seccomp_init.restype = ctypes.c_void_p
    library.seccomp_release.argtypes = [ctypes.c_void_p]
    library.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    library.seccomp_syscall_resolve_name.restype = ctypes.c_int
    library.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    library.seccomp_rule_add.restype = ctypes.c_int
    library.seccomp_load.argtypes = [ctypes.c_void_p]
    library.seccomp_load.restype = ctypes.c_int

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [
        ctypes.c_int,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
        ctypes.c_ulong,
    ]
    libc.prctl.restype = ctypes.c_int
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "failed to set no_new_privs")

    context = library.seccomp_init(_SCMP_ACT_ALLOW)
    if not context:
        raise RuntimeError("libseccomp initialization failed")
    resolved: set[str] = set()
    try:
        names = list(_denied_syscalls(profile))
        action = _SCMP_ACT_ERRNO | errno.EPERM
        for name in names:
            syscall = library.seccomp_syscall_resolve_name(name.encode("ascii"))
            if syscall < 0:
                continue
            resolved.add(name)
            if library.seccomp_rule_add(context, action, syscall, 0) != 0:
                raise RuntimeError(f"failed to add seccomp rule for {name}")
        required = _REQUIRED_RESOLVED_SYSCALLS
        if profile != "browser_offline":
            required = required | {"mount", "unshare"}
        if not required.issubset(resolved):
            raise RuntimeError("required seccomp syscalls are unavailable")
        if library.seccomp_load(context) != 0:
            raise RuntimeError("failed to load the seccomp profile")
    finally:
        library.seccomp_release(context)


def _denied_syscalls(profile: str) -> tuple[str, ...]:
    names = tuple(
        name
        for name in _COMMON_DENIED_SYSCALLS
        if profile != "browser_offline" or name not in _BROWSER_NAMESPACE_SYSCALLS
    )
    if profile == "browser_offline":
        return names
    return names + _PARSER_ONLY_DENIED_SYSCALLS


if __name__ == "__main__":
    raise SystemExit(main())
