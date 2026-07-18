"""Resource-bounded subprocess helper for reviewed worker programs."""

from __future__ import annotations

import asyncio
import json
import math
import os
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path

from fetech.logic.base import BackendExecutionError, BackendOutputError
from fetech.worker_isolation import PreparedWorkerIsolation, WorkerIsolationRequest

_DEFAULT_STARTUP_TIMEOUT_SECONDS = 5.0
_STARTUP_MARKER = b"fetech-limits-ready-v1\n"
_ISOLATION_STARTUP_MARKER = b"fetech-isolation-ready-v1\n"
_MAX_STARTUP_PROTOCOL_BYTES = 4_096
_MAX_STARTUP_STDERR_BYTES = 4_096


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes
    containment: str = "unprofiled"


async def run_bounded(
    arguments: tuple[str, ...],
    stdin: bytes,
    *,
    timeout_seconds: float,
    memory_mb: int,
    maximum_output_bytes: int = 1_000_000,
    maximum_file_bytes: int | None = None,
    startup_timeout_seconds: float | None = None,
    isolation: WorkerIsolationRequest | None = None,
) -> ProcessResult:
    if (
        timeout_seconds <= 0
        or memory_mb <= 0
        or maximum_output_bytes <= 0
        or (maximum_file_bytes is not None and maximum_file_bytes <= 0)
        or (startup_timeout_seconds is not None and startup_timeout_seconds <= 0)
    ):
        raise ValueError("subprocess limits must be positive")
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout_seconds
    prepared = (
        isolation.runtime.prepare(
            isolation,
            arguments,
            timeout_seconds=timeout_seconds,
            address_space_mb=memory_mb,
            maximum_file_bytes=maximum_file_bytes or maximum_output_bytes,
        )
        if isolation is not None
        else None
    )
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        # Use only the reviewed Fetech package root, never the caller's
        # PYTHONPATH. This keeps Python workers importable from both an
        # installed wheel and a source checkout without widening module search.
        "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
    }
    if prepared is not None and prepared.enforced:
        environment["PATH"] = "/usr/local/bin:/usr/bin:/bin"
    startup_timeout = min(
        max(0.001, deadline - loop.time()),
        (
            _DEFAULT_STARTUP_TIMEOUT_SECONDS
            if startup_timeout_seconds is None
            else startup_timeout_seconds
        ),
    )
    process: asyncio.subprocess.Process | None = None
    primary_failure: BaseException | None = None
    try:
        if os.name == "posix":
            process = await _spawn_posix_limited(
                arguments,
                environment=environment,
                startup_timeout_seconds=startup_timeout,
                cpu_seconds=max(1, math.ceil(timeout_seconds)),
                memory_bytes=memory_mb * 1024 * 1024,
                file_bytes=maximum_file_bytes or maximum_output_bytes,
                isolation=prepared,
            )
        else:
            process = await _spawn_portable(
                arguments,
                environment=environment,
                startup_timeout_seconds=startup_timeout,
            )
        remaining = deadline - loop.time()
        if remaining <= 0:
            await _kill_process_tree(process)
            raise BackendExecutionError(
                f"subprocess startup exhausted the {timeout_seconds:g}s wall budget"
            )
        try:
            async with asyncio.timeout(remaining):
                stdout, stderr = await _communicate_bounded(
                    process, stdin, maximum_output_bytes=maximum_output_bytes
                )
        except TimeoutError as exc:
            await _kill_process_tree(process)
            raise BackendExecutionError(
                f"worker process exceeded {timeout_seconds:g}s"
            ) from exc
        except BaseException:
            await _kill_process_tree(process)
            raise
        return ProcessResult(
            process.returncode or 0,
            stdout,
            stderr,
            (
                prepared.status
                if prepared is not None
                else "unprofiled"
            ),
        )
    except BaseException as exc:
        primary_failure = exc
        raise
    finally:
        if prepared is not None:
            try:
                await _close_prepared_without_abandoning(prepared)
            except BackendExecutionError as cleanup_error:
                if primary_failure is not None:
                    raise cleanup_error from primary_failure
                raise


async def _close_prepared_without_abandoning(
    prepared: PreparedWorkerIsolation,
) -> None:
    cleanup = asyncio.create_task(prepared.close())
    deferred_cancellation: asyncio.CancelledError | None = None
    while not cleanup.done():
        try:
            await asyncio.shield(cleanup)
        except asyncio.CancelledError as exc:
            deferred_cancellation = exc
    cleanup.result()
    if deferred_cancellation is not None:
        raise deferred_cancellation


async def _spawn_posix_limited(
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str],
    startup_timeout_seconds: float,
    cpu_seconds: int,
    memory_bytes: int,
    file_bytes: int,
    isolation: PreparedWorkerIsolation | None,
) -> asyncio.subprocess.Process:
    ready_read, ready_write = os.pipe()
    os.set_inheritable(ready_read, False)
    os.set_inheritable(ready_write, True)
    os.set_blocking(ready_read, False)
    process: asyncio.subprocess.Process | None = None
    status_buffer = bytearray()
    try:
        try:
            async with asyncio.timeout(startup_timeout_seconds):
                process = await asyncio.create_subprocess_exec(
                    *_limited_bootstrap_arguments(
                        (
                            isolation.launch_arguments(status_fd=ready_write)
                            if isolation is not None
                            else arguments
                        ),
                        ready_fd=ready_write,
                        cpu_seconds=cpu_seconds,
                        memory_bytes=memory_bytes,
                        file_bytes=file_bytes,
                        # The delegated cgroup supplies the authoritative PID
                        # ceiling. Applying RLIMIT_NPROC before Bubblewrap
                        # would count unrelated processes owned by the daemon
                        # UID and can prevent namespace setup itself.
                        process_limit=None,
                        cgroup_procs_path=(
                            isolation.cgroup_procs_path
                            if isolation is not None
                            else None
                        ),
                        pass_readiness=bool(
                            isolation is not None and isolation.enforced
                        ),
                    ),
                    stdin=asyncio.subprocess.PIPE,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                    env=environment,
                    start_new_session=True,
                    pass_fds=(ready_write,),
                )
                os.close(ready_write)
                ready_write = -1
                marker = await _read_startup_marker(
                    ready_read,
                    stop_at_newline=bool(
                        isolation is not None and isolation.enforced
                    ),
                    pending=(
                        status_buffer
                        if isolation is not None and isolation.enforced
                        else None
                    ),
                )
                if isolation is not None and isolation.enforced:
                    _validate_bubblewrap_status(marker)
                    if process.stdout is None:
                        raise BackendExecutionError(
                            "isolated worker stdout pipe was not created"
                        )
                    try:
                        inner_marker = await process.stdout.readexactly(
                            len(_ISOLATION_STARTUP_MARKER)
                        )
                    except asyncio.IncompleteReadError as exc:
                        diagnostic = await _isolation_startup_diagnostic(
                            process,
                            status_fd=ready_read,
                            pending_status=status_buffer,
                        )
                        raise BackendExecutionError(
                            diagnostic
                        ) from exc
                    if inner_marker != _ISOLATION_STARTUP_MARKER:
                        raise BackendExecutionError(
                            "isolated worker failed inner containment attestation"
                        )
                elif marker != _STARTUP_MARKER:
                    raise BackendExecutionError(
                        "bounded subprocess failed before completing guarded startup"
                    )
        except TimeoutError as exc:
            if process is not None:
                await _kill_process_tree(process)
            raise BackendExecutionError(
                f"subprocess startup exceeded {startup_timeout_seconds:g}s"
            ) from exc
        except BaseException:
            if process is not None:
                await _kill_process_tree(process)
            raise
        assert process is not None
        return process
    finally:
        with suppress(OSError):
            os.close(ready_read)
        if ready_write >= 0:
            with suppress(OSError):
                os.close(ready_write)


async def _spawn_portable(
    arguments: tuple[str, ...],
    *,
    environment: dict[str, str],
    startup_timeout_seconds: float,
) -> asyncio.subprocess.Process:
    process: asyncio.subprocess.Process | None = None
    try:
        async with asyncio.timeout(startup_timeout_seconds):
            process = await asyncio.create_subprocess_exec(
                *arguments,
                stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=environment,
            )
    except TimeoutError as exc:
        if process is not None:
            await _kill_process_tree(process)
        raise BackendExecutionError(
            f"subprocess startup exceeded {startup_timeout_seconds:g}s"
        ) from exc
    except BaseException:
        if process is not None:
            await _kill_process_tree(process)
        raise
    assert process is not None
    return process


def _limited_bootstrap_arguments(
    arguments: tuple[str, ...],
    *,
    ready_fd: int,
    cpu_seconds: int,
    memory_bytes: int,
    file_bytes: int,
    process_limit: int | None = None,
    cgroup_procs_path: Path | None = None,
    pass_readiness: bool = False,
) -> tuple[str, ...]:
    bootstrap = Path(__file__).with_name("process_bootstrap.py")
    return (
        sys.executable,
        "-I",
        "-B",
        str(bootstrap),
        str(ready_fd),
        str(cpu_seconds),
        str(memory_bytes),
        str(file_bytes),
        str(process_limit or 0),
        (
            str(cgroup_procs_path)
            if cgroup_procs_path is not None
            else "-"
        ),
        "1" if pass_readiness else "0",
        "--",
        *arguments,
    )


async def _read_startup_marker(
    descriptor: int,
    *,
    stop_at_newline: bool,
    pending: bytearray | None = None,
) -> bytes:
    loop = asyncio.get_running_loop()
    completed: asyncio.Future[bytes] = loop.create_future()
    content = pending if pending is not None else bytearray()

    def completed_value(*, eof: bool = False) -> bytes | None:
        if stop_at_newline and b"\n" in content:
            line, _, remainder = bytes(content).partition(b"\n")
            content.clear()
            content.extend(remainder)
            return line + b"\n"
        if eof or len(content) >= _MAX_STARTUP_PROTOCOL_BYTES:
            value = bytes(content)
            content.clear()
            return value
        return None

    buffered = completed_value()
    if buffered is not None:
        return buffered

    def readable() -> None:
        try:
            chunk = os.read(
                descriptor,
                max(1, _MAX_STARTUP_PROTOCOL_BYTES - len(content)),
            )
        except BlockingIOError:
            return
        except OSError as exc:
            loop.remove_reader(descriptor)
            if not completed.done():
                completed.set_exception(exc)
            return
        if chunk:
            content.extend(chunk)
        value = completed_value(eof=not chunk)
        if value is not None:
            loop.remove_reader(descriptor)
            if not completed.done():
                completed.set_result(value)

    loop.add_reader(descriptor, readable)
    try:
        return await completed
    finally:
        loop.remove_reader(descriptor)


async def _isolation_startup_diagnostic(
    process: asyncio.subprocess.Process,
    *,
    status_fd: int,
    pending_status: bytearray,
) -> str:
    status_task = asyncio.create_task(
        _read_startup_marker(
            status_fd,
            stop_at_newline=True,
            pending=pending_status,
        ),
        name="bubblewrap-exit-status",
    )
    stderr_task = asyncio.create_task(
        _read_startup_stderr(process.stderr),
        name="bubblewrap-startup-stderr",
    )
    terminal_returncode = process.returncode
    try:
        # No trusted worker attested, so no process from this group may remain
        # alive while diagnostics are collected.
        await _kill_process_tree(process)
        status_document, (stderr, stderr_truncated) = await asyncio.gather(
            status_task,
            stderr_task,
        )
    except BaseException:
        status_task.cancel()
        stderr_task.cancel()
        await asyncio.gather(status_task, stderr_task, return_exceptions=True)
        raise

    bubblewrap_exit_code = _bubblewrap_exit_code(status_document)
    fragments: list[str] = []
    if bubblewrap_exit_code is not None:
        fragments.append(f"Bubblewrap exit code {bubblewrap_exit_code}")
    elif terminal_returncode is not None:
        fragments.append(f"launcher return code {terminal_returncode}")
    if reason := _sanitize_startup_stderr(stderr):
        fragments.append(reason)
    if stderr_truncated:
        fragments.append("startup stderr was truncated")

    message = "isolated worker ended before containment attestation"
    if fragments:
        message = f"{message} ({'; '.join(fragments)})"
    return message


async def _read_startup_stderr(
    stream: asyncio.StreamReader | None,
) -> tuple[bytes, bool]:
    if stream is None:
        return b"", False
    content = bytearray()
    while len(content) <= _MAX_STARTUP_STDERR_BYTES:
        chunk = await stream.read(
            min(65_536, _MAX_STARTUP_STDERR_BYTES + 1 - len(content))
        )
        if not chunk:
            break
        content.extend(chunk)
    return (
        bytes(content[:_MAX_STARTUP_STDERR_BYTES]),
        len(content) > _MAX_STARTUP_STDERR_BYTES,
    )


def _bubblewrap_exit_code(document: bytes) -> int | None:
    try:
        value = json.loads(document)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    exit_code = value.get("exit-code") if isinstance(value, dict) else None
    if (
        not isinstance(exit_code, int)
        or isinstance(exit_code, bool)
        or not 0 <= exit_code <= 255
    ):
        return None
    return exit_code


def _sanitize_startup_stderr(stderr: bytes) -> str | None:
    if not stderr:
        return None
    lowered = stderr.lower()
    fixed_reasons = (
        (
            b"failed rtm_newaddr",
            "Bubblewrap loopback address setup was denied",
        ),
        (
            b"failed rtm_newlink",
            "Bubblewrap loopback link setup was denied",
        ),
        (
            b"creating new namespace failed",
            "Bubblewrap namespace setup was denied",
        ),
        (
            b"no permissions to creating new namespace",
            "Bubblewrap namespace setup was denied",
        ),
        (
            b"setting up uid map",
            "Bubblewrap identity mapping failed",
        ),
        (
            b"setting up gid map",
            "Bubblewrap identity mapping failed",
        ),
        (
            b"no such file or directory",
            "Bubblewrap startup dependency was unavailable",
        ),
        (
            b"operation not permitted",
            "Bubblewrap setup was denied",
        ),
        (
            b"permission denied",
            "Bubblewrap setup was denied",
        ),
    )
    for marker, reason in fixed_reasons:
        if marker in lowered:
            return reason
    return "unrecognized startup stderr was suppressed"


def _validate_bubblewrap_status(marker: bytes) -> None:
    try:
        document = json.loads(marker)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BackendExecutionError(
            "Bubblewrap failed before reporting isolated worker startup"
        ) from exc
    child_pid = document.get("child-pid") if isinstance(document, dict) else None
    if (
        not isinstance(child_pid, int)
        or isinstance(child_pid, bool)
        or child_pid <= 0
    ):
        raise BackendExecutionError(
            "Bubblewrap did not attest an isolated worker child"
        )


async def _communicate_bounded(
    process: asyncio.subprocess.Process,
    stdin: bytes,
    *,
    maximum_output_bytes: int,
) -> tuple[bytes, bytes]:
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise BackendExecutionError("logic backend pipes were not created")
    stdout_task = asyncio.create_task(
        _read_bounded(process.stdout, maximum_output_bytes), name="logic-stdout"
    )
    stderr_task = asyncio.create_task(
        _read_bounded(process.stderr, maximum_output_bytes), name="logic-stderr"
    )
    try:
        try:
            process.stdin.write(stdin)
            await process.stdin.drain()
        except (BrokenPipeError, ConnectionResetError):
            # A worker may exit after the guarded startup handshake but before
            # consuming its request. Preserve its return code and diagnostics
            # instead of leaking a transport-level pipe exception.
            pass
        finally:
            with suppress(BrokenPipeError, ConnectionResetError):
                process.stdin.close()
        stdout, stderr, _ = await asyncio.gather(
            stdout_task,
            stderr_task,
            process.wait(),
        )
    except BaseException:
        stdout_task.cancel()
        stderr_task.cancel()
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
        raise
    # The leader may have exited after leaving background descendants in its
    # dedicated process group. Reap that group before returning any result.
    await _kill_process_tree(process)
    return stdout, stderr


async def _read_bounded(stream: asyncio.StreamReader, maximum_bytes: int) -> bytes:
    chunks: list[bytes] = []
    size = 0
    while chunk := await stream.read(65_536):
        size += len(chunk)
        if size > maximum_bytes:
            raise BackendOutputError("logic backend output exceeded the configured bound")
        chunks.append(chunk)
    return b"".join(chunks)


async def _kill_process_tree(process: asyncio.subprocess.Process) -> None:
    if os.name == "posix":
        # start_new_session=True makes the leader PID the process-group ID.
        # The group may still contain descendants after the leader exits.
        with suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGKILL)
    elif process.returncode is None:
        with suppress(ProcessLookupError):
            process.kill()
    if process.returncode is None:
        await process.wait()
