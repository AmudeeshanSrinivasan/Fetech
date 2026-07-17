"""Resource-bounded subprocess helper for reviewed logic programs."""

from __future__ import annotations

import asyncio
import math
import os
import signal
import sys
from contextlib import suppress
from dataclasses import dataclass
from functools import partial
from pathlib import Path

from fetech.logic.base import BackendExecutionError, BackendOutputError


@dataclass(frozen=True)
class ProcessResult:
    returncode: int
    stdout: bytes
    stderr: bytes


async def run_bounded(
    arguments: tuple[str, ...],
    stdin: bytes,
    *,
    timeout_seconds: float,
    memory_mb: int,
    maximum_output_bytes: int = 1_000_000,
) -> ProcessResult:
    environment = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "LANG": os.environ.get("LANG", "C.UTF-8"),
        "LC_ALL": os.environ.get("LC_ALL", "C.UTF-8"),
        # Use only the reviewed Fetech package root, never the caller's
        # PYTHONPATH. This keeps Python workers importable from both an
        # installed wheel and a source checkout without widening module search.
        "PYTHONPATH": str(Path(__file__).resolve().parents[2]),
    }
    if os.name == "posix":
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
            start_new_session=True,
            preexec_fn=partial(
                _set_limits,
                cpu_seconds=max(1, math.ceil(timeout_seconds)),
                memory_bytes=memory_mb * 1024 * 1024,
            ),
        )
    else:
        process = await asyncio.create_subprocess_exec(
            *arguments,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env=environment,
        )
    try:
        async with asyncio.timeout(timeout_seconds):
            stdout, stderr = await _communicate_bounded(
                process, stdin, maximum_output_bytes=maximum_output_bytes
            )
    except TimeoutError as exc:
        await _kill_process_tree(process)
        raise BackendExecutionError(f"logic backend exceeded {timeout_seconds:g}s") from exc
    except BaseException:
        await _kill_process_tree(process)
        raise
    return ProcessResult(process.returncode or 0, stdout, stderr)


async def _communicate_bounded(
    process: asyncio.subprocess.Process,
    stdin: bytes,
    *,
    maximum_output_bytes: int,
) -> tuple[bytes, bytes]:
    if process.stdin is None or process.stdout is None or process.stderr is None:
        raise BackendExecutionError("logic backend pipes were not created")
    process.stdin.write(stdin)
    await process.stdin.drain()
    process.stdin.close()
    stdout_task = asyncio.create_task(
        _read_bounded(process.stdout, maximum_output_bytes), name="logic-stdout"
    )
    stderr_task = asyncio.create_task(
        _read_bounded(process.stderr, maximum_output_bytes), name="logic-stderr"
    )
    try:
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
    if process.returncode is not None:
        return
    with suppress(ProcessLookupError):
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    await process.wait()


def _set_limits(*, cpu_seconds: int, memory_bytes: int) -> None:
    try:
        import resource
    except ImportError:
        return
    with suppress(OSError, ValueError):
        _, hard_cpu = resource.getrlimit(resource.RLIMIT_CPU)
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, hard_cpu))
    # macOS rejects address-space limits in a pre-exec child. The wall-time/output
    # bounds still apply there; Linux daemon workers additionally enforce RLIMIT_AS.
    if sys.platform.startswith("linux") and hasattr(resource, "RLIMIT_AS"):
        with suppress(OSError, ValueError):
            _, hard_memory = resource.getrlimit(resource.RLIMIT_AS)
            resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, hard_memory))
