"""Optional bounded HTTP/3 acquisition through a reviewed curl executable."""

from __future__ import annotations

import shutil
from dataclasses import dataclass

from fetech.adapters.base import AdapterDependencyError, AdapterExecutionError
from fetech.logic.base import LogicBackendError
from fetech.logic.process import run_bounded

_MARKER = b"\n\x1eFETECH_HTTP3_METADATA\x1e"


@dataclass(frozen=True)
class HTTP3Response:
    status_code: int
    media_type: str
    redirect_url: str
    http_version: str
    body: bytes


class CurlHTTP3Client:
    def __init__(self, executable: str = "curl") -> None:
        self.executable = executable
        self._validated = False

    async def fetch(
        self,
        url: str,
        *,
        address: str,
        user_agent: str,
        timeout_seconds: float,
        maximum_bytes: int,
    ) -> HTTP3Response:
        executable = await self._available_executable()
        process_byte_limit = min(maximum_bytes, 100_000_000)
        host_port = _host_port(url)
        resolved_address = f"[{address}]" if ":" in address else address
        write_out = (
            _MARKER.decode()
            + "%{http_code}\t%{content_type}\t%{redirect_url}\t%{http_version}"
        )
        try:
            result = await run_bounded(
                (
                    executable,
                    "--http3-only",
                    "--silent",
                    "--show-error",
                    "--proto",
                    "=https",
                    "--max-time",
                    f"{timeout_seconds:g}",
                    "--max-filesize",
                    str(process_byte_limit),
                    "--resolve",
                    f"{host_port}:{resolved_address}",
                    "--user-agent",
                    user_agent,
                    "--output",
                    "-",
                    "--write-out",
                    write_out,
                    url,
                ),
                b"",
                timeout_seconds=timeout_seconds,
                memory_mb=512,
                maximum_output_bytes=process_byte_limit + 4_096,
            )
        except LogicBackendError as exc:
            raise AdapterExecutionError("bounded HTTP/3 process failed") from exc
        if result.returncode != 0:
            raise AdapterExecutionError(
                f"HTTP/3 transport failed with exit code {result.returncode}"
            )
        body, separator, metadata = result.stdout.rpartition(_MARKER)
        if not separator:
            raise AdapterExecutionError("HTTP/3 transport omitted response metadata")
        fields = metadata.decode(errors="replace").split("\t", maxsplit=3)
        if len(fields) != 4:
            raise AdapterExecutionError("HTTP/3 transport returned malformed metadata")
        status, media_type, redirect_url, version = fields
        if not version.startswith("3"):
            raise AdapterExecutionError(f"HTTP/3 was requested but curl negotiated HTTP/{version}")
        try:
            status_code = int(status)
        except ValueError as exc:
            raise AdapterExecutionError("HTTP/3 transport returned an invalid status") from exc
        return HTTP3Response(status_code, media_type, redirect_url, version, body)

    async def _available_executable(self) -> str:
        executable = shutil.which(self.executable)
        if executable is None:
            raise AdapterDependencyError(f"HTTP/3 curl executable not found: {self.executable}")
        if self._validated:
            return executable
        try:
            result = await run_bounded(
                (executable, "--version"),
                b"",
                timeout_seconds=2,
                memory_mb=128,
                maximum_output_bytes=20_000,
            )
        except LogicBackendError as exc:
            raise AdapterDependencyError("could not inspect the HTTP/3 curl executable") from exc
        if result.returncode != 0 or "HTTP3" not in result.stdout.decode(errors="replace"):
            raise AdapterDependencyError("configured curl was built without HTTP/3 support")
        self._validated = True
        return executable


def _host_port(url: str) -> str:
    from urllib.parse import urlsplit

    parts = urlsplit(url)
    host = parts.hostname or ""
    port = parts.port or 443
    displayed_host = f"[{host}]" if ":" in host else host
    return f"{displayed_host}:{port}"
