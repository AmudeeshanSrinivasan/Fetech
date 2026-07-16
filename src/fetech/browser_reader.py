"""Bounded offline browser-reader subprocess boundary."""

from __future__ import annotations

import json
import sys

from fetech.adapters.base import AdapterDependencyError, AdapterExecutionError
from fetech.logic.base import LogicBackendError
from fetech.logic.process import run_bounded


class BrowserReaderWorker:
    async def extract(
        self,
        document: str,
        *,
        target: str,
        user_agent: str,
        timeout_seconds: float,
        maximum_bytes: int,
    ) -> str:
        if timeout_seconds <= 0:
            raise AdapterExecutionError("browser reader has no browser-time budget")
        worker_byte_limit = min(maximum_bytes, 50_000_000)
        if len(document.encode()) > worker_byte_limit:
            raise AdapterExecutionError("browser reader input exceeded the worker byte limit")
        payload = json.dumps(
            {
                "document": document,
                "target": target,
                "user_agent": user_agent,
                "timeout_seconds": timeout_seconds,
                "maximum_bytes": worker_byte_limit,
            },
            separators=(",", ":"),
        ).encode()
        try:
            result = await run_bounded(
                (sys.executable, "-m", "fetech.browser_worker"),
                payload,
                timeout_seconds=timeout_seconds,
                memory_mb=768,
                maximum_output_bytes=worker_byte_limit + 4_096,
            )
        except LogicBackendError as exc:
            raise AdapterExecutionError("bounded browser reader process failed") from exc
        try:
            response = json.loads(result.stdout)
        except json.JSONDecodeError as exc:
            raise AdapterExecutionError("browser reader returned malformed output") from exc
        if result.returncode == 2 or response.get("error") == "dependency_missing":
            raise AdapterDependencyError(
                "browser_reader_mode requires fetech[browser] and an installed Chromium binary"
            )
        if result.returncode != 0 or response.get("error"):
            raise AdapterExecutionError("offline browser reader failed")
        text = response.get("text")
        if not isinstance(text, str):
            raise AdapterExecutionError("browser reader omitted extracted text")
        if len(text.encode()) > worker_byte_limit:
            raise AdapterExecutionError("browser reader output exceeded the byte budget")
        return text
