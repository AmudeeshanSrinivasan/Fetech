"""Bounded SWI-Prolog reasoner over sanitized typed facts."""

from __future__ import annotations

import hashlib
import json
import shutil
from pathlib import Path
from typing import Any

from pydantic import StrictBool, StrictInt, ValidationError

from fetech.logic.base import BackendExecutionError, BackendOutputError, BackendUnavailableError
from fetech.logic.models import BackendStatus, ReasoningQuery, ReasoningResult
from fetech.logic.process import run_bounded

_SENSITIVE_KEYS = {"authorization", "body", "cookie", "credential", "password", "secret", "token"}


class PrologReasonerBackend:
    name = "prolog"

    def __init__(
        self,
        *,
        executable: str = "swipl",
        timeout_seconds: float = 3.0,
        memory_mb: int = 512,
        rules_path: Path | None = None,
    ) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.memory_mb = memory_mb
        self.rules_path = rules_path or Path(__file__).parent / "rules" / "reasoner.pl"

    async def explain(self, query: ReasoningQuery) -> ReasoningResult:
        _reject_sensitive_facts(query.facts)
        executable = shutil.which(self.executable)
        if executable is None:
            raise BackendUnavailableError(f"SWI-Prolog executable not found: {self.executable}")
        rules = self.rules_path.read_bytes()
        payload = query.model_dump_json().encode()
        if len(payload) > 65_536:
            raise BackendOutputError("reasoning input exceeded the configured bound")
        result = await run_bounded(
            (executable, "--quiet", "--no-tty", "--nodebug", "-f", str(self.rules_path)),
            payload,
            timeout_seconds=self.timeout_seconds,
            memory_mb=self.memory_mb,
        )
        if result.returncode != 0:
            message = result.stderr.decode(errors="replace").strip() or "unknown Prolog failure"
            raise BackendExecutionError(f"SWI-Prolog exited with {result.returncode}: {message}")
        try:
            document: dict[str, Any] = json.loads(result.stdout)
            parsed = ReasoningResult(
                backend=self.name,
                status=BackendStatus.SUCCEEDED,
                capability_id=document["capability_id"],
                conclusion=document["conclusion"],
                eligible=document["eligible"],
                reasons=tuple(document.get("reasons", [])),
                ruleset_sha256=hashlib.sha256(rules).hexdigest(),
                input_sha256=hashlib.sha256(payload).hexdigest(),
                result_sha256=hashlib.sha256(result.stdout).hexdigest(),
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValidationError) as exc:
            raise BackendOutputError("SWI-Prolog returned malformed reasoning JSON") from exc
        if parsed.capability_id != query.capability_id:
            raise BackendOutputError("SWI-Prolog changed the queried capability ID")
        self._validate_semantics(parsed, query)
        version = await self._version(executable)
        return parsed.model_copy(update={"executable_version": version})

    @staticmethod
    def _validate_semantics(result: ReasoningResult, query: ReasoningQuery) -> None:
        expected = query.allowed and query.available
        expected_conclusion = "eligible" if expected else "ineligible"
        if result.eligible != expected or result.conclusion != expected_conclusion:
            raise BackendOutputError("SWI-Prolog result contradicts Python eligibility semantics")

    async def _version(self, executable: str) -> str | None:
        result = await run_bounded(
            (executable, "--version"),
            b"",
            timeout_seconds=self.timeout_seconds,
            memory_mb=self.memory_mb,
            maximum_output_bytes=10_000,
        )
        if result.returncode != 0:
            return None
        return result.stdout.decode(errors="replace").strip() or None


def _reject_sensitive_facts(facts: dict[str, StrictBool | StrictInt]) -> None:
    for key in facts:
        lowered = key.lower()
        if lowered in _SENSITIVE_KEYS or any(fragment in lowered for fragment in _SENSITIVE_KEYS):
            raise BackendOutputError(f"sensitive reasoning fact is forbidden: {key}")
