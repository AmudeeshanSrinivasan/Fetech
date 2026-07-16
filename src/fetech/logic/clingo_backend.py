"""Bounded Clingo planner that proves a Python-generated candidate plan."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
from importlib.util import find_spec
from pathlib import Path

from fetech.logic.base import (
    BackendExecutionError,
    BackendOutputError,
    BackendUnavailableError,
)
from fetech.logic.models import BackendStatus, PlanProposal
from fetech.logic.process import run_bounded
from fetech.models import FetchPlan, FetchRequest
from fetech.registry import CapabilityRegistry

_SELECTED = re.compile(r'^selected\("([^"\\]+)"\)$')


class ClingoPlannerBackend:
    name = "clingo"

    def __init__(
        self,
        *,
        executable: str = "clingo",
        timeout_seconds: float = 3.0,
        memory_mb: int = 512,
        solution_limit: int = 1,
        rules_path: Path | None = None,
    ) -> None:
        self.executable = executable
        self.timeout_seconds = timeout_seconds
        self.memory_mb = memory_mb
        self.solution_limit = solution_limit
        self.rules_path = rules_path or Path(__file__).parent / "rules" / "planner.lp"

    async def propose(
        self,
        request: FetchRequest,
        baseline: FetchPlan,
        registry: CapabilityRegistry,
    ) -> PlanProposal:
        command = self._command()
        if command is None:
            raise BackendUnavailableError(f"Clingo executable not found: {self.executable}")
        rules = self.rules_path.read_text(encoding="utf-8")
        facts = self._facts(request, baseline, registry)
        program = f"{rules}\n{facts}".encode()
        result = await run_bounded(
            (
                *command,
                "--outf=2",
                f"--models={self.solution_limit}",
                "--warn=none",
                "-",
            ),
            program,
            timeout_seconds=self.timeout_seconds,
            memory_mb=self.memory_mb,
        )
        if result.returncode not in {0, 10, 20, 30}:
            message = result.stderr.decode(errors="replace").strip() or "unknown Clingo failure"
            raise BackendExecutionError(f"Clingo exited with {result.returncode}: {message}")
        selected = self._selected_nodes(result.stdout)
        expected = {node.id for node in baseline.nodes}
        if selected != expected:
            missing = sorted(expected - selected)
            extra = sorted(selected - expected)
            raise BackendOutputError(
                f"Clingo proposal failed parity validation; missing={missing}, extra={extra}"
            )
        version = await self._version(command)
        plan = baseline.model_copy(update={"classifier": "clingo-asp-v1"})
        selected_document = json.dumps(sorted(selected), separators=(",", ":")).encode()
        return PlanProposal(
            backend=self.name,
            status=BackendStatus.SUCCEEDED,
            plan=plan,
            executable_version=version,
            ruleset_sha256=hashlib.sha256(rules.encode()).hexdigest(),
            manifest_version=registry.manifest_version,
            manifest_sha256=hashlib.sha256(registry.manifest_path.read_bytes()).hexdigest(),
            input_sha256=hashlib.sha256(program).hexdigest(),
            result_sha256=hashlib.sha256(selected_document).hexdigest(),
        )

    @staticmethod
    def _facts(
        request: FetchRequest,
        baseline: FetchPlan,
        registry: CapabilityRegistry,
    ) -> str:
        lines: list[str] = []
        lines.append(f"manifest_version({_asp_string(registry.manifest_version)}).")
        for node in baseline.nodes:
            identifier = _asp_string(node.id)
            lines.append(f"node({identifier}).")
            lines.append(f"required({identifier}).")
            entry = registry.get(node.capability_id)
            if not entry.available:
                lines.append(f"unavailable({identifier}).")
            if entry.id in request.deny_capabilities:
                lines.append(f"denied({identifier}).")
            for dependency in node.dependencies:
                lines.append(f"dependency({identifier},{_asp_string(dependency)}).")
        return "\n".join(lines)

    @staticmethod
    def _selected_nodes(output: bytes) -> set[str]:
        try:
            document = json.loads(output)
            witnesses = document["Call"][0]["Witnesses"]
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as exc:
            raise BackendOutputError("Clingo returned malformed JSON") from exc
        if len(witnesses) != 1:
            raise BackendOutputError(f"Clingo returned {len(witnesses)} answer sets; expected exactly one")
        selected: set[str] = set()
        for value in witnesses[0].get("Value", []):
            match = _SELECTED.fullmatch(value)
            if match:
                selected.add(match.group(1))
        return selected

    def _command(self) -> tuple[str, ...] | None:
        executable = shutil.which(self.executable)
        if executable is not None:
            return (executable,)
        if self.executable == "clingo" and find_spec("clingo") is not None:
            return (sys.executable, "-m", "clingo")
        return None

    async def _version(self, command: tuple[str, ...]) -> str | None:
        result = await run_bounded(
            (*command, "--version"),
            b"",
            timeout_seconds=self.timeout_seconds,
            memory_mb=self.memory_mb,
            maximum_output_bytes=10_000,
        )
        if result.returncode != 0:
            return None
        first_line = result.stdout.decode(errors="replace").splitlines()
        return first_line[0] if first_line else None


def _asp_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)
