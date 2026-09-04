from __future__ import annotations

import asyncio
import importlib.util
import json
import os
import shutil
import signal
import sys
from contextlib import suppress
from dataclasses import replace
from pathlib import Path

import httpx
import pytest
from typer.testing import CliRunner

from fetech.adapters.http import HTTPAdapter
from fetech.cli import app
from fetech.client import FetechClient
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.logic import process as process_module
from fetech.logic.base import BackendExecutionError, BackendOutputError, BackendUnavailableError
from fetech.logic.clingo_backend import ClingoPlannerBackend
from fetech.logic.coordinator import LogicCoordinator
from fetech.logic.models import BackendStatus, PlanProposal, ReasoningQuery, ReasoningResult
from fetech.logic.process import run_bounded
from fetech.logic.prolog_backend import PrologReasonerBackend
from fetech.models import FetchPlan, FetchRequest
from fetech.planning import DeterministicPlanner
from fetech.registry import CapabilityRegistry
from fetech.security import SafeURLPolicy

CLINGO_AVAILABLE = shutil.which("clingo") is not None or importlib.util.find_spec("clingo") is not None


def _settings(tmp_path: Path, **changes: object) -> Settings:
    settings = Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )
    return replace(settings, **changes)


def _coordinator(settings: Settings) -> LogicCoordinator:
    registry = CapabilityRegistry()
    return LogicCoordinator(settings, registry, DeterministicPlanner(registry))


@pytest.mark.asyncio
async def test_python_planner_is_dependency_free_baseline(tmp_path: Path) -> None:
    proposal = await _coordinator(_settings(tmp_path)).plan(FetchRequest(target="https://example.com"))
    assert proposal.backend == "python"
    assert proposal.status == BackendStatus.SUCCEEDED
    assert proposal.plan.classifier == "python-rules-v1"


@pytest.mark.asyncio
@pytest.mark.skipif(not CLINGO_AVAILABLE, reason="Clingo is not installed")
async def test_sdk_awaitable_plan_uses_configured_backend(tmp_path: Path) -> None:
    async with FetechClient(_settings(tmp_path, planner_backend="clingo")) as client:
        plan = await client.plan(FetchRequest(target="https://example.com"))
        explanation = await client.explain_capability("http_get")
    assert plan.classifier == "clingo-asp-v1"
    assert explanation.backend == "python"


@pytest.mark.asyncio
@pytest.mark.skipif(not CLINGO_AVAILABLE, reason="Clingo is not installed")
async def test_real_clingo_plan_has_python_safety_parity(tmp_path: Path) -> None:
    coordinator = _coordinator(_settings(tmp_path, planner_backend="clingo"))
    request = FetchRequest(target="https://example.com")
    proposal = await coordinator.plan(request)
    baseline = coordinator.deterministic_planner.plan(request)
    assert proposal.backend == "clingo"
    assert proposal.plan.classifier == "clingo-asp-v1"
    assert [node.model_dump() for node in proposal.plan.nodes] == [
        node.model_dump() for node in baseline.nodes
    ]
    assert proposal.ruleset_sha256
    assert proposal.manifest_version == "1.0"
    assert proposal.manifest_sha256
    assert proposal.input_sha256
    assert proposal.result_sha256
    assert proposal.executable_version and "clingo version" in proposal.executable_version


@pytest.mark.asyncio
async def test_missing_clingo_falls_back_to_python(tmp_path: Path) -> None:
    coordinator = _coordinator(
        _settings(
            tmp_path,
            planner_backend="clingo",
            clingo_executable="/definitely/missing/clingo",
        )
    )
    proposal = await coordinator.plan(FetchRequest(target="https://example.com"))
    assert proposal.backend == "python"
    assert proposal.status == BackendStatus.FALLBACK
    assert "Clingo executable not found" in proposal.diagnostics[0]


@pytest.mark.asyncio
async def test_missing_clingo_is_typed_error_when_fallback_disabled(tmp_path: Path) -> None:
    coordinator = _coordinator(
        _settings(
            tmp_path,
            planner_backend="clingo",
            clingo_executable="/definitely/missing/clingo",
            logic_fallback=False,
        )
    )
    with pytest.raises(BackendUnavailableError):
        await coordinator.plan(FetchRequest(target="https://example.com"))


def test_malformed_clingo_output_is_rejected() -> None:
    with pytest.raises(BackendOutputError, match="malformed JSON"):
        ClingoPlannerBackend._selected_nodes(b"not-json")


def test_clingo_python_module_is_used_when_console_script_is_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    backend = ClingoPlannerBackend()
    monkeypatch.setattr("fetech.logic.clingo_backend.shutil.which", lambda _: None)
    monkeypatch.setattr("fetech.logic.clingo_backend.find_spec", lambda _: object())
    assert backend._command() == (sys.executable, "-m", "clingo")


@pytest.mark.asyncio
@pytest.mark.skipif(shutil.which("swipl") is None, reason="SWI-Prolog is not installed")
async def test_real_prolog_reasoner_matches_python_semantics(tmp_path: Path) -> None:
    coordinator = _coordinator(_settings(tmp_path, reasoner_backend="prolog"))
    result = await coordinator.explain(coordinator.capability_query("http_get"))
    assert result.backend == "prolog"
    assert result.eligible
    assert result.conclusion == "eligible"
    assert result.ruleset_sha256
    assert result.input_sha256
    assert result.result_sha256
    assert result.executable_version and "SWI-Prolog version" in result.executable_version


@pytest.mark.asyncio
async def test_missing_prolog_falls_back_to_python(tmp_path: Path) -> None:
    coordinator = _coordinator(
        _settings(
            tmp_path,
            reasoner_backend="prolog",
            prolog_executable="/definitely/missing/swipl",
        )
    )
    result = await coordinator.explain(coordinator.capability_query("http_get"))
    assert result.backend == "python"
    assert result.status == BackendStatus.FALLBACK
    assert result.eligible


@pytest.mark.asyncio
async def test_sensitive_prolog_facts_are_rejected_before_execution() -> None:
    backend = PrologReasonerBackend(executable="/definitely/missing/swipl")
    query = ReasoningQuery(capability_id="http_get", facts={"api_token": 123})
    with pytest.raises(BackendOutputError, match="sensitive reasoning fact"):
        await backend.explain(query)


def test_contradictory_prolog_result_is_rejected() -> None:
    query = ReasoningQuery(capability_id="http_get", allowed=False, available=True)
    result = ReasoningResult(
        backend="prolog",
        status=BackendStatus.SUCCEEDED,
        capability_id="http_get",
        conclusion="eligible",
        eligible=True,
    )
    with pytest.raises(BackendOutputError, match="contradicts Python eligibility semantics"):
        PrologReasonerBackend._validate_semantics(result, query)


@pytest.mark.asyncio
async def test_structurally_mutated_logic_plan_falls_back_to_python(tmp_path: Path) -> None:
    class MutatingBackend:
        name = "clingo"

        async def propose(
            self,
            request: FetchRequest,
            baseline: FetchPlan,
            registry: CapabilityRegistry,
        ) -> PlanProposal:
            del request, registry
            first = baseline.nodes[0].model_copy(update={"adapter": "untrusted"})
            mutated = baseline.model_copy(update={"nodes": (first, *baseline.nodes[1:])})
            return PlanProposal(
                backend=self.name,
                status=BackendStatus.SUCCEEDED,
                plan=mutated,
            )

    coordinator = _coordinator(_settings(tmp_path, planner_backend="clingo"))
    coordinator.clingo_planner = MutatingBackend()  # type: ignore[assignment]
    proposal = await coordinator.plan(FetchRequest(target="https://example.com"))
    assert proposal.backend == "python"
    assert proposal.status == BackendStatus.FALLBACK
    assert "changed the safe Python node structure" in proposal.diagnostics[0]


@pytest.mark.parametrize(
    ("target", "output", "expected"),
    [
        ("https://example.com", "clean_text", "clean_text"),
        ("https://example.com/report.pdf", "clean_text", "pdf"),
        ("https://example.com/data.json", "clean_text", "json_endpoint"),
        ("https://example.com/feed.xml", "clean_text", "xml_endpoint"),
        ("https://example.com/movie.mp4", "video", "video_metadata"),
        ("https://example.com/song.mp3", "audio", "audio_metadata"),
        ("https://example.com/picture.png", "image", "image"),
        ("https://example.com/bundle.zip", "clean_text", "zip_archive"),
        ("https://example.com/file.txt", "clean_text", "txt"),
    ],
)
def test_all_planned_family_capabilities_are_canonical(
    target: str,
    output: str,
    expected: str,
) -> None:
    registry = CapabilityRegistry()
    plan = DeterministicPlanner(registry).plan(FetchRequest(target=target, output_requirements=(output,)))
    capability_ids = {node.capability_id for node in plan.nodes}
    assert expected in capability_ids
    assert all(registry.resolve_id(capability_id) == capability_id for capability_id in capability_ids)


@pytest.mark.asyncio
async def test_logic_subprocess_timeout_is_enforced() -> None:
    with pytest.raises(BackendExecutionError, match="exceeded"):
        await run_bounded(
            (sys.executable, "-c", "import time; time.sleep(2)"),
            b"",
            timeout_seconds=0.1,
            memory_mb=256,
        )


@pytest.mark.asyncio
async def test_subprocess_spawn_phase_has_an_independent_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def stalled_spawn(*_arguments: object, **_keywords: object) -> None:
        await asyncio.sleep(30)

    monkeypatch.setattr(
        process_module.asyncio,
        "create_subprocess_exec",
        stalled_spawn,
    )
    started = asyncio.get_running_loop().time()

    with pytest.raises(BackendExecutionError, match="startup exceeded"):
        await run_bounded(
            (sys.executable, "-c", "pass"),
            b"",
            timeout_seconds=2,
            startup_timeout_seconds=0.05,
            memory_mb=256,
        )

    assert asyncio.get_running_loop().time() - started < 0.5


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX startup handshake is required")
async def test_subprocess_startup_handshake_includes_target_exec() -> None:
    with pytest.raises(
        BackendExecutionError,
        match="failed before completing guarded startup",
    ):
        await run_bounded(
            ("/definitely/not/a/fetech-worker",),
            b"",
            timeout_seconds=1,
            startup_timeout_seconds=0.5,
            memory_mb=256,
        )


@pytest.mark.asyncio
async def test_subprocess_early_exit_does_not_leak_broken_pipe() -> None:
    result = await run_bounded(
        (sys.executable, "-c", "raise SystemExit(127)"),
        b"x" * 1_000_000,
        timeout_seconds=2,
        memory_mb=256,
    )

    assert result.returncode == 127
    assert result.stdout == b""


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups are required")
async def test_subprocess_startup_timeout_kills_bootstrap_descendants(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    child_pid_path = tmp_path / "startup-child.pid"

    def hanging_bootstrap(
        _arguments: tuple[str, ...],
        *,
        ready_fd: int,
        cpu_seconds: int,
        memory_bytes: int,
        file_bytes: int,
        process_limit: int | None,
        cgroup_procs_path: Path | None,
        pass_readiness: bool,
    ) -> tuple[str, ...]:
        del (
            ready_fd,
            cpu_seconds,
            memory_bytes,
            file_bytes,
            process_limit,
            cgroup_procs_path,
            pass_readiness,
        )
        probe = (
            "import pathlib,subprocess,sys,time;"
            "child=subprocess.Popen("
            "[sys.executable,'-c','import time;time.sleep(30)'],"
            "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,"
            "stderr=subprocess.DEVNULL"
            ");"
            "pathlib.Path(sys.argv[1]).write_text(str(child.pid));"
            "time.sleep(30)"
        )
        return (sys.executable, "-c", probe, str(child_pid_path))

    monkeypatch.setattr(
        process_module,
        "_limited_bootstrap_arguments",
        hanging_bootstrap,
    )

    with pytest.raises(BackendExecutionError, match="startup exceeded"):
        await run_bounded(
            (sys.executable, "-c", "pass"),
            b"",
            timeout_seconds=3,
            startup_timeout_seconds=0.5,
            memory_mb=256,
        )

    assert child_pid_path.exists()
    child_pid = int(child_pid_path.read_text())
    try:
        for _ in range(100):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("startup timeout left a bootstrap descendant running")
    finally:
        with suppress(ProcessLookupError):
            os.kill(child_pid, signal.SIGKILL)


@pytest.mark.asyncio
async def test_logic_subprocess_output_limit_is_enforced() -> None:
    with pytest.raises(BackendOutputError, match="output exceeded"):
        await run_bounded(
            (sys.executable, "-c", "print('x' * 100)"),
            b"",
            timeout_seconds=1,
            memory_mb=256,
            maximum_output_bytes=10,
        )


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX rlimits are required")
async def test_subprocess_limits_lower_the_child_hard_limits() -> None:
    probe = (
        "import json,resource;"
        "print(json.dumps({"
        "'core':resource.getrlimit(resource.RLIMIT_CORE),"
        "'file':resource.getrlimit(resource.RLIMIT_FSIZE),"
        "'nofile':resource.getrlimit(resource.RLIMIT_NOFILE)"
        "},sort_keys=True))"
    )
    result = await run_bounded(
        (sys.executable, "-c", probe),
        b"",
        timeout_seconds=2,
        memory_mb=256,
        maximum_output_bytes=4_096,
        maximum_file_bytes=8_192,
    )
    limits = json.loads(result.stdout)

    assert limits["core"] == [0, 0]
    assert limits["file"][0] == limits["file"][1] <= 8_192
    assert limits["nofile"][0] == limits["nofile"][1] <= 256


@pytest.mark.asyncio
@pytest.mark.skipif(os.name != "posix", reason="POSIX process groups are required")
async def test_subprocess_runner_kills_descendants_after_the_leader_exits() -> None:
    probe = (
        "import subprocess,sys;"
        "child=subprocess.Popen("
        "[sys.executable,'-c','import time;time.sleep(30)'],"
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL"
        ");"
        "print(child.pid)"
    )
    result = await run_bounded(
        (sys.executable, "-c", probe),
        b"",
        timeout_seconds=3,
        memory_mb=256,
        maximum_output_bytes=4_096,
    )
    child_pid = int(result.stdout)

    try:
        for _ in range(100):
            try:
                os.kill(child_pid, 0)
            except ProcessLookupError:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("bounded subprocess left a descendant running")
    finally:
        with suppress(ProcessLookupError):
            os.kill(child_pid, signal.SIGKILL)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("timeout_seconds", "memory_mb", "maximum_output_bytes"),
    [(0.0, 256, 1_000), (1.0, 0, 1_000), (1.0, 256, 0)],
)
async def test_logic_subprocess_rejects_non_positive_resource_limits(
    timeout_seconds: float,
    memory_mb: int,
    maximum_output_bytes: int,
) -> None:
    with pytest.raises(ValueError, match="limits must be positive"):
        await run_bounded(
            (sys.executable, "-c", "pass"),
            b"",
            timeout_seconds=timeout_seconds,
            memory_mb=memory_mb,
            maximum_output_bytes=maximum_output_bytes,
        )


@pytest.mark.asyncio
@pytest.mark.skipif(not CLINGO_AVAILABLE, reason="Clingo is not installed")
async def test_gateway_records_clingo_planner_provenance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = _settings(tmp_path, planner_backend="clingo")
    gateway = UniversalFetchGateway(settings)
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, headers={"content-type": "text/html"}, text="useful " * 20)

    monkeypatch.setattr(policy, "_resolve", public)
    gateway.policy = policy
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=settings.user_agent,
        policy=policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(FetchRequest(target="https://example.com"))
    events = await gateway.ledger.events(result.run_id)
    planning = [event for event in events if event.event_type == "planning.completed"]
    assert len(planning) == 1
    assert planning[0].actor == "clingo"
    assert planning[0].payload["classifier"] == "clingo-asp-v1"
    assert "ruleset_sha256" in planning[0].payload
    await gateway.close()


@pytest.mark.skipif(not CLINGO_AVAILABLE, reason="Clingo is not installed")
def test_cli_exposes_clingo_plan(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    result = CliRunner().invoke(app, ["plan", "https://example.com", "--backend", "clingo"])
    assert result.exit_code == 0, result.output
    assert '"classifier": "clingo-asp-v1"' in result.output


def test_cli_explanation_respects_request_deny(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    result = CliRunner().invoke(app, ["explain", "http_get", "--deny"])
    assert result.exit_code == 0, result.output
    assert '"conclusion": "ineligible"' in result.output
    assert '"eligible": false' in result.output
    assert "denied by the request policy" in result.output
