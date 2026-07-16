from __future__ import annotations

import importlib.util
import shutil
import sys
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
    backend = PrologReasonerBackend()
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
        ("https://example.com/picture.png", "image", "image_metadata"),
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
