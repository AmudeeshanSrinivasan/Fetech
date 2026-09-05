"""Beta dual-graph and bounded context-broker conformance."""

from __future__ import annotations

import asyncio
import json
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from fetech.cli import app as cli_app
from fetech.client import FetechClient
from fetech.config import Settings
from fetech.context import (
    ContextBroker,
    _ProcessResult,
    _qmd_query,
    _query_graph_projection,
    classify_context_needs,
)
from fetech.context import _run as run_context_process
from fetech.ledger import EventLedger
from fetech.models import (
    ContextBundle,
    ContextNeed,
    ContextProviderStatus,
    ContextSource,
    ProvenanceEvent,
)
from fetech.provenance import build_runtime_graph


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


def test_context_need_classification_is_deterministic_and_composable() -> None:
    assert classify_context_needs("Which module implements the planner?") == (
        ContextNeed.CODE_ARCHITECTURE,
    )
    assert classify_context_needs(f"Show events for run {uuid4()}") == (
        ContextNeed.RUNTIME_HISTORY,
    )
    assert classify_context_needs("What ADR recorded the accepted decision?") == (
        ContextNeed.DECISION_HISTORY,
    )
    assert classify_context_needs("Explain this project") == (
        ContextNeed.CODE_ARCHITECTURE,
        ContextNeed.DECISION_HISTORY,
    )
    assert classify_context_needs("Trace the runtime implementation") == (
        ContextNeed.CODE_ARCHITECTURE,
        ContextNeed.RUNTIME_HISTORY,
    )


@pytest.mark.parametrize(
    ("question", "expected"),
    [
        ("Which decision note records the canonical Fetech design?", "architecture"),
        ("Which decision note records the authoritative storage record?", "authoritative storage ledger"),
        ("Which code and decision note define the context token budget?", "context token budget"),
        ("Which code and decision note define the dual Graphify boundary?", "Graphify"),
        ("Which blocker note records unresolved project risks?", "blockers"),
    ],
)
def test_qmd_query_removes_routing_scaffolding(question: str, expected: str) -> None:
    assert _qmd_query(question, repository_name="Fetech") == expected


@pytest.mark.asyncio
async def test_cancelling_context_process_kills_the_child(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original = asyncio.create_subprocess_exec
    started = asyncio.Event()
    observed: dict[str, asyncio.subprocess.Process] = {}

    async def create(*arguments: str, **kwargs: Any) -> asyncio.subprocess.Process:
        process = await original(*arguments, **kwargs)
        observed["process"] = process
        started.set()
        return process

    monkeypatch.setattr(asyncio, "create_subprocess_exec", create)
    task = asyncio.create_task(
        run_context_process(
            sys.executable,
            "-c",
            "import time; time.sleep(30)",
            cwd=tmp_path,
        )
    )
    await asyncio.wait_for(started.wait(), 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    process = observed["process"]
    assert process.returncode is not None


@pytest.mark.asyncio
async def test_broker_queries_both_graphs_and_confirms_code_nodes_in_exact_source(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "module.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "def helper():\n"
        "    return 'bounded'\n"
        "\n"
        "def context_entry():\n"
        "    return helper()\n",
        encoding="utf-8",
    )
    code_graph = repository / "graphify-out" / "graph.json"
    runtime_graph = tmp_path / "data" / "runtime-graph" / "graph.json"
    code_graph.parent.mkdir(parents=True)
    runtime_graph.parent.mkdir(parents=True)
    code_graph.write_text("{}", encoding="utf-8")
    runtime_graph.write_text("{}", encoding="utf-8")
    queried_graphs: list[str] = []

    async def run(*arguments: str, **_: Any) -> _ProcessResult:
        assert arguments[:2] == ("graphify", "query")
        graph = arguments[arguments.index("--graph") + 1]
        queried_graphs.append(graph)
        if graph == str(code_graph):
            return _ProcessResult(
                0,
                "\n".join(
                    (
                        "NODE context_entry() [src=src/module.py loc=L4 community=1]",
                        "NODE helper() [src=src/module.py loc=L1 community=1]",
                        "EDGE context_entry() --calls [EXTRACTED]--> helper()",
                    )
                ),
                "",
            )
        assert graph == str(runtime_graph)
        return _ProcessResult(
            0,
            "NODE run:12345678 [src= loc=ledger://runs/12345678 community=2]\n"
            "EDGE run:12345678 --EMITTED--> run.finished",
            "",
        )

    monkeypatch.setattr("fetech.context._run", run)
    result = await ContextBroker(repository, runtime_graph=runtime_graph).search(
        "Trace the runtime implementation",
        token_budget=800,
    )

    assert set(queried_graphs) == {str(code_graph), str(runtime_graph)}
    assert result.needs == (
        ContextNeed.CODE_ARCHITECTURE,
        ContextNeed.RUNTIME_HISTORY,
    )
    assert {item.source_type for item in result.sources} == {
        "code_graph",
        "runtime_graph",
        "exact_source",
    }
    code = next(item for item in result.sources if item.source_type == "code_graph")
    exact = next(item for item in result.sources if item.source_type == "exact_source")
    assert code.graph_nodes == ("context_entry()", "helper()")
    assert code.graph_paths == ("context_entry() --calls [EXTRACTED]--> helper()",)
    assert code.source_locations == ("src/module.py:L4", "src/module.py:L1")
    assert code.verified is True
    runtime = next(item for item in result.sources if item.source_type == "runtime_graph")
    assert runtime.graph_nodes == ("run:12345678",)
    assert runtime.source_locations == ("ledger://runs/12345678",)
    assert exact.verified is True
    assert exact.locator.startswith("src/module.py:L")
    assert "return helper()" in "\n".join(
        item.excerpt for item in result.sources if item.source_type == "exact_source"
    )
    assert all(item.content_sha256 is not None for item in result.sources)
    assert result.estimated_tokens == result.token_usage.total <= result.token_budget
    reports = {report.provider: report for report in result.provider_reports}
    assert reports["code_graph"].status == ContextProviderStatus.SUCCEEDED
    assert reports["runtime_graph"].status == ContextProviderStatus.SUCCEEDED
    assert reports["qmd"].status == ContextProviderStatus.SKIPPED
    assert reports["exact_source"].status == ContextProviderStatus.SUCCEEDED


@pytest.mark.asyncio
async def test_stale_graph_location_is_not_mislabeled_as_source_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "feature.py"
    source.parent.mkdir(parents=True)
    source.write_text(
        "import os\n"
        "\n"
        "CONSTANT = True\n"
        "\n"
        "def target_symbol():\n"
        "    return CONSTANT\n",
        encoding="utf-8",
    )
    graph = repository / "graphify-out" / "graph.json"
    graph.parent.mkdir(parents=True)
    graph.write_text("{}", encoding="utf-8")

    async def run(*arguments: str, **_: Any) -> _ProcessResult:
        if arguments[0] == "graphify":
            return _ProcessResult(
                0,
                "NODE target_symbol() [src=src/feature.py loc=L1 community=1]",
                "",
            )
        record = {
            "type": "match",
            "data": {
                "path": {"text": "src/feature.py"},
                "lines": {"text": "def target_symbol():\n"},
                "line_number": 5,
            },
        }
        return _ProcessResult(0, json.dumps(record), "")

    monkeypatch.setattr("fetech.context._run", run)
    result = await ContextBroker(repository).search(
        "Which module implements target_symbol?",
        token_budget=800,
    )

    code = next(item for item in result.sources if item.source_type == "code_graph")
    exact = next(item for item in result.sources if item.source_type == "exact_source")
    assert code.source_locations == ("src/feature.py:L1",)
    assert code.verified is False
    assert exact.locator == "src/feature.py:L5"
    assert result.fallback_reason == "exact source search after stale graph locations"


@pytest.mark.asyncio
async def test_exact_source_search_supplements_a_valid_but_incomplete_graph_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    cli_source = repository / "src" / "cli.py"
    daemon_source = repository / "src" / "daemon.py"
    cli_source.parent.mkdir(parents=True)
    cli_source.write_text("def context_search(): pass\n", encoding="utf-8")
    daemon_source.write_text("async def context_search(): pass\n", encoding="utf-8")
    graph = repository / "graphify-out" / "graph.json"
    graph.parent.mkdir(parents=True)
    graph.write_text("{}", encoding="utf-8")

    async def run(*arguments: str, **_: Any) -> _ProcessResult:
        if arguments[0] == "graphify":
            return _ProcessResult(
                0,
                "NODE context_search() [src=src/cli.py loc=L1 community=1]",
                "",
            )
        assert arguments[0] == "rg"
        record = {
            "type": "match",
            "data": {
                "path": {"text": "src/daemon.py"},
                "lines": {"text": "async def context_search(): pass\n"},
                "line_number": 1,
            },
        }
        return _ProcessResult(0, json.dumps(record), "")

    monkeypatch.setattr("fetech.context._run", run)
    result = await ContextBroker(repository).search(
        "Which code module defines the context_search REST handler?"
    )

    exact_locations = {
        source.locator for source in result.sources if source.source_type == "exact_source"
    }
    assert "src/daemon.py:L1" in exact_locations


@pytest.mark.asyncio
async def test_decision_question_uses_only_scoped_qmd_and_deduplicates_by_hash(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    vault = tmp_path / "vault"
    repository.mkdir()
    vault.mkdir()
    inside = vault / "decision.md"
    inside.write_text("accepted decision", encoding="utf-8")
    calls: list[tuple[str, ...]] = []

    async def run(*arguments: str, **_: Any) -> _ProcessResult:
        calls.append(arguments)
        assert arguments[0] == "qmd"
        documents = [
            {
                "title": "Decision",
                "file": str(inside),
                "snippet": "accepted decision",
                "score": 1,
            },
            {
                "title": "Duplicate",
                "file": str(inside),
                "snippet": "accepted decision",
                "score": 0.9,
            },
            {
                "title": "Outside",
                "file": str(tmp_path / "outside.md"),
                "snippet": "must not escape",
                "score": 2,
            },
        ]
        return _ProcessResult(0, json.dumps(documents), "")

    monkeypatch.setattr("fetech.context._run", run)
    result = await ContextBroker(repository, vault=vault).search(
        "Show the accepted ADR decision history"
    )

    assert len(calls) == 1
    assert result.needs == (ContextNeed.DECISION_HISTORY,)
    assert len(result.sources) == 1
    assert result.sources[0].source_type == "qmd"
    assert result.sources[0].locator == str(inside)
    assert result.omitted_results == 1
    reports = {report.provider: report.status for report in result.provider_reports}
    assert reports == {
        "code_graph": ContextProviderStatus.SKIPPED,
        "runtime_graph": ContextProviderStatus.SKIPPED,
        "qmd": ContextProviderStatus.SUCCEEDED,
        "exact_source": ContextProviderStatus.SKIPPED,
    }


@pytest.mark.asyncio
async def test_qmd_uri_is_resolved_and_generic_query_language_is_removed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "Fetech"
    vault = tmp_path / "vault"
    note = vault / "brain" / "Fetech Architecture.md"
    repository.mkdir()
    note.parent.mkdir(parents=True)
    note.write_text("canonical architecture", encoding="utf-8")
    calls: list[tuple[str, ...]] = []

    async def run(*arguments: str, **_: Any) -> _ProcessResult:
        calls.append(arguments)
        assert arguments[:3] == ("qmd", "search", "architecture")
        documents = [
            {
                "title": "Fetech Architecture",
                "file": "qmd://obsidian-mind/brain/Fetech-Architecture.md?index=obsidian-mind",
                "snippet": "canonical architecture",
                "score": 1,
            }
        ]
        return _ProcessResult(0, json.dumps(documents), "")

    monkeypatch.setattr("fetech.context._run", run)
    result = await ContextBroker(repository, vault=vault).search(
        "Which decision note records the canonical Fetech design?"
    )

    assert len(calls) == 1
    assert result.sources[0].locator == str(note)
    assert result.sources[0].provenance == ("QMD lexical search",)


@pytest.mark.asyncio
async def test_qmd_uri_cannot_escape_the_configured_vault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    vault = tmp_path / "vault"
    repository.mkdir()
    vault.mkdir()
    escaped = tmp_path / "escaped.md"
    escaped.write_text("accepted ADR", encoding="utf-8")

    async def run(*arguments: str, **_: Any) -> _ProcessResult:
        if arguments[0] == "qmd":
            documents = [
                {
                    "title": "Escaped",
                    "file": "qmd://obsidian-mind/../escaped.md?index=obsidian-mind",
                    "snippet": "accepted ADR",
                    "score": 1,
                }
            ]
            return _ProcessResult(0, json.dumps(documents), "")
        assert arguments[0] == "rg"
        return _ProcessResult(1, "", "")

    monkeypatch.setattr("fetech.context._run", run)
    result = await ContextBroker(repository, vault=vault).search("Show accepted ADR history")

    assert result.sources == ()
    reports = {report.provider: report.status for report in result.provider_reports}
    assert reports["qmd"] == ContextProviderStatus.EMPTY


@pytest.mark.asyncio
async def test_graph_timeout_is_typed_and_falls_back_to_source_locations(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    source = repository / "src" / "feature.py"
    source.parent.mkdir(parents=True)
    source.write_text("def bounded_feature():\n    return True\n", encoding="utf-8")
    graph = repository / "graphify-out" / "graph.json"
    graph.parent.mkdir(parents=True)
    graph.write_text("{}", encoding="utf-8")

    async def run(*arguments: str, **_: Any) -> _ProcessResult:
        if arguments[0] == "graphify":
            return _ProcessResult(124, "", "private provider detail")
        assert arguments[0] == "rg"
        record = {
            "type": "match",
            "data": {
                "path": {"text": "src/feature.py"},
                "lines": {"text": "def bounded_feature():\n"},
                "line_number": 1,
            },
        }
        return _ProcessResult(0, json.dumps(record), "")

    monkeypatch.setattr("fetech.context._run", run)
    result = await ContextBroker(repository).search("Find the bounded_feature implementation")

    reports = {report.provider: report for report in result.provider_reports}
    assert reports["code_graph"].status == ContextProviderStatus.TIMED_OUT
    assert reports["code_graph"].detail == "provider exceeded its time limit"
    assert reports["exact_source"].status == ContextProviderStatus.SUCCEEDED
    assert result.fallback_reason == "exact source search after code graph miss"
    assert result.sources[0].locator == "src/feature.py:L1"
    assert result.sources[0].verified is True
    assert "private provider detail" not in result.model_dump_json()


@pytest.mark.asyncio
async def test_context_hard_ceiling_caps_large_runtime_graph_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    runtime_graph = tmp_path / "data" / "graph.json"
    runtime_graph.parent.mkdir()
    runtime_graph.write_text("{}", encoding="utf-8")

    async def run(*arguments: str, **_: Any) -> _ProcessResult:
        assert arguments[0] == "graphify"
        return _ProcessResult(
            0,
            "NODE run:fixture [src=event-ledger loc=ledger://runs/fixture community=1]\n"
            + "x" * 100_000,
            "",
        )

    monkeypatch.setattr("fetech.context._run", run)
    result = await ContextBroker(repository, runtime_graph=runtime_graph).search(
        "Show runtime run events",
        token_budget=9_000,
    )

    assert result.token_budget == 8_000
    assert result.estimated_tokens == result.token_usage.total <= 1_200
    assert len(result.sources[0].excerpt) <= 1_200 * 4


def test_projection_attribute_search_is_bounded_and_allowlisted(tmp_path: Path) -> None:
    graph = tmp_path / "runtime-graph.json"
    graph.write_text(
        json.dumps(
            {
                "nodes": [
                    {
                        "id": "event-1",
                        "label": "planning.completed",
                        "type": "ProvenanceEvent",
                        "source_file": "event-ledger",
                        "source_location": "ledger://runs/run-1/events/event-1",
                        "payload": {
                            "classifier": "python-rules-v1",
                            "status": "SUCCEEDED",
                            "unexpected": "must-not-appear",
                        },
                    }
                ],
                "links": [],
            }
        ),
        encoding="utf-8",
    )

    result = _query_graph_projection(graph, "python-rules-v1", 100)

    assert "python-rules-v1" in result
    assert "ledger://runs/run-1/events/event-1" in result
    assert "must-not-appear" not in result
    assert len(result) <= 400


@pytest.mark.asyncio
async def test_runtime_projection_is_deterministic_source_located_and_sanitized(
    tmp_path: Path,
) -> None:
    ledger = EventLedger.sqlite(tmp_path / "ledger.sqlite3")
    await ledger.initialize()
    run_id = uuid4()
    secret = "runtime-secret-value"
    await ledger.create_run(
        run_id,
        {
            "target": "https://example.com/private",
            "authentication_ref": "opaque-reference",
        },
        datetime.now(UTC),
    )
    await ledger.append(
        ProvenanceEvent(
            run_id=run_id,
            event_type="attempt.failed",
            actor="fixture",
            payload={"capability_id": "http_get", "api_key": secret, "code": "timeout"},
        )
    )
    output = tmp_path / "runtime-graph" / "graph.json"

    first = await build_runtime_graph(ledger, output)
    second = await build_runtime_graph(ledger, output)

    assert first == second
    assert first["graph"] == {
        "projection": "fetech-runtime",
        "schema_version": "1.0",
        "authoritative": False,
        "authority": "event-ledger",
    }
    event_node = next(node for node in first["nodes"] if node["type"] == "ProvenanceEvent")
    assert event_node["source_location"].startswith(f"ledger://runs/{run_id}/events/")
    assert event_node["source_file"] == "event-ledger"
    assert event_node["payload"]["code"] == "timeout"
    assert {link["relation"] for link in first["links"]} >= {
        "emitted",
        "references_capability_id",
    }
    assert secret not in json.dumps(first)
    assert not tuple(output.parent.glob(".*.tmp"))
    await ledger.close()


def test_sdk_rest_cli_and_mcp_return_the_same_context_contract(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    expected = ContextBundle(
        question="bounded question",
        sources=(
            ContextSource(
                source_type="exact_source",
                title="fixture",
                locator="src/fixture.py:L1",
                excerpt="1: bounded",
                verified=True,
            ),
        ),
        needs=(ContextNeed.CODE_ARCHITECTURE,),
        confidence=1,
        token_budget=500,
        estimated_tokens=3,
    )

    async def search(_: ContextBroker, question: str, *, token_budget: int | None = None) -> ContextBundle:
        assert question == expected.question
        assert token_budget == 500
        return expected

    monkeypatch.setattr(ContextBroker, "search", search)
    settings = _settings(tmp_path / "sdk")
    sdk = FetechClient(settings, repository=tmp_path)
    assert asyncio.run(sdk.context(expected.question, token_budget=500)) == expected
    asyncio.run(sdk.close())

    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path / "rest"))
    from fetech.daemon import create_app

    with TestClient(create_app()) as rest_client:
        response = rest_client.post(
            "/v1/context/search",
            params={"question": expected.question, "token_budget": 500},
        )
    assert response.status_code == 200, response.text
    assert ContextBundle.model_validate(response.json()) == expected

    invocation = CliRunner().invoke(
        cli_app,
        ["context", expected.question, "--repository", str(tmp_path), "--tokens", "500"],
    )
    assert invocation.exit_code == 0, invocation.output
    assert ContextBundle.model_validate_json(invocation.output) == expected

    import fetech.mcp_server as mcp_module

    tool = mcp_module.build_server()._tool_manager._tools["get_context"]
    assert ContextBundle.model_validate_json(
        asyncio.run(tool.fn(expected.question, token_budget=500))
    ) == expected
