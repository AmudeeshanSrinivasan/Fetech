from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from fetech.cli import app
from fetech.client import FetechClient
from fetech.config import Settings
from fetech.models import FetchRequest, FetchResult, ResultStatus


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


@pytest.mark.asyncio
async def test_sdk_crawl_sets_canonical_intent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FetechClient(_settings(tmp_path))
    observed: list[FetchRequest] = []

    async def fake_fetch(request: FetchRequest) -> FetchResult:
        observed.append(request)
        return FetchResult(status=ResultStatus.SUCCEEDED)

    monkeypatch.setattr(client.gateway, "fetch", fake_fetch)
    result = await client.crawl(FetchRequest(target="https://example.com"))
    assert result.status == ResultStatus.SUCCEEDED
    assert observed[0].intent == "crawl"


def test_cli_exposes_bounded_crawl_command() -> None:
    result = CliRunner(env={"COLUMNS": "30"}).invoke(app, ["crawl", "--help"])
    assert result.exit_code == 0
    assert "--max-pages" in result.stdout
    assert "--max-depth" in result.stdout
    assert "--search" in result.stdout
