"""Frozen Beta v1 public-surface and pre-Beta migration conformance."""

from __future__ import annotations

import copy
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest
from pydantic import BaseModel, ValidationError

from fetech.compatibility import (
    CompatibilityBaselineError,
    build_compatibility_snapshot,
    compatibility_differences,
    load_compatibility_baseline,
    verify_compatibility_baseline,
)
from fetech.models import Artifact, FetchPlan, FetchRequest, FetchResult

_ROOT = Path(__file__).parents[1]
_BASELINE = _ROOT / "compatibility" / "beta-v1.json"
_MIGRATION_FIXTURES = _ROOT / "compatibility" / "fixtures" / "v0.4.0a0-contracts.json"
_MODELS: dict[str, type[BaseModel]] = {
    "Artifact": Artifact,
    "FetchPlan": FetchPlan,
    "FetchRequest": FetchRequest,
    "FetchResult": FetchResult,
}


def _assert_subset(actual: object, expected: object) -> None:
    if isinstance(expected, Mapping):
        assert isinstance(actual, Mapping)
        for field_name, value in expected.items():
            assert field_name in actual
            _assert_subset(actual[field_name], value)
        return
    assert actual == expected


def _migration_cases() -> list[dict[str, Any]]:
    document = json.loads(_MIGRATION_FIXTURES.read_text(encoding="utf-8"))
    assert document["schema_version"] == "1.0"
    assert document["source_version"] == "0.4.0a0"
    cases = document["cases"]
    assert isinstance(cases, list)
    return cases


def test_current_public_surface_exactly_matches_frozen_beta_v1() -> None:
    baseline = load_compatibility_baseline(_BASELINE)
    first = build_compatibility_snapshot()
    second = build_compatibility_snapshot()

    assert first == second
    assert compatibility_differences(baseline, first) == ()
    assert verify_compatibility_baseline(_BASELINE) == ()
    assert str(_ROOT) not in json.dumps(first, sort_keys=True)
    assert len(first["contracts"]) == 25
    assert len(first["rest"]["operations"]) == 14
    assert len(first["cli"]["commands"]) == 12
    assert len(first["mcp"]["tools"]) == 13
    assert set(first["sdk"]["classes"]) == {"FetchHandle", "FetechClient"}


def test_snapshot_is_independent_of_the_callers_working_directory(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    expected = build_compatibility_snapshot()

    monkeypatch.chdir(tmp_path)

    assert build_compatibility_snapshot() == expected


def test_fail_closed_checker_reports_each_public_plane() -> None:
    baseline = load_compatibility_baseline(_BASELINE)
    changed = copy.deepcopy(baseline)
    changed["contracts"].pop("FetchRequest")
    changed["sdk"]["classes"]["FetechClient"]["methods"].pop("fetch")
    changed["rest"]["operations"].pop()
    changed["cli"]["commands"].pop("fetch")
    changed["mcp"]["tools"].pop("fetch_content")

    differences = compatibility_differences(baseline, changed)

    assert any(item == "$.contracts.FetchRequest: removed" for item in differences)
    assert any(
        item == "$.sdk.classes.FetechClient.methods.fetch: removed" for item in differences
    )
    assert any(item.startswith("$.rest.operations") for item in differences)
    assert any(item == "$.cli.commands.fetch: removed" for item in differences)
    assert any(item == "$.mcp.tools.fetch_content: removed" for item in differences)


def test_baseline_loader_fails_closed_for_missing_malformed_and_unknown_files(
    tmp_path: Path,
) -> None:
    with pytest.raises(CompatibilityBaselineError, match="unavailable"):
        load_compatibility_baseline(tmp_path / "missing.json")

    malformed = tmp_path / "malformed.json"
    malformed.write_text("not-json", encoding="utf-8")
    with pytest.raises(CompatibilityBaselineError, match="UTF-8 JSON"):
        load_compatibility_baseline(malformed)

    unknown = tmp_path / "unknown.json"
    unknown.write_text(
        json.dumps({"schema_version": "2.0", "baseline_id": "beta-v1"}),
        encoding="utf-8",
    )
    with pytest.raises(CompatibilityBaselineError, match="schema version"):
        load_compatibility_baseline(unknown)


@pytest.mark.parametrize("case", _migration_cases(), ids=lambda case: str(case["model"]))
def test_v04_documents_without_schema_versions_migrate_and_round_trip(
    case: dict[str, Any],
) -> None:
    model = _MODELS[case["model"]]
    migrated = model.model_validate(case["input"])
    canonical = migrated.model_dump(mode="json")

    _assert_subset(canonical, case["expected_subset"])
    assert model.model_validate(canonical) == migrated


@pytest.mark.parametrize("case", _migration_cases(), ids=lambda case: str(case["model"]))
def test_v04_documents_with_unknown_explicit_versions_fail_closed(
    case: dict[str, Any],
) -> None:
    model = _MODELS[case["model"]]
    document = copy.deepcopy(case["input"])
    document["schema_version"] = "2.0"

    with pytest.raises(ValidationError, match=r"1\.0"):
        model.model_validate(document)
