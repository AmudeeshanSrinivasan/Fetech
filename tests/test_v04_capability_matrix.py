"""Mechanical v0.4 evidence matrix for all 36 canonical capability IDs."""

from __future__ import annotations

import ast
import importlib
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from fetech.models import FetchRequest, ImplementationStatus
from fetech.planning import (
    CACHE_CAPABILITIES,
    DOCUMENT_CAPABILITIES,
    MEDIA_CAPABILITIES,
    DeterministicPlanner,
)
from fetech.registry import CapabilityRegistry

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "capability-catalog.md"
NODE_ID = re.compile(
    r"^tests/[a-zA-Z0-9_./-]+\.py::test_[a-zA-Z0-9_]+"
    r"(?:\[[a-zA-Z0-9_./:-]+\])?$"
)


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    capability_id: str
    implementation_symbol: str
    owner_adapter: str
    behavior_test: str


def _document(capability_id: str) -> CapabilityEvidence:
    archive = capability_id == "zip_archive"
    behavior_test = (
        "tests/test_v04_documents.py::"
        f"test_real_isolated_worker_normalizes_every_document_capability[{capability_id}]"
    )
    if capability_id == "scanned_pdf":
        behavior_test = (
            "tests/test_v04_documents.py::"
            "test_configured_pdf_ocr_transitions_needs_ocr_to_accepted_with_lineage"
        )
    elif capability_id == "github_raw":
        behavior_test = (
            "tests/test_v04_documents.py::"
            "test_github_raw_accepts_only_the_exact_raw_origin_and_file_path"
        )
    elif capability_id == "git_lfs":
        behavior_test = (
            "tests/test_v04_documents.py::"
            "test_git_lfs_resolver_is_exact_origin_sanitized_bounded_and_lineaged"
        )
    elif archive:
        behavior_test = (
            "tests/test_v04_cache_archives.py::"
            "test_real_archive_worker_is_ephemeral_and_returns_bounded_members"
        )
    return CapabilityEvidence(
        capability_id=capability_id,
        implementation_symbol=(
            "fetech.adapters.archive:ArchiveAdapter"
            if archive
            else "fetech.adapters.documents:DocumentAdapter"
        ),
        owner_adapter="archive" if archive else "documents",
        behavior_test=behavior_test,
    )


def _media(capability_id: str) -> CapabilityEvidence:
    return CapabilityEvidence(
        capability_id=capability_id,
        implementation_symbol=(
            "fetech.yt_dlp:YTDLPMetadataWorker"
            if capability_id == "youtube_metadata"
            else "fetech.adapters.media:MediaAdapter"
        ),
        owner_adapter="media",
        behavior_test=(
            (
                "tests/test_v04_ytdlp.py::"
                "test_ytdlp_provider_uses_a_fixed_isolated_bounded_worker"
            )
            if capability_id == "youtube_metadata"
            else (
                "tests/test_v04_media.py::"
                "test_all_eleven_media_capabilities_have_bounded_artifact_paths"
            )
        ),
    )


def _cache(capability_id: str) -> CapabilityEvidence:
    return CapabilityEvidence(
        capability_id=capability_id,
        implementation_symbol=(
            "fetech.wayback:WaybackSnapshotConnector"
            if capability_id == "internet_archive_snapshot"
            else "fetech.adapters.cache:CacheAdapter"
        ),
        owner_adapter="cache",
        behavior_test=_cache_behavior_test(capability_id),
    )


def _cache_behavior_test(capability_id: str) -> str:
    if capability_id == "internet_archive_snapshot":
        return (
            "tests/test_wayback.py::"
            "test_builtin_wayback_connector_fetches_an_exact_bounded_capture"
        )
    if capability_id == "previous_successful_snapshot":
        return (
            "tests/test_v04_cache_archives.py::"
            "test_previous_successful_snapshot_restores_the_exact_partition"
        )
    if capability_id in {
        "search_engine_cache_adapter",
        "alternate_search_cache_adapter",
        "web_archive",
        "internet_archive_snapshot",
        "cdn_copy",
    }:
        return (
            "tests/test_v04_cache_archives.py::"
            "test_optional_connectors_preserve_original_authority_and_store_snapshot"
        )
    return (
        "tests/test_v04_cache_archives.py::"
        "test_native_storage_strategies_store_only_validated_immutable_artifacts"
    )


CASES = (
    *(_document(capability_id) for capability_id in DOCUMENT_CAPABILITIES),
    *(_media(capability_id) for capability_id in MEDIA_CAPABILITIES),
    *(_cache(capability_id) for capability_id in CACHE_CAPABILITIES),
)
CASE_BY_ID = {case.capability_id: case for case in CASES}

OWNER_SYMBOLS = {
    "archive": "fetech.adapters.archive:ArchiveAdapter",
    "cache": "fetech.adapters.cache:CacheAdapter",
    "documents": "fetech.adapters.documents:DocumentAdapter",
    "media": "fetech.adapters.media:MediaAdapter",
}


def _import_symbol(reference: str) -> object:
    module_name, symbol_name = reference.split(":", maxsplit=1)
    module = importlib.import_module(module_name)
    return getattr(module, symbol_name)


def _test_function_exists(node_id: str) -> bool:
    path_text, target = node_id.split("::", maxsplit=1)
    function_name = target.split("[", maxsplit=1)[0]
    path = ROOT / path_text
    if not path.is_file():
        return False
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
        for node in tree.body
    )


def _request_for(case: CapabilityEvidence) -> FetchRequest:
    suffix = ".zip" if case.capability_id == "zip_archive" else ""
    return FetchRequest(
        target=f"https://example.com/resource{suffix}",
        output_requirements=(case.capability_id,),
    )


def test_v04_matrix_is_an_exact_projection_of_the_manifest() -> None:
    registry = CapabilityRegistry()
    v04_ids = {
        entry.id for entry in registry if entry.closure_release == "v0.4"
    }

    assert len(registry.categories) == 13
    assert len(registry) == 155
    assert len(CASES) == len(CASE_BY_ID) == 36
    assert set(CASE_BY_ID) == v04_ids


def test_v04_closure_is_155_cumulative_capabilities() -> None:
    releases = CapabilityRegistry().as_document()["releases"]

    assert releases["v0.4"] == {
        "release": "v0.4",
        "capability_count": 36,
        "implementation_path_count": 36,
        "runtime_available_count": 17,
        "closure_ready": True,
        "status_counts": {"native": 17, "optional": 19},
        "gaps": [],
    }
    assert sum(
        int(releases[release]["implementation_path_count"])
        for release in ("v0.1", "v0.2", "v0.3", "v0.4")
    ) == 155


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.capability_id)
def test_v04_capability_evidence_matrix(
    case: CapabilityEvidence,
    request: pytest.FixtureRequest,
) -> None:
    registry = CapabilityRegistry()
    entry = registry.get(case.capability_id)
    anchor = case.capability_id.replace("_", "-")
    evidence_node = (
        "tests/test_v04_capability_matrix.py::"
        f"test_v04_capability_evidence_matrix[{case.capability_id}]"
    )

    assert entry.reference == f"docs/capability-catalog.md#{anchor}"
    assert f'<a id="{anchor}"></a>' in CATALOG.read_text(encoding="utf-8")
    assert entry.tests == (evidence_node, case.behavior_test)
    assert request.node.nodeid == evidence_node

    implementation = _import_symbol(case.implementation_symbol)
    owner = _import_symbol(OWNER_SYMBOLS[case.owner_adapter])
    assert implementation is not None
    assert owner is not None
    assert entry.adapter == case.owner_adapter
    module_name, symbol_name = case.implementation_symbol.split(":", maxsplit=1)
    assert module_name in entry.implementation
    assert symbol_name in entry.implementation

    plan = DeterministicPlanner(registry).plan(_request_for(case))
    assert any(
        node.adapter == case.owner_adapter
        and node.capability_id == case.capability_id
        for node in plan.nodes
    )

    assert NODE_ID.fullmatch(evidence_node)
    assert NODE_ID.fullmatch(case.behavior_test)
    assert _test_function_exists(evidence_node)
    assert _test_function_exists(case.behavior_test)
    assert entry.implementation_status in {
        ImplementationStatus.NATIVE,
        ImplementationStatus.OPTIONAL,
    }
