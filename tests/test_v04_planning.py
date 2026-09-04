"""Deterministic planner coverage for every v0.4 capability family."""

from __future__ import annotations

import pytest

from fetech.models import FetchRequest
from fetech.planning import (
    CACHE_CAPABILITIES,
    DOCUMENT_CAPABILITIES,
    MEDIA_CAPABILITIES,
    PRE_ACQUISITION_CACHE_CAPABILITIES,
    DeterministicPlanner,
    classify_target,
)
from fetech.registry import CapabilityRegistry


def _selected_nodes(capability_id: str) -> tuple[tuple[str, str], ...]:
    plan = DeterministicPlanner(CapabilityRegistry()).plan(
        FetchRequest(
            target="https://example.com/resource",
            output_requirements=(capability_id,),
        )
    )
    return tuple(
        (node.capability_id, node.adapter)
        for node in plan.nodes
        if node.capability_id == capability_id
    )


def test_v04_planner_constants_are_an_exact_manifest_projection() -> None:
    registry = CapabilityRegistry()

    assert set(DOCUMENT_CAPABILITIES) == {
        entry.id for entry in registry.for_category("documents")
    }
    assert set(MEDIA_CAPABILITIES) == {
        entry.id for entry in registry.for_category("media")
    }
    assert set(CACHE_CAPABILITIES) == {
        entry.id for entry in registry.for_category("cache")
    }
    assert (
        len(DOCUMENT_CAPABILITIES),
        len(MEDIA_CAPABILITIES),
        len(CACHE_CAPABILITIES),
    ) == (14, 11, 11)


@pytest.mark.parametrize("capability_id", DOCUMENT_CAPABILITIES)
def test_planner_selects_every_document_capability(capability_id: str) -> None:
    expected_adapter = "archive" if capability_id == "zip_archive" else "documents"
    assert _selected_nodes(capability_id) == ((capability_id, expected_adapter),)


@pytest.mark.parametrize("capability_id", MEDIA_CAPABILITIES)
def test_planner_selects_every_media_capability(capability_id: str) -> None:
    assert _selected_nodes(capability_id) == ((capability_id, "media"),)


@pytest.mark.parametrize("capability_id", CACHE_CAPABILITIES)
def test_planner_selects_every_cache_capability(capability_id: str) -> None:
    assert _selected_nodes(capability_id) == ((capability_id, "cache"),)


def test_planner_preserves_multiple_independent_media_and_cache_outputs() -> None:
    registry = CapabilityRegistry()
    media = DeterministicPlanner(registry).plan(
        FetchRequest(
            target="https://example.com/movie.mp4",
            output_requirements=("video_metadata", "thumbnail", "transcript"),
        )
    )
    cache = DeterministicPlanner(registry).plan(
        FetchRequest(
            target="https://example.com/article",
            output_requirements=("local_snapshot", "rag_document_cache"),
        )
    )

    assert [
        node.capability_id for node in media.nodes if node.adapter == "media"
    ] == ["video_metadata", "transcript", "thumbnail"]
    assert [
        node.capability_id for node in cache.nodes if node.adapter == "cache"
    ] == ["local_snapshot", "rag_document_cache"]


def test_cache_retrieval_alternatives_run_before_http_and_can_short_circuit_it() -> None:
    plan = DeterministicPlanner(CapabilityRegistry()).plan(
        FetchRequest(
            target="https://example.com/article",
            output_requirements=(
                "previous_successful_snapshot",
                "web_archive",
                "cdn_copy",
            ),
        )
    )
    cache_nodes = [node for node in plan.nodes if node.adapter == "cache"]
    http = next(node for node in plan.nodes if node.id == "http")

    assert [node.capability_id for node in cache_nodes] == [
        capability_id
        for capability_id in PRE_ACQUISITION_CACHE_CAPABILITIES
        if capability_id
        in {"previous_successful_snapshot", "web_archive", "cdn_copy"}
    ]
    assert all(plan.nodes.index(node) < plan.nodes.index(http) for node in cache_nodes)
    assert all(node.dependencies == ("policy",) for node in cache_nodes)
    assert cache_nodes[0].fallback_for is None
    assert cache_nodes[1].fallback_for == cache_nodes[0].id
    assert cache_nodes[2].fallback_for == cache_nodes[1].id
    assert http.fallback_for == cache_nodes[-1].id
    assert cache_nodes[0].parameters == {
        "cache_operation": "lookup",
        "representation": "raw",
        "parser_version": "httpx/0.28",
    }


def test_mixed_content_and_cache_outputs_keep_extraction_before_storage() -> None:
    plan = DeterministicPlanner(CapabilityRegistry()).plan(
        FetchRequest(
            target="https://example.com/article",
            output_requirements=("clean_text", "local_snapshot"),
        )
    )
    reader = next(node for node in plan.nodes if node.capability_id == "clean_text")
    cache = next(node for node in plan.nodes if node.capability_id == "local_snapshot")
    browser = next((node for node in plan.nodes if node.id == "browser"), None)
    terminal = browser or reader

    assert classify_target(plan.request.target, plan.request.output_requirements) == "web"
    assert plan.nodes.index(reader) < plan.nodes.index(cache)
    assert cache.dependencies == (terminal.id,)
    if browser is not None:
        assert browser.fallback_for == reader.id


@pytest.mark.parametrize(
    ("cache_capability", "producer_capability", "producer_adapter"),
    [
        ("rag_document_cache", "clean_text", "reader"),
        ("browser_cache", "playwright", "browser"),
        (
            "search_snippet_cache",
            "search_engine_cache_adapter",
            "cache",
        ),
        ("search_cache", "search_engine_cache_adapter", "cache"),
    ],
)
def test_typed_cache_plans_include_an_exact_representation_producer(
    cache_capability: str,
    producer_capability: str,
    producer_adapter: str,
) -> None:
    plan = DeterministicPlanner(CapabilityRegistry()).plan(
        FetchRequest(
            target="https://example.com/article",
            output_requirements=(cache_capability,),
        )
    )
    producer = next(
        node
        for node in plan.nodes
        if node.capability_id == producer_capability
        and node.adapter == producer_adapter
    )
    cache = next(
        node
        for node in plan.nodes
        if node.capability_id == cache_capability
    )

    assert plan.nodes.index(producer) < plan.nodes.index(cache)
    assert cache.dependencies == (producer.id,)


def test_mixed_document_rag_cache_plan_keeps_the_required_typed_producer() -> None:
    plan = DeterministicPlanner(CapabilityRegistry()).plan(
        FetchRequest(
            target="https://example.com/report.pdf",
            output_requirements=("pdf", "rag_document_cache"),
        )
    )
    document = next(node for node in plan.nodes if node.capability_id == "pdf")
    producer = next(
        node
        for node in plan.nodes
        if node.capability_id == "clean_text"
        and node.adapter == "reader"
    )
    cache = next(
        node for node in plan.nodes if node.capability_id == "rag_document_cache"
    )

    assert plan.nodes.index(document) < plan.nodes.index(cache)
    assert plan.nodes.index(producer) < plan.nodes.index(cache)
    assert cache.dependencies == (producer.id,)
    assert producer.dependencies == (document.id,)


def test_browser_cache_rejects_non_html_source_families() -> None:
    with pytest.raises(ValueError, match="HTML-like targets"):
        DeterministicPlanner(CapabilityRegistry()).plan(
            FetchRequest(
                target="https://example.com/report.pdf",
                output_requirements=("pdf", "browser_cache"),
            )
        )


@pytest.mark.parametrize(
    "outputs",
    [
        ("pdf", "thumbnail"),
        ("clean_text", "thumbnail"),
        ("json_file", "image_metadata"),
    ],
)
def test_cross_family_schedulable_outputs_are_never_silently_dropped(
    outputs: tuple[str, str],
) -> None:
    with pytest.raises(ValueError, match="cannot be combined"):
        DeterministicPlanner(CapabilityRegistry()).plan(
            FetchRequest(
                target="https://example.com/resource",
                output_requirements=outputs,
            )
        )


@pytest.mark.parametrize(
    ("target", "outputs", "family"),
    [
        ("https://example.com/readme.md", ("clean_text",), "document"),
        ("https://example.com/data.json", ("json_file",), "document"),
        ("https://example.com/data.json", ("clean_text",), "api"),
        ("https://example.com/image.webp", ("clean_text",), "media"),
        ("https://example.com/archive.zip", ("clean_text",), "archive"),
        ("https://example.com/page", ("local_snapshot",), "cache"),
    ],
)
def test_v04_classification_uses_explicit_capabilities_before_suffix_heuristics(
    target: str,
    outputs: tuple[str, ...],
    family: str,
) -> None:
    assert classify_target(target, outputs) == family


def test_v04_nodes_reserve_the_relevant_bounded_resources() -> None:
    plan = DeterministicPlanner(CapabilityRegistry()).plan(
        FetchRequest(
            target="https://example.com/archive.zip",
            output_requirements=("zip_archive",),
        )
    )
    archive = next(node for node in plan.nodes if node.adapter == "archive")

    assert archive.reserved_budget["archive_members"] == plan.request.budget.archive_members
    assert archive.reserved_budget["archive_ratio"] == plan.request.budget.archive_ratio
    assert (
        archive.reserved_budget["decompressed_bytes"]
        == plan.request.budget.decompressed_bytes
    )
