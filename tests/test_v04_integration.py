"""End-to-end gateway coverage for the v0.4 execution owners."""

from __future__ import annotations

import io
import json
import struct
import zipfile
import zlib
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

from fetech.adapters.browser import BrowserAdapter
from fetech.adapters.cache import ArchivedSnapshot
from fetech.adapters.http import HTTPAdapter
from fetech.browser_render import BrowserRenderResult
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import CapabilityOutcomeStatus, FetchRequest, ResultStatus


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


def _png(width: int = 4, height: int = 3) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(
            ">I", zlib.crc32(kind + data) & 0xFFFFFFFF
        )

    scanline = b"\x00" + (b"\x00\x00\x00" * width)
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)),
            chunk(b"IDAT", zlib.compress(scanline * height)),
            chunk(b"IEND", b""),
        )
    )


def _zip() -> bytes:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(
            "readme.txt",
            b"Bounded archive member with useful deterministic content and source lineage.",
        )
    return stream.getvalue()


def _text_pdf() -> bytes:
    from pypdf import PdfWriter
    from pypdf.generic import (
        DecodedStreamObject,
        DictionaryObject,
        NameObject,
    )

    writer = PdfWriter()
    page = writer.add_blank_page(width=612, height=792)
    font = DictionaryObject(
        {
            NameObject("/Type"): NameObject("/Font"),
            NameObject("/Subtype"): NameObject("/Type1"),
            NameObject("/BaseFont"): NameObject("/Helvetica"),
        }
    )
    page[NameObject("/Resources")] = DictionaryObject(
        {
            NameObject("/Font"): DictionaryObject(
                {NameObject("/F1"): writer._add_object(font)}
            )
        }
    )
    content = DecodedStreamObject()
    content.set_data(
        (
            "BT /F1 12 Tf 72 720 Td "
            "(Useful deterministic PDF text for normalized RAG cache extraction, "
            "accepted quality, exact lineage, and bounded execution.) Tj ET"
        ).encode("ascii")
    )
    page[NameObject("/Contents")] = writer._add_object(content)
    stream = io.BytesIO()
    writer.write(stream)
    return stream.getvalue()


@pytest.mark.parametrize(
    ("target", "capability_id", "media_type", "body", "representation"),
    [
        (
            "https://example.com/readme.txt",
            "txt",
            "text/plain",
            b"Useful bounded text content with stable line locators and source provenance. " * 4,
            "document",
        ),
        (
            "https://example.com/image.png",
            "image_metadata",
            "image/png",
            _png(),
            "media_metadata",
        ),
        (
            "https://example.com/archive.zip",
            "zip_archive",
            "application/zip",
            _zip(),
            "archive_manifest",
        ),
        (
            "https://example.com/article",
            "local_snapshot",
            "text/plain",
            b"Useful validated source content for an immutable local snapshot. " * 4,
            "raw",
        ),
    ],
)
@pytest.mark.asyncio
async def test_gateway_executes_every_v04_owner_with_lineage_and_provenance(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    target: str,
    capability_id: str,
    media_type: str,
    body: bytes,
    representation: str,
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": media_type},
            content=body,
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target=target,
            output_requirements=(capability_id,),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    artifact = next(item for item in result.artifacts if item.representation == representation)
    assert await gateway.cas.verify(artifact.cas_uri)
    assert any(
        outcome.capability_id == capability_id
        and outcome.status == CapabilityOutcomeStatus.APPLIED
        for outcome in result.capability_outcomes
    )
    raw = next(item for item in result.artifacts if item.representation == "raw")
    if artifact.artifact_id != raw.artifact_id:
        assert raw.artifact_id in artifact.parent_artifact_ids
    if capability_id == "zip_archive":
        archive_attempt = next(
            attempt for attempt in result.attempts if attempt.capability_id == "zip_archive"
        )
        assert archive_attempt.consumed_budget["archive_members"] == 1
        assert archive_attempt.consumed_budget["decompressed_bytes"] >= len(
            b"Bounded archive member with useful deterministic content and source lineage."
        )
    assert result.provenance_event_ids
    await gateway.close()


@pytest.mark.asyncio
async def test_gateway_cache_store_is_immediately_retrievable_in_the_exact_partition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=b"Useful cache fixture with enough deterministic content for acceptance. " * 4,
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters
    target = "https://example.com/cacheable"

    stored = await gateway.fetch(
        FetchRequest(
            target=target,
            output_requirements=("local_snapshot",),
        )
    )
    restored = await gateway.fetch(
        FetchRequest(
            target=target,
            output_requirements=("previous_successful_snapshot",),
        )
    )

    assert stored.status == restored.status == ResultStatus.SUCCEEDED
    assert stored.artifacts[-1].sha256 == restored.artifacts[-1].sha256
    assert any(
        event.event_type == "snapshot_stored"
        for event in await gateway.ledger.events(stored.run_id)
    )
    await gateway.close()


@pytest.mark.asyncio
async def test_previous_snapshot_hit_avoids_a_failing_second_http_acquisition(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def initial_response(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=b"Useful prior snapshot content with deterministic cache lineage. " * 4,
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(initial_response),
    )
    gateway.executor.adapters = gateway.adapters
    target = "https://example.com/cache-before-network"
    stored = await gateway.fetch(
        FetchRequest(target=target, output_requirements=("local_snapshot",))
    )

    failed_http_calls = 0

    async def offline(request: httpx.Request) -> httpx.Response:
        nonlocal failed_http_calls
        failed_http_calls += 1
        raise httpx.ConnectError("offline fixture", request=request)

    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(offline),
    )
    gateway.executor.adapters = gateway.adapters
    restored = await gateway.fetch(
        FetchRequest(
            target=target,
            output_requirements=("previous_successful_snapshot",),
        )
    )

    assert stored.status == restored.status == ResultStatus.SUCCEEDED
    assert failed_http_calls == 0
    assert restored.artifacts[-1].sha256 == stored.artifacts[-1].sha256
    assert not any(attempt.capability_id == "http_get" for attempt in restored.attempts)
    assert any(
        outcome.capability_id == "previous_successful_snapshot"
        and outcome.status == CapabilityOutcomeStatus.APPLIED
        for outcome in restored.capability_outcomes
    )
    await gateway.close()


@pytest.mark.asyncio
async def test_policy_blocked_target_never_reaches_a_pre_http_cache_connector(
    tmp_path: Path,
) -> None:
    class NeverConnector:
        calls = 0

        async def fetch_snapshot(
            self,
            original_url: str,
            *,
            maximum_bytes: int,
            deadline_seconds: float,
        ) -> object:
            del original_url, maximum_bytes, deadline_seconds
            self.calls += 1
            raise AssertionError("policy-blocked target reached the connector")

    connector = NeverConnector()
    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        snapshot_connectors={"web_archive": connector},
    )

    result = await gateway.fetch(
        FetchRequest(
            target="http://127.0.0.1/private",
            output_requirements=("web_archive",),
        )
    )

    assert result.status == ResultStatus.BLOCKED_BY_POLICY
    assert connector.calls == 0
    connector_attempt = next(
        attempt
        for attempt in result.attempts
        if attempt.capability_id == "web_archive"
    )
    assert connector_attempt.failure_code == "policy"
    await gateway.close()


@pytest.mark.asyncio
async def test_gateway_produces_clean_text_before_typed_rag_cache_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/plain"},
            content=b"Useful source text for a deterministic RAG cache document. " * 4,
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/raw-only",
            output_requirements=("rag_document_cache",),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    assert {artifact.representation for artifact in result.artifacts} == {
        "raw",
        "clean_text",
    }
    assert any(
        outcome.capability_id == "rag_document_cache"
        and outcome.status == CapabilityOutcomeStatus.APPLIED
        for outcome in result.capability_outcomes
    )
    records = list((tmp_path / "snapshots").rglob("*.json"))
    assert len(records) == 1
    assert json.loads(records[0].read_text())["artifact"]["representation"] == "clean_text"
    await gateway.close()


@pytest.mark.asyncio
async def test_mixed_pdf_and_rag_cache_normalizes_document_blocks_before_storage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))
    body = _text_pdf()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "application/pdf"},
            content=body,
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/report.pdf",
            output_requirements=("pdf", "rag_document_cache"),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    document = next(
        artifact for artifact in result.artifacts
        if artifact.representation == "document"
    )
    clean_text = next(
        artifact for artifact in result.artifacts
        if artifact.representation == "clean_text"
    )
    assert clean_text.parent_artifact_ids == (document.artifact_id,)
    stored = json.loads(
        next((tmp_path / "snapshots").rglob("*.json")).read_text()
    )
    assert stored["artifact"]["representation"] == "clean_text"
    assert stored["artifact"]["sha256"] == clean_text.sha256
    await gateway.close()


@pytest.mark.parametrize(
    "cache_capability",
    ("search_snippet_cache", "search_cache"),
)
@pytest.mark.asyncio
async def test_search_cache_uses_a_configured_search_result_producer_before_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    cache_capability: str,
) -> None:
    class SearchConnector:
        calls = 0

        async def fetch_snapshot(
            self,
            original_url: str,
            *,
            maximum_bytes: int,
            deadline_seconds: float,
        ) -> ArchivedSnapshot:
            del maximum_bytes, deadline_seconds
            self.calls += 1
            return ArchivedSnapshot(
                original_url=original_url,
                snapshot_url="https://search.example/cache/result-set",
                body=(
                    b'{"results":[{"title":"Useful deterministic search result",'
                    b'"url":"https://example.com/article"}]}'
                ),
                media_type="application/json",
                captured_at=datetime(2026, 7, 17, tzinfo=UTC),
            )

    connector = SearchConnector()
    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        snapshot_connectors={"search_engine_cache_adapter": connector},
    )

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/search",
            output_requirements=(cache_capability,),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    assert connector.calls == 1
    assert not any(
        attempt.capability_id == "http_get"
        for attempt in result.attempts
    )
    assert [
        artifact.representation
        for artifact in result.artifacts
    ] == ["search_results"]
    assert any(
        outcome.capability_id == cache_capability
        and outcome.status == CapabilityOutcomeStatus.APPLIED
        for outcome in result.capability_outcomes
    )
    await gateway.close()


@pytest.mark.asyncio
async def test_browser_cache_uses_rendered_html_from_the_browser_producer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Renderer:
        async def render(
            self,
            document: str,
            *,
            target: str,
            user_agent: str,
            timeout_seconds: float,
            maximum_bytes: int,
            operations: frozenset[str],
            wait_selector: str,
            scroll_steps: int,
        ) -> BrowserRenderResult:
            del (
                document,
                target,
                user_agent,
                timeout_seconds,
                maximum_bytes,
                operations,
                wait_selector,
                scroll_steps,
            )
            return BrowserRenderResult(
                html=(
                    "<html><main>Useful deterministic rendered browser content "
                    "with exact cache lineage.</main></html>"
                ),
                visible_text=(
                    "Useful deterministic rendered browser content with exact "
                    "cache lineage."
                ),
                screenshot=None,
                observations={"blocked_requests": 1},
            )

    gateway = UniversalFetchGateway(_settings(tmp_path))

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            content=b"<main>Initial static shell</main>",
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.adapters["browser"] = BrowserAdapter(Renderer())
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/application",
            output_requirements=("browser_cache",),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    rendered = next(
        artifact
        for artifact in result.artifacts
        if artifact.representation == "rendered_html"
    )
    records = list((tmp_path / "snapshots").rglob("*.json"))
    assert len(records) == 1
    stored = json.loads(records[0].read_text())
    assert stored["artifact"]["sha256"] == rendered.sha256
    assert stored["artifact"]["representation"] == "rendered_html"
    await gateway.close()


@pytest.mark.asyncio
async def test_mixed_clean_text_and_snapshot_stores_the_derived_artifact(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    gateway = UniversalFetchGateway(_settings(tmp_path))

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            content=(
                b"<main>Useful derived article text with enough deterministic "
                b"content for validation and exact cache storage.</main>" * 4
            ),
        )

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/derived-cache",
            output_requirements=("clean_text", "local_snapshot"),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    derived = next(
        artifact for artifact in result.artifacts if artifact.representation == "clean_text"
    )
    records = list((tmp_path / "snapshots").rglob("*.json"))
    assert len(records) == 1
    stored = json.loads(records[0].read_text())
    assert stored["artifact"]["representation"] == "clean_text"
    assert stored["artifact"]["sha256"] == derived.sha256
    await gateway.close()
