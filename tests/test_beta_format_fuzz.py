"""Format-aware bounded fuzzing for parsers and worker IPC envelopes."""

from __future__ import annotations

import base64
import io
import math
import string
import tarfile
import zipfile
from urllib.parse import urlsplit

import pytest
import yaml
from hypothesis import given
from hypothesis import strategies as st

from fetech.adapters.api import NormalizedAPI, normalize_api_payload
from fetech.adapters.archive import _extract_members
from fetech.adapters.base import AdapterExecutionError
from fetech.adapters.discovery import _DiscoveryParser
from fetech.adapters.documents import (
    DocumentLimits,
    PDFOCRPage,
    _validate_pdf_ocr_pages,
    _validate_worker_result,
)
from fetech.adapters.http import _NavigationParser
from fetech.adapters.reader import _normalized_document_text, extract_visible_text
from fetech.browser_reader import BrowserReaderWorker
from fetech.browser_render import BrowserRenderWorker, _parse_result
from fetech.logic.process import ProcessResult

_TEXT = st.one_of(
    st.text(max_size=256),
    st.sampled_from(("\ud800", "https://\ud800.example/", "query=\udfff")),
)
_SAFE_SEGMENT = st.text(
    alphabet=string.ascii_letters + string.digits + "-_",
    min_size=1,
    max_size=20,
)
_SAFE_VISIBLE_TEXT = st.text(
    alphabet=string.ascii_letters + string.digits + " -_",
    min_size=1,
    max_size=48,
).filter(lambda value: bool(value.strip()))
_SAFE_PATHS = st.lists(_SAFE_SEGMENT, min_size=1, max_size=12, unique=True)


@given(
    st.sampled_from(("rss", "atom", "sitemap_xml")),
    _SAFE_PATHS,
    st.integers(min_value=1, max_value=5),
)
def test_valid_feed_families_are_deterministic_and_record_bounded(
    capability: str,
    identifiers: list[str],
    maximum_records: int,
) -> None:
    if capability == "rss":
        records = "".join(
            f"<item><title>{identifier}</title>"
            f"<link>https://example.test/{identifier}</link>"
            f"<guid>{identifier}</guid></item>"
            for identifier in identifiers
        )
        body = (
            f'<rss version="2.0"><channel><title>fixture</title>{records}'
            "</channel></rss>"
        )
        record_field = "items"
    elif capability == "atom":
        records = "".join(
            f"<entry><title>{identifier}</title><id>{identifier}</id>"
            f'<link href="https://example.test/{identifier}" /></entry>'
            for identifier in identifiers
        )
        body = (
            '<feed xmlns="http://www.w3.org/2005/Atom"><title>fixture</title>'
            f"{records}</feed>"
        )
        record_field = "entries"
    else:
        records = "".join(
            f"<url><loc>https://example.test/{identifier}</loc></url>"
            for identifier in identifiers
        )
        body = (
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            f"{records}</urlset>"
        )
        record_field = "records"

    def parse() -> NormalizedAPI:
        return normalize_api_payload(
            capability,
            body.encode(),
            media_type="application/xml",
            source_url="https://example.test/source.xml",
            authority_url="https://example.test/source.xml",
            maximum_nodes=256,
            maximum_depth=8,
            maximum_records=maximum_records,
        )

    first = parse()
    assert parse() == first
    assert len(first.document["data"][record_field]) == min(
        len(identifiers), maximum_records
    )
    assert first.omitted_records == max(0, len(identifiers) - maximum_records)
    assert len(first.locators) <= maximum_records
    assert len(first.locators) == len(set(first.locators))


@given(_SAFE_PATHS, st.integers(min_value=1, max_value=5))
def test_valid_openapi_yaml_is_deterministic_and_path_bounded(
    paths: list[str],
    maximum_records: int,
) -> None:
    document = {
        "openapi": "3.1.0",
        "info": {"title": "bounded fixture", "version": "1"},
        "paths": {
            f"/{path}": {
                "get": {"responses": {"200": {"description": "ok"}}}
            }
            for path in paths
        },
    }
    body = yaml.safe_dump(document, sort_keys=True).encode()

    def parse() -> NormalizedAPI:
        return normalize_api_payload(
            "openapi_discovery",
            body,
            media_type="application/yaml",
            source_url="https://example.test/openapi.yaml",
            authority_url="https://example.test/openapi.yaml",
            maximum_nodes=512,
            maximum_depth=12,
            maximum_records=maximum_records,
        )

    first = parse()
    assert parse() == first
    assert len(first.document["data"]["paths"]) == min(
        len(paths), maximum_records
    )
    assert first.omitted_records == max(0, len(paths) - maximum_records)
    assert len(first.locators) <= maximum_records


@given(_SAFE_SEGMENT)
def test_openapi_yaml_rejects_generated_duplicate_paths(path: str) -> None:
    body = (
        "openapi: 3.1.0\n"
        "info:\n  title: duplicate fixture\n  version: '1'\n"
        f"paths:\n  /{path}: {{}}\n  /{path}: {{}}\n"
    ).encode()
    with pytest.raises(yaml.YAMLError):
        normalize_api_payload(
            "openapi_discovery",
            body,
            media_type="application/yaml",
            source_url="https://example.test/openapi.yaml",
            authority_url="https://example.test/openapi.yaml",
            maximum_nodes=64,
            maximum_depth=8,
            maximum_records=8,
        )


@given(
    st.lists(
        st.tuples(
            _SAFE_SEGMENT,
            st.sampled_from(("internal", "next", "prev", "related", "tag")),
        ),
        min_size=1,
        max_size=12,
        unique_by=lambda item: item[0],
    ),
    st.lists(_SAFE_VISIBLE_TEXT, min_size=1, max_size=5),
)
def test_html_reader_and_discovery_are_deterministic_and_scheme_bounded(
    links: list[tuple[str, str]],
    visible_parts: list[str],
) -> None:
    hidden = "FETECH_HIDDEN_SCRIPT_PROBE"
    anchors = "".join(
        f'<a href="/{path}" rel="{relation if relation != "internal" else ""}">'
        f"{path}</a>"
        for path, relation in links
    )
    document = (
        "<html><head><style>FETECH_HIDDEN_STYLE_PROBE</style></head><body>"
        + " ".join(visible_parts)
        + anchors
        + f"<script>{hidden}</script>"
        + '<a href="javascript:alert(1)">unsafe</a>'
        + '<a href="mailto:private@example.test">mail</a></body></html>'
    )
    text = extract_visible_text(document)
    assert extract_visible_text(document) == text
    assert hidden not in text
    assert "FETECH_HIDDEN_STYLE_PROBE" not in text
    assert all(part.strip() in text for part in visible_parts)

    parser = _DiscoveryParser("https://example.test/base/")
    parser.feed(document)
    expected_relations = {
        "internal": "internal",
        "next": "next",
        "prev": "pagination",
        "related": "related",
        "tag": "category",
    }
    assert parser.links == [
        (f"https://example.test/{path}", expected_relations[relation])
        for path, relation in links
    ]
    assert all(
        urlsplit(candidate).scheme == "https" for candidate, _ in parser.links
    )


@given(st.lists(_SAFE_SEGMENT, min_size=4, max_size=4, unique=True))
def test_html_navigation_metadata_is_deterministic(paths: list[str]) -> None:
    document = (
        f'<link rel="canonical" href="/{paths[0]}">'
        f'<meta property="og:url" content="/{paths[1]}">'
        f'<meta http-equiv="refresh" content="0; url=/{paths[2]}">'
        f'<script>window.location = "/{paths[3]}";</script>'
    )
    expected = {
        "canonical_redirect": f"https://example.test/{paths[0]}",
        "opengraph_url_redirect": f"https://example.test/{paths[1]}",
        "meta_refresh_redirect": f"https://example.test/{paths[2]}",
        "javascript_redirect": f"https://example.test/{paths[3]}",
    }
    for _ in range(2):
        parser = _NavigationParser("https://example.test/base/")
        parser.feed(document)
        assert parser.candidates == expected


@given(_TEXT, _TEXT, st.binary(max_size=256))
def test_browser_worker_envelope_returns_a_typed_result_or_typed_rejection(
    html: str,
    visible_text: str,
    screenshot: bytes,
) -> None:
    envelope = {
        "html": html,
        "visible_text": visible_text,
        "screenshot": base64.b64encode(screenshot).decode("ascii"),
        "observations": {"blocked_requests": 1, "network_idle": True},
    }
    try:
        result = _parse_result(envelope, maximum_bytes=1_024)
    except AdapterExecutionError:
        return
    assert result.html == html
    assert result.visible_text == visible_text
    assert result.screenshot == screenshot
    assert (
        len(html.encode()) + len(visible_text.encode()) + len(screenshot) <= 1_024
    )


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_browser_worker_envelope_rejects_non_finite_observations(
    value: float,
) -> None:
    with pytest.raises(AdapterExecutionError, match="observations are invalid"):
        _parse_result(
            {
                "html": "ok",
                "visible_text": "ok",
                "observations": {"timing": value},
            },
            maximum_bytes=100,
        )


@given(_TEXT)
def test_document_worker_envelope_returns_a_typed_result_or_typed_rejection(
    text: str,
) -> None:
    envelope = {
        "document": {
            "type": "text",
            "blocks": [{"locator": "line:1", "text": text}],
        },
        "locators": ["line:1"],
        "parser": "text",
        "observed_capability": "txt",
        "parser_components": {},
        "artifact_bundle_id": None,
        "fallback_reason": None,
    }
    try:
        parsed = _validate_worker_result(
            envelope,
            limits=DocumentLimits(maximum_output_bytes=1_024, maximum_blocks=4),
            expected_observed="txt",
        )
    except AdapterExecutionError:
        return
    assert parsed.document == envelope["document"]


def test_document_ocr_and_reader_type_invalid_unicode() -> None:
    with pytest.raises(AdapterExecutionError, match="invalid output"):
        _validate_pdf_ocr_pages(
            [PDFOCRPage(locator="page:1", text="\ud800")],
            page_count=1,
            maximum_blocks=1,
            maximum_output_bytes=1_024,
        )
    with pytest.raises(AdapterExecutionError, match="invalid normalized document"):
        _normalized_document_text(
            b'{"blocks":[{"text":"\\ud800"}]}',
            maximum_bytes=1_024,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("worker_kind", ["render", "reader"])
async def test_browser_workers_type_malformed_utf8_process_output(
    worker_kind: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def malformed_worker(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        return ProcessResult(
            returncode=0,
            stdout=b"\xff",
            stderr=b"private worker detail",
        )

    if worker_kind == "render":
        monkeypatch.setattr("fetech.browser_render.run_bounded", malformed_worker)
        with pytest.raises(AdapterExecutionError, match="malformed output") as caught:
            await BrowserRenderWorker().render(
                "<main>fixture</main>",
                target="https://example.test",
                user_agent="Fetech/test",
                timeout_seconds=1,
                maximum_bytes=1_024,
                operations=frozenset({"visible_text"}),
                wait_selector="body",
                scroll_steps=1,
            )
    else:
        monkeypatch.setattr("fetech.browser_reader.run_bounded", malformed_worker)
        with pytest.raises(AdapterExecutionError, match="malformed output") as caught:
            await BrowserReaderWorker().extract(
                "<main>fixture</main>",
                target="https://example.test",
                user_agent="Fetech/test",
                timeout_seconds=1,
                maximum_bytes=1_024,
            )
    assert "private worker detail" not in str(caught.value)


@pytest.mark.asyncio
async def test_browser_reader_types_invalid_unicode_worker_text(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def invalid_text(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        return ProcessResult(
            returncode=0,
            stdout=b'{"text":"\\ud800"}',
            stderr=b"private worker detail",
        )

    monkeypatch.setattr("fetech.browser_reader.run_bounded", invalid_text)
    with pytest.raises(AdapterExecutionError, match="invalid Unicode text"):
        await BrowserReaderWorker().extract(
            "<main>fixture</main>",
            target="https://example.test",
            user_agent="Fetech/test",
            timeout_seconds=1,
            maximum_bytes=1_024,
        )


@pytest.mark.asyncio
@pytest.mark.parametrize("worker_kind", ["render", "reader"])
async def test_browser_workers_type_invalid_unicode_input(worker_kind: str) -> None:
    with pytest.raises(AdapterExecutionError, match="input is not valid Unicode text"):
        if worker_kind == "render":
            await BrowserRenderWorker().render(
                "\ud800",
                target="https://example.test",
                user_agent="Fetech/test",
                timeout_seconds=1,
                maximum_bytes=1_024,
                operations=frozenset({"visible_text"}),
                wait_selector="body",
                scroll_steps=1,
            )
        else:
            await BrowserReaderWorker().extract(
                "\ud800",
                target="https://example.test",
                user_agent="Fetech/test",
                timeout_seconds=1,
                maximum_bytes=1_024,
            )

@given(
    st.lists(
        st.tuples(_SAFE_SEGMENT, st.binary(max_size=128)),
        min_size=1,
        max_size=8,
        unique_by=lambda item: item[0].casefold(),
    )
)
def test_valid_zip_archives_round_trip_with_member_bounds(
    entries: list[tuple[str, bytes]],
) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        for name, content in entries:
            archive.writestr(f"{name}.bin", content)
    members = _extract_members(
        output.getvalue(),
        maximum_members=8,
        maximum_expanded=1_024,
        maximum_ratio=20,
    )
    assert members == [(f"{name}.bin", content) for name, content in entries]
    assert sum(len(content) for _, content in members) <= 1_024


@given(st.integers(min_value=1, max_value=64))
def test_structured_zip_truncation_fails_closed(removed_bytes: int) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr("bounded.txt", b"deterministic archive mutation fixture")
    body = output.getvalue()
    truncated = body[: -min(removed_bytes, len(body))]
    with pytest.raises(
        (EOFError, OSError, ValueError, tarfile.TarError, zipfile.BadZipFile)
    ):
        _extract_members(
            truncated,
            maximum_members=4,
            maximum_expanded=128,
            maximum_ratio=20,
        )


@pytest.mark.parametrize(
    "member_name",
    ["../escape", "/absolute", "nested/../../escape"],
)
def test_zip_archives_reject_unsafe_member_paths(member_name: str) -> None:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_STORED) as archive:
        archive.writestr(member_name, b"bounded")
    with pytest.raises(ValueError):
        _extract_members(
            output.getvalue(),
            maximum_members=4,
            maximum_expanded=128,
            maximum_ratio=20,
        )
