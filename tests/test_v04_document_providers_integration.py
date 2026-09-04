"""Gateway integration for bounded document provider injection."""

from __future__ import annotations

import io
from hashlib import sha256
from pathlib import Path

import httpx
import pytest

from fetech.adapters.documents import (
    GitLFSResolvedObject,
    GitLFSResolveRequest,
    PDFOCRPage,
)
from fetech.adapters.http import HTTPAdapter
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.models import FetchRequest, ResultStatus


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
    )


def _pdf() -> bytes:
    from pypdf import PdfWriter

    stream = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.write(stream)
    return stream.getvalue()


def _lfs_pointer(body: bytes) -> bytes:
    return (
        b"version https://git-lfs.github.com/spec/v1\n"
        b"oid sha256:"
        + sha256(body).hexdigest().encode("ascii")
        + b"\nsize "
        + str(len(body)).encode("ascii")
        + b"\n"
    )


def _wire_http(
    gateway: UniversalFetchGateway,
    *,
    media_type: str,
    body: bytes,
) -> HTTPAdapter:
    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": media_type},
            content=body,
        )

    return HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=gateway.policy,
        transport=httpx.MockTransport(respond),
    )


@pytest.mark.asyncio
async def test_gateway_executes_injected_exact_origin_git_lfs_resolver(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    resolved_body = b"Useful resolved Git LFS content with stable provenance. " * 5

    class Resolver:
        async def resolve(
            self,
            request: GitLFSResolveRequest,
        ) -> GitLFSResolvedObject:
            return GitLFSResolvedObject(origin=request.origin, body=resolved_body)

    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        git_lfs_resolver=Resolver(),
    )

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = _wire_http(
        gateway,
        media_type="text/plain",
        body=_lfs_pointer(resolved_body),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://git.example/owner/repo/asset.bin",
            output_requirements=("git_lfs",),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    document = next(
        item for item in result.artifacts if item.representation == "document"
    )
    raw = next(item for item in result.artifacts if item.representation == "raw")
    assert raw.artifact_id in document.parent_artifact_ids
    assert document.quality.accepted
    assert any(
        attempt.capability_id == "git_lfs"
        and attempt.parser == "text"
        and attempt.bytes_received == len(resolved_body)
        for attempt in result.attempts
    )
    await gateway.close()


@pytest.mark.asyncio
async def test_gateway_executes_injected_scanned_pdf_ocr_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class OCR:
        async def extract_pdf(
            self,
            body: bytes,
            *,
            page_count: int,
            language: str | None,
            timeout_seconds: float,
            maximum_output_bytes: int,
        ) -> tuple[PDFOCRPage, ...]:
            del body, language, timeout_seconds, maximum_output_bytes
            assert page_count == 1
            return (
                PDFOCRPage(
                    locator="page:1",
                    text="Useful bounded OCR result with stable page provenance. " * 5,
                ),
            )

    gateway = UniversalFetchGateway(
        _settings(tmp_path),
        pdf_ocr_provider=OCR(),
    )

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(gateway.policy, "_resolve", public)
    gateway.adapters["http"] = _wire_http(
        gateway,
        media_type="application/pdf",
        body=_pdf(),
    )
    gateway.executor.adapters = gateway.adapters

    result = await gateway.fetch(
        FetchRequest(
            target="https://publisher.example/scanned.pdf",
            output_requirements=("scanned_pdf",),
        )
    )

    assert result.status == ResultStatus.SUCCEEDED
    document = next(
        item for item in result.artifacts if item.representation == "document"
    )
    raw = next(item for item in result.artifacts if item.representation == "raw")
    assert document.quality.accepted
    assert raw.artifact_id in document.parent_artifact_ids
    assert any(
        attempt.capability_id == "scanned_pdf"
        and attempt.parser == "configured-pdf-ocr"
        for attempt in result.attempts
    )
    await gateway.close()
