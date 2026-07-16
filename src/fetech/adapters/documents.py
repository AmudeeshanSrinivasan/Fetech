"""Bounded document parsing with stable source locators."""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlsplit

from fetech.adapters.base import AdapterDependencyError, AdapterExecutionError, ExecutionContext
from fetech.models import AttemptStatus, FetchAttempt, PageState, PlanNode, QualityAssessment
from fetech.quality import assess_text
from fetech.security import sanitize_url
from fetech.storage import build_artifact

_TAGS = re.compile(r"<[^>]+>")


class DocumentAdapter:
    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        raw = context.latest_artifact("raw")
        if raw is None or not context.resources:
            raise AdapterExecutionError("document parsing requires a source artifact")
        body = await context.cas.get(raw.cas_uri, maximum_bytes=context.request.budget.bytes)
        parser_capability = _detect_capability(node.capability_id, context.request.target, body)
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        try:
            document, locators, parser = _parse(parser_capability, body)
        except ImportError as exc:
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "dependency_missing",
                    "warnings": (str(exc),),
                }
            )
            raise AdapterDependencyError(str(exc)) from exc
        except (OSError, ValueError, KeyError) as exc:
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "malformed_document",
                    "warnings": (str(exc),),
                }
            )
            raise AdapterExecutionError(str(exc)) from exc
        text = _document_text(document)
        quality = assess_text(text, expected_language=context.request.language)
        if parser_capability == "pdf" and not text.strip():
            quality = QualityAssessment(
                page_state=PageState.NEEDS_OCR,
                score=0,
                accepted=False,
                completeness=0,
                reasons=("PDF contains no extractable text",),
            )
        encoded = json.dumps(document, ensure_ascii=False, sort_keys=True).encode()
        uri, digest, size = await context.cas.put(encoded)
        artifact = build_artifact(
            role="primary" if quality.accepted else "checked-only",
            representation="document",
            media_type="application/vnd.fetech.document+json",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=context.resources[-1],
            extractor=f"{parser}/0.1",
            quality=quality,
            parents=(raw,),
            locators=locators,
        )
        context.artifacts.append(artifact)
        context.accepted = context.accepted or quality.accepted
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "bytes_received": len(body),
                "parser": parser,
                "artifact_ids": (artifact.artifact_id,),
            }
        )


def _detect_capability(requested: str, target: str, body: bytes) -> str:
    if requested not in {"dataset_file", "document_router"}:
        return requested
    signatures = (
        (b"%PDF-", "pdf"),
        (b"PK\x03\x04", "zip_container"),
    )
    for signature, capability in signatures:
        if body.startswith(signature):
            if capability == "zip_container":
                suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
                return {".docx": "docx", ".pptx": "pptx", ".xlsx": "xlsx", ".epub": "epub"}.get(
                    suffix, "docx"
                )
            return capability
    suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
    return {
        ".csv": "csv",
        ".docx": "docx",
        ".epub": "epub",
        ".pdf": "pdf",
        ".pptx": "pptx",
        ".txt": "plain_text_file",
        ".xls": "xls",
        ".xlsx": "xlsx",
    }.get(suffix, "plain_text_file")


def _parse(capability: str, body: bytes) -> tuple[dict[str, Any], tuple[str, ...], str]:
    if capability in {"plain_text_file", "txt", "markdown"}:
        text = body.decode("utf-8", errors="replace")
        return {"type": "text", "blocks": [{"locator": "line:1", "text": text}]}, ("line:1",), "text"
    if capability == "csv":
        rows = list(csv.reader(io.StringIO(body.decode("utf-8-sig", errors="replace"))))
        csv_blocks: list[dict[str, Any]] = [
            {"locator": f"row:{index}", "cells": row} for index, row in enumerate(rows, start=1)
        ]
        return {"type": "table", "blocks": csv_blocks}, _locators(csv_blocks), "csv"
    if capability == "pdf":
        try:
            from pypdf import PdfReader
        except ImportError as exc:
            raise ImportError("install fetech[documents] for PDF parsing") from exc
        pages: list[dict[str, Any]] = [
            {"locator": f"page:{index}", "text": page.extract_text() or ""}
            for index, page in enumerate(PdfReader(io.BytesIO(body)).pages, start=1)
        ]
        return {"type": "pdf", "blocks": pages}, _locators(pages), "pypdf"
    if capability == "docx":
        try:
            from docx import Document
        except ImportError as exc:
            raise ImportError("install fetech[documents] for DOCX parsing") from exc
        paragraphs: list[dict[str, Any]] = [
            {"locator": f"paragraph:{index}", "text": paragraph.text}
            for index, paragraph in enumerate(Document(io.BytesIO(body)).paragraphs, start=1)
            if paragraph.text.strip()
        ]
        return (
            {"type": "docx", "blocks": paragraphs},
            _locators(paragraphs),
            "python-docx",
        )
    if capability == "pptx":
        try:
            from pptx import Presentation
        except ImportError as exc:
            raise ImportError("install fetech[documents] for PPTX parsing") from exc
        slide_blocks: list[dict[str, Any]] = []
        for slide_index, slide in enumerate(Presentation(io.BytesIO(body)).slides, start=1):
            text = "\n".join(
                shape.text for shape in slide.shapes if hasattr(shape, "text") and shape.text.strip()
            )
            slide_blocks.append({"locator": f"slide:{slide_index}", "text": text})
        return {"type": "pptx", "blocks": slide_blocks}, _locators(slide_blocks), "python-pptx"
    if capability == "xlsx":
        try:
            from openpyxl import load_workbook
        except ImportError as exc:
            raise ImportError("install fetech[documents] for XLSX parsing") from exc
        workbook = load_workbook(io.BytesIO(body), read_only=True, data_only=True)
        sheet_blocks: list[dict[str, Any]] = []
        for sheet in workbook.worksheets:
            for row_index, row in enumerate(sheet.iter_rows(values_only=True), start=1):
                sheet_blocks.append({"locator": f"sheet:{sheet.title}/row:{row_index}", "cells": list(row)})
        return {"type": "xlsx", "blocks": sheet_blocks}, _locators(sheet_blocks), "openpyxl"
    if capability == "epub":
        import zipfile

        with zipfile.ZipFile(io.BytesIO(body)) as archive:
            names = [name for name in archive.namelist() if name.lower().endswith((".html", ".xhtml"))]
            epub_blocks: list[dict[str, Any]] = [
                {
                    "locator": f"member:{name}",
                    "text": _TAGS.sub(" ", archive.read(name).decode("utf-8", errors="replace")),
                }
                for name in names[:1_000]
                if _safe_member(name)
            ]
        return {"type": "epub", "blocks": epub_blocks}, _locators(epub_blocks), "zipfile"
    if capability in {"xls", "legacy_office"}:
        raise ImportError("legacy Office parsing requires a separately isolated connector")
    raise ValueError(f"unsupported document capability: {capability}")


def _document_text(document: dict[str, Any]) -> str:
    parts: list[str] = []
    for block in document.get("blocks", []):
        if "text" in block:
            parts.append(str(block["text"]))
        elif "cells" in block:
            parts.append(" ".join("" if value is None else str(value) for value in block["cells"]))
    return "\n".join(parts)


def _locators(blocks: list[dict[str, Any]]) -> tuple[str, ...]:
    return tuple(str(block["locator"]) for block in blocks)


def _safe_member(name: str) -> bool:
    path = PurePosixPath(name)
    return not path.is_absolute() and ".." not in path.parts
