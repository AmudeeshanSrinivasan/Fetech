"""Sandbox-oriented archive validation and bounded member extraction."""

from __future__ import annotations

import io
import json
import stat
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import PurePosixPath

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.models import AttemptStatus, FetchAttempt, PlanNode
from fetech.quality import assess_text
from fetech.security import sanitize_url
from fetech.storage import build_artifact

ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".zip"}


class ArchiveAdapter:
    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        raw = context.latest_artifact("raw")
        if raw is None or not context.resources:
            raise AdapterExecutionError("archive extraction requires a source artifact")
        body = await context.cas.get(raw.cas_uri, maximum_bytes=context.request.budget.bytes)
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        try:
            members = _extract_members(
                body,
                maximum_members=context.request.budget.archive_members,
                maximum_expanded=context.request.budget.decompressed_bytes,
                maximum_ratio=context.request.budget.archive_ratio,
            )
        except (tarfile.TarError, zipfile.BadZipFile, ValueError) as exc:
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "unsafe_or_malformed_archive",
                    "warnings": (str(exc),),
                }
            )
            raise AdapterExecutionError(str(exc)) from exc
        summary = {
            "members": [{"locator": f"member:{name}", "size": len(content)} for name, content in members]
        }
        encoded = json.dumps(summary, sort_keys=True).encode()
        quality = assess_text(" ".join(name for name, _ in members))
        uri, digest, size = await context.cas.put(encoded)
        artifact = build_artifact(
            role="primary" if quality.accepted else "checked-only",
            representation="archive_manifest",
            media_type="application/vnd.fetech.archive+json",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=context.resources[-1],
            extractor="stdlib-archive/0.1",
            quality=quality,
            parents=(raw,),
            locators=tuple(f"member:{name}" for name, _ in members),
        )
        context.artifacts.append(artifact)
        for name, content in members:
            member_uri, member_digest, member_size = await context.cas.put(content)
            member_quality = assess_text(content.decode("utf-8", errors="replace"))
            context.artifacts.append(
                build_artifact(
                    role="derived",
                    representation="archive_member",
                    media_type="application/octet-stream",
                    cas_uri=member_uri,
                    digest=member_digest,
                    size=member_size,
                    resource=context.resources[-1],
                    extractor="stdlib-archive/0.1",
                    quality=member_quality,
                    parents=(raw, artifact),
                    locators=(f"member:{name}",),
                )
            )
        context.accepted = context.accepted or bool(members)
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "bytes_received": len(body),
                "parser": "stdlib-archive",
                "artifact_ids": tuple(
                    item.artifact_id
                    for item in context.artifacts
                    if item in context.artifacts[-len(members) - 1 :]
                ),
            }
        )


def _extract_members(
    body: bytes, *, maximum_members: int, maximum_expanded: int, maximum_ratio: float
) -> list[tuple[str, bytes]]:
    if zipfile.is_zipfile(io.BytesIO(body)):
        return _extract_zip(body, maximum_members, maximum_expanded, maximum_ratio)
    try:
        return _extract_tar(body, maximum_members, maximum_expanded, maximum_ratio)
    except tarfile.ReadError as exc:
        raise ValueError("unsupported or malformed archive") from exc


def _extract_zip(
    body: bytes, maximum_members: int, maximum_expanded: int, maximum_ratio: float
) -> list[tuple[str, bytes]]:
    output: list[tuple[str, bytes]] = []
    expanded = 0
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        infos = archive.infolist()
        if len(infos) > maximum_members:
            raise ValueError("archive member limit exceeded")
        for info in infos:
            _validate_name(info.filename)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("archive symlinks are forbidden")
            if info.is_dir():
                continue
            ratio = info.file_size / max(1, info.compress_size)
            if ratio > maximum_ratio:
                raise ValueError("archive compression ratio exceeded")
            expanded += info.file_size
            if expanded > maximum_expanded:
                raise ValueError("archive expanded-byte limit exceeded")
            content = archive.read(info)
            _reject_nested(info.filename)
            output.append((info.filename, content))
    return output


def _extract_tar(
    body: bytes, maximum_members: int, maximum_expanded: int, maximum_ratio: float
) -> list[tuple[str, bytes]]:
    output: list[tuple[str, bytes]] = []
    expanded = 0
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as archive:
        members = archive.getmembers()
        if len(members) > maximum_members:
            raise ValueError("archive member limit exceeded")
        for member in members:
            _validate_name(member.name)
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("archive links and devices are forbidden")
            if not member.isfile():
                continue
            expanded += member.size
            if expanded > maximum_expanded:
                raise ValueError("archive expanded-byte limit exceeded")
            if expanded / max(1, len(body)) > maximum_ratio:
                raise ValueError("archive compression ratio exceeded")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("archive member could not be read")
            _reject_nested(member.name)
            output.append((member.name, extracted.read(member.size + 1)))
    return output


def _validate_name(name: str) -> None:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or "\x00" in name:
        raise ValueError("archive path traversal detected")


def _reject_nested(name: str) -> None:
    if PurePosixPath(name.lower()).suffix in ARCHIVE_SUFFIXES:
        raise ValueError("nested archives require an explicitly isolated recursive plan")
