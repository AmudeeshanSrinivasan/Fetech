"""Sandboxed archive validation and bounded member extraction."""

from __future__ import annotations

import base64
import binascii
import io
import json
import stat
import sys
import tarfile
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Protocol

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.logic.base import LogicBackendError
from fetech.logic.process import run_bounded
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    PageState,
    PlanNode,
    QualityAssessment,
)
from fetech.quality import assess_text
from fetech.security import sanitize_url_for_request
from fetech.storage import build_artifact
from fetech.worker_isolation import (
    WorkerIsolationProfile,
    WorkerIsolationRuntime,
)

ARCHIVE_SUFFIXES = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".zip"}
_MAX_WORKER_OUTPUT_BYTES = 256_000_000
_MAX_ARCHIVE_INPUT_BYTES = 50_000_000
_MAX_MEMBER_NAME_BYTES = 4_096


@dataclass(frozen=True, slots=True)
class ArchiveLimits:
    maximum_members: int
    maximum_expanded: int
    maximum_ratio: float

    def __post_init__(self) -> None:
        if self.maximum_members <= 0 or self.maximum_expanded <= 0:
            raise ValueError("archive integer limits must be positive")
        if self.maximum_ratio < 1:
            raise ValueError("archive compression ratio must be at least one")


class ArchiveParser(Protocol):
    async def extract(
        self,
        body: bytes,
        *,
        limits: ArchiveLimits,
        timeout_seconds: float,
    ) -> list[tuple[str, bytes]]: ...


class ArchiveParseWorker:
    """Run hostile ZIP/TAR parsing in an ephemeral resource-bounded process."""

    def __init__(
        self,
        *,
        memory_mb: int = 512,
        isolation: WorkerIsolationRuntime | None = None,
    ) -> None:
        if memory_mb <= 0:
            raise ValueError("archive worker memory limit must be positive")
        self.memory_mb = memory_mb
        self.isolation = isolation or WorkerIsolationRuntime.from_environment()

    async def extract(
        self,
        body: bytes,
        *,
        limits: ArchiveLimits,
        timeout_seconds: float,
    ) -> list[tuple[str, bytes]]:
        if timeout_seconds <= 0:
            raise AdapterExecutionError("archive extraction has no deadline budget")
        if len(body) > min(_MAX_ARCHIVE_INPUT_BYTES, limits.maximum_expanded):
            raise AdapterExecutionError("archive body exceeds the worker input limit")
        payload = json.dumps(
            {
                "body": base64.b64encode(body).decode("ascii"),
                "limits": {
                    "maximum_members": limits.maximum_members,
                    "maximum_expanded": limits.maximum_expanded,
                    "maximum_ratio": limits.maximum_ratio,
                },
            },
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
        try:
            process = await run_bounded(
                (sys.executable, "-m", "fetech.archive_worker"),
                payload,
                timeout_seconds=timeout_seconds,
                memory_mb=self.memory_mb,
                maximum_output_bytes=min(
                    _MAX_WORKER_OUTPUT_BYTES,
                    limits.maximum_expanded * 2 + 65_536,
                ),
                isolation=self.isolation.request(
                    WorkerIsolationProfile.ARCHIVE_PARSER
                ),
            )
        except LogicBackendError as exc:
            raise AdapterExecutionError("bounded archive extraction process failed") from exc
        if not process.stdout:
            raise AdapterExecutionError("archive worker exited without output")
        try:
            response = json.loads(process.stdout, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            raise AdapterExecutionError("archive worker returned malformed output") from exc
        if process.returncode != 0:
            raise AdapterExecutionError("bounded archive extraction failed")
        return _validate_worker_members(response, limits)


class ArchiveAdapter:
    def __init__(
        self,
        *,
        parser: ArchiveParser | None = None,
        worker_timeout_seconds: float = 20.0,
        isolation: WorkerIsolationRuntime | None = None,
    ) -> None:
        if worker_timeout_seconds <= 0:
            raise ValueError("archive worker timeout must be positive")
        self.parser = parser or ArchiveParseWorker(isolation=isolation)
        self.worker_timeout_seconds = worker_timeout_seconds

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        if node.capability_id != "zip_archive":
            raise AdapterExecutionError(
                f"archive adapter cannot execute {node.capability_id}"
            )
        raw = context.latest_artifact("raw")
        if raw is None or not context.resources:
            raise AdapterExecutionError("archive extraction requires a source artifact")
        input_limit = min(
            context.request.budget.bytes,
            context.request.budget.decompressed_bytes,
            _MAX_ARCHIVE_INPUT_BYTES,
        )
        if raw.size > input_limit:
            raise AdapterExecutionError("archive body exceeds the parser input limit")
        body = await context.cas.get(raw.cas_uri, maximum_bytes=input_limit)
        remaining_expanded = int(context.remaining_budget("decompressed_bytes"))
        remaining_members = int(context.remaining_budget("archive_members"))
        context.require_budget("decompressed_bytes", 1)
        context.require_budget("archive_members", 1)
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            adapter_version="0.4.0a0",
            sanitized_destination=sanitize_url_for_request(
                context.request.target,
                context.request,
            ),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        try:
            members = await self.parser.extract(
                body,
                limits=ArchiveLimits(
                    maximum_members=remaining_members,
                    maximum_expanded=remaining_expanded,
                    maximum_ratio=context.request.budget.archive_ratio,
                ),
                timeout_seconds=min(
                    self.worker_timeout_seconds,
                    context.request.budget.deadline_seconds,
                ),
            )
        except (
            AdapterExecutionError,
            EOFError,
            OSError,
            RuntimeError,
            tarfile.TarError,
            ValueError,
            zipfile.BadZipFile,
        ) as exc:
            context.attempts[-1] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "unsafe_or_malformed_archive",
                    "warnings": (str(exc),),
                }
            )
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "archive",
                reason=str(exc),
            )
            if isinstance(exc, AdapterExecutionError):
                raise
            raise AdapterExecutionError(str(exc)) from exc
        summary = {
            "members": [{"locator": f"member:{name}", "size": len(content)} for name, content in members]
        }
        encoded = json.dumps(summary, sort_keys=True).encode()
        expanded_bytes = sum(len(content) for _, content in members)
        context.require_budget(
            "decompressed_bytes",
            expanded_bytes + len(encoded),
        )
        context.require_budget("archive_members", len(members))
        quality = QualityAssessment(
            page_state=PageState.OK if members else PageState.EMPTY,
            score=1.0 if members else 0.0,
            accepted=bool(members),
            completeness=1.0 if members else 0.0,
            reasons=(
                ("bounded archive member manifest validated",)
                if members
                else ("archive contains no regular members",)
            ),
        )
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
        context.accepted = context.accepted or quality.accepted
        context.record_outcome(
            node.capability_id,
            CapabilityOutcomeStatus.APPLIED,
            "archive",
            bounded=True,
            isolated_worker=True,
            members=len(members),
            expanded_bytes=expanded_bytes,
        )
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
                "consumed_budget": {
                    "decompressed_bytes": expanded_bytes + size,
                    "archive_members": len(members),
                },
            }
        )


def _extract_members(
    body: bytes, *, maximum_members: int, maximum_expanded: int, maximum_ratio: float
) -> list[tuple[str, bytes]]:
    ArchiveLimits(maximum_members, maximum_expanded, maximum_ratio)
    if not body:
        raise ValueError("archive body cannot be empty")
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
    seen: set[str] = set()
    with zipfile.ZipFile(io.BytesIO(body)) as archive:
        infos = archive.infolist()
        if len(infos) > maximum_members:
            raise ValueError("archive member limit exceeded")
        for info in infos:
            name = _validate_name(info.filename)
            _record_name(name, seen)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise ValueError("archive symlinks are forbidden")
            if info.is_dir():
                continue
            if info.flag_bits & 0x1:
                raise ValueError("encrypted archive members are forbidden")
            ratio = info.file_size / max(1, info.compress_size)
            if ratio > maximum_ratio:
                raise ValueError("archive compression ratio exceeded")
            expanded += info.file_size
            if expanded > maximum_expanded:
                raise ValueError("archive expanded-byte limit exceeded")
            content = archive.read(info)
            if len(content) != info.file_size:
                raise ValueError("archive member size does not match metadata")
            _reject_nested(name, content)
            output.append((name, content))
    return output


def _extract_tar(
    body: bytes, maximum_members: int, maximum_expanded: int, maximum_ratio: float
) -> list[tuple[str, bytes]]:
    output: list[tuple[str, bytes]] = []
    expanded = 0
    seen: set[str] = set()
    with tarfile.open(fileobj=io.BytesIO(body), mode="r:*") as archive:
        members = archive.getmembers()
        if len(members) > maximum_members:
            raise ValueError("archive member limit exceeded")
        for member in members:
            name = _validate_name(member.name)
            _record_name(name, seen)
            if member.issym() or member.islnk() or member.isdev():
                raise ValueError("archive links and devices are forbidden")
            if not member.isfile():
                continue
            if getattr(member, "sparse", None):
                raise ValueError("sparse archive members are forbidden")
            expanded += member.size
            if expanded > maximum_expanded:
                raise ValueError("archive expanded-byte limit exceeded")
            if expanded / max(1, len(body)) > maximum_ratio:
                raise ValueError("archive compression ratio exceeded")
            extracted = archive.extractfile(member)
            if extracted is None:
                raise ValueError("archive member could not be read")
            content = extracted.read(member.size + 1)
            if len(content) != member.size:
                raise ValueError("archive member size does not match metadata")
            _reject_nested(name, content)
            output.append((name, content))
    return output


def _validate_name(name: str) -> str:
    if (
        not name
        or len(name.encode("utf-8")) > _MAX_MEMBER_NAME_BYTES
        or "\\" in name
        or "\x00" in name
        or any(ord(character) < 32 for character in name)
    ):
        raise ValueError("archive member name is invalid")
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or path == PurePosixPath("."):
        raise ValueError("archive path traversal detected")
    normalized = path.as_posix()
    if normalized.startswith("/") or normalized.startswith("../"):
        raise ValueError("archive path traversal detected")
    return normalized


def _record_name(name: str, seen: set[str]) -> None:
    portable_name = name.casefold()
    if portable_name in seen:
        raise ValueError("duplicate archive member path detected")
    seen.add(portable_name)


def _reject_nested(name: str, content: bytes) -> None:
    if PurePosixPath(name.lower()).suffix in ARCHIVE_SUFFIXES or _has_archive_signature(content):
        raise ValueError("nested archives require an explicitly isolated recursive plan")


def _has_archive_signature(content: bytes) -> bool:
    signatures = (
        b"PK\x03\x04",
        b"PK\x05\x06",
        b"PK\x07\x08",
        b"\x1f\x8b",
        b"BZh",
        b"7z\xbc\xaf'\x1c",
        b"Rar!\x1a\x07",
    )
    return content.startswith(signatures) or (
        len(content) > 262 and content[257:262] == b"ustar"
    )


def _validate_worker_members(
    response: object,
    limits: ArchiveLimits,
) -> list[tuple[str, bytes]]:
    if not isinstance(response, dict) or set(response) != {"members"}:
        raise AdapterExecutionError("archive worker response schema is invalid")
    raw_members = response["members"]
    if not isinstance(raw_members, list) or len(raw_members) > limits.maximum_members:
        raise AdapterExecutionError("archive worker member list is invalid")
    members: list[tuple[str, bytes]] = []
    expanded = 0
    seen: set[str] = set()
    for item in raw_members:
        if not isinstance(item, dict) or set(item) != {"body", "name"}:
            raise AdapterExecutionError("archive worker member schema is invalid")
        name_value = item["name"]
        body_value = item["body"]
        if not isinstance(name_value, str) or not isinstance(body_value, str):
            raise AdapterExecutionError("archive worker member types are invalid")
        name = _validate_name(name_value)
        _record_name(name, seen)
        try:
            content = base64.b64decode(body_value, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise AdapterExecutionError("archive worker returned invalid base64") from exc
        expanded += len(content)
        if expanded > limits.maximum_expanded:
            raise AdapterExecutionError("archive worker exceeded the expanded-byte limit")
        _reject_nested(name, content)
        members.append((name, content))
    return members


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")
