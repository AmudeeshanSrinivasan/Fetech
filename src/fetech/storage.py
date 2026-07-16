"""Content-addressed artifact storage and validated cache primitives."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from fetech.models import Artifact, QualityAssessment, Resource


class ArtifactStore(Protocol):
    async def put(self, body: bytes) -> tuple[str, str, int]: ...

    async def get(self, uri: str, *, maximum_bytes: int | None = None) -> bytes: ...


class FileSystemCAS:
    """Immutable SHA-256 content store with atomic writes."""

    def __init__(self, root: Path) -> None:
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, digest: str) -> Path:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("invalid SHA-256 digest")
        return self.root / digest[:2] / digest[2:4] / digest

    async def put(self, body: bytes) -> tuple[str, str, int]:
        digest = hashlib.sha256(body).hexdigest()
        target = self._path(digest)
        if not target.exists():
            await asyncio.to_thread(self._write_atomic, target, body)
        return f"cas://sha256/{digest}", digest, len(body)

    @staticmethod
    def _write_atomic(target: Path, body: bytes) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".write-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(body)
                handle.flush()
                os.fsync(handle.fileno())
            with suppress(FileExistsError):
                os.link(temporary_name, target)
        finally:
            Path(temporary_name).unlink(missing_ok=True)

    async def get(self, uri: str, *, maximum_bytes: int | None = None) -> bytes:
        prefix = "cas://sha256/"
        if not uri.startswith(prefix):
            raise ValueError("unsupported CAS URI")
        path = self._path(uri.removeprefix(prefix))
        body = await asyncio.to_thread(path.read_bytes)
        if maximum_bytes is not None and len(body) > maximum_bytes:
            raise ValueError("artifact exceeds the requested read bound")
        return body

    async def verify(self, uri: str) -> bool:
        body = await self.get(uri)
        return hashlib.sha256(body).hexdigest() == uri.rsplit("/", maxsplit=1)[-1]


@dataclass(frozen=True)
class CacheKey:
    url: str
    representation: str
    authentication_scope: str
    policy_profile: str
    language: str
    parser_version: str
    vary: tuple[tuple[str, str], ...] = ()

    @property
    def digest(self) -> str:
        document = {
            "url": self.url,
            "representation": self.representation,
            "authentication_scope": self.authentication_scope,
            "policy_profile": self.policy_profile,
            "language": self.language,
            "parser_version": self.parser_version,
            "vary": self.vary,
        }
        encoded = json.dumps(document, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class CacheRecord:
    key: CacheKey
    resource: Resource
    artifact: Artifact
    etag: str | None = None
    last_modified: str | None = None
    stored_at: datetime = dataclass_field(default_factory=lambda: datetime.min.replace(tzinfo=UTC))
    expires_at: datetime | None = None

    @property
    def fresh(self) -> bool:
        return self.expires_at is None or self.expires_at > datetime.now(UTC)


def build_artifact(
    *,
    role: str,
    representation: str,
    media_type: str,
    cas_uri: str,
    digest: str,
    size: int,
    resource: Resource,
    extractor: str,
    quality: QualityAssessment,
    parents: tuple[Artifact, ...] = (),
    locators: tuple[str, ...] = (),
) -> Artifact:
    return Artifact(
        role=role,
        representation=representation,
        media_type=media_type,
        cas_uri=cas_uri,
        sha256=digest,
        size=size,
        source_resource_id=resource.resource_id,
        parent_artifact_ids=tuple(parent.artifact_id for parent in parents),
        extractor_version=extractor,
        locators=locators,
        quality=quality,
    )
