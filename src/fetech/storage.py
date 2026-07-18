"""Content-addressed artifact storage and validated cache primitives."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import stat
import tempfile
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from fetech.auth import authentication_cache_scope
from fetech.models import Artifact, FetchRequest, QualityAssessment, Resource


class ArtifactStore(Protocol):
    async def put(self, body: bytes) -> tuple[str, str, int]: ...

    async def get(self, uri: str, *, maximum_bytes: int | None = None) -> bytes: ...


class CASIntegrityError(ValueError):
    """A digest path is occupied by content other than the requested body."""


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
        await asyncio.to_thread(self._write_atomic, target, body, digest, self.root)
        return f"cas://sha256/{digest}", digest, len(body)

    @classmethod
    def _write_atomic(
        cls,
        target: Path,
        body: bytes,
        digest: str,
        durability_root: Path,
    ) -> None:
        target.parent.mkdir(parents=True, exist_ok=True)

        try:
            cls._verify_existing(target, body, digest)
        except FileNotFoundError:
            pass
        else:
            cls._fsync_directory_chain(target.parent, durability_root)
            return

        descriptor, temporary_name = tempfile.mkstemp(prefix=".write-", dir=target.parent)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                written = handle.write(body)
                if written != len(body):
                    raise OSError("short write while staging CAS content")
                handle.flush()
                os.fsync(handle.fileno())

            for _attempt in range(2):
                try:
                    os.link(temporary_name, target, follow_symlinks=False)
                except FileExistsError:
                    try:
                        cls._verify_existing(target, body, digest)
                    except FileNotFoundError:
                        continue
                else:
                    cls._verify_existing(target, body, digest)
                cls._fsync_directory_chain(target.parent, durability_root)
                return
            raise CASIntegrityError("CAS target changed while content was being published")
        finally:
            Path(temporary_name).unlink(missing_ok=True)

    @staticmethod
    def _verify_existing(target: Path, body: bytes, digest: str) -> None:
        try:
            target_stat = target.lstat()
        except FileNotFoundError:
            raise
        if not stat.S_ISREG(target_stat.st_mode):
            raise CASIntegrityError("CAS digest path is not a regular file")

        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(target, flags)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise CASIntegrityError("CAS digest path could not be verified safely") from exc

        hasher = hashlib.sha256()
        offset = 0
        try:
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_size != len(body):
                raise CASIntegrityError("CAS digest path contains unexpected content")
            with os.fdopen(descriptor, "rb", closefd=False) as handle:
                while chunk := handle.read(1024 * 1024):
                    hasher.update(chunk)
                    end = offset + len(chunk)
                    if chunk != body[offset:end]:
                        raise CASIntegrityError("CAS digest path contains unexpected content")
                    offset = end
        finally:
            os.close(descriptor)

        if offset != len(body) or hasher.hexdigest() != digest:
            raise CASIntegrityError("CAS digest path contains unexpected content")

    @classmethod
    def _fsync_directory_chain(cls, directory: Path, durability_root: Path) -> None:
        current = directory
        stop = durability_root
        while True:
            cls._fsync_directory(current)
            if current == stop:
                return
            if current == current.parent or stop not in current.parents:
                raise CASIntegrityError("CAS durability root does not contain the digest path")
            current = current.parent

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        if os.name == "nt":
            return
        flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_CLOEXEC", 0)
        descriptor = os.open(directory, flags)
        try:
            os.fsync(descriptor)
        except OSError as exc:
            unsupported = {
                errno.EBADF,
                errno.EINVAL,
                getattr(errno, "ENOTSUP", errno.EINVAL),
                getattr(errno, "EOPNOTSUPP", errno.EINVAL),
            }
            if exc.errno not in unsupported:
                raise
        finally:
            os.close(descriptor)

    async def get(self, uri: str, *, maximum_bytes: int | None = None) -> bytes:
        prefix = "cas://sha256/"
        if not uri.startswith(prefix):
            raise ValueError("unsupported CAS URI")
        digest = uri.removeprefix(prefix)
        path = self._path(digest)
        return await asyncio.to_thread(self._read_verified, path, digest, maximum_bytes)

    @staticmethod
    def _read_verified(path: Path, digest: str, maximum_bytes: int | None) -> bytes:
        if maximum_bytes is not None and maximum_bytes < 0:
            raise CASIntegrityError("CAS read bound must be non-negative")

        try:
            path_stat = path.lstat()
        except FileNotFoundError:
            raise
        if not stat.S_ISREG(path_stat.st_mode):
            raise CASIntegrityError("CAS digest path is not a regular file")

        flags = os.O_RDONLY
        flags |= getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        try:
            descriptor = os.open(path, flags)
        except FileNotFoundError:
            raise
        except OSError as exc:
            raise CASIntegrityError("CAS digest path could not be opened safely") from exc

        chunks: list[bytes] = []
        hasher = hashlib.sha256()
        total = 0
        try:
            opened_stat = os.fstat(descriptor)
            if not stat.S_ISREG(opened_stat.st_mode):
                raise CASIntegrityError("CAS digest path is not a regular file")
            if (path_stat.st_dev, path_stat.st_ino) != (
                opened_stat.st_dev,
                opened_stat.st_ino,
            ):
                raise CASIntegrityError("CAS digest path changed while it was being opened")
            if maximum_bytes is not None and opened_stat.st_size > maximum_bytes:
                raise CASIntegrityError("CAS artifact exceeds the requested read bound")

            expected_size = opened_stat.st_size
            while True:
                remaining = expected_size - total
                chunk = os.read(descriptor, min(1024 * 1024, max(1, remaining + 1)))
                if not chunk:
                    break
                total += len(chunk)
                if total > expected_size or (
                    maximum_bytes is not None and total > maximum_bytes
                ):
                    raise CASIntegrityError("CAS artifact exceeds the requested read bound")
                hasher.update(chunk)
                chunks.append(chunk)

            final_stat = os.fstat(descriptor)
            if total != expected_size or final_stat.st_size != expected_size:
                raise CASIntegrityError("CAS digest path changed while it was being read")
        finally:
            os.close(descriptor)

        if hasher.hexdigest() != digest:
            raise CASIntegrityError("CAS artifact digest does not match its URI")
        return b"".join(chunks)

    async def verify(self, uri: str) -> bool:
        try:
            await self.get(uri)
        except CASIntegrityError:
            return False
        return True


@dataclass(frozen=True)
class CacheKey:
    url: str
    representation: str
    authentication_scope: str
    policy_profile: str
    language: str
    parser_version: str
    vary: tuple[tuple[str, str], ...] = ()
    region: str = ""

    @classmethod
    def for_request(
        cls,
        request: FetchRequest,
        *,
        url: str,
        representation: str,
        parser_version: str,
        vary: tuple[tuple[str, str], ...] = (),
    ) -> CacheKey:
        """Build a partitioned key without persisting the opaque authentication reference."""

        return cls(
            url=url,
            representation=representation,
            authentication_scope=authentication_cache_scope(request.authentication_ref),
            policy_profile=request.policy_profile,
            language=request.language or "",
            parser_version=parser_version,
            region=request.region or "",
            vary=vary,
        )

    @property
    def digest(self) -> str:
        document = {
            "url": self.url,
            "representation": self.representation,
            "authentication_scope": self.authentication_scope,
            "policy_profile": self.policy_profile,
            "language": self.language,
            "parser_version": self.parser_version,
            "region": self.region,
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
