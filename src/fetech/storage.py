"""Content-addressed artifact storage and validated cache primitives."""

from __future__ import annotations

import asyncio
import errno
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import AsyncIterator, Collection
from contextlib import asynccontextmanager
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


class CASReadLimitError(CASIntegrityError):
    """A valid CAS artifact exceeds the caller's explicit read bound."""


class StorageQuotaExceeded(OSError):
    """A local write would exceed the configured data-directory quota."""


class StorageLifecycleError(ValueError):
    """Local storage could not be inventoried or maintained safely."""


@dataclass(frozen=True, slots=True)
class StorageUsage:
    bytes_used: int
    regular_files: int


@dataclass(frozen=True, slots=True)
class CASMaintenanceReport:
    temporary_files_removed: int = 0
    temporary_bytes_removed: int = 0
    orphan_files_removed: int = 0
    orphan_bytes_removed: int = 0
    retained_files: int = 0
    retained_bytes: int = 0


class StorageQuota:
    """Serialize local writes against a bounded whole-data-directory inventory."""

    def __init__(
        self,
        root: Path,
        maximum_bytes: int,
        *,
        maximum_entries: int = 200_000,
        ledger_headroom_bytes: int | None = None,
    ) -> None:
        if isinstance(maximum_bytes, bool) or maximum_bytes < 1_048_576:
            raise ValueError("storage quota must be at least one MiB")
        if isinstance(maximum_entries, bool) or not 1 <= maximum_entries <= 1_000_000:
            raise ValueError("storage inventory entry bound is invalid")
        self.root = root.expanduser().resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.maximum_bytes = maximum_bytes
        self.maximum_entries = maximum_entries
        selected_headroom = (
            min(1_048_576, maximum_bytes // 4)
            if ledger_headroom_bytes is None
            else ledger_headroom_bytes
        )
        if (
            isinstance(selected_headroom, bool)
            or selected_headroom < 0
            or selected_headroom > maximum_bytes // 2
        ):
            raise ValueError("ledger storage headroom is outside the allowed bound")
        self.ledger_headroom_bytes = selected_headroom
        self._lock = asyncio.Lock()

    async def usage(self) -> StorageUsage:
        async with self._lock:
            return await asyncio.to_thread(
                _storage_usage,
                self.root,
                self.maximum_entries,
            )

    async def ensure_available(
        self,
        additional_bytes: int = 0,
        *,
        use_ledger_headroom: bool = False,
    ) -> StorageUsage:
        async with self._lock:
            return await self._ensure_available(
                additional_bytes,
                use_ledger_headroom=use_ledger_headroom,
            )

    @asynccontextmanager
    async def reserve(
        self,
        additional_bytes: int,
        *,
        use_ledger_headroom: bool = False,
    ) -> AsyncIterator[StorageUsage]:
        """Hold the single-daemon write boundary and verify the cap after the write."""

        async with self._lock:
            before = await self._ensure_available(
                additional_bytes,
                use_ledger_headroom=use_ledger_headroom,
            )
            yield before
            after = await asyncio.to_thread(
                _storage_usage,
                self.root,
                self.maximum_entries,
            )
            if after.bytes_used > self.maximum_bytes:
                raise StorageQuotaExceeded("data-directory quota was exceeded during a write")

    @asynccontextmanager
    async def exclusive_maintenance(self) -> AsyncIterator[None]:
        """Serialize a reducing maintenance operation even when the cap is already exceeded."""

        async with self._lock:
            yield

    async def _ensure_available(
        self,
        additional_bytes: int,
        *,
        use_ledger_headroom: bool,
    ) -> StorageUsage:
        if isinstance(additional_bytes, bool) or additional_bytes < 0:
            raise ValueError("storage reservation must be a non-negative byte count")
        usage = await asyncio.to_thread(
            _storage_usage,
            self.root,
            self.maximum_entries,
        )
        limit = self.maximum_bytes - (
            0 if use_ledger_headroom else self.ledger_headroom_bytes
        )
        if usage.bytes_used + additional_bytes > limit:
            raise StorageQuotaExceeded("data-directory quota does not permit this write")
        return usage


class FileSystemCAS:
    """Immutable SHA-256 content store with atomic writes."""

    def __init__(self, root: Path, *, quota: StorageQuota | None = None) -> None:
        self.root = root.expanduser().resolve()
        if quota is not None and self.root != quota.root and quota.root not in self.root.parents:
            raise ValueError("CAS root must be contained by the quota root")
        self.root.mkdir(parents=True, exist_ok=True)
        self.quota = quota
        self._write_locks = tuple(asyncio.Lock() for _ in range(64))

    def _path(self, digest: str) -> Path:
        if len(digest) != 64 or any(character not in "0123456789abcdef" for character in digest):
            raise ValueError("invalid SHA-256 digest")
        return self.root / digest[:2] / digest[2:4] / digest

    async def put(self, body: bytes) -> tuple[str, str, int]:
        digest = hashlib.sha256(body).hexdigest()
        target = self._path(digest)
        write_lock = self._write_locks[int(digest[:2], 16) % len(self._write_locks)]
        async with write_lock:
            try:
                await asyncio.to_thread(self._verify_existing, target, body, digest)
            except FileNotFoundError:
                pass
            else:
                return f"cas://sha256/{digest}", digest, len(body)
            async with _storage_reservation(self.quota, len(body)):
                await asyncio.to_thread(
                    self._write_atomic,
                    target,
                    body,
                    digest,
                    self.root,
                )
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
                raise CASReadLimitError("CAS artifact exceeds the requested read bound")

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
                    raise CASReadLimitError("CAS artifact exceeds the requested read bound")
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
        except (CASIntegrityError, FileNotFoundError, OSError, ValueError):
            return False
        return True

    async def maintain(
        self,
        referenced_uris: Collection[str],
        *,
        orphan_grace_seconds: int,
        now: datetime | None = None,
        maximum_entries: int = 200_000,
    ) -> CASMaintenanceReport:
        """Remove crash staging files and old unreferenced canonical blobs."""

        if not 0 <= orphan_grace_seconds <= 365 * 24 * 60 * 60:
            raise ValueError("CAS orphan grace period is outside the allowed bound")
        if not 1 <= maximum_entries <= 1_000_000:
            raise ValueError("CAS maintenance entry bound is invalid")
        current = now or datetime.now(UTC)
        if current.utcoffset() is None:
            raise ValueError("CAS maintenance time must include a timezone")
        referenced = {_cas_digest(uri) for uri in referenced_uris}
        if self.quota is None:
            return await asyncio.to_thread(
                self._maintain,
                referenced,
                current.timestamp() - orphan_grace_seconds,
                maximum_entries,
            )
        async with self.quota.exclusive_maintenance():
            return await asyncio.to_thread(
                self._maintain,
                referenced,
                current.timestamp() - orphan_grace_seconds,
                maximum_entries,
            )

    def _maintain(
        self,
        referenced: set[str],
        orphan_cutoff: float,
        maximum_entries: int,
    ) -> CASMaintenanceReport:
        temporary_files_removed = 0
        temporary_bytes_removed = 0
        orphan_files_removed = 0
        orphan_bytes_removed = 0
        retained_files = 0
        retained_bytes = 0
        touched: set[Path] = set()
        for path, state in _walk_storage_files(self.root, maximum_entries):
            if path.name.startswith(".write-"):
                if not stat.S_ISREG(state.st_mode):
                    raise StorageLifecycleError("CAS staging path is not a regular file")
                path.unlink()
                temporary_files_removed += 1
                temporary_bytes_removed += state.st_size
                touched.add(path.parent)
                continue
            digest = path.name
            canonical = (
                len(digest) == 64
                and all(character in "0123456789abcdef" for character in digest)
                and path == self._path(digest)
            )
            if not canonical:
                retained_files += 1
                retained_bytes += state.st_size
                continue
            if not stat.S_ISREG(state.st_mode):
                raise StorageLifecycleError("CAS digest path is not a regular file")
            if digest not in referenced and state.st_mtime <= orphan_cutoff:
                path.unlink()
                orphan_files_removed += 1
                orphan_bytes_removed += state.st_size
                touched.add(path.parent)
                continue
            retained_files += 1
            retained_bytes += state.st_size
        for directory in sorted(touched, key=lambda item: len(item.parts), reverse=True):
            self._fsync_directory(directory)
        return CASMaintenanceReport(
            temporary_files_removed=temporary_files_removed,
            temporary_bytes_removed=temporary_bytes_removed,
            orphan_files_removed=orphan_files_removed,
            orphan_bytes_removed=orphan_bytes_removed,
            retained_files=retained_files,
            retained_bytes=retained_bytes,
        )


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


@asynccontextmanager
async def _storage_reservation(
    quota: StorageQuota | None,
    additional_bytes: int,
) -> AsyncIterator[None]:
    if quota is None:
        yield
        return
    async with quota.reserve(additional_bytes):
        yield


def _cas_digest(uri: str) -> str:
    prefix = "cas://sha256/"
    if not uri.startswith(prefix):
        raise StorageLifecycleError("live artifact reference is not a canonical CAS URI")
    digest = uri.removeprefix(prefix)
    if len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise StorageLifecycleError("live artifact reference has an invalid digest")
    return digest


def _walk_storage_files(
    root: Path,
    maximum_entries: int,
) -> tuple[tuple[Path, os.stat_result], ...]:
    files: list[tuple[Path, os.stat_result]] = []
    entries = 0
    for directory, directory_names, filenames in os.walk(root, followlinks=False):
        parent = Path(directory)
        safe_directories: list[str] = []
        for name in sorted(directory_names):
            entries += 1
            if entries > maximum_entries:
                raise StorageLifecycleError("storage inventory exceeded its entry bound")
            path = parent / name
            state = path.lstat()
            if stat.S_ISLNK(state.st_mode):
                raise StorageLifecycleError("storage inventory contains a symbolic link")
            if not stat.S_ISDIR(state.st_mode):
                raise StorageLifecycleError("storage inventory contains an invalid directory entry")
            safe_directories.append(name)
        directory_names[:] = safe_directories
        for name in sorted(filenames):
            entries += 1
            if entries > maximum_entries:
                raise StorageLifecycleError("storage inventory exceeded its entry bound")
            path = parent / name
            state = path.lstat()
            if not stat.S_ISREG(state.st_mode):
                raise StorageLifecycleError("storage inventory contains a non-regular file")
            files.append((path, state))
    return tuple(files)


def _storage_usage(root: Path, maximum_entries: int) -> StorageUsage:
    files = _walk_storage_files(root, maximum_entries)
    return StorageUsage(
        bytes_used=sum(state.st_size for _, state in files),
        regular_files=len(files),
    )
