from __future__ import annotations

import asyncio
import hashlib
from pathlib import Path

import pytest

import fetech.storage as storage_module
from fetech.storage import CASIntegrityError, FileSystemCAS


@pytest.mark.asyncio
async def test_put_rejects_a_preexisting_corrupt_digest_path_without_overwriting(
    tmp_path: Path,
) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    expected = b"good"
    corrupt = b"evil"
    digest = hashlib.sha256(expected).hexdigest()
    target = cas._path(digest)
    target.parent.mkdir(parents=True)
    target.write_bytes(corrupt)

    with pytest.raises(CASIntegrityError, match="unexpected content"):
        await cas.put(expected)

    assert target.read_bytes() == corrupt
    assert not tuple(target.parent.glob(".write-*"))


@pytest.mark.asyncio
async def test_concurrent_puts_publish_once_and_deduplicate_cleanly(tmp_path: Path) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    body = b"concurrent immutable fixture" * 4096

    results = await asyncio.gather(*(cas.put(body) for _ in range(32)))

    assert len(set(results)) == 1
    uri, digest, size = results[0]
    target = cas._path(digest)
    assert uri == f"cas://sha256/{digest}"
    assert size == len(body)
    assert target.read_bytes() == body
    assert [path for path in cas.root.rglob("*") if path.is_file()] == [target]
    assert not tuple(target.parent.glob(".write-*"))


@pytest.mark.asyncio
async def test_get_rejects_a_symlink_at_the_digest_path(tmp_path: Path) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    body = b"valid target content"
    uri, digest, _size = await cas.put(body)
    target = cas._path(digest)
    external = tmp_path / "external"
    external.write_bytes(body)
    target.unlink()
    try:
        target.symlink_to(external)
    except (NotImplementedError, OSError):
        pytest.skip("symlink creation is not supported")

    with pytest.raises(CASIntegrityError, match="not a regular file"):
        await cas.get(uri)


@pytest.mark.asyncio
async def test_get_rejects_an_oversized_file_before_reading_it(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    body = b"x" * (2 * 1024 * 1024)
    uri, _digest, _size = await cas.put(body)

    def unexpected_read(_descriptor: int, _size: int) -> bytes:
        raise AssertionError("oversized CAS content must be rejected before reading")

    monkeypatch.setattr(storage_module.os, "read", unexpected_read)

    with pytest.raises(CASIntegrityError, match="exceeds the requested read bound"):
        await cas.get(uri, maximum_bytes=1024)


@pytest.mark.asyncio
async def test_get_rejects_post_publication_content_corruption(tmp_path: Path) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    body = b"published fixture"
    uri, digest, _size = await cas.put(body)
    target = cas._path(digest)
    target.write_bytes(b"corrupted fixture")

    with pytest.raises(CASIntegrityError, match="digest does not match"):
        await cas.get(uri, maximum_bytes=len(body))
    assert await cas.verify(uri) is False


def test_directory_durability_sync_stops_at_the_cas_root(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    target = cas._path("a" * 64)
    observed: list[Path] = []
    monkeypatch.setattr(
        FileSystemCAS,
        "_fsync_directory",
        lambda directory: observed.append(directory),
    )

    FileSystemCAS._fsync_directory_chain(target.parent, cas.root)

    assert observed == [
        cas.root / "aa" / "aa",
        cas.root / "aa",
        cas.root,
    ]
