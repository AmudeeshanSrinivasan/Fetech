from __future__ import annotations

import io
import json
import struct
import wave
import zlib
from collections.abc import Mapping
from importlib.metadata import PackageNotFoundError
from pathlib import Path
from uuid import uuid4

import pytest

from fetech.adapters.base import (
    AdapterBudgetExceededError,
    AdapterDependencyError,
    AdapterExecutionError,
    ExecutionContext,
)
from fetech.adapters.media import (
    MEDIA_CAPABILITIES,
    FFmpegThumbnailWorker,
    FFprobeWorker,
    MediaAdapter,
    TesseractOCRWorker,
    _extract_exif_metadata,
    _image_metadata,
)
from fetech.logic.process import ProcessResult
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchRequest,
    PlanNode,
    QualityAssessment,
    Resource,
    ResourceBudget,
)
from fetech.storage import FileSystemCAS, build_artifact
from fetech.yt_dlp import YouTubeMetadataResponse, YTDLPProviderError


def _png(width: int = 4, height: int = 3) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(
            ">I", zlib.crc32(kind + data) & 0xFFFFFFFF
        )

    scanlines = (
        (b"\x00" + (b"\x00\x00\x00" * width)) * height
        if width * height <= 1_000_000
        else b"\x00"
    )
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)),
            chunk(b"IDAT", zlib.compress(scanlines)),
            chunk(b"IEND", b""),
        )
    )


def _wav() -> bytes:
    stream = io.BytesIO()
    with wave.open(stream, "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(8_000)
        output.writeframes(b"\x00\x00" * 800)
    return stream.getvalue()


def _tiff_with_safe_make_and_sensitive_gps() -> bytes:
    header = b"II" + struct.pack("<HI", 42, 8)
    data_offset = 8 + 2 + (2 * 12) + 4
    make = b"Canon\x00"
    make_entry = struct.pack("<HHI", 0x010F, 2, len(make)) + struct.pack("<I", data_offset)
    gps_entry = struct.pack("<HHII", 0x8825, 4, 1, data_offset + len(make))
    return header + struct.pack("<H", 2) + make_entry + gps_entry + struct.pack("<I", 0) + make


_VTT = b"""\
WEBVTT

00:00:00.000 --> 00:00:02.000
This is a useful bounded transcript fixture with enough readable words.

00:00:02.000 --> 00:00:04.000
It preserves cue lineage without retaining timing directives as instructions.
"""

_PODCAST = b"""\
<rss version="2.0"><channel>
<title>Bounded media engineering</title>
<description>A useful podcast feed with enough descriptive words for deterministic quality.</description>
<item><title>Safe media workers and provenance</title>
<guid>episode-1</guid><pubDate>Fri, 17 Jul 2026 00:00:00 GMT</pubDate>
<description>This episode explains bounded media parsing and reliable source lineage.</description>
<enclosure url="https://cdn.example/episode.mp3?token=private" length="1200" type="audio/mpeg"/>
</item></channel></rss>
"""

_YOUTUBE_INFO = json.dumps(
    {
        "id": "video-1",
        "title": "Bounded metadata fixture",
        "description": "Useful offline yt-dlp information JSON.",
        "duration": 42,
        "webpage_url": "https://www.youtube.com/watch?v=video-1&signature=private",
        "subtitles": {"en": [{"url": "https://signed.example/private"}]},
        "automatic_captions": {"fr": [{"url": "https://signed.example/private"}]},
        "formats": [{"url": "https://signed.example/private"}],
    }
).encode()


async def _context(
    tmp_path: Path,
    *,
    target: str,
    body: bytes,
    media_type: str,
    language: str | None = None,
) -> ExecutionContext:
    cas = FileSystemCAS(tmp_path / f"cas-{uuid4()}")
    resource = Resource(
        canonical_url=target,
        requested_url=target,
        authority_url=target,
        media_type=media_type,
        status_code=200,
    )
    uri, digest, size = await cas.put(body)
    raw = build_artifact(
        role="source",
        representation="raw",
        media_type=media_type,
        cas_uri=uri,
        digest=digest,
        size=size,
        resource=resource,
        extractor="fixture-http/0.4",
        quality=QualityAssessment(accepted=True, score=1, completeness=1),
    )
    return ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target=target, language=language),
        cas=cas,
        resources=[resource],
        artifacts=[raw],
    )


class _Probe:
    async def probe(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> Mapping[str, object]:
        assert body
        assert 0 < timeout_seconds <= 60
        assert maximum_output_bytes <= 1_000_000
        return {
            "format": {
                "format_name": "mov,mp4",
                "duration": "12.5",
                "filename": "/private/source/path",
            },
            "streams": [
                {
                    "index": 0,
                    "codec_name": "h264",
                    "codec_type": "video",
                    "width": 640,
                    "height": 360,
                    "tags": {"secret": "not persisted"},
                }
            ],
        }


class _OCR:
    async def extract_text(
        self,
        body: bytes,
        *,
        language: str | None,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> str:
        assert body.startswith(b"\x89PNG")
        assert language in {None, "en"}
        assert timeout_seconds > 0
        assert maximum_output_bytes > 0
        return (
            "Useful OCR output from a bounded image worker with enough words "
            "for deterministic content-quality acceptance."
        )


class _Transcriber:
    async def transcribe(
        self,
        body: bytes,
        *,
        media_type: str,
        language: str | None,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> str:
        assert body
        assert media_type.startswith("audio/")
        assert language is None
        assert timeout_seconds > 0
        assert maximum_output_bytes > 0
        return "A useful bounded speech transcript with deterministic provenance and readable content."


class _Thumbnail:
    async def thumbnail(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> tuple[bytes, str]:
        assert body
        assert timeout_seconds > 0
        assert maximum_output_bytes > 0
        return _png(2, 2), "image/png"


class _YouTube:
    def __init__(self) -> None:
        self.target = ""

    async def metadata(
        self,
        target: str,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
        maximum_network_bytes: int,
        maximum_redirects: int,
    ) -> YouTubeMetadataResponse:
        self.target = target
        assert timeout_seconds > 0
        assert maximum_output_bytes > 0
        assert maximum_network_bytes > 0
        assert maximum_redirects >= 0
        return YouTubeMetadataResponse(
            metadata={
                "id": "video-1",
                "title": "Isolated connector metadata",
                "webpage_url": (
                    "https://www.youtube.com/watch?v=video-1&signature=private"
                ),
                "formats": [{"url": "https://signed.example/private"}],
            },
            network_bytes=512,
            decompressed_bytes=512,
            redirects=1,
        )


@pytest.mark.parametrize(
    ("capability_id", "target", "media_type", "body", "representation"),
    [
        ("image", "https://media.example/image.png", "image/png", _png(), "image"),
        (
            "image_metadata",
            "https://media.example/image.png",
            "image/png",
            _png(),
            "media_metadata",
        ),
        (
            "image_ocr",
            "https://media.example/image.png",
            "image/png",
            _png(),
            "ocr_text",
        ),
        (
            "screenshot_to_text",
            "https://media.example/screenshot.png",
            "image/png",
            _png(),
            "ocr_text",
        ),
        (
            "video_metadata",
            "https://media.example/video.mp4",
            "video/mp4",
            b"bounded-video-fixture",
            "media_metadata",
        ),
        (
            "audio_metadata",
            "https://media.example/audio.wav",
            "audio/wav",
            _wav(),
            "media_metadata",
        ),
        (
            "transcript",
            "https://media.example/subtitles.vtt",
            "text/vtt",
            _VTT,
            "transcript",
        ),
        (
            "youtube_metadata",
            "https://www.youtube.com/watch?v=video-1",
            "application/json",
            _YOUTUBE_INFO,
            "media_metadata",
        ),
        (
            "podcast_feed",
            "https://podcast.example/feed.xml",
            "application/rss+xml",
            _PODCAST,
            "podcast_feed",
        ),
        (
            "thumbnail",
            "https://media.example/video.mp4",
            "video/mp4",
            b"bounded-video-fixture",
            "thumbnail",
        ),
        (
            "exif_metadata",
            "https://media.example/image.tiff",
            "image/tiff",
            _tiff_with_safe_make_and_sensitive_gps(),
            "media_metadata",
        ),
    ],
)
@pytest.mark.asyncio
async def test_all_eleven_media_capabilities_have_bounded_artifact_paths(
    capability_id: str,
    target: str,
    media_type: str,
    body: bytes,
    representation: str,
    tmp_path: Path,
) -> None:
    context = await _context(
        tmp_path,
        target=target,
        body=body,
        media_type=media_type,
    )
    raw = context.artifacts[0]
    adapter = MediaAdapter(
        probe=_Probe(),
        ocr=_OCR(),
        transcriber=_Transcriber(),
        thumbnailer=_Thumbnail(),
    )

    await adapter.execute(
        PlanNode(id="media", capability_id=capability_id, adapter="media"),
        context,
    )

    artifact = context.artifacts[-1]
    assert artifact.representation == representation
    assert artifact.parent_artifact_ids == (raw.artifact_id,)
    assert artifact.source_resource_id == context.resources[0].resource_id
    assert artifact.quality.accepted is True
    assert context.attempts[-1].status == AttemptStatus.SUCCEEDED
    assert context.attempts[-1].artifact_ids == (artifact.artifact_id,)
    assert context.attempts[-1].bytes_received == len(body)
    assert context.capability_outcomes[-1].capability_id == capability_id
    assert context.capability_outcomes[-1].status == CapabilityOutcomeStatus.APPLIED


def test_media_capability_inventory_is_the_canonical_eleven() -> None:
    assert {
        "image",
        "image_metadata",
        "image_ocr",
        "screenshot_to_text",
        "video_metadata",
        "audio_metadata",
        "transcript",
        "youtube_metadata",
        "podcast_feed",
        "thumbnail",
        "exif_metadata",
    } == MEDIA_CAPABILITIES


@pytest.mark.asyncio
async def test_image_and_video_metadata_are_minimal_and_do_not_retain_private_fields(
    tmp_path: Path,
) -> None:
    image_context = await _context(
        tmp_path,
        target="https://media.example/image.png?token=secret",
        body=_png(7, 5),
        media_type="image/png",
    )
    await MediaAdapter().execute(
        PlanNode(id="media", capability_id="image_metadata", adapter="media"),
        image_context,
    )
    image_document = json.loads(await image_context.cas.get(image_context.artifacts[-1].cas_uri))
    assert image_document["source_url"] == "https://media.example/image.png"
    assert image_document["metadata"]["width"] == 7
    assert image_document["metadata"]["height"] == 5

    video_context = await _context(
        tmp_path,
        target="https://media.example/video.mp4",
        body=b"video",
        media_type="video/mp4",
    )
    await MediaAdapter(probe=_Probe()).execute(
        PlanNode(id="media", capability_id="video_metadata", adapter="media"),
        video_context,
    )
    video_document = json.loads(await video_context.cas.get(video_context.artifacts[-1].cas_uri))
    assert "filename" not in video_document["metadata"]["format"]
    assert "tags" not in video_document["metadata"]["streams"][0]


def test_exif_parser_keeps_selected_fields_and_omits_sensitive_gps() -> None:
    metadata = _extract_exif_metadata(
        _tiff_with_safe_make_and_sensitive_gps(),
        maximum_fields=16,
    )
    assert metadata["fields"] == {"make": "Canon"}
    assert metadata["omitted_sensitive_fields"] == 1


@pytest.mark.asyncio
async def test_youtube_and_podcast_metadata_drop_signed_queries_and_download_urls(
    tmp_path: Path,
) -> None:
    youtube_context = await _context(
        tmp_path,
        target="https://www.youtube.com/watch?v=video-1",
        body=_YOUTUBE_INFO,
        media_type="application/json",
    )
    await MediaAdapter().execute(
        PlanNode(id="media", capability_id="youtube_metadata", adapter="media"),
        youtube_context,
    )
    youtube = json.loads(await youtube_context.cas.get(youtube_context.artifacts[-1].cas_uri))
    metadata = youtube["metadata"]
    assert metadata["source_url"] == "https://www.youtube.com/watch?v=video-1"
    assert metadata["subtitles_languages"] == ["en"]
    assert metadata["automatic_captions_languages"] == ["fr"]
    assert metadata["omitted_download_formats"] == 1
    assert "signed.example" not in json.dumps(youtube)

    podcast_context = await _context(
        tmp_path,
        target="https://podcast.example/feed.xml",
        body=_PODCAST,
        media_type="application/rss+xml",
    )
    await MediaAdapter().execute(
        PlanNode(id="media", capability_id="podcast_feed", adapter="media"),
        podcast_context,
    )
    podcast = json.loads(await podcast_context.cas.get(podcast_context.artifacts[-1].cas_uri))
    assert podcast["episodes"][0]["enclosure_url"] == "https://cdn.example/episode.mp3"
    assert "private" not in json.dumps(podcast)


@pytest.mark.asyncio
async def test_live_youtube_provider_receives_only_a_bounded_safe_locator(
    tmp_path: Path,
) -> None:
    provider = _YouTube()
    context = await _context(
        tmp_path,
        target=(
            "https://www.youtube.com/watch?v=video-1&list=playlist-1"
            "&signature=private&token=private"
        ),
        body=b"<html>pre-acquired page without metadata JSON</html>",
        media_type="text/html",
    )
    await MediaAdapter(youtube_provider=provider).execute(
        PlanNode(id="media", capability_id="youtube_metadata", adapter="media"),
        context,
    )
    assert provider.target == (
        "https://www.youtube.com/watch?v=video-1&list=playlist-1"
    )
    document = json.loads(await context.cas.get(context.artifacts[-1].cas_uri))
    assert "private" not in json.dumps(document)
    assert document["metadata"]["source_url"] == (
        "https://www.youtube.com/watch?v=video-1"
    )
    assert context.attempts[-1].consumed_budget["bytes"] == 512
    assert context.attempts[-1].consumed_budget["decompressed_bytes"] > 512
    assert context.attempts[-1].consumed_budget["redirects"] == 1


@pytest.mark.asyncio
async def test_failed_youtube_provider_usage_is_preserved_on_the_attempt(
    tmp_path: Path,
) -> None:
    class FailedProvider:
        async def metadata(
            self,
            target: str,
            *,
            timeout_seconds: float,
            maximum_output_bytes: int,
            maximum_network_bytes: int,
            maximum_redirects: int,
        ) -> YouTubeMetadataResponse:
            del (
                target,
                timeout_seconds,
                maximum_output_bytes,
                maximum_network_bytes,
                maximum_redirects,
            )
            raise YTDLPProviderError(
                "bounded provider failure",
                network_bytes=321,
                decompressed_bytes=321,
                redirects=1,
            )

    context = await _context(
        tmp_path,
        target="https://www.youtube.com/watch?v=video-1",
        body=b"<html>pre-acquired page without metadata JSON</html>",
        media_type="text/html",
    )
    with pytest.raises(YTDLPProviderError, match="bounded provider failure"):
        await MediaAdapter(youtube_provider=FailedProvider()).execute(
            PlanNode(id="media", capability_id="youtube_metadata", adapter="media"),
            context,
        )
    assert context.attempts[-1].consumed_budget == {
        "bytes": 321,
        "decompressed_bytes": 321,
        "redirects": 1,
    }
    assert context.attempts[-1].failure_code == "media_extraction_failed"


@pytest.mark.asyncio
async def test_successful_youtube_provider_usage_survives_later_output_failure(
    tmp_path: Path,
) -> None:
    target = "https://www.youtube.com/watch?v=video-1"
    context = await _context(
        tmp_path,
        target=target,
        body=b"<html>pre-acquired page without metadata JSON</html>",
        media_type="text/html",
    )
    context.request = FetchRequest(
        target=target,
        budget=ResourceBudget(
            bytes=600,
            decompressed_bytes=600,
            redirects=2,
        ),
    )

    with pytest.raises(
        AdapterBudgetExceededError,
        match="decompressed_bytes budget exhausted",
    ):
        await MediaAdapter(youtube_provider=_YouTube()).execute(
            PlanNode(id="media", capability_id="youtube_metadata", adapter="media"),
            context,
        )

    assert context.attempts[-1].consumed_budget == {
        "bytes": 512,
        "decompressed_bytes": 512,
        "redirects": 1,
    }
    assert context.attempts[-1].failure_code == "budget_exhausted"


@pytest.mark.parametrize(
    "target",
    [
        "http://www.youtube.com/watch?v=video-1",
        "https://www.youtube.com:444/watch?v=video-1",
        "https://www.youtube.com/playlist?list=playlist-1",
    ],
)
@pytest.mark.asyncio
async def test_media_adapter_rejects_unsafe_youtube_targets_before_provider_use(
    tmp_path: Path,
    target: str,
) -> None:
    provider = _YouTube()
    context = await _context(
        tmp_path,
        target=target,
        body=b"<html>pre-acquired page without metadata JSON</html>",
        media_type="text/html",
    )

    with pytest.raises(AdapterExecutionError):
        await MediaAdapter(youtube_provider=provider).execute(
            PlanNode(id="media", capability_id="youtube_metadata", adapter="media"),
            context,
        )

    assert provider.target == ""
    assert context.attempts[-1].failure_code == "media_extraction_failed"


def _deep_youtube_document(depth: int) -> bytes:
    nested: dict[str, object] = {}
    cursor = nested
    for index in range(depth):
        child: dict[str, object] = {}
        cursor[f"level-{index}"] = child
        cursor = child
    return json.dumps(
        {
            "id": "video-1",
            "title": "Deep metadata",
            "nested": nested,
        },
    ).encode()


@pytest.mark.parametrize(
    "body",
    [
        b'{"id":"video-2","title":"Mismatched metadata"}',
        b'{"id":"video-1","id":"video-2","title":"Duplicate metadata"}',
        b'{"id":"video-1","title":"Non-finite metadata","duration":NaN}',
        _deep_youtube_document(70),
    ],
)
@pytest.mark.asyncio
async def test_preacquired_youtube_json_is_strict_and_bound_to_the_target(
    tmp_path: Path,
    body: bytes,
) -> None:
    context = await _context(
        tmp_path,
        target="https://www.youtube.com/watch?v=video-1",
        body=body,
        media_type="application/json",
    )

    with pytest.raises(AdapterExecutionError):
        await MediaAdapter(youtube_provider=_YouTube()).execute(
            PlanNode(id="media", capability_id="youtube_metadata", adapter="media"),
            context,
        )

    assert context.attempts[-1].consumed_budget == {}
    assert context.attempts[-1].failure_code == "media_extraction_failed"


@pytest.mark.asyncio
async def test_injected_youtube_provider_id_mismatch_preserves_usage(
    tmp_path: Path,
) -> None:
    class MismatchedProvider:
        async def metadata(
            self,
            target: str,
            *,
            timeout_seconds: float,
            maximum_output_bytes: int,
            maximum_network_bytes: int,
            maximum_redirects: int,
        ) -> YouTubeMetadataResponse:
            del (
                target,
                timeout_seconds,
                maximum_output_bytes,
                maximum_network_bytes,
                maximum_redirects,
            )
            return YouTubeMetadataResponse(
                metadata={
                    "id": "video-2",
                    "title": "Metadata for a different video",
                },
                network_bytes=123,
                decompressed_bytes=123,
                redirects=1,
            )

    context = await _context(
        tmp_path,
        target="https://www.youtube.com/watch?v=video-1",
        body=b"<html>pre-acquired page without metadata JSON</html>",
        media_type="text/html",
    )

    with pytest.raises(YTDLPProviderError, match="invalid result"):
        await MediaAdapter(youtube_provider=MismatchedProvider()).execute(
            PlanNode(id="media", capability_id="youtube_metadata", adapter="media"),
            context,
        )

    assert context.attempts[-1].consumed_budget == {
        "bytes": 123,
        "decompressed_bytes": 123,
        "redirects": 1,
    }
    assert context.attempts[-1].failure_code == "media_extraction_failed"


@pytest.mark.asyncio
async def test_transcript_uses_configured_worker_for_acquired_audio(tmp_path: Path) -> None:
    context = await _context(
        tmp_path,
        target="https://media.example/audio.mp3",
        body=b"acquired-audio",
        media_type="audio/mpeg",
    )
    await MediaAdapter(transcriber=_Transcriber()).execute(
        PlanNode(id="media", capability_id="transcript", adapter="media"),
        context,
    )
    assert context.artifacts[-1].representation == "transcript"
    assert b"bounded speech transcript" in await context.cas.get(context.artifacts[-1].cas_uri)


@pytest.mark.parametrize(
    ("capability_id", "target", "media_type", "body", "message"),
    [
        (
            "transcript",
            "https://media.example/audio.mp3",
            "audio/mpeg",
            b"acquired-audio",
            "configured bounded transcription worker",
        ),
        (
            "youtube_metadata",
            "https://www.youtube.com/watch?v=video-1",
            "text/html",
            b"<html>pre-acquired page</html>",
            "isolated yt-dlp connector",
        ),
    ],
)
@pytest.mark.asyncio
async def test_missing_optional_media_provider_is_a_typed_recorded_failure(
    capability_id: str,
    target: str,
    media_type: str,
    body: bytes,
    message: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if capability_id == "youtube_metadata":
        def missing_distribution(_: str) -> str:
            raise PackageNotFoundError

        monkeypatch.setattr(
            "fetech.yt_dlp._distribution_version",
            missing_distribution,
        )
    context = await _context(
        tmp_path,
        target=target,
        body=body,
        media_type=media_type,
    )
    with pytest.raises(AdapterDependencyError, match=message):
        await MediaAdapter().execute(
            PlanNode(id="media", capability_id=capability_id, adapter="media"),
            context,
        )
    assert context.attempts[-1].status == AttemptStatus.FAILED
    assert context.attempts[-1].failure_code == "dependency_missing"
    assert context.capability_outcomes[-1].status == CapabilityOutcomeStatus.DEPENDENCY_MISSING


@pytest.mark.parametrize("worker", [FFprobeWorker(), TesseractOCRWorker(), FFmpegThumbnailWorker()])
@pytest.mark.asyncio
async def test_default_media_workers_report_missing_binaries(
    worker: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr("fetech.adapters.media.shutil.which", lambda _: None)
    with pytest.raises(AdapterDependencyError):
        if isinstance(worker, FFprobeWorker):
            await worker.probe(b"media", timeout_seconds=1, maximum_output_bytes=1_000)
        elif isinstance(worker, TesseractOCRWorker):
            await worker.extract_text(
                _png(),
                language="en",
                timeout_seconds=1,
                maximum_output_bytes=1_000,
            )
        else:
            assert isinstance(worker, FFmpegThumbnailWorker)
            await worker.thumbnail(
                b"media",
                timeout_seconds=1,
                maximum_output_bytes=1_000,
            )


@pytest.mark.asyncio
async def test_ffprobe_worker_rejects_malformed_bounded_output_without_leaking_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    async def malformed(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
        isolation: object,
    ) -> ProcessResult:
        observed.update(
            arguments=arguments,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            memory_mb=memory_mb,
            maximum_output_bytes=maximum_output_bytes,
            isolation=isolation,
        )
        return ProcessResult(
            returncode=0,
            stdout=b"not-json",
            stderr=b"private media worker detail",
        )

    monkeypatch.setattr("fetech.adapters.media.shutil.which", lambda _: "/usr/bin/ffprobe")
    monkeypatch.setattr("fetech.adapters.media.run_bounded", malformed)
    with pytest.raises(AdapterExecutionError, match="malformed JSON") as caught:
        await FFprobeWorker().probe(
            b"media",
            timeout_seconds=2,
            maximum_output_bytes=3_000,
        )
    assert "private media worker detail" not in str(caught.value)
    assert observed["arguments"][0] == "/usr/bin/ffprobe"  # type: ignore[index]
    assert observed["stdin"] == b"media"
    assert observed["memory_mb"] == 512
    assert observed["maximum_output_bytes"] == 3_000


@pytest.mark.asyncio
async def test_ffmpeg_worker_rejects_non_png_output_and_uses_fixed_arguments(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed_arguments: tuple[str, ...] = ()

    async def invalid_image(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
        isolation: object,
    ) -> ProcessResult:
        del stdin, timeout_seconds, memory_mb, maximum_output_bytes, isolation
        nonlocal observed_arguments
        observed_arguments = arguments
        return ProcessResult(returncode=0, stdout=b"not-an-image", stderr=b"private")

    monkeypatch.setattr("fetech.adapters.media.shutil.which", lambda _: "/usr/bin/ffmpeg")
    monkeypatch.setattr("fetech.adapters.media.run_bounded", invalid_image)
    with pytest.raises(AdapterExecutionError, match="valid PNG"):
        await FFmpegThumbnailWorker().thumbnail(
            b"media",
            timeout_seconds=2,
            maximum_output_bytes=3_000,
        )
    assert observed_arguments[0] == "/usr/bin/ffmpeg"
    assert "pipe:0" in observed_arguments
    assert "pipe:1" in observed_arguments


@pytest.mark.asyncio
async def test_invalid_probe_output_is_recorded_as_typed_execution_failure(
    tmp_path: Path,
) -> None:
    class AudioOnlyProbe:
        async def probe(
            self,
            body: bytes,
            *,
            timeout_seconds: float,
            maximum_output_bytes: int,
        ) -> Mapping[str, object]:
            del body, timeout_seconds, maximum_output_bytes
            return {
                "format": {"format_name": "mp3"},
                "streams": [{"codec_type": "audio", "codec_name": "mp3"}],
            }

    context = await _context(
        tmp_path,
        target="https://media.example/video.mp4",
        body=b"not-a-video",
        media_type="video/mp4",
    )
    with pytest.raises(AdapterExecutionError, match="no video stream"):
        await MediaAdapter(probe=AudioOnlyProbe()).execute(
            PlanNode(id="media", capability_id="video_metadata", adapter="media"),
            context,
        )
    assert context.attempts[-1].failure_code == "media_extraction_failed"
    assert context.capability_outcomes[-1].status == CapabilityOutcomeStatus.FAILED


@pytest.mark.parametrize("capability_id", ["video_metadata", "youtube_metadata"])
@pytest.mark.asyncio
async def test_hostile_provider_mapping_is_sanitized_at_the_validation_boundary(
    tmp_path: Path,
    capability_id: str,
) -> None:
    class HostileMapping(Mapping[str, object]):
        def __getitem__(self, key: str) -> object:
            del key
            raise RuntimeError("private-provider-secret")

        def __iter__(self) -> object:
            return iter(("format",))

        def __len__(self) -> int:
            return 1

    class Probe:
        async def probe(
            self,
            body: bytes,
            *,
            timeout_seconds: float,
            maximum_output_bytes: int,
        ) -> Mapping[str, object]:
            del body, timeout_seconds, maximum_output_bytes
            return HostileMapping()

    class YouTube:
        async def metadata(
            self,
            target: str,
            *,
            timeout_seconds: float,
            maximum_output_bytes: int,
            maximum_network_bytes: int,
            maximum_redirects: int,
        ) -> YouTubeMetadataResponse:
            del (
                target,
                timeout_seconds,
                maximum_output_bytes,
                maximum_network_bytes,
                maximum_redirects,
            )
            return YouTubeMetadataResponse(
                metadata=HostileMapping(),
                network_bytes=10,
                decompressed_bytes=10,
                redirects=0,
            )

    youtube = capability_id == "youtube_metadata"
    context = await _context(
        tmp_path,
        target=(
            "https://www.youtube.com/watch?v=video-1"
            if youtube
            else "https://media.example/video.mp4"
        ),
        body=(
            b"<html>pre-acquired page</html>"
            if youtube
            else b"bounded-video"
        ),
        media_type="text/html" if youtube else "video/mp4",
    )
    adapter = MediaAdapter(
        probe=Probe(),
        youtube_provider=YouTube(),
    )

    with pytest.raises(AdapterExecutionError, match="invalid result") as caught:
        await adapter.execute(
            PlanNode(id="media", capability_id=capability_id, adapter="media"),
            context,
        )

    assert "private-provider-secret" not in str(caught.value)
    assert "private-provider-secret" not in " ".join(context.attempts[-1].warnings)


@pytest.mark.parametrize(
    ("thumbnail", "media_type", "message"),
    [
        (b"not-an-image", "image/png", "unsupported or malformed"),
        (_png(2, 2), "image/jpeg", "does not match"),
    ],
)
@pytest.mark.asyncio
async def test_thumbnail_provider_bytes_and_declared_type_must_agree(
    tmp_path: Path,
    thumbnail: bytes,
    media_type: str,
    message: str,
) -> None:
    class Thumbnail:
        async def thumbnail(
            self,
            body: bytes,
            *,
            timeout_seconds: float,
            maximum_output_bytes: int,
        ) -> tuple[bytes, str]:
            del body, timeout_seconds, maximum_output_bytes
            return thumbnail, media_type

    context = await _context(
        tmp_path,
        target="https://media.example/video.mp4",
        body=b"bounded-video",
        media_type="video/mp4",
    )

    with pytest.raises(AdapterExecutionError, match=message):
        await MediaAdapter(thumbnailer=Thumbnail()).execute(
            PlanNode(id="thumbnail", capability_id="thumbnail", adapter="media"),
            context,
        )


@pytest.mark.asyncio
async def test_image_pixel_bound_fails_before_any_complex_decoder(tmp_path: Path) -> None:
    context = await _context(
        tmp_path,
        target="https://media.example/bomb.png",
        body=_png(100_000, 100_000),
        media_type="image/png",
    )
    with pytest.raises(AdapterExecutionError, match="pixel bound"):
        await MediaAdapter(maximum_image_pixels=1_000_000).execute(
            PlanNode(id="media", capability_id="image_metadata", adapter="media"),
            context,
        )
    assert context.attempts[-1].failure_code == "media_extraction_failed"


@pytest.mark.asyncio
async def test_podcast_dtd_is_rejected_without_entity_expansion(tmp_path: Path) -> None:
    context = await _context(
        tmp_path,
        target="https://podcast.example/feed.xml",
        body=(
            b'<!DOCTYPE rss [<!ENTITY secret SYSTEM "file:///etc/passwd">]>'
            b"<rss><channel><item><title>&secret;</title></item></channel></rss>"
        ),
        media_type="application/rss+xml",
    )
    with pytest.raises(AdapterExecutionError, match="declarations are forbidden"):
        await MediaAdapter().execute(
            PlanNode(id="media", capability_id="podcast_feed", adapter="media"),
            context,
        )


def test_image_validation_rejects_truncated_png_and_supports_tiff_and_webp() -> None:
    with pytest.raises(AdapterExecutionError, match="image data or end marker"):
        _image_metadata(_png()[:-12], maximum_pixels=1_000_000)

    tiff = (
        b"II"
        + struct.pack("<HI", 42, 8)
        + struct.pack("<H", 2)
        + struct.pack("<HHI4s", 0x0100, 4, 1, struct.pack("<I", 12))
        + struct.pack("<HHI4s", 0x0101, 4, 1, struct.pack("<I", 8))
        + struct.pack("<I", 0)
    )
    webp = (
        b"RIFF"
        + struct.pack("<I", 22)
        + b"WEBPVP8X"
        + struct.pack("<I", 10)
        + b"\x00\x00\x00\x00"
        + (11).to_bytes(3, "little")
        + (7).to_bytes(3, "little")
    )

    assert _image_metadata(tiff, maximum_pixels=1_000_000)["format"] == "tiff"
    assert _image_metadata(webp, maximum_pixels=1_000_000) == {
        "format": "webp",
        "width": 12,
        "height": 8,
        "encoding": "extended",
    }


@pytest.mark.parametrize(
    ("body", "media_type", "suffix"),
    [
        (b"GIF89a" + struct.pack("<HH", 1, 1) + b"\x00\x00\x00;", "image/gif", "gif"),
        (
            b"\xff\xd8\xff\xc0\x00\x08\x08\x00\x01\x00\x01\x01\xff\xd9",
            "image/jpeg",
            "jpg",
        ),
        (
            b"II"
            + struct.pack("<HI", 42, 8)
            + struct.pack("<H", 2)
            + struct.pack("<HHI4s", 0x0100, 4, 1, struct.pack("<I", 1))
            + struct.pack("<HHI4s", 0x0101, 4, 1, struct.pack("<I", 1))
            + struct.pack("<I", 0),
            "image/tiff",
            "tiff",
        ),
        (
            b"RIFF"
            + struct.pack("<I", 22)
            + b"WEBPVP8X"
            + struct.pack("<I", 10)
            + b"\x00\x00\x00\x00"
            + (0).to_bytes(3, "little")
            + (0).to_bytes(3, "little"),
            "image/webp",
            "webp",
        ),
    ],
)
@pytest.mark.asyncio
async def test_header_only_images_are_never_admitted_as_primary_evidence(
    tmp_path: Path,
    body: bytes,
    media_type: str,
    suffix: str,
) -> None:
    context = await _context(
        tmp_path,
        target=f"https://media.example/header-only.{suffix}",
        body=body,
        media_type=media_type,
    )

    with pytest.raises(AdapterExecutionError, match="isolated image decoder rejected"):
        await MediaAdapter().execute(
            PlanNode(id="image", capability_id="image", adapter="media"),
            context,
        )

    assert not context.accepted


@pytest.mark.asyncio
async def test_provider_wrong_type_and_secret_exception_are_sanitized(
    tmp_path: Path,
) -> None:
    class WrongOCR:
        async def extract_text(
            self,
            body: bytes,
            *,
            language: str | None,
            timeout_seconds: float,
            maximum_output_bytes: int,
        ) -> str:
            del body, language, timeout_seconds, maximum_output_bytes
            return object()  # type: ignore[return-value]

    class SecretTranscriber:
        async def transcribe(
            self,
            body: bytes,
            *,
            media_type: str,
            language: str | None,
            timeout_seconds: float,
            maximum_output_bytes: int,
        ) -> str:
            del body, media_type, language, timeout_seconds, maximum_output_bytes
            raise RuntimeError("secret-provider-token")

    image_context = await _context(
        tmp_path,
        target="https://media.example/image.png",
        body=_png(),
        media_type="image/png",
    )
    with pytest.raises(AdapterExecutionError, match="invalid result"):
        await MediaAdapter(ocr=WrongOCR()).execute(
            PlanNode(id="ocr", capability_id="image_ocr", adapter="media"),
            image_context,
        )

    audio_context = await _context(
        tmp_path,
        target="https://media.example/audio.mp3",
        body=b"bounded audio fixture",
        media_type="audio/mpeg",
    )
    with pytest.raises(AdapterExecutionError, match="transcription provider failed") as caught:
        await MediaAdapter(transcriber=SecretTranscriber()).execute(
            PlanNode(id="transcript", capability_id="transcript", adapter="media"),
            audio_context,
        )
    assert "secret-provider-token" not in str(caught.value)
    assert "secret-provider-token" not in " ".join(audio_context.attempts[-1].warnings)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("body", "adapter", "message"),
    [
        (
            b"<rss><channel>"
            + (b"<group>" * 5)
            + b"<item><title>episode</title></item>"
            + (b"</group>" * 5)
            + b"</channel></rss>",
            MediaAdapter(maximum_podcast_depth=4),
            "depth bound",
        ),
        (
            b"<rss><channel>"
            + b"".join(
                b"<item><title>episode</title></item>" for _ in range(4)
            )
            + b"</channel></rss>",
            MediaAdapter(maximum_podcast_nodes=6),
            "node bound",
        ),
    ],
)
async def test_podcast_depth_and_node_limits_apply_before_tree_admission(
    tmp_path: Path,
    body: bytes,
    adapter: MediaAdapter,
    message: str,
) -> None:
    context = await _context(
        tmp_path,
        target="https://podcast.example/feed.xml",
        body=body,
        media_type="application/rss+xml",
    )
    with pytest.raises(AdapterExecutionError, match=message):
        await adapter.execute(
            PlanNode(id="podcast", capability_id="podcast_feed", adapter="media"),
            context,
        )
