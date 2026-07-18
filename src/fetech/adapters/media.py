"""Bounded normalization for pre-acquired image, audio, video, and media artifacts.

The adapter never downloads media.  HTTP acquisition and destination policy
remain owned by the runtime transport boundary.  Native parsing is deliberately
limited to bounded headers, subtitle text, podcast XML, and selected EXIF
fields.  Complex codecs and OCR run through resource-bounded worker protocols.
"""

from __future__ import annotations

import io
import json
import math
import re
import shutil
import struct
import sys
import wave
import xml.etree.ElementTree as ET
import zlib
from collections.abc import Mapping
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Literal, Protocol
from urllib.parse import urlsplit, urlunsplit

from fetech.adapters.base import (
    AdapterBudgetExceededError,
    AdapterDependencyError,
    AdapterExecutionError,
    ExecutionContext,
)
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
from fetech.yt_dlp import (
    YouTubeMetadataResponse,
    YTDLPBudgetExceededError,
    YTDLPMetadataWorker,
    YTDLPProviderError,
    YTDLPUsageError,
    _canonical_youtube_video_url,
    _project_metadata,
)

MEDIA_CAPABILITIES = frozenset(
    {
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
    }
)

_XML_DECLARATIONS = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SUBTITLE_TIMING = re.compile(
    r"^\s*(?:(\d+):)?(\d{2}):(\d{2})[,.](\d{3})\s*-->\s*"
    r"(?:(\d+):)?(\d{2}):(\d{2})[,.](\d{3})(?:\s+.*)?$"
)
_EXIF_TAGS = {
    0x010E: "image_description",
    0x010F: "make",
    0x0110: "model",
    0x0112: "orientation",
    0x011A: "x_resolution",
    0x011B: "y_resolution",
    0x0128: "resolution_unit",
    0x0131: "software",
    0x829A: "exposure_time",
    0x829D: "f_number",
    0x8827: "iso_speed",
    0x920A: "focal_length",
    0xA002: "pixel_width",
    0xA003: "pixel_height",
    0xA403: "white_balance",
    0xA405: "focal_length_35mm",
}
_SENSITIVE_EXIF_TAGS = frozenset(
    {
        0x8825,  # GPSInfo
        0x927C,  # MakerNote
        0x9286,  # UserComment
        0xA420,  # ImageUniqueID
        0xA430,  # CameraOwnerName
        0xA431,  # BodySerialNumber
        0xC62F,  # CameraSerialNumber
    }
)
_EXIF_TYPE_SIZES = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8}
_SAFE_FFPROBE_FORMAT_FIELDS = frozenset(
    {"format_name", "duration", "size", "bit_rate", "start_time", "nb_streams"}
)
_SAFE_FFPROBE_STREAM_FIELDS = frozenset(
    {
        "index",
        "codec_name",
        "codec_long_name",
        "codec_type",
        "profile",
        "width",
        "height",
        "sample_rate",
        "channels",
        "channel_layout",
        "duration",
        "bit_rate",
        "r_frame_rate",
        "avg_frame_rate",
    }
)
_MAX_MEDIA_INPUT_BYTES = 64_000_000
_MAX_PODCAST_INPUT_BYTES = 5_000_000
_MAX_PODCAST_NODES = 20_000
_MAX_PODCAST_DEPTH = 64
_MAX_YOUTUBE_JSON_NODES = 20_000
_MAX_YOUTUBE_JSON_DEPTH = 64


class MediaProbe(Protocol):
    """Resource-bounded audio/video metadata worker."""

    async def probe(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> Mapping[str, object]: ...


class OCRProvider(Protocol):
    """Resource-bounded OCR worker."""

    async def extract_text(
        self,
        body: bytes,
        *,
        language: str | None,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> str: ...


class TranscriptProvider(Protocol):
    """Configured speech-to-text worker for already acquired media bytes."""

    async def transcribe(
        self,
        body: bytes,
        *,
        media_type: str,
        language: str | None,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> str: ...


class ThumbnailProvider(Protocol):
    """Resource-bounded frame/thumbnail extraction worker."""

    async def thumbnail(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> tuple[bytes, str]: ...


class YouTubeMetadataProvider(Protocol):
    """Policy-aware, separately isolated yt-dlp-compatible connector."""

    async def metadata(
        self,
        target: str,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
        maximum_network_bytes: int,
        maximum_redirects: int,
    ) -> YouTubeMetadataResponse: ...


class ImageValidationProvider(Protocol):
    """Resource-bounded full image decoder used before evidence admission."""

    async def validate(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_input_bytes: int,
        maximum_pixels: int,
    ) -> Mapping[str, object]: ...


@dataclass(frozen=True)
class MediaExtraction:
    payload: bytes
    representation: str
    media_type: str
    parser: str
    locators: tuple[str, ...]
    quality_text: str = ""
    accepted: bool = True
    observed_format: str = ""
    provider_network_bytes: int = 0
    provider_decompressed_bytes: int = 0
    provider_redirects: int = 0


class FFprobeWorker:
    """Invoke FFprobe without a shell and with time, memory, and output bounds."""

    def __init__(self, *, isolation: WorkerIsolationRuntime | None = None) -> None:
        self.isolation = isolation or WorkerIsolationRuntime.from_environment()

    async def probe(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> Mapping[str, object]:
        executable = shutil.which("ffprobe")
        if executable is None:
            raise AdapterDependencyError(
                "audio/video metadata requires FFprobe from an FFmpeg installation"
            )
        try:
            process = await run_bounded(
                (
                    executable,
                    "-v",
                    "error",
                    "-show_entries",
                    (
                        "format=format_name,duration,size,bit_rate,start_time,nb_streams:"
                        "stream=index,codec_name,codec_long_name,codec_type,profile,width,height,"
                        "sample_rate,channels,channel_layout,duration,bit_rate,r_frame_rate,"
                        "avg_frame_rate"
                    ),
                    "-of",
                    "json",
                    "pipe:0",
                ),
                body,
                timeout_seconds=timeout_seconds,
                memory_mb=512,
                maximum_output_bytes=maximum_output_bytes,
                isolation=self.isolation.request(
                    WorkerIsolationProfile.MEDIA_NATIVE_OFFLINE
                ),
            )
        except LogicBackendError as exc:
            raise AdapterExecutionError("bounded FFprobe worker failed") from exc
        if process.returncode != 0:
            raise AdapterExecutionError("FFprobe could not parse the acquired media")
        try:
            document = json.loads(process.stdout, parse_constant=_reject_json_constant)
        except (json.JSONDecodeError, ValueError) as exc:
            raise AdapterExecutionError("FFprobe returned malformed JSON") from exc
        if not isinstance(document, dict):
            raise AdapterExecutionError("FFprobe response must be an object")
        return document


class TesseractOCRWorker:
    """Invoke Tesseract over stdin/stdout without creating caller-visible files."""

    def __init__(self, *, isolation: WorkerIsolationRuntime | None = None) -> None:
        self.isolation = isolation or WorkerIsolationRuntime.from_environment()

    async def extract_text(
        self,
        body: bytes,
        *,
        language: str | None,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> str:
        executable = shutil.which("tesseract")
        if executable is None:
            raise AdapterDependencyError(
                "image OCR requires Tesseract in the isolated media worker"
            )
        language_code = _tesseract_language(language)
        try:
            process = await run_bounded(
                (executable, "stdin", "stdout", "-l", language_code),
                body,
                timeout_seconds=timeout_seconds,
                memory_mb=512,
                maximum_output_bytes=maximum_output_bytes,
                isolation=self.isolation.request(
                    WorkerIsolationProfile.MEDIA_NATIVE_OFFLINE
                ),
            )
        except LogicBackendError as exc:
            raise AdapterExecutionError("bounded Tesseract worker failed") from exc
        if process.returncode != 0:
            raise AdapterExecutionError("Tesseract could not parse the acquired image")
        return _bounded_text(process.stdout.decode("utf-8", errors="replace"), maximum_output_bytes)


class FFmpegThumbnailWorker:
    """Extract one bounded PNG frame with FFmpeg through fixed arguments."""

    def __init__(self, *, isolation: WorkerIsolationRuntime | None = None) -> None:
        self.isolation = isolation or WorkerIsolationRuntime.from_environment()

    async def thumbnail(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
    ) -> tuple[bytes, str]:
        executable = shutil.which("ffmpeg")
        if executable is None:
            raise AdapterDependencyError(
                "thumbnail extraction requires FFmpeg in the isolated media worker"
            )
        try:
            process = await run_bounded(
                (
                    executable,
                    "-v",
                    "error",
                    "-i",
                    "pipe:0",
                    "-frames:v",
                    "1",
                    "-vf",
                    "scale=320:-2:force_original_aspect_ratio=decrease",
                    "-f",
                    "image2pipe",
                    "-vcodec",
                    "png",
                    "pipe:1",
                ),
                body,
                timeout_seconds=timeout_seconds,
                memory_mb=768,
                maximum_output_bytes=maximum_output_bytes,
                isolation=self.isolation.request(
                    WorkerIsolationProfile.MEDIA_NATIVE_OFFLINE
                ),
            )
        except LogicBackendError as exc:
            raise AdapterExecutionError("bounded FFmpeg thumbnail worker failed") from exc
        if process.returncode != 0 or not process.stdout.startswith(b"\x89PNG\r\n\x1a\n"):
            raise AdapterExecutionError("FFmpeg did not return a valid PNG thumbnail")
        return process.stdout, "image/png"


class PillowImageValidationWorker:
    """Decode an image fully in a resource-bounded subprocess."""

    def __init__(self, *, isolation: WorkerIsolationRuntime | None = None) -> None:
        self.isolation = isolation or WorkerIsolationRuntime.from_environment()

    async def validate(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
        maximum_input_bytes: int,
        maximum_pixels: int,
    ) -> Mapping[str, object]:
        if len(body) > maximum_input_bytes:
            raise AdapterExecutionError(
                "image input exceeds the isolated decoder byte bound"
            )
        try:
            process = await run_bounded(
                (
                    sys.executable,
                    "-m",
                    "fetech.image_worker",
                    str(maximum_input_bytes),
                    str(maximum_pixels),
                ),
                body,
                timeout_seconds=timeout_seconds,
                memory_mb=512,
                maximum_output_bytes=8_192,
                isolation=self.isolation.request(
                    WorkerIsolationProfile.IMAGE_DECODER
                ),
            )
        except LogicBackendError as exc:
            raise AdapterExecutionError(
                "bounded image validation worker failed"
            ) from exc
        if process.returncode == 2:
            raise AdapterDependencyError(
                "full image validation requires the fetech[media] extra"
            )
        if process.returncode != 0:
            raise AdapterExecutionError(
                "isolated image decoder rejected the acquired bytes"
            )
        try:
            document = json.loads(
                process.stdout,
                parse_constant=_reject_json_constant,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise AdapterExecutionError(
                "image validation worker returned malformed output"
            ) from exc
        if (
            not isinstance(document, dict)
            or set(document) != {"format", "height", "width"}
            or not isinstance(document["format"], str)
            or not isinstance(document["width"], int)
            or isinstance(document["width"], bool)
            or not isinstance(document["height"], int)
            or isinstance(document["height"], bool)
            or document["width"] <= 0
            or document["height"] <= 0
            or document["width"] * document["height"] > maximum_pixels
        ):
            raise AdapterExecutionError(
                "image validation worker returned an invalid result"
            )
        return document


class MediaAdapter:
    """Normalize a raw media artifact already acquired through the safe HTTP boundary."""

    def __init__(
        self,
        *,
        probe: MediaProbe | None = None,
        ocr: OCRProvider | None = None,
        transcriber: TranscriptProvider | None = None,
        thumbnailer: ThumbnailProvider | None = None,
        youtube_provider: YouTubeMetadataProvider | None = None,
        image_validator: ImageValidationProvider | None = None,
        maximum_metadata_fields: int = 256,
        maximum_text_bytes: int = 1_000_000,
        maximum_thumbnail_bytes: int = 5_000_000,
        maximum_image_pixels: int = 100_000_000,
        maximum_input_bytes: int = _MAX_MEDIA_INPUT_BYTES,
        maximum_podcast_bytes: int = _MAX_PODCAST_INPUT_BYTES,
        maximum_podcast_nodes: int = _MAX_PODCAST_NODES,
        maximum_podcast_depth: int = _MAX_PODCAST_DEPTH,
        isolation: WorkerIsolationRuntime | None = None,
    ) -> None:
        if min(
            maximum_metadata_fields,
            maximum_text_bytes,
            maximum_thumbnail_bytes,
            maximum_image_pixels,
            maximum_input_bytes,
            maximum_podcast_bytes,
            maximum_podcast_nodes,
            maximum_podcast_depth,
        ) <= 0:
            raise ValueError("media adapter limits must be positive")
        runtime = isolation or WorkerIsolationRuntime.from_environment()
        self.probe = probe or FFprobeWorker(isolation=runtime)
        self.ocr = ocr or TesseractOCRWorker(isolation=runtime)
        self.transcriber = transcriber
        self.thumbnailer = thumbnailer or FFmpegThumbnailWorker(isolation=runtime)
        self.youtube_provider = youtube_provider or YTDLPMetadataWorker(
            isolation=runtime
        )
        self.image_validator = image_validator or PillowImageValidationWorker(
            isolation=runtime
        )
        self.maximum_metadata_fields = maximum_metadata_fields
        self.maximum_text_bytes = maximum_text_bytes
        self.maximum_thumbnail_bytes = maximum_thumbnail_bytes
        self.maximum_image_pixels = maximum_image_pixels
        self.maximum_input_bytes = maximum_input_bytes
        self.maximum_podcast_bytes = min(maximum_podcast_bytes, maximum_input_bytes)
        self.maximum_podcast_nodes = maximum_podcast_nodes
        self.maximum_podcast_depth = maximum_podcast_depth

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            adapter_version="0.4.0a0",
            sanitized_destination=sanitize_url_for_request(
                context.request.target,
                context.request,
            ),
            status=AttemptStatus.RUNNING,
        )
        attempt_index = len(context.attempts)
        context.attempts.append(attempt)
        try:
            if node.capability_id not in MEDIA_CAPABILITIES:
                raise AdapterExecutionError(
                    f"media adapter cannot execute {node.capability_id}"
                )
            raw = context.latest_artifact("raw", "screenshot")
            if raw is None or not context.resources:
                raise AdapterExecutionError(
                    "media normalization requires an acquired source artifact"
                )
            maximum_input = min(
                context.request.budget.bytes,
                context.request.budget.decompressed_bytes,
                self.maximum_input_bytes,
            )
            if raw.size > maximum_input:
                raise AdapterExecutionError("media input exceeds the request byte budget")
            body = await context.cas.get(raw.cas_uri, maximum_bytes=maximum_input)
            timeout_seconds = min(60.0, context.request.budget.deadline_seconds)
            maximum_provider_bytes = min(
                int(context.remaining_budget("bytes")),
                int(context.remaining_budget("decompressed_bytes")),
            )
            maximum_provider_redirects = int(context.remaining_budget("redirects"))
            extraction = await self._extract(
                node.capability_id,
                body,
                target=context.request.target,
                media_type=raw.media_type,
                language=context.request.language,
                timeout_seconds=timeout_seconds,
                maximum_provider_bytes=maximum_provider_bytes,
                maximum_provider_redirects=maximum_provider_redirects,
            )
            context.record_attempt_consumption(
                attempt_index,
                bytes=extraction.provider_network_bytes,
                decompressed_bytes=extraction.provider_decompressed_bytes,
                redirects=extraction.provider_redirects,
            )
            if len(extraction.payload) > max(
                self.maximum_text_bytes,
                self.maximum_thumbnail_bytes,
                maximum_input,
            ):
                raise AdapterExecutionError("media output exceeded its configured byte bound")
            context.require_budget(
                "decompressed_bytes",
                len(extraction.payload),
            )
            quality = _quality(extraction)
            uri, digest, size = await context.cas.put(extraction.payload)
            artifact = build_artifact(
                role="primary" if quality.accepted else "checked-only",
                representation=extraction.representation,
                media_type=extraction.media_type,
                cas_uri=uri,
                digest=digest,
                size=size,
                resource=context.resources[-1],
                extractor=f"{extraction.parser}/0.4",
                quality=quality,
                parents=(raw,),
                locators=extraction.locators,
            )
            context.artifacts.append(artifact)
            context.accepted = context.accepted or quality.accepted
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.APPLIED,
                "media",
                bounded=True,
                format=extraction.observed_format,
                representation=extraction.representation,
                output_bytes=size,
            )
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.SUCCEEDED,
                    "finished_at": datetime.now(UTC),
                    "bytes_received": len(body) + extraction.provider_network_bytes,
                    "parser": extraction.parser,
                    "artifact_ids": (artifact.artifact_id,),
                    "consumed_budget": {
                        "bytes": extraction.provider_network_bytes,
                        "decompressed_bytes": (
                            len(extraction.payload)
                            + extraction.provider_decompressed_bytes
                        ),
                        "redirects": extraction.provider_redirects,
                    },
                }
            )
        except TimeoutError as exc:
            _record_provider_failure_usage(context, attempt_index, exc)
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "media",
                failure_code="budget_exhausted",
            )
            current_attempt = context.attempts[attempt_index]
            context.attempts[attempt_index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "budget_exhausted",
                    "warnings": ("media connector deadline budget exhausted",),
                }
            )
            raise
        except AdapterBudgetExceededError as exc:
            _record_provider_failure_usage(context, attempt_index, exc)
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "media",
                failure_code="budget_exhausted",
            )
            current_attempt = context.attempts[attempt_index]
            context.attempts[attempt_index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "budget_exhausted",
                    "warnings": (_bounded_text(str(exc), 256),),
                }
            )
            raise
        except AdapterDependencyError as exc:
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.DEPENDENCY_MISSING,
                "media",
                dependency=_bounded_text(str(exc), 256),
            )
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "dependency_missing",
                    "warnings": (_bounded_text(str(exc), 256),),
                }
            )
            raise
        except (AdapterExecutionError, OSError, ValueError, ET.ParseError) as exc:
            _record_provider_failure_usage(context, attempt_index, exc)
            message = _bounded_text(str(exc), 256)
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "media",
                failure_code="media_extraction_failed",
            )
            current_attempt = context.attempts[attempt_index]
            context.attempts[attempt_index] = current_attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "media_extraction_failed",
                    "warnings": (message,),
                }
            )
            if isinstance(exc, AdapterExecutionError):
                raise
            raise AdapterExecutionError(message) from exc

    async def _extract(
        self,
        capability_id: str,
        body: bytes,
        *,
        target: str,
        media_type: str,
        language: str | None,
        timeout_seconds: float,
        maximum_provider_bytes: int,
        maximum_provider_redirects: int,
    ) -> MediaExtraction:
        if capability_id in {"image", "image_metadata"}:
            metadata = await self._validated_image_metadata(
                body,
                timeout_seconds=timeout_seconds,
            )
            if capability_id == "image":
                return MediaExtraction(
                    payload=body,
                    representation="image",
                    media_type=_image_media_type(str(metadata["format"])),
                    parser="isolated-image-decoder",
                    locators=("image:1",),
                    observed_format=str(metadata["format"]),
                )
            return _metadata_extraction(
                capability_id,
                target,
                metadata,
                parser="isolated-image-decoder",
                observed_format=str(metadata["format"]),
            )
        if capability_id in {"image_ocr", "screenshot_to_text"}:
            await self._validated_image_metadata(
                body,
                timeout_seconds=timeout_seconds,
            )
            try:
                text = await self.ocr.extract_text(
                    body,
                    language=language,
                    timeout_seconds=timeout_seconds,
                    maximum_output_bytes=self.maximum_text_bytes,
                )
            except (AdapterDependencyError, AdapterExecutionError):
                raise
            except Exception as exc:
                raise AdapterExecutionError("configured OCR provider failed") from exc
            if not isinstance(text, str):
                raise AdapterExecutionError("OCR provider returned an invalid result")
            return _text_extraction(
                text,
                representation="ocr_text",
                parser="tesseract",
                locator="image:1",
                observed_format="text",
                maximum_text_bytes=self.maximum_text_bytes,
            )
        if capability_id in {"audio_metadata", "video_metadata"}:
            metadata, parser = await self._audio_video_metadata(
                capability_id,
                body,
                timeout_seconds=timeout_seconds,
            )
            return _metadata_extraction(
                capability_id,
                target,
                metadata,
                parser=parser,
                observed_format=capability_id.removesuffix("_metadata"),
            )
        if capability_id == "transcript":
            return await self._transcript(
                body,
                target=target,
                media_type=media_type,
                language=language,
                timeout_seconds=timeout_seconds,
            )
        if capability_id == "youtube_metadata":
            metadata, usage = await self._youtube_metadata(
                body,
                target=target,
                timeout_seconds=timeout_seconds,
                maximum_network_bytes=maximum_provider_bytes,
                maximum_redirects=maximum_provider_redirects,
            )
            return replace(
                _metadata_extraction(
                    capability_id,
                    target,
                    metadata,
                    parser="yt-dlp-info-json",
                    observed_format="youtube",
                ),
                provider_network_bytes=usage.network_bytes,
                provider_decompressed_bytes=usage.decompressed_bytes,
                provider_redirects=usage.redirects,
            )
        if capability_id == "podcast_feed":
            document, locators = _parse_podcast_feed(
                body,
                maximum_episodes=min(1_000, self.maximum_metadata_fields),
                maximum_bytes=self.maximum_podcast_bytes,
                maximum_nodes=self.maximum_podcast_nodes,
                maximum_depth=self.maximum_podcast_depth,
            )
            return MediaExtraction(
                payload=_json_bytes(document),
                representation="podcast_feed",
                media_type="application/vnd.fetech.podcast+json",
                parser="stdlib-podcast",
                locators=locators,
                quality_text=_podcast_quality_text(document),
                observed_format="rss",
            )
        if capability_id == "thumbnail":
            try:
                thumbnail_result = await self.thumbnailer.thumbnail(
                    body,
                    timeout_seconds=timeout_seconds,
                    maximum_output_bytes=self.maximum_thumbnail_bytes,
                )
            except (AdapterDependencyError, AdapterExecutionError):
                raise
            except Exception as exc:
                raise AdapterExecutionError("configured thumbnail provider failed") from exc
            if (
                not isinstance(thumbnail_result, tuple)
                or len(thumbnail_result) != 2
                or not isinstance(thumbnail_result[0], bytes)
                or not isinstance(thumbnail_result[1], str)
            ):
                raise AdapterExecutionError("thumbnail provider returned an invalid result")
            thumbnail, thumbnail_type = thumbnail_result
            if len(thumbnail) > self.maximum_thumbnail_bytes:
                raise AdapterExecutionError("thumbnail exceeded the configured byte bound")
            if (
                thumbnail_type not in {"image/jpeg", "image/png", "image/webp"}
                or not thumbnail
            ):
                raise AdapterExecutionError("thumbnail provider returned an invalid media type")
            thumbnail_metadata = _image_metadata(
                thumbnail,
                maximum_pixels=self.maximum_image_pixels,
            )
            if _image_media_type(str(thumbnail_metadata["format"])) != thumbnail_type:
                raise AdapterExecutionError(
                    "thumbnail provider media type does not match its bytes"
                )
            await self._validated_image_metadata(
                thumbnail,
                timeout_seconds=timeout_seconds,
            )
            return MediaExtraction(
                payload=thumbnail,
                representation="thumbnail",
                media_type=thumbnail_type,
                parser="ffmpeg",
                locators=("frame:1",),
                observed_format=thumbnail_type,
            )
        if capability_id == "exif_metadata":
            metadata = _extract_exif_metadata(
                body,
                maximum_fields=self.maximum_metadata_fields,
            )
            return _metadata_extraction(
                capability_id,
                target,
                metadata,
                parser="builtin-exif",
                observed_format="exif",
            )
        raise AdapterExecutionError(f"unsupported media capability: {capability_id}")

    async def _validated_image_metadata(
        self,
        body: bytes,
        *,
        timeout_seconds: float,
    ) -> dict[str, object]:
        header = _image_metadata(
            body,
            maximum_pixels=self.maximum_image_pixels,
        )
        try:
            decoded = await self.image_validator.validate(
                body,
                timeout_seconds=timeout_seconds,
                maximum_input_bytes=self.maximum_input_bytes,
                maximum_pixels=self.maximum_image_pixels,
            )
            normalized = dict(decoded)
        except (AdapterDependencyError, AdapterExecutionError):
            raise
        except Exception as exc:
            raise AdapterExecutionError(
                "configured image validation provider failed"
            ) from exc
        header_format = header.get("format")
        header_height = header.get("height")
        header_width = header.get("width")
        if (
            not isinstance(header_format, str)
            or not isinstance(header_height, int)
            or isinstance(header_height, bool)
            or not isinstance(header_width, int)
            or isinstance(header_width, bool)
        ):
            raise AdapterExecutionError("bounded image header metadata is invalid")
        expected = {
            "format": header_format,
            "height": header_height,
            "width": header_width,
        }
        observed = {
            "format": str(normalized.get("format", "")).casefold(),
            "height": normalized.get("height"),
            "width": normalized.get("width"),
        }
        if observed != expected:
            raise AdapterExecutionError(
                "image decoder result contradicts bounded header metadata"
            )
        return header

    async def _audio_video_metadata(
        self,
        capability_id: str,
        body: bytes,
        *,
        timeout_seconds: float,
    ) -> tuple[dict[str, object], str]:
        if capability_id == "audio_metadata" and body.startswith(b"RIFF") and body[8:12] == b"WAVE":
            return _wave_metadata(body), "stdlib-wave"
        try:
            raw = await self.probe.probe(
                body,
                timeout_seconds=timeout_seconds,
                maximum_output_bytes=min(self.maximum_text_bytes, 1_000_000),
            )
        except (AdapterDependencyError, AdapterExecutionError):
            raise
        except Exception as exc:
            raise AdapterExecutionError("configured media probe failed") from exc
        try:
            if not isinstance(raw, Mapping):
                raise AdapterExecutionError("media probe returned an invalid result")
            media_kind = capability_id.removesuffix("_metadata")
            metadata = _normalize_ffprobe(raw, expected_kind=media_kind)
        except AdapterExecutionError:
            raise
        except Exception as exc:
            raise AdapterExecutionError(
                "media probe returned an invalid result"
            ) from exc
        return metadata, "ffprobe"

    async def _transcript(
        self,
        body: bytes,
        *,
        target: str,
        media_type: str,
        language: str | None,
        timeout_seconds: float,
    ) -> MediaExtraction:
        suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
        if media_type.startswith("text/") or suffix in {".srt", ".txt", ".vtt"}:
            text, locators = _parse_subtitle_text(
                body,
                maximum_text_bytes=self.maximum_text_bytes,
            )
            return MediaExtraction(
                payload=text.encode("utf-8"),
                representation="transcript",
                media_type="text/plain; charset=utf-8",
                parser="builtin-subtitle",
                locators=locators,
                quality_text=text,
                observed_format=suffix.removeprefix(".") or "text",
            )
        if self.transcriber is None:
            raise AdapterDependencyError(
                "audio/video transcript requires a configured bounded transcription worker"
            )
        try:
            text = await self.transcriber.transcribe(
                body,
                media_type=media_type,
                language=language,
                timeout_seconds=timeout_seconds,
                maximum_output_bytes=self.maximum_text_bytes,
            )
        except (AdapterDependencyError, AdapterExecutionError):
            raise
        except Exception as exc:
            raise AdapterExecutionError("configured transcription provider failed") from exc
        if not isinstance(text, str):
            raise AdapterExecutionError("transcription provider returned an invalid result")
        return _text_extraction(
            text,
            representation="transcript",
            parser="configured-transcriber",
            locator="media:1",
            observed_format="speech-to-text",
            maximum_text_bytes=self.maximum_text_bytes,
        )

    async def _youtube_metadata(
        self,
        body: bytes,
        *,
        target: str,
        timeout_seconds: float,
        maximum_network_bytes: int,
        maximum_redirects: int,
    ) -> tuple[dict[str, object], YouTubeMetadataResponse]:
        safe_target = _canonical_youtube_video_url(target)
        response: YouTubeMetadataResponse
        document = _preacquired_youtube_document(
            body,
            maximum_bytes=min(self.maximum_text_bytes, 1_000_000),
        )
        if document is not None:
            response = YouTubeMetadataResponse(
                metadata=_project_metadata(document, source_url=safe_target),
                network_bytes=0,
                decompressed_bytes=0,
                redirects=0,
            )
        else:
            if maximum_network_bytes <= 0:
                raise AdapterBudgetExceededError("bytes budget exhausted") from None
            try:
                response = await self.youtube_provider.metadata(
                    safe_target,
                    timeout_seconds=timeout_seconds,
                    maximum_output_bytes=min(self.maximum_text_bytes, 1_000_000),
                    maximum_network_bytes=maximum_network_bytes,
                    maximum_redirects=maximum_redirects,
                )
            except (AdapterDependencyError, AdapterExecutionError):
                raise
            except Exception as exc:
                raise AdapterExecutionError("configured YouTube metadata provider failed") from exc
            if not isinstance(response, YouTubeMetadataResponse):
                raise AdapterExecutionError(
                    "yt-dlp metadata provider returned an invalid result"
                ) from None
            if (
                response.network_bytes > maximum_network_bytes
                or response.decompressed_bytes > maximum_network_bytes
                or response.redirects > maximum_redirects
            ):
                raise YTDLPBudgetExceededError(
                    "yt-dlp metadata provider exceeded the request budget",
                    network_bytes=response.network_bytes,
                    decompressed_bytes=response.decompressed_bytes,
                    redirects=response.redirects,
                ) from None
        try:
            if not isinstance(response.metadata, Mapping):
                raise AdapterExecutionError("yt-dlp metadata must be an object")
            projected = _project_metadata(
                response.metadata,
                source_url=safe_target,
            )
            return (
                _normalize_youtube(
                    projected,
                    maximum_fields=self.maximum_metadata_fields,
                    fallback_url=safe_target,
                ),
                response,
            )
        except AdapterExecutionError as exc:
            if (
                response.network_bytes
                or response.decompressed_bytes
                or response.redirects
            ):
                raise YTDLPProviderError(
                    "yt-dlp metadata provider returned an invalid result",
                    network_bytes=response.network_bytes,
                    decompressed_bytes=response.decompressed_bytes,
                    redirects=response.redirects,
                ) from exc
            raise
        except Exception as exc:
            raise AdapterExecutionError(
                "yt-dlp metadata provider returned an invalid result"
            ) from exc


def _record_provider_failure_usage(
    context: ExecutionContext,
    attempt_index: int,
    error: BaseException,
) -> None:
    if not isinstance(error, YTDLPUsageError):
        return
    context.record_attempt_consumption(
        attempt_index,
        bytes=error.network_bytes,
        decompressed_bytes=error.decompressed_bytes,
        redirects=error.redirects,
    )


def _quality(extraction: MediaExtraction) -> QualityAssessment:
    if extraction.quality_text:
        return assess_text(extraction.quality_text)
    if extraction.accepted:
        return QualityAssessment(
            page_state=PageState.OK,
            score=1.0,
            accepted=True,
            completeness=1.0,
            reasons=("bounded media artifact validated",),
        )
    return QualityAssessment(
        page_state=PageState.UNKNOWN,
        score=0.0,
        accepted=False,
        completeness=0.0,
        reasons=("media artifact did not satisfy the request",),
    )


def _metadata_extraction(
    capability_id: str,
    target: str,
    metadata: Mapping[str, object],
    *,
    parser: str,
    observed_format: str,
) -> MediaExtraction:
    document = {
        "schema": "fetech.media.v1",
        "capability": capability_id,
        "source_url": _public_url(target),
        "metadata": dict(metadata),
    }
    return MediaExtraction(
        payload=_json_bytes(document),
        representation="media_metadata",
        media_type="application/vnd.fetech.media+json",
        parser=parser,
        locators=("media:1",),
        observed_format=observed_format,
    )


def _text_extraction(
    text: str,
    *,
    representation: str,
    parser: str,
    locator: str,
    observed_format: str,
    maximum_text_bytes: int,
) -> MediaExtraction:
    cleaned = _CONTROL_CHARACTERS.sub("", text)
    if len(cleaned.encode("utf-8")) > maximum_text_bytes:
        raise AdapterExecutionError("media text output exceeded the configured byte bound")
    return MediaExtraction(
        payload=cleaned.encode("utf-8"),
        representation=representation,
        media_type="text/plain; charset=utf-8",
        parser=parser,
        locators=(locator,),
        quality_text=cleaned,
        observed_format=observed_format,
    )


def _image_metadata(body: bytes, *, maximum_pixels: int) -> dict[str, object]:
    if body.startswith(b"\x89PNG\r\n\x1a\n"):
        _validate_png(body)
        width, height, bit_depth, color_type = struct.unpack(">IIBB", body[16:26])
        metadata: dict[str, object] = {
            "format": "png",
            "width": width,
            "height": height,
            "bit_depth": bit_depth,
            "color_type": color_type,
        }
    elif body[:6] in {b"GIF87a", b"GIF89a"}:
        if len(body) < 14 or body[-1:] != b";":
            raise AdapterExecutionError("GIF structure is truncated or malformed")
        width, height = struct.unpack("<HH", body[6:10])
        metadata = {
            "format": "gif",
            "width": width,
            "height": height,
            "version": body[3:6].decode("ascii"),
        }
    elif body.startswith(b"\xff\xd8"):
        width, height, components = _jpeg_dimensions(body)
        if not body.endswith(b"\xff\xd9"):
            raise AdapterExecutionError("JPEG end marker is missing")
        metadata = {
            "format": "jpeg",
            "width": width,
            "height": height,
            "components": components,
        }
    elif body[:2] in {b"II", b"MM"}:
        width, height = _tiff_dimensions(body)
        metadata = {
            "format": "tiff",
            "width": width,
            "height": height,
        }
    elif body.startswith(b"RIFF") and body[8:12] == b"WEBP":
        width, height, encoding = _webp_dimensions(body)
        metadata = {
            "format": "webp",
            "width": width,
            "height": height,
            "encoding": encoding,
        }
    else:
        raise AdapterExecutionError("unsupported or malformed image format")
    pixels = width * height
    if pixels <= 0 or pixels > maximum_pixels:
        raise AdapterExecutionError("image dimensions exceed the configured pixel bound")
    return metadata


def _validate_png(body: bytes) -> None:
    position = 8
    chunk_index = 0
    saw_idat = False
    saw_iend = False
    while position + 12 <= len(body):
        length = int.from_bytes(body[position : position + 4], "big")
        chunk_type = body[position + 4 : position + 8]
        end = position + 12 + length
        if length > _MAX_MEDIA_INPUT_BYTES or end > len(body):
            raise AdapterExecutionError("PNG chunk is truncated or oversized")
        chunk_data = body[position + 8 : position + 8 + length]
        expected_crc = int.from_bytes(body[position + 8 + length : end], "big")
        observed_crc = zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF
        if observed_crc != expected_crc:
            raise AdapterExecutionError("PNG chunk checksum is invalid")
        if chunk_index == 0 and (chunk_type != b"IHDR" or length != 13):
            raise AdapterExecutionError("PNG IHDR is missing or malformed")
        if chunk_type == b"IDAT":
            saw_idat = True
        if chunk_type == b"IEND":
            if length != 0 or end != len(body):
                raise AdapterExecutionError("PNG IEND is malformed")
            saw_iend = True
            break
        position = end
        chunk_index += 1
    if not saw_idat or not saw_iend:
        raise AdapterExecutionError("PNG image data or end marker is missing")


def _jpeg_dimensions(body: bytes) -> tuple[int, int, int]:
    position = 2
    start_of_frame = frozenset(
        {
            0xC0,
            0xC1,
            0xC2,
            0xC3,
            0xC5,
            0xC6,
            0xC7,
            0xC9,
            0xCA,
            0xCB,
            0xCD,
            0xCE,
            0xCF,
        }
    )
    while position + 4 <= len(body):
        if body[position] != 0xFF:
            position += 1
            continue
        while position < len(body) and body[position] == 0xFF:
            position += 1
        if position >= len(body):
            break
        marker = body[position]
        position += 1
        if marker in {0x01, *range(0xD0, 0xDA)}:
            continue
        if position + 2 > len(body):
            break
        segment_length = int.from_bytes(body[position : position + 2], "big")
        if segment_length < 2 or position + segment_length > len(body):
            raise AdapterExecutionError("JPEG segment is truncated or malformed")
        if marker in start_of_frame:
            if segment_length < 8:
                raise AdapterExecutionError("JPEG frame header is malformed")
            height = int.from_bytes(body[position + 3 : position + 5], "big")
            width = int.from_bytes(body[position + 5 : position + 7], "big")
            components = body[position + 7]
            return width, height, components
        position += segment_length
    raise AdapterExecutionError("JPEG dimensions were not found")


def _image_media_type(image_format: str) -> str:
    return {
        "gif": "image/gif",
        "jpeg": "image/jpeg",
        "png": "image/png",
        "tiff": "image/tiff",
        "webp": "image/webp",
    }[image_format]


def _tiff_dimensions(body: bytes) -> tuple[int, int]:
    if len(body) < 8 or body[:2] not in {b"II", b"MM"}:
        raise AdapterExecutionError("TIFF header is malformed")
    byteorder: Literal["little", "big"] = "little" if body[:2] == b"II" else "big"
    if int.from_bytes(body[2:4], byteorder) != 42:
        raise AdapterExecutionError("TIFF marker is invalid")
    entries, _ = _read_ifd(body, int.from_bytes(body[4:8], byteorder), byteorder)
    dimensions: dict[int, int] = {}
    for tag, field_type, count, value_field in entries:
        if tag not in {0x0100, 0x0101}:
            continue
        value = _read_exif_value(body, field_type, count, value_field, byteorder)
        if isinstance(value, int):
            dimensions[tag] = value
    try:
        return dimensions[0x0100], dimensions[0x0101]
    except KeyError as exc:
        raise AdapterExecutionError("TIFF dimensions were not found") from exc


def _webp_dimensions(body: bytes) -> tuple[int, int, str]:
    if len(body) < 30:
        raise AdapterExecutionError("WebP structure is truncated")
    declared_size = int.from_bytes(body[4:8], "little") + 8
    if declared_size != len(body):
        raise AdapterExecutionError("WebP RIFF size is inconsistent")
    chunk = body[12:16]
    if chunk == b"VP8X":
        width = 1 + int.from_bytes(body[24:27], "little")
        height = 1 + int.from_bytes(body[27:30], "little")
        return width, height, "extended"
    if chunk == b"VP8 ":
        if len(body) < 30 or body[23:26] != b"\x9d\x01\x2a":
            raise AdapterExecutionError("WebP VP8 frame header is malformed")
        width = int.from_bytes(body[26:28], "little") & 0x3FFF
        height = int.from_bytes(body[28:30], "little") & 0x3FFF
        return width, height, "lossy"
    if chunk == b"VP8L":
        if len(body) < 25 or body[20] != 0x2F:
            raise AdapterExecutionError("WebP VP8L frame header is malformed")
        bits = int.from_bytes(body[21:25], "little")
        width = (bits & 0x3FFF) + 1
        height = ((bits >> 14) & 0x3FFF) + 1
        return width, height, "lossless"
    raise AdapterExecutionError("WebP encoding is unsupported")


def _wave_metadata(body: bytes) -> dict[str, object]:
    try:
        with wave.open(io.BytesIO(body), "rb") as audio:
            frames = audio.getnframes()
            rate = audio.getframerate()
            return {
                "format_name": "wav",
                "channels": audio.getnchannels(),
                "sample_width_bytes": audio.getsampwidth(),
                "sample_rate": rate,
                "frames": frames,
                "duration_seconds": frames / rate if rate else 0,
            }
    except (EOFError, wave.Error) as exc:
        raise AdapterExecutionError("WAV header is malformed") from exc


def _normalize_ffprobe(
    document: Mapping[str, object],
    *,
    expected_kind: str,
) -> dict[str, object]:
    raw_format = document.get("format", {})
    raw_streams = document.get("streams", [])
    if not isinstance(raw_format, Mapping) or not isinstance(raw_streams, list):
        raise AdapterExecutionError("FFprobe response omitted format or stream metadata")
    streams: list[dict[str, object]] = []
    kinds: set[str] = set()
    for raw_stream in raw_streams[:128]:
        if not isinstance(raw_stream, Mapping):
            raise AdapterExecutionError("FFprobe stream metadata must be objects")
        stream: dict[str, object] = {}
        for key, value in raw_stream.items():
            normalized = _safe_scalar(value)
            if key in _SAFE_FFPROBE_STREAM_FIELDS and normalized is not None:
                stream[str(key)] = normalized
        codec_type = stream.get("codec_type")
        if isinstance(codec_type, str):
            kinds.add(codec_type)
        streams.append(stream)
    if expected_kind not in kinds:
        raise AdapterExecutionError(
            f"FFprobe response contains no {expected_kind} stream"
        )
    format_metadata = {
        str(key): _safe_scalar(value)
        for key, value in raw_format.items()
        if key in _SAFE_FFPROBE_FORMAT_FIELDS and _safe_scalar(value) is not None
    }
    return {"format": format_metadata, "streams": streams}


def _parse_subtitle_text(
    body: bytes,
    *,
    maximum_text_bytes: int,
) -> tuple[str, tuple[str, ...]]:
    if len(body) > maximum_text_bytes:
        raise AdapterExecutionError("subtitle text exceeded the configured byte bound")
    text = body.decode("utf-8-sig", errors="strict")
    lines = text.splitlines()
    output: list[str] = []
    locators: list[str] = []
    current_locator = "cue:1"
    cue_index = 0
    for line in lines:
        stripped = _CONTROL_CHARACTERS.sub("", line).strip()
        if not stripped or stripped == "WEBVTT" or stripped.isdigit():
            continue
        timing = _SUBTITLE_TIMING.match(stripped)
        if timing:
            cue_index += 1
            current_locator = f"cue:{cue_index}"
            locators.append(current_locator)
            continue
        if stripped.startswith(("NOTE", "STYLE", "REGION")):
            continue
        output.append(stripped)
        if current_locator not in locators:
            locators.append(current_locator)
    normalized = "\n".join(output)
    if not normalized:
        raise AdapterExecutionError("subtitle artifact contains no transcript text")
    return _bounded_text(normalized, maximum_text_bytes), tuple(locators[:10_000])


def _parse_podcast_feed(
    body: bytes,
    *,
    maximum_episodes: int,
    maximum_bytes: int,
    maximum_nodes: int,
    maximum_depth: int,
) -> tuple[dict[str, object], tuple[str, ...]]:
    if len(body) > maximum_bytes:
        raise AdapterExecutionError("podcast XML exceeded the configured byte bound")
    if _XML_DECLARATIONS.search(body):
        raise AdapterExecutionError("podcast XML declarations are forbidden")
    _validate_xml_shape(
        body,
        maximum_nodes=maximum_nodes,
        maximum_depth=maximum_depth,
    )
    root = ET.fromstring(body)
    if _local_name(root.tag) != "rss":
        raise AdapterExecutionError("podcast feed must use an RSS root")
    channel = next(
        (child for child in root if _local_name(child.tag) == "channel"),
        None,
    )
    if channel is None:
        raise AdapterExecutionError("podcast RSS omitted its channel")
    episodes: list[dict[str, object]] = []
    locators: list[str] = []
    omitted = 0
    for child in channel:
        if _local_name(child.tag) != "item":
            continue
        if len(episodes) >= maximum_episodes:
            omitted += 1
            continue
        locator = f"episode:{len(episodes) + 1}"
        episode: dict[str, object] = {
            "locator": locator,
            "title": _child_text(child, "title", 2_048),
            "guid": _child_text(child, "guid", 2_048),
            "published": _child_text(child, "pubDate", 256),
            "description": _child_text(child, "description", 8_192),
        }
        enclosure = next(
            (item for item in child if _local_name(item.tag) == "enclosure"),
            None,
        )
        if enclosure is not None:
            raw_url = enclosure.attrib.get("url", "")
            if raw_url:
                episode["enclosure_url"] = _public_url(raw_url)
            episode["enclosure_type"] = _bounded_text(
                enclosure.attrib.get("type", ""),
                256,
            )
            raw_length = enclosure.attrib.get("length", "")
            if raw_length.isdigit():
                episode["enclosure_bytes"] = int(raw_length)
        episodes.append(episode)
        locators.append(locator)
    if not episodes:
        raise AdapterExecutionError("podcast feed contains no episodes")
    document: dict[str, object] = {
        "schema": "fetech.podcast.v1",
        "title": _child_text(channel, "title", 2_048),
        "description": _child_text(channel, "description", 8_192),
        "episodes": episodes,
        "omitted_episodes": omitted,
    }
    return document, tuple(locators)


def _validate_xml_shape(
    body: bytes,
    *,
    maximum_nodes: int,
    maximum_depth: int,
) -> None:
    """Reject high-node or deeply nested XML before constructing the feed tree."""

    depth = 0
    nodes = 0
    try:
        for event, _ in ET.iterparse(io.BytesIO(body), events=("start", "end")):
            if event == "start":
                depth += 1
                nodes += 1
                if depth > maximum_depth:
                    raise AdapterExecutionError(
                        "podcast XML exceeded the configured depth bound"
                    )
                if nodes > maximum_nodes:
                    raise AdapterExecutionError(
                        "podcast XML exceeded the configured node bound"
                    )
            else:
                depth -= 1
    except ET.ParseError:
        raise
    if depth != 0:
        raise AdapterExecutionError("podcast XML nesting is malformed")


def _extract_exif_metadata(
    body: bytes,
    *,
    maximum_fields: int,
) -> dict[str, object]:
    tiff = _find_tiff_payload(body)
    if tiff is None:
        return {"fields": {}, "omitted_sensitive_fields": 0}
    if len(tiff) < 8 or tiff[:2] not in {b"II", b"MM"}:
        raise AdapterExecutionError("EXIF TIFF header is malformed")
    byteorder: Literal["little", "big"] = "little" if tiff[:2] == b"II" else "big"
    if int.from_bytes(tiff[2:4], byteorder) != 42:
        raise AdapterExecutionError("EXIF TIFF marker is invalid")
    first_ifd = int.from_bytes(tiff[4:8], byteorder)
    fields: dict[str, object] = {}
    omitted_sensitive = 0
    queue = [first_ifd]
    visited: set[int] = set()
    while queue and len(fields) < maximum_fields:
        offset = queue.pop(0)
        if offset in visited:
            continue
        visited.add(offset)
        entries, next_ifd = _read_ifd(tiff, offset, byteorder)
        for tag, field_type, count, value_field in entries:
            if tag in _SENSITIVE_EXIF_TAGS:
                omitted_sensitive += 1
                continue
            if tag == 0x8769:
                sub_ifd = int.from_bytes(value_field, byteorder)
                if sub_ifd not in visited:
                    queue.append(sub_ifd)
                continue
            name = _EXIF_TAGS.get(tag)
            if name is None or len(fields) >= maximum_fields:
                continue
            value = _read_exif_value(
                tiff,
                field_type,
                count,
                value_field,
                byteorder,
            )
            if value is not None:
                fields[name] = value
        if next_ifd and len(visited) < 4:
            queue.append(next_ifd)
    return {
        "fields": fields,
        "omitted_sensitive_fields": omitted_sensitive,
        "truncated": bool(queue),
    }


def _find_tiff_payload(body: bytes) -> bytes | None:
    if body[:2] in {b"II", b"MM"}:
        return body
    if not body.startswith(b"\xff\xd8"):
        return None
    position = 2
    while position + 4 <= len(body):
        if body[position] != 0xFF:
            position += 1
            continue
        marker = body[position + 1]
        position += 2
        if marker in {0xD8, 0xD9}:
            continue
        if position + 2 > len(body):
            break
        length = int.from_bytes(body[position : position + 2], "big")
        if length < 2 or position + length > len(body):
            raise AdapterExecutionError("JPEG EXIF segment is malformed")
        segment = body[position + 2 : position + length]
        if marker == 0xE1 and segment.startswith(b"Exif\x00\x00"):
            return segment[6:]
        position += length
    return None


def _read_ifd(
    tiff: bytes,
    offset: int,
    byteorder: Literal["little", "big"],
) -> tuple[list[tuple[int, int, int, bytes]], int]:
    if offset < 8 or offset + 2 > len(tiff):
        raise AdapterExecutionError("EXIF IFD offset is out of bounds")
    count = int.from_bytes(tiff[offset : offset + 2], byteorder)
    if count > 512:
        raise AdapterExecutionError("EXIF IFD field count exceeds the bound")
    entries_end = offset + 2 + count * 12
    if entries_end + 4 > len(tiff):
        raise AdapterExecutionError("EXIF IFD is truncated")
    entries: list[tuple[int, int, int, bytes]] = []
    position = offset + 2
    for _ in range(count):
        tag = int.from_bytes(tiff[position : position + 2], byteorder)
        field_type = int.from_bytes(tiff[position + 2 : position + 4], byteorder)
        value_count = int.from_bytes(tiff[position + 4 : position + 8], byteorder)
        entries.append((tag, field_type, value_count, tiff[position + 8 : position + 12]))
        position += 12
    next_ifd = int.from_bytes(tiff[entries_end : entries_end + 4], byteorder)
    return entries, next_ifd


def _read_exif_value(
    tiff: bytes,
    field_type: int,
    count: int,
    value_field: bytes,
    byteorder: Literal["little", "big"],
) -> object | None:
    unit_size = _EXIF_TYPE_SIZES.get(field_type)
    if unit_size is None or count <= 0 or count > 4_096:
        return None
    size = unit_size * count
    if size > 16_384:
        return None
    if size <= 4:
        raw = value_field[:size]
    else:
        offset = int.from_bytes(value_field, byteorder)
        if offset < 8 or offset + size > len(tiff):
            raise AdapterExecutionError("EXIF value offset is out of bounds")
        raw = tiff[offset : offset + size]
    if field_type == 2:
        return _bounded_text(raw.rstrip(b"\x00").decode("utf-8", errors="replace"), 1_024)
    if field_type in {1, 7}:
        return raw[0] if count == 1 else [int(value) for value in raw[:64]]
    if field_type == 3:
        short_values = [
            int.from_bytes(raw[index : index + 2], byteorder)
            for index in range(0, len(raw), 2)
        ]
        return short_values[0] if len(short_values) == 1 else short_values[:64]
    if field_type in {4, 9}:
        integer_values = [
            int.from_bytes(
                raw[index : index + 4],
                byteorder,
                signed=field_type == 9,
            )
            for index in range(0, len(raw), 4)
        ]
        return integer_values[0] if len(integer_values) == 1 else integer_values[:64]
    if field_type in {5, 10}:
        rational_values: list[str] = []
        for index in range(0, len(raw), 8):
            numerator = int.from_bytes(
                raw[index : index + 4],
                byteorder,
                signed=field_type == 10,
            )
            denominator = int.from_bytes(
                raw[index + 4 : index + 8],
                byteorder,
                signed=field_type == 10,
            )
            rational_values.append(
                f"{numerator}/{denominator}" if denominator else f"{numerator}/0"
            )
        return (
            rational_values[0]
            if len(rational_values) == 1
            else rational_values[:64]
        )
    return None


def _normalize_youtube(
    document: Mapping[str, object],
    *,
    maximum_fields: int,
    fallback_url: str,
) -> dict[str, object]:
    if not isinstance(document.get("id"), str) or not isinstance(document.get("title"), str):
        raise AdapterExecutionError("yt-dlp metadata omitted the video id or title")
    scalar_fields = (
        "id",
        "title",
        "description",
        "uploader",
        "uploader_id",
        "channel",
        "channel_id",
        "duration",
        "upload_date",
        "availability",
        "live_status",
        "extractor",
        "ext",
        "width",
        "height",
        "view_count",
        "like_count",
        "age_limit",
    )
    output: dict[str, object] = {}
    for key in scalar_fields:
        scalar_value = _safe_scalar(
            document.get(key),
            maximum=8_192 if key == "description" else 2_048,
        )
        if scalar_value is not None:
            output[key] = scalar_value
        if len(output) >= maximum_fields:
            break
    for key in ("categories", "tags"):
        category_value = document.get(key)
        if isinstance(category_value, list):
            output[key] = [
                cleaned
                for item in category_value[:100]
                if (cleaned := _safe_scalar(item, maximum=256)) is not None
            ]
    chapters = document.get("chapters")
    if isinstance(chapters, list):
        normalized_chapters: list[dict[str, object]] = []
        for chapter in chapters[:500]:
            if not isinstance(chapter, Mapping):
                continue
            normalized_chapter: dict[str, object] = {}
            for chapter_key in ("title", "start_time", "end_time"):
                chapter_value = _safe_scalar(chapter.get(chapter_key), maximum=512)
                if chapter_value is not None:
                    normalized_chapter[chapter_key] = chapter_value
            normalized_chapters.append(normalized_chapter)
        output["chapters"] = normalized_chapters
    for key in ("subtitles", "automatic_captions"):
        caption_value = document.get(key)
        if isinstance(caption_value, Mapping):
            output[f"{key}_languages"] = sorted(
                _bounded_text(str(language), 64)
                for language in list(caption_value)[:200]
            )
    output["source_url"] = _youtube_url(
        str(document.get("webpage_url") or document.get("original_url") or fallback_url)
    )
    raw_formats = document.get("formats")
    output["omitted_download_formats"] = len(raw_formats) if isinstance(raw_formats, list) else 0
    return output


def _preacquired_youtube_document(
    body: bytes,
    *,
    maximum_bytes: int,
) -> Mapping[str, object] | None:
    if not body.lstrip().startswith(b"{"):
        return None
    if len(body) > maximum_bytes:
        raise AdapterExecutionError(
            "pre-acquired yt-dlp metadata exceeded its byte bound"
        )
    try:
        document = json.loads(
            body.decode("utf-8-sig"),
            object_pairs_hook=_strict_json_object,
            parse_constant=_reject_json_constant,
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise AdapterExecutionError(
            "pre-acquired yt-dlp metadata is malformed"
        ) from exc
    if not isinstance(document, Mapping):
        raise AdapterExecutionError("pre-acquired yt-dlp metadata must be an object")
    _validate_youtube_json_shape(document)
    return document


def _validate_youtube_json_shape(document: object) -> None:
    nodes = 0
    stack: list[tuple[object, int]] = [(document, 1)]
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > _MAX_YOUTUBE_JSON_NODES:
            raise AdapterExecutionError(
                "pre-acquired yt-dlp metadata exceeded its node bound"
            )
        if depth > _MAX_YOUTUBE_JSON_DEPTH:
            raise AdapterExecutionError(
                "pre-acquired yt-dlp metadata exceeded its depth bound"
            )
        if isinstance(value, Mapping):
            stack.extend((item, depth + 1) for item in value.values())
        elif isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)


def _strict_json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _podcast_quality_text(document: Mapping[str, object]) -> str:
    title = document.get("title", "")
    description = document.get("description", "")
    episodes = document.get("episodes", [])
    episode_titles = (
        " ".join(
            str(item.get("title", ""))
            for item in episodes
            if isinstance(item, Mapping)
        )
        if isinstance(episodes, list)
        else ""
    )
    return f"{title} {description} {episode_titles}".strip()


def _child_text(element: ET.Element, name: str, maximum: int) -> str:
    child = next(
        (item for item in element if _local_name(item.tag) == name),
        None,
    )
    return _bounded_text("".join(child.itertext()) if child is not None else "", maximum)


def _local_name(tag: str) -> str:
    return tag.rsplit("}", maxsplit=1)[-1]


def _tesseract_language(language: str | None) -> str:
    prefix = (language or "en").split("-", maxsplit=1)[0].lower()
    return {
        "de": "deu",
        "en": "eng",
        "es": "spa",
        "fr": "fra",
        "it": "ita",
        "ja": "jpn",
        "ko": "kor",
        "pt": "por",
        "zh": "chi_sim",
    }.get(prefix, "eng")


def _safe_scalar(value: object, maximum: int = 2_048) -> str | int | float | bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return value if math.isfinite(value) else None
    if isinstance(value, str):
        return _bounded_text(value, maximum)
    return None


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _bounded_text(value: str, maximum: int) -> str:
    cleaned = _CONTROL_CHARACTERS.sub("", value)
    encoded = cleaned.encode("utf-8")
    if len(encoded) <= maximum:
        return cleaned
    return encoded[:maximum].decode("utf-8", errors="ignore")


def _public_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        if value:
            raise AdapterExecutionError("media metadata URL must be absolute HTTP(S)")
        return ""
    host = parsed.hostname.encode("idna").decode("ascii").lower()
    port = parsed.port
    if (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80):
        port = None
    netloc = f"{host}:{port}" if port is not None else host
    return urlunsplit((parsed.scheme.lower(), netloc, parsed.path or "/", "", ""))


def _youtube_url(value: str) -> str:
    return _canonical_youtube_video_url(value)


def _json_bytes(document: Mapping[str, object]) -> bytes:
    return json.dumps(
        document,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
