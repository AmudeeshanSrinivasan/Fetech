"""Fail-closed built-in yt-dlp metadata provider.

The provider accepts only canonical HTTPS YouTube video locators and delegates
network work to :mod:`fetech.yt_dlp_worker`.  The subprocess receives no
credentials, user configuration, cookies, plugins, download instructions, or
shell command.  Its output is treated as untrusted and validated again here.
"""

from __future__ import annotations

import json
import math
import re
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from dataclasses import field as dataclass_field
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from fetech.adapters.base import (
    AdapterBudgetExceededError,
    AdapterDependencyError,
    AdapterExecutionError,
)
from fetech.logic.base import LogicBackendError
from fetech.logic.process import run_bounded
from fetech.scheduling import NetworkDeadlineExceededError, NetworkScheduler
from fetech.worker_isolation import (
    WorkerIsolationProfile,
    WorkerIsolationRuntime,
)

_WORKER_SCHEMA = "fetech.yt_dlp.worker.v1"
_WORKER_BOOTSTRAP = (
    "import runpy,sys;"
    "sys.path.insert(0,sys.argv.pop(1));"
    "runpy.run_module('fetech.yt_dlp_worker',run_name='__main__')"
)
_YOUTUBE_HOSTS = frozenset(
    {
        "youtu.be",
        "youtube.com",
        "www.youtube.com",
        "m.youtube.com",
        "music.youtube.com",
    }
)
_VIDEO_ID = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
_QUERY_VALUE = re.compile(r"^[A-Za-z0-9_.:-]{1,256}$")
_CONTROL_CHARACTERS = re.compile(r"[\x00-\x1f\x7f]")
_SCALAR_FIELDS = (
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
_MAX_FORMAT_COUNT = 10_000


@dataclass(frozen=True, slots=True)
class YouTubeMetadataResponse:
    """Validated metadata and measured acquisition usage from a provider."""

    metadata: Mapping[str, object]
    network_bytes: int
    decompressed_bytes: int
    redirects: int

    def __post_init__(self) -> None:
        for name in ("network_bytes", "decompressed_bytes", "redirects"):
            value = getattr(self, name)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"{name} must be a non-negative integer")


class YTDLPUsageError:
    """Marker carrying resources consumed before a provider failure."""

    network_bytes: int
    decompressed_bytes: int
    redirects: int

    def _set_usage(
        self,
        *,
        network_bytes: int,
        decompressed_bytes: int,
        redirects: int,
    ) -> None:
        self.network_bytes = network_bytes
        self.decompressed_bytes = decompressed_bytes
        self.redirects = redirects


class YTDLPProviderError(YTDLPUsageError, AdapterExecutionError):
    """yt-dlp failed after consuming a bounded amount of resources."""

    def __init__(
        self,
        message: str,
        *,
        network_bytes: int = 0,
        decompressed_bytes: int = 0,
        redirects: int = 0,
    ) -> None:
        super().__init__(message)
        self._set_usage(
            network_bytes=network_bytes,
            decompressed_bytes=decompressed_bytes,
            redirects=redirects,
        )


class YTDLPBudgetExceededError(YTDLPUsageError, AdapterBudgetExceededError):
    """The worker reached a request budget before metadata was complete."""

    def __init__(
        self,
        message: str,
        *,
        network_bytes: int = 0,
        decompressed_bytes: int = 0,
        redirects: int = 0,
    ) -> None:
        super().__init__(message)
        self._set_usage(
            network_bytes=network_bytes,
            decompressed_bytes=decompressed_bytes,
            redirects=redirects,
        )


class YTDLPDeadlineExceededError(
    YTDLPUsageError,
    NetworkDeadlineExceededError,
):
    """An operation-level yt-dlp slot exhausted the caller's deadline."""

    def __init__(
        self,
        message: str,
        *,
        network_bytes: int = 0,
        decompressed_bytes: int = 0,
        redirects: int = 0,
    ) -> None:
        super().__init__(message)
        self._set_usage(
            network_bytes=network_bytes,
            decompressed_bytes=decompressed_bytes,
            redirects=redirects,
        )


@dataclass(frozen=True, slots=True)
class YTDLPMetadataWorker:
    """Invoke yt-dlp with one shared slot for the complete worker operation.

    This admission bounds concurrent worker operations. The isolated worker
    independently restricts its allowed destinations and budgets; its internal
    multi-host requests are not individual scheduler admissions.
    """

    maximum_network_bytes: int = 5_000_000
    maximum_redirects: int = 4
    memory_mb: int = 512
    scheduler: NetworkScheduler = dataclass_field(
        default_factory=NetworkScheduler,
        compare=False,
        repr=False,
    )
    isolation: WorkerIsolationRuntime = dataclass_field(
        default_factory=WorkerIsolationRuntime.from_environment,
        compare=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        if (
            self.maximum_network_bytes <= 0
            or self.maximum_redirects < 0
            or self.memory_mb <= 0
        ):
            raise ValueError("yt-dlp worker limits are invalid")

    async def metadata(
        self,
        target: str,
        *,
        timeout_seconds: float,
        maximum_output_bytes: int,
        maximum_network_bytes: int,
        maximum_redirects: int,
    ) -> YouTubeMetadataResponse:
        if (
            timeout_seconds <= 0
            or maximum_network_bytes <= 0
            or maximum_redirects < 0
        ):
            raise ValueError("yt-dlp request limits are invalid")
        if maximum_output_bytes < 512:
            raise AdapterExecutionError(
                "yt-dlp metadata output limit must be at least 512 bytes"
            )
        safe_target = _canonical_youtube_video_url(target)
        try:
            _distribution_version("yt-dlp")
        except PackageNotFoundError as exc:
            raise AdapterDependencyError(
                "live YouTube metadata requires the isolated yt-dlp connector "
                "from fetech[media]"
            ) from exc

        output_limit = min(maximum_output_bytes, 1_000_000)
        network_limit = min(maximum_network_bytes, self.maximum_network_bytes)
        redirect_limit = min(maximum_redirects, self.maximum_redirects)
        socket_timeout = min(timeout_seconds, 15.0)
        host = urlsplit(safe_target).hostname or ""
        try:
            async with self.scheduler.slot(
                host,
                deadline_seconds=timeout_seconds,
            ):
                process = await run_bounded(
                    (
                        sys.executable,
                        "-I",
                        "-B",
                        "-c",
                        _WORKER_BOOTSTRAP,
                        str(Path(__file__).resolve().parents[1]),
                        str(network_limit),
                        str(redirect_limit),
                        f"{socket_timeout:g}",
                        str(output_limit),
                    ),
                    safe_target.encode("utf-8"),
                    timeout_seconds=timeout_seconds,
                    memory_mb=self.memory_mb,
                    maximum_output_bytes=output_limit,
                    maximum_file_bytes=output_limit,
                    isolation=self.isolation.request(
                        WorkerIsolationProfile.MEDIA_YTDLP_NETWORK
                    ),
                )
        except NetworkDeadlineExceededError as exc:
            raise YTDLPDeadlineExceededError(
                "yt-dlp metadata exhausted the operation deadline",
                network_bytes=network_limit,
                decompressed_bytes=network_limit,
                redirects=redirect_limit,
            ) from exc
        except LogicBackendError as exc:
            raise YTDLPProviderError(
                "bounded yt-dlp metadata worker failed",
                network_bytes=network_limit,
                decompressed_bytes=network_limit,
                redirects=redirect_limit,
            ) from exc
        if process.returncode == 2:
            raise AdapterDependencyError(
                "live YouTube metadata requires the isolated yt-dlp connector "
                "from fetech[media]"
            )
        if process.returncode == 3:
            raise AdapterExecutionError(
                "isolated yt-dlp metadata worker rejected its target"
            )
        if process.returncode != 0:
            raise YTDLPProviderError(
                "isolated yt-dlp metadata worker did not complete",
                network_bytes=network_limit,
                decompressed_bytes=network_limit,
                redirects=redirect_limit,
            )
        try:
            return _decode_worker_envelope(
                process.stdout,
                source_url=safe_target,
                maximum_network_bytes=network_limit,
                maximum_redirects=redirect_limit,
                request_network_limit=maximum_network_bytes,
                request_redirect_limit=maximum_redirects,
            )
        except (YTDLPBudgetExceededError, YTDLPProviderError):
            raise
        except AdapterExecutionError as exc:
            raise YTDLPProviderError(
                "isolated yt-dlp metadata worker returned unusable output",
                network_bytes=network_limit,
                decompressed_bytes=network_limit,
                redirects=redirect_limit,
            ) from exc


def _decode_worker_envelope(
    payload: bytes,
    *,
    source_url: str,
    maximum_network_bytes: int,
    maximum_redirects: int,
    request_network_limit: int,
    request_redirect_limit: int,
) -> YouTubeMetadataResponse:
    try:
        document = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise AdapterExecutionError(
            "yt-dlp metadata worker returned malformed output"
        ) from exc
    if not isinstance(document, dict):
        raise AdapterExecutionError("yt-dlp metadata worker output must be an object")

    status = document.get("status")
    expected = {
        "schema",
        "status",
        "network_bytes",
        "decompressed_bytes",
        "redirects",
    }
    expected.add("metadata" if status == "succeeded" else "failure_code")
    if set(document) != expected or document.get("schema") != _WORKER_SCHEMA:
        raise AdapterExecutionError("yt-dlp metadata worker output has an invalid schema")
    network_bytes = _usage_integer(document.get("network_bytes"), "network_bytes")
    decompressed_bytes = _usage_integer(
        document.get("decompressed_bytes"),
        "decompressed_bytes",
    )
    redirects = _usage_integer(document.get("redirects"), "redirects")
    if (
        network_bytes > maximum_network_bytes
        or decompressed_bytes > maximum_network_bytes
        or decompressed_bytes != network_bytes
        or redirects > maximum_redirects
    ):
        raise AdapterExecutionError("yt-dlp metadata worker exceeded its process limits")

    if status == "failed":
        failure_code = document.get("failure_code")
        if failure_code in {"network_budget_exhausted", "redirect_budget_exhausted"}:
            error_type: type[YTDLPBudgetExceededError] | type[YTDLPProviderError]
            request_limited = (
                failure_code == "network_budget_exhausted"
                and maximum_network_bytes == request_network_limit
            ) or (
                failure_code == "redirect_budget_exhausted"
                and maximum_redirects == request_redirect_limit
            )
            error_type = (
                YTDLPBudgetExceededError if request_limited else YTDLPProviderError
            )
            raise error_type(
                (
                    "yt-dlp metadata exhausted the request budget"
                    if request_limited
                    else "yt-dlp metadata exceeded its provider safety limit"
                ),
                network_bytes=network_bytes,
                decompressed_bytes=decompressed_bytes,
                redirects=redirects,
            )
        if failure_code not in {
            "extraction_failed",
            "output_limit_exhausted",
            "policy_blocked",
        }:
            raise AdapterExecutionError(
                "yt-dlp metadata worker returned an invalid failure code"
            )
        raise YTDLPProviderError(
            (
                "yt-dlp network policy blocked metadata acquisition"
                if failure_code == "policy_blocked"
                else (
                    "yt-dlp metadata exceeded the configured output limit"
                    if failure_code == "output_limit_exhausted"
                    else "yt-dlp could not acquire metadata for the requested video"
                )
            ),
            network_bytes=network_bytes,
            decompressed_bytes=decompressed_bytes,
            redirects=redirects,
        )
    if status != "succeeded":
        raise AdapterExecutionError("yt-dlp metadata worker returned an invalid status")

    metadata = document.get("metadata")
    try:
        projected = _project_metadata(metadata, source_url=source_url)
    except (TypeError, ValueError, AdapterExecutionError) as exc:
        raise YTDLPProviderError(
            "yt-dlp metadata worker returned an invalid result",
            network_bytes=network_bytes,
            decompressed_bytes=decompressed_bytes,
            redirects=redirects,
        ) from exc
    return YouTubeMetadataResponse(
        metadata=projected,
        network_bytes=network_bytes,
        decompressed_bytes=decompressed_bytes,
        redirects=redirects,
    )


def _canonical_youtube_video_url(target: str) -> str:
    if (
        not isinstance(target, str)
        or not target
        or len(target.encode("utf-8")) > 2_048
        or _CONTROL_CHARACTERS.search(target)
    ):
        raise AdapterExecutionError("YouTube metadata target is invalid")
    try:
        parsed = urlsplit(target)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise AdapterExecutionError("YouTube metadata target is invalid") from exc
    if (
        parsed.scheme.lower() != "https"
        or host not in _YOUTUBE_HOSTS
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or parsed.fragment
    ):
        raise AdapterExecutionError(
            "built-in yt-dlp metadata requires an exact HTTPS YouTube origin"
        )

    try:
        pairs = parse_qsl(parsed.query, keep_blank_values=False, max_num_fields=16)
    except ValueError as exc:
        raise AdapterExecutionError(
            "YouTube metadata query exceeds the field bound"
        ) from exc
    if len(pairs) > 8:
        raise AdapterExecutionError("YouTube metadata query exceeds the field bound")
    allowed_query = {"index", "list", "start", "t", "v"}
    safe_pairs: list[tuple[str, str]] = []
    for key, value in pairs:
        if key not in allowed_query:
            continue
        if not _QUERY_VALUE.fullmatch(value):
            raise AdapterExecutionError("YouTube metadata query value is invalid")
        safe_pairs.append((key, value))

    path = parsed.path or "/"
    query = dict(safe_pairs)
    if host == "youtu.be":
        segments = [segment for segment in path.split("/") if segment]
        if len(segments) != 1 or not _VIDEO_ID.fullmatch(segments[0]):
            raise AdapterExecutionError("short YouTube URL must identify one video")
        expected_video_id = segments[0]
        path = f"/{expected_video_id}"
    elif path == "/watch":
        expected_video_id = query.get("v", "")
        if not _VIDEO_ID.fullmatch(expected_video_id):
            raise AdapterExecutionError("YouTube watch URL must identify one video")
    else:
        segments = [segment for segment in path.split("/") if segment]
        if (
            len(segments) != 2
            or segments[0] not in {"embed", "live", "shorts"}
            or not _VIDEO_ID.fullmatch(segments[1])
        ):
            raise AdapterExecutionError("unsupported YouTube video locator")
        expected_video_id = segments[1]
        path = f"/{segments[0]}/{expected_video_id}"
    if "v" in query and query["v"] != expected_video_id:
        raise AdapterExecutionError("YouTube locator contains conflicting video ids")

    return urlunsplit(
        (
            "https",
            host,
            path,
            urlencode(safe_pairs),
            "",
        )
    )


def _project_metadata(
    document: object,
    *,
    source_url: str,
) -> dict[str, object]:
    if not isinstance(document, Mapping):
        raise AdapterExecutionError("yt-dlp metadata must be an object")
    expected_video_id = _video_id_from_url(source_url)
    video_id = document.get("id")
    title = document.get("title")
    if (
        not isinstance(video_id, str)
        or video_id != expected_video_id
        or not isinstance(title, str)
        or not title.strip()
    ):
        raise AdapterExecutionError(
            "yt-dlp metadata does not match the requested video"
        )

    output: dict[str, object] = {}
    for key in _SCALAR_FIELDS:
        value = _safe_scalar(
            document.get(key),
            maximum=8_192 if key == "description" else 2_048,
        )
        if value is not None:
            output[key] = value

    for key in ("categories", "tags"):
        value = document.get(key)
        if isinstance(value, list):
            output[key] = [
                item
                for candidate in value[:100]
                if (item := _safe_scalar(candidate, maximum=256)) is not None
            ]

    chapters = document.get("chapters")
    if isinstance(chapters, list):
        safe_chapters: list[dict[str, object]] = []
        for candidate in chapters[:500]:
            if not isinstance(candidate, Mapping):
                continue
            chapter: dict[str, object] = {}
            for key in ("title", "start_time", "end_time"):
                value = _safe_scalar(candidate.get(key), maximum=512)
                if value is not None:
                    chapter[key] = value
            safe_chapters.append(chapter)
        output["chapters"] = safe_chapters

    for key in ("subtitles", "automatic_captions"):
        value = document.get(key)
        if isinstance(value, Mapping):
            languages = sorted(
                language
                for candidate in list(value)[:200]
                if (
                    isinstance(candidate, str)
                    and (language := _bounded_text(candidate, 64))
                )
            )
            output[key] = {language: [] for language in languages}

    formats = document.get("formats")
    output["formats"] = (
        [None] * min(len(formats), _MAX_FORMAT_COUNT)
        if isinstance(formats, list)
        else []
    )
    output["webpage_url"] = _authoritative_youtube_video_url(source_url)
    return output


def _video_id_from_url(target: str) -> str:
    parsed = urlsplit(target)
    if parsed.hostname == "youtu.be":
        return parsed.path.strip("/")
    query = dict(parse_qsl(parsed.query, keep_blank_values=False))
    if parsed.path == "/watch":
        return query["v"]
    return parsed.path.rstrip("/").rsplit("/", maxsplit=1)[-1]


def _authoritative_youtube_video_url(target: str) -> str:
    canonical = _canonical_youtube_video_url(target)
    parsed = urlsplit(canonical)
    query = (
        urlencode((("v", _video_id_from_url(canonical)),))
        if parsed.path == "/watch"
        else ""
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, query, ""))


def _safe_scalar(
    value: object,
    *,
    maximum: int,
) -> str | int | float | bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value if abs(value) <= 9_223_372_036_854_775_807 else None
    if isinstance(value, float):
        return value if math.isfinite(value) and abs(value) <= 1e308 else None
    if isinstance(value, str):
        return _bounded_text(value, maximum)
    return None


def _bounded_text(value: str, maximum: int) -> str:
    cleaned = _CONTROL_CHARACTERS.sub("", value)
    encoded = cleaned.encode("utf-8")
    return (
        cleaned
        if len(encoded) <= maximum
        else encoded[:maximum].decode("utf-8", errors="ignore")
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _usage_integer(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise AdapterExecutionError(f"yt-dlp worker {name} is invalid")
    return value
