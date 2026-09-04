from __future__ import annotations

import json
import socket
import sys
import urllib.request
from email.message import Message
from importlib.metadata import PackageNotFoundError
from pathlib import Path

import pytest

from fetech.adapters.base import (
    AdapterDependencyError,
    AdapterExecutionError,
)
from fetech.adapters.media import MediaAdapter
from fetech.logic.base import BackendOutputError
from fetech.logic.process import ProcessResult, run_bounded
from fetech.yt_dlp import (
    _WORKER_BOOTSTRAP,
    YTDLPBudgetExceededError,
    YTDLPMetadataWorker,
    YTDLPProviderError,
    _canonical_youtube_video_url,
    _decode_worker_envelope,
    _project_metadata,
)
from fetech.yt_dlp_worker import (
    _BudgetState,
    _failure_code,
    _strip_cross_origin_headers,
    _validate_network_url,
    _validate_resolved_records,
    _validate_response_headers,
    _write_envelope,
)


def _worker_payload(
    *,
    status: str = "succeeded",
    failure_code: str | None = None,
    network_bytes: int = 1_024,
    redirects: int = 1,
) -> bytes:
    document: dict[str, object] = {
        "schema": "fetech.yt_dlp.worker.v1",
        "status": status,
        "network_bytes": network_bytes,
        "decompressed_bytes": network_bytes,
        "redirects": redirects,
    }
    if status == "succeeded":
        document["metadata"] = {
            "id": "video-1",
            "title": "Bounded built-in metadata",
            "description": "A hermetic worker fixture.",
            "webpage_url": (
                "https://www.youtube.com/watch?v=video-1&signature=private"
            ),
            "subtitles": {
                "en": [{"url": "https://signed.example/private"}],
            },
            "formats": [
                {"url": "https://signed.example/private-a"},
                {"url": "https://signed.example/private-b"},
            ],
        }
    else:
        document["failure_code"] = failure_code
    return json.dumps(document, separators=(",", ":")).encode()


def test_media_adapter_uses_the_built_in_ytdlp_worker_by_default() -> None:
    assert isinstance(MediaAdapter().youtube_provider, YTDLPMetadataWorker)


@pytest.mark.asyncio
async def test_ytdlp_provider_uses_a_fixed_isolated_bounded_worker(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    async def bounded(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
        maximum_file_bytes: int | None = None,
        isolation: object = None,
    ) -> ProcessResult:
        observed.update(
            arguments=arguments,
            stdin=stdin,
            timeout_seconds=timeout_seconds,
            memory_mb=memory_mb,
            maximum_output_bytes=maximum_output_bytes,
            maximum_file_bytes=maximum_file_bytes,
            isolation=isolation,
        )
        return ProcessResult(
            returncode=0,
            stdout=_worker_payload(),
            stderr=b"private worker diagnostics",
        )

    monkeypatch.setattr("fetech.yt_dlp._distribution_version", lambda _: "2026.07.04")
    monkeypatch.setattr("fetech.yt_dlp.run_bounded", bounded)
    response = await YTDLPMetadataWorker().metadata(
        (
            "https://www.youtube.com/watch?v=video-1&list=playlist-1"
            "&signature=private&token=private"
        ),
        timeout_seconds=7,
        maximum_output_bytes=20_000,
        maximum_network_bytes=4_000,
        maximum_redirects=2,
    )

    arguments = observed["arguments"]
    assert isinstance(arguments, tuple)
    assert arguments[:5] == (
        sys.executable,
        "-I",
        "-B",
        "-c",
        _WORKER_BOOTSTRAP,
    )
    assert arguments[5].endswith("/src")
    assert observed["stdin"] == (
        b"https://www.youtube.com/watch?v=video-1&list=playlist-1"
    )
    assert observed["memory_mb"] == 512
    assert observed["maximum_output_bytes"] == 20_000
    assert observed["maximum_file_bytes"] == 20_000
    assert response.network_bytes == 1_024
    assert response.redirects == 1
    serialized = json.dumps(response.metadata)
    assert "private" not in serialized
    assert response.metadata["formats"] == [None, None]
    assert response.metadata["subtitles"] == {"en": []}


@pytest.mark.asyncio
async def test_ytdlp_isolated_worker_bootstrap_imports_from_a_source_checkout() -> None:
    from fetech import yt_dlp

    result = await run_bounded(
        (
            sys.executable,
            "-I",
            "-B",
            "-c",
            _WORKER_BOOTSTRAP,
            str(Path(yt_dlp.__file__).resolve().parents[1]),
            "1024",
            "0",
            "1",
            "512",
        ),
        b"",
        timeout_seconds=5,
        memory_mb=256,
        maximum_output_bytes=512,
        maximum_file_bytes=512,
    )

    assert result.returncode == 3
    assert result.stdout == b""
    assert result.stderr == b""


@pytest.mark.asyncio
async def test_ytdlp_isolated_runtime_imports_reviewed_modules() -> None:
    from fetech import yt_dlp

    probe = (
        "import json,sys;"
        "sys.path.insert(0,sys.argv[1]);"
        "import fetech.yt_dlp_worker as worker;"
        "import yt_dlp;"
        "import yt_dlp.networking._urllib as urllib_backend;"
        "import yt_dlp.plugins as plugins;"
        "print(json.dumps([worker.__name__,yt_dlp.__name__,"
        "urllib_backend.__name__,plugins.__name__]))"
    )
    result = await run_bounded(
        (
            sys.executable,
            "-I",
            "-B",
            "-c",
            probe,
            str(Path(yt_dlp.__file__).resolve().parents[1]),
        ),
        b"",
        timeout_seconds=5,
        memory_mb=256,
        maximum_output_bytes=1_024,
        maximum_file_bytes=1_024,
    )

    assert result.returncode == 0
    assert json.loads(result.stdout) == [
        "fetech.yt_dlp_worker",
        "yt_dlp",
        "yt_dlp.networking._urllib",
        "yt_dlp.plugins",
    ]
    assert result.stderr == b""


@pytest.mark.asyncio
async def test_ytdlp_provider_reports_a_missing_optional_distribution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def missing(_: str) -> str:
        raise PackageNotFoundError

    monkeypatch.setattr("fetech.yt_dlp._distribution_version", missing)
    with pytest.raises(AdapterDependencyError, match="fetech\\[media\\]"):
        await YTDLPMetadataWorker().metadata(
            "https://www.youtube.com/watch?v=video-1",
            timeout_seconds=2,
            maximum_output_bytes=10_000,
            maximum_network_bytes=10_000,
            maximum_redirects=1,
        )


@pytest.mark.asyncio
async def test_ytdlp_provider_rejects_an_unreportable_output_limit_before_network(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def should_not_run(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        raise AssertionError("worker must not run")

    monkeypatch.setattr("fetech.yt_dlp._distribution_version", lambda _: "2026.07.04")
    monkeypatch.setattr("fetech.yt_dlp.run_bounded", should_not_run)
    with pytest.raises(AdapterExecutionError, match="at least 512"):
        await YTDLPMetadataWorker().metadata(
            "https://www.youtube.com/watch?v=video-1",
            timeout_seconds=2,
            maximum_output_bytes=511,
            maximum_network_bytes=10_000,
            maximum_redirects=1,
        )


@pytest.mark.asyncio
async def test_ytdlp_provider_preserves_failed_attempt_usage_and_budget_semantics(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def exhausted(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
        maximum_file_bytes: int | None = None,
        isolation: object = None,
    ) -> ProcessResult:
        del (
            arguments,
            stdin,
            timeout_seconds,
            memory_mb,
            maximum_output_bytes,
            maximum_file_bytes,
            isolation,
        )
        return ProcessResult(
            returncode=0,
            stdout=_worker_payload(
                status="failed",
                failure_code="network_budget_exhausted",
                network_bytes=2_000,
                redirects=0,
            ),
            stderr=b"private target and extractor error",
        )

    monkeypatch.setattr("fetech.yt_dlp._distribution_version", lambda _: "2026.07.04")
    monkeypatch.setattr("fetech.yt_dlp.run_bounded", exhausted)
    with pytest.raises(
        YTDLPBudgetExceededError,
        match="request budget",
    ) as caught:
        await YTDLPMetadataWorker().metadata(
            "https://www.youtube.com/watch?v=video-1",
            timeout_seconds=2,
            maximum_output_bytes=10_000,
            maximum_network_bytes=2_000,
            maximum_redirects=1,
        )
    assert caught.value.network_bytes == 2_000
    assert caught.value.decompressed_bytes == 2_000
    assert caught.value.redirects == 0
    assert "private target" not in str(caught.value)


@pytest.mark.asyncio
async def test_ytdlp_provider_conservatively_charges_reserved_usage_when_output_overflows(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def overflow(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        raise BackendOutputError("private subprocess output detail")

    monkeypatch.setattr("fetech.yt_dlp._distribution_version", lambda _: "2026.07.04")
    monkeypatch.setattr("fetech.yt_dlp.run_bounded", overflow)
    with pytest.raises(YTDLPProviderError, match="bounded yt-dlp") as caught:
        await YTDLPMetadataWorker(
            maximum_network_bytes=4_000,
            maximum_redirects=3,
        ).metadata(
            "https://www.youtube.com/watch?v=video-1",
            timeout_seconds=2,
            maximum_output_bytes=10_000,
            maximum_network_bytes=2_000,
            maximum_redirects=2,
        )

    assert caught.value.network_bytes == 2_000
    assert caught.value.decompressed_bytes == 2_000
    assert caught.value.redirects == 2
    assert "private subprocess" not in str(caught.value)


@pytest.mark.asyncio
async def test_ytdlp_provider_conservatively_charges_reserved_usage_for_malformed_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def malformed(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        return ProcessResult(
            returncode=0,
            stdout=b"not-json",
            stderr=b"private subprocess output detail",
        )

    monkeypatch.setattr("fetech.yt_dlp._distribution_version", lambda _: "2026.07.04")
    monkeypatch.setattr("fetech.yt_dlp.run_bounded", malformed)
    with pytest.raises(YTDLPProviderError, match="unusable output") as caught:
        await YTDLPMetadataWorker(
            maximum_network_bytes=4_000,
            maximum_redirects=3,
        ).metadata(
            "https://www.youtube.com/watch?v=video-1",
            timeout_seconds=2,
            maximum_output_bytes=10_000,
            maximum_network_bytes=2_000,
            maximum_redirects=2,
        )

    assert caught.value.network_bytes == 2_000
    assert caught.value.decompressed_bytes == 2_000
    assert caught.value.redirects == 2
    assert "private subprocess" not in str(caught.value)


@pytest.mark.parametrize(
    "payload",
    [
        b'{"schema":"fetech.yt_dlp.worker.v1","schema":"duplicate"}',
        (
            b'{"decompressed_bytes":0,"metadata":{"id":"video-1","title":"x"},'
            b'"network_bytes":NaN,"redirects":0,'
            b'"schema":"fetech.yt_dlp.worker.v1","status":"succeeded"}'
        ),
        b"not-json",
    ],
)
def test_ytdlp_provider_rejects_malformed_worker_output(payload: bytes) -> None:
    with pytest.raises(AdapterExecutionError, match=r"malformed|schema"):
        _decode_worker_envelope(
            payload,
            source_url="https://www.youtube.com/watch?v=video-1",
            maximum_network_bytes=10_000,
            maximum_redirects=2,
            request_network_limit=10_000,
            request_redirect_limit=2,
        )


def test_ytdlp_provider_rejects_non_identity_worker_usage() -> None:
    document = json.loads(_worker_payload())
    document["decompressed_bytes"] = document["network_bytes"] + 1
    with pytest.raises(AdapterExecutionError, match="process limits"):
        _decode_worker_envelope(
            json.dumps(document).encode(),
            source_url="https://www.youtube.com/watch?v=video-1",
            maximum_network_bytes=10_000,
            maximum_redirects=2,
            request_network_limit=10_000,
            request_redirect_limit=2,
        )


@pytest.mark.parametrize(
    "target",
    [
        "http://www.youtube.com/watch?v=video-1",
        "https://www.youtube.com:444/watch?v=video-1",
        "https://user:pass@www.youtube.com/watch?v=video-1",
        "https://www.youtube.com/redirect?q=https://127.0.0.1",
        "https://evil-youtube.com/watch?v=video-1",
        "https://www.youtube.com/watch?v=../../private",
    ],
)
def test_ytdlp_target_validation_rejects_unsafe_locators(target: str) -> None:
    with pytest.raises(AdapterExecutionError):
        _canonical_youtube_video_url(target)


@pytest.mark.parametrize(
    "target",
    [
        "http://www.youtube.com/watch?v=video-1",
        "https://evil-youtube.com/watch?v=video-1",
        "https://youtube.com:444/watch?v=video-1",
        "file:///private/etc/passwd",
    ],
)
def test_worker_network_policy_rejects_non_https_non_youtube_requests(
    target: str,
) -> None:
    with pytest.raises(RuntimeError):
        _validate_network_url(target)


def test_worker_cross_origin_redirects_keep_only_non_sensitive_headers() -> None:
    redirected = urllib.request.Request(
        "https://storage.googleapis.com/object",
        headers={
            "Accept": "application/json",
            "Authorization": "Bearer private",
            "Origin": "https://www.youtube.com",
            "Referer": "https://www.youtube.com/watch?v=video-1",
            "User-Agent": "Fetech-test",
            "X-Goog-Visitor-Id": "private-visitor",
        },
    )

    result = _strip_cross_origin_headers(
        redirected,
        previous_url="https://www.youtube.com/watch?v=video-1",
        next_url="https://storage.googleapis.com/object",
    )

    assert result.headers == {
        "Accept": "application/json",
        "User-agent": "Fetech-test",
    }
    assert result.unredirected_hdrs == {}


def test_worker_same_origin_redirects_preserve_request_headers() -> None:
    redirected = urllib.request.Request(
        "https://www.youtube.com/next",
        headers={"X-Goog-Visitor-Id": "same-origin"},
    )

    result = _strip_cross_origin_headers(
        redirected,
        previous_url="https://www.youtube.com/watch?v=video-1",
        next_url="https://www.youtube.com/next",
    )

    assert result.headers["X-goog-visitor-id"] == "same-origin"


@pytest.mark.parametrize(
    "address",
    ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fe80::1"],
)
def test_worker_dns_policy_rejects_every_non_public_resolution(address: str) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with pytest.raises(RuntimeError):
        _validate_resolved_records(
            [(family, socket.SOCK_STREAM, 6, "", (address, 443))]
        )


def test_worker_dns_policy_accepts_only_public_records() -> None:
    _validate_resolved_records(
        [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", 443)),
            (
                socket.AF_INET6,
                socket.SOCK_STREAM,
                6,
                "",
                ("2606:4700:4700::1111", 443, 0, 0),
            ),
        ]
    )


def test_worker_response_policy_forbids_compression_and_oversized_bodies() -> None:
    state = _BudgetState(maximum_network_bytes=1_000, maximum_redirects=1)
    compressed = Message()
    compressed["Content-Encoding"] = "gzip"
    with pytest.raises(RuntimeError, match="compressed"):
        _validate_response_headers(compressed, state=state)

    oversized = Message()
    oversized["Content-Length"] = "1001"
    with pytest.raises(OSError, match="byte budget"):
        _validate_response_headers(oversized, state=state)
    assert state.network_exhausted


def test_worker_response_policy_rejects_ambiguous_framing() -> None:
    state = _BudgetState(maximum_network_bytes=1_000, maximum_redirects=1)
    headers = Message()
    headers["Content-Length"] = "10"
    headers["Content-Length"] = "20"

    with pytest.raises(RuntimeError, match="ambiguous"):
        _validate_response_headers(headers, state=state)


def test_worker_response_policy_accepts_only_identity_within_budget() -> None:
    state = _BudgetState(maximum_network_bytes=1_000, maximum_redirects=1)
    headers = Message()
    headers["Content-Encoding"] = "identity"
    headers["Content-Length"] = "1000"

    _validate_response_headers(headers, state=state)
    assert not state.network_exhausted


def test_worker_redirect_budget_is_fail_closed() -> None:
    state = _BudgetState(maximum_network_bytes=1_000, maximum_redirects=1)
    state.before_redirect()
    with pytest.raises(RuntimeError):
        state.before_redirect()
    assert state.redirects == 1
    assert state.redirects_exhausted
    assert _failure_code(state) == "redirect_budget_exhausted"


def test_worker_projection_removes_download_urls_and_rejects_video_substitution() -> None:
    source = "https://www.youtube.com/watch?v=video-1"
    projected = _project_metadata(
        {
            "id": "video-1",
            "title": "Safe metadata",
            "webpage_url": f"{source}&signature=private",
            "formats": [{"url": "https://signed.example/private"}],
            "automatic_captions": {
                "en": [{"url": "https://signed.example/private"}],
            },
        },
        source_url=source,
    )
    assert projected["webpage_url"] == source
    assert projected["formats"] == [None]
    assert projected["automatic_captions"] == {"en": []}
    assert "signed.example" not in json.dumps(projected)
    with pytest.raises(AdapterExecutionError, match="requested video"):
        _project_metadata(
            {"id": "different-video", "title": "Substitution"},
            source_url=source,
        )


def test_worker_compacts_oversized_success_into_a_bounded_failure_envelope(
    capsysbinary: pytest.CaptureFixture[bytes],
) -> None:
    return_code = _write_envelope(
        {
            "schema": "fetech.yt_dlp.worker.v1",
            "status": "succeeded",
            "metadata": {"id": "video-1", "title": "x" * 2_000},
            "network_bytes": 123,
            "decompressed_bytes": 123,
            "redirects": 1,
        },
        maximum_output_bytes=512,
    )
    assert return_code == 0
    document = json.loads(capsysbinary.readouterr().out)
    assert document["status"] == "failed"
    assert document["failure_code"] == "output_limit_exhausted"
    assert document["network_bytes"] == 123
