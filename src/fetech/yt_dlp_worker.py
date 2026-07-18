"""Isolated yt-dlp metadata worker with fail-closed network guards."""

from __future__ import annotations

import importlib
import ipaddress
import json
import os
import socket
import sys
import tempfile
import urllib.error
import urllib.request
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from types import ModuleType
from typing import Any, cast
from urllib.parse import urlsplit

from fetech.yt_dlp import (
    _WORKER_SCHEMA,
    _canonical_youtube_video_url,
    _project_metadata,
)

_ALLOWED_NETWORK_SUFFIXES = (
    "ggpht.com",
    "googleapis.com",
    "googleusercontent.com",
    "googlevideo.com",
    "youtu.be",
    "youtube.com",
    "youtube-nocookie.com",
    "ytimg.com",
)
_CROSS_ORIGIN_SAFE_HEADERS = frozenset(
    {
        "accept",
        "accept-encoding",
        "accept-language",
        "range",
        "user-agent",
    }
)
_MAX_TARGET_BYTES = 2_048


class _PolicyViolation(RuntimeError):
    pass


@dataclass(slots=True)
class _BudgetState:
    maximum_network_bytes: int
    maximum_redirects: int
    network_bytes: int = 0
    redirects: int = 0
    network_exhausted: bool = False
    redirects_exhausted: bool = False
    policy_blocked: bool = False

    @property
    def remaining_network_bytes(self) -> int:
        return max(0, self.maximum_network_bytes - self.network_bytes)

    def before_redirect(self) -> None:
        if self.redirects >= self.maximum_redirects:
            self.redirects_exhausted = True
            raise _PolicyViolation("redirect budget exhausted")
        self.redirects += 1


class _SilentLogger:
    def debug(self, message: str) -> None:
        del message

    def warning(self, message: str) -> None:
        del message

    def error(self, message: str) -> None:
        del message


def main(arguments: Sequence[str] | None = None) -> int:
    argv = list(arguments if arguments is not None else sys.argv[1:])
    try:
        maximum_network_bytes, maximum_redirects, socket_timeout, output_limit = (
            _parse_arguments(argv)
        )
        raw_target = sys.stdin.buffer.read(_MAX_TARGET_BYTES + 1)
        if len(raw_target) > _MAX_TARGET_BYTES:
            raise ValueError("target exceeded its byte bound")
        target = _canonical_youtube_video_url(raw_target.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RuntimeError):
        return 3

    state = _BudgetState(
        maximum_network_bytes=maximum_network_bytes,
        maximum_redirects=maximum_redirects,
    )
    try:
        yt_dlp = importlib.import_module("yt_dlp")
        plugins = importlib.import_module("yt_dlp.plugins")
        urllib_networking = importlib.import_module("yt_dlp.networking._urllib")
    except ImportError:
        return 2

    try:
        _disable_plugins(plugins)
        with (
            _network_guards(state, urllib_networking),
            tempfile.TemporaryDirectory(prefix="fetech-ytdlp-") as temporary_directory,
            _temporary_working_directory(temporary_directory),
        ):
            document = _extract_metadata(
                yt_dlp,
                urllib_networking,
                target=target,
                socket_timeout=socket_timeout,
            )
        metadata = _project_metadata(document, source_url=target)
        envelope: dict[str, object] = {
            "schema": _WORKER_SCHEMA,
            "status": "succeeded",
            "metadata": metadata,
            "network_bytes": state.network_bytes,
            "decompressed_bytes": state.network_bytes,
            "redirects": state.redirects,
        }
    except BaseException:
        envelope = {
            "schema": _WORKER_SCHEMA,
            "status": "failed",
            "failure_code": _failure_code(state),
            "network_bytes": state.network_bytes,
            "decompressed_bytes": state.network_bytes,
            "redirects": state.redirects,
        }
    return _write_envelope(envelope, maximum_output_bytes=output_limit)


def _parse_arguments(arguments: Sequence[str]) -> tuple[int, int, float, int]:
    if len(arguments) != 4:
        raise ValueError("worker requires four bounded arguments")
    maximum_network_bytes = int(arguments[0])
    maximum_redirects = int(arguments[1])
    socket_timeout = float(arguments[2])
    output_limit = int(arguments[3])
    if (
        not 0 < maximum_network_bytes <= 100_000_000
        or not 0 <= maximum_redirects <= 30
        or not 0 < socket_timeout <= 60
        or not 0 < output_limit <= 1_000_000
    ):
        raise ValueError("worker limits are invalid")
    return (
        maximum_network_bytes,
        maximum_redirects,
        socket_timeout,
        output_limit,
    )


def _disable_plugins(plugins: ModuleType) -> None:
    plugin_directories = getattr(plugins, "plugin_dirs", None)
    loaded = getattr(plugins, "all_plugins_loaded", None)
    if plugin_directories is None or loaded is None:
        raise _PolicyViolation("yt-dlp plugin controls are unavailable")
    plugin_directories.value = []
    loaded.value = True


def _extract_metadata(
    yt_dlp: ModuleType,
    urllib_networking: ModuleType,
    *,
    target: str,
    socket_timeout: float,
) -> Mapping[str, object]:
    youtube_dl = getattr(yt_dlp, "YoutubeDL", None)
    urllib_handler = getattr(urllib_networking, "UrllibRH", None)
    if not isinstance(youtube_dl, type) or not isinstance(urllib_handler, type):
        raise _PolicyViolation("yt-dlp request handler controls are unavailable")

    class PolicyUrllibRH(urllib_handler):  # type: ignore[misc, valid-type]
        _SUPPORTED_URL_SCHEMES = ("https",)
        _SUPPORTED_PROXY_SCHEMES: tuple[str, ...] = ()

    class PolicyYoutubeDL(youtube_dl):  # type: ignore[misc, valid-type]
        def build_request_director(
            self,
            handlers: object,
            preferences: object | None = None,
        ) -> object:
            del handlers, preferences
            return super().build_request_director((PolicyUrllibRH,), ())

        def urlopen(self, request: object) -> object:
            url = request if isinstance(request, str) else getattr(request, "url", "")
            _validate_network_url(url)
            return super().urlopen(request)

    params: dict[str, object] = {
        "quiet": True,
        "no_warnings": True,
        "skip_download": True,
        "noplaylist": True,
        "cachedir": False,
        "cookiefile": None,
        "cookiesfrombrowser": None,
        "usenetrc": False,
        "netrc_cmd": None,
        "proxy": "",
        "geo_verification_proxy": "",
        "http_headers": {"Accept-Encoding": "identity"},
        "socket_timeout": socket_timeout,
        "retries": 0,
        "extractor_retries": 0,
        "fragment_retries": 0,
        "file_access_retries": 0,
        "js_runtimes": {},
        "remote_components": [],
        "exec_cmd": None,
        "postprocessors": [],
        "external_downloader": {},
        "writedescription": False,
        "writesubtitles": False,
        "writeautomaticsub": False,
        "writethumbnail": False,
        "write_all_thumbnails": False,
        "writeinfojson": False,
        "writeannotations": False,
        "getcomments": False,
        "allow_playlist_files": False,
        "enable_file_urls": False,
        "nocheckcertificate": False,
        "logger": _SilentLogger(),
    }
    with PolicyYoutubeDL(params, auto_init=True) as downloader:
        document = downloader.extract_info(target, download=False, process=True)
    if (
        not isinstance(document, Mapping)
        or document.get("_type") in {"playlist", "multi_video"}
    ):
        raise ValueError("yt-dlp did not return one video")
    return document


@contextmanager
def _network_guards(
    state: _BudgetState,
    urllib_networking: ModuleType,
) -> Iterator[None]:
    response_adapter_candidate = getattr(
        urllib_networking,
        "UrllibResponseAdapter",
        None,
    )
    redirect_handler_candidate = getattr(urllib_networking, "RedirectHandler", None)
    http_handler_candidate = getattr(urllib_networking, "HTTPHandler", None)
    if (
        not isinstance(response_adapter_candidate, type)
        or not isinstance(redirect_handler_candidate, type)
        or not isinstance(http_handler_candidate, type)
    ):
        raise _PolicyViolation("yt-dlp urllib controls are unavailable")
    response_adapter = cast(Any, response_adapter_candidate)
    redirect_handler = cast(Any, redirect_handler_candidate)
    http_handler = cast(Any, http_handler_candidate)

    original_getaddrinfo = cast(Any, socket.getaddrinfo)
    original_read = cast(Any, response_adapter.read)
    original_http_response = cast(Any, http_handler.http_response)
    original_https_response = cast(Any, http_handler.https_response)
    original_standard_redirect = cast(
        Any,
        urllib.request.HTTPRedirectHandler.redirect_request,
    )
    original_ytdlp_redirect = cast(
        Any,
        redirect_handler.redirect_request,
    )

    def guarded_getaddrinfo(
        host: str | bytes | None,
        port: str | int | None,
        *args: object,
        **kwargs: object,
    ) -> list[tuple[Any, ...]]:
        try:
            _validate_dns_request(host, port)
            records: list[tuple[Any, ...]] = original_getaddrinfo(
                host,
                port,
                *args,
                **kwargs,
            )
            _validate_resolved_records(records)
            return records
        except BaseException:
            state.policy_blocked = True
            raise

    def bounded_read(response: object, amount: int | None = None) -> bytes:
        remaining = state.remaining_network_bytes
        if remaining <= 0:
            state.network_exhausted = True
            raise OSError("yt-dlp response byte budget exhausted")
        requested = amount
        was_capped = amount is None or amount < 0 or amount > remaining
        if was_capped:
            requested = remaining
        data = original_read(response, requested)
        if not isinstance(data, bytes):
            state.policy_blocked = True
            raise OSError("yt-dlp response returned non-byte data")
        state.network_bytes += len(data)
        if was_capped and len(data) == remaining:
            state.network_exhausted = True
            raise OSError("yt-dlp response byte budget exhausted")
        return data

    def guarded_response(
        handler: Any,
        request: urllib.request.Request,
        response: Any,
    ) -> Any:
        try:
            _validate_network_url(request.full_url)
            _validate_response_headers(response.headers, state=state)
        except BaseException:
            state.policy_blocked = not state.network_exhausted
            response.close()
            raise
        return original_http_response(handler, request, response)

    def guarded_standard_redirect(
        handler: Any,
        request: urllib.request.Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Any:
        _validate_redirect(state, request.full_url, new_url)
        redirected = original_standard_redirect(
            handler,
            request,
            response,
            code,
            message,
            headers,
            new_url,
        )
        return _strip_cross_origin_headers(
            redirected,
            previous_url=request.full_url,
            next_url=new_url,
        )

    def guarded_ytdlp_redirect(
        handler: Any,
        request: urllib.request.Request,
        response: Any,
        code: int,
        message: str,
        headers: Any,
        new_url: str,
    ) -> Any:
        _validate_redirect(state, request.full_url, new_url)
        redirected = original_ytdlp_redirect(
            handler,
            request,
            response,
            code,
            message,
            headers,
            new_url,
        )
        return _strip_cross_origin_headers(
            redirected,
            previous_url=request.full_url,
            next_url=new_url,
        )

    _assign_runtime_attribute(socket, "getaddrinfo", guarded_getaddrinfo)
    _assign_runtime_attribute(response_adapter, "read", bounded_read)
    _assign_runtime_attribute(http_handler, "http_response", guarded_response)
    _assign_runtime_attribute(http_handler, "https_response", guarded_response)
    _assign_runtime_attribute(
        urllib.request.HTTPRedirectHandler,
        "redirect_request",
        guarded_standard_redirect,
    )
    _assign_runtime_attribute(
        redirect_handler,
        "redirect_request",
        guarded_ytdlp_redirect,
    )
    try:
        yield
    finally:
        _assign_runtime_attribute(socket, "getaddrinfo", original_getaddrinfo)
        _assign_runtime_attribute(response_adapter, "read", original_read)
        _assign_runtime_attribute(
            http_handler,
            "http_response",
            original_http_response,
        )
        _assign_runtime_attribute(
            http_handler,
            "https_response",
            original_https_response,
        )
        _assign_runtime_attribute(
            urllib.request.HTTPRedirectHandler,
            "redirect_request",
            original_standard_redirect,
        )
        _assign_runtime_attribute(
            redirect_handler,
            "redirect_request",
            original_ytdlp_redirect,
        )


def _assign_runtime_attribute(
    target: object,
    name: str,
    value: object,
) -> None:
    setattr(target, name, value)


def _validate_redirect(state: _BudgetState, previous_url: str, next_url: str) -> None:
    try:
        _validate_network_url(next_url, previous_url=previous_url)
        state.before_redirect()
    except BaseException:
        if not state.redirects_exhausted:
            state.policy_blocked = True
        raise


def _validate_network_url(value: object, *, previous_url: str | None = None) -> None:
    if not isinstance(value, str) or not value:
        raise _PolicyViolation("network URL is invalid")
    try:
        parsed = urlsplit(value)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        port = parsed.port
    except (UnicodeError, ValueError) as exc:
        raise _PolicyViolation("network URL is invalid") from exc
    if (
        parsed.scheme.lower() != "https"
        or parsed.username is not None
        or parsed.password is not None
        or port not in {None, 443}
        or not _allowed_network_host(host)
    ):
        raise _PolicyViolation("yt-dlp network destination is not allowed")
    if previous_url is not None:
        previous_scheme = urlsplit(previous_url).scheme.lower()
        if previous_scheme == "https" and parsed.scheme.lower() != "https":
            raise _PolicyViolation("HTTPS downgrade redirect is forbidden")


def _strip_cross_origin_headers(
    request: urllib.request.Request,
    *,
    previous_url: str,
    next_url: str,
) -> urllib.request.Request:
    if _network_origin(previous_url) == _network_origin(next_url):
        return request
    for attribute in ("headers", "unredirected_hdrs"):
        headers = getattr(request, attribute, None)
        if not isinstance(headers, dict):
            raise _PolicyViolation("redirect request headers are unavailable")
        for name in tuple(headers):
            if name.casefold() not in _CROSS_ORIGIN_SAFE_HEADERS:
                del headers[name]
    return request


def _network_origin(value: str) -> tuple[str, str, int]:
    try:
        parsed = urlsplit(value)
        scheme = parsed.scheme.casefold()
        host = (parsed.hostname or "").encode("idna").decode("ascii").casefold()
        port = parsed.port or (443 if scheme == "https" else 80)
    except (UnicodeError, ValueError) as exc:
        raise _PolicyViolation("network URL is invalid") from exc
    return scheme, host, port


def _validate_dns_request(
    host: str | bytes | None,
    port: str | int | None,
) -> None:
    if isinstance(host, bytes):
        host = host.decode("ascii")
    if not isinstance(host, str) or not _allowed_network_host(host.lower().rstrip(".")):
        raise _PolicyViolation("yt-dlp DNS hostname is not allowed")
    if port not in {443, "443", "https"}:
        raise _PolicyViolation("yt-dlp DNS port is not allowed")


def _allowed_network_host(host: str) -> bool:
    return any(host == suffix or host.endswith(f".{suffix}") for suffix in _ALLOWED_NETWORK_SUFFIXES)


def _validate_resolved_records(records: Sequence[tuple[Any, ...]]) -> None:
    if not records:
        raise _PolicyViolation("yt-dlp hostname did not resolve")
    for record in records:
        if len(record) < 5 or not isinstance(record[4], tuple) or not record[4]:
            raise _PolicyViolation("yt-dlp resolver returned an invalid record")
        try:
            address = ipaddress.ip_address(str(record[4][0]))
        except ValueError as exc:
            raise _PolicyViolation("yt-dlp resolver returned an invalid address") from exc
        if not address.is_global or address.is_multicast or address.is_unspecified:
            raise _PolicyViolation("yt-dlp hostname resolved to a non-public address")


def _validate_response_headers(headers: object, *, state: _BudgetState) -> None:
    getter = getattr(headers, "get", None)
    if not callable(getter):
        raise _PolicyViolation("yt-dlp response headers are unavailable")
    raw_encoding = _single_response_header(headers, "Content-Encoding") or ""
    if not isinstance(raw_encoding, str) or raw_encoding.strip().lower() not in {
        "",
        "identity",
    }:
        raise _PolicyViolation("compressed yt-dlp responses are forbidden")
    raw_length = _single_response_header(headers, "Content-Length")
    if raw_length is None:
        return
    if (
        not isinstance(raw_length, str)
        or not raw_length.isascii()
        or not raw_length.isdigit()
    ):
        raise _PolicyViolation("yt-dlp response Content-Length is invalid")
    if int(raw_length) > state.remaining_network_bytes:
        state.network_exhausted = True
        raise OSError("yt-dlp response byte budget exhausted")


def _single_response_header(headers: object, name: str) -> object:
    get_all = getattr(headers, "get_all", None)
    if callable(get_all):
        values = get_all(name, [])
        if not isinstance(values, list) or len(values) > 1:
            raise _PolicyViolation(f"ambiguous yt-dlp {name} is forbidden")
        return values[0] if values else None
    getter = getattr(headers, "get", None)
    if not callable(getter):
        raise _PolicyViolation("yt-dlp response headers are unavailable")
    return getter(name)


@contextmanager
def _temporary_working_directory(path: str) -> Iterator[None]:
    previous = os.getcwd()
    os.chdir(path)
    try:
        yield
    finally:
        os.chdir(previous)


def _failure_code(state: _BudgetState) -> str:
    if state.network_exhausted:
        return "network_budget_exhausted"
    if state.redirects_exhausted:
        return "redirect_budget_exhausted"
    if state.policy_blocked:
        return "policy_blocked"
    return "extraction_failed"


def _write_envelope(
    envelope: Mapping[str, object],
    *,
    maximum_output_bytes: int,
) -> int:
    try:
        payload = json.dumps(
            envelope,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError):
        return 6
    if len(payload) > maximum_output_bytes:
        compact_failure = {
            "schema": _WORKER_SCHEMA,
            "status": "failed",
            "failure_code": "output_limit_exhausted",
            "network_bytes": envelope.get("network_bytes", 0),
            "decompressed_bytes": envelope.get("decompressed_bytes", 0),
            "redirects": envelope.get("redirects", 0),
        }
        try:
            payload = json.dumps(
                compact_failure,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
        except (TypeError, ValueError):
            return 6
    if not payload or len(payload) > maximum_output_bytes:
        return 6
    sys.stdout.buffer.write(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
