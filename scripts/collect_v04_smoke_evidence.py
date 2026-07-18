"""Collect sanitized, exact-version smoke evidence for the v0.4 release.

The default run is local-only. Pass ``--live-network`` to exercise the fixed
yt-dlp and Wayback targets, and ``--require-complete`` in a release environment
to fail when any required check is missing, skipped, or unsuccessful.
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import hashlib
import hmac
import importlib
import io
import json
import platform
import shutil
import struct
import subprocess
import sys
import wave
import zipfile
import zlib
from collections.abc import Awaitable, Callable, Mapping, Sequence
from datetime import UTC, datetime
from email.parser import Parser
from importlib.metadata import (
    PackageNotFoundError,
    version,
)
from importlib.metadata import (
    distribution as installed_distribution,
)
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[1]
_SOURCE_ROOT = _ROOT / "src"

SCHEMA = "fetech.v0.4.smoke-evidence.v2"
DOCLING_REFERENCE_BUNDLE_SHA256 = (
    "e9aab284777b02541f427ff10ff7e2f1b5656eda04afa3082b9b448d8201bd76"
)
YTDLP_SMOKE_TARGET = "https://www.youtube.com/watch?v=BaW_jenozKc"
WAYBACK_SMOKE_TARGET = "https://example.com/"
REQUIRED_PACKAGE_DISTRIBUTIONS = (
    "fetech",
    "docling-slim",
    "openpyxl",
    "pillow",
    "playwright",
    "pypdf",
    "python-docx",
    "python-pptx",
    "selenium",
    "yt-dlp",
)
PACKAGE_IMPORT_NAMES: Mapping[str, str | None] = {
    "fetech": "fetech",
    # Docling is imported only inside the offline, resource-bounded worker.
    "docling-slim": None,
    "openpyxl": "openpyxl",
    "pillow": "PIL",
    "playwright": "playwright",
    "pypdf": "pypdf",
    "python-docx": "docx",
    "python-pptx": "pptx",
    "selenium": "selenium",
    "yt-dlp": "yt_dlp",
}
REQUIRED_EXECUTABLES: Mapping[str, tuple[str, ...]] = {
    "ffmpeg": ("-version",),
    "ffprobe": ("-version",),
    "tesseract": ("--version",),
}
REQUIRED_CHECK_IDS = frozenset(
    {
        *(f"package:{name}" for name in REQUIRED_PACKAGE_DISTRIBUTIONS),
        *(f"executable:{name}" for name in REQUIRED_EXECUTABLES),
        "artifact:docling-models",
        "artifact:wheel",
        "lock:uv",
        "source:git",
        "smoke:browser",
        "smoke:docling",
        "smoke:ffmpeg",
        "smoke:ffprobe",
        "smoke:tesseract",
        "smoke:wayback",
        "smoke:yt-dlp",
    }
)
DOCLING_REQUIRED_CHECK_IDS = frozenset(
    {
        "artifact:docling-models",
        "package:docling-slim",
        "smoke:docling",
    }
)
_MAX_COMMAND_OUTPUT_BYTES = 8_192
_MAX_WHEEL_BYTES = 500_000_000
_MAX_WHEEL_MEMBER_BYTES = 100_000_000
_DEFAULT_SMOKE_TIMEOUT_SECONDS = 45.0


def _check(
    check_id: str,
    status: str,
    *,
    version_text: str | None = None,
    detail: str | None = None,
    service: str | None = None,
    sha256: str | None = None,
) -> dict[str, str]:
    result = {"id": check_id, "status": status}
    if version_text:
        result["version"] = version_text
    if detail:
        result["detail"] = detail
    if service:
        result["service"] = service
    if sha256:
        result["sha256"] = sha256
    return result


def collect_package_checks() -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    for distribution in REQUIRED_PACKAGE_DISTRIBUTIONS:
        try:
            installed = version(distribution)
            import_name = PACKAGE_IMPORT_NAMES[distribution]
            if import_name is not None:
                importlib.import_module(import_name)
        except PackageNotFoundError:
            checks.append(_check(f"package:{distribution}", "missing"))
        except Exception as exc:
            checks.append(
                _check(
                    f"package:{distribution}",
                    "failed",
                    detail=type(exc).__name__,
                )
            )
        else:
            checks.append(
                _check(
                    f"package:{distribution}",
                    "passed",
                    version_text=installed,
                )
            )
    return checks


def collect_binding_checks(artifact: Path | None) -> list[dict[str, str]]:
    return [
        _git_source_check(),
        _lockfile_check(),
        _wheel_artifact_check(artifact),
    ]


def collect_docling_artifact_check(
    artifacts_path: Path | None,
    *,
    expected_sha256: str = DOCLING_REFERENCE_BUNDLE_SHA256,
) -> dict[str, str]:
    if artifacts_path is None:
        return _check(
            "artifact:docling-models",
            "skipped",
            detail="pass --docling-artifacts-path",
        )
    if (
        len(expected_sha256) != 64
        or any(character not in "0123456789abcdef" for character in expected_sha256)
    ):
        return _check(
            "artifact:docling-models",
            "failed",
            detail="expected_sha256_invalid",
        )
    try:
        from fetech.docling_artifacts import inspect_docling_artifact_bundle

        bundle = inspect_docling_artifact_bundle(
            artifacts_path,
            require_manifest=True,
        )
    except Exception as exc:
        return _check(
            "artifact:docling-models",
            "failed",
            detail=type(exc).__name__,
        )
    if not hmac.compare_digest(bundle.bundle_sha256, expected_sha256):
        return _check(
            "artifact:docling-models",
            "failed",
            detail="bundle_sha256_mismatch",
            sha256=bundle.bundle_sha256,
        )
    models = ",".join(
        f"{model.repository}@{model.revision}[{model.license}]"
        for model in bundle.models
    )
    return _check(
        "artifact:docling-models",
        "passed",
        version_text="2.113.0",
        detail=(
            f"files={len(bundle.files)}; bytes={bundle.total_bytes}; "
            f"models={models}"
        ),
        sha256=bundle.bundle_sha256,
    )


def _git_source_check() -> dict[str, str]:
    executable = shutil.which("git")
    if executable is None:
        return _check("source:git", "missing")
    commit = _command_output(
        (executable, "rev-parse", "--verify", "HEAD"),
        cwd=_ROOT,
    )
    if commit is None:
        return _check("source:git", "failed")
    tracked = subprocess.run(
        (executable, "diff-index", "--quiet", "HEAD", "--"),
        check=False,
        capture_output=True,
        timeout=5,
        cwd=_ROOT,
    )
    untracked = _command_output(
        (executable, "ls-files", "--others", "--exclude-standard"),
        cwd=_ROOT,
        allow_empty=True,
    )
    if tracked.returncode not in {0, 1} or untracked is None:
        return _check("source:git", "failed", version_text=commit)
    clean = tracked.returncode == 0 and not untracked
    return _check(
        "source:git",
        "passed" if clean else "failed",
        version_text=commit,
        detail="clean" if clean else "dirty",
    )


def _command_output(
    arguments: tuple[str, ...],
    *,
    cwd: Path,
    allow_empty: bool = False,
) -> str | None:
    try:
        completed = subprocess.run(
            arguments,
            check=False,
            capture_output=True,
            timeout=5,
            cwd=cwd,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if (
        completed.returncode != 0
        or len(completed.stdout) > _MAX_COMMAND_OUTPUT_BYTES
        or len(completed.stderr) > _MAX_COMMAND_OUTPUT_BYTES
    ):
        return None
    output = completed.stdout.decode("utf-8", errors="strict").strip()
    return output if output or allow_empty else None


def _lockfile_check() -> dict[str, str]:
    lockfile = _ROOT / "uv.lock"
    if not lockfile.is_file() or lockfile.is_symlink():
        return _check("lock:uv", "missing")
    try:
        digest = _file_sha256(lockfile, maximum_bytes=100_000_000)
    except (OSError, ValueError):
        return _check("lock:uv", "failed")
    return _check("lock:uv", "passed", sha256=digest)


def _wheel_artifact_check(artifact: Path | None) -> dict[str, str]:
    if artifact is None:
        return _check("artifact:wheel", "skipped", detail="pass --artifact")
    try:
        if artifact.expanduser().is_symlink():
            raise ValueError("artifact symlinks are not accepted")
        candidate = artifact.expanduser().resolve(strict=True)
        if candidate.suffix != ".whl" or not candidate.is_file():
            raise ValueError("artifact is not a regular wheel")
        wheel_digest = _file_sha256(candidate, maximum_bytes=_MAX_WHEEL_BYTES)
        wheel_version, package_members = _wheel_identity(candidate)
        if version("fetech") != wheel_version:
            raise ValueError("installed Fetech version differs from wheel")
        imported = importlib.import_module("fetech")
        imported_file = Path(str(imported.__file__)).resolve(strict=True)
        if _path_is_within(imported_file, _SOURCE_ROOT):
            raise ValueError("release smoke imported the source checkout")
        installed = installed_distribution("fetech")
        for member, expected_digest in package_members.items():
            installed_path = Path(str(installed.locate_file(member))).resolve(
                strict=True
            )
            if _file_sha256(
                installed_path,
                maximum_bytes=_MAX_WHEEL_MEMBER_BYTES,
            ) != expected_digest:
                raise ValueError("installed Fetech file differs from wheel")
    except (KeyError, OSError, PackageNotFoundError, ValueError, zipfile.BadZipFile) as exc:
        return _check(
            "artifact:wheel",
            "failed",
            detail=type(exc).__name__,
        )
    return _check(
        "artifact:wheel",
        "passed",
        version_text=wheel_version,
        detail=candidate.name,
        sha256=wheel_digest,
    )


def _wheel_identity(wheel: Path) -> tuple[str, dict[str, str]]:
    with zipfile.ZipFile(wheel) as archive:
        metadata_names = [
            name
            for name in archive.namelist()
            if name.startswith("fetech-") and name.endswith(".dist-info/METADATA")
        ]
        record_names = [
            name
            for name in archive.namelist()
            if name.startswith("fetech-") and name.endswith(".dist-info/RECORD")
        ]
        if len(metadata_names) != 1 or len(record_names) != 1:
            raise ValueError("wheel metadata layout is invalid")
        metadata_info = archive.getinfo(metadata_names[0])
        record_info = archive.getinfo(record_names[0])
        if max(metadata_info.file_size, record_info.file_size) > 1_000_000:
            raise ValueError("wheel metadata exceeds its bound")
        metadata = Parser().parsestr(
            archive.read(metadata_info).decode("utf-8", errors="strict")
        )
        if metadata.get("Name", "").casefold() != "fetech":
            raise ValueError("wheel project identity is invalid")
        wheel_version = metadata.get("Version")
        if not wheel_version:
            raise ValueError("wheel version is missing")
        record_rows = csv.reader(
            archive.read(record_info).decode("utf-8", errors="strict").splitlines()
        )
        record_hashes = {
            row[0]: row[1]
            for row in record_rows
            if len(row) == 3 and row[0].startswith("fetech/") and row[1]
        }
        members: dict[str, str] = {}
        for member in archive.infolist():
            if member.is_dir() or not member.filename.startswith("fetech/"):
                continue
            if member.file_size > _MAX_WHEEL_MEMBER_BYTES:
                raise ValueError("wheel package member exceeds its bound")
            encoded = record_hashes.get(member.filename, "")
            if not encoded.startswith("sha256="):
                raise ValueError("wheel package member lacks a SHA-256 RECORD entry")
            expected = encoded.removeprefix("sha256=")
            payload = archive.read(member)
            actual = _urlsafe_sha256(payload)
            if actual != expected:
                raise ValueError("wheel RECORD digest is invalid")
            members[member.filename] = hashlib.sha256(payload).hexdigest()
        if not members:
            raise ValueError("wheel contains no Fetech package files")
        return wheel_version, members


def _urlsafe_sha256(payload: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(hashlib.sha256(payload).digest()).rstrip(b"=").decode()


def _file_sha256(path: Path, *, maximum_bytes: int) -> str:
    size = path.stat().st_size
    if size < 0 or size > maximum_bytes:
        raise ValueError("file exceeds its hash bound")
    digest = hashlib.sha256()
    read = 0
    with path.open("rb") as stream:
        while chunk := stream.read(1_048_576):
            read += len(chunk)
            if read > maximum_bytes:
                raise ValueError("file exceeds its hash bound")
            digest.update(chunk)
    if read != size:
        raise ValueError("file changed while hashing")
    return digest.hexdigest()


def _path_is_within(candidate: Path, root: Path) -> bool:
    try:
        candidate.relative_to(root)
    except ValueError:
        return False
    return True


def collect_executable_checks() -> list[dict[str, str]]:
    checks: list[dict[str, str]] = []
    for executable_name, arguments in REQUIRED_EXECUTABLES.items():
        executable = shutil.which(executable_name)
        if executable is None:
            checks.append(_check(f"executable:{executable_name}", "missing"))
            continue
        try:
            completed = subprocess.run(
                (executable, *arguments),
                check=False,
                capture_output=True,
                timeout=5,
                env={
                    "PATH": str(Path(executable).parent),
                    "LANG": "C.UTF-8",
                    "LC_ALL": "C.UTF-8",
                },
            )
        except (OSError, subprocess.SubprocessError):
            checks.append(_check(f"executable:{executable_name}", "failed"))
            continue
        output = (completed.stdout + completed.stderr)[:_MAX_COMMAND_OUTPUT_BYTES]
        first_line = output.decode("utf-8", errors="replace").splitlines()[:1]
        status = "passed" if completed.returncode == 0 and first_line else "failed"
        checks.append(
            _check(
                f"executable:{executable_name}",
                status,
                version_text=first_line[0].strip() if first_line else None,
            )
        )
    return checks


async def _capture_async_check(
    check_id: str,
    operation: Callable[[], Awaitable[tuple[str | None, str | None]]],
    *,
    service: str | None = None,
    timeout_seconds: float = _DEFAULT_SMOKE_TIMEOUT_SECONDS,
) -> dict[str, str]:
    try:
        async with asyncio.timeout(timeout_seconds):
            version_text, detail = await operation()
    except Exception as exc:
        return _check(
            check_id,
            "failed",
            detail=type(exc).__name__,
            service=service,
        )
    return _check(
        check_id,
        "passed",
        version_text=version_text,
        detail=detail,
        service=service,
    )


def _docx_bytes() -> bytes:
    from docx import Document

    output = io.BytesIO()
    document = Document()
    document.add_paragraph(
        "Docling smoke evidence with a stable source paragraph and bounded output."
    )
    document.save(output)
    return output.getvalue()


def _pdf_bytes(text: str) -> bytes:
    escaped = text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 18 Tf 72 700 Td ({escaped}) Tj ET".encode("ascii")
    objects = (
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        (
            b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            b"/Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>"
        ),
        b"<< /Length " + str(len(stream)).encode("ascii") + b" >>\nstream\n"
        + stream
        + b"\nendstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    )
    document = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for index, payload in enumerate(objects, start=1):
        offsets.append(len(document))
        document.extend(f"{index} 0 obj\n".encode("ascii"))
        document.extend(payload)
        document.extend(b"\nendobj\n")
    xref_offset = len(document)
    document.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    document.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        document.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    document.extend(
        (
            f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n"
        ).encode("ascii")
    )
    return bytes(document)


def _png(width: int = 64, height: int = 32) -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data) & 0xFFFFFFFF)
        )

    rows = (b"\x00" + (b"\xff\xff\xff" * width)) * height
    return b"".join(
        (
            b"\x89PNG\r\n\x1a\n",
            chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)),
            chunk(b"IDAT", zlib.compress(rows)),
            chunk(b"IEND", b""),
        )
    )


def _ocr_png() -> bytes:
    from PIL import Image, ImageDraw, ImageFont

    image = Image.new("RGB", (640, 180), "white")
    draw = ImageDraw.Draw(image)
    try:
        font = ImageFont.load_default(size=56)
    except TypeError:
        font = ImageFont.load_default()
    draw.text((32, 48), "FETECH 42", fill="black", font=font)
    output = io.BytesIO()
    image.save(output, format="PNG")
    return output.getvalue()


def _wav_bytes() -> bytes:
    output = io.BytesIO()
    with wave.open(output, "wb") as wav:
        wav.setnchannels(1)
        wav.setsampwidth(2)
        wav.setframerate(8_000)
        wav.writeframes(b"\x00\x00" * 800)
    return output.getvalue()


async def _browser_smoke() -> tuple[str | None, str | None]:
    from playwright.async_api import async_playwright

    from fetech.browser_render import BrowserRenderWorker

    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(headless=True)
        browser_version = browser.version
        await browser.close()
    rendered = await BrowserRenderWorker().render(
        (
            "<html><body><main id='loading'>Loading</main><script>"
            "document.querySelector('main').textContent="
            "'Bounded browser smoke evidence from inline JavaScript.';"
            "</script></body></html>"
        ),
        target="https://example.com/browser-smoke",
        user_agent="Fetech/v0.4-smoke",
        timeout_seconds=10,
        maximum_bytes=1_000_000,
        operations=frozenset({"visible_text", "wait_for_selector"}),
        wait_selector="main",
        scroll_steps=0,
    )
    if "Bounded browser smoke evidence" not in rendered.visible_text:
        raise ValueError("browser smoke result did not contain the expected text")
    return browser_version, "Playwright Chromium launched through the Fetech worker"


async def _docling_smoke(
    artifacts_path: Path | None,
    expected_sha256: str,
) -> tuple[str | None, str | None]:
    from fetech.adapters.documents import DocumentLimits, DocumentParseWorker
    from fetech.docling_artifacts import inspect_docling_artifact_bundle

    if artifacts_path is None:
        raise ValueError("Docling artifacts path was not supplied")
    bundle = inspect_docling_artifact_bundle(
        artifacts_path,
        require_manifest=True,
    )
    if not hmac.compare_digest(bundle.bundle_sha256, expected_sha256):
        raise ValueError("Docling artifact bundle did not match the trust anchor")
    fixture_text = "Docling smoke evidence 42"
    parsed = await DocumentParseWorker(
        memory_mb=4_096,
        docling_artifacts_path=artifacts_path,
        docling_artifacts_sha256=expected_sha256,
    ).parse(
        "pdf",
        _pdf_bytes(fixture_text),
        target="https://example.com/document-smoke.pdf",
        limits=DocumentLimits(
            maximum_input_bytes=2_000_000,
            maximum_output_bytes=2_000_000,
            maximum_blocks=10,
        ),
        timeout_seconds=60,
    )
    if parsed.parser != "docling":
        raise ValueError("preferred Docling parser was not selected")
    if not parsed.locators:
        raise ValueError("Docling smoke result did not retain locators")
    if fixture_text not in json.dumps(
        parsed.document,
        ensure_ascii=False,
        sort_keys=True,
    ):
        raise ValueError("Docling smoke result did not retain fixture content")
    components = dict(parsed.parser_components)
    if (
        components.get("docling-slim") != "2.113.0"
        or not {"docling-core", "docling-parse"}.issubset(components)
        or parsed.artifact_bundle_id != bundle.bundle_sha256
    ):
        raise ValueError("Docling smoke result omitted reproducibility metadata")
    component_text = ",".join(
        f"{name}={component_version}"
        for name, component_version in sorted(components.items())
    )
    model_text = ",".join(
        f"{model.repository}@{model.revision}[{model.license}]"
        for model in bundle.models
    )
    return (
        version("docling-slim"),
        (
            f"parser={parsed.parser}; {component_text}; "
            f"artifact_bundle_sha256={bundle.bundle_sha256}; "
            f"models={model_text}"
        ),
    )


async def _ffprobe_smoke() -> tuple[str | None, str | None]:
    from fetech.adapters.media import FFprobeWorker

    result = await FFprobeWorker().probe(
        _wav_bytes(),
        timeout_seconds=5,
        maximum_output_bytes=100_000,
    )
    if not isinstance(result.get("format"), dict):
        raise ValueError("FFprobe smoke result did not contain format metadata")
    return _executable_version("ffprobe"), "bounded WAV metadata probe"


async def _ffmpeg_smoke() -> tuple[str | None, str | None]:
    from fetech.adapters.media import FFmpegThumbnailWorker

    thumbnail, media_type = await FFmpegThumbnailWorker().thumbnail(
        _png(),
        timeout_seconds=5,
        maximum_output_bytes=1_000_000,
    )
    if media_type != "image/png" or not thumbnail.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError("FFmpeg smoke result was not a PNG")
    return _executable_version("ffmpeg"), "bounded first-frame extraction"


async def _tesseract_smoke() -> tuple[str | None, str | None]:
    from fetech.adapters.media import TesseractOCRWorker

    text = await TesseractOCRWorker().extract_text(
        _ocr_png(),
        language="en",
        timeout_seconds=5,
        maximum_output_bytes=100_000,
    )
    normalized = "".join(character for character in text.upper() if character.isalnum())
    if "FETECH" not in normalized or "42" not in normalized:
        raise ValueError("Tesseract smoke result did not retain fixture content")
    return _executable_version("tesseract"), "bounded stdin/stdout OCR"


def _executable_version(executable_name: str) -> str | None:
    executable = shutil.which(executable_name)
    if executable is None:
        return None
    arguments = REQUIRED_EXECUTABLES[executable_name]
    completed = subprocess.run(
        (executable, *arguments),
        check=False,
        capture_output=True,
        timeout=5,
        env={
            "PATH": str(Path(executable).parent),
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
    )
    output = (completed.stdout + completed.stderr)[:_MAX_COMMAND_OUTPUT_BYTES]
    lines = output.decode("utf-8", errors="replace").splitlines()
    return lines[0].strip() if completed.returncode == 0 and lines else None


async def _yt_dlp_smoke() -> tuple[str | None, str | None]:
    from fetech.yt_dlp import YTDLPMetadataWorker

    result = await YTDLPMetadataWorker().metadata(
        YTDLP_SMOKE_TARGET,
        timeout_seconds=30,
        maximum_output_bytes=1_000_000,
        maximum_network_bytes=5_000_000,
        maximum_redirects=4,
    )
    if result.metadata.get("id") != "BaW_jenozKc":
        raise ValueError("yt-dlp smoke result did not contain the expected video ID")
    return version("yt-dlp"), "fixed public yt-dlp test video metadata"


async def _wayback_smoke() -> tuple[str | None, str | None]:
    from fetech.security import SafeURLPolicy
    from fetech.wayback import WaybackSnapshotConnector

    result = await WaybackSnapshotConnector(
        policy=SafeURLPolicy(),
        user_agent="Fetech/v0.4-smoke",
    ).fetch_snapshot(
        WAYBACK_SMOKE_TARGET,
        maximum_bytes=2_000_000,
        deadline_seconds=30,
    )
    if result.original_url != WAYBACK_SMOKE_TARGET or not result.body:
        raise ValueError("Wayback smoke result did not preserve source authority")
    return None, f"capture date {result.captured_at.isoformat()}"


async def collect_smoke_checks(
    *,
    live_network: bool,
    docling_artifacts_path: Path | None = None,
    docling_artifacts_sha256: str = DOCLING_REFERENCE_BUNDLE_SHA256,
) -> list[dict[str, str]]:
    checks = [
        await _capture_async_check("smoke:browser", _browser_smoke),
        await _capture_async_check(
            "smoke:docling",
            lambda: _docling_smoke(
                docling_artifacts_path,
                docling_artifacts_sha256,
            ),
            timeout_seconds=75,
        ),
        await _capture_async_check("smoke:ffmpeg", _ffmpeg_smoke),
        await _capture_async_check("smoke:ffprobe", _ffprobe_smoke),
        await _capture_async_check("smoke:tesseract", _tesseract_smoke),
    ]
    if live_network:
        checks.extend(
            (
                await _capture_async_check(
                    "smoke:yt-dlp",
                    _yt_dlp_smoke,
                    service="YouTube HTTPS metadata endpoints via yt-dlp",
                ),
                await _capture_async_check(
                    "smoke:wayback",
                    _wayback_smoke,
                    service="https://archive.org/wayback/available and https://web.archive.org",
                ),
            )
        )
    else:
        checks.extend(
            (
                _check(
                    "smoke:yt-dlp",
                    "skipped",
                    detail="rerun with --live-network",
                    service="YouTube HTTPS metadata endpoints via yt-dlp",
                ),
                _check(
                    "smoke:wayback",
                    "skipped",
                    detail="rerun with --live-network",
                    service="https://archive.org/wayback/available and https://web.archive.org",
                ),
            )
        )
    return checks


async def collect_evidence(
    *,
    live_network: bool,
    artifact: Path | None = None,
    docling_artifacts_path: Path | None = None,
    docling_artifacts_sha256: str = DOCLING_REFERENCE_BUNDLE_SHA256,
) -> dict[str, object]:
    checks = collect_package_checks()
    checks.extend(collect_binding_checks(artifact))
    checks.append(
        collect_docling_artifact_check(
            docling_artifacts_path,
            expected_sha256=docling_artifacts_sha256,
        )
    )
    checks.extend(collect_executable_checks())
    checks.extend(
        await collect_smoke_checks(
            live_network=live_network,
            docling_artifacts_path=docling_artifacts_path,
            docling_artifacts_sha256=docling_artifacts_sha256,
        )
    )
    return {
        "schema": SCHEMA,
        "generated_at": datetime.now(UTC).isoformat(),
        "platform": {
            "machine": platform.machine(),
            "python": platform.python_version(),
            "system": platform.system(),
            "system_release": platform.release(),
        },
        "network_smoke_requested": live_network,
        "checks": sorted(checks, key=lambda item: item["id"]),
    }


def incomplete_required_checks(evidence: Mapping[str, object]) -> list[str]:
    return _incomplete_checks(evidence, REQUIRED_CHECK_IDS)


def incomplete_docling_checks(
    evidence: Mapping[str, object],
    *,
    require_wheel: bool = False,
) -> list[str]:
    required_ids: frozenset[str] = DOCLING_REQUIRED_CHECK_IDS
    if require_wheel:
        required_ids = required_ids | frozenset({"artifact:wheel"})
    return _incomplete_checks(evidence, required_ids)


def _incomplete_checks(
    evidence: Mapping[str, object],
    required_ids: frozenset[str],
) -> list[str]:
    raw_checks = evidence.get("checks")
    if not isinstance(raw_checks, Sequence):
        return sorted(required_ids)
    statuses = {
        str(item.get("id")): item.get("status")
        for item in raw_checks
        if isinstance(item, Mapping)
    }
    return sorted(
        check_id
        for check_id in required_ids
        if statuses.get(check_id) != "passed"
    )


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--artifact",
        type=Path,
        help=(
            "bind evidence to this installed Fetech wheel by verifying its "
            "version, RECORD hashes, package files, and SHA-256"
        ),
    )
    parser.add_argument(
        "--docling-artifacts-path",
        type=Path,
        help="explicit local directory containing prefetched Docling 2.113 model artifacts",
    )
    parser.add_argument(
        "--docling-artifacts-sha256",
        default=DOCLING_REFERENCE_BUNDLE_SHA256,
        help=(
            "independent expected SHA-256 for the manifest-bound model bundle; "
            "defaults to the reviewed Fetech v0.4 reference bundle"
        ),
    )
    parser.add_argument(
        "--live-network",
        action="store_true",
        help="exercise the fixed public yt-dlp and Wayback smoke targets",
    )
    parser.add_argument(
        "--source-tree",
        action="store_true",
        help=(
            "prepend this checkout's src directory for an explicitly "
            "non-release development smoke"
        ),
    )
    parser.add_argument(
        "--require-complete",
        action="store_true",
        help="return non-zero unless every required package, tool, and smoke check passes",
    )
    parser.add_argument(
        "--require-docling",
        action="store_true",
        help=(
            "return non-zero unless the pinned Docling package, reviewed "
            "content manifest, and offline conversion smoke all pass"
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        help="write the sanitized JSON evidence to this path instead of stdout",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = _parser().parse_args(argv)
    if arguments.source_tree and str(_SOURCE_ROOT) not in sys.path:
        sys.path.insert(0, str(_SOURCE_ROOT))
    evidence = asyncio.run(
        collect_evidence(
            live_network=arguments.live_network,
            artifact=arguments.artifact,
            docling_artifacts_path=arguments.docling_artifacts_path,
            docling_artifacts_sha256=arguments.docling_artifacts_sha256,
        )
    )
    serialized = json.dumps(evidence, indent=2, sort_keys=True) + "\n"
    if arguments.output is None:
        sys.stdout.write(serialized)
    else:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(serialized, encoding="utf-8")
    if arguments.require_complete and incomplete_required_checks(evidence):
        return 1
    if arguments.require_docling and incomplete_docling_checks(
        evidence,
        require_wheel=arguments.artifact is not None,
    ):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
