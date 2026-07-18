from __future__ import annotations

import asyncio
import base64
import hashlib
import importlib.util
import io
import zipfile
from pathlib import Path
from types import ModuleType

import pytest

from fetech.docling_artifacts import (
    DoclingArtifactModel,
    write_docling_artifact_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "fetech_v04_smoke_evidence",
    ROOT / "scripts" / "collect_v04_smoke_evidence.py",
)
assert SPEC is not None and SPEC.loader is not None
smoke = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(smoke)
assert isinstance(smoke, ModuleType)


def test_required_check_inventory_covers_release_tools_and_services() -> None:
    assert {
        "artifact:docling-models",
        "artifact:wheel",
        "lock:uv",
        "package:docling-slim",
        "package:yt-dlp",
        "source:git",
        "executable:ffmpeg",
        "executable:ffprobe",
        "executable:tesseract",
        "smoke:browser",
        "smoke:docling",
        "smoke:wayback",
        "smoke:yt-dlp",
    } <= smoke.REQUIRED_CHECK_IDS


def test_incomplete_required_checks_reject_missing_skipped_and_failed() -> None:
    evidence = {
        "checks": [
            {"id": check_id, "status": "passed"}
            for check_id in smoke.REQUIRED_CHECK_IDS
            if check_id not in {"smoke:docling", "smoke:wayback"}
        ]
        + [
            {"id": "smoke:docling", "status": "failed"},
            {"id": "smoke:wayback", "status": "skipped"},
        ]
    }

    assert smoke.incomplete_required_checks(evidence) == [
        "smoke:docling",
        "smoke:wayback",
    ]


def test_docling_strict_inventory_is_narrow_and_complete() -> None:
    assert {
        "artifact:docling-models",
        "package:docling-slim",
        "smoke:docling",
    } == smoke.DOCLING_REQUIRED_CHECK_IDS
    assert smoke.incomplete_docling_checks(
        {
            "checks": [
                {"id": "artifact:docling-models", "status": "passed"},
                {"id": "package:docling-slim", "status": "passed"},
                {"id": "smoke:docling", "status": "failed"},
            ]
        }
    ) == ["smoke:docling"]


def test_docling_strict_inventory_requires_wheel_when_artifact_is_supplied() -> None:
    evidence = {
        "checks": [
            {"id": "artifact:docling-models", "status": "passed"},
            {"id": "artifact:wheel", "status": "failed"},
            {"id": "package:docling-slim", "status": "passed"},
            {"id": "smoke:docling", "status": "passed"},
        ]
    }

    assert smoke.incomplete_docling_checks(evidence) == []
    assert smoke.incomplete_docling_checks(
        evidence,
        require_wheel=True,
    ) == ["artifact:wheel"]


def test_docling_artifact_check_requires_the_expected_bundle_digest(
    tmp_path: Path,
) -> None:
    root = tmp_path / "models"
    model_root = root / "docling-project--docling-layout-heron"
    model_root.mkdir(parents=True)
    (model_root / "README.md").write_text(
        "---\nlicense: apache-2.0\n---\n",
        encoding="utf-8",
    )
    (model_root / "model.safetensors").write_bytes(b"test-weights")
    revision = "a" * 40
    bundle = write_docling_artifact_manifest(
        root,
        models=(
            DoclingArtifactModel(
                repository="docling-project/docling-layout-heron",
                revision=revision,
                license="apache-2.0",
                license_evidence_path=(
                    "docling-project--docling-layout-heron/README.md"
                ),
                source_url=(
                    "https://huggingface.co/docling-project/"
                    f"docling-layout-heron/tree/{revision}"
                ),
            ),
        ),
    )

    passed = smoke.collect_docling_artifact_check(
        root,
        expected_sha256=bundle.bundle_sha256,
    )
    rejected = smoke.collect_docling_artifact_check(
        root,
        expected_sha256="0" * 64,
    )

    assert passed["status"] == "passed"
    assert passed["sha256"] == bundle.bundle_sha256
    assert rejected == {
        "detail": "bundle_sha256_mismatch",
        "id": "artifact:docling-models",
        "sha256": bundle.bundle_sha256,
        "status": "failed",
    }


@pytest.mark.asyncio
async def test_smoke_operation_timeout_is_bounded_and_sanitized() -> None:
    async def hangs() -> tuple[str | None, str | None]:
        await asyncio.sleep(10)
        return None, None

    check = await smoke._capture_async_check(
        "smoke:test",
        hangs,
        timeout_seconds=0.01,
    )

    assert check == {
        "detail": "TimeoutError",
        "id": "smoke:test",
        "status": "failed",
    }


def test_wheel_identity_verifies_record_hashes(tmp_path: Path) -> None:
    wheel = tmp_path / "fetech-0.4.0a0-py3-none-any.whl"
    package_path = "fetech/__init__.py"
    payload = b'__version__ = "0.4.0a0"\n'
    encoded = (
        base64.urlsafe_b64encode(hashlib.sha256(payload).digest())
        .rstrip(b"=")
        .decode()
    )
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr(package_path, payload)
        archive.writestr(
            "fetech-0.4.0a0.dist-info/METADATA",
            "Metadata-Version: 2.3\nName: fetech\nVersion: 0.4.0a0\n",
        )
        archive.writestr(
            "fetech-0.4.0a0.dist-info/RECORD",
            f"{package_path},sha256={encoded},{len(payload)}\n",
        )

    wheel_version, members = smoke._wheel_identity(wheel)

    assert wheel_version == "0.4.0a0"
    assert members == {package_path: hashlib.sha256(payload).hexdigest()}


@pytest.mark.asyncio
async def test_network_smokes_are_explicit_and_service_located(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def passed(
        *_args: object,
        **_kwargs: object,
    ) -> tuple[str | None, str | None]:
        return "1.2.3", "bounded fixture"

    monkeypatch.setattr(smoke, "_browser_smoke", passed)
    monkeypatch.setattr(smoke, "_docling_smoke", passed)
    monkeypatch.setattr(smoke, "_ffmpeg_smoke", passed)
    monkeypatch.setattr(smoke, "_ffprobe_smoke", passed)
    monkeypatch.setattr(smoke, "_tesseract_smoke", passed)

    checks = await smoke.collect_smoke_checks(live_network=False)
    by_id = {check["id"]: check for check in checks}

    assert by_id["smoke:yt-dlp"]["status"] == "skipped"
    assert "YouTube HTTPS" in by_id["smoke:yt-dlp"]["service"]
    assert by_id["smoke:wayback"]["status"] == "skipped"
    assert "archive.org/wayback/available" in by_id["smoke:wayback"]["service"]


def test_cli_writes_sanitized_evidence_and_strict_mode_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "smoke.json"

    async def incomplete(
        *,
        live_network: bool,
        artifact: Path | None,
        docling_artifacts_path: Path | None,
        docling_artifacts_sha256: str,
    ) -> dict[str, object]:
        assert not live_network
        assert artifact is None
        assert docling_artifacts_path is None
        assert (
            docling_artifacts_sha256
            == smoke.DOCLING_REFERENCE_BUNDLE_SHA256
        )
        return {
            "schema": smoke.SCHEMA,
            "generated_at": "2026-07-18T00:00:00+00:00",
            "platform": {
                "machine": "arm64",
                "python": "3.12.0",
                "system": "Darwin",
                "system_release": "test",
            },
            "network_smoke_requested": False,
            "checks": [],
        }

    monkeypatch.setattr(smoke, "collect_evidence", incomplete)

    assert smoke.main(("--output", str(output), "--require-complete")) == 1
    content = output.read_text(encoding="utf-8")
    assert smoke.SCHEMA in content
    assert str(Path.home()) not in content


def test_cli_docling_mode_fails_when_supplied_wheel_is_not_verified(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output = tmp_path / "smoke.json"
    wheel = tmp_path / "fetech-0.3.0a0-py3-none-any.whl"

    async def invalid_wheel(
        *,
        live_network: bool,
        artifact: Path | None,
        docling_artifacts_path: Path | None,
        docling_artifacts_sha256: str,
    ) -> dict[str, object]:
        assert not live_network
        assert artifact == wheel
        assert docling_artifacts_path is None
        assert (
            docling_artifacts_sha256
            == smoke.DOCLING_REFERENCE_BUNDLE_SHA256
        )
        return {
            "schema": smoke.SCHEMA,
            "checks": [
                {"id": "artifact:docling-models", "status": "passed"},
                {"id": "artifact:wheel", "status": "failed"},
                {"id": "package:docling-slim", "status": "passed"},
                {"id": "smoke:docling", "status": "passed"},
            ],
        }

    monkeypatch.setattr(smoke, "collect_evidence", invalid_wheel)

    assert (
        smoke.main(
            (
                "--artifact",
                str(wheel),
                "--require-docling",
                "--output",
                str(output),
            )
        )
        == 1
    )


def test_pdf_smoke_fixture_is_valid_and_extractable() -> None:
    from pypdf import PdfReader

    expected = "Docling smoke evidence 42"
    reader = PdfReader(io.BytesIO(smoke._pdf_bytes(expected)))

    assert len(reader.pages) == 1
    assert expected in (reader.pages[0].extract_text() or "")
