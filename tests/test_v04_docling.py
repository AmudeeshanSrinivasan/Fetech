"""Focused tests for the optional bounded Docling PDF backend."""

from __future__ import annotations

import importlib.util
import inspect
import io
import json
import os
import sys
from enum import StrEnum
from importlib.metadata import version
from pathlib import Path
from types import ModuleType

import pytest

from fetech.adapters.base import AdapterExecutionError
from fetech.adapters.documents import (
    DocumentAdapter,
    DocumentLimits,
    DocumentParseWorker,
    _docling_artifact_bundle_identity,
    _validate_worker_result,
)
from fetech.config import Settings
from fetech.docling_artifacts import (
    DoclingArtifactModel,
    write_docling_artifact_manifest,
)
from fetech.document_worker import (
    _build_docling_runtime,
    _configure_docling_offline,
    _DoclingConfig,
    _DoclingContractError,
    _DoclingRuntime,
    _initialize_parser_runtime,
    _parse_docling_config,
    _parse_docling_pdf,
    _parse_preferred,
    _prepare_parser_runtime,
)
from fetech.gateway import UniversalFetchGateway
from fetech.logic.process import ProcessResult


def _manifested_artifacts(root: Path) -> tuple[Path, str]:
    root.mkdir(parents=True, exist_ok=True)
    model_root = root / "docling-project--docling-layout-heron"
    model_root.mkdir()
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
    return root, bundle.bundle_sha256


def _pdf_bytes() -> bytes:
    from pypdf import PdfWriter

    stream = io.BytesIO()
    writer = PdfWriter()
    writer.add_blank_page(width=72, height=72)
    writer.write(stream)
    return stream.getvalue()


def _docling_config(
    artifacts: Path,
    *,
    timeout_seconds: float = 1,
) -> _DoclingConfig:
    return _DoclingConfig(
        artifacts_path=artifacts,
        artifact_bundle_id="a" * 64,
        document_timeout_seconds=timeout_seconds,
    )


def _docling_components() -> dict[str, str]:
    return {
        "docling-core": "2.87.1",
        "docling-ibm-models": "3.13.3",
        "docling-parse": "7.8.0",
        "docling-slim": "2.113.0",
    }


def _docling_worker_provenance(artifacts: Path) -> dict[str, object]:
    return {
        "artifact_bundle_id": _docling_artifact_bundle_identity(artifacts),
        "fallback_reason": None,
        "parser_components": _docling_components(),
    }


def _unit_docling_config(
    artifacts: Path,
    *,
    timeout_seconds: float = 1,
) -> _DoclingConfig:
    return _DoclingConfig(
        artifacts_path=artifacts,
        artifact_bundle_id="a" * 64,
        document_timeout_seconds=timeout_seconds,
    )


def _build_fake_runtime(
    tmp_path: Path,
    artifacts: Path,
    body: bytes,
    *,
    timeout_seconds: float = 1,
) -> _DoclingRuntime:
    input_path = tmp_path / "docling-input.pdf"
    input_path.write_bytes(body)
    return _build_docling_runtime(
        _unit_docling_config(artifacts, timeout_seconds=timeout_seconds),
        input_path=input_path,
    )


def _placeholder_runtime(artifacts: Path, input_path: Path) -> _DoclingRuntime:
    return _DoclingRuntime(
        config=_unit_docling_config(artifacts),
        converter=object(),  # type: ignore[arg-type]
        input_format="pdf",
        input_path=input_path,
    )


def _install_fake_docling(
    monkeypatch: pytest.MonkeyPatch,
    *,
    pages: dict[object, object],
    texts: dict[int, object],
    status: str = "success",
    errors: list[object] | None = None,
    timed_out: bool = False,
    page_count: int | None = None,
    versions: dict[str, object] | None = None,
) -> dict[str, object]:
    captured: dict[str, object] = {}
    docling = ModuleType("docling")
    docling.__path__ = []  # type: ignore[attr-defined]
    datamodel = ModuleType("docling.datamodel")
    datamodel.__path__ = []  # type: ignore[attr-defined]
    accelerator_module = ModuleType("docling.datamodel.accelerator_options")
    base_models_module = ModuleType("docling.datamodel.base_models")
    pipeline_options_module = ModuleType("docling.datamodel.pipeline_options")
    converter_module = ModuleType("docling.document_converter")

    class AcceleratorDevice:
        CPU = "cpu"

    class AcceleratorOptions:
        def __init__(self, **kwargs: object) -> None:
            captured["accelerator_options"] = kwargs

    class InputFormat:
        PDF = "pdf"

    class ConversionStatus(StrEnum):
        SUCCESS = "success"
        PARTIAL_SUCCESS = "partial_success"
        FAILURE = "failure"

    class DocumentStream:
        def __init__(self, *, name: str, stream: io.BytesIO) -> None:
            self.name = name
            self.stream = stream
            captured["stream_name"] = name
            captured["stream_body"] = stream.getvalue()

    class PdfPipelineOptions:
        def __init__(self, **kwargs: object) -> None:
            captured["pipeline_options_instance"] = self
            captured["pipeline_options"] = kwargs

    class PdfFormatOption:
        def __init__(self, **kwargs: object) -> None:
            captured["format_option_instance"] = self
            captured["format_options"] = kwargs

    class ConvertedDocument:
        def __init__(self) -> None:
            self.pages = pages

        def export_to_text(
            self,
            *,
            page_no: int,
            traverse_pictures: bool,
        ) -> object:
            captured.setdefault("exports", []).append(
                (page_no, traverse_pictures)
            )
            return texts[page_no]

    class InputDocument:
        def __init__(self) -> None:
            valid_pages = [
                page for page in pages if isinstance(page, int) and not isinstance(page, bool)
            ]
            self.page_count = (
                page_count
                if page_count is not None
                else max(valid_pages, default=len(pages))
            )

    class VersionInfo:
        def __init__(self) -> None:
            values = {
                "docling_version": None,
                "docling_core_version": "2.87.1",
                "docling_ibm_models_version": "3.13.3",
                "docling_parse_version": "7.8.0",
                "docling_slim_version": "2.113.0",
            }
            values.update(versions or {})
            for name, value in values.items():
                setattr(self, name, value)

    class ConversionResult:
        def __init__(self) -> None:
            self.document = ConvertedDocument()
            self.errors = list(errors or ())
            self.input = InputDocument()
            self.status = ConversionStatus(status)
            self.version = VersionInfo()

        def has_timeout_errors(self) -> bool:
            return timed_out

    class DocumentConverter:
        def __init__(self, **kwargs: object) -> None:
            captured["converter_options"] = kwargs

        def initialize_pipeline(self, input_format: object) -> None:
            captured["initialized_format"] = input_format

        def convert(self, source: object, **kwargs: object) -> object:
            captured["convert_source"] = source
            captured["convert_options"] = kwargs
            return ConversionResult()

    accelerator_module.AcceleratorDevice = AcceleratorDevice
    accelerator_module.AcceleratorOptions = AcceleratorOptions
    base_models_module.DocumentStream = DocumentStream
    base_models_module.ConversionStatus = ConversionStatus
    base_models_module.InputFormat = InputFormat
    pipeline_options_module.PdfPipelineOptions = PdfPipelineOptions
    converter_module.DocumentConverter = DocumentConverter
    converter_module.PdfFormatOption = PdfFormatOption
    docling.datamodel = datamodel
    datamodel.accelerator_options = accelerator_module
    datamodel.base_models = base_models_module
    datamodel.pipeline_options = pipeline_options_module
    docling.document_converter = converter_module
    for name, module in {
        "docling": docling,
        "docling.datamodel": datamodel,
        "docling.datamodel.accelerator_options": accelerator_module,
        "docling.datamodel.base_models": base_models_module,
        "docling.datamodel.pipeline_options": pipeline_options_module,
        "docling.document_converter": converter_module,
    }.items():
        monkeypatch.setitem(sys.modules, name, module)
    return captured


def test_docling_pdf_path_is_local_offline_cpu_bounded_and_page_located(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured = _install_fake_docling(
        monkeypatch,
        pages={1: object(), 2: object()},
        texts={1: "Page one", 2: "Page two"},
    )
    artifacts = tmp_path / "models"
    artifacts.mkdir()
    body = b"%PDF-1.7 bounded fixture"
    limits = DocumentLimits(
        maximum_input_bytes=len(body),
        maximum_output_bytes=1_000,
        maximum_blocks=2,
    )

    runtime = _build_fake_runtime(
        tmp_path,
        artifacts,
        body,
        timeout_seconds=3.5,
    )
    parsed = _parse_docling_pdf(
        target="file.pdf",
        limits=limits,
        runtime=runtime,
    )

    assert parsed.parser == "docling"
    assert parsed.locators == ("page:1", "page:2")
    assert dict(parsed.parser_components) == {
        "docling-core": "2.87.1",
        "docling-ibm-models": "3.13.3",
        "docling-parse": "7.8.0",
        "docling-slim": "2.113.0",
    }
    assert parsed.artifact_bundle_id == "a" * 64
    assert parsed.document == {
        "type": "pdf",
        "blocks": [
            {"locator": "page:1", "text": "Page one"},
            {"locator": "page:2", "text": "Page two"},
        ],
    }
    assert captured["accelerator_options"] == {
        "num_threads": 1,
        "device": "cpu",
    }
    pipeline_options = captured["pipeline_options"]
    assert isinstance(pipeline_options, dict)
    assert pipeline_options == {
        "accelerator_options": pipeline_options["accelerator_options"],
        "allow_external_plugins": False,
        "artifacts_path": artifacts,
        "document_timeout": 3.5,
        "do_chart_extraction": False,
        "do_code_enrichment": False,
        "do_formula_enrichment": False,
        "do_ocr": False,
        "do_picture_classification": False,
        "do_picture_description": False,
        "do_table_structure": False,
        "enable_remote_services": False,
        "generate_page_images": False,
        "generate_picture_images": False,
    }
    assert captured["converter_options"] == {
        "allowed_formats": ["pdf"],
        "format_options": {"pdf": captured["format_option_instance"]},
    }
    assert captured["format_options"] == {
        "pipeline_options": captured["pipeline_options_instance"]
    }
    assert captured["initialized_format"] == "pdf"
    source = captured["convert_source"]
    assert isinstance(source, Path)
    assert source.read_bytes() == body
    assert captured["convert_options"] == {
        "raises_on_error": True,
        "max_num_pages": 2,
        "max_file_size": len(body),
    }
    assert captured["exports"] == [(1, True), (2, True)]


@pytest.mark.parametrize(
    ("pages", "texts", "match"),
    (
        ({"1": object()}, {1: "text"}, "docling_contract_invalid"),
        ({3: object()}, {3: "text"}, "docling_incomplete_pages"),
        ({1: object()}, {1: object()}, "page text"),
        ({1: object()}, {1: "x" * 100}, "decompressed-byte"),
    ),
)
def test_docling_output_is_treated_as_untrusted_and_bounded(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    pages: dict[object, object],
    texts: dict[int, object],
    match: str,
) -> None:
    _install_fake_docling(monkeypatch, pages=pages, texts=texts)
    artifacts = tmp_path / "models"
    artifacts.mkdir()
    runtime = _build_fake_runtime(tmp_path, artifacts, b"%PDF-1.7")

    with pytest.raises(ValueError, match=match):
        _parse_docling_pdf(
            target="file.pdf",
            limits=DocumentLimits(
                maximum_input_bytes=1_000,
                maximum_output_bytes=10,
                maximum_blocks=2,
            ),
            runtime=runtime,
        )


@pytest.mark.parametrize(
    (
        "status",
        "errors",
        "timed_out",
        "pages",
        "page_count",
        "versions",
        "expected_code",
    ),
    (
        (
            "partial_success",
            [],
            False,
            {1: object()},
            1,
            None,
            "docling_non_success",
        ),
        (
            "success",
            [object()],
            False,
            {1: object()},
            1,
            None,
            "docling_conversion_error",
        ),
        (
            "success",
            [],
            True,
            {1: object()},
            1,
            None,
            "docling_timeout",
        ),
        (
            "success",
            [],
            False,
            {1: object(), 3: object()},
            3,
            None,
            "docling_incomplete_pages",
        ),
        (
            "success",
            [],
            False,
            {1: object()},
            1,
            {"docling_slim_version": "2.114.0"},
            "docling_version_mismatch",
        ),
    ),
)
def test_docling_conversion_contract_rejects_partial_error_and_incomplete_results(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: str,
    errors: list[object],
    timed_out: bool,
    pages: dict[object, object],
    page_count: int,
    versions: dict[str, object] | None,
    expected_code: str,
) -> None:
    _install_fake_docling(
        monkeypatch,
        pages=pages,
        texts={1: "page one", 3: "page three"},
        status=status,
        errors=errors,
        timed_out=timed_out,
        page_count=page_count,
        versions=versions,
    )
    artifacts = tmp_path / "models"
    artifacts.mkdir()
    runtime = _build_fake_runtime(tmp_path, artifacts, b"%PDF-1.7")

    with pytest.raises(_DoclingContractError, match=expected_code):
        _parse_docling_pdf(
            target="file.pdf",
            limits=DocumentLimits(maximum_blocks=3),
            runtime=runtime,
        )


def test_docling_failure_falls_back_to_deterministic_pypdf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "models"
    artifacts.mkdir()

    def fail(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise RuntimeError("untrusted Docling failure")

    monkeypatch.setattr("fetech.document_worker._parse_docling_pdf", fail)
    runtime = _placeholder_runtime(artifacts, tmp_path / "unused.pdf")
    parsed = _parse_preferred(
        "pdf",
        _pdf_bytes(),
        target="file.pdf",
        limits=DocumentLimits(),
        docling=runtime,
        artifact_bundle_id="a" * 64,
    )

    assert parsed.parser == "pypdf"
    assert parsed.document["type"] == "pdf"
    assert parsed.locators == ("page:1",)
    assert parsed.fallback_reason == "docling_parse_failed"
    assert parsed.artifact_bundle_id == "a" * 64


def test_docling_audit_denial_is_not_downgraded_to_pypdf(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "models"
    artifacts.mkdir()

    def denied(*args: object, **kwargs: object) -> object:
        del args, kwargs
        raise PermissionError("worker operation denied by Python audit policy")

    monkeypatch.setattr("fetech.document_worker._parse_docling_pdf", denied)
    runtime = _placeholder_runtime(artifacts, tmp_path / "unused.pdf")
    with pytest.raises(PermissionError, match="audit policy"):
        _parse_preferred(
            "pdf",
            _pdf_bytes(),
            target="file.pdf",
            limits=DocumentLimits(),
            docling=runtime,
            artifact_bundle_id="a" * 64,
        )


def test_docling_audit_initialization_window_is_sealed_before_conversion(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "models"
    artifacts.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir()
    input_path = scratch / "document.pdf"
    input_path.write_bytes(b"pdf")
    observed: list[str] = []

    class Guard:
        def seal_native_initialization(self) -> None:
            observed.append("seal")

        def cleanup_private_scratch(self) -> None:
            observed.append("cleanup")

    guard = Guard()

    def create_scratch(body: bytes) -> tuple[Path, Path]:
        assert body == b"pdf"
        observed.append("scratch")
        return scratch, input_path

    def offline(path: Path) -> None:
        assert path == artifacts
        observed.append("offline")

    def scratch_environment(path: Path) -> None:
        assert path == scratch
        observed.append("scratch_env")

    def audit(
        *,
        additional_read_roots: tuple[Path, ...] = (),
        allow_reviewed_native_initialization: bool = False,
        private_scratch_root: Path | None = None,
    ) -> Guard:
        assert additional_read_roots == (artifacts, scratch)
        assert allow_reviewed_native_initialization
        assert private_scratch_root == scratch
        observed.append("audit")
        return guard

    def prepare(capability: str, *, prefer_docling: bool = False) -> bool:
        assert capability == "pdf"
        assert prefer_docling
        observed.append("import")
        return True

    def build(
        config: _DoclingConfig,
        *,
        input_path: Path,
        audit_guard: object,
    ) -> object:
        assert config.artifacts_path == artifacts
        assert input_path == scratch / "document.pdf"
        assert audit_guard is guard
        observed.append("pipeline")
        return object()

    monkeypatch.setattr(
        "fetech.document_worker._create_docling_scratch",
        create_scratch,
    )
    monkeypatch.setattr("fetech.document_worker._configure_docling_offline", offline)
    monkeypatch.setattr(
        "fetech.document_worker._configure_docling_scratch_environment",
        scratch_environment,
    )
    monkeypatch.setattr(
        "fetech.document_worker._prewarm_trusted_stdlib_probes",
        lambda: observed.append("prewarm"),
    )
    monkeypatch.setattr(
        "fetech.document_worker._trusted_utc_zoneinfo_path",
        lambda: None,
    )
    monkeypatch.setattr(
        "fetech.document_worker.restrict_worker_import_path",
        lambda **kwargs: observed.append("restrict"),
    )
    monkeypatch.setattr("fetech.document_worker.install_worker_audit_hook", audit)
    monkeypatch.setattr("fetech.document_worker._prepare_parser_runtime", prepare)
    monkeypatch.setattr("fetech.document_worker._build_docling_runtime", build)

    active, fallback = _initialize_parser_runtime(
        "pdf",
        _unit_docling_config(artifacts),
        body=b"pdf",
    )

    assert active is not None
    assert fallback is None
    assert observed == [
        "scratch",
        "offline",
        "scratch_env",
        "prewarm",
        "restrict",
        "audit",
        "import",
        "pipeline",
        "seal",
    ]


@pytest.mark.parametrize("failure_stage", ("prewarm", "audit"))
def test_docling_policy_setup_failure_cleans_scratch_and_fails_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_stage: str,
) -> None:
    artifacts = tmp_path / "models"
    artifacts.mkdir()
    scratch = tmp_path / "scratch"
    scratch.mkdir(mode=0o700)
    input_path = scratch / "document.pdf"
    input_path.write_bytes(b"pdf")

    monkeypatch.setattr(
        "fetech.document_worker._create_docling_scratch",
        lambda body: (scratch, input_path),
    )
    monkeypatch.setattr(
        "fetech.document_worker._configure_docling_offline",
        lambda path: None,
    )
    monkeypatch.setattr(
        "fetech.document_worker._configure_docling_scratch_environment",
        lambda path: None,
    )
    monkeypatch.setattr(
        "fetech.document_worker._trusted_utc_zoneinfo_path",
        lambda: None,
    )
    monkeypatch.setattr(
        "fetech.document_worker.restrict_worker_import_path",
        lambda **kwargs: None,
    )
    if failure_stage == "prewarm":
        monkeypatch.setattr(
            "fetech.document_worker._prewarm_trusted_stdlib_probes",
            lambda: (_ for _ in ()).throw(RuntimeError("prewarm failed")),
        )
    else:
        monkeypatch.setattr(
            "fetech.document_worker._prewarm_trusted_stdlib_probes",
            lambda: None,
        )
        monkeypatch.setattr(
            "fetech.document_worker.install_worker_audit_hook",
            lambda **kwargs: (_ for _ in ()).throw(
                RuntimeError("audit installation failed")
            ),
        )

    with pytest.raises(RuntimeError, match="failed"):
        _initialize_parser_runtime(
            "pdf",
            _unit_docling_config(artifacts),
            body=b"pdf",
        )

    assert not scratch.exists()


@pytest.mark.parametrize("failure", [ImportError, RuntimeError])
def test_docling_initialization_failure_falls_back_but_missing_artifacts_fail(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure: type[Exception],
) -> None:
    def missing() -> None:
        raise failure("docling cannot initialize")

    monkeypatch.setattr("fetech.document_worker._import_docling_runtime", missing)
    assert not _prepare_parser_runtime("pdf", prefer_docling=True)
    with pytest.raises(ValueError, match="unavailable"):
        _parse_docling_config(
            {
                "artifact_bundle_id": "0" * 64,
                "artifacts_path": str(tmp_path / "missing"),
                "document_timeout_seconds": 1,
            }
        )


def test_worker_rejects_a_symlinked_docling_artifacts_path(tmp_path: Path) -> None:
    artifacts, artifact_sha256 = _manifested_artifacts(tmp_path / "models")
    linked = tmp_path / "linked-models"
    linked.symlink_to(artifacts, target_is_directory=True)

    with pytest.raises(ValueError, match="artifacts path"):
        _parse_docling_config(
            {
                "artifact_bundle_id": artifact_sha256,
                "artifacts_path": str(linked.absolute()),
                "document_timeout_seconds": 1,
            }
        )


def test_docling_offline_environment_is_explicit_and_narrow(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts = tmp_path / "models"
    artifacts.mkdir()
    names = (
        "DOCLING_ARTIFACTS_PATH",
        "DOCLING_DEVICE",
        "DOCLING_NUM_THREADS",
        "HF_DATASETS_OFFLINE",
        "HF_HUB_OFFLINE",
        "OMP_NUM_THREADS",
        "TRANSFORMERS_OFFLINE",
    )
    for name in names:
        monkeypatch.delenv(name, raising=False)

    _configure_docling_offline(artifacts)

    assert {name: os.environ[name] for name in names} == {
        "DOCLING_ARTIFACTS_PATH": str(artifacts),
        "DOCLING_DEVICE": "cpu",
        "DOCLING_NUM_THREADS": "1",
        "HF_DATASETS_OFFLINE": "1",
        "HF_HUB_OFFLINE": "1",
        "OMP_NUM_THREADS": "1",
        "TRANSFORMERS_OFFLINE": "1",
    }


def test_environment_configures_the_gateway_docling_worker(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts, artifact_sha256 = _manifested_artifacts(tmp_path / "models")
    data_dir = tmp_path / "data"
    monkeypatch.setenv("FETECH_DATA_DIR", str(data_dir))
    monkeypatch.setenv("FETECH_DOCLING_ARTIFACTS_PATH", str(artifacts))
    monkeypatch.setenv(
        "FETECH_DOCLING_ARTIFACTS_SHA256",
        artifact_sha256,
    )
    monkeypatch.setenv("FETECH_DOCLING_WORKER_MEMORY_MB", "6144")

    settings = Settings.from_environment()
    gateway = UniversalFetchGateway(settings)
    adapter = gateway.adapters["documents"]

    assert settings.docling_artifacts_path == artifacts
    assert settings.docling_artifacts_sha256 == artifact_sha256
    assert isinstance(adapter, DocumentAdapter)
    assert isinstance(adapter.parser, DocumentParseWorker)
    assert adapter.parser.docling_artifacts_path == artifacts.resolve()
    assert adapter.parser.memory_mb == 512
    assert adapter.parser.docling_memory_mb == 6_144


@pytest.mark.parametrize("memory_mb", (0, 1_023, 8_193))
def test_docling_worker_memory_ceiling_is_explicit_and_bounded(
    memory_mb: int,
) -> None:
    with pytest.raises(ValueError, match="Docling worker memory"):
        DocumentParseWorker(docling_memory_mb=memory_mb)


@pytest.mark.parametrize(
    ("configured", "expected"),
    (("64", 1_024), ("99999", 8_192)),
)
def test_docling_worker_memory_environment_is_clamped(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    configured: str,
    expected: int,
) -> None:
    monkeypatch.setenv("FETECH_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("FETECH_DOCLING_WORKER_MEMORY_MB", configured)

    assert Settings.from_environment().docling_worker_memory_mb == expected


@pytest.mark.asyncio
async def test_parent_threads_only_explicit_docling_config_and_revalidates_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    async def worker(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
        maximum_file_bytes: int,
        isolation: object,
    ) -> ProcessResult:
        captured.update(
            {
                "arguments": arguments,
                "payload": json.loads(stdin),
                "timeout_seconds": timeout_seconds,
                "memory_mb": memory_mb,
                "maximum_output_bytes": maximum_output_bytes,
                "maximum_file_bytes": maximum_file_bytes,
                "isolation": isolation,
            }
        )
        return ProcessResult(
            returncode=0,
            stdout=json.dumps(
                {
                    "document": {
                        "type": "pdf",
                        "blocks": [
                            {
                                "locator": "page:1",
                                "text": "Bounded Docling page text",
                            }
                        ],
                    },
                    "locators": ["page:1"],
                    "parser": "docling",
                    "observed_capability": "pdf",
                    **_docling_worker_provenance(artifacts),
                }
            ).encode(),
            stderr=b"",
        )

    artifacts, artifact_sha256 = _manifested_artifacts(tmp_path / "models")
    monkeypatch.setattr("fetech.adapters.documents.run_bounded", worker)

    result = await DocumentParseWorker(
        docling_artifacts_path=artifacts,
        docling_artifacts_sha256=artifact_sha256,
    ).parse(
        "pdf",
        _pdf_bytes(),
        target="https://user:password@example.com/private/report.pdf?token=secret",
        limits=DocumentLimits(maximum_blocks=2),
        timeout_seconds=2,
    )

    assert result.parser == "docling"
    payload = captured["payload"]
    assert isinstance(payload, dict)
    assert payload["target_path"] == "file.pdf"
    assert payload["docling"] == {
        "artifact_bundle_id": _docling_artifact_bundle_identity(artifacts),
        "artifacts_path": str(artifacts.resolve()),
        "document_timeout_seconds": 2,
    }
    assert captured["memory_mb"] == 4_096
    assert captured["maximum_file_bytes"] == 50_065_536
    encoded = json.dumps(payload)
    assert "password" not in encoded
    assert "token" not in encoded
    assert "secret" not in encoded


@pytest.mark.asyncio
async def test_parent_rejects_forged_unconfigured_docling_provenance(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def worker(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        return ProcessResult(
            returncode=0,
            stdout=json.dumps(
                {
                    "artifact_bundle_id": "f" * 64,
                    "document": {
                        "type": "pdf",
                        "blocks": [{"locator": "page:1", "text": "forged"}],
                    },
                    "fallback_reason": None,
                    "locators": ["page:1"],
                    "observed_capability": "pdf",
                    "parser": "docling",
                    "parser_components": _docling_components(),
                }
            ).encode(),
            stderr=b"",
        )

    monkeypatch.setattr("fetech.adapters.documents.run_bounded", worker)

    with pytest.raises(AdapterExecutionError, match="parser identity"):
        await DocumentParseWorker().parse(
            "pdf",
            _pdf_bytes(),
            target="file.pdf",
            limits=DocumentLimits(maximum_blocks=2),
            timeout_seconds=1,
        )


@pytest.mark.asyncio
async def test_parent_rejects_wrong_configured_docling_bundle_identity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    artifacts, artifact_sha256 = _manifested_artifacts(tmp_path / "models")

    async def worker(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        return ProcessResult(
            returncode=0,
            stdout=json.dumps(
                {
                    "artifact_bundle_id": "f" * 64,
                    "document": {
                        "type": "pdf",
                        "blocks": [{"locator": "page:1", "text": "forged"}],
                    },
                    "fallback_reason": None,
                    "locators": ["page:1"],
                    "observed_capability": "pdf",
                    "parser": "docling",
                    "parser_components": _docling_components(),
                }
            ).encode(),
            stderr=b"",
        )

    monkeypatch.setattr("fetech.adapters.documents.run_bounded", worker)

    with pytest.raises(AdapterExecutionError, match="Docling provenance"):
        await DocumentParseWorker(
            docling_artifacts_path=artifacts,
            docling_artifacts_sha256=artifact_sha256,
        ).parse(
            "pdf",
            _pdf_bytes(),
            target="file.pdf",
            limits=DocumentLimits(maximum_blocks=2),
            timeout_seconds=1,
        )


def test_parent_requires_observable_configured_docling_or_fallback() -> None:
    response = {
        "artifact_bundle_id": None,
        "document": {
            "type": "pdf",
            "blocks": [{"locator": "page:1", "text": "suppressed"}],
        },
        "fallback_reason": None,
        "locators": ["page:1"],
        "observed_capability": "pdf",
        "parser": "pypdf",
        "parser_components": {},
    }

    with pytest.raises(AdapterExecutionError, match="omitted configured Docling"):
        _validate_worker_result(
            response,
            limits=DocumentLimits(maximum_blocks=2),
            expected_observed="pdf",
            expected_docling_bundle_id="a" * 64,
        )


def test_parent_requires_exact_locked_docling_component_versions() -> None:
    components = _docling_components()
    components["docling-core"] = "999.0"
    response = {
        "artifact_bundle_id": "a" * 64,
        "document": {
            "type": "pdf",
            "blocks": [{"locator": "page:1", "text": "forged"}],
        },
        "fallback_reason": None,
        "locators": ["page:1"],
        "observed_capability": "pdf",
        "parser": "docling",
        "parser_components": components,
    }

    with pytest.raises(AdapterExecutionError, match="Docling provenance"):
        _validate_worker_result(
            response,
            limits=DocumentLimits(maximum_blocks=2),
            expected_observed="pdf",
            expected_docling_bundle_id="a" * 64,
        )


@pytest.mark.parametrize("locator", ("page:0", "page:3", "page:1/forged"))
@pytest.mark.asyncio
async def test_parent_rejects_untrusted_docling_page_locators(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    locator: str,
) -> None:
    async def worker(*args: object, **kwargs: object) -> ProcessResult:
        del args, kwargs
        return ProcessResult(
            returncode=0,
            stdout=json.dumps(
                {
                    "document": {
                        "type": "pdf",
                        "blocks": [{"locator": locator, "text": "forged"}],
                    },
                    "locators": [locator],
                    "parser": "docling",
                    "observed_capability": "pdf",
                    **_docling_worker_provenance(artifacts),
                }
            ).encode(),
            stderr=b"",
        )

    artifacts, artifact_sha256 = _manifested_artifacts(tmp_path / "models")
    monkeypatch.setattr("fetech.adapters.documents.run_bounded", worker)

    with pytest.raises(AdapterExecutionError, match="page locators"):
        await DocumentParseWorker(
            docling_artifacts_path=artifacts,
            docling_artifacts_sha256=artifact_sha256,
        ).parse(
            "pdf",
            _pdf_bytes(),
            target="file.pdf",
            limits=DocumentLimits(maximum_blocks=2),
            timeout_seconds=1,
        )


def test_docling_artifacts_path_must_be_explicit_existing_and_non_root(
    tmp_path: Path,
) -> None:
    with pytest.raises(TypeError, match=r"pathlib\.Path"):
        DocumentParseWorker(docling_artifacts_path=str(tmp_path))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="existing directory"):
        DocumentParseWorker(docling_artifacts_path=tmp_path / "missing")
    model_file = tmp_path / "models.bin"
    model_file.write_bytes(b"model")
    with pytest.raises(ValueError, match="non-root directory"):
        DocumentParseWorker(docling_artifacts_path=model_file)
    linked = tmp_path / "linked-models"
    linked.symlink_to(tmp_path, target_is_directory=True)
    with pytest.raises(ValueError, match="symbolic link"):
        DocumentParseWorker(docling_artifacts_path=linked)
    with pytest.raises(ValueError, match="non-root directory"):
        DocumentParseWorker(docling_artifacts_path=Path("/"))
    with pytest.raises(ValueError, match="configured together"):
        DocumentParseWorker(docling_artifacts_path=tmp_path)
    with pytest.raises(ValueError, match="configured together"):
        DocumentParseWorker(docling_artifacts_sha256="0" * 64)


def test_docling_artifact_configuration_requires_manifest_and_expected_digest(
    tmp_path: Path,
) -> None:
    unmanifested = tmp_path / "unmanifested"
    unmanifested.mkdir()
    (unmanifested / "weights.bin").write_bytes(b"unreviewed")
    with pytest.raises(ValueError, match="reviewed manifest"):
        DocumentParseWorker(
            docling_artifacts_path=unmanifested,
            docling_artifacts_sha256="0" * 64,
        )

    artifacts, artifact_sha256 = _manifested_artifacts(tmp_path / "models")
    with pytest.raises(ValueError, match="expected SHA-256"):
        DocumentParseWorker(
            docling_artifacts_path=artifacts,
            docling_artifacts_sha256="0" * 64,
        )
    worker = DocumentParseWorker(
        docling_artifacts_path=artifacts,
        docling_artifacts_sha256=artifact_sha256,
    )
    assert worker.docling_artifact_bundle_id == artifact_sha256


def test_worker_rejects_replaced_docling_artifact_root(tmp_path: Path) -> None:
    artifacts, expected_bundle_id = _manifested_artifacts(tmp_path / "models")
    original = tmp_path / "original-models"
    artifacts.rename(original)
    artifacts.mkdir()
    (artifacts / "forged-model.bin").write_bytes(b"changed")

    with pytest.raises(PermissionError, match="identity changed"):
        _parse_docling_config(
            {
                "artifact_bundle_id": expected_bundle_id,
                "artifacts_path": str(artifacts),
                "document_timeout_seconds": 1,
            }
        )


@pytest.mark.asyncio
async def test_parent_rejects_replaced_docling_artifact_root(
    tmp_path: Path,
) -> None:
    artifacts, artifact_sha256 = _manifested_artifacts(tmp_path / "models")
    worker = DocumentParseWorker(
        docling_artifacts_path=artifacts,
        docling_artifacts_sha256=artifact_sha256,
    )
    original = tmp_path / "original-models"
    artifacts.rename(original)
    artifacts.mkdir()
    (artifacts / "forged-model.bin").write_bytes(b"changed")

    with pytest.raises(AdapterExecutionError, match="identity changed"):
        await worker.parse(
            "pdf",
            _pdf_bytes(),
            target="file.pdf",
            limits=DocumentLimits(),
            timeout_seconds=1,
        )


@pytest.mark.skipif(
    importlib.util.find_spec("docling") is None,
    reason="real Docling contract requires fetech[documents]",
)
def test_real_docling_2_113_contract_surface(tmp_path: Path) -> None:
    assert version("docling-slim") == "2.113.0"
    accelerator_module = __import__(
        "docling.datamodel.accelerator_options",
        fromlist=["AcceleratorDevice", "AcceleratorOptions"],
    )
    base_models_module = __import__(
        "docling.datamodel.base_models",
        fromlist=["ConversionStatus", "DocumentStream", "InputFormat"],
    )
    pipeline_options_module = __import__(
        "docling.datamodel.pipeline_options",
        fromlist=["PdfPipelineOptions"],
    )
    converter_module = __import__(
        "docling.document_converter",
        fromlist=["DocumentConverter", "PdfFormatOption"],
    )
    options = pipeline_options_module.PdfPipelineOptions(
        accelerator_options=accelerator_module.AcceleratorOptions(
            num_threads=1,
            device=accelerator_module.AcceleratorDevice.CPU,
        ),
        allow_external_plugins=False,
        artifacts_path=tmp_path,
        document_timeout=1,
        do_chart_extraction=False,
        do_code_enrichment=False,
        do_formula_enrichment=False,
        do_ocr=False,
        do_picture_classification=False,
        do_picture_description=False,
        do_table_structure=False,
        enable_remote_services=False,
        generate_page_images=False,
        generate_picture_images=False,
    )
    converter_module.DocumentConverter(
        allowed_formats=[base_models_module.InputFormat.PDF],
        format_options={
            base_models_module.InputFormat.PDF: converter_module.PdfFormatOption(
                pipeline_options=options
            )
        },
    )
    base_models_module.DocumentStream(
        name="fixture.pdf",
        stream=io.BytesIO(b"%PDF-1.7"),
    )
    convert_signature = inspect.signature(
        converter_module.DocumentConverter.convert
    )
    assert {
        "raises_on_error",
        "max_num_pages",
        "max_file_size",
    }.issubset(convert_signature.parameters)
    assert base_models_module.ConversionStatus.SUCCESS.value == "success"
    result_type = convert_signature.return_annotation
    if isinstance(result_type, str):
        result_type = getattr(converter_module, result_type)
    assert {
        "document",
        "errors",
        "input",
        "status",
        "version",
    }.issubset(result_type.model_fields)
