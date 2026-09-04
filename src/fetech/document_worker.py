"""Ephemeral stdin/stdout worker for hostile document bytes.

The worker receives no destination host, credentials, or network instruction.
It may receive one validated, path-bound, read-only Docling artifact root. Its
parent applies process limits and independently validates this process's JSON
result before storing an artifact.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import json
import mimetypes
import os
import platform
import sys
import tempfile
from contextlib import suppress
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, NoReturn, Protocol

from fetech.adapters.documents import (
    _DOCLING_SLIM_VERSION,
    DOCUMENT_CAPABILITIES,
    DocumentLimits,
    _detect_capability,
    _docling_artifact_bundle_identity,
    _parse,
)
from fetech.docling_artifacts import DoclingArtifactBundleError
from fetech.worker_audit import (
    WorkerAuditGuard,
    install_worker_audit_hook,
    restrict_worker_import_path,
)

MAX_DOCUMENT_WORKER_STDIN_BYTES = 70_000_000
_LIMIT_FIELDS = frozenset(
    {
        "maximum_input_bytes",
        "maximum_output_bytes",
        "maximum_blocks",
        "maximum_depth",
        "maximum_archive_members",
        "maximum_archive_ratio",
    }
)
_MAX_DOCLING_ARTIFACTS_PATH_BYTES = 8_192


@dataclass(frozen=True, slots=True)
class _DoclingConfig:
    artifacts_path: Path
    artifact_bundle_id: str
    document_timeout_seconds: float


class _DoclingConverter(Protocol):
    def convert(self, source: Path, **kwargs: object) -> Any: ...


@dataclass(frozen=True, slots=True)
class _DoclingRuntime:
    config: _DoclingConfig
    converter: _DoclingConverter
    input_format: object
    input_path: Path
    audit_guard: WorkerAuditGuard | None = None


@dataclass(frozen=True, slots=True)
class _WorkerParseResult:
    document: dict[str, object]
    locators: tuple[str, ...]
    parser: str
    parser_components: tuple[tuple[str, str], ...] = ()
    artifact_bundle_id: str | None = None
    fallback_reason: str | None = None


class _DoclingContractError(ValueError):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


def main() -> int:
    docling_runtime: _DoclingRuntime | None = None
    try:
        payload = _read_payload()
        capability, target_path, body, limits, docling = _validate_payload(payload)
        observed = _detect_capability(capability, target_path, body)
        requested_artifact_bundle_id = (
            docling.artifact_bundle_id if docling is not None else None
        )
        docling_runtime, initialization_fallback = _initialize_parser_runtime(
            observed,
            docling,
            body=body,
        )
        parsed = _parse_preferred(
            observed,
            body,
            target=target_path,
            limits=limits,
            docling=docling_runtime,
            fallback_reason=initialization_fallback,
            artifact_bundle_id=requested_artifact_bundle_id,
        )
        if docling_runtime is not None:
            _cleanup_docling_runtime(docling_runtime)
            docling_runtime = None
        response = {
            "artifact_bundle_id": parsed.artifact_bundle_id,
            "document": parsed.document,
            "fallback_reason": parsed.fallback_reason,
            "locators": list(parsed.locators),
            "parser": parsed.parser,
            "parser_components": dict(parsed.parser_components),
            "observed_capability": observed,
        }
        sys.stdout.write(
            json.dumps(
                response,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            )
        )
        return 0
    except ImportError as exc:
        if docling_runtime is not None:
            _cleanup_docling_runtime(docling_runtime)
        _write_error(
            "dependency_missing",
            dependency=(
                exc.name
                if isinstance(exc.name, str) and exc.name.isidentifier()
                else "unknown"
            ),
        )
        return 2
    except Exception:
        if docling_runtime is not None:
            with suppress(Exception):
                _cleanup_docling_runtime(docling_runtime)
        _write_error("parse_failed")
        return 1


def _read_payload() -> object:
    encoded = sys.stdin.buffer.read(MAX_DOCUMENT_WORKER_STDIN_BYTES + 1)
    if len(encoded) > MAX_DOCUMENT_WORKER_STDIN_BYTES:
        _fail("worker input exceeded its hard byte limit")
    try:
        return json.loads(encoded, parse_constant=_reject_constant)
    except (json.JSONDecodeError, ValueError) as exc:
        raise ValueError("worker input is not strict JSON") from exc


def _validate_payload(
    payload: object,
) -> tuple[str, str, bytes, DocumentLimits, _DoclingConfig | None]:
    if not isinstance(payload, dict):
        raise ValueError("worker payload must be an object")
    if set(payload) != {
        "body",
        "capability",
        "docling",
        "limits",
        "target_path",
    }:
        raise ValueError("worker payload schema is invalid")
    capability = payload["capability"]
    target_path = payload["target_path"]
    encoded_body = payload["body"]
    raw_limits = payload["limits"]
    if not isinstance(capability, str) or capability not in DOCUMENT_CAPABILITIES:
        raise ValueError("worker capability is not registered")
    if (
        not isinstance(target_path, str)
        or len(target_path.encode("utf-8")) > 8_192
        or "\x00" in target_path
    ):
        raise ValueError("worker target path is invalid")
    if not isinstance(encoded_body, str):
        raise ValueError("worker body must be base64 text")
    try:
        body = base64.b64decode(encoded_body, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("worker body is not valid base64") from exc
    limits = _parse_limits(raw_limits)
    if len(body) > limits.maximum_input_bytes:
        raise ValueError("worker body exceeds its input limit")
    docling = _parse_docling_config(payload["docling"])
    return capability, target_path, body, limits, docling


def _parse_limits(value: object) -> DocumentLimits:
    if not isinstance(value, dict) or set(value) != _LIMIT_FIELDS:
        raise ValueError("worker limits schema is invalid")
    integer_fields = _LIMIT_FIELDS - {"maximum_archive_ratio"}
    if not all(
        isinstance(value[field], int)
        and not isinstance(value[field], bool)
        and value[field] > 0
        for field in integer_fields
    ):
        raise ValueError("worker integer limits must be positive")
    ratio = value["maximum_archive_ratio"]
    if (
        not isinstance(ratio, (int, float))
        or isinstance(ratio, bool)
        or ratio <= 0
    ):
        raise ValueError("worker archive ratio must be positive")
    return DocumentLimits(
        maximum_input_bytes=value["maximum_input_bytes"],
        maximum_output_bytes=value["maximum_output_bytes"],
        maximum_blocks=value["maximum_blocks"],
        maximum_depth=value["maximum_depth"],
        maximum_archive_members=value["maximum_archive_members"],
        maximum_archive_ratio=float(ratio),
    )


def _parse_docling_config(value: object) -> _DoclingConfig | None:
    if value is None:
        return None
    if not isinstance(value, dict) or set(value) != {
        "artifact_bundle_id",
        "artifacts_path",
        "document_timeout_seconds",
    }:
        raise ValueError("Docling worker configuration is invalid")
    artifact_bundle_id = value["artifact_bundle_id"]
    raw_path = value["artifacts_path"]
    timeout = value["document_timeout_seconds"]
    if (
        not isinstance(artifact_bundle_id, str)
        or len(artifact_bundle_id) != 64
        or any(character not in "0123456789abcdef" for character in artifact_bundle_id)
        or not isinstance(raw_path, str)
        or not raw_path
        or "\x00" in raw_path
        or len(raw_path.encode("utf-8")) > _MAX_DOCLING_ARTIFACTS_PATH_BYTES
        or not Path(raw_path).is_absolute()
        or not isinstance(timeout, int | float)
        or isinstance(timeout, bool)
        or not 0 < float(timeout) <= 3_600
    ):
        raise ValueError("Docling worker configuration is invalid")
    try:
        supplied_path = Path(raw_path)
        if supplied_path.is_symlink():
            raise ValueError("Docling worker artifacts path is invalid")
        artifacts_path = supplied_path.resolve(strict=True)
    except OSError as exc:
        raise ValueError("Docling worker artifacts path is unavailable") from exc
    if (
        not artifacts_path.is_dir()
        or artifacts_path == Path(artifacts_path.anchor)
    ):
        raise ValueError("Docling worker artifacts path is invalid")
    try:
        observed_bundle_id = _docling_artifact_bundle_identity(artifacts_path)
    except DoclingArtifactBundleError as exc:
        raise PermissionError(
            "Docling artifact bundle identity changed or became invalid"
        ) from exc
    if not hmac.compare_digest(observed_bundle_id, artifact_bundle_id):
        raise PermissionError("Docling artifact bundle identity changed")
    return _DoclingConfig(
        artifacts_path=artifacts_path,
        artifact_bundle_id=artifact_bundle_id,
        document_timeout_seconds=float(timeout),
    )


def _prepare_parser_runtime(
    capability: str,
    *,
    prefer_docling: bool = False,
) -> bool:
    """Load the parser after the caller has applied the required audit policy."""

    if capability in {"pdf", "scanned_pdf"}:
        from pypdf import PdfReader

        del PdfReader
        if prefer_docling:
            try:
                _import_docling_runtime()
            except PermissionError:
                raise
            except Exception:
                return False
            return True
    elif capability == "docx":
        from docx import Document

        del Document
    elif capability == "pptx":
        from pptx import Presentation

        del Presentation
    elif capability == "xlsx":
        from openpyxl import load_workbook

        del load_workbook
    elif capability == "zip_archive":
        # ZIP filenames without the UTF-8 flag use CP437.
        b"document-worker".decode("cp437")
    return False


def _initialize_parser_runtime(
    capability: str,
    docling: _DoclingConfig | None,
    *,
    body: bytes = b"",
) -> tuple[_DoclingRuntime | None, str | None]:
    """Initialize reviewed native code, then seal policy before conversion."""

    if docling is None:
        _prewarm_document_stdlib_probes()
        install_worker_audit_hook()
        _prepare_parser_runtime(capability)
        return None, None

    scratch_root, input_path = _create_docling_scratch(body)
    try:
        _configure_docling_offline(docling.artifacts_path)
        _configure_docling_scratch_environment(scratch_root)
        _prewarm_trusted_stdlib_probes()
        zoneinfo_path = _trusted_utc_zoneinfo_path()
        additional_read_roots = (
            docling.artifacts_path,
            scratch_root,
            *((zoneinfo_path,) if zoneinfo_path is not None else ()),
        )
        restrict_worker_import_path(
            additional_read_roots=additional_read_roots,
        )
        guard = install_worker_audit_hook(
            additional_read_roots=additional_read_roots,
            allow_reviewed_native_initialization=True,
            private_scratch_root=scratch_root,
        )
    except Exception:
        # Continuing after policy setup failed would execute the fallback
        # parser without the worker audit boundary.
        _remove_unhooked_scratch(scratch_root)
        raise
    try:
        if not _prepare_parser_runtime(capability, prefer_docling=True):
            guard.seal_native_initialization()
            guard.cleanup_private_scratch()
            return None, "docling_unavailable"
        runtime = _build_docling_runtime(
            docling,
            input_path=input_path,
            audit_guard=guard,
        )
    except PermissionError:
        guard.seal_native_initialization()
        guard.cleanup_private_scratch()
        raise
    except Exception:
        guard.seal_native_initialization()
        guard.cleanup_private_scratch()
        return None, "docling_unavailable"
    guard.seal_native_initialization()
    return runtime, None


def _import_docling_runtime() -> None:
    for module_name in (
        "docling.datamodel.accelerator_options",
        "docling.datamodel.base_models",
        "docling.datamodel.pipeline_options",
        "docling.document_converter",
    ):
        import_module(module_name)


def _build_docling_runtime(
    config: _DoclingConfig,
    *,
    input_path: Path,
    audit_guard: WorkerAuditGuard | None = None,
) -> _DoclingRuntime:
    accelerator_module = import_module(
        "docling.datamodel.accelerator_options"
    )
    base_models_module = import_module("docling.datamodel.base_models")
    pipeline_options_module = import_module(
        "docling.datamodel.pipeline_options"
    )
    converter_module = import_module("docling.document_converter")
    AcceleratorDevice = accelerator_module.AcceleratorDevice
    AcceleratorOptions = accelerator_module.AcceleratorOptions
    InputFormat = base_models_module.InputFormat
    PdfPipelineOptions = pipeline_options_module.PdfPipelineOptions
    DocumentConverter = converter_module.DocumentConverter
    PdfFormatOption = converter_module.PdfFormatOption

    options = PdfPipelineOptions(
        accelerator_options=AcceleratorOptions(
            num_threads=1,
            device=AcceleratorDevice.CPU,
        ),
        allow_external_plugins=False,
        artifacts_path=config.artifacts_path,
        document_timeout=config.document_timeout_seconds,
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
    converter = DocumentConverter(
        allowed_formats=[InputFormat.PDF],
        format_options={
            InputFormat.PDF: PdfFormatOption(pipeline_options=options),
        },
    )
    initialize_pipeline = getattr(converter, "initialize_pipeline", None)
    if not callable(initialize_pipeline):
        raise _DoclingContractError("docling_contract_invalid")
    initialize_pipeline(InputFormat.PDF)
    return _DoclingRuntime(
        config=config,
        converter=converter,
        input_format=InputFormat.PDF,
        input_path=input_path,
        audit_guard=audit_guard,
    )


def _configure_docling_offline(artifacts_path: Path) -> None:
    """Set only reviewed offline/runtime controls in the already-clean worker env."""

    values = {
        "DOCLING_ARTIFACTS_PATH": str(artifacts_path),
        "DOCLING_DEVICE": "cpu",
        "DOCLING_NUM_THREADS": "1",
        "HF_DATASETS_OFFLINE": "1",
        "HF_HUB_OFFLINE": "1",
        "OMP_NUM_THREADS": "1",
        "TRANSFORMERS_OFFLINE": "1",
    }
    os.environ.update(values)


def _create_docling_scratch(body: bytes) -> tuple[Path, Path]:
    root = Path(tempfile.mkdtemp(prefix="fetech-docling-")).resolve(strict=True)
    try:
        root.chmod(0o700)
        for name in ("cache", "config", "home", "torchinductor"):
            (root / name).mkdir(mode=0o700)
        input_path = root / "document.pdf"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(input_path, flags, 0o400)
        try:
            view = memoryview(body)
            while view:
                written = os.write(descriptor, view)
                if written <= 0:
                    raise OSError("failed to materialize bounded Docling input")
                view = view[written:]
        finally:
            os.close(descriptor)
        return root, input_path
    except Exception:
        _remove_unhooked_scratch(root)
        raise


def _configure_docling_scratch_environment(root: Path) -> None:
    values = {
        "HOME": str(root / "home"),
        "TMPDIR": str(root),
        "TORCHINDUCTOR_CACHE_DIR": str(root / "torchinductor"),
        "XDG_CACHE_HOME": str(root / "cache"),
        "XDG_CONFIG_HOME": str(root / "config"),
    }
    os.environ.update(values)
    tempfile.tempdir = str(root)


def _prewarm_trusted_stdlib_probes() -> None:
    # Docling transitively asks the standard library for these host facts at
    # import time. Resolve them before policy installation, while no fetched
    # bytes have been parsed and no optional package code has been imported.
    platform.platform()
    _prewarm_document_stdlib_probes()


def _prewarm_document_stdlib_probes() -> None:
    # openpyxl constructs a fresh MimeTypes database during import. Populate
    # the process-global database from the host's reviewed MIME files before
    # the audit hook closes filesystem reads outside package roots.
    mimetypes.init()


def _trusted_utc_zoneinfo_path() -> Path | None:
    candidate = Path("/usr/share/zoneinfo/UTC")
    try:
        resolved = candidate.resolve(strict=True)
    except OSError:
        return None
    return resolved if resolved.is_file() else None


def _remove_unhooked_scratch(root: Path) -> None:
    if not root.exists():
        return
    for child in sorted(root.rglob("*"), key=lambda path: len(path.parts), reverse=True):
        if child.is_dir() and not child.is_symlink():
            child.rmdir()
        else:
            child.unlink()
    root.rmdir()


def _cleanup_docling_runtime(runtime: _DoclingRuntime) -> None:
    if runtime.audit_guard is not None:
        runtime.audit_guard.cleanup_private_scratch()


def _parse_preferred(
    capability: str,
    body: bytes,
    *,
    target: str,
    limits: DocumentLimits,
    docling: _DoclingRuntime | None,
    fallback_reason: str | None = None,
    artifact_bundle_id: str | None = None,
) -> _WorkerParseResult:
    if capability in {"pdf", "scanned_pdf"} and docling is not None:
        try:
            return _parse_docling_pdf(
                target=target,
                limits=limits,
                runtime=docling,
            )
        except PermissionError:
            # Audit/policy denials are security failures, never parser fallbacks.
            raise
        except MemoryError:
            raise
        except _DoclingContractError as exc:
            fallback_reason = exc.code
        except TimeoutError:
            fallback_reason = "docling_timeout"
        except Exception:
            # Docling output and failures are untrusted. The reviewed pypdf
            # path remains deterministic and is independently validated by
            # the parent process.
            fallback_reason = "docling_parse_failed"
    document, locators, parser = _parse(
        capability,
        body,
        target=target,
        limits=limits,
    )
    return _WorkerParseResult(
        document=document,
        locators=locators,
        parser=parser,
        artifact_bundle_id=(
            artifact_bundle_id if fallback_reason is not None else None
        ),
        fallback_reason=fallback_reason,
    )


def _parse_docling_pdf(
    *,
    target: str,
    limits: DocumentLimits,
    runtime: _DoclingRuntime,
) -> _WorkerParseResult:
    del target
    base_models_module = import_module("docling.datamodel.base_models")
    ConversionStatus = base_models_module.ConversionStatus
    input_size = runtime.input_path.stat().st_size
    if input_size > limits.maximum_input_bytes:
        raise PermissionError("Docling scratch input exceeded its bound")
    converted = runtime.converter.convert(
        runtime.input_path,
        raises_on_error=True,
        max_num_pages=limits.maximum_blocks,
        max_file_size=limits.maximum_input_bytes,
    )
    status = getattr(converted, "status", None)
    timeout_check = getattr(converted, "has_timeout_errors", None)
    errors = getattr(converted, "errors", None)
    if not callable(timeout_check) or not isinstance(errors, list):
        raise _DoclingContractError("docling_contract_invalid")
    try:
        timed_out = timeout_check()
    except Exception as exc:
        raise _DoclingContractError("docling_contract_invalid") from exc
    if not isinstance(timed_out, bool):
        raise _DoclingContractError("docling_contract_invalid")
    if timed_out:
        raise _DoclingContractError("docling_timeout")
    if errors:
        raise _DoclingContractError("docling_conversion_error")
    if status != ConversionStatus.SUCCESS:
        raise _DoclingContractError("docling_non_success")

    input_document = getattr(converted, "input", None)
    page_count = getattr(input_document, "page_count", None)
    if (
        not isinstance(page_count, int)
        or isinstance(page_count, bool)
        or not 1 <= page_count <= limits.maximum_blocks
    ):
        raise _DoclingContractError("docling_incomplete_pages")
    parser_components = _docling_parser_components(converted)
    document = converted.document
    pages = document.pages
    if (
        not isinstance(pages, dict)
        or not pages
        or len(pages) > limits.maximum_blocks
        or any(
            not isinstance(page_number, int)
            or isinstance(page_number, bool)
            or not 1 <= page_number <= limits.maximum_blocks
            for page_number in pages
        )
    ):
        raise _DoclingContractError("docling_contract_invalid")
    if sorted(pages) != list(range(1, page_count + 1)):
        raise _DoclingContractError("docling_incomplete_pages")
    blocks: list[dict[str, object]] = []
    output_bytes = 0
    for page_number in sorted(pages):
        text = document.export_to_text(
            page_no=page_number,
            traverse_pictures=True,
        )
        if not isinstance(text, str):
            raise ValueError("Docling returned invalid page text")
        output_bytes += len(text.encode("utf-8"))
        if output_bytes > limits.maximum_output_bytes:
            raise ValueError("Docling output exceeds the decompressed-byte budget")
        blocks.append(
            {
                "locator": f"page:{page_number}",
                "text": text,
            }
        )
    locators = tuple(str(block["locator"]) for block in blocks)
    return _WorkerParseResult(
        document={"type": "pdf", "blocks": blocks},
        locators=locators,
        parser="docling",
        parser_components=parser_components,
        artifact_bundle_id=runtime.config.artifact_bundle_id,
    )


def _docling_parser_components(
    converted: object,
) -> tuple[tuple[str, str], ...]:
    version = getattr(converted, "version", None)
    fields = (
        ("docling", "docling_version"),
        ("docling-core", "docling_core_version"),
        ("docling-ibm-models", "docling_ibm_models_version"),
        ("docling-parse", "docling_parse_version"),
        ("docling-slim", "docling_slim_version"),
    )
    components: dict[str, str] = {}
    for name, attribute in fields:
        value = getattr(version, attribute, None)
        if value is None:
            continue
        if (
            not isinstance(value, str)
            or not value
            or len(value) > 64
            or any(
                not (
                    character.isascii()
                    and (character.isalnum() or character in ".+_-")
                )
                for character in value
            )
        ):
            raise _DoclingContractError("docling_contract_invalid")
        components[name] = value
    if components.get("docling-slim") != _DOCLING_SLIM_VERSION:
        raise _DoclingContractError("docling_version_mismatch")
    if not {"docling-core", "docling-parse", "docling-slim"}.issubset(
        components
    ):
        raise _DoclingContractError("docling_contract_invalid")
    return tuple(sorted(components.items()))


def _reject_constant(value: str) -> object:
    raise ValueError(f"non-finite JSON number is forbidden: {value}")


def _write_error(code: str, *, dependency: str | None = None) -> None:
    payload = {"error": code}
    if dependency is not None:
        payload["dependency"] = dependency
    sys.stdout.write(json.dumps(payload, separators=(",", ":")))


def _fail(message: str) -> NoReturn:
    raise ValueError(message)


if __name__ == "__main__":
    raise SystemExit(main())
