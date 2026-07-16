"""Deterministic target classification and budgeted plan construction."""

from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urlsplit

from fetech.models import FetchPlan, FetchRequest, PlanNode, RetryRule
from fetech.registry import CapabilityRegistry
from fetech.security import normalize_url

DOCUMENT_EXTENSIONS = {".csv", ".docx", ".epub", ".pdf", ".pptx", ".txt", ".xls", ".xlsx"}
MEDIA_EXTENSIONS = {".aac", ".flac", ".gif", ".jpeg", ".jpg", ".m4a", ".mp3", ".mp4", ".png", ".wav", ".webm"}
ARCHIVE_EXTENSIONS = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".zip"}
API_EXTENSIONS = {".json", ".xml"}
READER_CAPABILITIES = (
    "raw_html",
    "clean_text",
    "main_article",
    "boilerplate_removal",
    "mozilla_readability",
    "trafilatura",
    "newspaper_style",
    "mercury_style",
    "jina_reader",
    "browser_reader_mode",
)


def classify_target(target: str, outputs: tuple[str, ...]) -> str:
    path = PurePosixPath(urlsplit(target).path.lower())
    suffix = path.suffix
    requested = set(outputs)
    if suffix in DOCUMENT_EXTENSIONS or requested & {"document", "tables", "ocr", "slides"}:
        return "document"
    if suffix in MEDIA_EXTENSIONS or requested & {
        "audio",
        "frames",
        "image",
        "subtitles",
        "transcript",
        "video",
    }:
        return "media"
    if suffix in ARCHIVE_EXTENSIONS or "archive" in requested:
        return "archive"
    if suffix in API_EXTENSIONS or requested & {"json", "xml", "feed"}:
        return "api"
    return "web"


class DeterministicPlanner:
    def __init__(self, registry: CapabilityRegistry) -> None:
        self.registry = registry

    def plan(self, request: FetchRequest) -> FetchPlan:
        target = normalize_url(request.target)
        normalized_request = request.model_copy(update={"target": target})
        family = classify_target(target, request.output_requirements)
        http_capability = self._http_capability(request)
        nodes: list[PlanNode] = [
            PlanNode(id="normalize", capability_id="url_normalisation", adapter="core"),
            PlanNode(
                id="policy",
                capability_id="url_validation",
                adapter="core",
                dependencies=("normalize",),
                reserved_budget={"deadline_seconds": 2},
            ),
            PlanNode(
                id="http",
                capability_id=http_capability,
                adapter="http",
                dependencies=("policy",),
                retry=RetryRule(maximum=2),
                stop_on_acceptance=family in {"api", "document", "media", "archive"},
                requires_approval=http_capability == "http_post",
                reserved_budget={"bytes": request.budget.bytes},
            ),
        ]
        if family == "web" and http_capability != "http_head":
            reader_nodes = self._reader_nodes(request)
            nodes.extend(reader_nodes)
            if self.registry.get("playwright").available:
                terminal_reader = reader_nodes[-1].id
                nodes.append(
                    PlanNode(
                        id="playwright",
                        capability_id="playwright",
                        adapter="browser",
                        dependencies=(terminal_reader,),
                        fallback_for=terminal_reader,
                        stop_on_acceptance=True,
                        reserved_budget={"browser_seconds": request.budget.browser_seconds},
                    )
                )
        elif family == "document":
            capability = self._document_capability(target)
            nodes.append(
                PlanNode(
                    id="document",
                    capability_id=capability,
                    adapter="documents",
                    dependencies=("http",),
                    stop_on_acceptance=True,
                )
            )
        elif family == "media":
            suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
            capability = (
                "image_metadata"
                if suffix in {".gif", ".jpeg", ".jpg", ".png"}
                else "audio_metadata"
                if suffix in {".aac", ".flac", ".m4a", ".mp3", ".wav"}
                else "video_metadata"
            )
            nodes.append(
                PlanNode(
                    id="media",
                    capability_id=capability,
                    adapter="media",
                    dependencies=("http",),
                    stop_on_acceptance=True,
                )
            )
        elif family == "archive":
            nodes.append(
                PlanNode(
                    id="archive",
                    capability_id="zip_archive",
                    adapter="cache",
                    dependencies=("http",),
                    stop_on_acceptance=True,
                )
            )
        elif family == "api":
            suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
            capability = "xml_endpoint" if suffix == ".xml" else "json_endpoint"
            nodes.append(
                PlanNode(
                    id="structured",
                    capability_id=capability,
                    adapter="api",
                    dependencies=("http",),
                    stop_on_acceptance=True,
                )
            )
        filtered = tuple(node for node in nodes if self._permitted(node.capability_id, request))
        if not any(
            node.capability_id
            in {"http_get", "http_head", "http_post", "browser_header_http", "range_request"}
            for node in filtered
        ):
            raise ValueError("the request capability policy denies the required HTTP operation")
        self._validate_nodes(filtered)
        return FetchPlan(request=normalized_request, nodes=filtered)

    @staticmethod
    def _document_capability(target: str) -> str:
        suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
        return {
            ".csv": "csv",
            ".docx": "docx",
            ".epub": "dataset_file",
            ".pdf": "pdf",
            ".pptx": "pptx",
            ".txt": "txt",
            ".xls": "dataset_file",
            ".xlsx": "xlsx",
        }.get(suffix, "dataset_file")

    @staticmethod
    def _http_capability(request: FetchRequest) -> str:
        for capability_id in ("http_head", "http_post", "browser_header_http", "range_request"):
            if capability_id in request.output_requirements:
                return capability_id
        return "http_get"

    @staticmethod
    def _reader_nodes(request: FetchRequest) -> list[PlanNode]:
        requested = [
            capability_id
            for capability_id in READER_CAPABILITIES
            if capability_id in request.output_requirements
        ]
        selected = requested or ["clean_text", "main_article"]
        nodes: list[PlanNode] = []
        for index, capability_id in enumerate(selected):
            previous = nodes[-1].id if nodes else None
            nodes.append(
                PlanNode(
                    id=f"reader-{index}-{capability_id.replace('_', '-')}",
                    capability_id=capability_id,
                    adapter="reader",
                    dependencies=("http",),
                    parallel_group="static-readers",
                    fallback_for=previous,
                    stop_on_acceptance=True,
                )
            )
        return nodes

    def _permitted(self, capability_id: str, request: FetchRequest) -> bool:
        canonical = self.registry.resolve_id(capability_id)
        if canonical in request.deny_capabilities:
            return False
        if request.allow_capabilities and canonical not in request.allow_capabilities:
            return canonical in {
                "url_normalisation",
                "url_validation",
                "http_get",
                "http_head",
                "http_post",
                "browser_header_http",
                "range_request",
            }
        return True

    def _validate_nodes(self, nodes: tuple[PlanNode, ...]) -> None:
        node_ids = {node.id for node in nodes}
        for node in nodes:
            self.registry.get(node.capability_id)
            missing = set(node.dependencies) - node_ids
            if missing:
                raise ValueError(f"node {node.id} has missing dependencies: {sorted(missing)}")
