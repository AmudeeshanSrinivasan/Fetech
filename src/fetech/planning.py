"""Deterministic target classification and budgeted plan construction."""

from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urlsplit

from fetech.adapters.api import API_CAPABILITIES, detect_named_api
from fetech.models import FetchPlan, FetchRequest, PlanNode, RetryRule
from fetech.registry import CapabilityRegistry
from fetech.security import normalize_url, sanitize_url_for_request

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
BROWSER_CAPABILITIES = (
    "playwright",
    "puppeteer",
    "selenium",
    "cdp",
    "headless_dom",
    "visible_text",
    "screenshot",
    "wait_for_selector",
    "wait_for_network_idle",
    "scroll_to_load",
    "click_expand",
    "cookie_banner_handling",
    "lazy_loading",
    "javascript_rendering",
    "spa_route_handling",
)
BROWSER_ENGINES = ("playwright", "puppeteer", "selenium", "cdp")
API_CAPABILITY_ORDER = (
    "rest",
    "graphql",
    "json_endpoint",
    "xml_endpoint",
    "rss",
    "atom",
    "sitemap_xml",
    "openapi_discovery",
    "github_api",
    "semantic_scholar_api",
    "arxiv_api",
    "openreview_api",
    "crossref_openalex_api",
)
AUTH_SESSION_CAPABILITIES = (
    "login_session",
    "oauth",
    "sso",
    "private_workspace",
)


def classify_target(target: str, outputs: tuple[str, ...]) -> str:
    path = PurePosixPath(urlsplit(target).path.lower())
    suffix = path.suffix
    requested = set(outputs)
    if requested & API_CAPABILITIES or detect_named_api(target) is not None:
        return "api"
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
        execution_request = request.model_copy(update={"target": target})
        public_request = execution_request.model_copy(
            update={"target": sanitize_url_for_request(target, execution_request)}
        )
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
        ]
        requested_sessions = [
            capability_id
            for capability_id in AUTH_SESSION_CAPABILITIES
            if capability_id in request.output_requirements
        ]
        if len(requested_sessions) > 1:
            raise ValueError("only one high-level authentication session may be requested")
        http_dependency = "policy"
        if requested_sessions:
            session_capability = requested_sessions[0]
            nodes.append(
                PlanNode(
                    id=f"auth-{session_capability.replace('_', '-')}",
                    capability_id=session_capability,
                    adapter="auth",
                    dependencies=("policy",),
                    retry=RetryRule(maximum=0),
                )
            )
            http_dependency = nodes[-1].id
        nodes.append(
            PlanNode(
                id="http",
                capability_id=http_capability,
                adapter="http",
                dependencies=(http_dependency,),
                retry=RetryRule(maximum=0 if http_capability == "http_post" else 2),
                stop_on_acceptance=family in {"api", "document", "media", "archive"},
                requires_approval=http_capability == "http_post",
                reserved_budget={"bytes": request.budget.bytes},
            )
        )
        acquired_dependency = "http"
        if "csrf_token" in request.output_requirements:
            nodes.append(
                PlanNode(
                    id="auth-csrf-token",
                    capability_id="csrf_token",
                    adapter="auth",
                    dependencies=(acquired_dependency,),
                    retry=RetryRule(maximum=0),
                )
            )
            acquired_dependency = nodes[-1].id
        if "form_submit" in request.output_requirements:
            nodes.append(
                PlanNode(
                    id="auth-form-submit",
                    capability_id="form_submit",
                    adapter="auth",
                    dependencies=(acquired_dependency,),
                    retry=RetryRule(maximum=0),
                    requires_approval=True,
                )
            )
            acquired_dependency = nodes[-1].id
        if request.intent == "crawl":
            nodes.append(
                PlanNode(
                    id="crawl",
                    capability_id="depth_limited_crawl",
                    adapter="discovery",
                    dependencies=(acquired_dependency,),
                    stop_on_acceptance=True,
                    reserved_budget={
                        "attempts": request.budget.attempts,
                        "crawl_pages": request.budget.crawl_pages,
                        "crawl_depth": request.budget.crawl_depth,
                    },
                )
            )
        elif family == "web" and http_capability != "http_head":
            reader_dependency = acquired_dependency
            if request.authentication_ref is None:
                nodes.append(
                    PlanNode(
                        id="alternatives",
                        capability_id="candidate_url_expansion",
                        adapter="variants",
                        dependencies=(acquired_dependency,),
                    )
                )
                reader_dependency = "alternatives"
            reader_nodes = self._reader_nodes(request, dependency=reader_dependency)
            nodes.extend(reader_nodes)
            if self.registry.get("playwright").available:
                terminal_reader = reader_nodes[-1].id
                requested_browser = set(request.output_requirements) & set(BROWSER_CAPABILITIES)
                browser_engine = next(
                    (
                        capability_id
                        for capability_id in BROWSER_ENGINES
                        if capability_id in requested_browser
                    ),
                    "playwright",
                )
                nodes.append(
                    PlanNode(
                        id="browser",
                        capability_id=browser_engine,
                        adapter="browser",
                        dependencies=(terminal_reader,),
                        fallback_for=None if requested_browser else terminal_reader,
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
                    dependencies=(acquired_dependency,),
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
                    dependencies=(acquired_dependency,),
                    stop_on_acceptance=True,
                )
            )
        elif family == "archive":
            nodes.append(
                PlanNode(
                    id="archive",
                    capability_id="zip_archive",
                    adapter="cache",
                    dependencies=(acquired_dependency,),
                    stop_on_acceptance=True,
                )
            )
        elif family == "api":
            capability = self._api_capability(target, request)
            nodes.append(
                PlanNode(
                    id="structured",
                    capability_id=capability,
                    adapter="api",
                    dependencies=(acquired_dependency,),
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
        return FetchPlan(request=public_request, nodes=filtered).bind_execution_request(
            execution_request
        )

    @staticmethod
    def _api_capability(target: str, request: FetchRequest) -> str:
        requested = [
            capability_id
            for capability_id in API_CAPABILITY_ORDER
            if capability_id in request.output_requirements
        ]
        if len(requested) > 1:
            raise ValueError("only one primary structured API capability may be requested")
        if requested:
            return requested[0]
        named = detect_named_api(target)
        if named is not None:
            return named
        suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
        return "xml_endpoint" if suffix == ".xml" else "json_endpoint"

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
    def _reader_nodes(request: FetchRequest, *, dependency: str) -> list[PlanNode]:
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
                    dependencies=(dependency,),
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
