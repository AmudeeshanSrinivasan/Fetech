"""Deterministic target classification and budgeted plan construction."""

from __future__ import annotations

from pathlib import PurePosixPath
from urllib.parse import urlsplit

from fetech.adapters.api import API_CAPABILITIES, detect_named_api
from fetech.models import (
    CapabilityKind,
    FetchPlan,
    FetchRequest,
    PlanNode,
    RetryRule,
)
from fetech.registry import CapabilityRegistry
from fetech.security import normalize_url, sanitize_url_for_request

DOCUMENT_EXTENSIONS = {
    ".csv",
    ".docx",
    ".epub",
    ".md",
    ".markdown",
    ".pdf",
    ".pptx",
    ".txt",
    ".xls",
    ".xlsx",
}
MEDIA_EXTENSIONS = {
    ".aac",
    ".flac",
    ".gif",
    ".jpeg",
    ".jpg",
    ".m4a",
    ".mp3",
    ".mp4",
    ".png",
    ".tif",
    ".tiff",
    ".wav",
    ".webm",
    ".webp",
}
ARCHIVE_EXTENSIONS = {".7z", ".bz2", ".gz", ".rar", ".tar", ".tgz", ".zip"}
API_EXTENSIONS = {".json", ".xml"}
DOCUMENT_CAPABILITIES = (
    "pdf",
    "scanned_pdf",
    "docx",
    "pptx",
    "xlsx",
    "csv",
    "txt",
    "markdown",
    "json_file",
    "xml_file",
    "zip_archive",
    "github_raw",
    "git_lfs",
    "dataset_file",
)
MEDIA_CAPABILITIES = (
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
)
CACHE_CAPABILITIES = (
    "search_snippet_cache",
    "search_cache",
    "search_engine_cache_adapter",
    "alternate_search_cache_adapter",
    "web_archive",
    "internet_archive_snapshot",
    "local_snapshot",
    "previous_successful_snapshot",
    "cdn_copy",
    "browser_cache",
    "rag_document_cache",
)
PRE_ACQUISITION_CACHE_CAPABILITIES = (
    "previous_successful_snapshot",
    "search_engine_cache_adapter",
    "alternate_search_cache_adapter",
    "web_archive",
    "internet_archive_snapshot",
    "cdn_copy",
)
POST_ACQUISITION_CACHE_CAPABILITIES = (
    "search_snippet_cache",
    "search_cache",
    "local_snapshot",
    "browser_cache",
    "rag_document_cache",
)
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
_SCHEDULABLE_KINDS = frozenset(
    {
        CapabilityKind.OPERATION,
        CapabilityKind.VARIANT_GENERATOR,
        CapabilityKind.EXTRACTOR,
        CapabilityKind.FORMAT_HANDLER,
        CapabilityKind.CONNECTOR,
        CapabilityKind.STORAGE_STRATEGY,
    }
)
_HTTP_EMBEDDED_AUTH_CAPABILITIES = frozenset(
    {
        "api_key",
        "bearer_token",
        "connector_auth",
        "cookie_session",
    }
)
_BROWSER_EMBEDDED_CAPABILITIES = (
    frozenset(BROWSER_CAPABILITIES) - frozenset(BROWSER_ENGINES)
)


def classify_target(target: str, outputs: tuple[str, ...]) -> str:
    path = PurePosixPath(urlsplit(target).path.lower())
    suffix = path.suffix
    requested = set(outputs)
    if requested & set(CACHE_CAPABILITIES) and not requested - set(CACHE_CAPABILITIES):
        return "cache"
    if requested & set(DOCUMENT_CAPABILITIES):
        return "archive" if "zip_archive" in requested else "document"
    if requested & set(MEDIA_CAPABILITIES):
        return "media"
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
        canonical_outputs = tuple(
            dict.fromkeys(
                self._canonical_output_requirement(capability_id)
                for capability_id in request.output_requirements
            )
        )
        request = request.model_copy(
            update={
                "target": target,
                "output_requirements": canonical_outputs,
            }
        )
        execution_request = request
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
        requested_cache = self._requested_cache_capabilities(request)
        requested_pre_cache = set(requested_cache)
        if (
            requested_pre_cache
            & {"search_snippet_cache", "search_cache"}
            and not requested_pre_cache
            & {
                "search_engine_cache_adapter",
                "alternate_search_cache_adapter",
            }
        ):
            requested_pre_cache.add("search_engine_cache_adapter")
        pre_acquisition_cache = tuple(
            capability_id
            for capability_id in PRE_ACQUISITION_CACHE_CAPABILITIES
            if capability_id in requested_pre_cache
            and self._permitted(capability_id, request)
        )
        previous_cache_node: str | None = None
        pre_cache_nodes: dict[str, str] = {}
        for index, capability in enumerate(pre_acquisition_cache):
            node_id = f"cache-pre-{index}-{capability.replace('_', '-')}"
            parameters: dict[str, str] = {}
            if capability == "previous_successful_snapshot":
                parameters = {
                    "cache_operation": "lookup",
                    "representation": "raw",
                    "parser_version": "httpx/0.28",
                }
            nodes.append(
                PlanNode(
                    id=node_id,
                    capability_id=capability,
                    adapter="cache",
                    dependencies=(http_dependency,),
                    fallback_for=previous_cache_node,
                    stop_on_acceptance=True,
                    reserved_budget={"bytes": request.budget.bytes},
                    parameters=parameters,
                )
            )
            previous_cache_node = node_id
            pre_cache_nodes[capability] = node_id
        cache_requires_http_source = bool(
            set(requested_cache) & {"browser_cache", "rag_document_cache"}
        )
        nodes.append(
            PlanNode(
                id="http",
                capability_id=http_capability,
                adapter="http",
                dependencies=(http_dependency,),
                fallback_for=(
                    previous_cache_node
                    if (
                        family == "cache"
                        and previous_cache_node is not None
                        and not cache_requires_http_source
                    )
                    else None
                ),
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
        terminal_dependency = acquired_dependency
        cache_producer_dependencies: dict[str, str] = {}
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
            terminal_dependency = "crawl"
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
            terminal_dependency = reader_nodes[-1].id
            if self.registry.get("playwright").implementation_available:
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
                terminal_dependency = "browser"
        elif family == "document":
            for index, capability in enumerate(self._document_capabilities(target, request)):
                nodes.append(
                    PlanNode(
                        id=f"document-{index}-{capability.replace('_', '-')}",
                        capability_id=capability,
                        adapter="documents",
                        dependencies=(acquired_dependency,),
                        parallel_group="document-extractors",
                        stop_on_acceptance=True,
                        reserved_budget={
                            "bytes": request.budget.bytes,
                            "decompressed_bytes": request.budget.decompressed_bytes,
                            "archive_members": request.budget.archive_members,
                            "archive_ratio": request.budget.archive_ratio,
                        },
                    )
                )
                terminal_dependency = nodes[-1].id
        elif family == "media":
            for index, capability in enumerate(self._media_capabilities(target, request)):
                nodes.append(
                    PlanNode(
                        id=f"media-{index}-{capability.replace('_', '-')}",
                        capability_id=capability,
                        adapter="media",
                        dependencies=(acquired_dependency,),
                        parallel_group="media-extractors",
                        stop_on_acceptance=True,
                        reserved_budget={
                            "bytes": request.budget.bytes,
                            "decompressed_bytes": request.budget.decompressed_bytes,
                        },
                    )
                )
                terminal_dependency = nodes[-1].id
        elif family == "archive":
            nodes.append(
                PlanNode(
                    id="archive",
                    capability_id="zip_archive",
                    adapter="archive",
                    dependencies=(acquired_dependency,),
                    stop_on_acceptance=True,
                    reserved_budget={
                        "bytes": request.budget.bytes,
                        "decompressed_bytes": request.budget.decompressed_bytes,
                        "archive_members": request.budget.archive_members,
                        "archive_ratio": request.budget.archive_ratio,
                    },
                )
            )
            terminal_dependency = "archive"
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
            terminal_dependency = "structured"
        if "rag_document_cache" in requested_cache:
            if not self._permitted("clean_text", request):
                raise ValueError(
                    "rag_document_cache requires the clean_text producer capability"
                )
            producer = next(
                (
                    node
                    for node in reversed(nodes)
                    if node.capability_id == "clean_text" and node.adapter == "reader"
                ),
                None,
            )
            if producer is None:
                dependency = (
                    terminal_dependency
                    if family == "document"
                    else acquired_dependency
                )
                producer = PlanNode(
                    id="cache-producer-rag-document",
                    capability_id="clean_text",
                    adapter="reader",
                    dependencies=(dependency,),
                    reserved_budget={
                        "decompressed_bytes": request.budget.decompressed_bytes,
                    },
                )
                nodes.append(producer)
            cache_producer_dependencies["rag_document_cache"] = producer.id
        if "browser_cache" in requested_cache:
            if (
                family in {"document", "media", "archive"}
                or classify_target(target, ()) in {"document", "media", "archive"}
            ):
                raise ValueError(
                    "browser_cache accepts HTML-like targets, not document, media, "
                    "or archive bytes"
                )
            producer = next(
                (
                    node
                    for node in reversed(nodes)
                    if node.adapter == "browser"
                    and node.capability_id in BROWSER_ENGINES
                ),
                None,
            )
            if producer is None:
                if not self._permitted("playwright", request):
                    raise ValueError(
                        "browser_cache requires the playwright producer capability"
                    )
                producer = PlanNode(
                    id="cache-producer-browser-render",
                    capability_id="playwright",
                    adapter="browser",
                    dependencies=(acquired_dependency,),
                    reserved_budget={
                        "browser_seconds": request.budget.browser_seconds,
                        "decompressed_bytes": request.budget.decompressed_bytes,
                    },
                )
                nodes.append(producer)
            cache_producer_dependencies["browser_cache"] = producer.id
        post_acquisition_cache = tuple(
            capability_id
            for capability_id in POST_ACQUISITION_CACHE_CAPABILITIES
            if capability_id in requested_cache
        )
        for index, capability in enumerate(post_acquisition_cache):
            dependency = cache_producer_dependencies.get(
                capability,
                terminal_dependency,
            )
            if capability in {"search_snippet_cache", "search_cache"}:
                dependency = next(
                    (
                        pre_cache_nodes[candidate]
                        for candidate in (
                            "search_engine_cache_adapter",
                            "alternate_search_cache_adapter",
                        )
                        if candidate in pre_cache_nodes
                    ),
                    dependency,
                )
            nodes.append(
                PlanNode(
                    id=f"cache-post-{index}-{capability.replace('_', '-')}",
                    capability_id=capability,
                    adapter="cache",
                    dependencies=(dependency,),
                    parallel_group="cache-strategies",
                    reserved_budget={"bytes": request.budget.bytes},
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
        self._validate_requested_schedulable_outputs(
            filtered,
            request,
            family=family,
        )
        return FetchPlan(request=public_request, nodes=filtered).bind_execution_request(
            execution_request
        )

    def _canonical_output_requirement(self, capability_id: str) -> str:
        try:
            return self.registry.resolve_id(capability_id)
        except KeyError:
            return capability_id

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
    def _document_capabilities(
        target: str,
        request: FetchRequest,
    ) -> tuple[str, ...]:
        requested = tuple(
            capability_id
            for capability_id in DOCUMENT_CAPABILITIES
            if capability_id in request.output_requirements and capability_id != "zip_archive"
        )
        if requested:
            return requested
        suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
        return (
            {
                ".md": "markdown",
                ".markdown": "markdown",
                ".json": "json_file",
                ".xml": "xml_file",
                ".csv": "csv",
                ".docx": "docx",
                ".epub": "dataset_file",
                ".pdf": "pdf",
                ".pptx": "pptx",
                ".txt": "txt",
                ".xls": "dataset_file",
                ".xlsx": "xlsx",
            }.get(suffix, "dataset_file"),
        )

    @staticmethod
    def _media_capabilities(
        target: str,
        request: FetchRequest,
    ) -> tuple[str, ...]:
        requested = tuple(
            capability_id
            for capability_id in MEDIA_CAPABILITIES
            if capability_id in request.output_requirements
        )
        if requested:
            return requested
        suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
        return (
            "image_metadata"
            if suffix in {".gif", ".jpeg", ".jpg", ".png", ".tif", ".tiff", ".webp"}
            else "audio_metadata"
            if suffix in {".aac", ".flac", ".m4a", ".mp3", ".wav"}
            else "video_metadata",
        )

    @staticmethod
    def _requested_cache_capabilities(request: FetchRequest) -> tuple[str, ...]:
        return tuple(
            capability_id
            for capability_id in CACHE_CAPABILITIES
            if capability_id in request.output_requirements
        )

    @staticmethod
    def _document_capability(target: str) -> str:
        """Compatibility helper retained for callers of the v0.3 planner surface."""

        suffix = PurePosixPath(urlsplit(target).path.lower()).suffix
        return {
            ".md": "markdown",
            ".markdown": "markdown",
            ".json": "json_file",
            ".xml": "xml_file",
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

    def _validate_requested_schedulable_outputs(
        self,
        nodes: tuple[PlanNode, ...],
        request: FetchRequest,
        *,
        family: str,
    ) -> None:
        scheduled = {self.registry.resolve_id(node.capability_id) for node in nodes}
        missing: list[str] = []
        denied: list[str] = []
        for capability_id in request.output_requirements:
            if (
                capability_id == "clean_text"
                and request.output_requirements == ("clean_text",)
                and (family != "web" or request.intent == "crawl")
            ):
                continue
            try:
                entry = self.registry.get(capability_id)
            except KeyError:
                continue
            if entry.kind not in _SCHEDULABLE_KINDS:
                continue
            if (
                entry.id in _BROWSER_EMBEDDED_CAPABILITIES
                and any(node.adapter == "browser" for node in nodes)
            ):
                continue
            if (
                entry.id in _HTTP_EMBEDDED_AUTH_CAPABILITIES
                and any(node.adapter == "http" for node in nodes)
            ):
                continue
            if not self._permitted(entry.id, request):
                denied.append(entry.id)
            elif entry.id not in scheduled:
                missing.append(entry.id)
        if denied:
            raise ValueError(
                f"requested schedulable capabilities are denied: {sorted(denied)}"
            )
        if missing:
            raise ValueError(
                "requested schedulable capabilities cannot be combined in one plan: "
                f"{sorted(missing)}"
            )
