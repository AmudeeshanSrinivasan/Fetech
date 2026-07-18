"""Truthful implementation inventory layered over the canonical capability IDs."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from typing import TypedDict

from fetech.models import CapabilityManifestEntry, ImplementationStatus


class ImplementationRecord(TypedDict):
    status: ImplementationStatus
    implementation: str


_V01_OPTIONAL: dict[str, str] = {
    "browser_reader_mode": "fetech.browser_reader.BrowserReaderWorker[playwright chromium]",
    "http_3": "fetech.http3.CurlHTTP3Client[curl built with HTTP3]",
    "jina_reader": "fetech.adapters.reader.ReaderAdapter[configured remote reader]",
    "mozilla_readability": "fetech.adapters.reader.ReaderAdapter[readability-lxml]",
    "trafilatura": "fetech.adapters.reader.ReaderAdapter[trafilatura]",
}

_V01_PLANNED: dict[str, str] = {}

_V02_OPTIONAL: dict[str, str] = {
    "playwright": "fetech.adapters.browser.BrowserAdapter[fetech[browser]]",
    "puppeteer": "fetech.adapters.browser.BrowserAdapter[configured Puppeteer connector]",
    "search_provider_discovery": (
        "fetech.adapters.discovery.DiscoveryAdapter[configured search provider connector]"
    ),
    "selenium": "fetech.adapters.browser.BrowserAdapter[configured Selenium connector]",
}

_V03_NATIVE: dict[str, str] = {
    "api_key": "fetech.auth.CredentialProvider+fetech.adapters.http.HTTPAdapter",
    "arxiv_api": "fetech.adapters.api.StructuredAPIAdapter[arXiv Atom schema]",
    "atom": "fetech.adapters.api.StructuredAPIAdapter[bounded Atom parser]",
    "bearer_token": "fetech.auth.CredentialProvider+fetech.adapters.http.HTTPAdapter",
    "connector_auth": "fetech.auth.CredentialProvider",
    "cookie_session": "fetech.auth.CredentialProvider+fetech.adapters.http.HTTPAdapter",
    "crossref_openalex_api": (
        "fetech.adapters.api.StructuredAPIAdapter[Crossref/OpenAlex schemas]"
    ),
    "csrf_token": "fetech.auth_flows.extract_csrf_token+fetech.adapters.auth.AuthAdapter",
    "form_submit": "fetech.adapters.auth.AuthAdapter[explicit approval]",
    "github_api": "fetech.adapters.api.StructuredAPIAdapter[GitHub schema]",
    "graphql": "fetech.adapters.api.StructuredAPIAdapter[GraphQL envelope]",
    "json_endpoint": "fetech.adapters.api.StructuredAPIAdapter[bounded JSON parser]",
    "login_session": (
        "fetech.adapters.auth.AuthAdapter[origin-scoped session provider and approved form login]"
    ),
    "oauth": "fetech.adapters.auth.AuthAdapter[origin-scoped OAuth session provider]",
    "openapi_discovery": "fetech.adapters.api.StructuredAPIAdapter[bounded OpenAPI parser]",
    "openreview_api": "fetech.adapters.api.StructuredAPIAdapter[OpenReview schema]",
    "rest": "fetech.adapters.api.StructuredAPIAdapter[JSON/XML response]",
    "rss": "fetech.adapters.api.StructuredAPIAdapter[bounded RSS parser]",
    "semantic_scholar_api": (
        "fetech.adapters.api.StructuredAPIAdapter[Semantic Scholar schema]"
    ),
    "sitemap_xml": "fetech.adapters.api.StructuredAPIAdapter[bounded sitemap parser]",
    "xml_endpoint": "fetech.adapters.api.StructuredAPIAdapter[DTD-free XML parser]",
}

_V03_OPTIONAL: dict[str, str] = {
    "private_workspace": (
        "fetech.adapters.auth.AuthAdapter[configured private workspace connector]"
    ),
    "sso": "fetech.adapters.auth.AuthAdapter[configured SSO session connector]",
}

_V04_NATIVE: dict[str, str] = {
    "browser_cache": "fetech.adapters.cache.CacheAdapter[validated SnapshotStore]",
    "csv": "fetech.adapters.documents.DocumentAdapter[bounded DocumentParseWorker]",
    "dataset_file": "fetech.adapters.documents.DocumentAdapter[signature-first routing]",
    "exif_metadata": "fetech.adapters.media.MediaAdapter[bounded EXIF parser]",
    "github_raw": (
        "fetech.adapters.documents.DocumentAdapter[exact raw.githubusercontent.com origin]"
    ),
    "internet_archive_snapshot": (
        "fetech.wayback.WaybackSnapshotConnector[pinned exact-host Wayback client]"
    ),
    "json_file": "fetech.adapters.documents.DocumentAdapter[bounded JSON parser]",
    "local_snapshot": "fetech.adapters.cache.CacheAdapter[validated SnapshotStore]",
    "markdown": "fetech.adapters.documents.DocumentAdapter[bounded DocumentParseWorker]",
    "podcast_feed": "fetech.adapters.media.MediaAdapter[bounded RSS parser]",
    "previous_successful_snapshot": (
        "fetech.adapters.cache.CacheAdapter[integrity-verified SnapshotStore lookup]"
    ),
    "rag_document_cache": "fetech.adapters.cache.CacheAdapter[validated SnapshotStore]",
    "search_cache": "fetech.adapters.cache.CacheAdapter[validated SnapshotStore]",
    "search_snippet_cache": "fetech.adapters.cache.CacheAdapter[validated SnapshotStore]",
    "txt": "fetech.adapters.documents.DocumentAdapter[bounded DocumentParseWorker]",
    "xml_file": "fetech.adapters.documents.DocumentAdapter[DTD-free XML parser]",
    "zip_archive": "fetech.adapters.archive.ArchiveAdapter[bounded ArchiveParseWorker]",
}

_V04_OPTIONAL: dict[str, str] = {
    "alternate_search_cache_adapter": (
        "fetech.adapters.cache.CacheAdapter[configured SnapshotConnector]"
    ),
    "audio_metadata": "fetech.adapters.media.MediaAdapter[WAV or bounded FFprobeWorker]",
    "cdn_copy": "fetech.adapters.cache.CacheAdapter[configured SnapshotConnector]",
    "docx": "fetech.adapters.documents.DocumentAdapter[python-docx worker]",
    "git_lfs": (
        "fetech.adapters.documents.DocumentAdapter[configured exact-origin LFS resolver]"
    ),
    "image_ocr": "fetech.adapters.media.MediaAdapter[bounded TesseractOCRWorker]",
    "image": (
        "fetech.adapters.media.MediaAdapter[bounded header parser + "
        "PillowImageValidationWorker]"
    ),
    "image_metadata": (
        "fetech.adapters.media.MediaAdapter[bounded header parser + "
        "PillowImageValidationWorker]"
    ),
    "pdf": "fetech.adapters.documents.DocumentAdapter[pypdf worker]",
    "pptx": "fetech.adapters.documents.DocumentAdapter[python-pptx worker]",
    "scanned_pdf": (
        "fetech.adapters.documents.DocumentAdapter[pypdf worker + configured PDFOCRProvider]"
    ),
    "screenshot_to_text": "fetech.adapters.media.MediaAdapter[bounded TesseractOCRWorker]",
    "search_engine_cache_adapter": (
        "fetech.adapters.cache.CacheAdapter[configured SnapshotConnector]"
    ),
    "thumbnail": "fetech.adapters.media.MediaAdapter[bounded FFmpegThumbnailWorker]",
    "transcript": "fetech.adapters.media.MediaAdapter[bounded parser or TranscriptProvider]",
    "video_metadata": "fetech.adapters.media.MediaAdapter[bounded FFprobeWorker]",
    "web_archive": "fetech.adapters.cache.CacheAdapter[configured SnapshotConnector]",
    "xlsx": "fetech.adapters.documents.DocumentAdapter[openpyxl worker]",
    "youtube_metadata": (
        "fetech.yt_dlp.YTDLPMetadataWorker[bounded built-in yt-dlp metadata worker]"
    ),
}

_IMPLEMENTATIONS = {
    "browser": "fetech.adapters.browser.BrowserAdapter[fetech[browser]]",
    "core": "fetech.gateway._CoreAdapter",
    "discovery": "fetech.adapters.discovery.DiscoveryAdapter",
    "http": "fetech.adapters.http.HTTPAdapter",
    "reader": "fetech.adapters.reader.ReaderAdapter",
    "variants": "fetech.adapters.variants.VariantAdapter",
    "quality": "fetech.quality+fetech.executor.ExecutionEngine+fetech.storage.CacheRecord",
}


def implementation_for(
    capability_id: str,
    closure_release: str,
    adapter: str,
) -> ImplementationRecord:
    if closure_release == "v0.3" and capability_id in _V03_NATIVE:
        return {
            "status": ImplementationStatus.NATIVE,
            "implementation": _V03_NATIVE[capability_id],
        }
    if closure_release == "v0.3" and capability_id in _V03_OPTIONAL:
        return {
            "status": ImplementationStatus.OPTIONAL,
            "implementation": _V03_OPTIONAL[capability_id],
        }
    if closure_release == "v0.4" and capability_id in _V04_NATIVE:
        return {
            "status": ImplementationStatus.NATIVE,
            "implementation": _V04_NATIVE[capability_id],
        }
    if closure_release == "v0.4" and capability_id in _V04_OPTIONAL:
        return {
            "status": ImplementationStatus.OPTIONAL,
            "implementation": _V04_OPTIONAL[capability_id],
        }
    if closure_release not in {"v0.1", "v0.2"}:
        return {
            "status": ImplementationStatus.PLANNED,
            "implementation": f"{closure_release} roadmap",
        }
    if closure_release == "v0.2" and capability_id in _V02_OPTIONAL:
        return {
            "status": ImplementationStatus.OPTIONAL,
            "implementation": _V02_OPTIONAL[capability_id],
        }
    if capability_id in _V01_PLANNED:
        return {
            "status": ImplementationStatus.PLANNED,
            "implementation": _V01_PLANNED[capability_id],
        }
    if capability_id in _V01_OPTIONAL:
        return {
            "status": ImplementationStatus.OPTIONAL,
            "implementation": _V01_OPTIONAL[capability_id],
        }
    return {
        "status": ImplementationStatus.NATIVE,
        "implementation": _IMPLEMENTATIONS[adapter],
    }


def release_report(
    entries: Iterable[CapabilityManifestEntry], release: str = "v0.1"
) -> dict[str, object]:
    selected = [entry for entry in entries if entry.closure_release == release]
    counts = Counter(entry.implementation_status.value for entry in selected)
    gaps = [entry.id for entry in selected if entry.implementation_status == ImplementationStatus.PLANNED]
    return {
        "release": release,
        "capability_count": len(selected),
        "implementation_path_count": sum(
            entry.implementation_available for entry in selected
        ),
        "runtime_available_count": sum(
            entry.runtime_available for entry in selected
        ),
        "closure_ready": not gaps,
        "status_counts": dict(sorted(counts.items())),
        "gaps": gaps,
    }
