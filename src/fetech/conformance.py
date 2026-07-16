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
        "available_count": sum(entry.available for entry in selected),
        "closure_ready": not gaps,
        "status_counts": dict(sorted(counts.items())),
        "gaps": gaps,
    }
