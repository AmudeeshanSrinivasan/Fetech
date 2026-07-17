"""Bounded normalization for structured APIs, feeds, and public API connectors.

This adapter intentionally has no transport dependency.  It accepts only a raw
artifact already produced by Fetech's acquisition boundary, so destination
policy, redirects, authentication, and transfer budgets remain the HTTP
adapter's responsibility.
"""

from __future__ import annotations

import json
import math
import re
import xml.etree.ElementTree as ET
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import yaml
from yaml.constructor import ConstructorError
from yaml.nodes import MappingNode
from yaml.resolver import BaseResolver
from yaml.tokens import AliasToken, AnchorToken

from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.models import (
    Artifact,
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    PageState,
    PlanNode,
    PolicyDecision,
    QualityAssessment,
    Resource,
)
from fetech.security import (
    PolicyBlockedError,
    sanitize_url,
    sanitize_url_for_request,
)
from fetech.storage import build_artifact

API_CAPABILITIES = frozenset(
    {
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
    }
)

_JSON_NAMED_CAPABILITIES = frozenset(
    {
        "github_api",
        "semantic_scholar_api",
        "openreview_api",
        "crossref_openalex_api",
    }
)
_SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
_KNOWN_METHODS = _SAFE_METHODS | {"POST", "PUT", "PATCH", "DELETE"}
_PUBLIC_HTTP_NAMED_CAPABILITIES = frozenset({"arxiv_api"})
_XML_DECLARATIONS = re.compile(br"<!\s*(?:DOCTYPE|ENTITY)\b", re.IGNORECASE)


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects ambiguous duplicate mapping keys."""


def _construct_unique_mapping(
    loader: _UniqueKeySafeLoader,
    node: MappingNode,
    deep: bool = False,
) -> dict[Any, Any]:
    loader.flatten_mapping(node)
    mapping: dict[Any, Any] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            duplicate = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing an OpenAPI mapping",
                node.start_mark,
                "found an unhashable mapping key",
                key_node.start_mark,
            ) from exc
        if duplicate:
            raise ConstructorError(
                "while constructing an OpenAPI mapping",
                node.start_mark,
                f"found duplicate key {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_UniqueKeySafeLoader.add_constructor(
    BaseResolver.DEFAULT_MAPPING_TAG,
    _construct_unique_mapping,
)

# Exact public origins and bounded path families.  A suffix match is never used:
# ``api.github.com.attacker.example`` must not classify as GitHub.
_NAMED_API_ROUTES: dict[str, tuple[tuple[str, tuple[str, ...]], ...]] = {
    "github_api": (("api.github.com", ("/",)),),
    "semantic_scholar_api": (
        (
            "api.semanticscholar.org",
            ("/graph/v1", "/recommendations/v1", "/datasets/v1"),
        ),
    ),
    "arxiv_api": (("export.arxiv.org", ("/api/query",)),),
    "openreview_api": (
        ("api.openreview.net", ("/",)),
        ("api2.openreview.net", ("/",)),
    ),
    "crossref_openalex_api": (
        (
            "api.crossref.org",
            ("/works", "/journals", "/members", "/funders", "/prefixes", "/types", "/licenses"),
        ),
        (
            "api.openalex.org",
            (
                "/works",
                "/authors",
                "/sources",
                "/institutions",
                "/topics",
                "/publishers",
                "/funders",
                "/concepts",
                "/autocomplete",
                "/text",
            ),
        ),
    ),
}


@dataclass(frozen=True)
class NormalizedAPI:
    """Deterministic normalized document ready for canonical JSON storage."""

    document: dict[str, Any]
    representation: str
    parser: str
    locators: tuple[str, ...]
    observed_format: str
    omitted_records: int = 0


class StructuredAPIAdapter:
    """Normalize a previously acquired raw artifact without performing I/O."""

    def __init__(
        self,
        *,
        maximum_parse_bytes: int = 16_000_000,
        maximum_nodes: int = 100_000,
        maximum_depth: int = 64,
        maximum_records: int = 10_000,
    ) -> None:
        if min(maximum_parse_bytes, maximum_nodes, maximum_depth, maximum_records) <= 0:
            raise ValueError("API parser limits must be positive")
        self.maximum_parse_bytes = maximum_parse_bytes
        self.maximum_nodes = maximum_nodes
        self.maximum_depth = maximum_depth
        self.maximum_records = maximum_records

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            adapter_version="0.3.0a0",
            sanitized_destination=sanitize_url_for_request(
                context.request.target,
                context.request,
            ),
            status=AttemptStatus.RUNNING,
        )
        attempt_index = len(context.attempts)
        context.attempts.append(attempt)
        try:
            if node.capability_id not in API_CAPABILITIES:
                raise AdapterExecutionError(
                    f"structured API adapter cannot execute {node.capability_id}"
                )
            _enforce_non_mutating_request(node, context)
            raw, resource = _acquired_source(context)
            parse_limit = min(
                self.maximum_parse_bytes,
                context.request.budget.bytes,
                context.request.budget.decompressed_bytes,
            )
            if raw.size > parse_limit:
                raise AdapterExecutionError("structured API body exceeds the parser byte limit")
            body = await context.cas.get(raw.cas_uri, maximum_bytes=parse_limit)
            normalized = normalize_api_payload(
                node.capability_id,
                body,
                media_type=raw.media_type,
                source_url=sanitize_url_for_request(
                    resource.canonical_url,
                    context.request,
                ),
                authority_url=sanitize_url_for_request(
                    resource.authority_url or resource.requested_url,
                    context.request,
                ),
                maximum_nodes=self.maximum_nodes,
                maximum_depth=self.maximum_depth,
                maximum_records=self.maximum_records,
            )
            encoded = json.dumps(
                normalized.document,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
                allow_nan=False,
            ).encode("utf-8")
            uri, digest, size = await context.cas.put(encoded)
            quality = QualityAssessment(
                page_state=PageState.OK,
                score=1.0,
                accepted=True,
                completeness=1.0,
                reasons=("schema-valid bounded structured response",),
            )
            artifact = build_artifact(
                role="primary",
                representation=normalized.representation,
                media_type=f"application/vnd.fetech.{normalized.representation}+json",
                cas_uri=uri,
                digest=digest,
                size=size,
                resource=resource,
                extractor=f"builtin-api/{node.capability_id}/0.3",
                quality=quality,
                parents=(raw,),
                locators=normalized.locators,
            )
            context.artifacts.append(artifact)
            context.accepted = True
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.APPLIED,
                "api",
                format=normalized.observed_format,
                bounded=True,
                omitted_records=normalized.omitted_records,
            )
            _record_format_outcome(context, node.capability_id, normalized.observed_format)
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.SUCCEEDED,
                    "finished_at": datetime.now(UTC),
                    "bytes_received": len(body),
                    "parser": normalized.parser,
                    "artifact_ids": (artifact.artifact_id,),
                }
            )
        except PolicyBlockedError:
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.BLOCKED,
                "api",
                reason="mutating API operation requires explicit approval",
            )
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "policy",
                }
            )
            raise
        except AdapterExecutionError as exc:
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "api",
                reason=str(exc),
            )
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "malformed_api_payload",
                    "warnings": (str(exc),),
                }
            )
            raise
        except (ET.ParseError, UnicodeError, ValueError, yaml.YAMLError) as exc:
            message = "structured API payload is invalid or exceeds parser limits"
            context.record_outcome(
                node.capability_id,
                CapabilityOutcomeStatus.FAILED,
                "api",
                reason=message,
            )
            context.attempts[attempt_index] = attempt.model_copy(
                update={
                    "status": AttemptStatus.FAILED,
                    "finished_at": datetime.now(UTC),
                    "failure_code": "malformed_api_payload",
                    "warnings": (message,),
                }
            )
            raise AdapterExecutionError(message) from exc


# Short public name for gateway wiring while retaining the descriptive class.
APIAdapter = StructuredAPIAdapter


def detect_named_api(source_url: str) -> str | None:
    """Return a named capability only for an exact canonical public API origin."""

    for capability_id in _NAMED_API_ROUTES:
        if _matches_named_origin(capability_id, source_url):
            return capability_id
    return None


def normalize_api_payload(
    capability_id: str,
    body: bytes,
    *,
    media_type: str,
    source_url: str,
    authority_url: str,
    maximum_nodes: int = 100_000,
    maximum_depth: int = 64,
    maximum_records: int = 10_000,
) -> NormalizedAPI:
    """Normalize one bounded response; callers remain responsible for acquisition."""

    if capability_id not in API_CAPABILITIES:
        raise AdapterExecutionError(f"unknown structured API capability {capability_id}")
    if capability_id in _NAMED_API_ROUTES and not _matches_named_origin(
        capability_id, source_url
    ):
        raise AdapterExecutionError(
            f"{capability_id} requires its canonical public API origin and path"
        )

    authority = sanitize_url(authority_url)
    source = sanitize_url(source_url)
    if capability_id == "openapi_discovery":
        data, parser = _parse_openapi(
            body,
            maximum_nodes=maximum_nodes,
            maximum_depth=maximum_depth,
        )
        paths = data["paths"]
        assert isinstance(paths, dict)
        selected_paths = dict(list(paths.items())[:maximum_records])
        omitted = max(0, len(paths) - len(selected_paths))
        data = {**data, "paths": selected_paths}
        locators = tuple(f"path:{path}" for path in selected_paths)
        return _normalized(
            capability_id,
            authority,
            source,
            "openapi",
            data,
            parser,
            locators or ("document",),
            "openapi",
            omitted,
        )

    if capability_id in {"rss", "atom", "sitemap_xml", "arxiv_api"}:
        root = _parse_xml(body, maximum_nodes=maximum_nodes, maximum_depth=maximum_depth)
        if capability_id == "rss":
            data, locators, omitted = _normalize_rss(root, maximum_records)
            representation, observed = "feed", "rss"
        elif capability_id in {"atom", "arxiv_api"}:
            data, locators, omitted = _normalize_atom(root, maximum_records)
            representation, observed = (
                ("api_response", "atom") if capability_id == "arxiv_api" else ("feed", "atom")
            )
        else:
            data, locators, omitted = _normalize_sitemap(root, maximum_records)
            representation, observed = "sitemap", "sitemap_xml"
        return _normalized(
            capability_id,
            authority,
            source,
            representation,
            data,
            "elementtree-safe",
            locators,
            observed,
            omitted,
        )

    if capability_id == "xml_endpoint":
        root = _parse_xml(body, maximum_nodes=maximum_nodes, maximum_depth=maximum_depth)
        data = _element_document(root)
        return _normalized(
            capability_id,
            authority,
            source,
            "xml",
            data,
            "elementtree-safe",
            (f"element:/{_local_name(root.tag)}",),
            "xml",
        )

    if capability_id == "rest" and _looks_like_xml(body, media_type):
        root = _parse_xml(body, maximum_nodes=maximum_nodes, maximum_depth=maximum_depth)
        data = _element_document(root)
        return _normalized(
            capability_id,
            authority,
            source,
            "api_response",
            data,
            "elementtree-safe",
            (f"element:/{_local_name(root.tag)}",),
            "xml",
        )

    data = _parse_json(body, maximum_nodes=maximum_nodes, maximum_depth=maximum_depth)
    if capability_id == "graphql":
        if not isinstance(data, dict) or not ({"data", "errors"} & data.keys()):
            raise AdapterExecutionError("GraphQL response must contain data or errors")
        representation = "graphql"
    elif capability_id == "json_endpoint":
        representation = "json"
    else:
        representation = "api_response"
    if capability_id in _JSON_NAMED_CAPABILITIES:
        _validate_named_schema(capability_id, data, source_url)
    data, omitted = _truncate_json_lists(data, maximum_records)
    locators = _json_locators(data, maximum_records)
    return _normalized(
        capability_id,
        authority,
        source,
        representation,
        data,
        "json-stdlib",
        locators,
        "json",
        omitted,
    )


def _normalized(
    capability_id: str,
    authority_url: str,
    source_url: str,
    representation: str,
    data: Any,
    parser: str,
    locators: tuple[str, ...],
    observed_format: str,
    omitted_records: int = 0,
) -> NormalizedAPI:
    return NormalizedAPI(
        document={
            "schema_version": "1.0",
            "capability": capability_id,
            "authority_url": authority_url,
            "source_url": source_url,
            "format": observed_format,
            "data": data,
            "omitted_records": omitted_records,
        },
        representation=representation,
        parser=parser,
        locators=locators,
        observed_format=observed_format,
        omitted_records=omitted_records,
    )


def _acquired_source(context: ExecutionContext) -> tuple[Artifact, Resource]:
    raw = context.latest_artifact("raw")
    if raw is None:
        raise AdapterExecutionError("structured API parsing requires an acquired raw artifact")
    resource = next(
        (
            candidate
            for candidate in reversed(context.resources)
            if candidate.resource_id == raw.source_resource_id
        ),
        None,
    )
    if resource is None:
        raise AdapterExecutionError("raw artifact has no matching source resource")
    acquired = any(
        attempt.status == AttemptStatus.SUCCEEDED
        and raw.artifact_id in attempt.artifact_ids
        and attempt.capability_id
        in {"http_get", "http_head", "http_post", "browser_header_http", "range_request"}
        for attempt in context.attempts
    )
    if not acquired:
        raise AdapterExecutionError(
            "structured API parsing requires successful HTTP acquisition provenance"
        )
    return raw, resource


def _enforce_non_mutating_request(node: PlanNode, context: ExecutionContext) -> None:
    method_value = node.parameters.get("method", context.request.metadata.get("http_method", "GET"))
    method = str(method_value).upper()
    if method not in _KNOWN_METHODS:
        raise AdapterExecutionError("structured API method is unsupported")
    operation_value = node.parameters.get(
        "operation_type", context.request.metadata.get("api_operation", "query")
    )
    operation = str(operation_value).casefold()
    mutating = method not in _SAFE_METHODS or operation == "mutation"
    approved = (
        node.capability_id in context.request.approved_capabilities
        or context.request.metadata.get("api_mutation_approved", "").casefold() == "true"
        or (
            method == "POST"
            and context.request.metadata.get("http_post_approved", "").casefold() == "true"
            and operation != "mutation"
        )
    )
    if mutating and not approved:
        reason = "mutating API operation requires explicit approval"
        raise PolicyBlockedError(
            reason,
            (
                PolicyDecision(
                    policy_id="api_mutation_approval",
                    allowed=False,
                    reason=reason,
                    destination=sanitize_url(context.request.target),
                ),
            ),
        )


def _record_format_outcome(
    context: ExecutionContext, requested_capability: str, observed_format: str
) -> None:
    format_capability = (
        "json_endpoint"
        if observed_format == "json"
        else "xml_endpoint"
        if observed_format in {"xml", "rss", "atom", "sitemap_xml"}
        else None
    )
    if format_capability is not None and format_capability != requested_capability:
        context.record_outcome(
            format_capability,
            CapabilityOutcomeStatus.OBSERVED,
            "api",
            discovered_by=requested_capability,
        )


def _validate_named_schema(capability_id: str, data: Any, source_url: str) -> None:
    """Conservatively recognize public API response envelopes after host checks."""

    if capability_id == "github_api":
        if isinstance(data, list):
            return
        required_any = {
            "id",
            "login",
            "name",
            "full_name",
            "items",
            "message",
            "documentation_url",
            "current_user_url",
        }
    elif capability_id == "semantic_scholar_api":
        required_any = {
            "paperId",
            "title",
            "authors",
            "data",
            "total",
            "offset",
            "externalIds",
            "message",
        }
    elif capability_id == "openreview_api":
        required_any = {
            "id",
            "notes",
            "groups",
            "profiles",
            "invitations",
            "edges",
            "count",
            "content",
            "forum",
        }
    else:
        host = (urlsplit(source_url).hostname or "").casefold().rstrip(".")
        required_any = (
            {"status", "message-type", "message"}
            if host == "api.crossref.org"
            else {"id", "results", "meta", "display_name", "count"}
        )
    if not isinstance(data, dict) or not (required_any & data.keys()):
        raise AdapterExecutionError(
            f"{capability_id} response does not match its public API schema"
        )


def _parse_json(body: bytes, *, maximum_nodes: int, maximum_depth: int) -> Any:
    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON numbers are forbidden")

    def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("duplicate JSON object keys are forbidden")
            result[key] = value
        return result

    data = json.loads(
        body.decode("utf-8-sig"),
        object_pairs_hook=unique_object,
        parse_constant=reject_constant,
    )
    _validate_json_structure(data, maximum_nodes=maximum_nodes, maximum_depth=maximum_depth)
    return data


def _parse_openapi(
    body: bytes, *, maximum_nodes: int, maximum_depth: int
) -> tuple[dict[str, Any], str]:
    stripped = body.lstrip()
    if stripped.startswith((b"{", b"[")):
        candidate = _parse_json(
            body,
            maximum_nodes=maximum_nodes,
            maximum_depth=maximum_depth,
        )
        parser = "openapi-json"
    else:
        text = body.decode("utf-8-sig")
        if any(isinstance(token, (AliasToken, AnchorToken)) for token in yaml.scan(text)):
            raise ValueError("YAML aliases and anchors are forbidden in untrusted OpenAPI input")
        candidate = yaml.load(text, Loader=_UniqueKeySafeLoader)
        _validate_json_structure(
            candidate,
            maximum_nodes=maximum_nodes,
            maximum_depth=maximum_depth,
        )
        parser = "openapi-yaml-safe"
    if not isinstance(candidate, dict):
        raise AdapterExecutionError("OpenAPI document must be an object")
    version = candidate.get("openapi") or candidate.get("swagger")
    if not isinstance(version, str) or not version.strip():
        raise AdapterExecutionError("OpenAPI document is missing its version")
    paths = candidate.get("paths")
    if not isinstance(paths, dict):
        raise AdapterExecutionError("OpenAPI document must contain a paths object")
    return candidate, parser


def _validate_json_structure(data: Any, *, maximum_nodes: int, maximum_depth: int) -> None:
    stack: list[tuple[Any, int]] = [(data, 1)]
    nodes = 0
    while stack:
        value, depth = stack.pop()
        nodes += 1
        if nodes > maximum_nodes:
            raise ValueError("structured payload exceeds the node limit")
        if depth > maximum_depth:
            raise ValueError("structured payload exceeds the nesting limit")
        if value is None or isinstance(value, (str, bool, int)):
            continue
        if isinstance(value, float):
            if not math.isfinite(value):
                raise ValueError("non-finite numbers are forbidden")
            continue
        if isinstance(value, list):
            stack.extend((item, depth + 1) for item in value)
            continue
        if isinstance(value, Mapping):
            for key, item in value.items():
                if not isinstance(key, str):
                    raise ValueError("structured object keys must be strings")
                stack.append((item, depth + 1))
            continue
        raise ValueError("structured payload contains a non-JSON value")


def _parse_xml(body: bytes, *, maximum_nodes: int, maximum_depth: int) -> ET.Element:
    if _XML_DECLARATIONS.search(body):
        raise ValueError("DTD and entity declarations are forbidden in untrusted XML")
    root = ET.fromstring(body)
    stack: list[tuple[ET.Element, int]] = [(root, 1)]
    nodes = 0
    while stack:
        element, depth = stack.pop()
        nodes += 1
        if nodes > maximum_nodes:
            raise ValueError("XML payload exceeds the node limit")
        if depth > maximum_depth:
            raise ValueError("XML payload exceeds the nesting limit")
        stack.extend((child, depth + 1) for child in list(element))
    return root


def _element_document(element: ET.Element) -> dict[str, Any]:
    return {
        "tag": _local_name(element.tag),
        "attributes": {
            _local_name(key): value for key, value in sorted(element.attrib.items())
        },
        "text": (element.text or "").strip(),
        "children": [_element_document(child) for child in list(element)],
    }


def _normalize_rss(
    root: ET.Element, maximum_records: int
) -> tuple[dict[str, Any], tuple[str, ...], int]:
    root_name = _local_name(root.tag).casefold()
    if root_name not in {"rss", "rdf"}:
        raise AdapterExecutionError("RSS document must have an rss or RDF root")
    if root_name == "rss" and not root.attrib.get("version", "").strip():
        raise AdapterExecutionError("RSS document must declare its version")
    channel = next(
        (element for element in root.iter() if _local_name(element.tag).casefold() == "channel"),
        root,
    )
    all_items = [
        element for element in root.iter() if _local_name(element.tag).casefold() == "item"
    ]
    items = [_feed_record(item, atom=False) for item in all_items[:maximum_records]]
    locators = tuple(f"item:{index}" for index in range(1, len(items) + 1))
    return (
        {
            "type": "rss",
            "title": _child_text(channel, "title"),
            "link": _child_text(channel, "link"),
            "description": _child_text(channel, "description"),
            "items": items,
        },
        locators or ("channel",),
        max(0, len(all_items) - len(items)),
    )


def _normalize_atom(
    root: ET.Element, maximum_records: int
) -> tuple[dict[str, Any], tuple[str, ...], int]:
    if (
        _local_name(root.tag).casefold() != "feed"
        or _namespace(root.tag) != "http://www.w3.org/2005/Atom"
    ):
        raise AdapterExecutionError("Atom document must have the Atom namespaced feed root")
    all_entries = [
        element for element in list(root) if _local_name(element.tag).casefold() == "entry"
    ]
    entries = [_feed_record(entry, atom=True) for entry in all_entries[:maximum_records]]
    locators = tuple(f"entry:{index}" for index in range(1, len(entries) + 1))
    return (
        {
            "type": "atom",
            "title": _child_text(root, "title"),
            "link": _atom_link(root),
            "id": _child_text(root, "id"),
            "updated": _child_text(root, "updated"),
            "entries": entries,
        },
        locators or ("feed",),
        max(0, len(all_entries) - len(entries)),
    )


def _normalize_sitemap(
    root: ET.Element, maximum_records: int
) -> tuple[dict[str, Any], tuple[str, ...], int]:
    root_name = _local_name(root.tag).casefold()
    if root_name not in {"urlset", "sitemapindex"}:
        raise AdapterExecutionError("sitemap XML must have a urlset or sitemapindex root")
    record_name = "url" if root_name == "urlset" else "sitemap"
    all_records = [
        element
        for element in list(root)
        if _local_name(element.tag).casefold() == record_name
    ]
    records = [
        {
            key: _child_text(record, key)
            for key in ("loc", "lastmod", "changefreq", "priority")
            if _child_text(record, key) is not None
        }
        for record in all_records[:maximum_records]
    ]
    locators = tuple(f"{record_name}:{index}" for index in range(1, len(records) + 1))
    return (
        {"type": root_name, "records": records},
        locators or (root_name,),
        max(0, len(all_records) - len(records)),
    )


def _feed_record(element: ET.Element, *, atom: bool) -> dict[str, str | None]:
    return {
        "title": _child_text(element, "title"),
        "link": _atom_link(element) if atom else _child_text(element, "link"),
        "id": _child_text(element, "id") or _child_text(element, "guid"),
        "summary": _child_text(element, "summary")
        or _child_text(element, "description")
        or _child_text(element, "content"),
        "published": _child_text(element, "published")
        or _child_text(element, "pubDate"),
        "updated": _child_text(element, "updated"),
    }


def _child_text(element: ET.Element, name: str) -> str | None:
    expected = name.casefold()
    for child in list(element):
        if _local_name(child.tag).casefold() == expected:
            text = "".join(child.itertext()).strip()
            return text or None
    return None


def _atom_link(element: ET.Element) -> str | None:
    for child in list(element):
        if _local_name(child.tag).casefold() != "link":
            continue
        relation = child.attrib.get("rel", "alternate").casefold()
        if relation == "alternate" and child.attrib.get("href"):
            return child.attrib["href"]
    return None


def _local_name(tag: str) -> str:
    return tag.rsplit("}", maxsplit=1)[-1].rsplit(":", maxsplit=1)[-1]


def _namespace(tag: str) -> str | None:
    return tag[1:].split("}", maxsplit=1)[0] if tag.startswith("{") and "}" in tag else None


def _looks_like_xml(body: bytes, media_type: str) -> bool:
    normalized_media_type = media_type.casefold().split(";", maxsplit=1)[0].strip()
    return (
        normalized_media_type in {"application/xml", "text/xml"}
        or normalized_media_type.endswith("+xml")
        or body.lstrip().startswith(b"<")
    )


def _json_locators(data: Any, maximum_records: int) -> tuple[str, ...]:
    if isinstance(data, dict):
        return tuple(f"json:/{_json_pointer(key)}" for key in list(data)[:maximum_records]) or (
            "json:/",
        )
    if isinstance(data, list):
        return tuple(f"json:/{index}" for index in range(min(len(data), maximum_records))) or (
            "json:/",
        )
    return ("json:/",)


def _truncate_json_lists(data: Any, maximum_records: int) -> tuple[Any, int]:
    """Bound list breadth throughout a JSON response while preserving object fields."""

    if isinstance(data, list):
        omitted = max(0, len(data) - maximum_records)
        normalized: list[Any] = []
        for item in data[:maximum_records]:
            bounded, child_omitted = _truncate_json_lists(item, maximum_records)
            normalized.append(bounded)
            omitted += child_omitted
        return normalized, omitted
    if isinstance(data, dict):
        normalized_object: dict[str, Any] = {}
        omitted = 0
        for key, value in data.items():
            bounded, child_omitted = _truncate_json_lists(value, maximum_records)
            normalized_object[key] = bounded
            omitted += child_omitted
        return normalized_object, omitted
    return data, 0


def _json_pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _matches_named_origin(capability_id: str, source_url: str) -> bool:
    routes = _NAMED_API_ROUTES.get(capability_id, ())
    try:
        parts = urlsplit(source_url)
        port = parts.port
        host = (parts.hostname or "").encode("idna").decode("ascii").casefold().rstrip(".")
    except (UnicodeError, ValueError):
        return False
    scheme = parts.scheme.casefold()
    valid_origin = (scheme == "https" and port in {None, 443}) or (
        capability_id in _PUBLIC_HTTP_NAMED_CAPABILITIES
        and scheme == "http"
        and port in {None, 80}
    )
    if (
        not valid_origin
        or parts.username is not None
        or parts.password is not None
    ):
        return False
    path = parts.path or "/"
    for expected_host, prefixes in routes:
        if host != expected_host:
            continue
        if any(
            prefix == "/"
            or path == prefix
            or path.startswith(prefix.rstrip("/") + "/")
            for prefix in prefixes
        ):
            return True
    return False
