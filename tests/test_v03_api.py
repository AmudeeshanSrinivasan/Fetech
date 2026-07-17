from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import httpx
import pytest

from fetech.adapters.api import (
    API_CAPABILITIES,
    StructuredAPIAdapter,
    detect_named_api,
)
from fetech.adapters.base import AdapterExecutionError, ExecutionContext
from fetech.adapters.http import HTTPAdapter
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    FetchRequest,
    PlanNode,
    QualityAssessment,
    Resource,
)
from fetech.security import PolicyBlockedError, SafeURLPolicy, sanitize_url
from fetech.storage import FileSystemCAS, build_artifact

_RSS = b"""\
<rss version="2.0"><channel><title>Updates</title><link>https://publisher.example/</link>
<description>Authoritative updates</description><item><title>One</title>
<link>https://publisher.example/one</link><guid>one</guid>
<description>First useful item</description></item></channel></rss>
"""
_ATOM = b"""\
<feed xmlns="http://www.w3.org/2005/Atom"><title>Research</title>
<id>https://publisher.example/feed</id><updated>2026-07-17T00:00:00Z</updated>
<entry><title>Paper</title><id>paper-1</id><link href="https://publisher.example/paper"/>
<summary>Useful research summary</summary><updated>2026-07-17T00:00:00Z</updated></entry></feed>
"""
_SITEMAP = b"""\
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>https://publisher.example/a</loc><lastmod>2026-07-17</lastmod></url>
</urlset>
"""


async def _acquired_context(
    tmp_path: Path,
    *,
    target: str,
    body: bytes,
    media_type: str,
    metadata: dict[str, str] | None = None,
    with_acquisition_attempt: bool = True,
) -> ExecutionContext:
    cas = FileSystemCAS(tmp_path / "cas")
    resource = Resource(
        canonical_url=target,
        requested_url=target,
        authority_url=target,
        media_type=media_type,
        status_code=200,
    )
    uri, digest, size = await cas.put(body)
    raw = build_artifact(
        role="source",
        representation="raw",
        media_type=media_type,
        cas_uri=uri,
        digest=digest,
        size=size,
        resource=resource,
        extractor="httpx/test",
        quality=QualityAssessment(accepted=True, score=1, completeness=1),
    )
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target=target, metadata=metadata or {}),
        cas=cas,
        resources=[resource],
        artifacts=[raw],
    )
    if with_acquisition_attempt:
        context.attempts.append(
            FetchAttempt(
                capability_id="http_get",
                sanitized_destination=sanitize_url(target),
                status=AttemptStatus.SUCCEEDED,
                artifact_ids=(raw.artifact_id,),
            )
        )
    return context


@pytest.mark.parametrize(
    ("capability_id", "target", "media_type", "body", "representation", "observed_format"),
    [
        (
            "rest",
            "https://service.example/v1/items",
            "application/json",
            b'{"items":[{"id":1,"name":"bounded"}]}',
            "api_response",
            "json",
        ),
        (
            "graphql",
            "https://service.example/graphql",
            "application/json",
            b'{"data":{"viewer":{"login":"octocat"}}}',
            "graphql",
            "json",
        ),
        (
            "json_endpoint",
            "https://service.example/data.json",
            "application/problem+json",
            b'{"status":200,"detail":"bounded fixture"}',
            "json",
            "json",
        ),
        (
            "xml_endpoint",
            "https://service.example/data.xml",
            "application/xml",
            b"<result><id>1</id><name>bounded</name></result>",
            "xml",
            "xml",
        ),
        (
            "rss",
            "https://publisher.example/feed.rss",
            "application/rss+xml",
            _RSS,
            "feed",
            "rss",
        ),
        (
            "atom",
            "https://publisher.example/feed.atom",
            "application/atom+xml",
            _ATOM,
            "feed",
            "atom",
        ),
        (
            "sitemap_xml",
            "https://publisher.example/sitemap.xml",
            "application/xml",
            _SITEMAP,
            "sitemap",
            "sitemap_xml",
        ),
        (
            "openapi_discovery",
            "https://service.example/openapi.yaml",
            "application/yaml",
            (
                b"openapi: 3.1.0\ninfo:\n  title: Fixture\n  version: 1.0.0\n"
                b"paths:\n  /items:\n    get:\n      responses:\n        '200':\n"
                b"          description: ok\n"
            ),
            "openapi",
            "openapi",
        ),
        (
            "github_api",
            "https://api.github.com/repos/openai/openai-python",
            "application/vnd.github+json",
            b'{"id":123,"full_name":"openai/openai-python","private":false}',
            "api_response",
            "json",
        ),
        (
            "semantic_scholar_api",
            "https://api.semanticscholar.org/graph/v1/paper/paper-1",
            "application/json",
            b'{"paperId":"paper-1","title":"Bounded parsing"}',
            "api_response",
            "json",
        ),
        (
            "arxiv_api",
            "https://export.arxiv.org/api/query?search_query=all:test",
            "application/atom+xml",
            _ATOM,
            "api_response",
            "atom",
        ),
        (
            "openreview_api",
            "https://api2.openreview.net/notes?id=note-1",
            "application/json",
            b'{"notes":[{"id":"note-1","content":{"title":{"value":"Fixture"}}}],"count":1}',
            "api_response",
            "json",
        ),
        (
            "crossref_openalex_api",
            "https://api.crossref.org/works/10.1000%2Ffixture",
            "application/json",
            b'{"status":"ok","message-type":"work","message":{"DOI":"10.1000/fixture"}}',
            "api_response",
            "json",
        ),
    ],
)
@pytest.mark.asyncio
async def test_all_structured_api_capabilities_normalize_acquired_artifacts(
    capability_id: str,
    target: str,
    media_type: str,
    body: bytes,
    representation: str,
    observed_format: str,
    tmp_path: Path,
) -> None:
    context = await _acquired_context(
        tmp_path,
        target=target,
        body=body,
        media_type=media_type,
    )
    raw = context.artifacts[0]
    resource = context.resources[0]

    await StructuredAPIAdapter().execute(
        PlanNode(id="api", capability_id=capability_id, adapter="api"),
        context,
    )

    derived = context.artifacts[-1]
    assert derived.representation == representation
    assert derived.source_resource_id == resource.resource_id
    assert derived.parent_artifact_ids == (raw.artifact_id,)
    assert derived.quality.accepted is True
    assert context.attempts[-1].status == AttemptStatus.SUCCEEDED
    assert context.attempts[-1].artifact_ids == (derived.artifact_id,)
    outcome = next(
        item
        for item in context.capability_outcomes
        if item.capability_id == capability_id
        and item.status == CapabilityOutcomeStatus.APPLIED
    )
    assert outcome.details["format"] == observed_format
    document = json.loads(await context.cas.get(derived.cas_uri))
    assert document["capability"] == capability_id
    assert document["authority_url"] == sanitize_url(target)
    assert document["source_url"] == sanitize_url(target)
    assert context.accepted is True


def test_capability_inventory_and_named_origin_detection_are_exact() -> None:
    assert {
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
    } == API_CAPABILITIES
    assert detect_named_api("https://api.github.com/repos/openai/openai-python") == "github_api"
    assert (
        detect_named_api("https://api.openalex.org/works/W2741809807")
        == "crossref_openalex_api"
    )
    assert detect_named_api("http://export.arxiv.org/api/query") == "arxiv_api"
    assert detect_named_api("https://api.github.com.attacker.example/repos/x/y") is None
    assert detect_named_api("http://api.github.com/repos/x/y") is None
    assert detect_named_api("https://api.semanticscholar.org.attacker.example/graph/v1") is None


@pytest.mark.asyncio
async def test_adapter_composes_after_safe_http_acquisition(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    transport_calls: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        transport_calls.append(request)
        return httpx.Response(
            200,
            headers={"content-type": "application/json"},
            json={"items": [{"id": 1, "name": "acquired safely"}]},
        )

    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target="https://service.example/v1/items"),
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    await HTTPAdapter(
        user_agent="Fetech/test",
        policy=policy,
        transport=httpx.MockTransport(respond),
    ).execute(
        PlanNode(id="http", capability_id="http_get", adapter="http"),
        context,
    )
    await StructuredAPIAdapter().execute(
        PlanNode(id="api", capability_id="rest", adapter="api", dependencies=("http",)),
        context,
    )
    assert len(transport_calls) == 1
    assert context.artifacts[-1].parent_artifact_ids == (context.artifacts[0].artifact_id,)


@pytest.mark.asyncio
async def test_raw_artifact_without_acquisition_provenance_is_rejected(tmp_path: Path) -> None:
    context = await _acquired_context(
        tmp_path,
        target="https://service.example/data.json",
        body=b'{"safe":true}',
        media_type="application/json",
        with_acquisition_attempt=False,
    )
    with pytest.raises(AdapterExecutionError, match="acquisition provenance"):
        await StructuredAPIAdapter().execute(
            PlanNode(id="api", capability_id="json_endpoint", adapter="api"),
            context,
        )
    assert context.attempts[-1].status == AttemptStatus.FAILED
    assert context.artifacts[-1].representation == "raw"


@pytest.mark.asyncio
async def test_xml_dtd_and_entity_declarations_are_rejected(tmp_path: Path) -> None:
    body = b'<!DOCTYPE result [<!ENTITY secret SYSTEM "file:///etc/passwd">]><result>&secret;</result>'
    context = await _acquired_context(
        tmp_path,
        target="https://service.example/data.xml",
        body=body,
        media_type="application/xml",
    )
    with pytest.raises(AdapterExecutionError, match="invalid or exceeds"):
        await StructuredAPIAdapter().execute(
            PlanNode(id="api", capability_id="xml_endpoint", adapter="api"),
            context,
        )
    assert context.attempts[-1].failure_code == "malformed_api_payload"
    assert context.capability_outcomes[-1].status == CapabilityOutcomeStatus.FAILED


@pytest.mark.asyncio
async def test_openapi_yaml_aliases_are_rejected_without_expansion(tmp_path: Path) -> None:
    body = (
        b"openapi: 3.1.0\ninfo: &shared\n  title: Unsafe\n  version: 1.0\n"
        b"paths: {}\nx-copy: *shared\n"
    )
    context = await _acquired_context(
        tmp_path,
        target="https://service.example/openapi.yaml",
        body=body,
        media_type="application/yaml",
    )
    with pytest.raises(AdapterExecutionError, match="invalid or exceeds"):
        await StructuredAPIAdapter().execute(
            PlanNode(id="api", capability_id="openapi_discovery", adapter="api"),
            context,
        )


@pytest.mark.asyncio
async def test_openapi_yaml_duplicate_keys_are_rejected(tmp_path: Path) -> None:
    context = await _acquired_context(
        tmp_path,
        target="https://service.example/openapi.yaml",
        body=(
            b"openapi: 3.1.0\n"
            b"paths:\n"
            b"  /items: {}\n"
            b"  /items:\n"
            b"    get: {}\n"
        ),
        media_type="application/yaml",
    )

    with pytest.raises(AdapterExecutionError, match="invalid or exceeds"):
        await StructuredAPIAdapter().execute(
            PlanNode(
                id="api",
                capability_id="openapi_discovery",
                adapter="api",
            ),
            context,
        )

    assert context.attempts[-1].failure_code == "malformed_api_payload"


@pytest.mark.asyncio
async def test_openapi_external_references_are_recorded_but_never_followed(tmp_path: Path) -> None:
    reference = "https://schemas.example/remote.yaml#/components/schemas/Item"
    context = await _acquired_context(
        tmp_path,
        target="https://service.example/openapi.json",
        body=json.dumps(
            {
                "openapi": "3.1.0",
                "info": {"title": "Fixture", "version": "1.0"},
                "paths": {
                    "/items": {
                        "get": {
                            "responses": {
                                "200": {
                                    "description": "ok",
                                    "content": {
                                        "application/json": {
                                            "schema": {"$ref": reference}
                                        }
                                    },
                                }
                            }
                        }
                    }
                },
            }
        ).encode(),
        media_type="application/json",
    )
    await StructuredAPIAdapter().execute(
        PlanNode(id="api", capability_id="openapi_discovery", adapter="api"),
        context,
    )
    document = json.loads(await context.cas.get(context.artifacts[-1].cas_uri))
    schema = document["data"]["paths"]["/items"]["get"]["responses"]["200"]["content"][
        "application/json"
    ]["schema"]
    assert schema == {"$ref": reference}
    assert len(context.attempts) == 2


@pytest.mark.parametrize(
    ("capability_id", "body", "message"),
    [
        ("rss", b"<rss><channel><title>No version</title></channel></rss>", "version"),
        ("atom", b"<feed><title>No namespace</title></feed>", "namespaced feed root"),
        ("sitemap_xml", b"<feed/>", "urlset or sitemapindex"),
    ],
)
@pytest.mark.asyncio
async def test_feed_schema_markers_are_required(
    capability_id: str,
    body: bytes,
    message: str,
    tmp_path: Path,
) -> None:
    context = await _acquired_context(
        tmp_path,
        target=f"https://publisher.example/{capability_id}.xml",
        body=body,
        media_type="application/xml",
    )
    with pytest.raises(AdapterExecutionError, match=message):
        await StructuredAPIAdapter().execute(
            PlanNode(id="api", capability_id=capability_id, adapter="api"),
            context,
        )


@pytest.mark.asyncio
async def test_parser_byte_and_tree_limits_fail_closed(tmp_path: Path) -> None:
    oversized = await _acquired_context(
        tmp_path / "bytes",
        target="https://service.example/data.json",
        body=b'{"value":"' + (b"x" * 256) + b'"}',
        media_type="application/json",
    )
    with pytest.raises(AdapterExecutionError, match="byte limit"):
        await StructuredAPIAdapter(maximum_parse_bytes=64).execute(
            PlanNode(id="api", capability_id="json_endpoint", adapter="api"),
            oversized,
        )

    too_many_nodes = await _acquired_context(
        tmp_path / "nodes",
        target="https://service.example/data.json",
        body=b'{"items":[1,2,3,4,5,6]}',
        media_type="application/json",
    )
    with pytest.raises(AdapterExecutionError, match="invalid or exceeds"):
        await StructuredAPIAdapter(maximum_nodes=4).execute(
            PlanNode(id="api", capability_id="json_endpoint", adapter="api"),
            too_many_nodes,
        )


@pytest.mark.asyncio
async def test_graphql_response_envelope_and_duplicate_json_keys_are_rejected(
    tmp_path: Path,
) -> None:
    invalid_graphql = await _acquired_context(
        tmp_path / "graphql",
        target="https://service.example/graphql",
        body=b'{"result":"not a GraphQL envelope"}',
        media_type="application/json",
    )
    with pytest.raises(AdapterExecutionError, match="data or errors"):
        await StructuredAPIAdapter().execute(
            PlanNode(id="api", capability_id="graphql", adapter="api"),
            invalid_graphql,
        )

    duplicate = await _acquired_context(
        tmp_path / "duplicate",
        target="https://service.example/data.json",
        body=b'{"id":1,"id":2}',
        media_type="application/json",
    )
    with pytest.raises(AdapterExecutionError, match="invalid or exceeds"):
        await StructuredAPIAdapter().execute(
            PlanNode(id="api", capability_id="json_endpoint", adapter="api"),
            duplicate,
        )


@pytest.mark.asyncio
async def test_named_connector_rejects_lookalike_origin_before_parsing(tmp_path: Path) -> None:
    context = await _acquired_context(
        tmp_path,
        target="https://api.github.com.attacker.example/repos/x/y",
        body=b'{"id":123,"full_name":"x/y"}',
        media_type="application/json",
    )
    with pytest.raises(AdapterExecutionError, match="canonical public API origin"):
        await StructuredAPIAdapter().execute(
            PlanNode(id="api", capability_id="github_api", adapter="api"),
            context,
        )
    assert context.artifacts[-1].representation == "raw"


@pytest.mark.asyncio
async def test_named_connector_requires_a_recognizable_response_schema(tmp_path: Path) -> None:
    context = await _acquired_context(
        tmp_path,
        target="https://api.semanticscholar.org/graph/v1/paper/paper-1",
        body=b'{"unrelated":"valid JSON from an unexpected service"}',
        media_type="application/json",
    )
    with pytest.raises(AdapterExecutionError, match="public API schema"):
        await StructuredAPIAdapter().execute(
            PlanNode(id="api", capability_id="semantic_scholar_api", adapter="api"),
            context,
        )


@pytest.mark.asyncio
async def test_mutating_api_operation_requires_explicit_approval(tmp_path: Path) -> None:
    context = await _acquired_context(
        tmp_path,
        target="https://service.example/items/1",
        body=b'{"deleted":true}',
        media_type="application/json",
    )
    with pytest.raises(PolicyBlockedError, match="explicit approval"):
        await StructuredAPIAdapter().execute(
            PlanNode(
                id="api",
                capability_id="rest",
                adapter="api",
                parameters={"method": "DELETE"},
            ),
            context,
        )
    assert context.attempts[-1].failure_code == "policy"
    assert context.capability_outcomes[-1].status == CapabilityOutcomeStatus.BLOCKED


@pytest.mark.asyncio
async def test_unknown_api_method_is_never_treated_as_an_approved_mutation(
    tmp_path: Path,
) -> None:
    context = await _acquired_context(
        tmp_path,
        target="https://service.example/items",
        body=b'{"ok":true}',
        media_type="application/json",
        metadata={"api_mutation_approved": "true"},
    )
    with pytest.raises(AdapterExecutionError, match="method is unsupported"):
        await StructuredAPIAdapter().execute(
            PlanNode(
                id="api",
                capability_id="rest",
                adapter="api",
                parameters={"method": "CONNECT"},
            ),
            context,
        )


@pytest.mark.asyncio
async def test_payload_links_never_replace_original_source_authority(tmp_path: Path) -> None:
    target = "https://publisher.example/feed.rss"
    context = await _acquired_context(
        tmp_path,
        target=target,
        body=(
            b'<rss version="2.0"><channel><title>Fixture</title><item><title>External</title>'
            b"<link>https://adapter.example/not-authority</link></item></channel></rss>"
        ),
        media_type="application/rss+xml",
    )
    resource_id = context.resources[0].resource_id
    await StructuredAPIAdapter().execute(
        PlanNode(id="api", capability_id="rss", adapter="api"),
        context,
    )
    derived = context.artifacts[-1]
    document = json.loads(await context.cas.get(derived.cas_uri))
    assert document["authority_url"] == target
    assert document["data"]["items"][0]["link"] == "https://adapter.example/not-authority"
    assert derived.source_resource_id == resource_id


@pytest.mark.asyncio
async def test_feed_record_limit_reports_omitted_count(tmp_path: Path) -> None:
    body = (
        b'<rss version="2.0"><channel><title>Fixture</title>'
        b"<item><title>One</title></item><item><title>Two</title></item>"
        b"</channel></rss>"
    )
    context = await _acquired_context(
        tmp_path,
        target="https://publisher.example/feed.rss",
        body=body,
        media_type="application/rss+xml",
    )
    await StructuredAPIAdapter(maximum_records=1).execute(
        PlanNode(id="api", capability_id="rss", adapter="api"),
        context,
    )
    document = json.loads(await context.cas.get(context.artifacts[-1].cas_uri))
    assert len(document["data"]["items"]) == 1
    assert document["omitted_records"] == 1
    assert context.capability_outcomes[0].details["omitted_records"] == 1
