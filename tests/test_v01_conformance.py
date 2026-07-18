from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from importlib.util import find_spec
from pathlib import Path
from uuid import uuid4

import httpx
import pytest
from pydantic import ValidationError
from sqlalchemy import select

from fetech.adapters.base import AdapterBudgetExceededError, ExecutionContext
from fetech.adapters.http import HTTPAdapter
from fetech.adapters.reader import ReaderAdapter
from fetech.browser_reader import BrowserReaderWorker
from fetech.config import Settings
from fetech.conformance import release_report
from fetech.gateway import UniversalFetchGateway
from fetech.http3 import CurlHTTP3Client, HTTP3Response
from fetech.ledger import EventLedger, RunRow
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    FetchRequest,
    PlanNode,
    ResourceBudget,
    ResultStatus,
)
from fetech.quality import assess_text
from fetech.registry import CapabilityRegistry
from fetech.security import PolicyBlockedError, SafeURLPolicy
from fetech.storage import FileSystemCAS


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        data_dir=tmp_path,
        database_path=tmp_path / "ledger.sqlite3",
        artifact_dir=tmp_path / "artifacts",
        runtime_graph_path=tmp_path / "runtime-graph" / "graph.json",
        per_host_min_interval_seconds=0,
    )


def _public_policy(monkeypatch: pytest.MonkeyPatch) -> SafeURLPolicy:
    policy = SafeURLPolicy()

    async def public(_: str, __: int) -> tuple[str, ...]:
        return ("93.184.216.34",)

    monkeypatch.setattr(policy, "_resolve", public)
    return policy


def test_v01_inventory_is_truthful_and_cardinality_locked() -> None:
    registry = CapabilityRegistry()
    entries = [entry for entry in registry if entry.closure_release == "v0.1"]
    report = release_report(entries)
    assert len(entries) == 56
    assert report == {
        "release": "v0.1",
        "capability_count": 56,
        "implementation_path_count": 56,
        "runtime_available_count": 51,
        "closure_ready": True,
        "status_counts": {"native": 51, "optional": 5},
        "gaps": [],
    }
    assert all(entry.implementation for entry in entries)
    assert all(entry.tests for entry in entries)


def test_request_rejects_zero_execution_budget() -> None:
    with pytest.raises(ValidationError, match="at least one attempt"):
        FetchRequest(
            target="https://example.com",
            budget=ResourceBudget(attempts=0),
        )


@pytest.mark.asyncio
async def test_run_ledger_redacts_target_query_secrets(tmp_path: Path) -> None:
    request = FetchRequest(
        target="https://example.com/private?token=never-store&q=ok",
        metadata={"api_key": "also-never-store"},
    )
    ledger = EventLedger.sqlite(tmp_path / "ledger.sqlite3")
    await ledger.initialize()
    run_id = uuid4()
    await ledger.create_run(run_id, request.model_dump(mode="json"), datetime.now(UTC))
    async with ledger.sessions() as session:
        row = await session.scalar(select(RunRow).where(RunRow.run_id == str(run_id)))
    assert row is not None
    stored = json.loads(row.request_json)
    assert stored["target"] == "https://example.com/private?token=%5BREDACTED%5D&q=ok"
    assert stored["metadata"]["api_key"] == "[REDACTED]"
    await ledger.close()


@pytest.mark.parametrize(
    ("http_status", "result_status"),
    [(401, ResultStatus.AUTH_REQUIRED), (403, ResultStatus.AUTH_REQUIRED), (404, ResultStatus.NOT_FOUND)],
)
@pytest.mark.asyncio
async def test_http_terminal_statuses_are_typed_without_retries(
    http_status: int,
    result_status: ResultStatus,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy = _public_policy(monkeypatch)
    gateway = UniversalFetchGateway(_settings(tmp_path))
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=policy,
        transport=httpx.MockTransport(lambda _: httpx.Response(http_status)),
    )
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(FetchRequest(target="https://example.com/missing"))
    assert result.status == result_status
    assert len(result.attempts) == 1
    await gateway.close()


@pytest.mark.asyncio
async def test_attempt_budget_is_cumulative_and_reported(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    policy = _public_policy(monkeypatch)

    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text="<main>Useful bounded fixture content for budget accounting.</main>",
        )

    gateway = UniversalFetchGateway(_settings(tmp_path))
    gateway.adapters["http"] = HTTPAdapter(
        user_agent=gateway.settings.user_agent,
        policy=policy,
        transport=httpx.MockTransport(respond),
    )
    gateway.executor.adapters = gateway.adapters
    result = await gateway.fetch(
        FetchRequest(
            target="https://example.com/article",
            budget=ResourceBudget(attempts=1),
        )
    )
    assert result.status == ResultStatus.BUDGET_EXHAUSTED
    assert result.remaining_budget.attempts == 0
    assert len(result.attempts) == 1
    assert any(diagnostic.code == "budget_exhausted" for diagnostic in result.diagnostics)
    await gateway.close()


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("capability_id", "expected_method", "expected_header"),
    [
        ("http_head", "HEAD", None),
        ("browser_header_http", "GET", "sec-fetch-mode"),
        ("range_request", "GET", "range"),
    ],
)
async def test_http_operation_modes_are_explicit(
    capability_id: str,
    expected_method: str,
    expected_header: str | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: list[httpx.Request] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        observed.append(request)
        return httpx.Response(200, headers={"content-type": "text/plain"}, text="useful response")

    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target="https://example.com", output_requirements=(capability_id,)),
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    await adapter.execute(
        PlanNode(id="http", capability_id=capability_id, adapter="http"),
        context,
    )
    assert observed[0].method == expected_method
    if expected_header:
        assert expected_header in observed[0].headers


@pytest.mark.asyncio
async def test_explicit_http3_uses_validated_pinned_transport(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeHTTP3Client(CurlHTTP3Client):
        def __init__(self) -> None:
            self.addresses: list[str] = []

        async def fetch(
            self,
            url: str,
            *,
            address: str,
            user_agent: str,
            timeout_seconds: float,
            maximum_bytes: int,
        ) -> HTTP3Response:
            del url, user_agent, timeout_seconds, maximum_bytes
            self.addresses.append(address)
            return HTTP3Response(200, "text/plain", "", "3", b"useful HTTP3 response")

    client = FakeHTTP3Client()
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target="https://example.com", output_requirements=("http_3",)),
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        http3_client=client,
    )
    await adapter.execute(PlanNode(id="http", capability_id="http_get", adapter="http"), context)
    assert client.addresses == ["93.184.216.34"]
    outcome = next(item for item in context.capability_outcomes if item.capability_id == "http_3")
    assert outcome.status == CapabilityOutcomeStatus.OBSERVED


@pytest.mark.asyncio
async def test_http_post_requires_explicit_approval(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(lambda _: httpx.Response(200)),
    )
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target="https://example.com", output_requirements=("http_post",)),
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    with pytest.raises(PolicyBlockedError, match="explicit"):
        await adapter.execute(
            PlanNode(id="http", capability_id="http_post", adapter="http"),
            context,
        )


@pytest.mark.asyncio
async def test_crawl_robots_disallow_blocks_target_before_fetch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    paths: list[str] = []

    async def respond(request: httpx.Request) -> httpx.Response:
        paths.append(request.url.path)
        if request.url.path == "/robots.txt":
            return httpx.Response(200, text="User-agent: *\nDisallow: /private")
        return httpx.Response(200, text="must not be fetched")

    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target="https://example.com/private", intent="crawl"),
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    with pytest.raises(PolicyBlockedError, match=r"robots\.txt disallows"):
        await adapter.execute(
            PlanNode(id="http", capability_id="http_get", adapter="http"),
            context,
        )
    assert paths == ["/robots.txt"]
    outcome = next(
        item for item in context.capability_outcomes if item.capability_id == "robots_policy_check"
    )
    assert outcome.status == CapabilityOutcomeStatus.BLOCKED


@pytest.mark.asyncio
async def test_html_navigation_metadata_is_observed_not_followed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def respond(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            headers={"content-type": "text/html"},
            text=(
                '<meta http-equiv="refresh" content="0; url=/next">'
                '<link rel="canonical" href="/canonical">'
                '<meta property="og:url" content="/social">'
                '<script>window.location = "/script";</script>'
                "<main>Useful content remains authoritative.</main>"
            ),
        )

    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target="https://example.com/start"),
        cas=FileSystemCAS(tmp_path / "cas"),
    )
    adapter = HTTPAdapter(
        user_agent="Fetech/test",
        policy=_public_policy(monkeypatch),
        transport=httpx.MockTransport(respond),
    )
    await adapter.execute(PlanNode(id="http", capability_id="http_get", adapter="http"), context)
    outcomes = {
        outcome.capability_id: outcome
        for outcome in context.capability_outcomes
        if outcome.capability_id.endswith("redirect")
    }
    assert all(outcome.status == CapabilityOutcomeStatus.OBSERVED for outcome in outcomes.values())
    assert all(outcome.details["followed"] is False for outcome in outcomes.values())


@pytest.mark.asyncio
async def test_builtin_main_reader_prefers_article_content(tmp_path: Path) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(target="https://example.com"),
        cas=cas,
    )
    from fetech.models import QualityAssessment, Resource
    from fetech.storage import build_artifact

    resource = Resource(canonical_url="https://example.com/", requested_url="https://example.com/")
    body = b"<nav>noise</nav><article>The important article text is here.</article>"
    uri, digest, size = await cas.put(body)
    context.resources.append(resource)
    context.artifacts.append(
        build_artifact(
            role="source",
            representation="raw",
            media_type="text/html",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor="fixture",
            quality=QualityAssessment(),
        )
    )
    await ReaderAdapter().execute(
        PlanNode(id="reader", capability_id="main_article", adapter="reader"),
        context,
    )
    extracted = await cas.get(context.artifacts[-1].cas_uri)
    assert extracted == b"The important article text is here."


@pytest.mark.asyncio
async def test_browser_reader_mode_uses_isolated_worker_boundary(tmp_path: Path) -> None:
    from fetech.models import QualityAssessment, Resource
    from fetech.storage import build_artifact

    class FakeBrowserReader(BrowserReaderWorker):
        async def extract(
            self,
            document: str,
            *,
            target: str,
            user_agent: str,
            timeout_seconds: float,
            maximum_bytes: int,
        ) -> str:
            assert "<article>" in document
            assert target == "https://example.com"
            assert user_agent.startswith("Fetech/")
            assert timeout_seconds > 0
            assert maximum_bytes > 0
            return "Offline browser reader extracted this article."

    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(
            target="https://example.com",
            output_requirements=("browser_reader_mode",),
        ),
        cas=cas,
    )
    resource = Resource(canonical_url="https://example.com/", requested_url="https://example.com/")
    body = b"<article>browser reader source</article>"
    uri, digest, size = await cas.put(body)
    context.resources.append(resource)
    context.artifacts.append(
        build_artifact(
            role="source",
            representation="raw",
            media_type="text/html",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor="fixture",
            quality=QualityAssessment(),
        )
    )
    await ReaderAdapter(browser_reader=FakeBrowserReader()).execute(
        PlanNode(id="reader", capability_id="browser_reader_mode", adapter="reader"),
        context,
    )
    artifact = context.artifacts[-1]
    assert artifact.extractor_version.startswith("offline-browser-reader/")
    assert artifact.source_resource_id == resource.resource_id


@pytest.mark.skipif(find_spec("playwright") is not None, reason="Playwright is installed")
@pytest.mark.asyncio
async def test_browser_reader_reports_missing_optional_dependency() -> None:
    from fetech.adapters.base import AdapterDependencyError

    with pytest.raises(AdapterDependencyError, match=r"fetech\[browser\]"):
        await BrowserReaderWorker().extract(
            "<main>offline document</main>",
            target="https://example.com",
            user_agent="Fetech/test",
            timeout_seconds=3,
            maximum_bytes=10_000,
        )


@pytest.mark.asyncio
async def test_browser_reader_exit_two_without_json_is_dependency_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fetech.adapters.base import AdapterDependencyError
    from fetech.logic.process import ProcessResult

    async def missing_worker(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
        maximum_file_bytes: int | None,
        isolation: object,
    ) -> ProcessResult:
        del (
            arguments,
            stdin,
            timeout_seconds,
            memory_mb,
            maximum_output_bytes,
            maximum_file_bytes,
            isolation,
        )
        return ProcessResult(returncode=2, stdout=b"", stderr=b"private worker detail")

    monkeypatch.setattr("fetech.browser_reader.run_bounded", missing_worker)
    with pytest.raises(AdapterDependencyError, match=r"installed Chromium binary") as caught:
        await BrowserReaderWorker().extract(
            "<main>offline document</main>",
            target="https://example.com",
            user_agent="Fetech/test",
            timeout_seconds=3,
            maximum_bytes=10_000,
        )
    assert "private worker detail" not in str(caught.value)


@pytest.mark.asyncio
async def test_browser_reader_crash_is_typed_bounded_and_does_not_leak_stderr(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fetech.adapters.base import AdapterExecutionError
    from fetech.logic.process import ProcessResult

    observed_memory_mb = 0

    async def crashed_worker(
        arguments: tuple[str, ...],
        stdin: bytes,
        *,
        timeout_seconds: float,
        memory_mb: int,
        maximum_output_bytes: int,
        maximum_file_bytes: int | None,
        isolation: object,
    ) -> ProcessResult:
        del (
            arguments,
            stdin,
            timeout_seconds,
            maximum_output_bytes,
            maximum_file_bytes,
            isolation,
        )
        nonlocal observed_memory_mb
        observed_memory_mb = memory_mb
        return ProcessResult(returncode=-9, stdout=b"", stderr=b"private worker detail")

    monkeypatch.setattr("fetech.browser_reader.run_bounded", crashed_worker)
    with pytest.raises(AdapterExecutionError, match=r"exited without output") as caught:
        await BrowserReaderWorker().extract(
            "<main>offline document</main>",
            target="https://example.com",
            user_agent="Fetech/test",
            timeout_seconds=3,
            maximum_bytes=10_000,
        )
    assert observed_memory_mb == 2 * 1024 * 1024
    assert "private worker detail" not in str(caught.value)


@pytest.mark.asyncio
async def test_configured_remote_reader_is_policy_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from fetech.models import QualityAssessment, Resource
    from fetech.storage import build_artifact

    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(
            target="https://example.com",
            output_requirements=("jina_reader",),
            policy_profile="allow_remote_readers",
        ),
        cas=cas,
    )
    resource = Resource(canonical_url="https://example.com/", requested_url="https://example.com/")
    uri, digest, size = await cas.put(b"<main>original publisher body</main>")
    context.resources.append(resource)
    context.artifacts.append(
        build_artifact(
            role="source",
            representation="raw",
            media_type="text/html",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor="fixture",
            quality=QualityAssessment(),
        )
    )

    async def remote(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "reader.example"
        assert "https%3A%2F%2Fexample.com" in str(request.url)
        return httpx.Response(200, text="Remote reader output with useful article content.")

    adapter = ReaderAdapter(
        remote_reader_template="https://reader.example/read?url={target}",
        policy=_public_policy(monkeypatch),
        remote_transport=httpx.MockTransport(remote),
    )
    await adapter.execute(
        PlanNode(id="reader", capability_id="jina_reader", adapter="reader"),
        context,
    )
    artifact = context.artifacts[-1]
    assert artifact.source_resource_id == resource.resource_id
    assert artifact.extractor_version.startswith("jina-reader/")


@pytest.mark.asyncio
async def test_remote_reader_is_capped_by_the_remaining_decompressed_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fetech.models import QualityAssessment, Resource
    from fetech.storage import build_artifact

    cas = FileSystemCAS(tmp_path / "cas")
    context = ExecutionContext(
        run_id=uuid4(),
        request=FetchRequest(
            target="https://example.com",
            output_requirements=("jina_reader",),
            policy_profile="allow_remote_readers",
            budget=ResourceBudget(decompressed_bytes=20),
        ),
        cas=cas,
    )
    resource = Resource(canonical_url="https://example.com/", requested_url="https://example.com/")
    uri, digest, size = await cas.put(b"<main>original publisher body</main>")
    context.resources.append(resource)
    context.artifacts.append(
        build_artifact(
            role="source",
            representation="raw",
            media_type="text/html",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor="fixture",
            quality=QualityAssessment(),
        )
    )

    async def remote(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 21)

    adapter = ReaderAdapter(
        remote_reader_template="https://reader.example/read?url={target}",
        policy=_public_policy(monkeypatch),
        remote_transport=httpx.MockTransport(remote),
    )
    with pytest.raises(
        AdapterBudgetExceededError,
        match="remaining decompressed byte budget",
    ):
        await adapter.execute(
            PlanNode(id="reader", capability_id="jina_reader", adapter="reader"),
            context,
        )


@pytest.mark.asyncio
async def test_remote_reader_and_publisher_http_share_the_wire_byte_budget(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from fetech.models import QualityAssessment, Resource
    from fetech.storage import build_artifact

    publisher_body = b"<main>publisher body</main>"
    remote_body = b"x" * 21
    budget = ResourceBudget(
        bytes=len(publisher_body) + len(remote_body) - 1,
        decompressed_bytes=1_000,
    )
    cas = FileSystemCAS(tmp_path / "cas")
    request = FetchRequest(
        target="https://example.com",
        output_requirements=("jina_reader",),
        policy_profile="allow_remote_readers",
        budget=budget,
    )
    context = ExecutionContext(run_id=uuid4(), request=request, cas=cas)
    resource = Resource(
        canonical_url="https://example.com/",
        requested_url="https://example.com/",
    )
    uri, digest, size = await cas.put(publisher_body)
    context.resources.append(resource)
    context.artifacts.append(
        build_artifact(
            role="source",
            representation="raw",
            media_type="text/html",
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor="fixture",
            quality=QualityAssessment(),
        )
    )
    context.attempts.append(
        FetchAttempt(
            capability_id="http_get",
            sanitized_destination=request.target,
            status=AttemptStatus.SUCCEEDED,
            consumed_budget={
                "bytes": len(publisher_body),
                "decompressed_bytes": len(publisher_body),
            },
        )
    )

    async def remote(_: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=remote_body)

    adapter = ReaderAdapter(
        remote_reader_template="https://reader.example/read?url={target}",
        policy=_public_policy(monkeypatch),
        remote_transport=httpx.MockTransport(remote),
    )

    with pytest.raises(
        AdapterBudgetExceededError,
        match="remaining wire byte budget",
    ):
        await adapter.execute(
            PlanNode(id="reader", capability_id="jina_reader", adapter="reader"),
            context,
        )

    assert context.attempts[-1].consumed_budget == {"bytes": len(remote_body)}
    assert sum(
        int(attempt.consumed_budget.get("bytes", 0))
        for attempt in context.attempts
    ) > budget.bytes


def test_deterministic_language_detection_marks_mismatch() -> None:
    quality = assess_text(
        "Este es el contenido de la pagina y que contiene informacion para los lectores.",
        expected_language="en",
    )
    assert quality.language == "es"
    assert quality.page_state.value == "WRONG_LANGUAGE"
    assert quality.accepted is False


def test_cache_expiry_check_has_deterministic_freshness_semantics() -> None:
    from fetech.models import Artifact, QualityAssessment, Resource
    from fetech.storage import CacheKey, CacheRecord

    now = datetime.now(UTC)
    resource = Resource(canonical_url="https://example.com/", requested_url="https://example.com/")
    artifact = Artifact(
        role="source",
        representation="raw",
        media_type="text/plain",
        cas_uri="cas://sha256/" + "a" * 64,
        sha256="a" * 64,
        size=1,
        source_resource_id=resource.resource_id,
        extractor_version="fixture",
        quality=QualityAssessment(),
    )
    key = CacheKey(
        url="https://example.com/",
        representation="raw",
        authentication_scope="public",
        policy_profile="default",
        language="",
        parser_version="fixture",
    )
    assert CacheRecord(key=key, resource=resource, artifact=artifact, expires_at=now + timedelta(1)).fresh
    assert not CacheRecord(
        key=key,
        resource=resource,
        artifact=artifact,
        expires_at=now - timedelta(1),
    ).fresh
