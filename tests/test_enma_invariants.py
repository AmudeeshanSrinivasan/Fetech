"""Behavioral baseline generalized from the verified ENMA 30-test fetch seam."""

from __future__ import annotations

import io
import zipfile
from pathlib import Path
from uuid import uuid4

import pytest

from fetech.adapters.archive import _extract_members
from fetech.adapters.documents import _detect_capability, _parse
from fetech.context import ContextBudget
from fetech.ledger import EventLedger
from fetech.models import FetchRequest, PageState, ProvenanceEvent, ResourceBudget
from fetech.planning import DeterministicPlanner, classify_target
from fetech.quality import assess_text
from fetech.registry import CapabilityKind, CapabilityRegistry
from fetech.security import (
    PolicyBlockedError,
    SafeURLPolicy,
    ensure_safe_redirect,
    normalize_url,
    sanitize_url,
)
from fetech.storage import CacheKey, FileSystemCAS
from fetech.variants import clean_query_parameters, generate_variants


def test_01_attempt_order_never_downgrades_https() -> None:
    variants = generate_variants("https://example.com/article")
    assert variants[0] == "https://example.com/article"
    assert all(not value.startswith("http://") for value in variants)


def test_02_plan_is_deterministic_except_identity_fields() -> None:
    planner = DeterministicPlanner(CapabilityRegistry())
    request = FetchRequest(target="https://example.com")
    first, second = planner.plan(request), planner.plan(request)
    assert [node.model_dump() for node in first.nodes] == [node.model_dump() for node in second.nodes]


def test_03_normalizer_deduplicates_default_ports() -> None:
    assert normalize_url("https://EXAMPLE.com:443") == "https://example.com/"


def test_04_query_cleaner_removes_tracking_only() -> None:
    cleaned = clean_query_parameters("https://example.com/?q=keep&utm_source=x&fbclid=y")
    assert cleaned == "https://example.com/?q=keep"


def test_05_credentials_in_url_are_forbidden() -> None:
    with pytest.raises(ValueError, match="credentials"):
        normalize_url("https://user:secret@example.com/")


@pytest.mark.asyncio
async def test_06_browser_boundary_blocks_localhost_before_worker() -> None:
    with pytest.raises(PolicyBlockedError):
        await SafeURLPolicy().evaluate("http://localhost/")


@pytest.mark.asyncio
async def test_07_private_dns_result_is_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    policy = SafeURLPolicy()

    async def private(_: str, __: int) -> tuple[str, ...]:
        return ("10.0.0.8",)

    monkeypatch.setattr(policy, "_resolve", private)
    with pytest.raises(PolicyBlockedError, match="non-public"):
        await policy.evaluate("https://example.com/")


def test_08_https_redirect_downgrade_is_blocked() -> None:
    with pytest.raises(PolicyBlockedError):
        ensure_safe_redirect("https://example.com", "http://example.com")


def test_09_sensitive_urls_are_redacted() -> None:
    assert sanitize_url("https://user:pw@example.com/x?token=secret&q=yes#part") == (
        "https://example.com/x?token=%5BREDACTED%5D&q=yes"
    )


def test_10_page_state_ok() -> None:
    assert assess_text("useful article " * 10).page_state == PageState.OK


def test_11_page_state_empty() -> None:
    assert assess_text(" ").page_state == PageState.EMPTY


def test_12_page_state_login() -> None:
    assert assess_text("Sign in and enter your password").page_state == PageState.LOGIN


def test_13_page_state_captcha() -> None:
    assert assess_text("Verify you are human with this CAPTCHA").page_state == PageState.CAPTCHA


def test_14_page_state_bot_block() -> None:
    assert assess_text("Access denied due to unusual traffic").page_state == PageState.BOT_BLOCK


def test_15_page_state_paywall() -> None:
    assert assess_text("Subscribe to continue reading").page_state == PageState.PAYWALL


def test_16_non_ok_page_state_is_checked_only() -> None:
    assessment = assess_text("Subscription required to unlock this article")
    assert not assessment.accepted


def test_17_target_classifier_prefers_document_intent() -> None:
    assert classify_target("https://example.com/no-extension", ("document",)) == "document"


def test_18_target_classifier_recognizes_pdf() -> None:
    assert classify_target("https://example.com/report.pdf", ("clean_text",)) == "document"


def test_19_target_classifier_recognizes_media() -> None:
    assert classify_target("https://example.com/video.mp4", ("clean_text",)) == "media"


def test_20_target_classifier_recognizes_api() -> None:
    assert classify_target("https://example.com/data.json", ("clean_text",)) == "api"


def test_21_content_router_prefers_file_signature() -> None:
    assert _detect_capability("document_router", "https://example.com/wrong.txt", b"%PDF-1.7") == "pdf"


def test_22_plain_text_preserves_locator() -> None:
    document, locators, parser = _parse("plain_text_file", b"hello")
    assert document["blocks"][0]["text"] == "hello"
    assert locators == ("line:1",)
    assert parser == "text"


def test_23_csv_preserves_row_locators() -> None:
    document, locators, _ = _parse("csv", b"a,b\n1,2\n")
    assert len(document["blocks"]) == 2
    assert locators == ("row:1", "row:2")


def test_24_safe_zip_extracts_with_member_locator() -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("folder/file.txt", "hello")
    assert _extract_members(stream.getvalue(), maximum_members=5, maximum_expanded=100, maximum_ratio=10)[
        0
    ] == (
        "folder/file.txt",
        b"hello",
    )


def test_25_archive_traversal_is_blocked() -> None:
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../escape.txt", "bad")
    with pytest.raises(ValueError, match="traversal"):
        _extract_members(stream.getvalue(), maximum_members=5, maximum_expanded=100, maximum_ratio=10)


def test_26_registry_freezes_thirteen_categories_and_155_ids() -> None:
    registry = CapabilityRegistry()
    assert len(registry.categories) == 13
    assert len(registry) == 155


def test_27_alias_does_not_increase_capability_count() -> None:
    registry = CapabilityRegistry()
    assert registry.resolve_id("playwright_render") == "playwright"
    assert len(registry) == 155


def test_28_every_manifest_entry_has_kind_reference_and_test() -> None:
    for entry in CapabilityRegistry():
        assert isinstance(entry.kind, CapabilityKind)
        assert entry.reference
        assert entry.tests


def test_29_authenticated_cache_scope_isolated() -> None:
    public = CacheKey("https://example.com", "text", "public", "default", "", "v1")
    private = CacheKey("https://example.com", "text", "auth:user-1", "default", "", "v1")
    assert public.digest != private.digest


@pytest.mark.asyncio
async def test_30_event_ledger_redacts_secrets_and_cas_deduplicates(tmp_path: Path) -> None:
    cas = FileSystemCAS(tmp_path / "cas")
    first = await cas.put(b"same")
    second = await cas.put(b"same")
    assert first == second
    assert await cas.verify(first[0])

    ledger = EventLedger.sqlite(tmp_path / "events.sqlite3")
    await ledger.initialize()
    run_id = uuid4()
    await ledger.create_run(
        run_id,
        FetchRequest(target="https://example.com", budget=ResourceBudget()).model_dump(mode="json"),
        ProvenanceEvent(run_id=run_id, event_type="created", actor="test").timestamp,
    )
    await ledger.append(
        ProvenanceEvent(
            run_id=run_id,
            event_type="secret.test",
            actor="test",
            payload={"token": "never-store-me", "safe": "yes"},
        )
    )
    stored = await ledger.events(run_id)
    assert stored[0].payload == {"safe": "yes", "token": "[REDACTED]"}
    assert ContextBudget().total_tokens == 4_000
    await ledger.close()
