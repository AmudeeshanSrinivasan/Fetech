"""Scoped MCP tools for fetching, traces, provenance, and bounded context."""

from __future__ import annotations

import os
from collections.abc import Mapping
from pathlib import Path
from typing import Literal

from fetech.adapters.cache import SnapshotConnector
from fetech.adapters.documents import GitLFSResolver, PDFOCRProvider
from fetech.adapters.media import MediaAdapter
from fetech.auth import CredentialProvider
from fetech.auth_flows import FormSubmissionProvider, SessionProvider
from fetech.config import Settings
from fetech.context import ContextBroker
from fetech.contracts import contract_manifest
from fetech.errors import (
    invalid_parameter,
    validate_context_request,
    validate_fetch_request,
    validate_uuid,
    validation_exception,
)
from fetech.failures import failure_catalogue
from fetech.gateway import UniversalFetchGateway
from fetech.models import FetchRequest


def _fetch_request(
    target: str,
    outputs: list[str] | None,
    maximum_bytes: int,
    authentication_ref: str | None,
    privacy_profile: Literal["public", "private"],
    approved_capabilities: list[str] | None,
) -> FetchRequest:
    return validate_fetch_request(
        {
            "target": target,
            "output_requirements": outputs or ["clean_text"],
            "authentication_ref": authentication_ref,
            "privacy_profile": privacy_profile,
            "approved_capabilities": approved_capabilities or [],
            "budget": {"bytes": maximum_bytes},
        }
    )


def build_server(
    *,
    credential_provider: CredentialProvider | None = None,
    session_provider: SessionProvider | None = None,
    form_submission_provider: FormSubmissionProvider | None = None,
    git_lfs_resolver: GitLFSResolver | None = None,
    pdf_ocr_provider: PDFOCRProvider | None = None,
    media_adapter: MediaAdapter | None = None,
    snapshot_connectors: Mapping[str, SnapshotConnector] | None = None,
) -> object:
    """Build the scoped MCP server with configured opaque-material providers.

    Session descriptors and credential material remain separate injected
    boundaries; MCP receives only opaque references.
    """

    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("install fetech[mcp] to run the MCP server") from exc

    server = FastMCP("fetech-context")
    gateway = UniversalFetchGateway(
        credential_provider=credential_provider,
        session_provider=session_provider,
        form_submission_provider=form_submission_provider,
        git_lfs_resolver=git_lfs_resolver,
        pdf_ocr_provider=pdf_ocr_provider,
        media_adapter=media_adapter,
        snapshot_connectors=snapshot_connectors,
    )
    repository = Path(os.environ.get("FETECH_REPOSITORY", Path.cwd())).resolve()
    vault_value = os.environ.get("FETECH_OBSIDIAN_VAULT")
    broker = ContextBroker(
        repository,
        runtime_graph=Settings.from_environment().runtime_graph_path,
        vault=Path(vault_value) if vault_value else None,
    )

    @server.tool()
    async def fetch_content(
        target: str,
        outputs: list[str] | None = None,
        maximum_bytes: int = 10_000_000,
        authentication_ref: str | None = None,
        privacy_profile: Literal["public", "private"] = "public",
        approved_capabilities: list[str] | None = None,
    ) -> str:
        """Fetch content using opaque auth references and explicit capability approvals."""
        request = _fetch_request(
            target,
            outputs,
            maximum_bytes,
            authentication_ref,
            privacy_profile,
            approved_capabilities,
        )
        return (await gateway.fetch(request)).model_dump_json()

    @server.tool()
    async def submit_fetch(
        target: str,
        outputs: list[str] | None = None,
        maximum_bytes: int = 10_000_000,
        authentication_ref: str | None = None,
        privacy_profile: Literal["public", "private"] = "public",
        approved_capabilities: list[str] | None = None,
    ) -> str:
        """Submit a fetch and return its run identifier without waiting for completion."""
        request = _fetch_request(
            target,
            outputs,
            maximum_bytes,
            authentication_ref,
            privacy_profile,
            approved_capabilities,
        )
        return (await gateway.submit(request)).model_dump_json()

    @server.tool()
    async def cancel_fetch(run_id: str) -> str:
        """Idempotently cancel an active fetch run."""

        return (await gateway.cancel(validate_uuid(run_id, "run_id"))).model_dump_json()

    @server.tool()
    async def inspect_target(target: str) -> str:
        """Normalize, classify, and policy-check a public target without fetching its body."""
        return (await gateway.inspect(FetchRequest(target=target))).model_dump_json()

    @server.tool()
    async def crawl_domain(target: str, maximum_pages: int = 20, maximum_depth: int = 2) -> str:
        """Submit a bounded domain crawl request."""
        if not 1 <= maximum_pages <= 99:
            raise invalid_parameter(("maximum_pages",), code="less_than_equal")
        request = validate_fetch_request(
            {
                "target": target,
                "intent": "crawl",
                "budget": {
                    "attempts": maximum_pages + 1,
                    "crawl_pages": maximum_pages,
                    "crawl_depth": maximum_depth,
                },
            }
        )
        return (await gateway.fetch(request)).model_dump_json()

    @server.tool()
    async def extract_document(target: str) -> str:
        """Acquire a document and route it to a registered document parser."""
        return (
            await gateway.fetch(FetchRequest(target=target, output_requirements=("document",)))
        ).model_dump_json()

    @server.tool()
    async def extract_media(target: str) -> str:
        """Acquire media and route it to a registered media parser."""
        return (
            await gateway.fetch(FetchRequest(target=target, output_requirements=("video",)))
        ).model_dump_json()

    @server.tool()
    async def get_fetch_trace(run_id: str) -> str:
        """Return the stored run snapshot and its sanitized event trace."""
        identifier = validate_uuid(run_id, "run_id")
        snapshot = await gateway.get_run(identifier)
        events = await gateway.provenance(identifier)
        return "\n".join([snapshot.model_dump_json(), *(event.model_dump_json() for event in events)])

    @server.tool()
    async def query_provenance(run_id: str) -> str:
        """Query immutable provenance events for one run."""
        identifier = validate_uuid(run_id, "run_id")
        return "\n".join(event.model_dump_json() for event in await gateway.provenance(identifier))

    @server.tool()
    async def get_context(question: str, token_budget: int = 4_000) -> str:
        """Return bounded Graphify, QMD, and exact source context for Codex."""
        validated_question, validated_budget = validate_context_request(question, token_budget)
        try:
            return (
                await broker.search(validated_question, token_budget=validated_budget)
            ).model_dump_json()
        except ValueError as exc:
            raise validation_exception(exc, location=("question",)) from None

    @server.tool()
    async def get_contracts() -> str:
        """Return public contract versions and deterministic JSON Schema hashes."""

        return contract_manifest().model_dump_json()

    @server.tool()
    async def get_failures() -> str:
        """Return terminal statuses and stable machine-readable failure codes."""

        return failure_catalogue().model_dump_json()

    @server.tool()
    async def explain_capability(capability_id: str, allowed: bool = True) -> str:
        """Explain capability eligibility through the configured bounded reasoner."""
        if not capability_id.strip() or len(capability_id.encode("utf-8")) > 256:
            raise invalid_parameter(("capability_id",))
        request = (
            None
            if allowed
            else validate_fetch_request(
                {
                    "target": "https://policy.invalid/",
                    "deny_capabilities": [capability_id],
                }
            )
        )
        return (await gateway.explain_capability(capability_id, request=request)).model_dump_json()

    return server


def main() -> None:
    server = build_server()
    server.run()  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()
