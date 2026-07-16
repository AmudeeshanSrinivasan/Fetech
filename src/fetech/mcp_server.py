"""Scoped MCP tools for fetching, traces, provenance, and bounded context."""

from __future__ import annotations

import os
from pathlib import Path
from uuid import UUID

from fetech.context import ContextBroker
from fetech.gateway import UniversalFetchGateway
from fetech.models import FetchRequest, ResourceBudget


def build_server() -> object:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("install fetech[mcp] to run the MCP server") from exc

    server = FastMCP("fetech-context")
    gateway = UniversalFetchGateway()
    repository = Path(os.environ.get("FETECH_REPOSITORY", Path.cwd())).resolve()
    vault_value = os.environ.get("FETECH_OBSIDIAN_VAULT")
    broker = ContextBroker(repository, vault=Path(vault_value) if vault_value else None)

    @server.tool()
    async def fetch_content(
        target: str, outputs: list[str] | None = None, maximum_bytes: int = 10_000_000
    ) -> str:
        """Fetch public content through Fetech policy, budgets, evidence, and provenance."""
        request = FetchRequest(
            target=target,
            output_requirements=tuple(outputs or ["clean_text"]),
            budget=ResourceBudget(bytes=maximum_bytes),
        )
        return (await gateway.fetch(request)).model_dump_json()

    @server.tool()
    async def inspect_target(target: str) -> str:
        """Normalize, classify, and policy-check a public target without fetching its body."""
        return (await gateway.inspect(FetchRequest(target=target))).model_dump_json()

    @server.tool()
    async def crawl_domain(target: str, maximum_pages: int = 20, maximum_depth: int = 2) -> str:
        """Submit a bounded domain crawl request."""
        if not 1 <= maximum_pages <= 99:
            raise ValueError("maximum_pages must be between 1 and 99")
        request = FetchRequest(
            target=target,
            intent="crawl",
            budget=ResourceBudget(
                attempts=maximum_pages + 1,
                crawl_pages=maximum_pages,
                crawl_depth=maximum_depth,
            ),
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
        identifier = UUID(run_id)
        snapshot = await gateway.get_run(identifier)
        events = await gateway.ledger.events(identifier)
        return "\n".join([snapshot.model_dump_json(), *(event.model_dump_json() for event in events)])

    @server.tool()
    async def query_provenance(run_id: str) -> str:
        """Query immutable provenance events for one run."""
        return "\n".join(event.model_dump_json() for event in await gateway.ledger.events(UUID(run_id)))

    @server.tool()
    async def get_context(question: str, token_budget: int = 4_000) -> str:
        """Return bounded Graphify, QMD, and exact source context for Codex."""
        return (await broker.search(question, token_budget=token_budget)).model_dump_json()

    @server.tool()
    async def explain_capability(capability_id: str, allowed: bool = True) -> str:
        """Explain capability eligibility through the configured bounded reasoner."""
        request = (
            None
            if allowed
            else FetchRequest(
                target="https://policy.invalid/",
                deny_capabilities=frozenset({capability_id}),
            )
        )
        return (await gateway.explain_capability(capability_id, request=request)).model_dump_json()

    return server


def main() -> None:
    server = build_server()
    server.run()  # type: ignore[attr-defined]


if __name__ == "__main__":
    main()
