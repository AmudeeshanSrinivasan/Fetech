"""Typer command-line interface."""

from __future__ import annotations

import asyncio
import json
from dataclasses import replace
from enum import StrEnum
from pathlib import Path
from typing import Annotated
from uuid import UUID

import typer

from fetech.client import FetechClient
from fetech.config import Settings
from fetech.context import ContextBroker
from fetech.models import FetchRequest, ResourceBudget
from fetech.provenance import build_runtime_graph
from fetech.registry import CapabilityRegistry

app = typer.Typer(
    no_args_is_help=True,
    help="Policy-aware universal content acquisition.",
    rich_markup_mode=None,
)
DEFAULT_REPOSITORY = Path.cwd()


class PrivacyProfile(StrEnum):
    """CLI-safe projection of the public request privacy profiles."""

    PUBLIC = "public"
    PRIVATE = "private"


def _json(document: object) -> None:
    if hasattr(document, "model_dump_json"):
        typer.echo(document.model_dump_json(indent=2))
    else:
        typer.echo(json.dumps(document, indent=2, sort_keys=True, default=str))


@app.command()
def capabilities(summary: Annotated[bool, typer.Option(help="Print category totals only.")] = False) -> None:
    """Show the canonical capability manifest."""
    registry = CapabilityRegistry()
    if summary:
        _json(
            {
                "manifest_version": registry.manifest_version,
                "categories": {
                    category: len(registry.for_category(category)) for category in registry.categories
                },
                "category_count": len(registry.categories),
                "capability_count": len(registry),
            }
        )
        return
    _json(registry.as_document())


@app.command()
def plan(
    target: str,
    output: Annotated[list[str] | None, typer.Option("--output", "-o")] = None,
    backend: Annotated[str | None, typer.Option("--backend", help="python or clingo")] = None,
    authentication_ref: Annotated[
        str | None,
        typer.Option("--auth-ref", help="Opaque reference for a configured provider."),
    ] = None,
    privacy_profile: Annotated[
        PrivacyProfile,
        typer.Option("--privacy", help="Request privacy profile."),
    ] = PrivacyProfile.PUBLIC,
    approve: Annotated[
        list[str] | None,
        typer.Option("--approve", help="Explicitly approve a capability."),
    ] = None,
) -> None:
    """Build a validated fetch plan without making a network request."""

    async def run() -> None:
        request = FetchRequest(
            target=target,
            output_requirements=tuple(output or ["clean_text"]),
            authentication_ref=authentication_ref,
            privacy_profile=privacy_profile.value,
            approved_capabilities=frozenset(approve or ()),
        )
        settings = Settings.from_environment()
        if backend:
            settings = replace(settings, planner_backend=backend.lower())
        async with FetechClient(settings) as client:
            _json(await client.plan(request))

    asyncio.run(run())


@app.command()
def explain(
    capability_id: str,
    backend: Annotated[str | None, typer.Option("--backend", help="python, prolog, or swipl")] = None,
    deny: Annotated[bool, typer.Option("--deny", help="Evaluate as request-denied")] = False,
) -> None:
    """Explain capability eligibility with the configured bounded reasoner."""

    async def run() -> None:
        settings = Settings.from_environment()
        if backend:
            settings = replace(settings, reasoner_backend=backend.lower())
        request = (
            FetchRequest(
                target="https://policy.invalid/",
                deny_capabilities=frozenset({capability_id}),
            )
            if deny
            else None
        )
        async with FetechClient(settings) as client:
            _json(await client.explain_capability(capability_id, request=request))

    asyncio.run(run())


@app.command()
def inspect(target: str) -> None:
    """Classify and policy-check a target without acquiring its body."""

    async def run() -> None:
        async with FetechClient() as client:
            _json(await client.gateway.inspect(FetchRequest(target=target)))

    asyncio.run(run())


@app.command()
def fetch(
    target: str,
    output: Annotated[list[str] | None, typer.Option("--output", "-o")] = None,
    maximum_bytes: Annotated[int, typer.Option("--max-bytes")] = 10_000_000,
    authentication_ref: Annotated[
        str | None,
        typer.Option("--auth-ref", help="Opaque reference for a configured provider."),
    ] = None,
    privacy_profile: Annotated[
        PrivacyProfile,
        typer.Option("--privacy", help="Request privacy profile."),
    ] = PrivacyProfile.PUBLIC,
    approve: Annotated[
        list[str] | None,
        typer.Option("--approve", help="Explicitly approve a capability."),
    ] = None,
) -> None:
    """Fetch a target and print its canonical result."""

    async def run() -> None:
        request = FetchRequest(
            target=target,
            output_requirements=tuple(output or ["clean_text"]),
            authentication_ref=authentication_ref,
            privacy_profile=privacy_profile.value,
            approved_capabilities=frozenset(approve or ()),
            budget=ResourceBudget(bytes=maximum_bytes),
        )
        async with FetechClient() as client:
            _json(await client.fetch(request))

    asyncio.run(run())


@app.command()
def crawl(
    target: str,
    maximum_pages: Annotated[int, typer.Option("--max-pages", min=1, max=99)] = 20,
    maximum_depth: Annotated[int, typer.Option("--max-depth", min=0, max=20)] = 2,
    search: Annotated[
        bool,
        typer.Option("--search", help="Use the configured search connector."),
    ] = False,
) -> None:
    """Crawl one public domain within explicit page and depth limits."""

    async def run() -> None:
        request = FetchRequest(
            target=target,
            intent="crawl",
            policy_profile="allow_search_discovery" if search else "default",
            budget=ResourceBudget(
                attempts=min(100, maximum_pages + 1),
                crawl_pages=maximum_pages,
                crawl_depth=maximum_depth,
            ),
        )
        async with FetechClient() as client:
            _json(await client.crawl(request))

    asyncio.run(run())


@app.command("run")
def run_snapshot(run_id: UUID) -> None:
    """Read a persisted run snapshot."""

    async def run() -> None:
        async with FetechClient() as client:
            _json(await client.gateway.get_run(run_id))

    asyncio.run(run())


@app.command("project-runtime-graph")
def project_runtime_graph() -> None:
    """Rebuild the disposable runtime graph from the authoritative ledger."""

    async def run() -> None:
        async with FetechClient() as client:
            graph = await build_runtime_graph(
                client.gateway.ledger, client.gateway.settings.runtime_graph_path
            )
            _json(
                {
                    "path": str(client.gateway.settings.runtime_graph_path),
                    "nodes": len(graph["nodes"]),
                    "links": len(graph["links"]),
                }
            )

    asyncio.run(run())


@app.command("context")
def context_search(
    question: str,
    repository: Annotated[Path, typer.Option("--repository", "-r")] = DEFAULT_REPOSITORY,
    vault: Annotated[Path | None, typer.Option("--vault")] = None,
    token_budget: Annotated[int, typer.Option("--tokens")] = 4_000,
) -> None:
    """Retrieve bounded Graphify, QMD, and exact-source context."""

    async def run() -> None:
        broker = ContextBroker(repository, vault=vault)
        _json(await broker.search(question, token_budget=token_budget))

    asyncio.run(run())


if __name__ == "__main__":
    app()
