"""FastAPI daemon exposing the SDK contracts over REST and SSE."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

from fetech.auth import CredentialProvider
from fetech.auth_flows import FormSubmissionProvider, SessionProvider
from fetech.context import ContextBroker
from fetech.gateway import UniversalFetchGateway
from fetech.logic.models import ReasoningResult
from fetech.models import ContextBundle, FetchPlan, FetchRequest, FetchRun, InspectionResult


def create_app(
    *,
    credential_provider: CredentialProvider | None = None,
    session_provider: SessionProvider | None = None,
    form_submission_provider: FormSubmissionProvider | None = None,
) -> Any:
    try:
        from fastapi import FastAPI, HTTPException, Query
        from fastapi.responses import Response, StreamingResponse
    except ImportError as exc:
        raise RuntimeError("install fetech[server] to run the daemon") from exc

    gateway = UniversalFetchGateway(
        credential_provider=credential_provider,
        session_provider=session_provider,
        form_submission_provider=form_submission_provider,
    )
    repository = Path(os.environ.get("FETECH_REPOSITORY", Path.cwd())).resolve()
    vault_value = os.environ.get("FETECH_OBSIDIAN_VAULT")
    broker = ContextBroker(repository, vault=Path(vault_value) if vault_value else None)

    @asynccontextmanager
    async def lifespan(_: object) -> AsyncIterator[None]:
        await gateway.initialize()
        try:
            yield
        finally:
            await gateway.close()

    app = FastAPI(title="Fetech", version="0.3.0a0", lifespan=lifespan)
    app.state.gateway = gateway

    @app.post("/v1/fetch", response_model=FetchRun, status_code=202)
    async def fetch(request: FetchRequest) -> FetchRun:
        return await gateway.submit(request)

    @app.post("/v1/crawl", response_model=FetchRun, status_code=202)
    async def crawl(request: FetchRequest) -> FetchRun:
        return await gateway.submit(request.model_copy(update={"intent": "crawl"}))

    @app.post("/v1/plan", response_model=FetchPlan)
    async def plan(request: FetchRequest) -> FetchPlan:
        try:
            return await gateway.plan_async(request)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="request could not produce a valid execution plan",
            ) from exc

    @app.get("/v1/capabilities/{capability_id}/explanation", response_model=ReasoningResult)
    async def explain_capability(capability_id: str) -> ReasoningResult:
        try:
            return await gateway.explain_capability(capability_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/capabilities/{capability_id}/explanation", response_model=ReasoningResult)
    async def explain_capability_for_request(capability_id: str, request: FetchRequest) -> ReasoningResult:
        try:
            return await gateway.explain_capability(capability_id, request=request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/inspect", response_model=InspectionResult)
    async def inspect(request: FetchRequest) -> InspectionResult:
        try:
            return await gateway.inspect(request)
        except ValueError as exc:
            raise HTTPException(
                status_code=422,
                detail="request could not be inspected safely",
            ) from exc

    @app.get("/v1/runs/{run_id}", response_model=FetchRun)
    async def get_run(run_id: UUID) -> FetchRun:
        try:
            return await gateway.get_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/v1/runs/{run_id}/events")
    async def events(run_id: UUID) -> Any:
        async def stream() -> AsyncIterator[str]:
            try:
                async for event in gateway.ledger.stream(run_id):
                    yield f"event: {event.event_type}\ndata: {event.model_dump_json()}\n\n"
            except KeyError:
                yield 'event: error\ndata: {"detail":"run not found"}\n\n'

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/v1/artifacts/{artifact_id}")
    async def artifact(
        artifact_id: UUID,
        content: bool = Query(default=False),
        maximum_bytes: int = Query(default=1_000_000, ge=1, le=10_000_000),
    ) -> object:
        try:
            metadata = gateway.get_artifact(artifact_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc
        if not content:
            return metadata
        try:
            body = await gateway.cas.get(metadata.cas_uri, maximum_bytes=maximum_bytes)
        except ValueError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        return Response(body, media_type=metadata.media_type, headers={"ETag": metadata.sha256})

    @app.get("/v1/capabilities")
    async def capabilities() -> dict[str, object]:
        return gateway.registry.as_document()

    @app.post("/v1/context/search", response_model=ContextBundle)
    async def context_search(question: str, token_budget: int = 4_000) -> ContextBundle:
        return await broker.search(question, token_budget=token_budget)

    return app


def main() -> None:
    try:
        import uvicorn
    except ImportError as exc:
        raise RuntimeError("install fetech[server] to run the daemon") from exc
    host = os.environ.get("FETECH_HOST", "127.0.0.1")
    port = int(os.environ.get("FETECH_PORT", "8787"))
    uvicorn.run(create_app(), host=host, port=port)


if __name__ == "__main__":
    main()
