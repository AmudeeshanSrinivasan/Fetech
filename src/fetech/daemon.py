"""FastAPI daemon exposing the SDK contracts over REST and SSE."""

from __future__ import annotations

import os
from collections.abc import AsyncIterator, Mapping
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from uuid import UUID

from fetech.adapters.cache import SnapshotConnector
from fetech.adapters.documents import GitLFSResolver, PDFOCRProvider
from fetech.adapters.media import MediaAdapter
from fetech.auth import CredentialProvider
from fetech.auth_flows import FormSubmissionProvider, SessionProvider
from fetech.context import ContextBroker
from fetech.contracts import contract_manifest
from fetech.errors import (
    FetechValidationError,
    public_validation_error,
    validate_context_request,
    validation_exception,
)
from fetech.gateway import UniversalFetchGateway
from fetech.logic.models import ReasoningResult
from fetech.models import (
    ContextBundle,
    ContractManifest,
    FetchPlan,
    FetchRequest,
    FetchRun,
    InspectionResult,
    PublicError,
)
from fetech.storage import CASIntegrityError, CASReadLimitError
from fetech.version import __version__


def create_app(
    *,
    credential_provider: CredentialProvider | None = None,
    session_provider: SessionProvider | None = None,
    form_submission_provider: FormSubmissionProvider | None = None,
    git_lfs_resolver: GitLFSResolver | None = None,
    pdf_ocr_provider: PDFOCRProvider | None = None,
    media_adapter: MediaAdapter | None = None,
    snapshot_connectors: Mapping[str, SnapshotConnector] | None = None,
) -> Any:
    try:
        from fastapi import FastAPI, HTTPException, Query
        from fastapi.exceptions import RequestValidationError
        from fastapi.responses import JSONResponse, Response, StreamingResponse
    except ImportError as exc:
        raise RuntimeError("install fetech[server] to run the daemon") from exc

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
        runtime_graph=gateway.settings.runtime_graph_path,
        vault=Path(vault_value) if vault_value else None,
    )

    @asynccontextmanager
    async def lifespan(_: object) -> AsyncIterator[None]:
        await gateway.initialize()
        try:
            yield
        finally:
            await gateway.close()

    app = FastAPI(title="Fetech", version=__version__, lifespan=lifespan)
    app.state.gateway = gateway
    validation_responses: dict[int | str, dict[str, Any]] = {
        422: {
            "model": PublicError,
            "description": "Sanitized request validation failure",
        }
    }

    @app.exception_handler(RequestValidationError)
    async def request_validation_error(_: object, exc: RequestValidationError) -> JSONResponse:
        error = public_validation_error(exc)
        return JSONResponse(
            status_code=error.status_code,
            content=error.model_dump(mode="json"),
        )

    @app.exception_handler(FetechValidationError)
    async def fetech_validation_error(_: object, exc: FetechValidationError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.error.status_code,
            content=exc.error.model_dump(mode="json"),
        )

    @app.post(
        "/v1/fetch",
        response_model=FetchRun,
        status_code=202,
        responses=validation_responses,
    )
    async def fetch(request: FetchRequest) -> FetchRun:
        return await gateway.submit(request)

    @app.post(
        "/v1/crawl",
        response_model=FetchRun,
        status_code=202,
        responses=validation_responses,
    )
    async def crawl(request: FetchRequest) -> FetchRun:
        return await gateway.submit(request.model_copy(update={"intent": "crawl"}))

    @app.post("/v1/plan", response_model=FetchPlan, responses=validation_responses)
    async def plan(request: FetchRequest) -> FetchPlan:
        try:
            return await gateway.plan_async(request)
        except ValueError as exc:
            raise validation_exception(exc) from None

    @app.get("/v1/capabilities/{capability_id}/explanation", response_model=ReasoningResult)
    async def explain_capability(capability_id: str) -> ReasoningResult:
        try:
            return await gateway.explain_capability(capability_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(
        "/v1/capabilities/{capability_id}/explanation",
        response_model=ReasoningResult,
        responses=validation_responses,
    )
    async def explain_capability_for_request(capability_id: str, request: FetchRequest) -> ReasoningResult:
        try:
            return await gateway.explain_capability(capability_id, request=request)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post("/v1/inspect", response_model=InspectionResult, responses=validation_responses)
    async def inspect(request: FetchRequest) -> InspectionResult:
        try:
            return await gateway.inspect(request)
        except ValueError as exc:
            raise validation_exception(exc) from None

    @app.get("/v1/runs/{run_id}", response_model=FetchRun, responses=validation_responses)
    async def get_run(run_id: UUID) -> FetchRun:
        try:
            return await gateway.get_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.delete("/v1/runs/{run_id}", response_model=FetchRun, responses=validation_responses)
    async def cancel_run(run_id: UUID) -> FetchRun:
        try:
            return await gateway.cancel(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.get("/v1/runs/{run_id}/events", responses=validation_responses)
    async def events(run_id: UUID) -> Any:
        try:
            await gateway.get_run(run_id)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

        async def stream() -> AsyncIterator[str]:
            async for event in gateway.events(run_id):
                yield f"event: {event.event_type}\ndata: {event.model_dump_json()}\n\n"

        return StreamingResponse(stream(), media_type="text/event-stream")

    @app.get("/v1/artifacts/{artifact_id}", responses=validation_responses)
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
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="artifact content is unavailable") from exc
        except CASReadLimitError as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except (CASIntegrityError, ValueError) as exc:
            raise HTTPException(status_code=409, detail="artifact integrity check failed") from exc
        return Response(body, media_type=metadata.media_type, headers={"ETag": metadata.sha256})

    @app.get("/v1/capabilities")
    async def capabilities() -> dict[str, object]:
        return gateway.registry.as_document()

    @app.get("/v1/contracts", response_model=ContractManifest)
    async def contracts() -> ContractManifest:
        return contract_manifest()

    @app.post(
        "/v1/context/search",
        response_model=ContextBundle,
        responses=validation_responses,
    )
    async def context_search(
        question: str = Query(),
        token_budget: int = Query(default=4_000),
    ) -> ContextBundle:
        validated_question, validated_budget = validate_context_request(question, token_budget)
        try:
            return await broker.search(validated_question, token_budget=validated_budget)
        except ValueError as exc:
            raise validation_exception(exc, location=("question",)) from None

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
