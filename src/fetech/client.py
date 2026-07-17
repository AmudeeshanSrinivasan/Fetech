"""Asynchronous Python SDK."""

from __future__ import annotations

from collections.abc import AsyncIterator
from uuid import UUID

from fetech.auth import CredentialProvider
from fetech.auth_flows import FormSubmissionProvider, SessionProvider
from fetech.config import Settings
from fetech.gateway import UniversalFetchGateway
from fetech.logic.models import ReasoningResult
from fetech.models import FetchPlan, FetchRequest, FetchResult, FetchRun, ProvenanceEvent


class FetchHandle:
    def __init__(self, run_id: UUID, gateway: UniversalFetchGateway) -> None:
        self.run_id = run_id
        self._gateway = gateway

    async def result(self) -> FetchResult:
        return await self._gateway.wait(self.run_id)

    async def events(self) -> AsyncIterator[ProvenanceEvent]:
        async for event in self._gateway.ledger.stream(self.run_id):
            yield event

    async def snapshot(self) -> FetchRun:
        return await self._gateway.get_run(self.run_id)


class FetechClient:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        credential_provider: CredentialProvider | None = None,
        session_provider: SessionProvider | None = None,
        form_submission_provider: FormSubmissionProvider | None = None,
    ) -> None:
        self.gateway = UniversalFetchGateway(
            settings,
            credential_provider=credential_provider,
            session_provider=session_provider,
            form_submission_provider=form_submission_provider,
        )

    async def __aenter__(self) -> FetechClient:
        await self.gateway.initialize()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self.gateway.close()

    async def plan(self, request: FetchRequest) -> FetchPlan:
        return await self.gateway.plan_async(request)

    def plan_deterministic(self, request: FetchRequest) -> FetchPlan:
        return self.gateway.plan(request)

    async def explain_capability(
        self, capability_id: str, *, request: FetchRequest | None = None
    ) -> ReasoningResult:
        return await self.gateway.explain_capability(capability_id, request=request)

    async def fetch(self, request: FetchRequest) -> FetchResult:
        return await self.gateway.fetch(request)

    async def crawl(self, request: FetchRequest) -> FetchResult:
        """Run a bounded crawl using the same canonical result contract."""

        return await self.gateway.fetch(request.model_copy(update={"intent": "crawl"}))

    async def submit(self, request: FetchRequest) -> FetchHandle:
        run = await self.gateway.submit(request)
        return FetchHandle(run.run_id, self.gateway)
