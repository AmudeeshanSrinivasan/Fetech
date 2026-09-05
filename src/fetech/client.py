"""Asynchronous Python SDK."""

from __future__ import annotations

from collections.abc import AsyncIterator, Mapping
from pathlib import Path
from uuid import UUID

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
from fetech.logic.models import ReasoningResult
from fetech.models import (
    ContextBundle,
    ContractManifest,
    FailureCatalogue,
    FetchPlan,
    FetchRequest,
    FetchResult,
    FetchRun,
    InspectionResult,
    ProvenanceEvent,
)


class FetchHandle:
    def __init__(self, run_id: UUID, gateway: UniversalFetchGateway) -> None:
        self.run_id = run_id
        self._gateway = gateway

    async def result(self) -> FetchResult:
        return await self._gateway.wait(self.run_id)

    async def events(self) -> AsyncIterator[ProvenanceEvent]:
        async for event in self._gateway.events(self.run_id):
            yield event

    async def snapshot(self) -> FetchRun:
        return await self._gateway.get_run(self.run_id)

    async def cancel(self) -> FetchRun:
        return await self._gateway.cancel(self.run_id)


class FetechClient:
    def __init__(
        self,
        settings: Settings | None = None,
        *,
        credential_provider: CredentialProvider | None = None,
        session_provider: SessionProvider | None = None,
        form_submission_provider: FormSubmissionProvider | None = None,
        git_lfs_resolver: GitLFSResolver | None = None,
        pdf_ocr_provider: PDFOCRProvider | None = None,
        media_adapter: MediaAdapter | None = None,
        snapshot_connectors: Mapping[str, SnapshotConnector] | None = None,
        repository: Path | None = None,
        vault: Path | None = None,
        qmd_index: str = "obsidian-mind",
    ) -> None:
        self.gateway = UniversalFetchGateway(
            settings,
            credential_provider=credential_provider,
            session_provider=session_provider,
            form_submission_provider=form_submission_provider,
            git_lfs_resolver=git_lfs_resolver,
            pdf_ocr_provider=pdf_ocr_provider,
            media_adapter=media_adapter,
            snapshot_connectors=snapshot_connectors,
        )
        self.context_broker = ContextBroker(
            repository or Path.cwd(),
            runtime_graph=self.gateway.settings.runtime_graph_path,
            vault=vault,
            qmd_index=qmd_index,
        )

    async def __aenter__(self) -> FetechClient:
        await self.gateway.initialize()
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    async def close(self) -> None:
        await self.gateway.close()

    def contracts(self) -> ContractManifest:
        """Return the deterministic public-contract inventory."""

        return contract_manifest()

    def failures(self) -> FailureCatalogue:
        """Return stable terminal and machine-readable failure semantics."""

        return failure_catalogue()

    async def context(self, question: str, *, token_budget: int = 4_000) -> ContextBundle:
        """Retrieve bounded code, runtime, decision, and exact-source evidence."""

        validated_question, validated_budget = validate_context_request(question, token_budget)
        try:
            return await self.context_broker.search(
                validated_question,
                token_budget=validated_budget,
            )
        except ValueError as exc:
            raise validation_exception(exc, location=("question",)) from None

    async def plan(self, request: FetchRequest | Mapping[str, object]) -> FetchPlan:
        try:
            return await self.gateway.plan_async(validate_fetch_request(request))
        except ValueError as exc:
            raise validation_exception(exc) from None

    def plan_deterministic(self, request: FetchRequest | Mapping[str, object]) -> FetchPlan:
        try:
            return self.gateway.plan(validate_fetch_request(request))
        except ValueError as exc:
            raise validation_exception(exc) from None

    async def explain_capability(
        self, capability_id: str, *, request: FetchRequest | None = None
    ) -> ReasoningResult:
        if not capability_id.strip() or len(capability_id.encode("utf-8")) > 256:
            raise invalid_parameter(("capability_id",))
        return await self.gateway.explain_capability(capability_id, request=request)

    async def inspect(self, request: FetchRequest | Mapping[str, object]) -> InspectionResult:
        try:
            return await self.gateway.inspect(validate_fetch_request(request))
        except ValueError as exc:
            raise validation_exception(exc) from None

    async def fetch(self, request: FetchRequest | Mapping[str, object]) -> FetchResult:
        try:
            return await self.gateway.fetch(validate_fetch_request(request))
        except ValueError as exc:
            raise validation_exception(exc) from None

    async def crawl(self, request: FetchRequest | Mapping[str, object]) -> FetchResult:
        """Run a bounded crawl using the same canonical result contract."""

        try:
            validated = validate_fetch_request(request)
            return await self.gateway.fetch(validated.model_copy(update={"intent": "crawl"}))
        except ValueError as exc:
            raise validation_exception(exc) from None

    async def submit(self, request: FetchRequest | Mapping[str, object]) -> FetchHandle:
        try:
            run = await self.gateway.submit(validate_fetch_request(request))
        except ValueError as exc:
            raise validation_exception(exc) from None
        return FetchHandle(run.run_id, self.gateway)

    async def cancel(self, run_id: UUID | str) -> FetchRun:
        return await self.gateway.cancel(validate_uuid(run_id, "run_id"))
