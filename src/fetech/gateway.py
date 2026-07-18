"""Universal gateway composing registry, planner, execution, and persistence."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from uuid import UUID, uuid4

from fetech.adapters.api import APIAdapter
from fetech.adapters.archive import ArchiveAdapter
from fetech.adapters.auth import AuthAdapter
from fetech.adapters.base import Adapter, ExecutionContext
from fetech.adapters.browser import BrowserAdapter
from fetech.adapters.cache import CacheAdapter, SnapshotConnector, SnapshotStore
from fetech.adapters.discovery import DiscoveryAdapter
from fetech.adapters.documents import (
    DocumentAdapter,
    DocumentParseWorker,
    GitLFSResolver,
    PDFOCRProvider,
)
from fetech.adapters.http import HTTPAdapter
from fetech.adapters.media import MediaAdapter
from fetech.adapters.reader import ReaderAdapter
from fetech.adapters.variants import VariantAdapter
from fetech.auth import CredentialProvider, NullCredentialProvider
from fetech.auth_flows import (
    FormSubmissionProvider,
    NullFormSubmissionProvider,
    NullSessionProvider,
    SessionProvider,
)
from fetech.browser_reader import BrowserReaderWorker
from fetech.browser_render import BrowserRenderWorker, RemoteBrowserConnector
from fetech.config import Settings
from fetech.executor import ExecutionEngine
from fetech.ledger import EventLedger
from fetech.logic import LogicCoordinator, ReasoningResult
from fetech.logic.models import PlanProposal
from fetech.models import (
    Artifact,
    CapabilityOutcomeStatus,
    Diagnostic,
    FetchPlan,
    FetchRequest,
    FetchResult,
    FetchRun,
    InspectionResult,
    PlanNode,
    ProvenanceEvent,
    ResultStatus,
    RunState,
)
from fetech.planning import DeterministicPlanner, classify_target
from fetech.provenance import build_runtime_graph
from fetech.registry import CapabilityRegistry
from fetech.scheduling import NetworkScheduler
from fetech.search import HTTPSearchProvider
from fetech.security import (
    PolicyBlockedError,
    SafeURLPolicy,
    normalize_url,
    sanitize_output_for_request,
)
from fetech.storage import FileSystemCAS
from fetech.wayback import WaybackSnapshotConnector
from fetech.worker_isolation import (
    WorkerIsolationMode,
    WorkerIsolationRuntime,
)
from fetech.yt_dlp import YTDLPMetadataWorker


class UniversalFetchGateway:
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
    ) -> None:
        self.settings = settings or Settings.from_environment()
        try:
            isolation_mode = WorkerIsolationMode(
                self.settings.worker_isolation_mode
            )
        except ValueError as exc:
            raise ValueError(
                "worker_isolation_mode must be development or required"
            ) from exc
        self.worker_isolation = WorkerIsolationRuntime(
            mode=isolation_mode,
            bubblewrap_executable=self.settings.worker_bwrap_executable,
            cgroup_root=self.settings.worker_cgroup_root,
            data_dir=self.settings.data_dir,
        )
        self.worker_isolation.validate_required_backend()
        self.credential_provider = credential_provider or NullCredentialProvider()
        self.session_provider = session_provider or NullSessionProvider()
        self.form_submission_provider = (
            form_submission_provider or NullFormSubmissionProvider()
        )
        self.registry = CapabilityRegistry()
        self.planner = DeterministicPlanner(self.registry)
        self.logic = LogicCoordinator(self.settings, self.registry, self.planner)
        self.policy = SafeURLPolicy()
        self.ledger = EventLedger.sqlite(self.settings.database_path)
        self.cas = FileSystemCAS(self.settings.artifact_dir)
        self.network_scheduler = NetworkScheduler(
            global_concurrency=self.settings.global_concurrency,
            per_host_concurrency=self.settings.per_host_concurrency,
            per_host_min_interval_seconds=self.settings.per_host_min_interval_seconds,
        )
        http_adapter = HTTPAdapter(
            user_agent=self.settings.user_agent,
            policy=self.policy,
            credential_provider=self.credential_provider,
            global_concurrency=self.settings.global_concurrency,
            per_host_concurrency=self.settings.per_host_concurrency,
            per_host_min_interval_seconds=self.settings.per_host_min_interval_seconds,
            scheduler=self.network_scheduler,
        )
        remote_browsers = {
            engine: RemoteBrowserConnector(endpoint, policy=self.policy)
            for engine, endpoint in {
                "puppeteer": self.settings.puppeteer_connector_url,
                "selenium": self.settings.selenium_connector_url,
            }.items()
            if endpoint
        }
        search_provider = (
            HTTPSearchProvider(
                self.settings.search_provider_template,
                policy=self.policy,
                user_agent=self.settings.user_agent,
            )
            if self.settings.search_provider_template
            else None
        )
        cache_connectors: dict[str, SnapshotConnector] = {
            "internet_archive_snapshot": WaybackSnapshotConnector(
                policy=self.policy,
                user_agent=self.settings.user_agent,
                scheduler=self.network_scheduler,
            )
        }
        cache_connectors.update(snapshot_connectors or {})
        self.adapters: dict[str, Adapter] = {
            "http": http_adapter,
            "discovery": DiscoveryAdapter(http_adapter, search_provider=search_provider),
            "reader": ReaderAdapter(
                remote_reader_template=self.settings.jina_reader_template,
                policy=self.policy,
                user_agent=self.settings.user_agent,
                browser_reader=BrowserReaderWorker(
                    isolation=self.worker_isolation,
                    browser_artifacts_path=self.settings.browser_artifacts_path,
                ),
            ),
            "variants": VariantAdapter(http_adapter),
            "auth": AuthAdapter(
                http_adapter,
                credential_provider=self.credential_provider,
                session_provider=self.session_provider,
                form_submission_provider=self.form_submission_provider,
            ),
            "api": APIAdapter(),
            "browser": BrowserAdapter(
                BrowserRenderWorker(
                    isolation=self.worker_isolation,
                    browser_artifacts_path=self.settings.browser_artifacts_path,
                ),
                remote_renderers=remote_browsers,
                user_agent=self.settings.user_agent,
            ),
            "documents": DocumentAdapter(
                parser=DocumentParseWorker(
                    docling_artifacts_path=self.settings.docling_artifacts_path,
                    docling_artifacts_sha256=(
                        self.settings.docling_artifacts_sha256
                    ),
                    docling_memory_mb=self.settings.docling_worker_memory_mb,
                    isolation=self.worker_isolation,
                ),
                git_lfs_resolver=git_lfs_resolver,
                pdf_ocr_provider=pdf_ocr_provider,
            ),
            "media": media_adapter
            or MediaAdapter(
                isolation=self.worker_isolation,
                youtube_provider=YTDLPMetadataWorker(
                    scheduler=self.network_scheduler,
                    isolation=self.worker_isolation,
                )
            ),
            "archive": ArchiveAdapter(isolation=self.worker_isolation),
            "cache": CacheAdapter(
                SnapshotStore(self.settings.data_dir / "snapshots", self.cas),
                connectors=cache_connectors,
                policy=self.policy,
            ),
            "core": _CoreAdapter(),
        }
        self.executor = ExecutionEngine(adapters=self.adapters, cas=self.cas, ledger=self.ledger)
        self._tasks: dict[UUID, asyncio.Task[FetchResult]] = {}
        self._artifacts: dict[UUID, Artifact] = {}
        self._initialized = False

    async def initialize(self) -> None:
        if not self._initialized:
            await self.ledger.initialize()
            self._initialized = True

    async def close(self) -> None:
        running = [task for task in self._tasks.values() if not task.done()]
        for task in running:
            task.cancel()
        if running:
            await asyncio.gather(*running, return_exceptions=True)
        await self.ledger.close()
        self._initialized = False

    def plan(self, request: FetchRequest) -> FetchPlan:
        """Return the dependency-free deterministic Python plan."""
        return self.planner.plan(request)

    async def plan_async(self, request: FetchRequest) -> FetchPlan:
        """Return a plan from the configured backend with safe Python fallback."""
        return (await self.logic.plan(request)).plan

    async def explain_capability(
        self, capability_id: str, *, request: FetchRequest | None = None
    ) -> ReasoningResult:
        query = self.logic.capability_query(capability_id, request=request)
        return await self.logic.explain(query)

    async def inspect(self, request: FetchRequest) -> InspectionResult:
        normalized = normalize_url(request.target)
        family = classify_target(normalized, request.output_requirements)
        try:
            _, decisions = await self.policy.evaluate(normalized)
        except PolicyBlockedError as exc:
            decisions = exc.decisions
        plan = await self.plan_async(request)
        inspection = InspectionResult(
            normalized_target=normalized,
            family=family,
            policy_decisions=decisions,
            suggested_capabilities=tuple(node.capability_id for node in plan.nodes),
        )
        return InspectionResult.model_validate(
            sanitize_output_for_request(inspection.model_dump(mode="python"), request)
        )

    async def submit(self, request: FetchRequest) -> FetchRun:
        await self.initialize()
        run_id = uuid4()
        submitted_at = datetime.now(UTC)
        await self.ledger.create_run(run_id, request.model_dump(mode="json"), submitted_at)
        try:
            proposal = await self.logic.plan(request)
        except Exception:
            result = await self._record_planning_failure(run_id, request)
            return FetchRun(
                run_id=run_id,
                state=RunState.FINISHED,
                submitted_at=submitted_at,
                result=result,
            )
        await self._record_plan(run_id, proposal)
        plan = proposal.plan
        task = asyncio.create_task(self._execute_and_project(run_id, plan), name=f"fetech:{run_id}")
        self._tasks[run_id] = task
        task.add_done_callback(lambda _: self._tasks.pop(run_id, None))
        return FetchRun(run_id=run_id, state=RunState.QUEUED, submitted_at=submitted_at)

    async def fetch(self, request: FetchRequest) -> FetchResult:
        run = await self.submit(request)
        if run.result is not None:
            return run.result
        task = self._tasks[run.run_id]
        return await task

    async def get_run(self, run_id: UUID) -> FetchRun:
        await self.initialize()
        state, submitted_at, result = await self.ledger.run_snapshot(run_id)
        return FetchRun(run_id=run_id, state=state, submitted_at=submitted_at, result=result)

    async def wait(self, run_id: UUID) -> FetchResult:
        task = self._tasks.get(run_id)
        if task is not None:
            return await task
        snapshot = await self.get_run(run_id)
        if snapshot.result is None:
            raise RuntimeError(f"run {run_id} has no active task or stored result")
        return snapshot.result

    def get_artifact(self, artifact_id: UUID) -> Artifact:
        try:
            return self._artifacts[artifact_id]
        except KeyError as exc:
            raise KeyError(f"unknown artifact: {artifact_id}") from exc

    async def _execute_and_project(self, run_id: UUID, plan: FetchPlan) -> FetchResult:
        try:
            result = await self.executor.execute(run_id, plan)
        except asyncio.CancelledError:
            await self._record_terminal_failure(
                run_id,
                plan,
                code="run_cancelled",
                message="fetch execution was cancelled",
            )
            raise
        except Exception:
            result = await self._record_terminal_failure(
                run_id,
                plan,
                code="internal_error",
                message="fetch execution failed at an internal boundary",
            )
        self._artifacts.update({artifact.artifact_id: artifact for artifact in result.artifacts})
        with suppress(Exception):
            await build_runtime_graph(self.ledger, self.settings.runtime_graph_path)
        return result

    async def _record_terminal_failure(
        self,
        run_id: UUID,
        plan: FetchPlan,
        *,
        code: str,
        message: str,
    ) -> FetchResult:
        event = ProvenanceEvent(
            run_id=run_id,
            event_type="run.failed",
            actor="gateway",
            payload={"code": code},
        )
        await self.ledger.append(event)
        result = FetchResult(
            run_id=run_id,
            status=ResultStatus.FAILED,
            diagnostics=(Diagnostic(code=code, message=message),),
            provenance_event_ids=(event.event_id,),
            remaining_budget=plan.request.budget,
        )
        await self.ledger.update_run(run_id, RunState.FINISHED, result)
        return result

    async def _record_planning_failure(
        self,
        run_id: UUID,
        request: FetchRequest,
    ) -> FetchResult:
        event = ProvenanceEvent(
            run_id=run_id,
            event_type="run.planning_failed",
            actor="planner",
            payload={"code": "planning_failed"},
        )
        await self.ledger.append(event)
        result = FetchResult(
            run_id=run_id,
            status=ResultStatus.FAILED,
            diagnostics=(
                Diagnostic(
                    code="planning_failed",
                    message="request could not produce a valid execution plan",
                ),
            ),
            provenance_event_ids=(event.event_id,),
            remaining_budget=request.budget,
        )
        await self.ledger.update_run(run_id, RunState.FINISHED, result)
        return result

    async def _record_plan(self, run_id: UUID, proposal: PlanProposal) -> None:
        payload = {
            "backend": proposal.backend,
            "status": proposal.status.value,
            "classifier": proposal.plan.classifier,
        }
        if proposal.executable_version:
            payload["executable_version"] = proposal.executable_version
        if proposal.ruleset_sha256:
            payload["ruleset_sha256"] = proposal.ruleset_sha256
        if proposal.manifest_version:
            payload["manifest_version"] = proposal.manifest_version
        if proposal.manifest_sha256:
            payload["manifest_sha256"] = proposal.manifest_sha256
        if proposal.input_sha256:
            payload["input_sha256"] = proposal.input_sha256
        if proposal.result_sha256:
            payload["result_sha256"] = proposal.result_sha256
        if proposal.diagnostics:
            payload["diagnostic"] = "; ".join(proposal.diagnostics)
        await self.ledger.append(
            ProvenanceEvent(
                run_id=run_id,
                event_type="planning.completed",
                actor=proposal.backend,
                payload=payload,
            )
        )


class _CoreAdapter:
    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        if node.capability_id == "url_normalisation":
            normalized = normalize_url(context.request.target)
            context.record_outcome(
                "url_normalisation",
                CapabilityOutcomeStatus.APPLIED,
                "core",
                changed=normalized != context.request.target,
            )
            return
        if node.capability_id == "url_validation":
            normalize_url(context.request.target)
            context.record_outcome(
                "url_validation",
                CapabilityOutcomeStatus.APPLIED,
                "core",
                scheme="http(s)",
            )
            context.record_outcome(
                "resource_budget_policy",
                CapabilityOutcomeStatus.APPLIED,
                "core",
                attempts=context.request.budget.attempts,
                maximum_bytes=context.request.budget.bytes,
            )
            if context.request.intent != "crawl":
                context.record_outcome(
                    "robots_policy_check",
                    CapabilityOutcomeStatus.NOT_APPLICABLE,
                    "core",
                    reason="robots policy is applied to crawling, not a single retrieval",
                )
            return
        raise ValueError(f"core adapter cannot execute {node.capability_id}")
