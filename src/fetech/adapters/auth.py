"""Executable authentication-flow adapter behind the safe HTTP boundary."""

from __future__ import annotations

from datetime import UTC, datetime
from hmac import compare_digest
from urllib.parse import urlencode
from uuid import UUID

import httpx

from fetech.adapters.base import (
    AdapterAuthExpiredError,
    AdapterAuthRequiredError,
    AdapterDependencyError,
    AdapterExecutionError,
    ExecutionContext,
)
from fetech.adapters.http import HTTPAdapter
from fetech.auth import (
    CredentialMaterial,
    CredentialNotFoundError,
    CredentialProvider,
    CredentialProviderError,
    CredentialProviderUnavailableError,
    canonical_origin,
)
from fetech.auth_flows import (
    ApprovalRequiredError,
    AuthFlowError,
    CSRFTokenMaterial,
    FormSubmission,
    FormSubmissionNotFoundError,
    FormSubmissionProvider,
    FormSubmissionProviderError,
    NullFormSubmissionProvider,
    NullSessionProvider,
    OriginScopedSession,
    SessionBindingError,
    SessionNotFoundError,
    SessionProvider,
    SessionProviderError,
    SessionProviderUnavailableError,
    extract_csrf_token,
)
from fetech.models import (
    AttemptStatus,
    CapabilityOutcomeStatus,
    FetchAttempt,
    PageState,
    PlanNode,
    PolicyDecision,
    Resource,
)
from fetech.quality import assess_binary, assess_text
from fetech.security import (
    PolicyBlockedError,
    sanitize_url,
    sanitize_url_for_request,
)
from fetech.storage import build_artifact

SESSION_CAPABILITIES = frozenset(
    {"login_session", "oauth", "sso", "private_workspace"}
)


class AuthAdapter:
    """Validate configured sessions and execute explicitly approved form proposals."""

    def __init__(
        self,
        http_adapter: HTTPAdapter,
        *,
        credential_provider: CredentialProvider,
        session_provider: SessionProvider | None = None,
        form_submission_provider: FormSubmissionProvider | None = None,
    ) -> None:
        self.http_adapter = http_adapter
        self.credential_provider = credential_provider
        self.session_provider = session_provider or NullSessionProvider()
        self.form_submission_provider = (
            form_submission_provider or NullFormSubmissionProvider()
        )

    async def execute(self, node: PlanNode, context: ExecutionContext) -> None:
        if node.capability_id in SESSION_CAPABILITIES:
            await self._validate_session(node, context)
            return
        if node.capability_id == "csrf_token":
            await self._extract_csrf(node, context)
            return
        if node.capability_id == "form_submit":
            await self._submit_form(node, context)
            return
        raise AdapterExecutionError(
            f"authentication adapter cannot execute {node.capability_id}"
        )

    async def _validate_session(
        self,
        node: PlanNode,
        context: ExecutionContext,
    ) -> None:
        attempt = self._start_attempt(node, context)
        reference = context.request.authentication_ref
        if reference is None:
            self._fail_attempt(context, attempt, "auth_required")
            raise AdapterAuthRequiredError("authentication reference is required")
        try:
            normalized_target = await self._evaluate_session_policy(node, context)
            session = await self._resolve_session(reference, node.capability_id)
            self._validate_session_descriptor(
                session,
                node=node,
                authentication_ref=reference,
                target=normalized_target,
            )
            material = await self._resolve_material(reference)
            self._validate_existing_material(session, material)
            descriptor_expired = session.expired()
            material_expired = material.expired
            refresh_authorized = (
                node.capability_id in {"oauth", "sso"}
                and material.capability_id == "bearer_token"
                and session.refresh_ref is not None
            )
            if refresh_authorized and (
                descriptor_expired or material_expired or session.needs_refresh()
            ):
                material = await self._refresh_session(session, material, context)
                self._validate_existing_material(session, material)
                if material.expired:
                    raise AdapterAuthExpiredError(
                        "credential refresh returned expired material"
                    )
            elif descriptor_expired or material_expired:
                raise AdapterAuthExpiredError("session credential is expired")
        except PolicyBlockedError:
            self._fail_attempt(context, attempt, "policy")
            raise
        except AdapterDependencyError:
            self._fail_attempt(context, attempt, "dependency_missing")
            raise
        except AdapterAuthExpiredError:
            self._fail_attempt(context, attempt, "auth_expired")
            raise
        except AdapterAuthRequiredError:
            self._fail_attempt(context, attempt, "auth_required")
            raise
        context.sensitive_state["credential_material"] = material
        context.sensitive_state["origin_scoped_session"] = session
        context.sensitive_state["session_capability_id"] = node.capability_id
        context.record_outcome(
            node.capability_id,
            CapabilityOutcomeStatus.APPLIED,
            "auth",
            exact_origin=True,
            credential_type=material.capability_id,
            issuer_origin=session.issuer_origin,
            scope_count=len(session.scopes),
            connector_id=session.connector_id,
        )
        context.record_runtime_event(
            "auth.session.validated",
            "auth",
            capability_id=node.capability_id,
        )
        self._finish_attempt(context, attempt, parser="origin-scoped-session")

    async def _extract_csrf(
        self,
        node: PlanNode,
        context: ExecutionContext,
    ) -> None:
        attempt = self._start_attempt(node, context)
        raw = context.latest_artifact("raw")
        if raw is None:
            self._fail_attempt(context, attempt, "dependency_missing")
            raise AdapterDependencyError(
                "CSRF extraction requires an acquired HTML artifact"
            )
        source = next(
            (
                resource
                for resource in context.resources
                if resource.resource_id == raw.source_resource_id
            ),
            None,
        )
        if source is None:
            self._fail_attempt(context, attempt, "dependency_missing")
            raise AdapterDependencyError(
                "CSRF artifact has no matching source resource"
            )
        if raw.media_type not in {"text/html", "application/xhtml+xml"}:
            self._fail_attempt(context, attempt, "adapter_failed")
            raise AdapterExecutionError(
                "CSRF extraction requires an HTML source artifact"
            )
        maximum = min(raw.size, context.request.budget.decompressed_bytes, 256 * 1024)
        try:
            body = await context.cas.get(raw.cas_uri, maximum_bytes=maximum)
            token = extract_csrf_token(body, source.canonical_url)
        except (AuthFlowError, UnicodeError) as exc:
            self._fail_attempt(context, attempt, "adapter_failed")
            raise AdapterExecutionError("bounded same-origin CSRF extraction failed") from exc
        except (OSError, ValueError) as exc:
            self._fail_attempt(context, attempt, "dependency_missing")
            raise AdapterDependencyError(
                "CSRF source artifact is unavailable or invalid"
            ) from exc
        context.sensitive_state["csrf_token"] = token
        context.sensitive_state["csrf_source_resource_id"] = source.resource_id
        context.record_outcome(
            "csrf_token",
            CapabilityOutcomeStatus.APPLIED,
            "auth",
            exact_action=True,
            method=token.form_method,
            field_name=token.field_name,
        )
        self._finish_attempt(
            context,
            attempt,
            parser="bounded-html-form",
            bytes_received=len(body),
        )

    async def _evaluate_session_policy(
        self,
        node: PlanNode,
        context: ExecutionContext,
    ) -> str:
        """Apply destination and privacy policy before touching either provider."""

        normalized, decisions = await self.http_adapter.policy.evaluate(
            context.request.target
        )
        context.policy_decisions.extend(decisions)
        for decision in decisions:
            context.record_outcome(
                decision.policy_id,
                (
                    CapabilityOutcomeStatus.APPLIED
                    if decision.allowed
                    else CapabilityOutcomeStatus.BLOCKED
                ),
                "security",
                reason=decision.reason,
            )
        if not normalized.startswith("https://"):
            reason = "authenticated sessions require an HTTPS destination"
            raise PolicyBlockedError(
                reason,
                (
                    PolicyDecision(
                        policy_id="authenticated_https",
                        allowed=False,
                        reason=reason,
                        destination=sanitize_url(normalized),
                    ),
                ),
            )
        if (
            node.capability_id == "private_workspace"
            and context.request.privacy_profile != "private"
        ):
            reason = "private_workspace requires a private privacy profile"
            raise PolicyBlockedError(
                reason,
                (
                    PolicyDecision(
                        policy_id="private_workspace_privacy",
                        allowed=False,
                        reason=reason,
                        destination=sanitize_url(normalized),
                    ),
                ),
            )
        return normalized

    @staticmethod
    def _validate_session_descriptor(
        session: OriginScopedSession,
        *,
        node: PlanNode,
        authentication_ref: str,
        target: str,
    ) -> None:
        if session.authentication_ref != authentication_ref:
            raise AdapterAuthRequiredError(
                "session descriptor does not match the authentication reference"
            )
        if session.capability_id.value != node.capability_id:
            raise AdapterAuthRequiredError(
                "session descriptor does not match the requested capability"
            )
        if not session.applies_to(target):
            raise AdapterAuthRequiredError(
                "session descriptor does not match the target origin"
            )
        if (
            node.capability_id == "private_workspace"
            and session.connector_id is None
        ):
            raise AdapterDependencyError(
                "private workspace session has no configured connector identity"
            )

    @staticmethod
    def _validate_existing_material(
        session: OriginScopedSession,
        material: CredentialMaterial,
    ) -> None:
        try:
            session.validate_material_binding(material)
        except SessionBindingError as exc:
            raise AdapterAuthRequiredError(
                "credential material does not match the configured session"
            ) from exc

    async def _refresh_session(
        self,
        session: OriginScopedSession,
        existing_material: CredentialMaterial,
        context: ExecutionContext,
    ) -> CredentialMaterial:
        """Refresh only an explicitly authorized OAuth/SSO bearer descriptor."""

        refresh_ref = session.refresh_ref
        if (
            session.capability_id.value not in {"oauth", "sso"}
            or existing_material.capability_id != "bearer_token"
            or refresh_ref is None
        ):
            raise AdapterAuthExpiredError("session credential is expired")
        refresh = getattr(self.credential_provider, "refresh", None)
        if not callable(refresh):
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=session.capability_id.value,
                reason="refresh_unsupported",
            )
            raise AdapterAuthExpiredError("credential refresh is unavailable")
        context.record_runtime_event(
            "auth.refresh.started",
            "auth",
            capability_id=session.capability_id.value,
        )
        try:
            material = await refresh(refresh_ref)
        except CredentialProviderUnavailableError as exc:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=session.capability_id.value,
                reason="provider_unavailable",
            )
            raise AdapterDependencyError("credential provider is unavailable") from exc
        except (CredentialNotFoundError, CredentialProviderError) as exc:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=session.capability_id.value,
                reason="refresh_rejected",
            )
            raise AdapterAuthExpiredError("credential refresh was rejected") from exc
        except Exception as exc:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=session.capability_id.value,
                reason="provider_failed",
            )
            raise AdapterDependencyError("credential provider failed") from exc
        if not isinstance(material, CredentialMaterial):
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=session.capability_id.value,
                reason="invalid_material",
            )
            raise AdapterDependencyError("credential provider returned invalid material")
        try:
            session.validate_material_binding(material)
        except SessionBindingError as exc:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=session.capability_id.value,
                reason="invalid_binding",
            )
            raise AdapterAuthRequiredError(
                "refreshed credential does not match the configured session"
            ) from exc
        if material.capability_id != existing_material.capability_id:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=session.capability_id.value,
                reason="credential_type_changed",
            )
            raise AdapterAuthRequiredError(
                "refreshed credential changed authentication type"
            )
        if material.expired:
            context.record_runtime_event(
                "auth.refresh.failed",
                "auth",
                capability_id=session.capability_id.value,
                reason="expired_material",
            )
            raise AdapterAuthExpiredError(
                "credential refresh returned expired material"
            )
        context.record_outcome(
            session.capability_id.value,
            CapabilityOutcomeStatus.APPLIED,
            "auth",
            refreshed=True,
        )
        context.record_runtime_event(
            "auth.refresh.succeeded",
            "auth",
            capability_id=session.capability_id.value,
        )
        return material

    async def _submit_form(
        self,
        node: PlanNode,
        context: ExecutionContext,
    ) -> None:
        attempt = self._start_attempt(node, context)
        reference = context.request.authentication_ref
        if reference is None:
            self._fail_attempt(context, attempt, "auth_required")
            raise AdapterAuthRequiredError(
                "form submission requires an opaque authentication reference"
            )
        try:
            normalized_target = await self._evaluate_session_policy(node, context)
            submission = await self._resolve_submission(reference, context.run_id)
            if submission.authentication_ref != reference:
                raise AuthFlowError(
                    "form submission reference does not match the request reference"
                )
            if submission.origin != _origin(normalized_target):
                reason = "form submission action must remain on the request origin"
                raise PolicyBlockedError(
                    reason,
                    (
                        PolicyDecision(
                            policy_id="form_action_origin",
                            allowed=False,
                            reason=reason,
                            destination=sanitize_url(submission.target),
                        ),
                    ),
                )
            await self._evaluate_form_action_policy(submission, context)
            csrf = self._context_csrf(context)
            if submission.csrf is not None:
                if csrf is None or not self._same_csrf_material(
                    submission.csrf,
                    csrf,
                ):
                    raise AdapterExecutionError(
                        "form CSRF token does not match the current source binding"
                    )
            elif isinstance(csrf, CSRFTokenMaterial):
                submission = FormSubmission(
                    target=submission.target,
                    method=submission.method,
                    fields=submission.fields,
                    authentication_ref=submission.authentication_ref,
                    csrf=csrf,
                    approval=submission.approval,
                )
            submission.assert_authorized()
            payload = submission.payload()
            encoded = urlencode(payload).encode("utf-8")
            has_session_credential = isinstance(
                context.sensitive_state.get("credential_material"),
                CredentialMaterial,
            )
            response, response_body, wire_bytes = await self.http_adapter._request(
                submission.target,
                context,
                method_override=submission.method,
                body=encoded,
                extra_headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                allow_ephemeral_login_cookies=not has_session_credential,
                credential_mode=(
                    "request" if has_session_credential else "anonymous"
                ),
            )
        except ApprovalRequiredError as exc:
            self._fail_attempt(context, attempt, "policy")
            reason = "form_submit requires a live exact-target approval"
            raise PolicyBlockedError(
                reason,
                (
                    PolicyDecision(
                        policy_id="form_submit_approval",
                        allowed=False,
                        reason=reason,
                        destination=sanitize_url(context.request.target),
                    ),
                ),
            ) from exc
        except FormSubmissionNotFoundError as exc:
            self._fail_attempt(context, attempt, "dependency_missing")
            raise AdapterDependencyError(
                "approved form submission provider is unavailable"
            ) from exc
        except FormSubmissionProviderError as exc:
            self._fail_attempt(context, attempt, "dependency_missing")
            raise AdapterDependencyError("form submission provider failed") from exc
        except AuthFlowError as exc:
            self._fail_attempt(context, attempt, "adapter_failed")
            raise AdapterExecutionError("form submission proposal is invalid") from exc
        except PolicyBlockedError:
            self._fail_attempt(context, attempt, "policy")
            raise
        except AdapterAuthExpiredError:
            self._fail_attempt(context, attempt, "auth_expired")
            raise
        except AdapterAuthRequiredError:
            self._fail_attempt(context, attempt, "auth_required")
            raise
        except AdapterDependencyError:
            self._fail_attempt(context, attempt, "dependency_missing")
            raise
        except AdapterExecutionError:
            self._fail_attempt(context, attempt, "adapter_failed")
            raise
        except (httpx.HTTPError, OSError, UnicodeError) as exc:
            self._fail_attempt(context, attempt, "adapter_failed")
            raise AdapterExecutionError("form transport failed") from exc
        except Exception as exc:
            self._fail_attempt(context, attempt, "adapter_failed")
            raise AdapterExecutionError("form execution boundary failed") from exc

        media_type = (
            response.headers.get("content-type", "application/octet-stream")
            .split(";", 1)[0]
            .strip()
        )
        resource = Resource(
            canonical_url=sanitize_url_for_request(
                str(response.url),
                context.request,
            ),
            requested_url=sanitize_url_for_request(
                submission.target,
                context.request,
            ),
            authority_url=sanitize_url_for_request(
                submission.target,
                context.request,
            ),
            media_type=media_type,
            status_code=response.status_code,
        )
        quality = (
            assess_text(
                response_body.decode(response.encoding or "utf-8", errors="replace"),
                media_type=media_type,
                expected_language=context.request.language,
            )
            if media_type.startswith("text/")
            or media_type in {"application/json", "application/xml"}
            else assess_binary(len(response_body), media_type=media_type)
        )
        uri, digest, size = await context.cas.put(response_body)
        artifact = build_artifact(
            role="source",
            representation="raw",
            media_type=media_type,
            cas_uri=uri,
            digest=digest,
            size=size,
            resource=resource,
            extractor="builtin-auth-form/0.3",
            quality=quality,
        )
        context.resources.append(resource)
        context.artifacts.append(artifact)
        context.accepted = context.accepted or (
            quality.accepted and quality.page_state != PageState.LOGIN
        )
        context.record_outcome(
            "form_submit",
            CapabilityOutcomeStatus.APPLIED,
            "auth",
            method=submission.method,
            status_code=response.status_code,
            field_count=len(payload),
            csrf_bound=submission.csrf is not None,
        )
        if response.extensions.get("fetech_ephemeral_login_cookie_handoff") is True:
            context.record_outcome(
                "cookie_session",
                CapabilityOutcomeStatus.APPLIED,
                "auth",
                ephemeral=True,
                exact_origin=True,
            )
            context.record_outcome(
                "login_session",
                CapabilityOutcomeStatus.APPLIED,
                "auth",
                established_by="approved_form_redirect",
                ephemeral=True,
            )
        if submission.csrf is not None:
            context.record_outcome(
                "csrf_token",
                CapabilityOutcomeStatus.APPLIED,
                "auth",
                attached=True,
            )
        context.record_runtime_event(
            "auth.form.submitted",
            "auth",
            capability_id="form_submit",
            method=submission.method,
            status_code=response.status_code,
        )
        self._finish_attempt(
            context,
            attempt,
            parser="approved-form",
            bytes_received=wire_bytes,
            artifact_ids=(artifact.artifact_id,),
        )

    async def _evaluate_form_action_policy(
        self,
        submission: FormSubmission,
        context: ExecutionContext,
    ) -> None:
        normalized, decisions = await self.http_adapter.policy.evaluate(
            submission.target,
            previous_url=context.request.target,
        )
        context.policy_decisions.extend(decisions)
        for decision in decisions:
            context.record_outcome(
                decision.policy_id,
                (
                    CapabilityOutcomeStatus.APPLIED
                    if decision.allowed
                    else CapabilityOutcomeStatus.BLOCKED
                ),
                "security",
                reason=decision.reason,
            )
        if normalized != submission.target:
            raise AdapterExecutionError(
                "form action changed during destination normalization"
            )

    @staticmethod
    def _context_csrf(context: ExecutionContext) -> CSRFTokenMaterial | None:
        token = context.sensitive_state.get("csrf_token")
        if token is None:
            return None
        if not isinstance(token, CSRFTokenMaterial):
            raise AdapterExecutionError("CSRF execution state is invalid")
        source_resource_id = context.sensitive_state.get(
            "csrf_source_resource_id"
        )
        if not isinstance(source_resource_id, UUID):
            raise AdapterExecutionError("CSRF source binding is missing")
        source = next(
            (
                resource
                for resource in context.resources
                if resource.resource_id == source_resource_id
            ),
            None,
        )
        if source is None or source.canonical_url != token.source_url:
            raise AdapterExecutionError("CSRF source binding is invalid")
        return token

    @staticmethod
    def _same_csrf_material(
        supplied: CSRFTokenMaterial,
        extracted: CSRFTokenMaterial,
    ) -> bool:
        return (
            supplied.source_url == extracted.source_url
            and supplied.form_action == extracted.form_action
            and supplied.form_method == extracted.form_method
            and supplied.field_name == extracted.field_name
            and compare_digest(supplied.token, extracted.token)
        )

    async def _resolve_session(
        self,
        reference: str,
        capability_id: str,
    ) -> OriginScopedSession:
        try:
            session = await self.session_provider.resolve(reference)
        except SessionProviderUnavailableError as exc:
            raise AdapterDependencyError("session provider is unavailable") from exc
        except SessionNotFoundError as exc:
            if capability_id in {"sso", "private_workspace"}:
                raise AdapterDependencyError(
                    "configured session connector is unavailable"
                ) from exc
            raise AdapterAuthRequiredError(
                "authentication reference has no configured session"
            ) from exc
        except SessionProviderError as exc:
            raise AdapterDependencyError("session provider failed") from exc
        except Exception as exc:
            raise AdapterDependencyError("session provider failed") from exc
        if not isinstance(session, OriginScopedSession):
            raise AdapterDependencyError(
                "session provider returned an invalid descriptor"
            )
        return session

    async def _resolve_material(self, reference: str) -> CredentialMaterial:
        try:
            material = await self.credential_provider.resolve(reference)
        except CredentialProviderUnavailableError as exc:
            raise AdapterDependencyError("credential provider is unavailable") from exc
        except CredentialNotFoundError as exc:
            raise AdapterAuthRequiredError(
                "authentication reference could not be resolved"
            ) from exc
        except CredentialProviderError as exc:
            raise AdapterDependencyError("credential provider failed") from exc
        except Exception as exc:
            raise AdapterDependencyError("credential provider failed") from exc
        if not isinstance(material, CredentialMaterial):
            raise AdapterDependencyError("credential provider returned invalid material")
        return material

    async def _resolve_submission(
        self,
        reference: str,
        run_id: UUID,
    ) -> FormSubmission:
        try:
            submission = await self.form_submission_provider.consume(reference, run_id)
        except FormSubmissionNotFoundError:
            raise
        except FormSubmissionProviderError:
            raise
        except Exception as exc:
            raise FormSubmissionProviderError("form submission provider failed") from exc
        if not isinstance(submission, FormSubmission):
            raise FormSubmissionProviderError(
                "form submission provider returned invalid material"
            )
        return submission

    @staticmethod
    def _start_attempt(node: PlanNode, context: ExecutionContext) -> FetchAttempt:
        attempt = FetchAttempt(
            capability_id=node.capability_id,
            sanitized_destination=sanitize_url(context.request.target),
            status=AttemptStatus.RUNNING,
        )
        context.attempts.append(attempt)
        return attempt

    @staticmethod
    def _finish_attempt(
        context: ExecutionContext,
        attempt: FetchAttempt,
        *,
        parser: str,
        bytes_received: int = 0,
        artifact_ids: tuple[UUID, ...] = (),
    ) -> None:
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.SUCCEEDED,
                "finished_at": datetime.now(UTC),
                "bytes_received": bytes_received,
                "parser": parser,
                "artifact_ids": artifact_ids,
            }
        )

    @staticmethod
    def _fail_attempt(
        context: ExecutionContext,
        attempt: FetchAttempt,
        failure_code: str,
    ) -> None:
        context.attempts[-1] = attempt.model_copy(
            update={
                "status": AttemptStatus.FAILED,
                "finished_at": datetime.now(UTC),
                "failure_code": failure_code,
            }
        )


def _origin(url: str) -> str:
    return canonical_origin(url)
