from __future__ import annotations

import ast
import inspect
from dataclasses import FrozenInstanceError
from datetime import UTC, datetime, timedelta
from uuid import uuid4

import pytest

import fetech.auth_flows as auth_flows
from fetech.auth import CredentialMaterial
from fetech.auth_flows import (
    MAX_CSRF_HTML_BYTES,
    ApprovalRequiredError,
    AuthFlowError,
    CSRFExtractionError,
    CSRFTokenAmbiguousError,
    CSRFTokenMaterial,
    CSRFTokenNotFoundError,
    FormSubmission,
    FormSubmissionApproval,
    FormSubmissionNotFoundError,
    InMemoryFormSubmissionProvider,
    NullFormSubmissionProvider,
    OriginScopedSession,
    PrivateWorkspaceTarget,
    SessionBindingError,
    SessionCapability,
    extract_csrf_token,
)


def test_oauth_and_sso_sessions_are_opaque_exact_origin_and_refresh_bounded() -> None:
    now = datetime.now(UTC)
    access_ref = "vault://oauth/access-reference"
    refresh_ref = "vault://oauth/refresh-reference"
    session = OriginScopedSession.oauth(
        "https://API.EXAMPLE:443",
        access_ref,
        issuer_origin="https://identity.example",
        expires_at=now + timedelta(minutes=10),
        refresh_ref=refresh_ref,
        refresh_after=now + timedelta(minutes=5),
        scopes=("read:documents", "read:profile"),
    )

    assert session.origin == "https://api.example"
    assert session.applies_to("https://api.example/private/documents")
    assert not session.applies_to("https://sub.api.example/private")
    assert not session.applies_to("http://api.example/private")
    assert not session.needs_refresh(at=now + timedelta(minutes=4))
    assert session.needs_refresh(at=now + timedelta(minutes=6))
    assert not session.expired(at=now + timedelta(minutes=6))
    assert access_ref not in repr(session)
    assert refresh_ref not in repr(session)
    assert access_ref not in repr(session.public_metadata())
    assert refresh_ref not in repr(session.public_metadata())
    assert session.public_metadata()["refresh_available"] is True

    session.validate_material(
        CredentialMaterial.bearer(
            "https://api.example",
            "access-secret",
            expires_at=now + timedelta(minutes=9),
        ),
        at=now,
    )
    sso = OriginScopedSession.sso(
        "https://workspace.example",
        "keychain://sso/session",
        issuer_origin="https://idp.example",
    )
    sso.validate_material(
        CredentialMaterial.cookie_session(
            "https://workspace.example",
            {"session": "sso-cookie-secret"},
        )
    )


def test_session_contract_rejects_insecure_scope_bad_refresh_and_wrong_material() -> None:
    now = datetime.now(UTC)

    with pytest.raises(SessionBindingError, match="HTTPS"):
        OriginScopedSession.login_session("http://example.com", "vault://login")
    with pytest.raises(SessionBindingError, match="issuer"):
        OriginScopedSession(
            origin="https://example.com",
            capability_id=SessionCapability.OAUTH,
            authentication_ref="vault://oauth",
        )
    with pytest.raises(SessionBindingError, match="unsupported capability"):
        OriginScopedSession(
            origin="https://example.com",
            capability_id="csrf_token",  # type: ignore[arg-type]
            authentication_ref="vault://csrf",
        )
    with pytest.raises(SessionBindingError, match="refresh_after"):
        OriginScopedSession.oauth(
            "https://example.com",
            "vault://oauth",
            issuer_origin="https://idp.example",
            refresh_after=now,
        )
    with pytest.raises(SessionBindingError, match="later"):
        OriginScopedSession.oauth(
            "https://example.com",
            "vault://oauth",
            issuer_origin="https://idp.example",
            expires_at=now + timedelta(minutes=1),
            refresh_ref="vault://refresh",
            refresh_after=now + timedelta(minutes=2),
        )
    with pytest.raises(SessionBindingError, match="timezone"):
        OriginScopedSession.login_session(
            "https://example.com",
            "vault://login",
            expires_at=datetime(2030, 1, 1),
        )

    login = OriginScopedSession.login_session("https://example.com", "vault://login")
    with pytest.raises(SessionBindingError, match="credential type"):
        login.validate_material(CredentialMaterial.bearer("https://example.com", "secret"))
    with pytest.raises(SessionBindingError, match="origin"):
        login.validate_material(
            CredentialMaterial.cookie_session("https://other.example", {"session": "secret"})
        )

    expired = OriginScopedSession.oauth(
        "https://example.com",
        "vault://oauth",
        issuer_origin="https://idp.example",
        expires_at=now - timedelta(seconds=1),
    )
    with pytest.raises(SessionBindingError, match="expired"):
        expired.validate_material(CredentialMaterial.bearer("https://example.com", "secret"), at=now)


def test_csrf_extraction_accepts_only_one_bounded_same_origin_hidden_form_token() -> None:
    secret = "csrf-top-secret"
    html = f"""
        <form action="https://attacker.example/collect" method="post">
          <input type="hidden" name="csrf_token" value="attacker-token">
        </form>
        <form action="/account/update" method="post">
          <input type="text" name="csrf_token" value="visible-field-is-not-a-token">
          <input type="hidden" name="csrf_token" value="{secret}">
        </form>
    """

    token = extract_csrf_token(
        html,
        "https://EXAMPLE.com:443/account",
        expected_action="/account/update",
    )

    assert token.origin == "https://example.com"
    assert token.form_action == "https://example.com/account/update"
    assert token.form_method == "POST"
    assert token.applies_to("https://example.com/account/update", "post")
    assert not token.applies_to("https://example.com/account/other", "POST")
    assert secret not in repr(token)
    assert "account/update" not in repr(token)
    assert secret not in repr(token.public_metadata())
    assert token.form_field() == {"csrf_token": secret}


def test_csrf_extraction_fails_closed_for_cross_origin_ambiguous_and_oversized_data() -> None:
    cross_origin = """
        <form action="https://attacker.example/submit" method="post">
          <input type="hidden" name="_csrf" value="secret">
        </form>
    """
    with pytest.raises(CSRFTokenNotFoundError):
        extract_csrf_token(cross_origin, "https://example.com/form")
    with pytest.raises(CSRFExtractionError, match="same-origin"):
        extract_csrf_token(
            "<form></form>",
            "https://example.com/form",
            expected_action="https://attacker.example/submit",
        )

    ambiguous = """
        <form action="/submit" method="post">
          <input type="hidden" name="_csrf" value="one">
          <input type="hidden" name="csrf_token" value="two">
        </form>
    """
    with pytest.raises(CSRFTokenAmbiguousError):
        extract_csrf_token(ambiguous, "https://example.com/form")

    with pytest.raises(CSRFExtractionError, match="HTML"):
        extract_csrf_token(
            b"x" * (MAX_CSRF_HTML_BYTES + 1),
            "https://example.com/form",
        )
    with pytest.raises(CSRFExtractionError, match="form budget"):
        extract_csrf_token(
            "<form></form><form></form>",
            "https://example.com/form",
            max_forms=1,
        )
    with pytest.raises(CSRFTokenNotFoundError):
        extract_csrf_token(
            '<form action="/submit"><input name="_csrf" value="not-hidden"></form>',
            "https://example.com/form",
        )


def test_mutating_form_submission_requires_live_exact_approval_and_hides_values() -> None:
    now = datetime.now(UTC)
    target = "https://example.com/account/update"
    token = CSRFTokenMaterial(
        source_url="https://example.com/account",
        form_action=target,
        form_method="POST",
        field_name="_csrf",
        token="csrf-secret",
    )

    with pytest.raises(ApprovalRequiredError, match="explicit approval"):
        FormSubmission(
            target=target,
            method="POST",
            fields={"password": "password-secret"},
            authentication_ref="vault://login/session",
            csrf=token,
        )

    wrong_approval = FormSubmissionApproval.grant(
        "https://example.com/account/other",
        "POST",
        granted_at=now,
    )
    with pytest.raises(ApprovalRequiredError, match="exact target"):
        FormSubmission(
            target=target,
            method="POST",
            fields={"password": "password-secret"},
            csrf=token,
            approval=wrong_approval,
        )

    approval = FormSubmissionApproval.grant(target, "POST", granted_at=now)
    reference = "vault://login/session"
    submission = FormSubmission(
        target=target,
        method="post",
        fields={"password": "password-secret"},
        authentication_ref=reference,
        csrf=token,
        approval=approval,
    )

    assert submission.mutating
    assert submission.origin == "https://example.com"
    assert "password-secret" not in repr(submission)
    assert "csrf-secret" not in repr(submission)
    assert reference not in repr(submission)
    assert submission.payload(at=now + timedelta(minutes=1)) == {
        "password": "password-secret",
        "_csrf": "csrf-secret",
    }
    with pytest.raises(ApprovalRequiredError):
        submission.payload(at=now + timedelta(minutes=6))
    with pytest.raises(TypeError):
        submission.fields["other"] = "value"  # type: ignore[index]
    with pytest.raises(FrozenInstanceError):
        submission.method = "GET"  # type: ignore[misc]


def test_get_form_proposals_are_rejected_and_mutating_forms_remain_bounded() -> None:
    with pytest.raises(AuthFlowError, match="GET form"):
        FormSubmission(
            target="https://example.com/search",
            method="GET",
            fields={"q": "fetech"},
        )

    with pytest.raises(AuthFlowError, match="field count"):
        FormSubmission(
            target="https://example.com/search",
            method="POST",
            fields={f"field_{index}": "x" for index in range(129)},
        )
    with pytest.raises(AuthFlowError, match="payload size"):
        FormSubmission(
            target="https://example.com/search",
            method="POST",
            fields={"q": "x" * (64 * 1024)},
        )
    with pytest.raises(AuthFlowError, match="HTTPS"):
        FormSubmission(target="http://example.com/search", method="POST")


@pytest.mark.asyncio
async def test_form_submission_providers_are_async_fail_closed_and_repr_safe() -> None:
    now = datetime.now(UTC)
    reference = "vault://form/private-reference"
    target = "https://example.com/account/update"
    submission = FormSubmission(
        target=target,
        method="POST",
        fields={"password": "password-secret"},
        authentication_ref=reference,
        approval=FormSubmissionApproval.grant(target, "POST", granted_at=now),
    )
    source = {reference: submission}
    provider = InMemoryFormSubmissionProvider(source)
    source.clear()

    resolved = await provider.consume(reference, uuid4())
    assert resolved is submission
    assert reference not in repr(provider)
    assert "password-secret" not in repr(provider)
    with pytest.raises(FormSubmissionNotFoundError, match="unavailable"):
        await provider.consume(reference, uuid4())

    unknown = "vault://form/unknown-reference"
    with pytest.raises(FormSubmissionNotFoundError) as error:
        await provider.consume(unknown, uuid4())
    assert unknown not in str(error.value)
    with pytest.raises(FormSubmissionNotFoundError, match="unavailable"):
        await NullFormSubmissionProvider().consume(reference, uuid4())

    public_submission = FormSubmission(
        target="https://example.com/search",
        method="POST",
        fields={"q": "fetech"},
        approval=FormSubmissionApproval.grant(
            "https://example.com/search",
            "POST",
        ),
    )
    with pytest.raises(SessionBindingError, match="require"):
        InMemoryFormSubmissionProvider({reference: public_submission})
    with pytest.raises(SessionBindingError, match="must match"):
        InMemoryFormSubmissionProvider({"vault://form/other": submission})


def test_private_workspace_is_an_opaque_exact_origin_authenticated_connector_target() -> None:
    reference = "vault://workspace/account-one"
    workspace = PrivateWorkspaceTarget(
        target="https://WORKSPACE.example:443/private/page",
        connector_id="workspace.documents",
        authentication_ref=reference,
    )
    session = workspace.as_session()

    assert workspace.origin == "https://workspace.example"
    assert session.capability_id is SessionCapability.PRIVATE_WORKSPACE
    assert session.applies_to(workspace.target)
    assert reference not in repr(workspace)
    assert reference not in repr(workspace.public_metadata())
    workspace.validate_material(
        CredentialMaterial.cookie_session(
            "https://workspace.example",
            {"session": "workspace-secret"},
        )
    )

    with pytest.raises(SessionBindingError, match="target origin"):
        workspace.validate_session(
            OriginScopedSession.private_workspace(
                "https://other.example",
                reference,
            )
        )
    with pytest.raises(SessionBindingError, match="different opaque reference"):
        workspace.validate_session(
            OriginScopedSession.private_workspace(
                "https://workspace.example",
                "vault://workspace/other",
            )
        )
    with pytest.raises(SessionBindingError, match="connector_id"):
        PrivateWorkspaceTarget(
            target="https://workspace.example/private",
            connector_id="../unsafe",
            authentication_ref=reference,
        )


def test_auth_flow_module_has_no_network_process_or_filesystem_execution_imports() -> None:
    tree = ast.parse(inspect.getsource(auth_flows))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".", maxsplit=1)[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".", maxsplit=1)[0])

    assert imported.isdisjoint(
        {
            "aiohttp",
            "httpx",
            "os",
            "pathlib",
            "requests",
            "shutil",
            "socket",
            "subprocess",
        }
    )
