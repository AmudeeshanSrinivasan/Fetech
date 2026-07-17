"""Network-free, exact-origin contracts for authenticated session flows.

This module deliberately does not perform login, OAuth, SSO, refresh, or form
network requests.  It validates bounded proposals that an execution adapter can
consume only after the normal Python policy and approval gates have run.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from html.parser import HTMLParser
from types import MappingProxyType
from typing import Protocol
from urllib.parse import urljoin, urlsplit, urlunsplit
from uuid import UUID, uuid4

from fetech.auth import CredentialMaterial, canonical_origin

SUPPORTED_AUTH_FLOW_CAPABILITIES = frozenset(
    {
        "login_session",
        "oauth",
        "csrf_token",
        "form_submit",
        "sso",
        "private_workspace",
    }
)

MAX_CSRF_HTML_BYTES = 256 * 1024
MAX_CSRF_FORMS = 32
MAX_CSRF_FIELDS = 256
MAX_CSRF_TOKEN_BYTES = 4 * 1024
MAX_FORM_FIELDS = 128
MAX_FORM_BYTES = 64 * 1024
MAX_APPROVAL_LIFETIME = timedelta(minutes=15)

_FIELD_NAME = re.compile(r"^[A-Za-z0-9_.:\-\[\]]{1,128}$")
_CONNECTOR_ID = re.compile(r"^[a-z][a-z0-9_.-]{0,127}$")
_SCOPE = re.compile(r"^[\x21-\x7e]{1,256}$")
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_FORM_METHODS = frozenset({"GET", *_MUTATING_METHODS})
_MATERIAL_CAPABILITIES: dict[str, frozenset[str]] = {
    "login_session": frozenset({"cookie_session"}),
    "oauth": frozenset({"bearer_token"}),
    "sso": frozenset({"bearer_token", "cookie_session"}),
    "private_workspace": frozenset({"api_key", "bearer_token", "cookie_session"}),
}
_DEFAULT_CSRF_FIELD_NAMES = frozenset(
    {
        "_csrf",
        "_csrf_token",
        "__requestverificationtoken",
        "authenticity_token",
        "csrf",
        "csrf_token",
        "csrftoken",
    }
)


class AuthFlowError(ValueError):
    """Base error for an invalid or unsafe authentication-flow proposal."""


class SessionBindingError(AuthFlowError):
    """A session handle or resolved credential is not valid for the target origin."""


class SessionProviderError(RuntimeError):
    """Base error for a configured high-level session descriptor provider."""


class SessionNotFoundError(SessionProviderError):
    """An opaque authentication reference has no configured session descriptor."""


class SessionProviderUnavailableError(SessionProviderError):
    """No high-level session connector is configured or currently available."""


class CSRFExtractionError(AuthFlowError):
    """CSRF form data is missing, ambiguous, cross-origin, or over budget."""


class CSRFTokenNotFoundError(CSRFExtractionError):
    """No acceptable CSRF token was present in bounded same-origin form data."""


class CSRFTokenAmbiguousError(CSRFExtractionError):
    """Several different acceptable CSRF tokens were present."""


class ApprovalRequiredError(AuthFlowError):
    """A mutating form submission lacks a valid, explicit approval grant."""


class FormSubmissionProviderError(RuntimeError):
    """Base error for a configured form-submission proposal provider."""


class FormSubmissionNotFoundError(FormSubmissionProviderError):
    """An opaque authentication reference has no approved form proposal."""


class FormSubmissionProvider(Protocol):
    """Atomically consume an approved proposal for one execution run."""

    async def consume(self, authentication_ref: str, run_id: UUID) -> FormSubmission: ...


class SessionProvider(Protocol):
    """Resolve trusted, non-secret session metadata for an opaque reference."""

    async def resolve(self, authentication_ref: str) -> OriginScopedSession: ...


class SessionCapability(StrEnum):
    """Session-producing capability represented by an opaque credential handle."""

    LOGIN_SESSION = "login_session"
    OAUTH = "oauth"
    SSO = "sso"
    PRIVATE_WORKSPACE = "private_workspace"


@dataclass(frozen=True, slots=True)
class OriginScopedSession:
    """Opaque session/token metadata restricted to one canonical HTTPS origin.

    ``authentication_ref`` and ``refresh_ref`` are handles for a configured
    credential store.  They are never token, cookie, password, or refresh-token
    values and are intentionally excluded from representations and public
    metadata.
    """

    origin: str
    capability_id: SessionCapability
    authentication_ref: str = field(repr=False, compare=False)
    expires_at: datetime | None = None
    refresh_ref: str | None = field(default=None, repr=False, compare=False)
    refresh_after: datetime | None = None
    issuer_origin: str | None = None
    scopes: tuple[str, ...] = ()
    connector_id: str | None = None

    def __post_init__(self) -> None:
        origin = _https_origin(self.origin)
        reference = _opaque_reference(self.authentication_ref, "authentication_ref")
        try:
            capability = SessionCapability(self.capability_id)
        except ValueError as exc:
            raise SessionBindingError("session uses an unsupported capability") from exc
        expires_at = _aware_datetime(self.expires_at, "session expiry")
        refresh_after = _aware_datetime(self.refresh_after, "session refresh time")
        refresh_ref = (
            _opaque_reference(self.refresh_ref, "refresh_ref") if self.refresh_ref is not None else None
        )

        if capability in {SessionCapability.OAUTH, SessionCapability.SSO}:
            if self.issuer_origin is None:
                raise SessionBindingError("OAuth and SSO sessions require an HTTPS issuer origin")
            issuer_origin = _https_origin(self.issuer_origin)
        elif self.issuer_origin is not None:
            raise SessionBindingError("issuer_origin is supported only for OAuth and SSO sessions")
        else:
            issuer_origin = None
        if capability is SessionCapability.PRIVATE_WORKSPACE:
            connector_id = (
                _bounded_connector_id(self.connector_id)
                if self.connector_id is not None
                else None
            )
        elif self.connector_id is not None:
            raise SessionBindingError(
                "connector_id is supported only for private workspace sessions"
            )
        else:
            connector_id = None

        if refresh_after is not None and refresh_ref is None:
            raise SessionBindingError("refresh_after requires an opaque refresh_ref")
        if refresh_ref is not None and capability not in {
            SessionCapability.OAUTH,
            SessionCapability.SSO,
        }:
            raise SessionBindingError("refresh metadata is supported only for OAuth and SSO sessions")
        if expires_at is not None and refresh_after is not None and refresh_after > expires_at:
            raise SessionBindingError("refresh_after cannot be later than session expiry")

        scopes = tuple(self.scopes)
        if len(scopes) > 128 or len(set(scopes)) != len(scopes):
            raise SessionBindingError("session scopes must be unique and bounded")
        if any(_SCOPE.fullmatch(scope) is None for scope in scopes):
            raise SessionBindingError("session contains an invalid scope")

        object.__setattr__(self, "origin", origin)
        object.__setattr__(self, "capability_id", capability)
        object.__setattr__(self, "authentication_ref", reference)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "refresh_ref", refresh_ref)
        object.__setattr__(self, "refresh_after", refresh_after)
        object.__setattr__(self, "issuer_origin", issuer_origin)
        object.__setattr__(self, "scopes", scopes)
        object.__setattr__(self, "connector_id", connector_id)

    @classmethod
    def login_session(
        cls,
        origin: str,
        authentication_ref: str,
        *,
        expires_at: datetime | None = None,
    ) -> OriginScopedSession:
        return cls(
            origin=origin,
            capability_id=SessionCapability.LOGIN_SESSION,
            authentication_ref=authentication_ref,
            expires_at=expires_at,
        )

    @classmethod
    def oauth(
        cls,
        origin: str,
        authentication_ref: str,
        *,
        issuer_origin: str,
        expires_at: datetime | None = None,
        refresh_ref: str | None = None,
        refresh_after: datetime | None = None,
        scopes: tuple[str, ...] = (),
    ) -> OriginScopedSession:
        return cls(
            origin=origin,
            capability_id=SessionCapability.OAUTH,
            authentication_ref=authentication_ref,
            expires_at=expires_at,
            refresh_ref=refresh_ref,
            refresh_after=refresh_after,
            issuer_origin=issuer_origin,
            scopes=scopes,
        )

    @classmethod
    def sso(
        cls,
        origin: str,
        authentication_ref: str,
        *,
        issuer_origin: str,
        expires_at: datetime | None = None,
        refresh_ref: str | None = None,
        refresh_after: datetime | None = None,
        scopes: tuple[str, ...] = (),
    ) -> OriginScopedSession:
        return cls(
            origin=origin,
            capability_id=SessionCapability.SSO,
            authentication_ref=authentication_ref,
            expires_at=expires_at,
            refresh_ref=refresh_ref,
            refresh_after=refresh_after,
            issuer_origin=issuer_origin,
            scopes=scopes,
        )

    @classmethod
    def private_workspace(
        cls,
        origin: str,
        authentication_ref: str,
        *,
        connector_id: str | None = None,
        expires_at: datetime | None = None,
    ) -> OriginScopedSession:
        return cls(
            origin=origin,
            capability_id=SessionCapability.PRIVATE_WORKSPACE,
            authentication_ref=authentication_ref,
            expires_at=expires_at,
            connector_id=connector_id,
        )

    def applies_to(self, url: str) -> bool:
        try:
            return canonical_origin(_https_url(url)) == self.origin
        except ValueError:
            return False

    def expired(self, *, at: datetime | None = None) -> bool:
        instant = _comparison_time(at)
        return self.expires_at is not None and instant >= self.expires_at.astimezone(UTC)

    def needs_refresh(self, *, at: datetime | None = None) -> bool:
        if self.refresh_ref is None:
            return False
        instant = _comparison_time(at)
        if self.refresh_after is not None:
            return instant >= self.refresh_after.astimezone(UTC)
        return self.expires_at is not None and instant >= self.expires_at.astimezone(UTC)

    def validate_material(
        self,
        material: CredentialMaterial,
        *,
        at: datetime | None = None,
    ) -> None:
        """Validate resolved material without copying or serializing its secrets."""

        self.validate_material_binding(material)
        if self.expired(at=at):
            raise SessionBindingError("session metadata is expired")
        instant = _comparison_time(at)
        if material.expires_at is not None and instant >= material.expires_at.astimezone(UTC):
            raise SessionBindingError("resolved credential material is expired")

    def validate_material_binding(self, material: CredentialMaterial) -> None:
        """Validate origin and credential kind before any refresh is attempted."""

        if material.origin != self.origin:
            raise SessionBindingError("resolved credentials do not match the session origin")
        allowed = _MATERIAL_CAPABILITIES[self.capability_id.value]
        if material.capability_id not in allowed:
            raise SessionBindingError("resolved credential type is invalid for this session capability")

    def public_metadata(self) -> dict[str, object]:
        """Return persistence-safe metadata with all opaque references omitted."""

        return {
            "origin": self.origin,
            "capability_id": self.capability_id.value,
            "expires_at": self.expires_at.isoformat() if self.expires_at is not None else None,
            "refresh_after": (self.refresh_after.isoformat() if self.refresh_after is not None else None),
            "refresh_available": self.refresh_ref is not None,
            "issuer_origin": self.issuer_origin,
            "scopes": self.scopes,
            "connector_id": self.connector_id,
        }


@dataclass(frozen=True, slots=True)
class CSRFTokenMaterial:
    """Short-lived in-memory CSRF form field bound to one exact action URL."""

    source_url: str = field(repr=False)
    form_action: str = field(repr=False)
    form_method: str
    field_name: str
    token: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        source_url = _https_url(self.source_url)
        form_action = _https_url(self.form_action)
        method = _form_method(self.form_method)
        if canonical_origin(source_url) != canonical_origin(form_action):
            raise CSRFExtractionError("CSRF form action must use the source page origin")
        if _FIELD_NAME.fullmatch(self.field_name) is None:
            raise CSRFExtractionError("CSRF field name is invalid")
        _validate_secret_value(self.token, "CSRF token", MAX_CSRF_TOKEN_BYTES)
        object.__setattr__(self, "source_url", source_url)
        object.__setattr__(self, "form_action", form_action)
        object.__setattr__(self, "form_method", method)

    @property
    def origin(self) -> str:
        return canonical_origin(self.source_url)

    def applies_to(self, target: str, method: str) -> bool:
        try:
            return _https_url(target) == self.form_action and _form_method(method) == self.form_method
        except ValueError:
            return False

    def form_field(self) -> dict[str, str]:
        """Return an ephemeral payload fragment; callers must never persist it."""

        return {self.field_name: self.token}

    def public_metadata(self) -> dict[str, str]:
        return {
            "origin": self.origin,
            "form_method": self.form_method,
            "field_name": self.field_name,
        }


@dataclass(frozen=True, slots=True)
class FormSubmissionApproval:
    """Short-lived explicit approval for one mutating method and exact action URL."""

    approval_id: str
    target: str = field(repr=False)
    method: str
    expires_at: datetime
    granted_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    actor: str = "user"

    def __post_init__(self) -> None:
        approval_id = _bounded_label(self.approval_id, "approval_id")
        target = _https_url(self.target)
        method = _form_method(self.method)
        if method not in _MUTATING_METHODS:
            raise ApprovalRequiredError("approval grants are only valid for mutating form methods")
        granted_at = _aware_datetime(self.granted_at, "approval grant time")
        expires_at = _aware_datetime(self.expires_at, "approval expiry")
        assert granted_at is not None
        assert expires_at is not None
        if expires_at <= granted_at:
            raise ApprovalRequiredError("approval expiry must be later than grant time")
        if expires_at - granted_at > MAX_APPROVAL_LIFETIME:
            raise ApprovalRequiredError("approval lifetime exceeds the bounded maximum")
        actor = _bounded_label(self.actor, "approval actor")
        object.__setattr__(self, "approval_id", approval_id)
        object.__setattr__(self, "target", target)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "granted_at", granted_at)
        object.__setattr__(self, "expires_at", expires_at)
        object.__setattr__(self, "actor", actor)

    @classmethod
    def grant(
        cls,
        target: str,
        method: str,
        *,
        actor: str = "user",
        granted_at: datetime | None = None,
        valid_for: timedelta = timedelta(minutes=5),
    ) -> FormSubmissionApproval:
        instant = granted_at or datetime.now(UTC)
        if valid_for <= timedelta(0) or valid_for > MAX_APPROVAL_LIFETIME:
            raise ApprovalRequiredError("approval validity must be positive and bounded")
        return cls(
            approval_id=f"approval-{uuid4()}",
            target=target,
            method=method,
            granted_at=instant,
            expires_at=instant + valid_for,
            actor=actor,
        )

    def permits(
        self,
        target: str,
        method: str,
        *,
        at: datetime | None = None,
    ) -> bool:
        try:
            normalized_target = _https_url(target)
            normalized_method = _form_method(method)
        except ValueError:
            return False
        instant = _comparison_time(at)
        return (
            normalized_target == self.target
            and normalized_method == self.method
            and self.granted_at.astimezone(UTC) <= instant < self.expires_at.astimezone(UTC)
        )

    def public_metadata(self) -> dict[str, str]:
        return {
            "approval_id": self.approval_id,
            "origin": canonical_origin(self.target),
            "method": self.method,
            "actor": self.actor,
            "granted_at": self.granted_at.isoformat(),
            "expires_at": self.expires_at.isoformat(),
        }


@dataclass(frozen=True, slots=True)
class FormSubmission:
    """Bounded form proposal; mutating instances require exact, live approval."""

    target: str = field(repr=False)
    method: str
    fields: Mapping[str, str] = field(default_factory=dict, repr=False, compare=False, hash=False)
    authentication_ref: str | None = field(default=None, repr=False, compare=False)
    csrf: CSRFTokenMaterial | None = field(default=None, repr=False, compare=False)
    approval: FormSubmissionApproval | None = field(default=None, repr=False, compare=False)

    def __post_init__(self) -> None:
        target = _https_url(self.target)
        method = _form_method(self.method)
        if method == "GET":
            raise AuthFlowError(
                "GET form proposals are unsupported; encode retrieval fields in the target URL"
            )
        fields = _validated_form_fields(self.fields)
        authentication_ref = (
            _opaque_reference(self.authentication_ref, "authentication_ref")
            if self.authentication_ref is not None
            else None
        )
        if self.csrf is not None:
            if not self.csrf.applies_to(target, method):
                raise CSRFExtractionError("CSRF token is not bound to the exact form action and method")
            existing = fields.get(self.csrf.field_name)
            if existing is not None and existing != self.csrf.token:
                raise CSRFExtractionError("form fields conflict with the bound CSRF token")

        object.__setattr__(self, "target", target)
        object.__setattr__(self, "method", method)
        object.__setattr__(self, "fields", MappingProxyType(fields))
        object.__setattr__(self, "authentication_ref", authentication_ref)
        self.assert_authorized()

    @property
    def mutating(self) -> bool:
        return self.method in _MUTATING_METHODS

    @property
    def origin(self) -> str:
        return canonical_origin(self.target)

    def assert_authorized(self, *, at: datetime | None = None) -> None:
        if self.mutating and (
            self.approval is None or not self.approval.permits(self.target, self.method, at=at)
        ):
            raise ApprovalRequiredError(
                "mutating form submission requires explicit approval for the exact target and method"
            )

    def payload(self, *, at: datetime | None = None) -> dict[str, str]:
        """Return an ephemeral body after rechecking approval at execution time."""

        self.assert_authorized(at=at)
        payload = dict(self.fields)
        if self.csrf is not None:
            payload[self.csrf.field_name] = self.csrf.token
        return payload

    def public_metadata(self) -> dict[str, object]:
        return {
            "origin": self.origin,
            "method": self.method,
            "field_count": len(self.fields) + (1 if self.csrf is not None else 0),
            "authenticated": self.authentication_ref is not None,
            "csrf_bound": self.csrf is not None,
            "approval_id": self.approval.approval_id if self.approval is not None else None,
        }


class NullFormSubmissionProvider:
    """Fail-closed default when no explicit form proposal source is configured."""

    async def consume(
        self,
        authentication_ref: str,
        run_id: UUID,
    ) -> FormSubmission:
        del authentication_ref, run_id
        raise FormSubmissionNotFoundError("approved form submission is unavailable")


class InMemoryFormSubmissionProvider:
    """Process-local, one-shot proposal provider with atomic event-loop consumption."""

    def __init__(self, submissions: Mapping[str, FormSubmission]) -> None:
        validated: dict[str, FormSubmission] = {}
        for reference, submission in submissions.items():
            normalized = _opaque_reference(reference, "authentication_ref")
            if submission.authentication_ref is None:
                raise SessionBindingError("provider form submissions require an opaque authentication_ref")
            if submission.authentication_ref != normalized:
                raise SessionBindingError("provider key must match the form submission authentication_ref")
            validated[normalized] = submission
        self._submissions = validated

    def __repr__(self) -> str:
        return f"{type(self).__name__}(submissions={len(self._submissions)})"

    async def consume(
        self,
        authentication_ref: str,
        run_id: UUID,
    ) -> FormSubmission:
        reference = _opaque_reference(authentication_ref, "authentication_ref")
        if not isinstance(run_id, UUID):
            raise FormSubmissionProviderError("form submission run_id must be a UUID")
        try:
            submission = self._submissions.pop(reference)
        except KeyError as exc:
            raise FormSubmissionNotFoundError("approved form submission is unavailable") from exc
        submission.assert_authorized()
        return submission


class NullSessionProvider:
    """Fail closed when no trusted session connector has been configured."""

    async def resolve(self, authentication_ref: str) -> OriginScopedSession:
        del authentication_ref
        raise SessionProviderUnavailableError("session provider is unavailable")


class InMemorySessionProvider:
    """Process-local provider for trusted, immutable session descriptors."""

    def __init__(self, sessions: Mapping[str, OriginScopedSession]) -> None:
        validated: dict[str, OriginScopedSession] = {}
        for reference, session in sessions.items():
            normalized = _opaque_reference(reference, "authentication_ref")
            if session.authentication_ref != normalized:
                raise SessionBindingError(
                    "provider key must match the session authentication_ref"
                )
            if (
                session.capability_id is SessionCapability.PRIVATE_WORKSPACE
                and session.connector_id is None
            ):
                raise SessionBindingError(
                    "private workspace session providers require a connector_id"
                )
            validated[normalized] = session
        self._sessions = MappingProxyType(validated)

    def __repr__(self) -> str:
        return f"{type(self).__name__}(sessions={len(self._sessions)})"

    async def resolve(self, authentication_ref: str) -> OriginScopedSession:
        reference = _opaque_reference(authentication_ref, "authentication_ref")
        try:
            return self._sessions[reference]
        except KeyError as exc:
            raise SessionNotFoundError("session descriptor is unavailable") from exc


@dataclass(frozen=True, slots=True)
class PrivateWorkspaceTarget:
    """Origin-scoped authenticated connector target for a private workspace."""

    target: str = field(repr=False)
    connector_id: str
    authentication_ref: str = field(repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "target", _https_url(self.target))
        if _CONNECTOR_ID.fullmatch(self.connector_id) is None:
            raise SessionBindingError("private workspace connector_id is invalid")
        object.__setattr__(
            self,
            "authentication_ref",
            _opaque_reference(self.authentication_ref, "authentication_ref"),
        )

    @property
    def origin(self) -> str:
        return canonical_origin(self.target)

    def as_session(self, *, expires_at: datetime | None = None) -> OriginScopedSession:
        return OriginScopedSession.private_workspace(
            self.origin,
            self.authentication_ref,
            connector_id=self.connector_id,
            expires_at=expires_at,
        )

    def validate_session(self, session: OriginScopedSession) -> None:
        if session.capability_id is not SessionCapability.PRIVATE_WORKSPACE:
            raise SessionBindingError("private workspace session uses the wrong capability")
        if session.origin != self.origin:
            raise SessionBindingError("private workspace session does not match the target origin")
        if session.authentication_ref != self.authentication_ref:
            raise SessionBindingError("private workspace session uses a different opaque reference")
        if session.connector_id != self.connector_id:
            raise SessionBindingError(
                "private workspace session uses a different connector_id"
            )

    def validate_material(
        self,
        material: CredentialMaterial,
        *,
        at: datetime | None = None,
    ) -> None:
        self.as_session(expires_at=material.expires_at).validate_material(material, at=at)

    def public_metadata(self) -> dict[str, str]:
        return {"origin": self.origin, "connector_id": self.connector_id}


def extract_csrf_token(
    html: str | bytes,
    page_url: str,
    *,
    expected_action: str | None = None,
    field_names: frozenset[str] = _DEFAULT_CSRF_FIELD_NAMES,
    max_html_bytes: int = MAX_CSRF_HTML_BYTES,
    max_forms: int = MAX_CSRF_FORMS,
    max_fields: int = MAX_CSRF_FIELDS,
) -> CSRFTokenMaterial:
    """Extract one hidden CSRF input from bounded, same-origin form data.

    Cross-origin actions, non-hidden inputs, over-budget documents, and
    ambiguous token sets fail closed.  This parser does not perform network
    requests and does not execute scripts.
    """

    _bounded_limit(max_html_bytes, MAX_CSRF_HTML_BYTES, "CSRF HTML byte")
    _bounded_limit(max_forms, MAX_CSRF_FORMS, "CSRF form")
    _bounded_limit(max_fields, MAX_CSRF_FIELDS, "CSRF field")
    source_url = _https_url(page_url)
    source_origin = canonical_origin(source_url)
    normalized_expected: str | None = None
    if expected_action is not None:
        normalized_expected = _https_url(urljoin(source_url, expected_action))
        if canonical_origin(normalized_expected) != source_origin:
            raise CSRFExtractionError("expected CSRF form action must be same-origin")

    if isinstance(html, bytes):
        raw = html
        text = html.decode("utf-8", errors="replace")
    else:
        text = html
        raw = html.encode("utf-8")
    if len(raw) > max_html_bytes:
        raise CSRFExtractionError("HTML exceeds the bounded CSRF extraction budget")

    normalized_names = frozenset(name.casefold() for name in field_names)
    if (
        not normalized_names
        or len(normalized_names) > 32
        or any(_FIELD_NAME.fullmatch(name) is None for name in normalized_names)
    ):
        raise CSRFExtractionError("CSRF field-name allowlist is invalid or unbounded")

    parser = _BoundedCSRFParser(
        field_names=normalized_names,
        max_forms=max_forms,
        max_fields=max_fields,
    )
    try:
        parser.feed(text)
        parser.close()
    except CSRFExtractionError:
        raise
    except Exception as exc:
        raise CSRFExtractionError("HTML form data could not be parsed safely") from exc

    accepted: dict[tuple[str, str, str, str], CSRFTokenMaterial] = {}
    for action, method, name, token in parser.candidates:
        try:
            normalized_action = _https_url(urljoin(source_url, action or source_url))
        except ValueError:
            continue
        if canonical_origin(normalized_action) != source_origin:
            continue
        if normalized_expected is not None and normalized_action != normalized_expected:
            continue
        material = CSRFTokenMaterial(
            source_url=source_url,
            form_action=normalized_action,
            form_method=method,
            field_name=name,
            token=token,
        )
        accepted[(normalized_action, material.form_method, name, token)] = material

    if not accepted:
        raise CSRFTokenNotFoundError("no bounded same-origin CSRF form token was found")
    if len(accepted) != 1:
        raise CSRFTokenAmbiguousError("several different same-origin CSRF tokens were found")
    return next(iter(accepted.values()))


@dataclass(frozen=True, slots=True)
class _FormState:
    action: str
    method: str


class _BoundedCSRFParser(HTMLParser):
    def __init__(
        self,
        *,
        field_names: frozenset[str],
        max_forms: int,
        max_fields: int,
    ) -> None:
        super().__init__(convert_charrefs=True)
        self._field_names = field_names
        self._max_forms = max_forms
        self._max_fields = max_fields
        self._forms = 0
        self._fields = 0
        self._form: _FormState | None = None
        self.candidates: list[tuple[str, str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        lowered = tag.casefold()
        attributes = _attributes(attrs)
        if lowered == "form":
            if self._form is not None:
                raise CSRFExtractionError("nested form data is rejected")
            self._forms += 1
            if self._forms > self._max_forms:
                raise CSRFExtractionError("HTML exceeds the bounded CSRF form budget")
            self._form = _FormState(
                action=attributes.get("action", ""),
                method=attributes.get("method", "GET"),
            )
            return
        if lowered != "input" or self._form is None:
            return
        self._fields += 1
        if self._fields > self._max_fields:
            raise CSRFExtractionError("HTML exceeds the bounded CSRF field budget")
        name = attributes.get("name", "")
        if attributes.get("type", "text").casefold() != "hidden" or name.casefold() not in self._field_names:
            return
        token = attributes.get("value", "")
        _validate_secret_value(token, "CSRF token", MAX_CSRF_TOKEN_BYTES)
        self.candidates.append((self._form.action, self._form.method, name, token))

    def handle_endtag(self, tag: str) -> None:
        if tag.casefold() == "form":
            self._form = None


def _attributes(attrs: list[tuple[str, str | None]]) -> dict[str, str]:
    result: dict[str, str] = {}
    for name, value in attrs:
        lowered = name.casefold()
        if lowered in result:
            raise CSRFExtractionError("duplicate HTML form attributes are rejected")
        result[lowered] = value or ""
    return result


def _https_origin(url: str) -> str:
    try:
        origin = canonical_origin(url, origin_only=True)
    except ValueError as exc:
        raise SessionBindingError(str(exc)) from exc
    if not origin.startswith("https://"):
        raise SessionBindingError("authenticated session origins must use HTTPS")
    return origin


def _https_url(url: str) -> str:
    candidate = url.strip()
    parts = urlsplit(candidate)
    if parts.scheme.lower() != "https":
        raise AuthFlowError("authenticated flow targets must use HTTPS")
    if parts.username or parts.password:
        raise AuthFlowError("authenticated flow targets cannot contain user information")
    if not parts.hostname:
        raise AuthFlowError("authenticated flow targets require a hostname")
    if parts.fragment:
        raise AuthFlowError("authenticated flow targets cannot contain fragments")
    try:
        origin = canonical_origin(candidate)
    except ValueError as exc:
        raise AuthFlowError(str(exc)) from exc
    path = parts.path or "/"
    return urlunsplit(("https", urlsplit(origin).netloc, path, parts.query, ""))


def _form_method(method: str) -> str:
    normalized = method.strip().upper()
    if normalized not in _FORM_METHODS:
        raise AuthFlowError("form method is unsupported")
    return normalized


def _opaque_reference(value: str | None, name: str) -> str:
    if value is None:
        raise SessionBindingError(f"{name} is required")
    candidate = value.strip()
    if (
        not candidate
        or len(candidate.encode("utf-8")) > 2_048
        or any(ord(character) < 32 or ord(character) == 127 for character in candidate)
    ):
        raise SessionBindingError(f"{name} must be a bounded opaque reference")
    return candidate


def _bounded_connector_id(value: str) -> str:
    candidate = value.strip()
    if _CONNECTOR_ID.fullmatch(candidate) is None:
        raise SessionBindingError("private workspace connector_id is invalid")
    return candidate


def _aware_datetime(value: datetime | None, name: str) -> datetime | None:
    if value is not None and value.utcoffset() is None:
        raise SessionBindingError(f"{name} must include a timezone")
    return value


def _comparison_time(value: datetime | None) -> datetime:
    if value is None:
        return datetime.now(UTC)
    if value.utcoffset() is None:
        raise SessionBindingError("comparison time must include a timezone")
    return value.astimezone(UTC)


def _validated_form_fields(fields: Mapping[str, str]) -> dict[str, str]:
    if len(fields) > MAX_FORM_FIELDS:
        raise AuthFlowError("form exceeds the bounded field count")
    result: dict[str, str] = {}
    total = 0
    for name, value in fields.items():
        if _FIELD_NAME.fullmatch(name) is None:
            raise AuthFlowError("form contains an invalid field name")
        _validate_secret_value(value, "form field value", MAX_FORM_BYTES)
        total += len(name.encode("utf-8")) + len(value.encode("utf-8"))
        if total > MAX_FORM_BYTES:
            raise AuthFlowError("form exceeds the bounded payload size")
        result[name] = value
    return result


def _validate_secret_value(value: str, name: str, maximum_bytes: int) -> None:
    if not value or "\x00" in value or len(value.encode("utf-8")) > maximum_bytes:
        raise AuthFlowError(f"{name} must be non-empty, bounded, and contain no NUL bytes")


def _bounded_limit(value: int, maximum: int, name: str) -> None:
    if value < 1 or value > maximum:
        raise CSRFExtractionError(f"{name} limit must be positive and no greater than {maximum}")


def _bounded_label(value: str, name: str) -> str:
    candidate = value.strip()
    if (
        not candidate
        or len(candidate) > 256
        or any(not 32 <= ord(character) <= 126 for character in candidate)
    ):
        raise AuthFlowError(f"{name} must be printable and bounded")
    return candidate
