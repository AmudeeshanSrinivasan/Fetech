"""Mechanical v0.3 evidence matrix for every canonical capability ID."""

from __future__ import annotations

import ast
import importlib
import re
from dataclasses import dataclass
from pathlib import Path

import pytest

from fetech.models import FetchRequest, ImplementationStatus
from fetech.planning import DeterministicPlanner
from fetech.registry import CapabilityRegistry

ROOT = Path(__file__).resolve().parents[1]
CATALOG = ROOT / "docs" / "capability-catalog.md"
NODE_ID = re.compile(
    r"^tests/[a-zA-Z0-9_./-]+\.py::test_[a-zA-Z0-9_]+"
    r"(?:\[[a-zA-Z0-9_./:-]+\])?$"
)


@dataclass(frozen=True, slots=True)
class CapabilityEvidence:
    capability_id: str
    implementation_symbol: str
    owner_adapter: str
    planner_mode: str
    behavior_test: str


def _api(capability_id: str) -> CapabilityEvidence:
    return CapabilityEvidence(
        capability_id=capability_id,
        implementation_symbol="fetech.adapters.api:StructuredAPIAdapter",
        owner_adapter="api",
        planner_mode="exact",
        behavior_test=(
            "tests/test_v03_integration.py::"
            f"test_planner_selects_every_v03_api_capability[{capability_id}]"
        ),
    )


CASES = (
    CapabilityEvidence(
        "cookie_session",
        "fetech.auth:CredentialProvider",
        "http",
        "owner",
        "tests/test_v03_auth.py::test_authenticated_crawl_never_sends_credentials_to_robots",
    ),
    CapabilityEvidence(
        "login_session",
        "fetech.adapters.auth:AuthAdapter",
        "auth",
        "exact",
        "tests/test_v03_auth_flows.py::"
        "test_session_contract_rejects_insecure_scope_bad_refresh_and_wrong_material",
    ),
    CapabilityEvidence(
        "oauth",
        "fetech.adapters.auth:AuthAdapter",
        "auth",
        "exact",
        "tests/test_v03_integration.py::test_oauth_refreshes_once_and_emits_sanitized_events",
    ),
    CapabilityEvidence(
        "api_key",
        "fetech.auth:CredentialProvider",
        "http",
        "owner",
        "tests/test_v03_auth.py::test_exact_origin_credentials_are_injected_per_request",
    ),
    CapabilityEvidence(
        "bearer_token",
        "fetech.auth:CredentialProvider",
        "http",
        "owner",
        "tests/test_v03_auth.py::test_only_explicit_protocol_evidence_marks_server_rejection_expired",
    ),
    CapabilityEvidence(
        "csrf_token",
        "fetech.auth_flows:extract_csrf_token",
        "auth",
        "exact",
        "tests/test_v03_auth_flows.py::"
        "test_csrf_extraction_accepts_only_one_bounded_same_origin_hidden_form_token",
    ),
    CapabilityEvidence(
        "form_submit",
        "fetech.adapters.auth:AuthAdapter",
        "auth",
        "exact",
        "tests/test_v03_auth_flows.py::"
        "test_mutating_form_submission_requires_live_exact_approval_and_hides_values",
    ),
    CapabilityEvidence(
        "sso",
        "fetech.adapters.auth:AuthAdapter",
        "auth",
        "exact",
        "tests/test_v03_auth_flows.py::"
        "test_oauth_and_sso_sessions_are_opaque_exact_origin_and_refresh_bounded",
    ),
    CapabilityEvidence(
        "connector_auth",
        "fetech.auth:CredentialProvider",
        "http",
        "owner",
        "tests/test_v03_auth.py::test_exact_origin_credentials_are_injected_per_request",
    ),
    CapabilityEvidence(
        "private_workspace",
        "fetech.adapters.auth:AuthAdapter",
        "auth",
        "exact",
        "tests/test_v03_auth_flows.py::"
        "test_private_workspace_is_an_opaque_exact_origin_authenticated_connector_target",
    ),
    *(
        _api(capability_id)
        for capability_id in (
            "rest",
            "graphql",
            "json_endpoint",
            "xml_endpoint",
            "rss",
            "atom",
            "sitemap_xml",
            "openapi_discovery",
            "github_api",
            "semantic_scholar_api",
            "arxiv_api",
            "openreview_api",
            "crossref_openalex_api",
        )
    ),
)

CASE_BY_ID = {case.capability_id: case for case in CASES}

OWNER_SYMBOLS = {
    "http": "fetech.adapters.http:HTTPAdapter",
    "auth": "fetech.adapters.auth:AuthAdapter",
    "api": "fetech.adapters.api:StructuredAPIAdapter",
}


def _import_symbol(reference: str) -> object:
    module_name, symbol_name = reference.split(":", maxsplit=1)
    module = importlib.import_module(module_name)
    return getattr(module, symbol_name)


def _test_function_exists(node_id: str) -> bool:
    path_text, target = node_id.split("::", maxsplit=1)
    function_name = target.split("[", maxsplit=1)[0]
    path = ROOT / path_text
    if not path.is_file():
        return False
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return any(
        isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.name == function_name
        for node in tree.body
    )


def _request_for(case: CapabilityEvidence) -> FetchRequest:
    kwargs: dict[str, object] = {
        "target": "https://example.com/resource",
        "output_requirements": (case.capability_id,),
    }
    if case.owner_adapter in {"auth", "http"}:
        kwargs["authentication_ref"] = "vault://matrix/opaque-reference"
    if case.capability_id == "form_submit":
        kwargs["approved_capabilities"] = frozenset({"form_submit"})
    return FetchRequest(**kwargs)


def test_v03_matrix_is_an_exact_projection_of_the_manifest() -> None:
    registry = CapabilityRegistry()
    v03_ids = {
        entry.id for entry in registry if entry.closure_release == "v0.3"
    }

    assert len(registry.categories) == 13
    assert len(registry) == 155
    assert len(CASES) == len(CASE_BY_ID) == 23
    assert set(CASE_BY_ID) == v03_ids


@pytest.mark.parametrize("case", CASES, ids=lambda case: case.capability_id)
def test_v03_capability_evidence_matrix(
    case: CapabilityEvidence,
    request: pytest.FixtureRequest,
) -> None:
    registry = CapabilityRegistry()
    entry = registry.get(case.capability_id)
    anchor = case.capability_id.replace("_", "-")
    evidence_node = (
        "tests/test_v03_capability_matrix.py::"
        f"test_v03_capability_evidence_matrix[{case.capability_id}]"
    )

    assert entry.reference == f"docs/capability-catalog.md#{anchor}"
    assert f'<a id="{anchor}"></a>' in CATALOG.read_text(encoding="utf-8")
    assert entry.tests == (evidence_node, case.behavior_test)
    assert request.node.nodeid == evidence_node

    implementation = _import_symbol(case.implementation_symbol)
    owner = _import_symbol(OWNER_SYMBOLS[case.owner_adapter])
    assert implementation is not None
    assert owner is not None
    assert entry.adapter == case.owner_adapter
    module_name, symbol_name = case.implementation_symbol.split(":", maxsplit=1)
    assert module_name in entry.implementation
    assert symbol_name in entry.implementation

    plan = DeterministicPlanner(registry).plan(_request_for(case))
    assert any(node.adapter == case.owner_adapter for node in plan.nodes)
    if case.planner_mode == "exact":
        assert any(
            node.adapter == case.owner_adapter
            and node.capability_id == case.capability_id
            for node in plan.nodes
        )

    assert NODE_ID.fullmatch(evidence_node)
    assert NODE_ID.fullmatch(case.behavior_test)
    assert _test_function_exists(evidence_node)
    assert _test_function_exists(case.behavior_test)
    assert entry.implementation_status in {
        ImplementationStatus.NATIVE,
        ImplementationStatus.OPTIONAL,
    }
