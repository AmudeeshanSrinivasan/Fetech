"""The v0.4 release-readiness report must remain conservative and deterministic."""

from __future__ import annotations

import importlib.util
import inspect
import json
import sys
from pathlib import Path

import pytest
import yaml

from fetech.conformance import release_report
from fetech.registry import CapabilityRegistry

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check_v04_release_readiness.py"
SPEC = importlib.util.spec_from_file_location("fetech_release_readiness", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = MODULE
SPEC.loader.exec_module(MODULE)

CANONICAL_GATE_IDS = MODULE.CANONICAL_GATE_IDS
EXPECTED_GATE_METADATA = MODULE.EXPECTED_GATE_METADATA
GateResult = MODULE.GateResult
build_report = MODULE.build_report
classify_state = MODULE.classify_state
load_publication_gates = MODULE.load_publication_gates
main = MODULE.main
render_report = MODULE.render_report


def _gate_profile(*, duplicate: bool = False, omit_last: bool = False) -> str:
    gate_ids = list(CANONICAL_GATE_IDS)
    if duplicate:
        gate_ids[-1] = gate_ids[0]
    if omit_last:
        gate_ids.pop()
    sections: list[str] = []
    for gate_id in gate_ids:
        phase, evidence_kind = EXPECTED_GATE_METADATA[gate_id]
        lines = [
            "[[publication_gates]]",
            f'id = "{gate_id}"',
            f'phase = "{phase}"',
            f'evidence_kind = "{evidence_kind}"',
            f'description = "Verify {gate_id}."',
            f'pending_reason = "{gate_id} evidence is pending."',
        ]
        if gate_id == "final-sbom-and-license-report":
            lines.append('check = "candidate_evidence_v1"')
        elif gate_id == "wheel-sdist-checksums":
            lines.append('check = "release_artifacts_v1"')
        sections.append(
            "\n".join(lines)
        )
    return f"{'\n\n'.join(sections)}\n"


def _write_manifest(root: Path) -> None:
    categories = []
    capability_number = 0
    for category_number in range(13):
        category_capabilities = []
        count = 11 if category_number < 12 else 23
        for _ in range(count):
            capability_number += 1
            category_capabilities.append(
                {
                    "id": f"capability_{capability_number:03d}",
                    "aliases": [f"alias_{capability_number:03d}"],
                }
            )
        categories.append(
            {
                "id": f"category_{category_number + 1:02d}",
                "capabilities": category_capabilities,
            }
        )
    assert capability_number == 155
    manifest = root / "capabilities" / "manifest.yaml"
    manifest.parent.mkdir(parents=True)
    manifest.write_text(
        yaml.safe_dump({"categories": categories}, sort_keys=False),
        encoding="utf-8",
    )


def _write_project(
    root: Path,
    *,
    version: str = "0.3.0a0",
    runtime_version: str | None = None,
    openapi_version: str | None = None,
) -> Path:
    (root / "scripts").mkdir(parents=True)
    (root / "release").mkdir()
    package = root / "src" / "fetech"
    package.mkdir(parents=True)
    runtime_version = runtime_version or version
    openapi_version = openapi_version or version
    (package / "__init__.py").write_text(
        "from fetech.version import __version__\n",
        encoding="utf-8",
    )
    (package / "version.py").write_text(
        f'__version__ = "{runtime_version}"\n',
        encoding="utf-8",
    )
    (package / "daemon.py").write_text(
        "\n".join(
            (
                "from fetech.version import __version__",
                "",
                "def create_app():",
                "    return FastAPI(",
                '        title="Fetech",',
                (
                    "        version=__version__,"
                    if openapi_version == runtime_version
                    else f'        version="{openapi_version}",'
                ),
                "    )",
                "",
            )
        ),
        encoding="utf-8",
    )
    (root / "pyproject.toml").write_text(
        f'[project]\nname = "fetech"\nversion = "{version}"\n',
        encoding="utf-8",
    )
    (root / "uv.lock").write_text(
        "\n".join(
            (
                "version = 1",
                "",
                "[[package]]",
                'name = "fetech"',
                f'version = "{version}"',
                "",
            )
        ),
        encoding="utf-8",
    )
    profile = root / "scripts" / "release_v04_candidate.toml"
    profile.write_text(_gate_profile(), encoding="utf-8")
    (root / "scripts" / "release_published.toml").write_text(
        'profile_version = "1"\n',
        encoding="utf-8",
    )
    verifier = root / "scripts" / "generate_release_evidence.py"
    verifier.write_text(
        "\n".join(
            (
                "import sys",
                'raise SystemExit(1 if "--overlay-profile" in sys.argv else 0)',
                "",
            )
        ),
        encoding="utf-8",
    )
    _write_manifest(root)
    return profile


def test_profile_requires_exact_unique_canonical_gate_ids(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    profile = scripts / "release_v04_development.toml"

    profile.write_text(_gate_profile(duplicate=True), encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate publication gate ID"):
        load_publication_gates(tmp_path, profile)

    profile.write_text(_gate_profile(omit_last=True), encoding="utf-8")
    with pytest.raises(ValueError, match="exactly 14 publication gates"):
        load_publication_gates(tmp_path, profile)

    invalid = _gate_profile().replace(
        'id = "manifest-13-155"',
        'id = "invented-gate"',
        1,
    )
    profile.write_text(invalid, encoding="utf-8")
    with pytest.raises(ValueError, match="unknown canonical publication gate ID"):
        load_publication_gates(tmp_path, profile)


def test_profile_cannot_reclassify_a_prepublication_gate(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    profile = scripts / "release_v04_development.toml"
    profile.write_text(
        _gate_profile().replace(
            'phase = "prepublication"',
            'phase = "postpublication"',
            1,
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must use phase prepublication"):
        load_publication_gates(tmp_path, profile)


def test_profile_cannot_claim_a_gate_passed(tmp_path: Path) -> None:
    scripts = tmp_path / "scripts"
    scripts.mkdir()
    profile = scripts / "release_v04_development.toml"
    profile.write_text(f'{_gate_profile()}state = "passed"\n', encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported fields: state"):
        load_publication_gates(tmp_path, profile)


def test_report_is_deterministic_and_never_passes_from_profile_claims(
    tmp_path: Path,
) -> None:
    profile = _write_project(tmp_path)

    report = build_report(tmp_path, profile)
    rendered = render_report(report)
    decoded = json.loads(rendered)

    assert report == decoded
    assert rendered == render_report(build_report(tmp_path, profile))
    assert report["state"] == "blocked"
    assert report["summary"] == {
        "gate_count": 14,
        "passed_count": 2,
        "blocked_count": 12,
        "prepublication_blocked_count": 10,
        "postpublication_blocked_count": 2,
    }
    states = {gate["id"]: gate["state"] for gate in report["gates"]}
    assert states["manifest-13-155"] == "passed"
    assert states["published-history-integrity"] == "passed"
    assert states["release-version-0.4.0a0"] == "blocked"
    assert states["artifact-legal-review"] == "blocked"
    assert states["target-systemd-attestation"] == "blocked"
    assert states["git-tag-and-github-release"] == "blocked"
    assert str(tmp_path) not in rendered
    assert "raise SystemExit" not in rendered


def test_attestation_file_presence_is_not_treated_as_verification(
    tmp_path: Path,
) -> None:
    profile = _write_project(tmp_path)
    profile.write_text(
        profile.read_text(encoding="utf-8").replace(
            'pending_reason = "artifact-legal-review evidence is pending."',
            "\n".join(
                (
                    'pending_reason = "artifact-legal-review evidence is pending."',
                    'evidence_path = "release/legal-review.json"',
                )
            ),
        ),
        encoding="utf-8",
    )
    (tmp_path / "release" / "legal-review.json").write_text(
        '{"state":"passed"}\n',
        encoding="utf-8",
    )

    report = build_report(tmp_path, profile)
    legal_gate = next(
        gate
        for gate in report["gates"]
        if gate["id"] == "artifact-legal-review"
    )
    assert legal_gate["state"] == "blocked"


def test_state_requires_all_prepublication_then_all_publication_gates() -> None:
    results = [
        GateResult(
            id=gate_id,
            phase=phase,
            evidence_kind=evidence_kind,
            description="description",
            state="passed",
            reason="verified",
        )
        for gate_id, (phase, evidence_kind) in EXPECTED_GATE_METADATA.items()
    ]

    assert classify_state(results) == "published"

    results[-1] = GateResult(
        id=results[-1].id,
        phase="postpublication",
        evidence_kind="publication",
        description="description",
        state="blocked",
        reason="pending",
    )
    assert classify_state(results) == "publishable"

    results[0] = GateResult(
        id=results[0].id,
        phase="prepublication",
        evidence_kind="machine",
        description="description",
        state="blocked",
        reason="pending",
    )
    assert classify_state(results) == "blocked"


def test_cli_writes_checks_and_requires_publishable(tmp_path: Path) -> None:
    _write_project(tmp_path)
    arguments = ("--project-root", str(tmp_path))
    report_path = tmp_path / "release" / "fetech-v0.4-readiness.json"

    assert main((*arguments, "--write")) == 0
    assert report_path.is_file()
    assert main((*arguments, "--check")) == 0
    assert main((*arguments, "--check", "--require-publishable")) == 1

    report_path.write_text("{}\n", encoding="utf-8")
    assert main((*arguments, "--check")) == 1


def test_matching_target_version_does_not_pass_unverified_gates(
    tmp_path: Path,
) -> None:
    profile = _write_project(tmp_path, version="0.4.0a0")

    report = build_report(tmp_path, profile)
    states = {gate["id"]: gate["state"] for gate in report["gates"]}

    assert states["release-version-0.4.0a0"] == "passed"
    assert report["state"] == "blocked"
    assert report["summary"]["passed_count"] == 3


def test_candidate_evidence_gate_passes_only_through_its_verifier(
    tmp_path: Path,
) -> None:
    profile = _write_project(tmp_path, version="0.4.0a0")
    verifier = tmp_path / "scripts" / "generate_release_evidence.py"
    verifier.write_text("raise SystemExit(0)\n", encoding="utf-8")

    report = build_report(tmp_path, profile)
    evidence_gate = next(
        gate
        for gate in report["gates"]
        if gate["id"] == "final-sbom-and-license-report"
    )

    assert evidence_gate["state"] == "passed"
    assert report["summary"]["passed_count"] == 4


def test_artifact_gate_passes_only_through_the_dedicated_verifier(
    tmp_path: Path,
) -> None:
    profile = _write_project(tmp_path, version="0.4.0a0")
    verifier = tmp_path / "scripts" / "verify_v04_release_artifacts.py"
    verifier.write_text("raise SystemExit(0)\n", encoding="utf-8")
    artifact_dir = tmp_path / "dist"
    artifact_dir.mkdir()

    report = build_report(
        tmp_path,
        profile,
        release_artifacts_dir=artifact_dir,
    )
    artifact_gate = next(
        gate
        for gate in report["gates"]
        if gate["id"] == "wheel-sdist-checksums"
    )
    assert artifact_gate["state"] == "passed"
    assert report["summary"]["passed_count"] == 4

    verifier.write_text("raise SystemExit(1)\n", encoding="utf-8")
    failed = build_report(
        tmp_path,
        profile,
        release_artifacts_dir=artifact_dir,
    )
    failed_gate = next(
        gate
        for gate in failed["gates"]
        if gate["id"] == "wheel-sdist-checksums"
    )
    assert failed_gate["state"] == "blocked"


@pytest.mark.parametrize(
    ("runtime_version", "openapi_version"),
    (("0.3.0a0", "0.4.0a0"), ("0.4.0a0", "0.3.0a0")),
)
def test_version_gate_rejects_runtime_or_openapi_drift(
    tmp_path: Path,
    runtime_version: str,
    openapi_version: str,
) -> None:
    profile = _write_project(
        tmp_path,
        version="0.4.0a0",
        runtime_version=runtime_version,
        openapi_version=openapi_version,
    )

    report = build_report(tmp_path, profile)
    version_gate = next(
        gate
        for gate in report["gates"]
        if gate["id"] == "release-version-0.4.0a0"
    )

    assert version_gate["state"] == "blocked"


def test_default_outbound_identity_matches_candidate_version() -> None:
    from fetech.adapters.browser import BrowserAdapter
    from fetech.adapters.reader import ReaderAdapter
    from fetech.browser_worker import DEFAULT_USER_AGENT as WORKER_USER_AGENT
    from fetech.config import Settings
    from fetech.search import HTTPSearchProvider
    from fetech.version import DEFAULT_USER_AGENT, __version__

    assert __version__ == "0.4.0a0"
    assert DEFAULT_USER_AGENT.startswith(f"Fetech/{__version__} ")
    assert Settings.__dataclass_fields__["user_agent"].default == DEFAULT_USER_AGENT
    assert (
        inspect.signature(BrowserAdapter).parameters["user_agent"].default
        == DEFAULT_USER_AGENT
    )
    assert (
        inspect.signature(ReaderAdapter).parameters["user_agent"].default
        == DEFAULT_USER_AGENT
    )
    assert (
        inspect.signature(HTTPSearchProvider).parameters["user_agent"].default
        == DEFAULT_USER_AGENT
    )
    assert WORKER_USER_AGENT == DEFAULT_USER_AGENT


def test_release_note_capability_accounting_matches_live_registry() -> None:
    registry = CapabilityRegistry()
    expected = {
        "v0.1": (51, 5, 56, 56),
        "v0.2": (36, 4, 40, 96),
        "v0.3": (21, 2, 23, 119),
        "v0.4": (17, 19, 36, 155),
    }

    native_total = 0
    optional_total = 0
    for release, (native, optional, total, _) in expected.items():
        report = release_report(registry, release)
        assert report["status_counts"] == {
            "native": native,
            "optional": optional,
        }
        assert report["capability_count"] == total
        native_total += native
        optional_total += optional
    assert (native_total, optional_total, native_total + optional_total) == (
        125,
        30,
        155,
    )

    v03_notes = (ROOT / "docs" / "releases" / "v0.3.0a0.md").read_text(
        encoding="utf-8"
    )
    v04_notes = (ROOT / "docs" / "releases" / "v0.4.0a0.md").read_text(
        encoding="utf-8"
    )
    for release, (native, optional, total, cumulative) in expected.items():
        row_label = "v0.4 candidate" if release == "v0.4" else release
        row = (
            f"| {row_label} | {native} | {optional} | {total} | "
            f"{cumulative} |"
        )
        assert row in v04_notes
        if release != "v0.4":
            assert row in v03_notes
    assert "125 native and 30 optional" in v04_notes
