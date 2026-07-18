#!/usr/bin/env python3
"""Render and verify the conservative v0.4 publication-readiness report."""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, Literal

import yaml

TARGET_VERSION: Final = "0.4.0a0"
REPORT_SCHEMA_VERSION: Final = "1"
DEFAULT_PROFILE: Final = Path("scripts/release_v04_development.toml")
DEFAULT_OUTPUT: Final = Path("release/fetech-v0.4-readiness.json")
MAX_PROFILE_BYTES: Final = 256 * 1024
MAX_TEXT_BYTES: Final = 4_000
CHECK_NAME_PATTERN: Final = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}\Z")

Phase = Literal["prepublication", "postpublication"]
EvidenceKind = Literal["machine", "attestation", "publication"]
GateState = Literal["passed", "blocked"]
ReadinessState = Literal["blocked", "publishable", "published"]

# Phase and evidence kind are part of the security boundary. In particular, an
# edited profile cannot reclassify a prepublication gate as postpublication and
# thereby make an incomplete release appear publishable.
EXPECTED_GATE_METADATA: Final[dict[str, tuple[Phase, EvidenceKind]]] = {
    "manifest-13-155": ("prepublication", "machine"),
    "quality-suite": ("prepublication", "attestation"),
    "published-history-integrity": ("prepublication", "machine"),
    "release-version-0.4.0a0": ("prepublication", "machine"),
    "final-sbom-and-license-report": ("prepublication", "machine"),
    "wheel-sdist-checksums": ("prepublication", "machine"),
    "complete-artifact-smoke": ("prepublication", "machine"),
    "release-commit-ci": ("prepublication", "attestation"),
    "target-systemd-attestation": ("prepublication", "attestation"),
    "ytdlp-egress-or-narrowed-claim": ("prepublication", "attestation"),
    "artifact-legal-review": ("prepublication", "attestation"),
    "optional-runtime-live-evidence": ("prepublication", "attestation"),
    "git-tag-and-github-release": ("postpublication", "publication"),
    "package-publication": ("postpublication", "publication"),
}
CANONICAL_GATE_IDS: Final = tuple(EXPECTED_GATE_METADATA)
_ALLOWED_GATE_FIELDS: Final = {
    "id",
    "phase",
    "evidence_kind",
    "description",
    "pending_reason",
    "evidence_path",
    "check",
}


@dataclass(frozen=True, slots=True)
class PublicationGate:
    """One validated gate from the checked-in release profile."""

    id: str
    phase: Phase
    evidence_kind: EvidenceKind
    description: str
    pending_reason: str
    evidence_path: str | None = None
    check: str | None = None


@dataclass(frozen=True, slots=True)
class GateResult:
    """Sanitized result of evaluating one publication gate."""

    id: str
    phase: Phase
    evidence_kind: EvidenceKind
    description: str
    state: GateState
    reason: str

    def as_document(self) -> dict[str, str]:
        return {
            "id": self.id,
            "phase": self.phase,
            "evidence_kind": self.evidence_kind,
            "description": self.description,
            "state": self.state,
            "reason": self.reason,
        }


def _bounded_text(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"publication gate {field} must be a string")
    text = value.strip()
    if (
        not text
        or len(text.encode("utf-8")) > MAX_TEXT_BYTES
        or any(character in text for character in ("\x00", "\r", "\n"))
    ):
        raise ValueError(
            f"publication gate {field} must be bounded, non-empty single-line text"
        )
    return text


def _repository_path(project_root: Path, value: object, field: str) -> str:
    text = _bounded_text(value, field)
    relative = Path(text)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError(f"publication gate {field} must be project-relative")
    root = project_root.resolve()
    try:
        (root / relative).resolve().relative_to(root)
    except ValueError as exc:
        raise ValueError(
            f"publication gate {field} must remain within the project root"
        ) from exc
    return relative.as_posix()


def _root_file(project_root: Path, path: Path, label: str) -> Path:
    root = project_root.resolve()
    candidate = path if path.is_absolute() else root / path
    if candidate.is_symlink():
        raise ValueError(f"{label} cannot be a symlink")
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError(f"{label} must remain within the project root") from exc
    return resolved


def load_publication_gates(
    project_root: Path,
    profile_path: Path,
) -> tuple[PublicationGate, ...]:
    """Load the exact canonical gate set from a bounded repository profile."""

    resolved = _root_file(project_root, profile_path, "release profile")
    if not resolved.is_file() or resolved.stat().st_size > MAX_PROFILE_BYTES:
        raise ValueError("release profile is missing or oversized")
    try:
        document = tomllib.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ValueError("release profile is not valid bounded UTF-8 TOML") from exc

    raw_gates = document.get("publication_gates")
    if not isinstance(raw_gates, list):
        raise ValueError("release profile must contain [[publication_gates]]")
    if len(raw_gates) != len(CANONICAL_GATE_IDS):
        raise ValueError(
            "release profile must contain exactly "
            f"{len(CANONICAL_GATE_IDS)} publication gates"
        )

    loaded: dict[str, PublicationGate] = {}
    for raw_gate in raw_gates:
        if not isinstance(raw_gate, dict):
            raise ValueError("publication gates must be TOML tables")
        unknown_fields = set(raw_gate) - _ALLOWED_GATE_FIELDS
        if unknown_fields:
            raise ValueError(
                "publication gate contains unsupported fields: "
                + ", ".join(sorted(unknown_fields))
            )
        gate_id = _bounded_text(raw_gate.get("id"), "id")
        if gate_id not in EXPECTED_GATE_METADATA:
            raise ValueError(f"unknown canonical publication gate ID: {gate_id}")
        if gate_id in loaded:
            raise ValueError(f"duplicate publication gate ID: {gate_id}")

        expected_phase, expected_kind = EXPECTED_GATE_METADATA[gate_id]
        phase = _bounded_text(raw_gate.get("phase"), "phase")
        evidence_kind = _bounded_text(
            raw_gate.get("evidence_kind"),
            "evidence_kind",
        )
        if phase != expected_phase or evidence_kind != expected_kind:
            raise ValueError(
                f"publication gate {gate_id} must use phase {expected_phase} "
                f"and evidence kind {expected_kind}"
            )

        configured_path = raw_gate.get("evidence_path")
        evidence_path = (
            None
            if configured_path is None
            else _repository_path(project_root, configured_path, "evidence_path")
        )
        configured_check = raw_gate.get("check")
        check = (
            None
            if configured_check is None
            else _bounded_text(configured_check, "check")
        )
        if check is not None and CHECK_NAME_PATTERN.fullmatch(check) is None:
            raise ValueError(
                "publication gate check must be a bounded lowercase identifier"
            )

        loaded[gate_id] = PublicationGate(
            id=gate_id,
            phase=expected_phase,
            evidence_kind=expected_kind,
            description=_bounded_text(raw_gate.get("description"), "description"),
            pending_reason=_bounded_text(
                raw_gate.get("pending_reason"),
                "pending_reason",
            ),
            evidence_path=evidence_path,
            check=check,
        )

    missing = set(CANONICAL_GATE_IDS) - set(loaded)
    if missing:
        raise ValueError(
            "release profile is missing canonical publication gates: "
            + ", ".join(sorted(missing))
        )
    return tuple(loaded[gate_id] for gate_id in CANONICAL_GATE_IDS)


def _passed(gate: PublicationGate, reason: str) -> GateResult:
    return GateResult(
        id=gate.id,
        phase=gate.phase,
        evidence_kind=gate.evidence_kind,
        description=gate.description,
        state="passed",
        reason=reason,
    )


def _blocked(gate: PublicationGate, reason: str | None = None) -> GateResult:
    return GateResult(
        id=gate.id,
        phase=gate.phase,
        evidence_kind=gate.evidence_kind,
        description=gate.description,
        state="blocked",
        reason=reason or gate.pending_reason,
    )


def _check_manifest(project_root: Path, gate: PublicationGate) -> GateResult:
    manifest_path = project_root / "capabilities" / "manifest.yaml"
    if manifest_path.is_symlink() or not manifest_path.is_file():
        return _blocked(gate, "Canonical capability manifest is unavailable.")
    try:
        document = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, yaml.YAMLError):
        return _blocked(gate, "Canonical capability manifest is not valid UTF-8 YAML.")
    if not isinstance(document, dict) or not isinstance(document.get("categories"), list):
        return _blocked(gate, "Canonical capability manifest has an invalid structure.")

    categories = document["categories"]
    category_ids: list[str] = []
    capability_ids: list[str] = []
    aliases: list[str] = []
    for category in categories:
        if not isinstance(category, dict):
            return _blocked(gate, "Canonical capability manifest has an invalid category.")
        category_id = category.get("id")
        capabilities = category.get("capabilities")
        if not isinstance(category_id, str) or not category_id or not isinstance(
            capabilities, list
        ):
            return _blocked(gate, "Canonical capability manifest has an invalid category.")
        category_ids.append(category_id)
        for capability in capabilities:
            if not isinstance(capability, dict):
                return _blocked(
                    gate,
                    "Canonical capability manifest has an invalid capability.",
                )
            capability_id = capability.get("id")
            capability_aliases = capability.get("aliases", [])
            if (
                not isinstance(capability_id, str)
                or not capability_id
                or not isinstance(capability_aliases, list)
                or not all(
                    isinstance(alias, str) and alias
                    for alias in capability_aliases
                )
            ):
                return _blocked(
                    gate,
                    "Canonical capability manifest has an invalid capability.",
                )
            capability_ids.append(capability_id)
            aliases.extend(capability_aliases)

    valid = (
        len(category_ids) == 13
        and len(set(category_ids)) == 13
        and len(capability_ids) == 155
        and len(set(capability_ids)) == 155
        and len(aliases) == len(set(aliases))
        and not set(capability_ids).intersection(aliases)
    )
    if not valid:
        return _blocked(
            gate,
            "Manifest must contain 13 unique categories, 155 unique canonical IDs, "
            "and collision-free aliases.",
        )
    return _passed(
        gate,
        "Verified 13 unique categories, 155 unique canonical IDs, and "
        "collision-free aliases.",
    )


def _check_release_version(
    project_root: Path,
    gate: PublicationGate,
) -> GateResult:
    try:
        project = tomllib.loads(
            (project_root / "pyproject.toml").read_text(encoding="utf-8")
        )
        lock = tomllib.loads((project_root / "uv.lock").read_text(encoding="utf-8"))
        project_version = project["project"]["version"]
        packages = lock["package"]
    except (OSError, UnicodeDecodeError, KeyError, TypeError, tomllib.TOMLDecodeError):
        return _blocked(gate, "Package or lock metadata is unavailable or invalid.")

    root_versions = [
        package.get("version")
        for package in packages
        if isinstance(package, dict) and package.get("name") == "fetech"
    ]
    if project_version != TARGET_VERSION or root_versions != [TARGET_VERSION]:
        return _blocked(
            gate,
            f"pyproject.toml and the unique uv.lock root package must both use "
            f"{TARGET_VERSION}.",
        )
    return _passed(
        gate,
        f"Verified package and lock root version {TARGET_VERSION}.",
    )


def _check_published_history(
    project_root: Path,
    gate: PublicationGate,
) -> GateResult:
    verifier = project_root / "scripts" / "generate_release_evidence.py"
    profile = project_root / "scripts" / "release_published.toml"
    if (
        verifier.is_symlink()
        or profile.is_symlink()
        or not verifier.is_file()
        or not profile.is_file()
    ):
        return _blocked(gate, "Published-history verifier or profile is unavailable.")
    try:
        process = subprocess.run(
            [
                sys.executable,
                str(verifier),
                "--project-root",
                str(project_root),
                "--check-published",
            ],
            cwd=project_root,
            check=False,
            capture_output=True,
            text=True,
            timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        return _blocked(gate, "Published-history verification did not complete.")
    if process.returncode != 0:
        return _blocked(gate, "Published-history hash or metadata verification failed.")
    return _passed(
        gate,
        "Verified immutable published-history artifact hashes and release metadata.",
    )


def evaluate_gates(
    project_root: Path,
    gates: Sequence[PublicationGate],
) -> tuple[GateResult, ...]:
    """Evaluate trusted local checks and fail closed for every other gate."""

    root = project_root.resolve()
    results: list[GateResult] = []
    for gate in gates:
        if gate.id == "manifest-13-155":
            results.append(_check_manifest(root, gate))
        elif gate.id == "published-history-integrity":
            results.append(_check_published_history(root, gate))
        elif gate.id == "release-version-0.4.0a0":
            results.append(_check_release_version(root, gate))
        else:
            # A profile assertion or an evidence file's mere existence is not a
            # trusted verifier. Dedicated parsers can be added per gate later.
            results.append(_blocked(gate))
    return tuple(results)


def classify_state(results: Sequence[GateResult]) -> ReadinessState:
    """Return blocked, publishable, or published from gate results."""

    if any(
        result.phase == "prepublication" and result.state != "passed"
        for result in results
    ):
        return "blocked"
    if all(result.state == "passed" for result in results):
        return "published"
    return "publishable"


def build_report(
    project_root: Path,
    profile_path: Path = DEFAULT_PROFILE,
) -> dict[str, object]:
    """Build the deterministic sanitized readiness document."""

    gates = load_publication_gates(project_root, profile_path)
    results = evaluate_gates(project_root, gates)
    passed_count = sum(result.state == "passed" for result in results)
    prepublication_blocked_count = sum(
        result.phase == "prepublication" and result.state == "blocked"
        for result in results
    )
    postpublication_blocked_count = sum(
        result.phase == "postpublication" and result.state == "blocked"
        for result in results
    )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "target_version": TARGET_VERSION,
        "state": classify_state(results),
        "summary": {
            "gate_count": len(results),
            "passed_count": passed_count,
            "blocked_count": len(results) - passed_count,
            "prepublication_blocked_count": prepublication_blocked_count,
            "postpublication_blocked_count": postpublication_blocked_count,
        },
        "gates": [result.as_document() for result in results],
    }


def render_report(report: Mapping[str, object]) -> str:
    """Return canonical deterministic JSON."""

    return f"{json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False)}\n"


def _write_or_check(
    output_path: Path,
    rendered: str,
    *,
    write: bool,
    check: bool,
) -> bool:
    if write:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(rendered, encoding="utf-8")
        return True
    if check:
        return (
            output_path.is_file()
            and not output_path.is_symlink()
            and output_path.read_text(encoding="utf-8") == rendered
        )
    return True


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--profile", type=Path, default=DEFAULT_PROFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument(
        "--write",
        action="store_true",
        help="write the canonical readiness report",
    )
    mode.add_argument(
        "--check",
        action="store_true",
        help="fail if the tracked readiness report is absent or stale",
    )
    parser.add_argument(
        "--require-publishable",
        action="store_true",
        help="fail unless all prepublication gates have passed",
    )
    args = parser.parse_args(argv)

    try:
        project_root = args.project_root.resolve()
        output_path = _root_file(project_root, args.output, "readiness output")
        report = build_report(project_root, args.profile)
        rendered = render_report(report)
        current = _write_or_check(
            output_path,
            rendered,
            write=args.write,
            check=args.check,
        )
    except (OSError, ValueError) as exc:
        print(f"release readiness error: {exc}", file=sys.stderr)
        return 1

    if not current:
        print("release readiness report is absent or stale", file=sys.stderr)
        return 1
    if not args.write and not args.check:
        print(rendered, end="")
    if args.require_publishable and report["state"] == "blocked":
        print("release remains blocked by prepublication gates", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
