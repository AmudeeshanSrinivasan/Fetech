#!/usr/bin/env python3
"""Generate deterministic SPDX and dependency-license evidence from uv.lock."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import tomllib
from collections import Counter, defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

RELEASE_CREATED = "2026-07-17T00:00:00Z"
GENERATOR_NAME = "fetech-release-evidence-generator/1"
ROOT_PACKAGE = "fetech"
SPDX_DOCUMENT_ID = "SPDXRef-DOCUMENT"
SPDX_ROOT_ID = "SPDXRef-Package-fetech"
AGPL_PATTERN = re.compile(r"\bAGPL(?:-\d+(?:\.\d+)?)?(?:-only|-or-later)?\b", re.IGNORECASE)
LICENSE_REF_PATTERN = re.compile(r"\bLicenseRef-[A-Za-z0-9.-]+\b")
EXTRACTED_LICENSE_INFO: dict[str, dict[str, Any]] = {
    "LicenseRef-BSD-Unknown": {
        "licenseId": "LicenseRef-BSD-Unknown",
        "extractedText": "BSD License",
        "name": "Unidentified BSD license variant",
        "seeAlsos": ["https://pypi.org/project/sgmllib3k/1.0.0/"],
        "comment": (
            "The package metadata contains only the short reference “BSD License”; "
            "it does not identify the clause variant."
        ),
    }
}
SEPARATELY_INSTALLED_TOOLS = (
    (
        "SWI-Prolog",
        "Optional v0.3 logic executable; installed separately and not shipped by Fetech.",
        "`BSD-2-Clause` for the core.",
        (
            "The selected build may link GMP or load add-ons with additional terms; "
            "inspect the build with SWI-Prolog's `license.` predicate."
        ),
        "https://www.swi-prolog.org/license.html",
    ),
    (
        "curl",
        "Optional v0.3 HTTP/3 executable; installed separately and not shipped by Fetech.",
        "SPDX `curl`.",
        (
            "Record and review the selected curl build and its linked libraries before "
            "redistributing a system image."
        ),
        "https://curl.se/docs/copyright.html",
    ),
    (
        "Playwright browser binaries",
        "Downloaded separately by the Playwright CLI; not contained in the Python wheel.",
        "Varies by browser and build.",
        (
            "The Python `playwright` package is in the SBOM; browser binaries are separate "
            "artifacts whose bundled licenses and notices must be reviewed."
        ),
        "https://playwright.dev/python/docs/browsers",
    ),
    (
        "FFmpeg",
        "Planned for v0.4 media support; not shipped or required by v0.3.",
        "`LGPL-2.1-or-later` baseline.",
        (
            "Optional GPL-covered parts change the license of the complete FFmpeg build "
            "to GPL; inspect configure flags and linked libraries before distribution."
        ),
        "https://ffmpeg.org/legal.html",
    ),
)


@dataclass(frozen=True, slots=True)
class ReleaseInputs:
    """Validated release inputs and derived dependency scopes."""

    project: dict[str, Any]
    root_package: dict[str, Any]
    packages: tuple[dict[str, Any], ...]
    licenses: dict[str, str]
    review_notes: dict[str, str]
    scopes: dict[str, frozenset[str]]
    dependency_edges: dict[tuple[str, str], frozenset[str]]
    direct_scopes: dict[str, frozenset[str]]
    lock_sha256: str


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _catalog_key(package: dict[str, Any]) -> str:
    return f"{_canonical_name(str(package['name']))}=={package['version']}"


def _spdx_package_id(name: str, version: str) -> str:
    value = re.sub(r"[^A-Za-z0-9.-]+", "-", f"{_canonical_name(name)}-{version}")
    return f"SPDXRef-Package-{value}"


def _dependency_extras(reference: dict[str, Any]) -> tuple[str, ...]:
    extras = reference.get("extra", reference.get("extras", ()))
    if isinstance(extras, str):
        return (extras,)
    return tuple(sorted(str(extra) for extra in extras))


def _scope_sort_key(scope: str) -> tuple[int, str]:
    if scope == "runtime":
        return (0, scope)
    if scope == "lock-only":
        return (2, scope)
    return (1, scope)


def _scope_closure(
    package_by_name: dict[str, dict[str, Any]],
    roots: Sequence[dict[str, Any]],
) -> tuple[set[str], set[tuple[str, str]]]:
    queue: deque[tuple[str, str, tuple[str, ...]]] = deque(
        (ROOT_PACKAGE, _canonical_name(str(reference["name"])), _dependency_extras(reference))
        for reference in roots
    )
    seen_activations: set[tuple[str, tuple[str, ...]]] = set()
    seen_packages: set[str] = set()
    edges: set[tuple[str, str]] = set()

    while queue:
        parent, name, extras = queue.popleft()
        edges.add((parent, name))
        seen_packages.add(name)
        activation = (name, extras)
        if activation in seen_activations:
            continue
        seen_activations.add(activation)

        package = package_by_name.get(name)
        if package is None:
            raise ValueError(f"uv.lock references missing package {name!r}")

        references = list(package.get("dependencies", ()))
        optional = package.get("optional-dependencies", {})
        for extra in extras:
            references.extend(optional.get(extra, ()))
        for reference in references:
            queue.append(
                (
                    name,
                    _canonical_name(str(reference["name"])),
                    _dependency_extras(reference),
                )
            )

    return seen_packages, edges


def load_release_inputs(
    project_path: Path,
    lock_path: Path,
    catalog_path: Path,
) -> ReleaseInputs:
    """Load and strictly cross-check project, lock, and reviewed license data."""

    project_document = tomllib.loads(project_path.read_text(encoding="utf-8"))
    lock_document = tomllib.loads(lock_path.read_text(encoding="utf-8"))
    catalog_document = tomllib.loads(catalog_path.read_text(encoding="utf-8"))
    project = dict(project_document["project"])

    all_packages = [dict(package) for package in lock_document["package"]]
    roots = [
        package
        for package in all_packages
        if _canonical_name(str(package["name"])) == ROOT_PACKAGE
    ]
    if len(roots) != 1:
        raise ValueError("uv.lock must contain exactly one fetech package")
    root_package = roots[0]
    packages = tuple(
        sorted(
            (
                package
                for package in all_packages
                if _canonical_name(str(package["name"])) != ROOT_PACKAGE
            ),
            key=lambda package: (
                _canonical_name(str(package["name"])),
                str(package["version"]),
            ),
        )
    )
    if str(project["version"]) != str(root_package["version"]):
        raise ValueError("pyproject.toml and uv.lock disagree on the Fetech version")

    package_by_name: dict[str, dict[str, Any]] = {}
    for package in packages:
        name = _canonical_name(str(package["name"]))
        if name in package_by_name:
            raise ValueError(f"multiple locked versions are unsupported for {name!r}")
        package_by_name[name] = package

    licenses = {
        str(key): str(value) for key, value in catalog_document["packages"].items()
    }
    expected_catalog_keys = {_catalog_key(package) for package in packages}
    actual_catalog_keys = set(licenses)
    if expected_catalog_keys != actual_catalog_keys:
        missing = sorted(expected_catalog_keys - actual_catalog_keys)
        stale = sorted(actual_catalog_keys - expected_catalog_keys)
        raise ValueError(f"license catalog drift; missing={missing}, stale={stale}")
    if any(not expression.strip() or expression == "NOASSERTION" for expression in licenses.values()):
        raise ValueError("every dependency requires a reviewed declared license expression")
    referenced_license_refs = {
        reference
        for expression in licenses.values()
        for reference in LICENSE_REF_PATTERN.findall(expression)
    }
    missing_license_refs = referenced_license_refs - EXTRACTED_LICENSE_INFO.keys()
    if missing_license_refs:
        raise ValueError(
            "custom license references require extracted licensing information: "
            f"{sorted(missing_license_refs)}"
        )

    review_notes = {
        str(key): str(value)
        for key, value in catalog_document.get("review_notes", {}).items()
    }
    unknown_notes = set(review_notes) - expected_catalog_keys
    if unknown_notes:
        raise ValueError(f"review notes reference unlocked packages: {sorted(unknown_notes)}")

    scope_roots: dict[str, Sequence[dict[str, Any]]] = {
        "runtime": tuple(root_package.get("dependencies", ()))
    }
    for extra, references in root_package.get("optional-dependencies", {}).items():
        scope_roots[f"extra:{extra}"] = tuple(references)

    scopes: defaultdict[str, set[str]] = defaultdict(set)
    dependency_edges: defaultdict[tuple[str, str], set[str]] = defaultdict(set)
    direct_scopes: defaultdict[str, set[str]] = defaultdict(set)
    for scope, references in sorted(scope_roots.items()):
        closure, edges = _scope_closure(package_by_name, references)
        for name in closure:
            scopes[name].add(scope)
        for edge in edges:
            dependency_edges[edge].add(scope)
        for reference in references:
            direct_scopes[_canonical_name(str(reference["name"]))].add(scope)

    for name in package_by_name:
        if name not in scopes:
            scopes[name].add("lock-only")

    lock_sha256 = hashlib.sha256(lock_path.read_bytes()).hexdigest()
    return ReleaseInputs(
        project=project,
        root_package=root_package,
        packages=packages,
        licenses=licenses,
        review_notes=review_notes,
        scopes={name: frozenset(values) for name, values in scopes.items()},
        dependency_edges={
            edge: frozenset(values) for edge, values in dependency_edges.items()
        },
        direct_scopes={
            name: frozenset(values) for name, values in direct_scopes.items()
        },
        lock_sha256=lock_sha256,
    )


def _package_download_and_checksum(
    package: dict[str, Any],
) -> tuple[str, list[dict[str, str]]]:
    artifact = package.get("sdist")
    if artifact is None:
        wheels = package.get("wheels", ())
        artifact = wheels[0] if wheels else None
    if artifact is None:
        return ("NOASSERTION", [])

    checksums: list[dict[str, str]] = []
    digest = str(artifact.get("hash", ""))
    if digest.startswith("sha256:"):
        checksums.append({"algorithm": "SHA256", "checksumValue": digest.removeprefix("sha256:")})
    return (str(artifact["url"]), checksums)


def build_spdx_document(inputs: ReleaseInputs) -> dict[str, Any]:
    """Build a deterministic SPDX 2.3 JSON document."""

    version = str(inputs.project["version"])
    namespace = (
        "https://github.com/AmudeeshanSrinivasan/Fetech/"
        f"spdx/fetech-{quote(version, safe='')}-{inputs.lock_sha256}"
    )
    root_package = {
        "SPDXID": SPDX_ROOT_ID,
        "name": ROOT_PACKAGE,
        "versionInfo": version,
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "Apache-2.0",
        "licenseDeclared": "Apache-2.0",
        "copyrightText": "NOASSERTION",
        "primaryPackagePurpose": "APPLICATION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:pypi/fetech@{quote(version, safe='')}",
            }
        ],
        "comment": (
            "Root package metadata from pyproject.toml and uv.lock. "
            f"uv.lock SHA-256: {inputs.lock_sha256}."
        ),
    }
    spdx_packages: list[dict[str, Any]] = [root_package]
    package_ids: dict[str, str] = {}

    for package in inputs.packages:
        name = _canonical_name(str(package["name"]))
        package_version = str(package["version"])
        package_id = _spdx_package_id(name, package_version)
        package_ids[name] = package_id
        catalog_key = _catalog_key(package)
        download_location, checksums = _package_download_and_checksum(package)
        scopes = ", ".join(
            sorted(inputs.scopes[name], key=_scope_sort_key)
        )
        entry: dict[str, Any] = {
            "SPDXID": package_id,
            "name": name,
            "versionInfo": package_version,
            "downloadLocation": download_location,
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": inputs.licenses[catalog_key],
            "copyrightText": "NOASSERTION",
            "primaryPackagePurpose": "LIBRARY",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": (
                        f"pkg:pypi/{quote(name, safe='')}@{quote(package_version, safe='')}"
                    ),
                }
            ],
            "comment": (
                f"Universal-lock scopes: {scopes}. "
                "LicenseConcluded remains NOASSERTION because this engineering "
                "inventory is not a legal conclusion."
            ),
        }
        if checksums:
            entry["checksums"] = checksums
        if catalog_key in inputs.review_notes:
            entry["comment"] += f" Review note: {inputs.review_notes[catalog_key]}"
        spdx_packages.append(entry)

    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": SPDX_DOCUMENT_ID,
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": SPDX_ROOT_ID,
        }
    ]
    for name, scopes in sorted(inputs.direct_scopes.items()):
        scope_text = ", ".join(sorted(scopes, key=_scope_sort_key))
        if "runtime" in scopes:
            relationships.append(
                {
                    "spdxElementId": SPDX_ROOT_ID,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package_ids[name],
                    "comment": f"Direct dependency scopes: {scope_text}.",
                }
            )
        elif scopes == {"extra:dev"}:
            relationships.append(
                {
                    "spdxElementId": package_ids[name],
                    "relationshipType": "DEV_DEPENDENCY_OF",
                    "relatedSpdxElement": SPDX_ROOT_ID,
                    "comment": f"Direct dependency scopes: {scope_text}.",
                }
            )
        else:
            relationships.append(
                {
                    "spdxElementId": package_ids[name],
                    "relationshipType": "OPTIONAL_DEPENDENCY_OF",
                    "relatedSpdxElement": SPDX_ROOT_ID,
                    "comment": f"Direct dependency scopes: {scope_text}.",
                }
            )

    for (parent, dependency), scopes in sorted(inputs.dependency_edges.items()):
        if parent == ROOT_PACKAGE:
            continue
        relationships.append(
            {
                "spdxElementId": package_ids[parent],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_ids[dependency],
                "comment": (
                    "Resolved universal-lock scopes: "
                    f"{', '.join(sorted(scopes, key=_scope_sort_key))}."
                ),
            }
        )

    lock_only = sorted(
        name for name, scopes in inputs.scopes.items() if scopes == {"lock-only"}
    )
    for name in lock_only:
        relationships.append(
            {
                "spdxElementId": package_ids[name],
                "relationshipType": "OTHER",
                "relatedSpdxElement": SPDX_ROOT_ID,
                "comment": "Present in uv.lock but not reachable from a declared Fetech dependency scope.",
            }
        )

    referenced_license_refs = sorted(
        {
            reference
            for expression in inputs.licenses.values()
            for reference in LICENSE_REF_PATTERN.findall(expression)
        }
    )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": SPDX_DOCUMENT_ID,
        "name": f"fetech-{version}-universal-lock",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": RELEASE_CREATED,
            "creators": [f"Tool: {GENERATOR_NAME}"],
        },
        "documentDescribes": [SPDX_ROOT_ID],
        "hasExtractedLicensingInfos": [
            EXTRACTED_LICENSE_INFO[reference] for reference in referenced_license_refs
        ],
        "packages": spdx_packages,
        "relationships": relationships,
        "comment": (
            "Deterministic release SBOM generated from pyproject.toml, uv.lock, "
            "and scripts/release_license_catalog.toml. It describes the universal "
            "lock across all declared extras and platform markers, not one installed environment."
        ),
    }


def build_license_report(inputs: ReleaseInputs) -> str:
    """Build the human-readable dependency-license audit report."""

    version = str(inputs.project["version"])
    counts = Counter(inputs.licenses.values())
    agpl_packages = sorted(
        key for key, expression in inputs.licenses.items() if AGPL_PATTERN.search(expression)
    )
    choice_packages = sorted(
        key
        for key, expression in inputs.licenses.items()
        if ("GPL-" in expression or "LGPL-" in expression) and " OR " in expression
    )
    ambiguous_packages = sorted(
        key
        for key, expression in inputs.licenses.items()
        if "LicenseRef-" in expression
    )
    scope_counts = Counter(
        scope for package_scopes in inputs.scopes.values() for scope in package_scopes
    )

    lines = [
        f"# Fetech {version} dependency-license report",
        "",
        "This is deterministic engineering evidence, not legal advice. License declarations",
        "were reviewed for the exact versions in `uv.lock`; SPDX `licenseConcluded` remains",
        "`NOASSERTION` for third-party packages because this report does not make legal conclusions.",
        "",
        "## Inputs and coverage",
        "",
        f"- Generator: `{GENERATOR_NAME}`",
        f"- Evidence timestamp: `{RELEASE_CREATED}`",
        f"- `uv.lock` SHA-256: `{inputs.lock_sha256}`",
        f"- Third-party locked packages: **{len(inputs.packages)}**",
        "- Coverage: base runtime, every declared optional extra, development dependencies,",
        "  and all platform-marker alternatives represented by the universal lock.",
        "- Package evidence links point to version-specific PyPI release pages. The reviewed",
        "  catalog also uses package metadata, bundled notices, and upstream license files;",
        "  special review notes remain attached to affected rows.",
        "",
        "## Automated policy observations",
        "",
        "- Missing or `NOASSERTION` declared licenses: **0**",
        f"- Declared AGPL expressions: **{len(agpl_packages)}**",
        f"- Ambiguous `LicenseRef` declarations: **{len(ambiguous_packages)}**",
        f"- Disjunctive GPL/LGPL choice expressions: **{len(choice_packages)}**",
    ]
    if agpl_packages:
        lines.append(f"- AGPL review list: {', '.join(f'`{key}`' for key in agpl_packages)}")
    else:
        lines.append("- AGPL policy check: **pass** — no locked package declares AGPL.")
    if choice_packages:
        lines.append(
            "- License-choice review: "
            + ", ".join(f"`{key}`" for key in choice_packages)
            + ". Preserve the selected upstream license and notices when redistributing."
        )
    if ambiguous_packages:
        lines.append(
            "- Exact-license review: "
            + ", ".join(f"`{key}`" for key in ambiguous_packages)
            + ". The package metadata does not identify a precise SPDX license."
        )
    lines.extend(
        [
            "",
            "## Separately installed and future runtime tools",
            "",
            "These executables and downloaded artifacts are not Python packages distributed in",
            "the v0.3 wheel, so they are not added as packages in this lock-derived SBOM. If a",
            "future Fetech distribution bundles them, generate a distribution-specific SBOM and",
            "carry their exact versions, build options, licenses, notices, and transitive libraries.",
            "",
            "| Component | v0.3 status | License observation | Required review | Primary source |",
            "|---|---|---|---|---|",
        ]
    )
    for name, status, license_expression, review, url in SEPARATELY_INSTALLED_TOOLS:
        lines.append(
            f"| {name} | {status} | {license_expression} | {review} | "
            f"[Upstream]({url}) |"
        )
    lines.extend(
        [
            "",
            "## Scope counts",
            "",
            "| Scope | Packages |",
            "|---|---:|",
        ]
    )
    for scope, count in sorted(scope_counts.items(), key=lambda item: _scope_sort_key(item[0])):
        lines.append(f"| `{scope}` | {count} |")

    lines.extend(
        [
            "",
            "A package may appear in multiple scopes. The `all` extra intentionally overlaps",
            "the narrower feature extras.",
            "",
            "## License-expression summary",
            "",
            "| Declared SPDX expression | Packages |",
            "|---|---:|",
        ]
    )
    for expression, count in sorted(counts.items()):
        lines.append(f"| `{expression}` | {count} |")

    lines.extend(
        [
            "",
            "## Dependency inventory",
            "",
            "| Package | Version | Scope(s) | Declared license | Evidence |",
            "|---|---|---|---|---|",
        ]
    )
    for package in inputs.packages:
        name = _canonical_name(str(package["name"]))
        package_version = str(package["version"])
        key = _catalog_key(package)
        scopes = ", ".join(
            f"`{scope}`" for scope in sorted(inputs.scopes[name], key=_scope_sort_key)
        )
        url = (
            f"https://pypi.org/project/{quote(name, safe='')}/"
            f"{quote(package_version, safe='')}/"
        )
        note = inputs.review_notes.get(key)
        evidence = f"[PyPI release]({url})"
        if note:
            evidence += f"<br>Review: {note}"
        lines.append(
            f"| `{name}` | `{package_version}` | {scopes} | "
            f"`{inputs.licenses[key]}` | {evidence} |"
        )

    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "Run from the repository root:",
            "",
            "```console",
            "uv run python scripts/generate_release_evidence.py --check",
            "```",
            "",
            "`--check` regenerates both artifacts in memory and fails if tracked evidence",
            "differs from `pyproject.toml`, `uv.lock`, or the reviewed catalog.",
            "",
        ]
    )
    return "\n".join(lines)


def render_release_evidence(
    project_path: Path,
    lock_path: Path,
    catalog_path: Path,
) -> tuple[str, str, str]:
    """Return version, canonical SPDX JSON, and canonical Markdown report."""

    inputs = load_release_inputs(project_path, lock_path, catalog_path)
    spdx = json.dumps(
        build_spdx_document(inputs),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    report = build_license_report(inputs)
    return str(inputs.project["version"]), f"{spdx}\n", report


def _artifact_paths(output_dir: Path, version: str) -> tuple[Path, Path]:
    return (
        output_dir / f"fetech-{version}.spdx.json",
        output_dir / "dependency-licenses.md",
    )


def _check_artifact(path: Path, expected: str) -> None:
    if not path.is_file():
        raise ValueError(f"missing generated artifact: {path.name}")
    if path.read_text(encoding="utf-8") != expected:
        raise ValueError(f"generated artifact is stale: {path.name}")


def generate(
    project_root: Path,
    output_dir: Path,
    *,
    check: bool,
) -> tuple[Path, Path]:
    """Generate or verify both release evidence artifacts."""

    version, spdx, report = render_release_evidence(
        project_root / "pyproject.toml",
        project_root / "uv.lock",
        project_root / "scripts" / "release_license_catalog.toml",
    )
    spdx_path, report_path = _artifact_paths(output_dir, version)
    if check:
        _check_artifact(spdx_path, spdx)
        _check_artifact(report_path, report)
    else:
        output_dir.mkdir(parents=True, exist_ok=True)
        spdx_path.write_text(spdx, encoding="utf-8")
        report_path.write_text(report, encoding="utf-8")
    return spdx_path, report_path


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--project-root",
        type=Path,
        default=Path(__file__).resolve().parents[1],
    )
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when tracked artifacts differ instead of writing them",
    )
    args = parser.parse_args(argv)
    project_root = args.project_root.resolve()
    output_dir = args.output_dir or project_root / "release"
    paths = generate(project_root, output_dir, check=args.check)
    action = "verified" if args.check else "generated"
    print(f"{action}: {', '.join(path.name for path in paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
