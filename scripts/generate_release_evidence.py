#!/usr/bin/env python3
"""Generate deterministic SPDX and dependency-license evidence from uv.lock."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import re
import tomllib
from collections import Counter, defaultdict, deque
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import quote

import yaml

RELEASE_CREATED = "2026-07-17T00:00:00Z"
GENERATOR_NAME = "fetech-release-evidence-generator/2"
OVERLAY_GENERATOR_NAME = GENERATOR_NAME
PUBLISHED_PROFILE_VERSION = "1"
ROOT_PACKAGE = "fetech"
SPDX_DOCUMENT_ID = "SPDXRef-DOCUMENT"
SPDX_ROOT_ID = "SPDXRef-Package-fetech"
AGPL_PATTERN = re.compile(r"\bAGPL(?:-\d+(?:\.\d+)?)?(?:-only|-or-later)?\b", re.IGNORECASE)
LICENSE_REF_PATTERN = re.compile(r"\bLicenseRef-[A-Za-z0-9.-]+\b")
OVERLAY_ID_PATTERN = re.compile(r"[a-z0-9][a-z0-9.-]*\Z")
CLOSURE_RELEASE_PATTERN = re.compile(r"v\d+\.\d+\Z")
UTC_TIMESTAMP_PATTERN = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z\Z")
PUBLISHED_VERSION_PATTERN = re.compile(r"[0-9][0-9A-Za-z.+-]{0,63}\Z")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}\Z")
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
    },
    "LicenseRef-NVIDIA-CUDNN-SLA": {
        "licenseId": "LicenseRef-NVIDIA-CUDNN-SLA",
        "extractedText": "NVIDIA cuDNN Software License Agreement",
        "name": "NVIDIA cuDNN Software License Agreement",
        "seeAlsos": [
            "https://docs.nvidia.com/deeplearning/cudnn/backend/v9.20.0/reference/eula.html"
        ],
        "comment": (
            "The exact PyPI metadata has blank license fields. NVIDIA's versioned "
            "cuDNN documentation identifies this agreement as governing; perform "
            "artifact-level legal review before redistribution."
        ),
    },
    "LicenseRef-NVIDIA-CUDA-13.0-EULA": {
        "licenseId": "LicenseRef-NVIDIA-CUDA-13.0-EULA",
        "extractedText": "NVIDIA CUDA Toolkit End User License Agreement",
        "name": "NVIDIA CUDA Toolkit 13.0 End User License Agreement",
        "seeAlsos": ["https://docs.nvidia.com/cuda/archive/13.0.3/pdf/EULA.pdf"],
        "comment": (
            "Used only for the locked CUDA 13.0 toolkit and runtime packages whose "
            "PyPI metadata has blank license fields. NVIDIA's archived 13.0 agreement "
            "is the upstream reference; review each artifact and its bundled notices "
            "before redistribution."
        ),
    },
    "LicenseRef-NVIDIA-CUDA-13.3-EULA": {
        "licenseId": "LicenseRef-NVIDIA-CUDA-13.3-EULA",
        "extractedText": "NVIDIA CUDA Toolkit End User License Agreement",
        "name": "NVIDIA CUDA Toolkit 13.3 End User License Agreement",
        "seeAlsos": ["https://docs.nvidia.com/cuda/eula/index.html"],
        "comment": (
            "Used only for the locked nvJitLink 13.3 package. NVIDIA's current "
            "versioned page identifies itself as the CUDA 13.3 agreement; review the "
            "artifact and preserve a release-time copy of its bundled terms before "
            "redistribution."
        ),
    },
    "LicenseRef-NVIDIA-NVSHMEM-SDK": {
        "licenseId": "LicenseRef-NVIDIA-NVSHMEM-SDK",
        "extractedText": "NVIDIA NVSHMEM SDK license terms",
        "name": "NVIDIA NVSHMEM SDK license terms",
        "seeAlsos": [
            "https://github.com/NVIDIA/nvshmem/blob/v3.4.5-0/License.txt"
        ],
        "comment": (
            "The exact v3.4.5-0 tag contains custom NVIDIA SDK terms and additional "
            "component notices. The later default-branch Apache-2.0 label does not "
            "apply retroactively."
        ),
    },
    "LicenseRef-nvidia-cublas-13.1.1.3-Proprietary": {
        "licenseId": "LicenseRef-nvidia-cublas-13.1.1.3-Proprietary",
        "extractedText": "LicenseRef-NVIDIA-Proprietary",
        "name": "nvidia-cublas 13.1.1.3 proprietary license declaration",
        "seeAlsos": ["https://pypi.org/project/nvidia-cublas/13.1.1.3/"],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary reference. "
            "It does not establish equivalence with another package's terms; review "
            "this wheel's bundled License.txt before redistribution."
        ),
    },
    "LicenseRef-nvidia-cuda-cupti-13.0.85-Proprietary": {
        "licenseId": "LicenseRef-nvidia-cuda-cupti-13.0.85-Proprietary",
        "extractedText": "LicenseRef-NVIDIA-Proprietary",
        "name": "nvidia-cuda-cupti 13.0.85 proprietary license declaration",
        "seeAlsos": ["https://pypi.org/project/nvidia-cuda-cupti/13.0.85/"],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary reference. "
            "It does not establish equivalence with another package's terms; review "
            "this wheel's bundled terms before redistribution."
        ),
    },
    "LicenseRef-nvidia-cuda-nvrtc-13.0.88-Proprietary": {
        "licenseId": "LicenseRef-nvidia-cuda-nvrtc-13.0.88-Proprietary",
        "extractedText": "LicenseRef-NVIDIA-Proprietary",
        "name": "nvidia-cuda-nvrtc 13.0.88 proprietary license declaration",
        "seeAlsos": ["https://pypi.org/project/nvidia-cuda-nvrtc/13.0.88/"],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary reference. "
            "It does not establish equivalence with another package's terms; review "
            "this wheel's bundled terms before redistribution."
        ),
    },
    "LicenseRef-nvidia-cufft-12.0.0.61-Proprietary": {
        "licenseId": "LicenseRef-nvidia-cufft-12.0.0.61-Proprietary",
        "extractedText": "LicenseRef-NVIDIA-Proprietary",
        "name": "nvidia-cufft 12.0.0.61 proprietary license declaration",
        "seeAlsos": ["https://pypi.org/project/nvidia-cufft/12.0.0.61/"],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary reference. "
            "It does not establish equivalence with another package's terms; review "
            "this wheel's bundled terms before redistribution."
        ),
    },
    "LicenseRef-nvidia-cufile-1.15.1.6-Proprietary": {
        "licenseId": "LicenseRef-nvidia-cufile-1.15.1.6-Proprietary",
        "extractedText": "LicenseRef-NVIDIA-Proprietary",
        "name": "nvidia-cufile 1.15.1.6 proprietary license declaration",
        "seeAlsos": ["https://pypi.org/project/nvidia-cufile/1.15.1.6/"],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary reference. "
            "It does not establish equivalence with another package's terms; review "
            "this wheel's bundled terms before redistribution."
        ),
    },
    "LicenseRef-nvidia-curand-10.4.0.35-Proprietary": {
        "licenseId": "LicenseRef-nvidia-curand-10.4.0.35-Proprietary",
        "extractedText": "LicenseRef-NVIDIA-Proprietary",
        "name": "nvidia-curand 10.4.0.35 proprietary license declaration",
        "seeAlsos": ["https://pypi.org/project/nvidia-curand/10.4.0.35/"],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary reference. "
            "It does not establish equivalence with another package's terms; review "
            "this wheel's bundled terms before redistribution."
        ),
    },
    "LicenseRef-nvidia-cusolver-12.0.4.66-Proprietary": {
        "licenseId": "LicenseRef-nvidia-cusolver-12.0.4.66-Proprietary",
        "extractedText": "LicenseRef-NVIDIA-Proprietary",
        "name": "nvidia-cusolver 12.0.4.66 proprietary license declaration",
        "seeAlsos": ["https://pypi.org/project/nvidia-cusolver/12.0.4.66/"],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary reference. "
            "It does not establish equivalence with another package's terms; review "
            "this wheel's bundled terms before redistribution."
        ),
    },
    "LicenseRef-nvidia-cusparse-12.6.3.3-Proprietary": {
        "licenseId": "LicenseRef-nvidia-cusparse-12.6.3.3-Proprietary",
        "extractedText": "LicenseRef-NVIDIA-Proprietary",
        "name": "nvidia-cusparse 12.6.3.3 proprietary license declaration",
        "seeAlsos": ["https://pypi.org/project/nvidia-cusparse/12.6.3.3/"],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary reference. "
            "It does not establish equivalence with another package's terms; review "
            "this wheel's bundled terms before redistribution."
        ),
    },
    "LicenseRef-nvidia-cusparselt-cu13-0.8.1-Proprietary": {
        "licenseId": "LicenseRef-nvidia-cusparselt-cu13-0.8.1-Proprietary",
        "extractedText": "NVIDIA Proprietary Software",
        "name": "nvidia-cusparselt-cu13 0.8.1 proprietary license declaration",
        "seeAlsos": [
            "https://pypi.org/project/nvidia-cusparselt-cu13/0.8.1/"
        ],
        "comment": (
            "The exact PyPI metadata exposes only this short proprietary label. It "
            "does not establish equivalence with another package's terms; review "
            "this wheel's bundled terms before redistribution."
        ),
    },
    "LicenseRef-NVIDIA-SOFTWARE-LICENSE": {
        "licenseId": "LicenseRef-NVIDIA-SOFTWARE-LICENSE",
        "extractedText": "NVIDIA Software License",
        "name": "NVIDIA Software License",
        "seeAlsos": ["https://pypi.org/project/cuda-bindings/13.3.1/"],
        "comment": (
            "The exact cuda-bindings release declares NVIDIA software license terms; "
            "review the bundled agreement before redistribution."
        ),
    },
    "LicenseRef-pypdfium2-5.12.1-Mixed": {
        "licenseId": "LicenseRef-pypdfium2-5.12.1-Mixed",
        "extractedText": "BSD-3-Clause, Apache-2.0, dependency licenses",
        "name": "pypdfium2 5.12.1 mixed distribution licensing",
        "seeAlsos": ["https://pypi.org/project/pypdfium2/5.12.1/"],
        "comment": (
            "The Python wrapper offers an Apache-2.0 or BSD-3-Clause choice, while "
            "the bundled PDFium binary and documentation have build-specific dependency "
            "licenses and notices that require artifact review."
        ),
    },
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


@dataclass(frozen=True, slots=True)
class PublishedReleaseEvidence:
    """Immutable metadata and hashes for one already-published release."""

    version: str
    tag: str
    created: str
    generator: str
    lock_sha256: str
    third_party_package_count: int
    spdx_filename: str
    spdx_sha256: str
    spdx_document_name: str
    spdx_document_namespace: str
    license_report_filename: str
    license_report_sha256: str


@dataclass(frozen=True, slots=True)
class ExternalComponent:
    """One unbundled executable, downloaded artifact, or provider boundary."""

    name: str
    status: str
    license_observation: str
    required_review: str
    source_url: str


@dataclass(frozen=True, slots=True)
class DevelopmentOverlay:
    """Validated metadata for an unreleased development evidence projection."""

    identifier: str
    title: str
    package_version: str
    status: str
    created: str
    closure_release: str
    capability_count: int
    cumulative_capability_count: int
    spdx_filename: str
    license_report_filename: str
    input_hashes: tuple[tuple[str, str], ...]
    external_components: tuple[ExternalComponent, ...]
    publication_gaps: tuple[str, ...]


def _canonical_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def _catalog_key(package: dict[str, Any]) -> str:
    return f"{_canonical_name(str(package['name']))}=={package['version']}"


def _reference_key(
    reference: dict[str, Any],
    packages_by_name: dict[str, tuple[dict[str, Any], ...]],
) -> str:
    """Resolve one uv dependency reference to an exact locked package identity."""

    name = _canonical_name(str(reference["name"]))
    candidates = packages_by_name.get(name, ())
    requested_version = reference.get("version")
    if requested_version is not None:
        key = f"{name}=={requested_version}"
        if not any(_catalog_key(package) == key for package in candidates):
            raise ValueError(f"uv.lock references missing package {key!r}")
        return key
    if len(candidates) != 1:
        versions = sorted(str(package["version"]) for package in candidates)
        raise ValueError(
            "uv.lock dependency reference is ambiguous without an exact version: "
            f"{name!r} candidates={versions}"
        )
    return _catalog_key(candidates[0])


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
    package_by_key: dict[str, dict[str, Any]],
    packages_by_name: dict[str, tuple[dict[str, Any], ...]],
    roots: Sequence[dict[str, Any]],
) -> tuple[set[str], set[tuple[str, str]]]:
    queue: deque[tuple[str, str, tuple[str, ...]]] = deque(
        (
            ROOT_PACKAGE,
            _reference_key(reference, packages_by_name),
            _dependency_extras(reference),
        )
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

        package = package_by_key.get(name)
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
                    _reference_key(reference, packages_by_name),
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

    package_by_key: dict[str, dict[str, Any]] = {}
    mutable_packages_by_name: defaultdict[str, list[dict[str, Any]]] = defaultdict(list)
    for package in packages:
        key = _catalog_key(package)
        if key in package_by_key:
            raise ValueError(f"duplicate locked package identity {key!r}")
        package_by_key[key] = package
        mutable_packages_by_name[_canonical_name(str(package["name"]))].append(
            package
        )
    packages_by_name = {
        name: tuple(
            sorted(values, key=lambda package: str(package["version"]))
        )
        for name, values in mutable_packages_by_name.items()
    }

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
        closure, edges = _scope_closure(
            package_by_key,
            packages_by_name,
            references,
        )
        for key in closure:
            scopes[key].add(scope)
        for edge in edges:
            dependency_edges[edge].add(scope)
        for reference in references:
            direct_scopes[_reference_key(reference, packages_by_name)].add(scope)

    for key in package_by_key:
        if key not in scopes:
            scopes[key].add("lock-only")

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


def _bounded_profile_text(value: object, field: str, *, maximum: int = 2_000) -> str:
    text = str(value).strip()
    if not text or len(text.encode("utf-8")) > maximum:
        raise ValueError(f"overlay {field} must be non-empty and at most {maximum} bytes")
    if any(character in text for character in ("\x00", "\r", "\n", "|")):
        raise ValueError(f"overlay {field} contains unsupported characters")
    return text


def _published_profile_text(
    value: object,
    field: str,
    *,
    maximum: int = 2_000,
) -> str:
    text = str(value).strip()
    if not text or len(text.encode("utf-8")) > maximum:
        raise ValueError(
            f"published {field} must be non-empty and at most {maximum} bytes"
        )
    if any(character in text for character in ("\x00", "\r", "\n", "|")):
        raise ValueError(f"published {field} contains unsupported characters")
    return text


def _published_sha256(value: object, field: str) -> str:
    digest = _published_profile_text(value, field, maximum=64)
    if SHA256_PATTERN.fullmatch(digest) is None:
        raise ValueError(f"published {field} must be a lowercase SHA-256")
    return digest


def _published_filename(value: object, field: str, *, suffix: str) -> str:
    filename = _published_profile_text(value, field, maximum=160)
    if Path(filename).name != filename or not filename.endswith(suffix):
        raise ValueError(
            f"published {field} must be a bounded {suffix} basename"
        )
    return filename


def load_published_evidence_profile(
    project_root: Path,
    profile_path: Path,
) -> tuple[PublishedReleaseEvidence, ...]:
    """Load bounded immutable metadata for already-published evidence."""

    root = project_root.resolve()
    resolved_profile = profile_path.resolve()
    try:
        profile_relative = resolved_profile.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError(
            "published evidence profile must remain within the project root"
        ) from exc
    if (
        resolved_profile.is_symlink()
        or not resolved_profile.is_file()
        or resolved_profile.stat().st_size > 64 * 1024
    ):
        raise ValueError(
            f"published evidence profile is unavailable or oversized: {profile_relative}"
        )

    document = tomllib.loads(resolved_profile.read_text(encoding="utf-8"))
    if document.get("profile_version") != PUBLISHED_PROFILE_VERSION:
        raise ValueError("unsupported published evidence profile version")
    configured_releases = document.get("releases")
    if (
        not isinstance(configured_releases, list)
        or not configured_releases
        or len(configured_releases) > 50
    ):
        raise ValueError(
            "published evidence profile must contain between 1 and 50 releases"
        )

    releases: list[PublishedReleaseEvidence] = []
    for raw_release in configured_releases:
        if not isinstance(raw_release, dict):
            raise ValueError("published evidence releases must be mappings")
        version = _published_profile_text(
            raw_release.get("version", ""),
            "version",
            maximum=64,
        )
        if PUBLISHED_VERSION_PATTERN.fullmatch(version) is None:
            raise ValueError("published version is invalid")
        tag = _published_profile_text(raw_release.get("tag", ""), "tag", maximum=65)
        if tag != f"v{version}":
            raise ValueError("published tag must equal v plus the package version")
        created = _published_profile_text(
            raw_release.get("created", ""),
            "created",
            maximum=20,
        )
        if UTC_TIMESTAMP_PATTERN.fullmatch(created) is None:
            raise ValueError("published created must be a fixed UTC timestamp")
        generator = _published_profile_text(
            raw_release.get("generator", ""),
            "generator",
            maximum=120,
        )
        lock_sha256 = _published_sha256(
            raw_release.get("lock_sha256", ""),
            "lock_sha256",
        )
        package_count = int(raw_release.get("third_party_package_count", 0))
        if package_count <= 0 or package_count > 100_000:
            raise ValueError("published third_party_package_count is invalid")
        spdx_filename = _published_filename(
            raw_release.get("spdx_filename", ""),
            "spdx_filename",
            suffix=".spdx.json",
        )
        report_filename = _published_filename(
            raw_release.get("license_report_filename", ""),
            "license_report_filename",
            suffix=".md",
        )
        if spdx_filename == report_filename:
            raise ValueError("published evidence filenames must be distinct")
        spdx_document_name = _published_profile_text(
            raw_release.get("spdx_document_name", ""),
            "spdx_document_name",
            maximum=160,
        )
        spdx_document_namespace = _published_profile_text(
            raw_release.get("spdx_document_namespace", ""),
            "spdx_document_namespace",
            maximum=500,
        )
        if not spdx_document_namespace.startswith("https://"):
            raise ValueError("published SPDX namespace must use HTTPS")
        releases.append(
            PublishedReleaseEvidence(
                version=version,
                tag=tag,
                created=created,
                generator=generator,
                lock_sha256=lock_sha256,
                third_party_package_count=package_count,
                spdx_filename=spdx_filename,
                spdx_sha256=_published_sha256(
                    raw_release.get("spdx_sha256", ""),
                    "spdx_sha256",
                ),
                spdx_document_name=spdx_document_name,
                spdx_document_namespace=spdx_document_namespace,
                license_report_filename=report_filename,
                license_report_sha256=_published_sha256(
                    raw_release.get("license_report_sha256", ""),
                    "license_report_sha256",
                ),
            )
        )

    versions = [release.version for release in releases]
    tags = [release.tag for release in releases]
    filenames = [
        filename
        for release in releases
        for filename in (release.spdx_filename, release.license_report_filename)
    ]
    if len(versions) != len(set(versions)):
        raise ValueError("published evidence versions must be unique")
    if len(tags) != len(set(tags)):
        raise ValueError("published evidence tags must be unique")
    if len(filenames) != len(set(filenames)):
        raise ValueError("published evidence filenames must be unique")
    return tuple(releases)


def _published_artifact(
    output_dir: Path,
    filename: str,
    expected_sha256: str,
) -> tuple[Path, bytes]:
    root = output_dir.resolve()
    path = root / filename
    if path.is_symlink():
        raise ValueError(f"published evidence artifact cannot be a symlink: {filename}")
    try:
        resolved = path.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError) as exc:
        raise ValueError(f"missing published evidence artifact: {filename}") from exc
    if not resolved.is_file() or resolved.stat().st_size > 64 * 1024 * 1024:
        raise ValueError(
            f"published evidence artifact is invalid or oversized: {filename}"
        )
    content = resolved.read_bytes()
    actual_sha256 = hashlib.sha256(content).hexdigest()
    if not hmac.compare_digest(actual_sha256, expected_sha256):
        raise ValueError(f"published evidence hash mismatch: {filename}")
    return resolved, content


def _strict_json_document(content: bytes, label: str) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise ValueError(f"{label} contains duplicate JSON keys")
            result[key] = value
        return result

    try:
        document = json.loads(
            content.decode("utf-8"),
            object_pairs_hook=reject_duplicates,
            parse_constant=lambda value: (_ for _ in ()).throw(
                ValueError(f"{label} contains a non-finite number: {value}")
            ),
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"{label} is not valid UTF-8 JSON") from exc
    if not isinstance(document, dict):
        raise ValueError(f"{label} must contain a JSON object")
    return document


def verify_published_release_evidence(
    project_root: Path,
    profile_path: Path,
    output_dir: Path,
) -> tuple[Path, ...]:
    """Verify immutable artifact hashes and redundant internal release metadata."""

    releases = load_published_evidence_profile(project_root, profile_path)
    verified: list[Path] = []
    for release in releases:
        spdx_path, spdx_content = _published_artifact(
            output_dir,
            release.spdx_filename,
            release.spdx_sha256,
        )
        report_path, report_content = _published_artifact(
            output_dir,
            release.license_report_filename,
            release.license_report_sha256,
        )
        document = _strict_json_document(spdx_content, release.spdx_filename)
        if (
            document.get("spdxVersion") != "SPDX-2.3"
            or document.get("name") != release.spdx_document_name
            or document.get("documentNamespace") != release.spdx_document_namespace
        ):
            raise ValueError(
                f"published SPDX document metadata mismatch: {release.spdx_filename}"
            )
        creation = document.get("creationInfo")
        if not isinstance(creation, dict) or creation != {
            "created": release.created,
            "creators": [f"Tool: {release.generator}"],
        }:
            raise ValueError(
                f"published SPDX creation metadata mismatch: {release.spdx_filename}"
            )
        packages = document.get("packages")
        if (
            not isinstance(packages, list)
            or len(packages) != release.third_party_package_count + 1
        ):
            raise ValueError(
                f"published SPDX package count mismatch: {release.spdx_filename}"
            )
        roots = [
            package
            for package in packages
            if isinstance(package, dict)
            and package.get("SPDXID") == SPDX_ROOT_ID
        ]
        if (
            len(roots) != 1
            or roots[0].get("name") != ROOT_PACKAGE
            or roots[0].get("versionInfo") != release.version
            or release.lock_sha256 not in str(roots[0].get("comment", ""))
        ):
            raise ValueError(
                f"published SPDX root metadata mismatch: {release.spdx_filename}"
            )

        try:
            report = report_content.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(
                f"published license report is not UTF-8: {release.license_report_filename}"
            ) from exc
        required_report_lines = {
            f"# Fetech {release.version} dependency-license report",
            f"- Generator: `{release.generator}`",
            f"- Evidence timestamp: `{release.created}`",
            f"- `uv.lock` SHA-256: `{release.lock_sha256}`",
            (
                "- Third-party locked packages: "
                f"**{release.third_party_package_count}**"
            ),
        }
        if not required_report_lines.issubset(set(report.splitlines())):
            raise ValueError(
                "published license report metadata mismatch: "
                f"{release.license_report_filename}"
            )
        verified.extend((spdx_path, report_path))
    return tuple(verified)


def _profile_input(
    project_root: Path,
    configured_path: str,
) -> tuple[str, str]:
    relative = Path(configured_path)
    if relative.is_absolute() or ".." in relative.parts:
        raise ValueError("overlay evidence inputs must be project-relative paths")
    root = project_root.resolve()
    resolved = (root / relative).resolve()
    try:
        canonical_relative = resolved.relative_to(root)
    except ValueError as exc:
        raise ValueError("overlay evidence inputs must remain within the project root") from exc
    if not resolved.is_file():
        raise ValueError(f"missing overlay evidence input: {canonical_relative.as_posix()}")
    return (
        canonical_relative.as_posix(),
        hashlib.sha256(resolved.read_bytes()).hexdigest(),
    )


def _manifest_capability_counts(
    manifest_path: Path,
    closure_release: str,
) -> tuple[int, int]:
    """Return canonical IDs in one closure release and across the manifest."""

    document = yaml.safe_load(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(document, dict):
        raise ValueError("capability manifest must be a mapping")
    categories = document.get("categories")
    if not isinstance(categories, list):
        raise ValueError("capability manifest must contain a categories list")

    category_ids: list[str] = []
    capability_ids: list[str] = []
    closure_capability_ids: list[str] = []
    for category in categories:
        if not isinstance(category, dict):
            raise ValueError("capability manifest categories must be mappings")
        category_id = category.get("id")
        if not isinstance(category_id, str) or not category_id:
            raise ValueError("capability manifest categories require non-empty IDs")
        category_ids.append(category_id)
        capabilities = category.get("capabilities")
        if not isinstance(capabilities, list):
            raise ValueError(
                f"capability manifest category {category_id!r} requires a capabilities list"
            )
        category_release = category.get("closure_release")
        if not isinstance(category_release, str) or not category_release:
            raise ValueError(
                f"capability manifest category {category_id!r} requires closure_release"
            )
        for capability in capabilities:
            if not isinstance(capability, dict):
                raise ValueError("capability manifest capabilities must be mappings")
            capability_id = capability.get("id")
            if not isinstance(capability_id, str) or not capability_id:
                raise ValueError("capability manifest capabilities require non-empty IDs")
            capability_ids.append(capability_id)
            if category_release == closure_release:
                closure_capability_ids.append(capability_id)

    if len(category_ids) != len(set(category_ids)):
        raise ValueError("capability manifest category IDs must be unique")
    if len(capability_ids) != len(set(capability_ids)):
        raise ValueError("capability manifest canonical capability IDs must be unique")
    if not closure_capability_ids:
        raise ValueError(
            f"capability manifest has no capabilities for closure_release {closure_release!r}"
        )

    declared_categories = document.get("category_count")
    if declared_categories != len(category_ids):
        raise ValueError(
            "capability manifest category_count does not match its categories list"
        )
    declared_capabilities = document.get("capability_count")
    if declared_capabilities != len(capability_ids):
        raise ValueError(
            "capability manifest capability_count does not match its capabilities"
        )
    return len(closure_capability_ids), len(capability_ids)


def load_development_overlay(
    project_root: Path,
    profile_path: Path,
    *,
    package_version: str,
) -> DevelopmentOverlay:
    """Load a bounded development-overlay profile and hash every declared input."""

    root = project_root.resolve()
    resolved_profile = profile_path.resolve()
    try:
        profile_relative = resolved_profile.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("overlay profile must remain within the project root") from exc
    if not resolved_profile.is_file():
        raise ValueError(f"missing overlay profile: {profile_relative}")

    document = tomllib.loads(resolved_profile.read_text(encoding="utf-8"))
    overlay = dict(document.get("overlay", {}))
    identifier = _bounded_profile_text(overlay.get("identifier", ""), "identifier", maximum=80)
    if OVERLAY_ID_PATTERN.fullmatch(identifier) is None:
        raise ValueError("overlay identifier must use lowercase letters, digits, dots, or hyphens")
    title = _bounded_profile_text(overlay.get("title", ""), "title", maximum=120)
    declared_package_version = _bounded_profile_text(
        overlay.get("package_version", ""),
        "package_version",
        maximum=80,
    )
    if declared_package_version != package_version:
        raise ValueError(
            "overlay package_version must match pyproject.toml and uv.lock; "
            "development evidence cannot relabel the package"
        )
    status = _bounded_profile_text(overlay.get("status", ""), "status", maximum=80)
    if status != "unreleased-development":
        raise ValueError("overlay status must be unreleased-development")
    created = _bounded_profile_text(overlay.get("created", ""), "created", maximum=32)
    if UTC_TIMESTAMP_PATTERN.fullmatch(created) is None:
        raise ValueError("overlay created must be a fixed UTC timestamp")
    closure_release = _bounded_profile_text(
        overlay.get("closure_release", ""),
        "closure_release",
        maximum=32,
    )
    if CLOSURE_RELEASE_PATTERN.fullmatch(closure_release) is None:
        raise ValueError("overlay closure_release must use the form vMAJOR.MINOR")

    capability_count = int(overlay.get("capability_count", 0))
    cumulative_capability_count = int(overlay.get("cumulative_capability_count", 0))
    if capability_count <= 0 or cumulative_capability_count < capability_count:
        raise ValueError("overlay capability counts are inconsistent")

    spdx_filename = _bounded_profile_text(
        overlay.get("spdx_filename", ""),
        "spdx_filename",
        maximum=160,
    )
    report_filename = _bounded_profile_text(
        overlay.get("license_report_filename", ""),
        "license_report_filename",
        maximum=160,
    )
    if (
        Path(spdx_filename).name != spdx_filename
        or not spdx_filename.endswith(".spdx.json")
    ):
        raise ValueError("overlay spdx_filename must be a bounded .spdx.json basename")
    if (
        Path(report_filename).name != report_filename
        or not report_filename.endswith(".md")
    ):
        raise ValueError("overlay license_report_filename must be a bounded .md basename")
    if spdx_filename == report_filename:
        raise ValueError("overlay evidence output filenames must be distinct")

    configured_inputs = overlay.get("evidence_inputs", ())
    if not isinstance(configured_inputs, list) or not configured_inputs:
        raise ValueError("overlay evidence_inputs must be a non-empty list")
    input_paths = [profile_relative]
    input_paths.extend(
        _bounded_profile_text(value, "evidence_input", maximum=500)
        for value in configured_inputs
    )
    if len(input_paths) != len(set(input_paths)):
        raise ValueError("overlay evidence_inputs must be unique")
    input_hashes = tuple(
        _profile_input(root, configured_path)
        for configured_path in input_paths
    )
    manifest_relative = "capabilities/manifest.yaml"
    if manifest_relative not in dict(input_hashes):
        raise ValueError(
            "overlay evidence_inputs must include capabilities/manifest.yaml"
        )
    manifest_capability_count, manifest_cumulative_capability_count = (
        _manifest_capability_counts(root / manifest_relative, closure_release)
    )
    if capability_count != manifest_capability_count:
        raise ValueError(
            f"overlay capability_count {capability_count} does not match manifest "
            f"{closure_release} count {manifest_capability_count}"
        )
    if cumulative_capability_count != manifest_cumulative_capability_count:
        raise ValueError(
            f"overlay cumulative_capability_count {cumulative_capability_count} "
            f"does not match manifest count {manifest_cumulative_capability_count}"
        )

    external_components: list[ExternalComponent] = []
    for entry in document.get("external_components", ()):
        component = dict(entry)
        source_url = _bounded_profile_text(
            component.get("source_url", ""),
            "external component source_url",
            maximum=500,
        )
        if not source_url.startswith("https://"):
            raise ValueError("overlay external component source_url must use HTTPS")
        external_components.append(
            ExternalComponent(
                name=_bounded_profile_text(
                    component.get("name", ""),
                    "external component name",
                    maximum=120,
                ),
                status=_bounded_profile_text(
                    component.get("status", ""),
                    "external component status",
                ),
                license_observation=_bounded_profile_text(
                    component.get("license_observation", ""),
                    "external component license_observation",
                ),
                required_review=_bounded_profile_text(
                    component.get("required_review", ""),
                    "external component required_review",
                ),
                source_url=source_url,
            )
        )
    if not external_components:
        raise ValueError("overlay external_components must not be empty")
    names = [component.name.casefold() for component in external_components]
    if len(names) != len(set(names)):
        raise ValueError("overlay external component names must be unique")

    publication_gaps = tuple(
        _bounded_profile_text(value, "publication_gap")
        for value in overlay.get("publication_gaps", ())
    )
    if not publication_gaps:
        raise ValueError("overlay publication_gaps must not be empty")

    return DevelopmentOverlay(
        identifier=identifier,
        title=title,
        package_version=declared_package_version,
        status=status,
        created=created,
        closure_release=closure_release,
        capability_count=capability_count,
        cumulative_capability_count=cumulative_capability_count,
        spdx_filename=spdx_filename,
        license_report_filename=report_filename,
        input_hashes=input_hashes,
        external_components=tuple(external_components),
        publication_gaps=publication_gaps,
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


def build_spdx_document(
    inputs: ReleaseInputs,
    overlay: DevelopmentOverlay | None = None,
) -> dict[str, Any]:
    """Build a deterministic SPDX 2.3 JSON document."""

    version = str(inputs.project["version"])
    if overlay is not None and overlay.package_version != version:
        raise ValueError("development overlay does not match the package version")
    evidence_name = overlay.identifier if overlay is not None else version
    namespace_digest = inputs.lock_sha256
    if overlay is not None:
        overlay_digest = hashlib.sha256(
            "\n".join(
                f"{path}\0{digest}" for path, digest in overlay.input_hashes
            ).encode("utf-8")
        ).hexdigest()
        namespace_digest = f"{inputs.lock_sha256}-{overlay_digest}"
    namespace = (
        "https://github.com/AmudeeshanSrinivasan/Fetech/"
        f"spdx/fetech-{quote(evidence_name, safe='')}-{namespace_digest}"
    )
    root_comment = (
        "Root package metadata from pyproject.toml and uv.lock. "
        f"uv.lock SHA-256: {inputs.lock_sha256}."
    )
    if overlay is not None:
        root_comment += (
            f" {overlay.title} is {overlay.status}; the package version remains "
            f"{version}, and this document is not a published-release SBOM."
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
        "comment": root_comment,
    }
    spdx_packages: list[dict[str, Any]] = [root_package]
    package_ids: dict[str, str] = {}

    for package in inputs.packages:
        name = _canonical_name(str(package["name"]))
        package_version = str(package["version"])
        package_id = _spdx_package_id(name, package_version)
        catalog_key = _catalog_key(package)
        package_ids[catalog_key] = package_id
        download_location, checksums = _package_download_and_checksum(package)
        package_scope_text = ", ".join(
            sorted(inputs.scopes[catalog_key], key=_scope_sort_key)
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
                f"Universal-lock scopes: {package_scope_text}. "
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
    for package_key, direct_scope_set in sorted(inputs.direct_scopes.items()):
        scope_text = ", ".join(sorted(direct_scope_set, key=_scope_sort_key))
        if "runtime" in direct_scope_set:
            relationships.append(
                {
                    "spdxElementId": SPDX_ROOT_ID,
                    "relationshipType": "DEPENDS_ON",
                    "relatedSpdxElement": package_ids[package_key],
                    "comment": f"Direct dependency scopes: {scope_text}.",
                }
            )
        elif direct_scope_set == {"extra:dev"}:
            relationships.append(
                {
                    "spdxElementId": package_ids[package_key],
                    "relationshipType": "DEV_DEPENDENCY_OF",
                    "relatedSpdxElement": SPDX_ROOT_ID,
                    "comment": f"Direct dependency scopes: {scope_text}.",
                }
            )
        else:
            relationships.append(
                {
                    "spdxElementId": package_ids[package_key],
                    "relationshipType": "OPTIONAL_DEPENDENCY_OF",
                    "relatedSpdxElement": SPDX_ROOT_ID,
                    "comment": f"Direct dependency scopes: {scope_text}.",
                }
            )

    for (parent, dependency), dependency_scope_set in sorted(
        inputs.dependency_edges.items()
    ):
        if parent == ROOT_PACKAGE:
            continue
        relationships.append(
            {
                "spdxElementId": package_ids[parent],
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_ids[dependency],
                "comment": (
                    "Resolved universal-lock scopes: "
                    f"{', '.join(sorted(dependency_scope_set, key=_scope_sort_key))}."
                ),
            }
        )

    lock_only = sorted(
        key for key, scopes in inputs.scopes.items() if scopes == {"lock-only"}
    )
    for package_key in lock_only:
        relationships.append(
            {
                "spdxElementId": package_ids[package_key],
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
    document_comment = (
        "Deterministic release SBOM generated from pyproject.toml, uv.lock, "
        "and scripts/release_license_catalog.toml. It describes the universal "
        "lock across all declared extras and platform markers, not one installed environment."
    )
    if overlay is not None:
        input_hashes = ", ".join(
            f"{path}=sha256:{digest}" for path, digest in overlay.input_hashes
        )
        document_comment = (
            f"Deterministic {overlay.status} overlay SBOM generated from "
            "pyproject.toml, uv.lock, scripts/release_license_catalog.toml, and "
            f"the hashed overlay inputs ({input_hashes}). It covers "
            f"{overlay.capability_count} overlay capabilities and "
            f"{overlay.cumulative_capability_count} cumulative capabilities. "
            "It describes the universal Python lock, not one installed environment; "
            "unbundled executables, browser downloads, and configured provider boundaries "
            "are excluded from the SPDX package inventory and itemized in the paired "
            "dependency-license report."
        )
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": SPDX_DOCUMENT_ID,
        "name": f"fetech-{evidence_name}-universal-lock",
        "documentNamespace": namespace,
        "creationInfo": {
            "created": overlay.created if overlay is not None else RELEASE_CREATED,
            "creators": [
                f"Tool: {OVERLAY_GENERATOR_NAME if overlay is not None else GENERATOR_NAME}"
            ],
        },
        "documentDescribes": [SPDX_ROOT_ID],
        "hasExtractedLicensingInfos": [
            EXTRACTED_LICENSE_INFO[reference] for reference in referenced_license_refs
        ],
        "packages": spdx_packages,
        "relationships": relationships,
        "comment": document_comment,
    }


def build_license_report(
    inputs: ReleaseInputs,
    overlay: DevelopmentOverlay | None = None,
) -> str:
    """Build the human-readable dependency-license audit report."""

    version = str(inputs.project["version"])
    if overlay is not None and overlay.package_version != version:
        raise ValueError("development overlay does not match the package version")
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

    if overlay is None:
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
    else:
        lines = [
            f"# Fetech {overlay.title} dependency-license report",
            "",
            "This is deterministic development engineering evidence, not legal advice and not",
            "a published-release license report. The package metadata and universal lock remain",
            f"`{version}`; the overlay label does not relabel the Python distribution.",
            "License declarations were reviewed for the exact versions in `uv.lock`; SPDX",
            "`licenseConcluded` remains `NOASSERTION` for third-party packages because this",
            "report does not make legal conclusions.",
            "",
            "## Inputs and coverage",
            "",
            f"- Generator: `{OVERLAY_GENERATOR_NAME}`",
            f"- Evidence timestamp: `{overlay.created}`",
            f"- Overlay status: `{overlay.status}`",
            f"- Package version: `{version}`",
            f"- `uv.lock` SHA-256: `{inputs.lock_sha256}`",
            f"- Third-party locked packages: **{len(inputs.packages)}**",
            f"- Overlay capabilities: **{overlay.capability_count}**",
            f"- Cumulative registered capabilities: **{overlay.cumulative_capability_count}**",
            "- Coverage: base runtime, every declared optional extra, development dependencies,",
            "  and all platform-marker alternatives represented by the universal lock.",
            "- Package evidence links point to version-specific PyPI release pages. The reviewed",
            "  catalog also uses package metadata, bundled notices, and upstream license files;",
            "  special review notes remain attached to affected rows.",
            "",
            "### Hashed development-overlay inputs",
            "",
            "| Input | SHA-256 |",
            "|---|---|",
        ]
        lines.extend(
            f"| `{path}` | `{digest}` |"
            for path, digest in overlay.input_hashes
        )
        lines.extend(
            [
                "",
                "## Automated policy observations",
                "",
                "- Missing or `NOASSERTION` declared licenses: **0**",
                f"- Declared AGPL expressions: **{len(agpl_packages)}**",
                f"- Ambiguous `LicenseRef` declarations: **{len(ambiguous_packages)}**",
                f"- Disjunctive GPL/LGPL choice expressions: **{len(choice_packages)}**",
            ]
        )
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
    if overlay is None:
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
    else:
        lines.extend(
            [
                "",
                "## Separately installed tools and configured boundaries",
                "",
                "These executables, downloaded artifacts, and provider boundaries are not Python",
                f"packages distributed in the current `{version}` wheel, so they are excluded from",
                "the lock-derived SPDX package inventory. Their rows are development inputs, not",
                "proof that a particular executable build, browser download, service, or connector",
                "was installed or exercised. A distribution that bundles one must record its exact",
                "version, build options, licenses, notices, and transitive libraries.",
                "",
                "| Component | Development-overlay status | License observation | "
                "Required review | Primary source |",
                "|---|---|---|---|---|",
            ]
        )
        for component in overlay.external_components:
            lines.append(
                f"| {component.name} | {component.status} | "
                f"{component.license_observation} | {component.required_review} | "
                f"[Upstream]({component.source_url}) |"
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
            f"`{scope}`" for scope in sorted(inputs.scopes[key], key=_scope_sort_key)
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

    if overlay is not None:
        lines.extend(
            [
                "",
                "## Publication gaps",
                "",
            ]
        )
        lines.extend(f"- {gap}" for gap in overlay.publication_gaps)
    reproduction_command = "uv run python scripts/generate_release_evidence.py --check"
    checked_inputs = "`pyproject.toml`, `uv.lock`, or the reviewed catalog"
    if overlay is not None:
        reproduction_command = (
            "uv run python scripts/generate_release_evidence.py "
            "--overlay-profile scripts/release_v04_development.toml --check"
        )
        checked_inputs = (
            "`pyproject.toml`, `uv.lock`, the reviewed catalog, or any hashed "
            "development-overlay input"
        )
    lines.extend(
        [
            "",
            "## Reproduction",
            "",
            "Run from the repository root:",
            "",
            "```console",
            reproduction_command,
            "```",
            "",
            "`--check` regenerates both artifacts in memory and fails if tracked evidence",
            f"differs from {checked_inputs}.",
            "",
        ]
    )
    return "\n".join(lines)


def render_release_evidence(
    project_path: Path,
    lock_path: Path,
    catalog_path: Path,
    overlay: DevelopmentOverlay | None = None,
) -> tuple[str, str, str]:
    """Return version, canonical SPDX JSON, and canonical Markdown report."""

    inputs = load_release_inputs(project_path, lock_path, catalog_path)
    spdx = json.dumps(
        build_spdx_document(inputs, overlay),
        indent=2,
        sort_keys=True,
        ensure_ascii=False,
    )
    report = build_license_report(inputs, overlay)
    return str(inputs.project["version"]), f"{spdx}\n", report


def _artifact_paths(
    output_dir: Path,
    version: str,
    overlay: DevelopmentOverlay | None = None,
) -> tuple[Path, Path]:
    if overlay is not None:
        return (
            output_dir / overlay.spdx_filename,
            output_dir / overlay.license_report_filename,
        )
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
    overlay_profile: Path | None = None,
) -> tuple[Path, Path]:
    """Generate or verify both release evidence artifacts."""

    project_path = project_root / "pyproject.toml"
    lock_path = project_root / "uv.lock"
    catalog_path = project_root / "scripts" / "release_license_catalog.toml"
    overlay = None
    if overlay_profile is not None:
        release_inputs = load_release_inputs(project_path, lock_path, catalog_path)
        overlay = load_development_overlay(
            project_root,
            overlay_profile,
            package_version=str(release_inputs.project["version"]),
        )
    version, spdx, report = render_release_evidence(
        project_path,
        lock_path,
        catalog_path,
        overlay,
    )
    spdx_path, report_path = _artifact_paths(output_dir, version, overlay)
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
        "--overlay-profile",
        type=Path,
        help=(
            "generate an explicitly unreleased development-overlay projection "
            "without changing the package version"
        ),
    )
    parser.add_argument(
        "--published-profile",
        type=Path,
        default=Path("scripts/release_published.toml"),
        help="bounded hash and metadata profile for immutable published evidence",
    )
    parser.add_argument(
        "--check-published",
        action="store_true",
        help="verify immutable published artifacts instead of generating evidence",
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when tracked artifacts differ instead of writing them",
    )
    args = parser.parse_args(argv)
    project_root = args.project_root.resolve()
    output_dir = args.output_dir or project_root / "release"
    overlay_profile = args.overlay_profile
    published_profile = args.published_profile
    if overlay_profile is not None and not overlay_profile.is_absolute():
        overlay_profile = project_root / overlay_profile
    if not published_profile.is_absolute():
        published_profile = project_root / published_profile
    if args.check_published:
        if overlay_profile is not None:
            raise ValueError(
                "--check-published cannot be combined with --overlay-profile"
            )
        paths = verify_published_release_evidence(
            project_root,
            published_profile,
            output_dir,
        )
        print(
            "verified published: "
            f"{', '.join(path.name for path in paths)}"
        )
        return 0
    if overlay_profile is None and published_profile.is_file():
        project_document = tomllib.loads(
            (project_root / "pyproject.toml").read_text(encoding="utf-8")
        )
        package_version = str(project_document["project"]["version"])
        published_versions = {
            release.version
            for release in load_published_evidence_profile(
                project_root,
                published_profile,
            )
        }
        if package_version in published_versions:
            raise ValueError(
                f"release evidence for published version {package_version} is immutable; "
                "use --check-published, an explicit development overlay, or bump the "
                "package version"
            )
    paths = generate(
        project_root,
        output_dir,
        check=args.check,
        overlay_profile=overlay_profile,
    )
    action = "verified" if args.check else "generated"
    print(f"{action}: {', '.join(path.name for path in paths)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
