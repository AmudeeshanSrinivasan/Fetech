"""Canonical capability registry backed by the checked-in manifest."""

from __future__ import annotations

import os
from collections.abc import Iterator
from importlib.resources import files
from pathlib import Path
from typing import Any

import yaml

from fetech.models import CapabilityKind, CapabilityManifestEntry

EXPECTED_CATEGORIES = 13
EXPECTED_CAPABILITIES = 155


class ManifestError(ValueError):
    """Raised when the canonical manifest violates a registry invariant."""


def default_manifest_path() -> Path:
    configured = os.environ.get("FETECH_MANIFEST")
    if configured:
        return Path(configured).expanduser().resolve()
    source_path = Path(__file__).resolve().parents[2] / "capabilities" / "manifest.yaml"
    if source_path.exists():
        return source_path
    resource = files("fetech").joinpath("data/manifest.yaml")
    return Path(str(resource))


class CapabilityRegistry:
    def __init__(self, manifest_path: Path | None = None) -> None:
        self.manifest_path = manifest_path or default_manifest_path()
        self.manifest_version, self._entries = self._load(self.manifest_path)
        self._by_id = {entry.id: entry for entry in self._entries}
        self._aliases = {alias: entry.id for entry in self._entries for alias in entry.aliases}
        self._validate()

    @staticmethod
    def _load(path: Path) -> tuple[str, tuple[CapabilityManifestEntry, ...]]:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or not isinstance(raw.get("categories"), list):
            raise ManifestError("manifest must contain a categories list")
        entries: list[CapabilityManifestEntry] = []
        for category in raw["categories"]:
            if not isinstance(category, dict):
                raise ManifestError("each category must be a mapping")
            for capability in category.get("capabilities", []):
                if not isinstance(capability, dict):
                    raise ManifestError("each capability must be a mapping")
                capability_id = str(capability["id"])
                entries.append(
                    CapabilityManifestEntry(
                        id=capability_id,
                        aliases=tuple(capability.get("aliases", [])),
                        category=str(category["id"]),
                        category_name=str(category["name"]),
                        closure_release=str(category["closure_release"]),
                        kind=CapabilityKind(str(capability["kind"])),
                        adapter=str(capability.get("adapter", category["adapter"])),
                        risk_class=str(capability.get("risk_class", category["risk_class"])),
                        inputs=tuple(capability.get("inputs", ["target"])),
                        outputs=tuple(capability.get("outputs", ["attempt"])),
                        dependencies=tuple(capability.get("dependencies", [])),
                        reference=str(
                            capability.get(
                                "reference", f"docs/capability-catalog.md#{capability_id.replace('_', '-')}"
                            )
                        ),
                        tests=tuple(capability.get("tests", [f"manifest::{capability_id}"])),
                        lifecycle_status=str(capability.get("status", "registered")),
                        available=bool(capability.get("available", True)),
                    )
                )
        return str(raw.get("manifest_version", "unknown")), tuple(entries)

    def _validate(self) -> None:
        categories = {entry.category for entry in self._entries}
        ids = [entry.id for entry in self._entries]
        aliases = [alias for entry in self._entries for alias in entry.aliases]
        errors: list[str] = []
        if len(categories) != EXPECTED_CATEGORIES:
            errors.append(f"expected {EXPECTED_CATEGORIES} categories, found {len(categories)}")
        if len(ids) != EXPECTED_CAPABILITIES:
            errors.append(f"expected {EXPECTED_CAPABILITIES} capabilities, found {len(ids)}")
        if len(ids) != len(set(ids)):
            errors.append("canonical capability IDs are not unique")
        if len(aliases) != len(set(aliases)):
            errors.append("aliases are not unique")
        collisions = set(ids) & set(aliases)
        if collisions:
            errors.append(f"aliases collide with canonical IDs: {sorted(collisions)}")
        if errors:
            raise ManifestError("; ".join(errors))

    def __iter__(self) -> Iterator[CapabilityManifestEntry]:
        return iter(self._entries)

    def __len__(self) -> int:
        return len(self._entries)

    @property
    def categories(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(entry.category for entry in self._entries))

    def resolve_id(self, capability_id: str) -> str:
        if capability_id in self._by_id:
            return capability_id
        try:
            return self._aliases[capability_id]
        except KeyError as exc:
            raise KeyError(f"unknown capability: {capability_id}") from exc

    def get(self, capability_id: str) -> CapabilityManifestEntry:
        return self._by_id[self.resolve_id(capability_id)]

    def for_category(self, category: str) -> tuple[CapabilityManifestEntry, ...]:
        return tuple(entry for entry in self._entries if entry.category == category)

    def as_document(self) -> dict[str, Any]:
        grouped: dict[str, list[dict[str, Any]]] = {}
        for entry in self._entries:
            grouped.setdefault(entry.category, []).append(entry.model_dump(mode="json"))
        return {
            "manifest_version": self.manifest_version,
            "category_count": len(self.categories),
            "capability_count": len(self),
            "categories": grouped,
        }
