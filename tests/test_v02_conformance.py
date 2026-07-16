from __future__ import annotations

from fetech.conformance import release_report
from fetech.registry import CapabilityRegistry


def test_v02_inventory_is_truthful_and_cardinality_locked() -> None:
    registry = CapabilityRegistry()
    entries = [entry for entry in registry if entry.closure_release == "v0.2"]
    report = release_report(entries, "v0.2")
    assert len(entries) == 40
    assert {entry.category for entry in entries} == {
        "discovery",
        "alternatives",
        "browser",
    }
    assert report == {
        "release": "v0.2",
        "capability_count": 40,
        "available_count": 40,
        "closure_ready": True,
        "status_counts": {"native": 36, "optional": 4},
        "gaps": [],
    }
    assert all(entry.implementation for entry in entries)
    assert all(entry.tests for entry in entries)
