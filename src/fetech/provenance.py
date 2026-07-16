"""Rebuildable runtime Graphify projection derived from immutable ledger events."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fetech.ledger import EventLedger


async def build_runtime_graph(ledger: EventLedger, output: Path) -> dict[str, Any]:
    events = await ledger.all_events()
    nodes: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    known: set[str] = set()
    for event in events:
        event_id = str(event.event_id)
        run_id = str(event.run_id)
        if run_id not in known:
            nodes.append({"id": run_id, "label": f"run:{run_id[:8]}", "type": "FetchRun"})
            known.add(run_id)
        nodes.append(
            {
                "id": event_id,
                "label": event.event_type,
                "type": "ProvenanceEvent",
                "timestamp": event.timestamp.isoformat(),
                "actor": event.actor,
                "source": "event-ledger",
            }
        )
        known.add(event_id)
        links.append({"source": run_id, "target": event_id, "type": "EMITTED"})
        for parent in event.parent_event_ids:
            links.append({"source": str(parent), "target": event_id, "type": "PRECEDES"})
        for field in ("artifact_id", "resource_id", "capability_id"):
            value = event.payload.get(field)
            if value is None:
                continue
            target = f"{field}:{value}"
            if target not in known:
                nodes.append({"id": target, "label": str(value), "type": field.removesuffix("_id").title()})
                known.add(target)
            links.append({"source": event_id, "target": target, "type": f"REFERENCES_{field.upper()}"})
    graph = {
        "directed": True,
        "multigraph": True,
        "graph": {"projection": "fetech-runtime", "authoritative": False},
        "nodes": nodes,
        "links": links,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(graph, indent=2, sort_keys=True), encoding="utf-8")
    return graph
