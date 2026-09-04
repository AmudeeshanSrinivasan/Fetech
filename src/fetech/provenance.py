"""Rebuildable runtime Graphify projection derived from immutable ledger events."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

from fetech.ledger import EventLedger
from fetech.storage import StorageLifecycleError, StorageQuota


async def build_runtime_graph(
    ledger: EventLedger,
    output: Path,
    *,
    quota: StorageQuota | None = None,
) -> dict[str, Any]:
    events = await ledger.all_events()
    nodes: list[dict[str, Any]] = []
    links: list[dict[str, Any]] = []
    known: set[str] = set()
    for event in events:
        event_id = str(event.event_id)
        run_id = str(event.run_id)
        if run_id not in known:
            nodes.append(
                {
                    "id": run_id,
                    "label": f"run:{run_id[:8]}",
                    "type": "FetchRun",
                    "source": "event-ledger",
                    "source_file": "event-ledger",
                    "source_location": f"ledger://runs/{run_id}",
                }
            )
            known.add(run_id)
        nodes.append(
            {
                "id": event_id,
                "label": event.event_type,
                "type": "ProvenanceEvent",
                "event_id": event_id,
                "run_id": run_id,
                "event_type": event.event_type,
                "timestamp": event.timestamp.isoformat(),
                "actor": event.actor,
                "payload": event.payload,
                "source": "event-ledger",
                "source_file": "event-ledger",
                "source_location": f"ledger://runs/{run_id}/events/{event_id}",
            }
        )
        known.add(event_id)
        links.append(
            {
                "source": run_id,
                "target": event_id,
                "type": "EMITTED",
                "relation": "emitted",
                "confidence": "EXTRACTED",
                "confidence_score": 1.0,
            }
        )
        for parent in event.parent_event_ids:
            links.append(
                {
                    "source": str(parent),
                    "target": event_id,
                    "type": "PRECEDES",
                    "relation": "precedes",
                    "confidence": "EXTRACTED",
                    "confidence_score": 1.0,
                }
            )
        for field in ("artifact_id", "resource_id", "capability_id"):
            value = event.payload.get(field)
            if value is None:
                continue
            target = f"{field}:{value}"
            if target not in known:
                nodes.append({"id": target, "label": str(value), "type": field.removesuffix("_id").title()})
                known.add(target)
            relation = f"references_{field}"
            links.append(
                {
                    "source": event_id,
                    "target": target,
                    "type": relation.upper(),
                    "relation": relation,
                    "confidence": "EXTRACTED",
                    "confidence_score": 1.0,
                }
            )
    graph = {
        "directed": True,
        "multigraph": True,
        "graph": {
            "projection": "fetech-runtime",
            "schema_version": "1.0",
            "authoritative": False,
            "authority": "event-ledger",
        },
        "nodes": nodes,
        "links": links,
    }
    encoded = (json.dumps(graph, indent=2, sort_keys=True) + "\n").encode("utf-8")
    existing_size = _existing_regular_size(output)
    additional_bytes = max(0, len(encoded) - existing_size)
    if quota is None:
        _write_runtime_graph(output, encoded)
    else:
        resolved_output = output.expanduser().resolve()
        if resolved_output != quota.root and quota.root not in resolved_output.parents:
            raise ValueError("runtime graph must be contained by the storage quota root")
        async with quota.reserve(additional_bytes):
            _write_runtime_graph(resolved_output, encoded)
    return graph


def _existing_regular_size(path: Path) -> int:
    try:
        state = path.lstat()
    except FileNotFoundError:
        return 0
    if path.is_symlink() or not path.is_file():
        raise StorageLifecycleError("runtime graph path is not a regular file")
    return state.st_size


def _write_runtime_graph(output: Path, encoded: bytes) -> None:
    output.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output.name}.",
        suffix=".tmp",
        dir=output.parent,
    )
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, output)
        if os.name != "nt":
            directory = os.open(
                output.parent,
                os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
    finally:
        temporary.unlink(missing_ok=True)
