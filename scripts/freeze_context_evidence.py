#!/usr/bin/env python3
"""Capture or verify private, local input evidence; never call an answer model."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

from fetech.context_benchmark import ContextBenchmarkError, load_benchmark_suite
from fetech.context_evaluation import write_local_json
from fetech.context_snapshot import capture_evidence_snapshot, load_evidence_snapshot

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--suite", type=Path, default=ROOT / "benchmarks/context-tasks.yaml")
    parser.add_argument("--protocol", type=Path, default=ROOT / "benchmarks/context-answer-protocol.md")
    parser.add_argument("--vault", type=Path)
    parser.add_argument("--ledger", type=Path, default=ROOT / ".fetech/ledger.sqlite3")
    parser.add_argument("--runtime-graph", type=Path, default=ROOT / ".fetech/runtime-graphify/graph.json")
    parser.add_argument("--output", type=Path,
                        default=ROOT / "runtime-data/context-answer-evaluation/evidence-snapshot.json")
    parser.add_argument("--verify", type=Path, help="verify a saved snapshot without reading live inputs")
    parser.add_argument("--development", action="store_true", help="allow a dirty, non-release rehearsal")
    args = parser.parse_args()
    try:
        if args.verify is not None:
            snapshot = load_evidence_snapshot(args.verify)
            path = args.verify
        else:
            if args.vault is None:
                raise ContextBenchmarkError("capture requires an explicit --vault directory")
            output = args.output.expanduser().absolute()
            allowed = args.repository.expanduser().resolve() / "runtime-data"
            if allowed not in output.resolve().parents:
                raise ContextBenchmarkError("private snapshots must remain under repository runtime-data")
            if output.exists() or output.is_symlink():
                raise ContextBenchmarkError("refusing to overwrite an existing snapshot")
            snapshot = capture_evidence_snapshot(
                args.repository, load_benchmark_suite(args.suite), args.suite.read_bytes(),
                args.protocol.read_bytes(), vault=args.vault, ledger=args.ledger,
                runtime_graph=args.runtime_graph, development=args.development,
            )
            write_local_json(output, snapshot, private=True)
            # Re-read the exact serialized artifact to verify on-disk integrity.
            snapshot = load_evidence_snapshot(output)
            path = output
        print(json.dumps({
            "output": str(path), "snapshot_sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "tasks": len(snapshot.tasks), "documents": len(snapshot.documents),
            "notes": sum(doc.kind == "note" for doc in snapshot.documents),
            "maximum_baseline_estimated_tokens": max(task.estimated_tokens for task in snapshot.tasks),
            "source_commit": snapshot.source_commit, "source_dirty": snapshot.source_dirty,
            "stage": snapshot.stage,
        }, sort_keys=True))
    except (ContextBenchmarkError, OSError, ValueError):
        # Validation exceptions may include private input snippets; never echo them.
        print("evidence freeze failed: invalid, changed, oversized, mismatched or existing inputs; "
              "check paths, clean-source state and ledger/projection parity", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
