#!/usr/bin/env python3
"""Prepare and finalize a blinded independent context-answer evaluation."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from fetech.context_benchmark import (
    ContextBenchmarkError,
    benchmark_source_identity,
    load_benchmark_suite,
)
from fetech.context_evaluation import (
    build_blinded_review,
    build_candidate_templates,
    finalize_blinded_review,
    load_blinding_map,
    load_candidate_answers,
    load_review_packet,
    load_review_ratings,
    write_local_json,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE = ROOT / "benchmarks" / "context-tasks.yaml"
DEFAULT_PROTOCOL = ROOT / "benchmarks" / "context-answer-protocol.md"
DEFAULT_DIRECTORY = ROOT / "runtime-data" / "context-answer-evaluation"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run Fetech's commit-bound blinded answer-review workflow.",
    )
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--generation-protocol", type=Path, default=DEFAULT_PROTOCOL)
    subparsers = parser.add_subparsers(dest="command", required=True)

    templates = subparsers.add_parser("templates", help="write two answer-producer templates")
    templates.add_argument(
        "--full-output", type=Path, default=DEFAULT_DIRECTORY / "full-context-answers.json"
    )
    templates.add_argument(
        "--broker-output", type=Path, default=DEFAULT_DIRECTORY / "broker-answers.json"
    )
    templates.add_argument("--force", action="store_true")

    blind = subparsers.add_parser("blind", help="blind two completed candidate answer sets")
    blind.add_argument(
        "--full-answers", type=Path, default=DEFAULT_DIRECTORY / "full-context-answers.json"
    )
    blind.add_argument(
        "--broker-answers", type=Path, default=DEFAULT_DIRECTORY / "broker-answers.json"
    )
    blind.add_argument(
        "--packet-output", type=Path, default=DEFAULT_DIRECTORY / "review-packet.json"
    )
    blind.add_argument(
        "--mapping-output", type=Path, default=DEFAULT_DIRECTORY / "blinding-map.json"
    )
    blind.add_argument(
        "--ratings-output", type=Path, default=DEFAULT_DIRECTORY / "review-ratings.json"
    )
    blind.add_argument("--force", action="store_true")

    finalize = subparsers.add_parser("finalize", help="validate and unblind completed ratings")
    finalize.add_argument(
        "--packet", type=Path, default=DEFAULT_DIRECTORY / "review-packet.json"
    )
    finalize.add_argument(
        "--mapping", type=Path, default=DEFAULT_DIRECTORY / "blinding-map.json"
    )
    finalize.add_argument(
        "--ratings", type=Path, default=DEFAULT_DIRECTORY / "review-ratings.json"
    )
    finalize.add_argument(
        "--output", type=Path, default=DEFAULT_DIRECTORY / "answer-evaluations.json"
    )
    finalize.add_argument("--force", action="store_true")
    return parser.parse_args()


def _clean_commit(repository: Path) -> str:
    commit, dirty = benchmark_source_identity(repository)
    if commit is None or dirty:
        raise ContextBenchmarkError(
            "answer evaluation requires a clean Git worktree at a canonical commit"
        )
    return commit


def _refuse_existing(paths: tuple[Path, ...], *, force: bool) -> None:
    if force:
        return
    existing = [path.name for path in paths if path.expanduser().resolve().exists()]
    if existing:
        raise ContextBenchmarkError(
            "refusing to overwrite existing review files: " + ", ".join(existing)
        )


def main() -> int:
    arguments = _arguments()
    repository = arguments.repository.expanduser().resolve()
    try:
        suite_bytes = arguments.suite.read_bytes()
        protocol_bytes = arguments.generation_protocol.read_bytes()
        suite = load_benchmark_suite(arguments.suite)
        commit = _clean_commit(repository)
        if arguments.command == "templates":
            _refuse_existing(
                (arguments.full_output, arguments.broker_output), force=arguments.force
            )
            full_context, broker = build_candidate_templates(
                suite, suite_bytes, protocol_bytes, commit
            )
            write_local_json(arguments.full_output, full_context, force=arguments.force)
            write_local_json(arguments.broker_output, broker, force=arguments.force)
            result = {
                "broker_output": str(arguments.broker_output),
                "full_output": str(arguments.full_output),
                "source_commit": commit,
                "tasks": len(suite.tasks),
            }
        elif arguments.command == "blind":
            _refuse_existing(
                (arguments.packet_output, arguments.mapping_output, arguments.ratings_output),
                force=arguments.force,
            )
            full_context = load_candidate_answers(arguments.full_answers)
            broker = load_candidate_answers(arguments.broker_answers)
            packet, mapping, ratings = build_blinded_review(
                suite, suite_bytes, protocol_bytes, commit, full_context, broker
            )
            write_local_json(arguments.packet_output, packet, force=arguments.force)
            write_local_json(arguments.mapping_output, mapping, private=True, force=arguments.force)
            write_local_json(arguments.ratings_output, ratings, force=arguments.force)
            result = {
                "mapping_output": str(arguments.mapping_output),
                "packet_output": str(arguments.packet_output),
                "ratings_output": str(arguments.ratings_output),
                "tasks": len(packet.tasks),
            }
        else:
            _refuse_existing((arguments.output,), force=arguments.force)
            evaluations = finalize_blinded_review(
                suite,
                suite_bytes,
                protocol_bytes,
                commit,
                load_review_packet(arguments.packet),
                load_blinding_map(arguments.mapping),
                load_review_ratings(arguments.ratings),
            )
            write_local_json(arguments.output, evaluations, force=arguments.force)
            result = {
                "evaluator": evaluations.evaluator,
                "output": str(arguments.output),
                "tasks": len(evaluations.evaluations),
            }
    except (ContextBenchmarkError, OSError, ValueError) as exc:
        print(f"context answer evaluation failed: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
