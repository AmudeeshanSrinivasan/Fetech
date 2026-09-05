#!/usr/bin/env python3
"""Validate or run the Fetech context-efficiency acceptance benchmark."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from fetech.context import ContextBroker
from fetech.context_benchmark import (
    ContextBenchmarkError,
    load_answer_evaluations,
    load_benchmark_suite,
    run_context_benchmark,
    validate_benchmark_environment,
    write_benchmark_report,
)

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SUITE = ROOT / "benchmarks" / "context-tasks.yaml"
DEFAULT_JSON = ROOT / "runtime-data" / "context-benchmark.json"
DEFAULT_MARKDOWN = ROOT / "runtime-data" / "context-benchmark.md"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Measure bounded ContextBundle retrieval against tracked full-document loading.",
    )
    parser.add_argument("--repository", type=Path, default=ROOT)
    parser.add_argument("--suite", type=Path, default=DEFAULT_SUITE)
    parser.add_argument("--runtime-graph", type=Path)
    parser.add_argument("--vault", type=Path)
    parser.add_argument("--qmd-index", default="obsidian-mind")
    parser.add_argument("--answer-evaluations", type=Path)
    parser.add_argument("--output", type=Path, default=DEFAULT_JSON)
    parser.add_argument("--markdown-output", type=Path, default=DEFAULT_MARKDOWN)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument(
        "--validate-only",
        action="store_true",
        help="Validate the 100-task suite and tracked baseline without invoking providers.",
    )
    parser.add_argument(
        "--enforce-targets",
        action="store_true",
        help="Exit non-zero unless every target, including answer correctness, passes.",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    repository = arguments.repository.expanduser().resolve()
    try:
        suite_bytes = arguments.suite.read_bytes()
        suite = load_benchmark_suite(arguments.suite)
        summary = validate_benchmark_environment(repository, suite)
        if arguments.validate_only:
            print(json.dumps(summary, sort_keys=True))
            return 0
        evaluations = (
            load_answer_evaluations(arguments.answer_evaluations)
            if arguments.answer_evaluations is not None
            else None
        )
        broker = ContextBroker(
            repository,
            runtime_graph=arguments.runtime_graph,
            vault=arguments.vault,
            qmd_index=arguments.qmd_index,
        )
        report = asyncio.run(
            run_context_benchmark(
                broker,
                repository,
                suite,
                answer_evaluations=evaluations,
                concurrency=arguments.concurrency,
                suite_bytes=suite_bytes,
            )
        )
        write_benchmark_report(report, arguments.output, arguments.markdown_output)
    except (ContextBenchmarkError, OSError, ValueError) as exc:
        print(f"context benchmark failed: {exc}", file=sys.stderr)
        return 2
    print(
        json.dumps(
            {
                "status": report.status,
                "tasks": report.metrics.task_count,
                "median_token_reduction_percent": report.metrics.median_token_reduction_percent,
                "relevant_evidence_recall_percent": (
                    report.metrics.relevant_evidence_recall_percent
                ),
                "output": str(arguments.output),
            },
            sort_keys=True,
        )
    )
    return int(arguments.enforce_targets and report.status != "PASSED")


if __name__ == "__main__":
    raise SystemExit(main())
