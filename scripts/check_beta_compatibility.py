"""Check or explicitly refresh the frozen Beta v1 public-surface baseline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from fetech.compatibility import (
    CompatibilityBaselineError,
    verify_compatibility_baseline,
    write_compatibility_baseline,
)

_ROOT = Path(__file__).resolve().parents[1]
_DEFAULT_BASELINE = _ROOT / "compatibility" / "beta-v1.json"


def _arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail closed when the frozen Beta v1 public interface surface drifts.",
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=_DEFAULT_BASELINE,
        help="Checked-in compatibility baseline path.",
    )
    parser.add_argument(
        "--write",
        action="store_true",
        help="Explicitly replace the baseline with the current reviewed surface.",
    )
    return parser.parse_args()


def main() -> int:
    arguments = _arguments()
    try:
        if arguments.write:
            write_compatibility_baseline(arguments.baseline)
            print(f"wrote Beta compatibility baseline: {arguments.baseline}")
            return 0
        differences = verify_compatibility_baseline(arguments.baseline)
    except CompatibilityBaselineError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    if differences:
        print("Beta public interface surface differs from the checked-in baseline:", file=sys.stderr)
        for difference in differences:
            print(f"- {difference}", file=sys.stderr)
        print(
            "Review compatibility and run this script with --write only for an intentional freeze.",
            file=sys.stderr,
        )
        return 1
    print("Beta compatibility baseline matches the current public surface.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
