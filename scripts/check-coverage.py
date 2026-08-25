#!/usr/bin/env python3
"""Enforce the branch and line thresholds in an llvm-cov JSON summary."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import NoReturn

MINIMUM_PERCENT = 90.0
CARGO_LLVM_COV_VERSION = "0.9.0"


class CoverageError(ValueError):
    """A malformed or insufficient coverage summary."""


def percentage(totals: dict[str, object], metric: str) -> float:
    """Return one nonempty coverage percentage."""
    value = totals.get(metric)
    if not isinstance(value, dict):
        raise CoverageError(f"coverage summary has no {metric} totals")
    count = value.get("count")
    percent = value.get("percent")
    if not isinstance(count, int) or count <= 0:
        raise CoverageError(f"coverage summary has no measurable {metric}")
    if not isinstance(percent, (int, float)) or not 0.0 <= percent <= 100.0:
        raise CoverageError(f"coverage summary has an invalid {metric} percentage")
    return float(percent)


def validate(path: Path) -> tuple[float, float]:
    """Validate one summary emitted by the pinned cargo-llvm-cov version."""
    try:
        report = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise CoverageError(f"cannot read coverage summary: {error}") from error
    if not isinstance(report, dict):
        raise CoverageError("coverage summary must be a JSON object")
    tool = report.get("cargo_llvm_cov")
    if not isinstance(tool, dict) or tool.get("version") != CARGO_LLVM_COV_VERSION:
        raise CoverageError("coverage summary came from an unpinned cargo-llvm-cov version")
    data = report.get("data")
    if not isinstance(data, list) or len(data) != 1 or not isinstance(data[0], dict):
        raise CoverageError("coverage summary must contain exactly one merged data set")
    totals = data[0].get("totals")
    if not isinstance(totals, dict):
        raise CoverageError("coverage summary has no totals")
    branch_percent = percentage(totals, "branches")
    line_percent = percentage(totals, "lines")
    if branch_percent < MINIMUM_PERCENT:
        raise CoverageError(
            f"branch coverage {branch_percent:.2f}% is below {MINIMUM_PERCENT:.2f}%"
        )
    if line_percent < MINIMUM_PERCENT:
        raise CoverageError(f"line coverage {line_percent:.2f}% is below {MINIMUM_PERCENT:.2f}%")
    return branch_percent, line_percent


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"coverage check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Validate the path supplied by the Stage-00 gate."""
    if len(sys.argv) != 2:
        fail("usage: check-coverage.py <llvm-cov-summary.json>")
    try:
        branch_percent, line_percent = validate(Path(sys.argv[1]))
    except CoverageError as error:
        fail(str(error))
    print(
        f"coverage threshold: ok (branches {branch_percent:.2f}%, lines {line_percent:.2f}%)"
    )


if __name__ == "__main__":
    main()
