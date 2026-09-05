#!/usr/bin/env python3
"""Run the full feature matrix and enforce the final branch floor."""

import os
import runpy
import shutil
import sys
from pathlib import Path

from release_qualification.driver import command, context, finish
from release_qualification.records import QualificationError, canonical, write_once


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    candidate, directory, attempt, target = context(root)
    for name, argv in (
        ("format", ["cargo", "fmt", "--all", "--check"]),
        ("source", ["python3", "scripts/check-source.py", "check"]),
        ("workspace", ["python3", "scripts/check-workspace.py", "check"]),
        ("requirements", ["python3", "scripts/requirements.py", "check"]),
        ("inherited", ["bash", "scripts/check-stage-nine.sh"]),
        ("runner-tests", ["python3", "scripts/test-release-qualification.py"]),
    ):
        command(root, attempt, name, argv, 14400)
    combinations = [[], ["history"], ["wss"], ["history", "wss"]]
    for index, features in enumerate(combinations):
        flags = ["--no-default-features", "--locked"]
        if features:
            flags += ["--features", ",".join(features)]
        for action in ("check", "clippy", "test"):
            argv = ["cargo", action, "--workspace", *flags]
            if action != "test":
                argv += ["--all-targets"]
            if action == "clippy":
                argv += ["--", "-D", "warnings"]
            command(root, attempt, f"matrix-{index}-{action}", argv, 14400)
    report = attempt / "evidence/coverage.json"
    environment = dict(os.environ)
    environment["RUSTC_BOOTSTRAP"] = "1"
    command(root, attempt, "coverage", ["cargo", "llvm-cov", "--workspace", "--all-features", "--branch", "--locked", "--json", "--output-path", str(report)], 14400, environment)
    policy = runpy.run_path(str(root / "scripts/check-coverage.py"))
    branch, line, regions = policy["validate"](root, report, root / "conformance/critical-coverage.toml")
    write_once(attempt / "evidence/coverage-summary.json", canonical({"branch_percent": branch, "line_percent": line, "critical_regions": regions}))
    if branch < 90 or line < 90:
        raise QualificationError(f"release coverage is below 90 percent: branches={branch:.2f}, lines={line:.2f}")
    # A source-bound inventory beyond the inherited Stage 04 ranges is required
    # before this driver can attest that all release-critical branches are covered.
    release_policy = root / "conformance/release-critical-coverage.toml"
    if not release_policy.is_file():
        raise QualificationError("the complete release critical-branch inventory has not been recorded")
    policy["validate"](root, report, release_policy)
    finish(attempt, "workspace", {"feature_combinations": combinations, "branch_percent": branch,
           "line_percent": line, "critical_percent": 100, "critical_categories": sorted(policy["REQUIRED_CATEGORIES"]),
           "critical_inventory_complete": True})


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError) as error:
        print(f"Stage 10 workspace: {error}", file=sys.stderr)
        sys.exit(1)
