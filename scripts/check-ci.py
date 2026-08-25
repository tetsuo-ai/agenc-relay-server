#!/usr/bin/env python3
"""Validate that CI invokes the complete pinned Stage-00 gate."""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

CHECKOUT_COMMIT = "df4cb1c069e1874edd31b4311f1884172cec0e10"
WORKFLOW_PATH = ".github/workflows/ci.yml"
GATE_PATH = "scripts/check-stage-zero.sh"
REQUIRED_WORKFLOW_SNIPPETS = (
    "permissions:\n  contents: read",
    f"uses: actions/checkout@{CHECKOUT_COMMIT}",
    "persist-credentials: false",
    "rustup toolchain install 1.98.0 --profile minimal",
    "cargo +1.98.0 install --locked cargo-deny --version 0.20.2",
    "cargo +1.98.0 install --locked cargo-audit --version 0.22.2",
    "cargo +1.98.0 install --locked cargo-llvm-cov --version 0.9.0",
    "run: bash scripts/check-stage-zero.sh",
)
REQUIRED_GATE_SNIPPETS = (
    "set -euo pipefail",
    "bash scripts/check-spec.sh",
    "python3 scripts/check-baseline.py",
    "python3 scripts/requirements.py check",
    "python3 scripts/requirements.py self-test",
    "python3 scripts/check-workspace.py check",
    "python3 scripts/check-workspace.py self-test",
    "python3 scripts/check-source.py check",
    "python3 scripts/check-source.py self-test",
    "python3 scripts/check-evidence.py check",
    "python3 scripts/check-evidence.py self-test",
    "python3 scripts/check-ci.py check",
    "python3 scripts/check-ci.py self-test",
    "cargo fmt --all --check",
    "cargo check --workspace --all-targets --all-features --locked",
    "--target x86_64-unknown-linux-gnu",
    "--target aarch64-unknown-linux-gnu",
    "cargo clippy --workspace --all-targets --all-features --locked -- -D warnings",
    "cargo test --workspace --all-features --locked",
    "cargo test --workspace --doc --all-features --locked",
    "cargo tree --workspace --all-features --locked",
    "cargo deny check",
    "cargo audit --deny warnings",
    "RUSTC_BOOTSTRAP=1 cargo llvm-cov --workspace --all-features --branch",
    "python3 scripts/check-coverage.py target/stage-zero-coverage.json",
)


class CiError(ValueError):
    """A CI pin, permission, or gate-coverage violation."""


def validate_text(workflow: str, gate: str) -> None:
    """Validate closed workflow and gate requirements."""
    for snippet in REQUIRED_WORKFLOW_SNIPPETS:
        if snippet not in workflow:
            raise CiError(f"workflow is missing required content: {snippet}")
    for snippet in REQUIRED_GATE_SNIPPETS:
        if snippet not in gate:
            raise CiError(f"Stage-00 gate is missing required command: {snippet}")

    action_references = re.findall(r"^\s*uses:\s*([^\s]+)\s*$", workflow, flags=re.MULTILINE)
    if action_references != [f"actions/checkout@{CHECKOUT_COMMIT}"]:
        raise CiError("workflow actions are floating, unexpected, or not in the closed pin set")
    if "pull_request_target:" in workflow:
        raise CiError("pull_request_target is forbidden")
    if re.search(r"^\s*[A-Za-z_-]+:\s*write\s*$", workflow, flags=re.MULTILINE):
        raise CiError("workflow requests write permission")
    if "continue-on-error" in workflow:
        raise CiError("workflow may not weaken a gate with continue-on-error")
    if "RUSTC_BOOTSTRAP" in workflow:
        raise CiError("RUSTC_BOOTSTRAP may not be global workflow state")
    if gate.count("RUSTC_BOOTSTRAP=1") != 1:
        raise CiError("coverage-only RUSTC_BOOTSTRAP scope is missing or widened")


def validate(root: Path) -> None:
    """Validate files, executable modes, and shell syntax."""
    workflow_path = root / WORKFLOW_PATH
    gate_path = root / GATE_PATH
    try:
        workflow = workflow_path.read_text(encoding="utf-8")
        gate = gate_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise CiError(f"cannot read CI source: {error}") from error
    validate_text(workflow, gate)
    scripts = sorted((root / "scripts").glob("check-*.py")) + [gate_path, root / "scripts/requirements.py"]
    for script in scripts:
        if not os.access(script, os.X_OK):
            raise CiError(f"validation script is not executable: {script.relative_to(root)}")
    completed = subprocess.run(
        ["bash", "-n", str(gate_path)], capture_output=True, check=False, text=True
    )
    if completed.returncode != 0:
        raise CiError(f"Stage-00 gate has invalid shell syntax: {completed.stderr.strip()}")


def expect_rejection(label: str, workflow: str, gate: str, fragment: str) -> None:
    """Require one seeded CI mutation to reach its intended rejection branch."""
    try:
        validate_text(workflow, gate)
    except CiError as error:
        if fragment not in str(error):
            raise CiError(f"self-test {label!r} reached the wrong branch: {error}") from error
        return
    raise CiError(f"self-test {label!r} was accepted")


def self_test(root: Path) -> int:
    """Exercise pin, permission, gate, and environment rejection paths."""
    workflow = (root / WORKFLOW_PATH).read_text(encoding="utf-8")
    gate = (root / GATE_PATH).read_text(encoding="utf-8")
    validate_text(workflow, gate)
    cases = 0

    floating = workflow.replace(
        f"actions/checkout@{CHECKOUT_COMMIT}", "actions/checkout@v6", 1
    )
    expect_rejection("floating action", floating, gate, "missing required content")
    cases += 1

    writable = workflow.replace("contents: read", "contents: write", 1)
    expect_rejection("write permission", writable, gate, "missing required content")
    cases += 1

    weakened = workflow.replace(
        "run: bash scripts/check-stage-zero.sh",
        "continue-on-error: true\n        run: bash scripts/check-stage-zero.sh",
        1,
    )
    expect_rejection("continue on error", weakened, gate, "continue-on-error")
    cases += 1

    missing_gate = gate.replace("cargo audit --deny warnings", "cargo audit", 1)
    expect_rejection("missing audit policy", workflow, missing_gate, "missing required command")
    cases += 1

    widened_bootstrap = workflow.replace(
        "CARGO_INCREMENTAL: \"0\"", 'CARGO_INCREMENTAL: "0"\n      RUSTC_BOOTSTRAP: "1"', 1
    )
    expect_rejection("global bootstrap", widened_bootstrap, gate, "global workflow state")
    cases += 1
    return cases


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"CI validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch the CI check and seeded negative tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "check":
            validate(root)
            print("CI policy: ok")
        else:
            cases = self_test(root)
            print(f"CI policy self-test: ok ({cases} rejection cases)")
    except (CiError, OSError, UnicodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
