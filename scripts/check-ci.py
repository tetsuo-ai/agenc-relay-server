#!/usr/bin/env python3
"""Validate CI pins and the structured conformance-gate manifest."""

from __future__ import annotations

import argparse
import copy
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

CHECKOUT_COMMIT = "df4cb1c069e1874edd31b4311f1884172cec0e10"
WORKFLOW_PATH = ".github/workflows/ci.yml"
GATE_PATHS = ("scripts/check-stage-zero.sh", "scripts/check-stage-one.sh")
MANIFEST_PATH = "conformance/gates.toml"
REQUIRED_WORKFLOW_SNIPPETS = (
    "permissions:\n  contents: read",
    f"uses: actions/checkout@{CHECKOUT_COMMIT}",
    "persist-credentials: false",
    "rustup toolchain install 1.98.0 --profile minimal",
    "cargo +1.98.0 install --locked cargo-deny --version 0.20.2",
    "cargo +1.98.0 install --locked cargo-audit --version 0.22.2",
    "cargo +1.98.0 install --locked cargo-llvm-cov --version 0.9.0",
    "run: bash scripts/check-stage-one.sh",
)
REQUIRED_STAGE_ZERO = (
    ("bash", "scripts/check-spec.sh"),
    ("python3", "scripts/check-baseline.py"),
    ("python3", "scripts/requirements.py", "check"),
    ("python3", "scripts/requirements.py", "check-stage-zero"),
    ("python3", "scripts/requirements.py", "self-test"),
    ("python3", "scripts/check-workspace.py", "check"),
    ("python3", "scripts/check-workspace.py", "self-test"),
    ("python3", "scripts/check-source.py", "check"),
    ("python3", "scripts/check-source.py", "self-test"),
    ("python3", "scripts/check-evidence.py", "check"),
    ("python3", "scripts/check-evidence.py", "self-test"),
    ("python3", "scripts/check-ci.py", "check"),
    ("python3", "scripts/check-ci.py", "self-test"),
    ("cargo", "fmt", "--all", "--check"),
    ("cargo", "check", "--workspace", "--all-targets", "--all-features", "--locked"),
    (
        "cargo", "check", "--workspace", "--all-targets", "--all-features", "--locked",
        "--target", "x86_64-unknown-linux-gnu",
    ),
    (
        "cargo", "check", "--workspace", "--all-targets", "--all-features", "--locked",
        "--target", "aarch64-unknown-linux-gnu",
    ),
    (
        "cargo", "clippy", "--workspace", "--all-targets", "--all-features", "--locked",
        "--", "-D", "warnings",
    ),
    ("cargo", "test", "--workspace", "--all-features", "--locked"),
    ("cargo", "test", "--workspace", "--doc", "--all-features", "--locked"),
    ("cargo", "tree", "--workspace", "--all-features", "--locked"),
    ("cargo", "deny", "check"),
    ("cargo", "audit", "--deny", "warnings"),
    (
        "cargo", "llvm-cov", "--workspace", "--all-features", "--branch", "--json",
        "--summary-only", "--output-path", "target/stage-zero-coverage.json",
    ),
    ("python3", "scripts/check-coverage.py", "target/stage-zero-coverage.json"),
)
REQUIRED_STAGE_ONE = (
    ("python3", "scripts/requirements.py", "check-stage-one"),
    ("python3", "scripts/check-stage-one.py", "check"),
    ("python3", "scripts/check-stage-one.py", "self-test"),
)


class CiError(ValueError):
    """A CI pin, permission, or gate-coverage violation."""


def validate_workflow(workflow: str) -> None:
    """Validate the workflow's exact external pins and permissions."""
    for snippet in REQUIRED_WORKFLOW_SNIPPETS:
        if snippet not in workflow:
            raise CiError(f"workflow is missing required content: {snippet}")
    actions = re.findall(r"^\s*uses:\s*([^\s]+)\s*$", workflow, flags=re.MULTILINE)
    if actions != [f"actions/checkout@{CHECKOUT_COMMIT}"]:
        raise CiError("workflow actions are floating, unexpected, or not in the closed pin set")
    if "pull_request_target:" in workflow:
        raise CiError("pull_request_target is forbidden")
    if re.search(r"^\s*[A-Za-z_-]+:\s*write\s*$", workflow, flags=re.MULTILINE):
        raise CiError("workflow requests write permission")
    if "continue-on-error" in workflow:
        raise CiError("workflow may not weaken a gate with continue-on-error")
    if "RUSTC_BOOTSTRAP" in workflow:
        raise CiError("RUSTC_BOOTSTRAP may not be global workflow state")


def validate_manifest(manifest: dict[str, object]) -> None:
    """Validate exact argv arrays instead of accepting textual command hints."""
    if set(manifest) != {"schema_version", "gate"} or manifest.get("schema_version") != 1:
        raise CiError("gate manifest has an invalid top-level schema")
    gates = manifest.get("gate")
    if not isinstance(gates, dict) or set(gates) != {"stage-zero", "stage-one"}:
        raise CiError("gate manifest must define exactly stage-zero and stage-one")
    stage_zero = gates.get("stage-zero")
    stage_one = gates.get("stage-one")
    if not isinstance(stage_zero, dict) or set(stage_zero) != {"command"}:
        raise CiError("stage-zero gate has invalid fields")
    if not isinstance(stage_one, dict) or set(stage_one) != {"includes", "command"}:
        raise CiError("stage-one gate has invalid fields")
    if stage_one.get("includes") != ["stage-zero"]:
        raise CiError("stage-one must include the exact stage-zero gate")
    commands = stage_zero.get("command")
    if not isinstance(commands, list):
        raise CiError("stage-zero commands must be an array")
    actual: list[tuple[str, ...]] = []
    bootstrap_count = 0
    for index, command in enumerate(commands):
        if not isinstance(command, dict) or set(command) - {"argv", "environment"}:
            raise CiError(f"stage-zero command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-zero command {index} has invalid argv")
        actual.append(tuple(argv))
        environment = command.get("environment", {})
        if environment:
            bootstrap_count += 1
            if environment != {"RUSTC_BOOTSTRAP": "1"} or "llvm-cov" not in argv:
                raise CiError("RUSTC_BOOTSTRAP is not scoped only to coverage")
    if tuple(actual) != REQUIRED_STAGE_ZERO:
        raise CiError("stage-zero argv sequence differs from the reviewed closed gate")
    if bootstrap_count != 1:
        raise CiError("coverage-only RUSTC_BOOTSTRAP scope is missing or duplicated")
    stage_one_commands = stage_one.get("command")
    if not isinstance(stage_one_commands, list):
        raise CiError("stage-one commands must be an array")
    stage_one_actual = []
    for index, command in enumerate(stage_one_commands):
        if not isinstance(command, dict) or set(command) != {"argv"}:
            raise CiError(f"stage-one command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-one command {index} has invalid argv")
        stage_one_actual.append(tuple(argv))
    if tuple(stage_one_actual) != REQUIRED_STAGE_ONE:
        raise CiError("stage-one command sequence differs from the reviewed gate")


def load_manifest_text(text: str) -> dict[str, object]:
    """Parse one TOML fixture with a stable error."""
    try:
        return tomllib.loads(text)
    except tomllib.TOMLDecodeError as error:
        raise CiError(f"gate manifest is invalid TOML: {error}") from error


def validate(root: Path) -> None:
    """Validate workflow, gate manifest, executable modes, and shell syntax."""
    workflow = (root / WORKFLOW_PATH).read_text(encoding="utf-8")
    validate_workflow(workflow)
    validate_manifest(load_manifest_text((root / MANIFEST_PATH).read_text(encoding="utf-8")))
    scripts = sorted((root / "scripts").glob("check-*.py"))
    gate_paths = [root / relative for relative in GATE_PATHS]
    scripts.extend(gate_paths)
    scripts.extend([root / "scripts/requirements.py", root / "scripts/run-gate.py"])
    for script in scripts:
        if not os.access(script, os.X_OK):
            raise CiError(f"validation script is not executable: {script.relative_to(root)}")
    for gate_path in gate_paths:
        completed = subprocess.run(
            ["bash", "-n", str(gate_path)], capture_output=True, check=False, text=True
        )
        if completed.returncode != 0:
            raise CiError(
                f"gate has invalid shell syntax: {gate_path.name}: {completed.stderr.strip()}"
            )


def expect_rejection(label: str, action: object, fragment: str) -> None:
    """Require one seeded mutation to reach its intended rejection branch."""
    if not callable(action):
        raise CiError(f"self-test {label!r} is not callable")
    try:
        action()
    except CiError as error:
        if fragment not in str(error):
            raise CiError(f"self-test {label!r} reached the wrong branch: {error}") from error
        return
    raise CiError(f"self-test {label!r} was accepted")


def self_test(root: Path) -> int:
    """Exercise workflow and structured-command rejection paths."""
    workflow = (root / WORKFLOW_PATH).read_text(encoding="utf-8")
    manifest = load_manifest_text((root / MANIFEST_PATH).read_text(encoding="utf-8"))
    validate_workflow(workflow)
    validate_manifest(manifest)
    cases = 0
    floating = workflow.replace(f"actions/checkout@{CHECKOUT_COMMIT}", "actions/checkout@v6", 1)
    expect_rejection("floating action", lambda: validate_workflow(floating), "missing required")
    cases += 1
    writable = workflow.replace("contents: read", "contents: write", 1)
    expect_rejection("write permission", lambda: validate_workflow(writable), "missing required")
    cases += 1
    weakened = workflow.replace("run: bash scripts/check-stage-one.sh", "continue-on-error: true\n        run: bash scripts/check-stage-one.sh", 1)
    expect_rejection("continue on error", lambda: validate_workflow(weakened), "continue-on-error")
    cases += 1
    dead_text = copy.deepcopy(manifest)
    dead_text["gate"]["stage-zero"]["command"][22]["argv"] = ["true", "cargo audit --deny warnings"]
    expect_rejection("dead command text", lambda: validate_manifest(dead_text), "argv sequence")
    cases += 1
    widened = copy.deepcopy(manifest)
    widened["gate"]["stage-zero"]["command"][0]["environment"] = {"RUSTC_BOOTSTRAP": "1"}
    expect_rejection("widened bootstrap", lambda: validate_manifest(widened), "not scoped")
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
