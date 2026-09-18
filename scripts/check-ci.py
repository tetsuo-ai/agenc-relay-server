#!/usr/bin/env python3
"""Validate CI pins and the structured conformance-gate manifest."""

from __future__ import annotations

import argparse
import copy
import os
import re
import runpy
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path
from typing import NoReturn
from unittest import mock

CHECKOUT_COMMIT = "df4cb1c069e1874edd31b4311f1884172cec0e10"
WORKFLOW_PATH = ".github/workflows/ci.yml"
GATE_PATHS = (
    "scripts/check-stage-zero.sh",
    "scripts/check-stage-one.sh",
    "scripts/check-stage-two.sh",
    "scripts/check-stage-three.sh",
    "scripts/check-stage-four.sh",
    "scripts/check-stage-five.sh",
    "scripts/check-stage-six.sh",
    "scripts/check-stage-seven.sh",
    "scripts/check-stage-eight.sh",
    "scripts/check-stage-nine.sh",
)
MANIFEST_PATH = "conformance/gates.toml"
REQUIRED_WORKFLOW_SNIPPETS = (
    "permissions:\n  contents: read",
    f"uses: actions/checkout@{CHECKOUT_COMMIT}",
    "persist-credentials: false",
    "fetch-depth: 0",
    "rustup toolchain install 1.98.0 --profile minimal",
    "rustup toolchain install nightly-2026-08-24 --profile minimal",
    "rustup component add --toolchain nightly-2026-08-24 rustfmt",
    "cargo +1.98.0 install --locked cargo-deny --version 0.20.2",
    "cargo +1.98.0 install --locked cargo-audit --version 0.22.2",
    "cargo +1.98.0 install --locked cargo-llvm-cov --version 0.9.0",
    "cargo +1.98.0 install --locked cargo-nextest --version 0.9.145",
    "cargo +1.98.0 install --locked cargo-fuzz --version 0.13.2",
    "sudo apt-get install --no-install-recommends gcc-aarch64-linux-gnu libc6-dev-arm64-cross tor",
    "sudo rm -rf /usr/share/dotnet /usr/local/lib/android /opt/ghc /usr/local/.ghcup /opt/hostedtoolcache/CodeQL",
)
REQUIRED_GATE_STEP = (
    "      - name: Run Stage 09 implementation checks\n"
    "        run: bash scripts/check-stage-nine.sh"
)
REQUIRED_CHECKOUT_STEP = (
    "      - name: Check out the exact source revision\n"
    f"        uses: actions/checkout@{CHECKOUT_COMMIT}\n"
    "        with:\n"
    "          persist-credentials: false\n"
    "          fetch-depth: 0"
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
    ("python3", "scripts/check-rust-components.py", "self-test"),
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
    ("cargo", "nextest", "run", "--workspace", "--all-features", "--locked"),
    ("cargo", "test", "--workspace", "--doc", "--all-features", "--locked"),
    ("cargo", "tree", "--workspace", "--all-features", "--locked"),
    ("cargo", "deny", "check"),
    ("cargo", "audit", "--deny", "warnings"),
    (
        "python3", "scripts/check-coverage.py", "self-test",
        "conformance/critical-coverage.toml",
    ),
    (
        "cargo", "llvm-cov", "nextest", "--workspace", "--all-features", "--branch", "--locked",
        "--json", "--output-path", "target/stage-zero-coverage.json",
    ),
    (
        "python3", "scripts/check-coverage.py", "check",
        "target/stage-zero-coverage.json", "conformance/critical-coverage.toml",
    ),
)
REQUIRED_STAGE_ONE = (
    ("python3", "scripts/requirements.py", "check-stage-one"),
    ("python3", "scripts/check-stage-one.py", "check"),
    ("python3", "scripts/check-stage-one.py", "self-test"),
)
REQUIRED_STAGE_TWO = (
    ("python3", "scripts/requirements.py", "check-stage-two"),
    ("python3", "scripts/generate-stage-two.py", "--check"),
    ("python3", "scripts/check-stage-two.py", "check"),
    ("python3", "scripts/check-stage-two.py", "self-test"),
    (
        "cargo", "+nightly-2026-08-24", "fmt", "--manifest-path",
        "fuzz/Cargo.toml", "--", "--check",
    ),
    (
        "cargo", "+nightly-2026-08-24", "check", "--manifest-path",
        "fuzz/Cargo.toml", "--bins", "--locked",
    ),
    ("cargo", "deny", "--manifest-path", "fuzz/Cargo.toml", "check"),
    ("bash", "scripts/run-stage-two-fuzz.sh"),
)
REQUIRED_STAGE_THREE = (
    ("python3", "scripts/requirements.py", "check-stage-three"),
    ("python3", "scripts/generate-stage-three.py", "--check"),
    ("python3", "scripts/check-stage-three.py", "check"),
    ("python3", "scripts/check-stage-three.py", "self-test"),
    (
        "cargo", "nextest", "run", "-p", "agenc-ircd-testkit",
        "--test", "domain_channels",
        "--test", "domain_commands",
        "--test", "domain_lifecycle",
        "--test", "domain_reference_model",
        "--test", "domain_stage_three_matrix",
        "--locked",
    ),
)
REQUIRED_STAGE_FOUR = (
    ("python3", "scripts/requirements.py", "check-stage-four"),
    ("python3", "scripts/check-stage-four.py", "check"),
    ("python3", "scripts/check-stage-four.py", "self-test"),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-auth", "--test", "stage_four", "--locked"),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-crypto", "--test", "stage_four", "--locked"),
    (
        "cargo", "nextest", "run", "-p", "agenc-ircd-testkit",
        "--test", "stage_four_domain_auth", "--locked",
    ),
    ("bash", "scripts/run-stage-four-fuzz.sh"),
)
REQUIRED_STAGE_FIVE = (
    ("python3", "scripts/requirements.py", "check-stage-five"),
    ("python3", "scripts/check-stage-five.py", "check"),
    ("python3", "scripts/check-stage-five.py", "self-test"),
    (
        "cargo", "nextest", "run", "-p", "agenc-ircd-storage", "--all-features", "--locked",
    ),
    (
        "cargo", "+nightly-2026-08-24", "fmt", "--manifest-path",
        "fuzz/Cargo.toml", "--", "--check",
    ),
    (
        "cargo", "+nightly-2026-08-24", "check", "--manifest-path",
        "fuzz/Cargo.toml", "--bins", "--locked",
    ),
    ("cargo", "deny", "--manifest-path", "fuzz/Cargo.toml", "check"),
    ("bash", "scripts/run-stage-five-fuzz.sh"),
)
REQUIRED_STAGE_SIX = (
    ("python3", "scripts/requirements.py", "check-stage-six"),
    ("python3", "scripts/check-stage-six.py", "check"),
    ("python3", "scripts/check-stage-six.py", "self-test"),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-config", "--all-features", "--locked"),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-admin", "--all-features", "--locked"),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-runtime", "--all-features", "--locked"),
    (
        "cargo", "nextest", "run", "-p", "agenc-ircd-testkit",
        "--test", "stage_six_persistence", "--locked",
    ),
    ("bash", "scripts/run-stage-six-loom.sh"),
    ("bash", "scripts/run-stage-six-transcripts.sh"),
    ("bash", "scripts/run-stage-six-soak.sh"),
    ("python3", "scripts/check-deploy.py", "check"),
    ("python3", "scripts/check-deploy.py", "self-test"),
    ("bash", "scripts/qualify-stage-six.sh"),
    (
        "cargo", "+nightly-2026-08-24", "fmt", "--manifest-path",
        "fuzz/Cargo.toml", "--", "--check",
    ),
    (
        "cargo", "+nightly-2026-08-24", "check", "--manifest-path",
        "fuzz/Cargo.toml", "--bins", "--locked",
    ),
    ("cargo", "deny", "--manifest-path", "fuzz/Cargo.toml", "check"),
    ("bash", "scripts/run-stage-six-fuzz.sh"),
)
REQUIRED_STAGE_SEVEN = (
    ("python3", "scripts/requirements.py", "check-stage-seven"),
    ("python3", "scripts/check-stage-seven.py", "check"),
    ("python3", "scripts/check-stage-seven.py", "self-test"),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-federation-wire", "--all-features", "--locked"),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-domain", "--all-features", "--locked"),
    (
        "cargo", "nextest", "run", "-p", "agenc-ircd-storage",
        "--test", "stage_five", "--locked", "federation_records",
    ),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-crypto", "--all-features", "--locked"),
    ("bash", "scripts/run-stage-seven-model.sh"),
    ("bash", "scripts/run-stage-seven-transcripts.sh"),
    ("bash", "scripts/run-stage-seven-fuzz.sh"),
)
REQUIRED_STAGE_EIGHT = (
    ("python3", "scripts/requirements.py", "check-stage-eight"),
    ("python3", "scripts/check-stage-eight.py", "check"),
    ("python3", "scripts/check-stage-eight.py", "self-test"),
    ("python3", "scripts/generate-e2ee-wire-budget.py", "--check"),
    ("python3", "scripts/generate-e2ee-vectors.py", "--check"),
    ("python3", "scripts/generate-e2ee-fuzz-seeds.py", "--check"),
    ("cargo", "nextest", "run", "-p", "agenc-ircd-e2ee", "--all-features", "--locked"),
    (
        "cargo", "nextest", "run", "-p", "agenc-ircd-storage",
        "--test", "stage_five", "--locked", "e2ee_records",
    ),
    ("bash", "scripts/run-stage-eight-model.sh"),
    ("bash", "scripts/run-stage-eight-transcripts.sh"),
    ("bash", "scripts/run-stage-eight-fuzz.sh"),
    ("bash", "scripts/run-stage-eight-load.sh"),
)


class CiError(ValueError):
    """A CI pin, permission, or gate-coverage violation."""


def live_workflow_text(workflow: str) -> str:
    """Remove full-line YAML comments before checking reviewed statements."""
    return "\n".join(
        line for line in workflow.splitlines() if not line.lstrip().startswith("#")
    )


def validate_workflow(workflow: str) -> None:
    """Validate the workflow's exact external pins and permissions."""
    live_workflow = live_workflow_text(workflow)
    for snippet in REQUIRED_WORKFLOW_SNIPPETS:
        if snippet not in live_workflow:
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
    if re.search(r"^\s*if\s*:", workflow, flags=re.MULTILINE):
        raise CiError("workflow may not conditionally skip a reviewed step")
    if live_workflow.count(REQUIRED_CHECKOUT_STEP) != 1:
        raise CiError("workflow must contain one exact live checkout step")
    if live_workflow.count(REQUIRED_GATE_STEP) != 1:
        raise CiError("workflow must contain one live Stage 09 implementation-check step")


def validate_manifest(manifest: dict[str, object]) -> None:
    """Validate exact argv arrays instead of accepting textual command hints."""
    schema_version = manifest.get("schema_version")
    if (
        set(manifest) != {"schema_version", "gate"}
        or type(schema_version) is not int
        or schema_version != 1
    ):
        raise CiError("gate manifest has an invalid top-level schema")
    gates = manifest.get("gate")
    if not isinstance(gates, dict) or set(gates) != {
        "stage-zero-implementation",
        "stage-one-implementation",
        "stage-two-implementation",
        "stage-three-implementation",
        "stage-four-implementation",
        "stage-five-implementation",
        "stage-six-implementation",
        "stage-seven-implementation",
        "stage-eight-implementation",
        "stage-nine-implementation",
    }:
        raise CiError(
            "gate manifest must define Stage 00 through Stage 09 implementation checks"
        )
    stage_zero = gates.get("stage-zero-implementation")
    stage_one = gates.get("stage-one-implementation")
    stage_two = gates.get("stage-two-implementation")
    stage_three = gates.get("stage-three-implementation")
    stage_four = gates.get("stage-four-implementation")
    stage_five = gates.get("stage-five-implementation")
    stage_six = gates.get("stage-six-implementation")
    stage_seven = gates.get("stage-seven-implementation")
    stage_eight = gates.get("stage-eight-implementation")
    stage_nine = gates.get("stage-nine-implementation")
    if not isinstance(stage_zero, dict) or set(stage_zero) != {"command"}:
        raise CiError("stage-zero implementation checks have invalid fields")
    if not isinstance(stage_one, dict) or set(stage_one) != {"includes", "command"}:
        raise CiError("stage-one implementation checks have invalid fields")
    if stage_one.get("includes") != ["stage-zero-implementation"]:
        raise CiError("stage-one implementation checks must include stage-zero checks")
    if not isinstance(stage_two, dict) or set(stage_two) != {"includes", "command"}:
        raise CiError("stage-two implementation checks have invalid fields")
    if stage_two.get("includes") != ["stage-one-implementation"]:
        raise CiError("stage-two implementation checks must include stage-one checks")
    if not isinstance(stage_three, dict) or set(stage_three) != {"includes", "command"}:
        raise CiError("stage-three implementation checks have invalid fields")
    if stage_three.get("includes") != ["stage-two-implementation"]:
        raise CiError("stage-three implementation checks must include stage-two checks")
    if not isinstance(stage_four, dict) or set(stage_four) != {"includes", "command"}:
        raise CiError("stage-four implementation checks have invalid fields")
    if stage_four.get("includes") != ["stage-three-implementation"]:
        raise CiError("stage-four implementation checks must include stage-three checks")
    if not isinstance(stage_five, dict) or set(stage_five) != {"includes", "command"}:
        raise CiError("stage-five implementation checks have invalid fields")
    if stage_five.get("includes") != ["stage-four-implementation"]:
        raise CiError("stage-five implementation checks must include stage-four checks")
    if not isinstance(stage_six, dict) or set(stage_six) != {"includes", "command"}:
        raise CiError("stage-six implementation checks have invalid fields")
    if stage_six.get("includes") != ["stage-five-implementation"]:
        raise CiError("stage-six implementation checks must include stage-five checks")
    if not isinstance(stage_seven, dict) or set(stage_seven) != {"includes", "command"}:
        raise CiError("stage-seven implementation checks have invalid fields")
    if stage_seven.get("includes") != ["stage-six-implementation"]:
        raise CiError("stage-seven implementation checks must include stage-six checks")
    if not isinstance(stage_eight, dict) or set(stage_eight) != {"includes", "command"}:
        raise CiError("stage-eight implementation checks have invalid fields")
    if stage_eight.get("includes") != ["stage-seven-implementation"]:
        raise CiError("stage-eight implementation checks must include stage-seven checks")
    validate_stage_nine(stage_nine)
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
        raise CiError("stage-zero argv sequence differs from the reviewed implementation checks")
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
        raise CiError("stage-one command sequence differs from the reviewed implementation checks")
    stage_two_commands = stage_two.get("command")
    if not isinstance(stage_two_commands, list):
        raise CiError("stage-two commands must be an array")
    stage_two_actual = []
    for index, command in enumerate(stage_two_commands):
        if not isinstance(command, dict) or set(command) != {"argv"}:
            raise CiError(f"stage-two command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-two command {index} has invalid argv")
        stage_two_actual.append(tuple(argv))
    if tuple(stage_two_actual) != REQUIRED_STAGE_TWO:
        raise CiError("stage-two command sequence differs from the reviewed implementation checks")
    stage_three_commands = stage_three.get("command")
    if not isinstance(stage_three_commands, list):
        raise CiError("stage-three commands must be an array")
    stage_three_actual = []
    for index, command in enumerate(stage_three_commands):
        if not isinstance(command, dict) or set(command) != {"argv"}:
            raise CiError(f"stage-three command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-three command {index} has invalid argv")
        stage_three_actual.append(tuple(argv))
    if tuple(stage_three_actual) != REQUIRED_STAGE_THREE:
        raise CiError("stage-three command sequence differs from the reviewed implementation checks")
    stage_four_commands = stage_four.get("command")
    if not isinstance(stage_four_commands, list):
        raise CiError("stage-four implementation commands must be an array")
    stage_four_actual = []
    for index, command in enumerate(stage_four_commands):
        if not isinstance(command, dict) or set(command) != {"argv"}:
            raise CiError(f"stage-four implementation command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-four implementation command {index} has invalid argv")
        stage_four_actual.append(tuple(argv))
    if tuple(stage_four_actual) != REQUIRED_STAGE_FOUR:
        raise CiError("stage-four implementation command sequence differs from the reviewed checks")
    stage_five_commands = stage_five.get("command")
    if not isinstance(stage_five_commands, list):
        raise CiError("stage-five implementation commands must be an array")
    stage_five_actual = []
    for index, command in enumerate(stage_five_commands):
        if not isinstance(command, dict) or set(command) != {"argv"}:
            raise CiError(f"stage-five implementation command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-five implementation command {index} has invalid argv")
        stage_five_actual.append(tuple(argv))
    if tuple(stage_five_actual) != REQUIRED_STAGE_FIVE:
        raise CiError("stage-five implementation command sequence differs from the reviewed checks")
    stage_six_commands = stage_six.get("command")
    if not isinstance(stage_six_commands, list):
        raise CiError("stage-six implementation commands must be an array")
    stage_six_actual = []
    for index, command in enumerate(stage_six_commands):
        if not isinstance(command, dict) or set(command) != {"argv"}:
            raise CiError(f"stage-six implementation command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-six implementation command {index} has invalid argv")
        stage_six_actual.append(tuple(argv))
    if tuple(stage_six_actual) != REQUIRED_STAGE_SIX:
        raise CiError("stage-six implementation command sequence differs from the reviewed checks")
    stage_seven_commands = stage_seven.get("command")
    if not isinstance(stage_seven_commands, list):
        raise CiError("stage-seven implementation commands must be an array")
    stage_seven_actual = []
    for index, command in enumerate(stage_seven_commands):
        if not isinstance(command, dict) or set(command) != {"argv"}:
            raise CiError(f"stage-seven implementation command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-seven implementation command {index} has invalid argv")
        stage_seven_actual.append(tuple(argv))
    if tuple(stage_seven_actual) != REQUIRED_STAGE_SEVEN:
        raise CiError("stage-seven implementation command sequence differs from the reviewed checks")
    stage_eight_commands = stage_eight.get("command")
    if not isinstance(stage_eight_commands, list):
        raise CiError("stage-eight implementation commands must be an array")
    stage_eight_actual = []
    for index, command in enumerate(stage_eight_commands):
        if not isinstance(command, dict) or set(command) != {"argv"}:
            raise CiError(f"stage-eight implementation command {index} has invalid fields")
        argv = command.get("argv")
        if not isinstance(argv, list) or any(not isinstance(item, str) for item in argv):
            raise CiError(f"stage-eight implementation command {index} has invalid argv")
        stage_eight_actual.append(tuple(argv))
    if tuple(stage_eight_actual) != REQUIRED_STAGE_EIGHT:
        raise CiError("stage-eight implementation command sequence differs from the reviewed checks")


REQUIRED_STAGE_NINE = (
    ("python3", "scripts/requirements.py", "check-stage-nine"),
    ("python3", "scripts/check-stage-nine.py", "check"),
    ("python3", "scripts/check-stage-nine.py", "self-test"),
    ("bash", "scripts/check-stage-nine-matrix.sh"),
    ("bash", "scripts/run-stage-nine-fuzz.sh"),
    ("bash", "scripts/run-stage-nine-history-fuzz.sh"),
)


def validate_stage_nine(stage: object) -> None:
    if not isinstance(stage, dict) or set(stage) != {"includes", "command"}:
        raise CiError("stage-nine implementation checks have invalid fields")
    if stage["includes"] != ["stage-eight-implementation"]:
        raise CiError("stage-nine must include every inherited stage-eight check")
    commands = stage["command"]
    if not isinstance(commands, list) or any(not isinstance(item, dict) or set(item) != {"argv"} for item in commands):
        raise CiError("stage-nine commands must contain only argv")
    if [item["argv"] for item in commands] != [list(argv) for argv in REQUIRED_STAGE_NINE]:
        raise CiError("stage-nine command sequence differs from the reviewed checks")


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
    scripts.extend(
        [
            root / "scripts/generate-gate-evidence.py",
            root / "scripts/requirements.py",
            root / "scripts/run-gate.py",
        ]
    )
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
    boolean_schema = copy.deepcopy(manifest)
    boolean_schema["schema_version"] = True
    expect_rejection(
        "boolean manifest schema",
        lambda: validate_manifest(boolean_schema),
        "invalid top-level schema",
    )
    cases += 1
    floating = workflow.replace(f"actions/checkout@{CHECKOUT_COMMIT}", "actions/checkout@v6", 1)
    expect_rejection("floating action", lambda: validate_workflow(floating), "missing required")
    cases += 1
    writable = workflow.replace("contents: read", "contents: write", 1)
    expect_rejection("write permission", lambda: validate_workflow(writable), "missing required")
    cases += 1
    weakened = workflow.replace("run: bash scripts/check-stage-nine.sh", "continue-on-error: true\n        run: bash scripts/check-stage-nine.sh", 1)
    expect_rejection("continue on error", lambda: validate_workflow(weakened), "continue-on-error")
    cases += 1
    commented = workflow.replace(
        "        run: bash scripts/check-stage-nine.sh",
        "        # run: bash scripts/check-stage-nine.sh",
        1,
    )
    expect_rejection(
        "commented gate",
        lambda: validate_workflow(commented),
        "one live Stage 09 implementation-check step",
    )
    cases += 1
    commented_checkout = workflow.replace(
        f"        uses: actions/checkout@{CHECKOUT_COMMIT}",
        f"        # uses: actions/checkout@{CHECKOUT_COMMIT}",
        1,
    )
    expect_rejection(
        "commented checkout",
        lambda: validate_workflow(commented_checkout),
        "missing required content",
    )
    cases += 1
    conditional = workflow.replace(
        "        run: bash scripts/check-stage-nine.sh",
        "        if: false\n        run: bash scripts/check-stage-nine.sh",
        1,
    )
    expect_rejection(
        "conditional gate", lambda: validate_workflow(conditional), "conditionally skip"
    )
    cases += 1
    dead_text = copy.deepcopy(manifest)
    dead_text["gate"]["stage-zero-implementation"]["command"][22]["argv"] = [
        "true",
        "cargo audit --deny warnings",
    ]
    expect_rejection("dead command text", lambda: validate_manifest(dead_text), "argv sequence")
    cases += 1
    widened = copy.deepcopy(manifest)
    widened["gate"]["stage-zero-implementation"]["command"][0]["environment"] = {
        "RUSTC_BOOTSTRAP": "1"
    }
    expect_rejection("widened bootstrap", lambda: validate_manifest(widened), "not scoped")
    cases += 1

    runner = runpy.run_path(str(root / "scripts/run-gate.py"))
    environment_builder = runner.get("command_environment")
    if not callable(environment_builder):
        raise CiError("gate runner does not expose reviewed environment construction")
    inherited = {
        "AGENC_IRCD_RECORD_GATE": "1",
        "AGENC_STAGE3_SEED": "1",
        "AGENC_STAGE3_STEPS": "1",
        "BASH_ENV": "/tmp/unreviewed-shell-environment",
        "BASHOPTS": "xpg_echo",
        "BASH_FUNC_cargo%%": "() { printf injected; }",
        "CARGO_ENCODED_RUSTDOCFLAGS": "--test-args\u001f--skip\u001fall",
        "GIT_COMMON_DIR": "/tmp/unreviewed-common-directory",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "GIT_CONFIG_PARAMETERS": "'core.useReplaceRefs'='true'",
        "GIT_EXEC_PATH": "/tmp/unreviewed-git-exec-path",
        "GIT_FUTURE_OVERRIDE": "unreviewed-future-state",
        "GIT_GRAFT_FILE": "/tmp/unreviewed-grafts",
        "GIT_NAMESPACE": "unreviewed-namespace",
        "GIT_NO_REPLACE_OBJECTS": "0",
        "GIT_REPLACE_REF_BASE": "refs/unreviewed/replace/",
        "LD_PRELOAD": "/tmp/unreviewed-library.so",
        "LD_AUDIT": "/tmp/unreviewed-audit-library.so",
        "PATH": "/usr/bin",
        "PYTHONPATH": "/tmp/unreviewed-python-path",
        "CARGO_PROFILE_RELEASE_PANIC": "abort",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "-C target-feature=+crt-static",
        "CARGO_LLVM_COV_FLAGS": "--ignore-filename-regex=.*",
        "CLIPPY_CONF_DIR": "/tmp/unreviewed-clippy-config",
        "LLVM_COV": "/tmp/unreviewed-llvm-cov",
        "LLVM_PROFDATA": "/tmp/unreviewed-llvm-profdata",
        "CC": "/tmp/unreviewed-cc",
        "CC_x86_64_unknown_linux_gnu": "/tmp/unreviewed-target-cc",
        "CXX": "/tmp/unreviewed-cxx",
        "AR": "/tmp/unreviewed-ar",
        "ASAN_OPTIONS": "detect_leaks=0",
        "CUSTOM_LIBFUZZER_PATH": "/tmp/unreviewed-libfuzzer.a",
        "CUSTOM_LIBFUZZER_STD_CXX": "none",
        "RUSTC_BOOTSTRAP": "1",
        "RUSTC_STAGE": "2",
        "RUSTFMT": "/tmp/unreviewed-rustfmt",
        "RUST_LIBFUZZER_DEBUG_PATH": "/tmp/unreviewed-libfuzzer-debug",
        "RUST_LIBC_UNSTABLE_GNU_TIME_BITS": "64",
        "RUSTFLAGS": "-Zallow-features=all",
        "RUSTUP_TOOLCHAIN": "nightly",
        "SHELLOPTS": "xtrace",
    }
    clean_environment = environment_builder(inherited, {})
    if clean_environment != {
        "CARGO_INCREMENTAL": "0",
        "PATH": "/usr/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }:
        raise CiError("gate runner retained an inherited Rust build override")
    coverage_environment = environment_builder(inherited, {"RUSTC_BOOTSTRAP": "1"})
    if coverage_environment != {
        "CARGO_INCREMENTAL": "0",
        "PATH": "/usr/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
        "RUSTC_BOOTSTRAP": "1",
    }:
        raise CiError("gate runner did not restore the reviewed coverage override exactly")
    cases += 1

    git_environment_builder = runner.get("git_environment")
    if not callable(git_environment_builder):
        raise CiError("gate runner does not expose isolated Git environment construction")
    git_environment = git_environment_builder(
        {
            "GIT_DIR": "/tmp/unreviewed-repository",
            "GIT_PAGER": "unreviewed-pager",
            "PATH": "/usr/bin",
        }
    )
    if git_environment != {
        "CARGO_INCREMENTAL": "0",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_GRAFT_FILE": os.devnull,
        "GIT_NO_REPLACE_OBJECTS": "1",
        "PATH": "/usr/bin",
        "PYTHONDONTWRITEBYTECODE": "1",
    }:
        raise CiError("gate runner did not isolate Git object lookups")
    cases += 1

    git_lookup = runner.get("git_output")
    clean_source = runner.get("require_clean_source")
    gate_error = runner.get("GateError")
    if (
        not callable(git_lookup)
        or not callable(clean_source)
        or not isinstance(gate_error, type)
    ):
        raise CiError("gate runner does not expose exact-source validation")

    def expect_source_rejection(label: str, root_path: Path, fragment: str) -> None:
        nonlocal cases
        try:
            clean_source(root_path)
        except gate_error as error:
            if fragment not in str(error):
                raise CiError(
                    f"exact-source self-test {label!r} reached the wrong branch: {error}"
                ) from error
        else:
            raise CiError(f"exact-source self-test {label!r} was accepted")
        cases += 1

    with tempfile.TemporaryDirectory(prefix="agenc-exact-source-test-") as temporary:
        temporary_root = Path(temporary)
        tracked_path = temporary_root / "tracked.txt"
        tracked_path.write_text("committed\n", encoding="utf-8")
        (temporary_root / ".gitignore").write_text("/target/\n", encoding="utf-8")
        initialized = subprocess.run(
            ["git", "init", "--quiet"],
            cwd=temporary_root,
            env=git_environment_builder(os.environ),
            capture_output=True,
            check=False,
        )
        if initialized.returncode != 0:
            raise CiError("cannot create the exact-source self-test repository")
        git_lookup(
            temporary_root,
            ["add", "--", ".gitignore", "tracked.txt"],
            "exact-source files",
        )
        author = [
            "-c",
            "user.name=CI Self-Test",
            "-c",
            "user.email=ci@example.invalid",
        ]
        git_lookup(
            temporary_root,
            [*author, "commit", "--quiet", "-m", "Add exact source"],
            "exact-source commit",
        )
        source_commit = clean_source(temporary_root)
        original_blob = git_lookup(
            temporary_root,
            ["cat-file", "blob", f"{source_commit}:tracked.txt"],
            "exact-source blob",
        )

        empty_tree = git_lookup(
            temporary_root,
            ["hash-object", "-t", "tree", os.devnull],
            "exact-source empty tree",
        ).decode("ascii").strip()
        replacement_commit = git_lookup(
            temporary_root,
            [*author, "commit-tree", empty_tree, "-m", "Replacement source"],
            "exact-source replacement commit",
        ).decode("ascii").strip()
        git_lookup(
            temporary_root,
            ["replace", source_commit, replacement_commit],
            "exact-source replacement reference",
        )
        attack_environment = {
            name: value
            for name, value in os.environ.items()
            if not name.startswith("GIT_")
        }
        replaced_read = subprocess.run(
            ["git", "cat-file", "-e", f"{source_commit}:tracked.txt"],
            cwd=temporary_root,
            env=attack_environment,
            capture_output=True,
            check=False,
        )
        if replaced_read.returncode == 0:
            raise CiError("exact-source replacement fixture did not alter ordinary Git")
        isolated_blob = git_lookup(
            temporary_root,
            ["cat-file", "blob", f"{source_commit}:tracked.txt"],
            "replacement-isolated source blob",
        )
        if isolated_blob != original_blob or clean_source(temporary_root) != source_commit:
            raise CiError("gate recorder trusted a replacement source object")
        git_lookup(
            temporary_root,
            ["replace", "-d", source_commit],
            "exact-source replacement cleanup",
        )
        cases += 1

        git_lookup(
            temporary_root,
            [*author, "commit", "--quiet", "--allow-empty", "-m", "Add descendant"],
            "exact-source descendant",
        )
        descendant_commit = clean_source(temporary_root)
        graft_path = temporary_root / ".git/info/grafts"
        graft_path.parent.mkdir(parents=True, exist_ok=True)
        graft_path.write_text(f"{descendant_commit}\n", encoding="ascii")
        grafted_ancestry = subprocess.run(
            ["git", "merge-base", "--is-ancestor", source_commit, descendant_commit],
            cwd=temporary_root,
            env=attack_environment,
            capture_output=True,
            check=False,
        )
        if grafted_ancestry.returncode != 1:
            raise CiError("exact-source graft fixture did not alter ordinary Git ancestry")
        git_lookup(
            temporary_root,
            ["merge-base", "--is-ancestor", source_commit, descendant_commit],
            "graft-isolated source ancestry",
        )
        if clean_source(temporary_root) != descendant_commit:
            raise CiError("gate recorder trusted grafted source ancestry")
        graft_path.unlink()
        cases += 1

        git_lookup(
            temporary_root,
            ["update-index", "--assume-unchanged", "tracked.txt"],
            "assume-unchanged fixture",
        )
        tracked_path.write_text("hidden modification\n", encoding="utf-8")
        expect_source_rejection(
            "assume-unchanged file",
            temporary_root,
            "hidden Git index flags",
        )
        git_lookup(
            temporary_root,
            ["update-index", "--no-assume-unchanged", "tracked.txt"],
            "assume-unchanged cleanup",
        )
        tracked_path.write_text("committed\n", encoding="utf-8")

        git_lookup(
            temporary_root,
            ["update-index", "--skip-worktree", "tracked.txt"],
            "skip-worktree fixture",
        )
        expect_source_rejection(
            "skip-worktree file",
            temporary_root,
            "hidden Git index flags",
        )
        git_lookup(
            temporary_root,
            ["update-index", "--no-skip-worktree", "tracked.txt"],
            "skip-worktree cleanup",
        )

        tracked_path.write_text("staged modification\n", encoding="utf-8")
        git_lookup(
            temporary_root,
            ["add", "--", "tracked.txt"],
            "index-divergence fixture",
        )
        expect_source_rejection(
            "divergent index tree",
            temporary_root,
            "Git index tree to equal HEAD",
        )
        tracked_path.write_text("committed\n", encoding="utf-8")
        git_lookup(
            temporary_root,
            ["add", "--", "tracked.txt"],
            "index-divergence cleanup",
        )

        tracked_path.write_text("unstaged modification\n", encoding="utf-8")
        expect_source_rejection(
            "modified worktree bytes",
            temporary_root,
            "worktree bytes from HEAD",
        )
        tracked_path.write_text("committed\n", encoding="utf-8")

        cargo_directory = temporary_root / ".cargo"
        cargo_directory.mkdir()
        (cargo_directory / "config.toml").write_text(
            "[build]\nrustflags = ['--cfg', 'forged_gate']\n",
            encoding="utf-8",
        )
        exclude_path = temporary_root / ".git/info/exclude"
        exclude_path.write_text(
            exclude_path.read_text(encoding="utf-8") + "\n.cargo/config.toml\n",
            encoding="utf-8",
        )
        expect_source_rejection(
            "ignored Cargo configuration",
            temporary_root,
            "ignored source inputs",
        )
        (cargo_directory / "config.toml").unlink()
        cargo_directory.rmdir()

        target_directory = temporary_root / "target"
        target_directory.mkdir()
        (target_directory / "cache").write_bytes(b"external build cache\n")
        if clean_source(temporary_root) != descendant_commit:
            raise CiError("gate recorder rejected its reviewed build-cache limitation")
        cases += 1

        shallow_path = temporary_root / ".git/shallow"
        shallow_path.write_text(f"{descendant_commit}\n", encoding="ascii")
        expect_source_rejection(
            "shallow source history",
            temporary_root,
            "complete Git history",
        )

    toolchain_probe = runner.get("probe_toolchain")
    if not callable(toolchain_probe) or not isinstance(gate_error, type):
        raise CiError("gate runner does not expose reviewed toolchain probing")

    def expect_probe_rejection(
        label: str,
        root_path: Path,
        tool: dict[str, object],
        fragment: str,
    ) -> None:
        nonlocal cases
        try:
            toolchain_probe(root_path, [tool])
        except gate_error as error:
            if fragment not in str(error):
                raise CiError(
                    f"toolchain probe self-test {label!r} reached the wrong branch: {error}"
                ) from error
        else:
            raise CiError(f"toolchain probe self-test {label!r} was accepted")
        cases += 1

    with tempfile.TemporaryDirectory(prefix="agenc-toolchain-probe-test-") as temporary:
        temporary_root = Path(temporary)
        probe_path = temporary_root / "reviewed-tool"

        def write_probe(program: str) -> None:
            probe_path.write_text(
                f"#!{sys.executable}\n{program}\n",
                encoding="utf-8",
            )
            probe_path.chmod(0o755)

        reviewed_tool = {
            "name": "reviewed-tool",
            "argv": ["reviewed-tool", "--version"],
            "version": "reviewed-tool 1.0",
        }
        with mock.patch.dict(os.environ, {"PATH": str(temporary_root)}):
            write_probe("print('reviewed-tool 1.0')")
            if toolchain_probe(temporary_root, [reviewed_tool]) != [reviewed_tool]:
                raise CiError("gate runner changed a successful toolchain identity")

            write_probe("print('reviewed-tool 2.0')")
            expect_probe_rejection(
                "wrong stdout",
                temporary_root,
                reviewed_tool,
                "unexpected version",
            )
            write_probe("print('reviewed-tool 1.0\\nextra output')")
            expect_probe_rejection(
                "extra stdout",
                temporary_root,
                reviewed_tool,
                "unexpected version",
            )
            write_probe("import os; os.write(1, b'x' * 70000)")
            expect_probe_rejection(
                "oversized stdout",
                temporary_root,
                reviewed_tool,
                "stdout exceeded 65536 bytes",
            )
            write_probe("import sys; print('diagnostic', file=sys.stderr)")
            expect_probe_rejection(
                "stderr output",
                temporary_root,
                reviewed_tool,
                "wrote to stderr",
            )
            write_probe("raise SystemExit(9)")
            expect_probe_rejection(
                "nonzero exit",
                temporary_root,
                reviewed_tool,
                "failed with status 9",
            )
            write_probe("import time; time.sleep(2)")
            probe_globals = toolchain_probe.__globals__
            with mock.patch.dict(
                probe_globals,
                {"TOOLCHAIN_PROBE_TIMEOUT_SECONDS": 0.05},
            ):
                expect_probe_rejection(
                    "timeout",
                    temporary_root,
                    reviewed_tool,
                    "timed out",
                )
            missing_tool = copy.deepcopy(reviewed_tool)
            missing_tool["argv"] = ["missing-reviewed-tool", "--version"]
            expect_probe_rejection(
                "missing executable",
                temporary_root,
                missing_tool,
                "cannot execute",
            )

    record_gate = runner.get("record_gate")
    if not callable(record_gate):
        raise CiError("gate runner does not expose failure-atomic recording")

    with tempfile.TemporaryDirectory(prefix="agenc-gate-atomicity-test-") as temporary:
        temporary_root = Path(temporary)
        destination = temporary_root / "artifact.json"
        source_commit = "1" * 40
        expected_toolchain = [
            {
                "name": "reviewed-tool",
                "argv": ["reviewed-tool", "--version"],
                "version": "reviewed-tool 1.0",
            }
        ]

        def expect_record_rejection(
            label: str,
            replacements: dict[str, object],
            fragment: str,
        ) -> None:
            nonlocal cases
            writer = mock.Mock()
            defaults: dict[str, object] = {
                "artifact_metadata": lambda _root, _gate: {
                    "source_commit": source_commit,
                    "toolchain": copy.deepcopy(expected_toolchain),
                },
                "evidence_artifact_path": lambda _root, _gate, _commit: (
                    destination,
                    "conformance/evidence/artifacts/test.json",
                ),
                "probe_toolchain": mock.Mock(
                    side_effect=[
                        copy.deepcopy(expected_toolchain),
                        copy.deepcopy(expected_toolchain),
                    ]
                ),
                "utc_timestamp": mock.Mock(
                    side_effect=["2026-08-27T00:00:00Z", "2026-08-27T00:00:01Z"]
                ),
                "execute": lambda _root, _gate: [],
                "require_clean_source": lambda _root: source_commit,
                "write_artifact": writer,
            }
            defaults.update(replacements)
            try:
                with mock.patch.dict(record_gate.__globals__, defaults):
                    record_gate(temporary_root, "stage-zero-implementation")
            except gate_error as error:
                if fragment not in str(error):
                    raise CiError(
                        f"gate atomicity self-test {label!r} reached the wrong branch: {error}"
                    ) from error
            else:
                raise CiError(f"gate atomicity self-test {label!r} was accepted")
            if writer.called or destination.exists():
                raise CiError(
                    f"gate atomicity self-test {label!r} published partial evidence"
                )
            cases += 1

        expect_record_rejection(
            "initial probe failure",
            {
                "probe_toolchain": mock.Mock(
                    side_effect=gate_error("toolchain probe failed")
                )
            },
            "toolchain probe failed",
        )
        expect_record_rejection(
            "gate command failure",
            {"execute": mock.Mock(side_effect=gate_error("command failed"))},
            "command failed",
        )
        drifted_toolchain = copy.deepcopy(expected_toolchain)
        drifted_toolchain[0]["version"] = "reviewed-tool 2.0"
        expect_record_rejection(
            "toolchain drift",
            {
                "probe_toolchain": mock.Mock(
                    side_effect=[expected_toolchain, drifted_toolchain]
                )
            },
            "toolchain identity changed",
        )
        expect_record_rejection(
            "source drift",
            {"require_clean_source": lambda _root: "2" * 40},
            "source HEAD changed",
        )

        artifact_writer = runner.get("write_artifact")
        if not callable(artifact_writer):
            raise CiError("gate runner does not expose atomic artifact publication")
        artifact_metadata = {
            "toolchain_policy_sha256": "2" * 64,
            "toolchain": expected_toolchain,
            "limitations": ["Self-test limitation."],
            "source_commit": source_commit,
            "source_sha256": "3" * 64,
            "lock_sha256": "4" * 64,
            "target": "x86_64-unknown-linux-gnu",
            "features": ["all-features"],
            "evidence": [],
        }
        with mock.patch.object(
            os,
            "fsync",
            side_effect=[None, OSError("seeded directory fsync failure")],
        ):
            try:
                artifact_writer(
                    root,
                    destination,
                    "conformance/evidence/artifacts/test.json",
                    "stage-zero-implementation",
                    artifact_metadata,
                    "2026-08-27T00:00:00Z",
                    "2026-08-27T00:00:01Z",
                    [],
                )
            except gate_error as error:
                if "seeded directory fsync failure" not in str(error):
                    raise CiError(
                        f"artifact rollback reached the wrong branch: {error}"
                    ) from error
            else:
                raise CiError("artifact writer accepted a failed directory fsync")
        if destination.exists() or list(temporary_root.glob(".*.tmp")):
            raise CiError("artifact writer retained output after a post-link failure")
        cases += 1

        class BrokenOutput:
            """A status stream whose consumer closed its read end."""

            def write(self, _text: str) -> int:
                raise BrokenPipeError("seeded closed output")

            def flush(self) -> None:
                raise BrokenPipeError("seeded closed output")

        with mock.patch.object(sys, "stdout", BrokenOutput()):
            artifact_writer(
                root,
                destination,
                "conformance/evidence/artifacts/test.json",
                "stage-zero-implementation",
                artifact_metadata,
                "2026-08-27T00:00:00Z",
                "2026-08-27T00:00:01Z",
                [],
            )
            if sys.stdout is not None:
                raise CiError("artifact writer retained a broken status stream")
        if not destination.is_file():
            raise CiError("artifact writer lost published output after status failure")
        cases += 1

    artifact_path_builder = runner.get("evidence_artifact_path")
    if not callable(artifact_path_builder):
        raise CiError("gate runner does not expose deterministic artifact paths")
    with tempfile.TemporaryDirectory(prefix="agenc-gate-path-test-") as temporary:
        temporary_root = Path(temporary)
        (temporary_root / "conformance/evidence").mkdir(parents=True)
        source_commit = "1" * 40
        _path, relative = artifact_path_builder(
            temporary_root,
            "stage-four-implementation",
            source_commit,
        )
        expected = (
            "conformance/evidence/artifacts/"
            f"stage-four-implementation-{source_commit}.json"
        )
        if relative != expected:
            raise CiError("gate runner derived a noncanonical artifact path")
    cases += 1

    generator = runpy.run_path(str(root / "scripts/generate-gate-evidence.py"))
    identity_checker = generator.get("require_artifact_identity")
    path_checker = generator.get("repository_path")
    manifest_writer = generator.get("write_manifest")
    generation_error = generator.get("GenerationError")
    artifact_directory = generator.get("ARTIFACT_DIRECTORY")
    manifest_directory = generator.get("MANIFEST_DIRECTORY")
    if (
        not callable(identity_checker)
        or not callable(path_checker)
        or not callable(manifest_writer)
        or not isinstance(generation_error, type)
        or not isinstance(artifact_directory, Path)
        or not isinstance(manifest_directory, Path)
    ):
        raise CiError("gate evidence generator does not expose closed path checks")
    try:
        identity_checker(
            "conformance/evidence/artifacts/renamed.json",
            "stage-four-implementation",
            "1" * 40,
        )
    except ValueError as error:
        if "does not match its gate and source commit" not in str(error):
            raise CiError(f"renamed artifact reached the wrong rejection: {error}") from error
    else:
        raise CiError("gate evidence generator accepted a renamed artifact")
    cases += 1

    with tempfile.TemporaryDirectory(prefix="agenc-manifest-path-test-") as temporary:
        temporary_root = Path(temporary)
        evidence_directory = temporary_root / manifest_directory
        evidence_directory.mkdir(parents=True)
        existing = evidence_directory / "stage-04-existing.json"
        existing.write_text("reserved\n", encoding="utf-8")
        try:
            path_checker(
                temporary_root,
                existing.relative_to(temporary_root).as_posix(),
                manifest_directory,
                must_exist=False,
            )
        except ValueError as error:
            if "output already exists" not in str(error):
                raise CiError(f"manifest collision reached the wrong rejection: {error}") from error
        else:
            raise CiError("gate evidence generator accepted an existing manifest path")
    cases += 1

    with tempfile.TemporaryDirectory(prefix="agenc-manifest-atomicity-test-") as temporary:
        temporary_root = Path(temporary)
        evidence_directory = temporary_root / manifest_directory
        evidence_directory.mkdir(parents=True)
        destination = evidence_directory / "stage-04-atomic.json"
        relative = destination.relative_to(temporary_root).as_posix()
        with mock.patch.object(
            os,
            "fsync",
            side_effect=[None, OSError("seeded directory fsync failure")],
        ):
            try:
                manifest_writer(destination, relative, {"schema_version": 2})
            except generation_error as error:
                if "seeded directory fsync failure" not in str(error):
                    raise CiError(
                        f"manifest rollback reached the wrong branch: {error}"
                    ) from error
            else:
                raise CiError("manifest writer accepted a failed directory fsync")
        if destination.exists() or list(evidence_directory.glob(".*.tmp")):
            raise CiError("manifest writer retained output after a post-link failure")
        cases += 1

        with mock.patch.object(sys, "stdout", BrokenOutput()):
            manifest_writer(destination, relative, {"schema_version": 2})
            if sys.stdout is not None:
                raise CiError("manifest writer retained a broken status stream")
        if not destination.is_file():
            raise CiError("manifest writer lost published output after status failure")
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
