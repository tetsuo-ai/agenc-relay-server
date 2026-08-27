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

CHECKOUT_COMMIT = "df4cb1c069e1874edd31b4311f1884172cec0e10"
WORKFLOW_PATH = ".github/workflows/ci.yml"
GATE_PATHS = (
    "scripts/check-stage-zero.sh",
    "scripts/check-stage-one.sh",
    "scripts/check-stage-two.sh",
    "scripts/check-stage-three.sh",
    "scripts/check-stage-four.sh",
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
    "cargo +1.98.0 install --locked cargo-fuzz --version 0.13.2",
)
REQUIRED_GATE_STEP = (
    "      - name: Run Stage 04 implementation checks\n"
    "        run: bash scripts/check-stage-four.sh"
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
        "python3", "scripts/check-coverage.py", "self-test",
        "conformance/critical-coverage.toml",
    ),
    (
        "cargo", "llvm-cov", "--workspace", "--all-features", "--branch", "--locked",
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
        "cargo", "test", "-p", "agenc-ircd-testkit",
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
    ("cargo", "test", "-p", "agenc-ircd-auth", "--test", "stage_four", "--locked"),
    ("cargo", "test", "-p", "agenc-ircd-crypto", "--test", "stage_four", "--locked"),
    (
        "cargo", "test", "-p", "agenc-ircd-testkit",
        "--test", "stage_four_domain_auth", "--locked",
    ),
    ("bash", "scripts/run-stage-four-fuzz.sh"),
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
        raise CiError("workflow must contain one live Stage 04 implementation-check step")


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
    }:
        raise CiError(
            "gate manifest must define Stages 00 through 03 and Stage 04 implementation checks"
        )
    stage_zero = gates.get("stage-zero-implementation")
    stage_one = gates.get("stage-one-implementation")
    stage_two = gates.get("stage-two-implementation")
    stage_three = gates.get("stage-three-implementation")
    stage_four = gates.get("stage-four-implementation")
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
    weakened = workflow.replace("run: bash scripts/check-stage-four.sh", "continue-on-error: true\n        run: bash scripts/check-stage-four.sh", 1)
    expect_rejection("continue on error", lambda: validate_workflow(weakened), "continue-on-error")
    cases += 1
    commented = workflow.replace(
        "        run: bash scripts/check-stage-four.sh",
        "        # run: bash scripts/check-stage-four.sh",
        1,
    )
    expect_rejection(
        "commented gate",
        lambda: validate_workflow(commented),
        "one live Stage 04 implementation-check step",
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
        "        run: bash scripts/check-stage-four.sh",
        "        if: false\n        run: bash scripts/check-stage-four.sh",
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
        "BASH_ENV": "/tmp/unreviewed-shell-environment",
        "BASH_FUNC_cargo%%": "() { printf injected; }",
        "GIT_CONFIG_KEY_0": "core.hooksPath",
        "LD_PRELOAD": "/tmp/unreviewed-library.so",
        "PATH": "/usr/bin",
        "PYTHONPATH": "/tmp/unreviewed-python-path",
        "CARGO_PROFILE_RELEASE_PANIC": "abort",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "-C target-feature=+crt-static",
        "RUSTC_BOOTSTRAP": "1",
        "RUSTFLAGS": "-Zallow-features=all",
        "RUSTUP_TOOLCHAIN": "nightly",
    }
    clean_environment = environment_builder(inherited, {})
    if clean_environment != {"PATH": "/usr/bin"}:
        raise CiError("gate runner retained an inherited Rust build override")
    coverage_environment = environment_builder(inherited, {"RUSTC_BOOTSTRAP": "1"})
    if coverage_environment != {"PATH": "/usr/bin", "RUSTC_BOOTSTRAP": "1"}:
        raise CiError("gate runner did not restore the reviewed coverage override exactly")
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
