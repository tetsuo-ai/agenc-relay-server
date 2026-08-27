#!/usr/bin/env python3
"""Execute a reviewed conformance gate without a command shell."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
import subprocess
import sys
import tempfile
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, NoReturn, TypedDict

MANIFEST_PATH = "conformance/gates.toml"
ALLOWED_ENVIRONMENT = {"RUSTC_BOOTSTRAP"}
ARTIFACT_ENVIRONMENT = "AGENC_IRCD_RECORD_GATE"
ARTIFACT_DIRECTORY = Path("conformance/evidence/artifacts")
ARTIFACT_MAX_BYTES = 4 * 1024 * 1024
STAGE_GATES = {
    "stage-zero-implementation": 0,
    "stage-one-implementation": 1,
    "stage-two-implementation": 2,
    "stage-three-implementation": 3,
    "stage-four-implementation": 4,
}
BUILD_OVERRIDE_ENVIRONMENT = frozenset(
    {
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC",
        "RUSTC_BOOTSTRAP",
        "RUSTC_WRAPPER",
        "RUSTC_WORKSPACE_WRAPPER",
        "RUSTDOC",
        "RUSTDOCFLAGS",
        "RUSTFLAGS",
        "RUSTUP_TOOLCHAIN",
    }
)
CONTROL_ENVIRONMENT = frozenset({ARTIFACT_ENVIRONMENT})
INJECTION_ENVIRONMENT = frozenset(
    {
        "BASH_ENV",
        "CDPATH",
        "ENV",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_SYSTEM",
        "GIT_DIR",
        "GIT_INDEX_FILE",
        "GIT_OBJECT_DIRECTORY",
        "GIT_WORK_TREE",
        "GLOBIGNORE",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
    }
)
INJECTION_ENVIRONMENT_PREFIXES = (
    "BASH_FUNC_",
    "DYLD_",
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
)
BUILD_OVERRIDE_PREFIXES = (
    "CARGO_BUILD_",
    "CARGO_PROFILE_",
    "CARGO_TARGET_",
)


class GateError(ValueError):
    """A gate manifest or command execution failure."""


class CommandResult(TypedDict):
    """One command result suitable for the closed evidence schema."""

    argv: list[str]
    environment: dict[str, str]
    started_at: str
    ended_at: str
    exit_code: int


def load_gates(root: Path) -> dict[str, object]:
    """Load the closed gate manifest."""
    try:
        manifest = tomllib.loads((root / MANIFEST_PATH).read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise GateError(f"cannot read gate manifest: {error}") from error
    if manifest.get("schema_version") != 1 or set(manifest) != {"schema_version", "gate"}:
        raise GateError("gate manifest has an invalid top-level schema")
    gates = manifest.get("gate")
    if not isinstance(gates, dict):
        raise GateError("gate manifest has no gate table")
    return gates


def resolve_commands(
    gates: dict[str, object], name: str, resolving: tuple[str, ...] = ()
) -> list[dict[str, object]]:
    """Resolve included gates in deterministic order and reject cycles."""
    if name in resolving:
        raise GateError(f"gate include cycle reaches {name}")
    gate = gates.get(name)
    if not isinstance(gate, dict) or set(gate) - {"includes", "command"}:
        raise GateError(f"gate {name!r} is missing or malformed")
    includes = gate.get("includes", [])
    commands = gate.get("command", [])
    if not isinstance(includes, list) or any(not isinstance(item, str) for item in includes):
        raise GateError(f"gate {name!r} has invalid includes")
    if not isinstance(commands, list):
        raise GateError(f"gate {name!r} has invalid commands")
    resolved: list[dict[str, object]] = []
    for included in includes:
        resolved.extend(resolve_commands(gates, included, resolving + (name,)))
    for command in commands:
        if not isinstance(command, dict) or set(command) - {"argv", "environment"}:
            raise GateError(f"gate {name!r} contains a malformed command")
        argv = command.get("argv")
        if not isinstance(argv, list) or not argv or any(not isinstance(item, str) or not item for item in argv):
            raise GateError(f"gate {name!r} contains invalid argv")
        environment = command.get("environment", {})
        if not isinstance(environment, dict) or set(environment) - ALLOWED_ENVIRONMENT:
            raise GateError(f"gate {name!r} contains invalid environment state")
        if any(not isinstance(value, str) for value in environment.values()):
            raise GateError(f"gate {name!r} contains a non-string environment value")
        resolved.append(command)
    return resolved


def command_environment(
    inherited: Mapping[str, str], reviewed: Mapping[str, str]
) -> dict[str, str]:
    """Return inherited process state without unreviewed Rust build overrides."""
    environment = {
        name: value
        for name, value in inherited.items()
        if name not in BUILD_OVERRIDE_ENVIRONMENT
        and name not in CONTROL_ENVIRONMENT
        and name not in INJECTION_ENVIRONMENT
        and not name.startswith(BUILD_OVERRIDE_PREFIXES)
        and not name.startswith(INJECTION_ENVIRONMENT_PREFIXES)
    }
    environment.update(reviewed)
    return environment


def utc_timestamp() -> str:
    """Return a canonical UTC timestamp for evidence records."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


def execute(root: Path, name: str) -> list[CommandResult]:
    """Execute one gate and return ordered, output-free command results."""
    commands = resolve_commands(load_gates(root), name)
    results: list[CommandResult] = []
    for command in commands:
        argv = command["argv"]
        reviewed_environment = command.get("environment", {})
        environment = command_environment(os.environ, reviewed_environment)
        print("+ " + " ".join(argv), flush=True)
        started_at = utc_timestamp()
        completed = subprocess.run(argv, cwd=root, env=environment, check=False)
        ended_at = utc_timestamp()
        if completed.returncode != 0:
            raise GateError(f"command failed with status {completed.returncode}: {argv!r}")
        results.append(
            {
                "argv": list(argv),
                "environment": dict(reviewed_environment),
                "started_at": started_at,
                "ended_at": ended_at,
                "exit_code": completed.returncode,
            }
        )
    return results


def evidence_policy(root: Path) -> dict[str, object]:
    """Load the checked-in evidence policy without creating a second policy copy."""
    return runpy.run_path(
        str(root / "scripts/check-evidence.py"),
        run_name="agenc_ircd_evidence_policy",
    )


def git_output(root: Path, arguments: list[str], label: str) -> bytes:
    """Run one bounded Git query and return its stdout."""
    completed = subprocess.run(
        ["git", *arguments],
        cwd=root,
        env=command_environment(os.environ, {}),
        capture_output=True,
        check=False,
    )
    if completed.returncode != 0:
        details = completed.stderr.decode("utf-8", errors="replace").strip()
        raise GateError(f"Git query failed for {label}: {details}")
    return completed.stdout


def reject_symlink_parents(root: Path, relative: Path) -> None:
    """Reject an output path whose existing parents traverse a symbolic link."""
    cursor = root
    for part in relative.parent.parts:
        cursor /= part
        if cursor.is_symlink():
            raise GateError("evidence output paths may not traverse symbolic links")


def evidence_artifact_path(
    root: Path, gate: str, source_commit: str
) -> tuple[Path, str]:
    """Derive one deterministic, repository-local evidence artifact path."""
    if gate not in STAGE_GATES:
        raise GateError(f"gate {gate!r} is not eligible for closure evidence")
    relative = ARTIFACT_DIRECTORY / f"{gate}-{source_commit}.json"
    reject_symlink_parents(root, relative)
    candidate = root / relative
    if candidate.exists() or candidate.is_symlink():
        raise GateError(f"evidence artifact already exists: {relative.as_posix()}")
    return candidate, relative.as_posix()


def require_clean_source(root: Path) -> str:
    """Return HEAD after rejecting changes outside generated evidence artifacts."""
    raw_status = git_output(
        root,
        ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        "working tree status",
    )
    dirty_source_paths: list[str] = []
    for raw_record in raw_status.split(b"\0"):
        if not raw_record:
            continue
        record = raw_record.decode("utf-8", errors="replace")
        path = record[3:] if len(record) >= 4 and record[2] == " " else record
        candidate = Path(path)
        if candidate.parent != ARTIFACT_DIRECTORY or candidate.suffix != ".json":
            dirty_source_paths.append(path)
    if dirty_source_paths:
        shown = ", ".join(sorted(dirty_source_paths)[:8])
        if len(dirty_source_paths) > 8:
            shown += ", ..."
        raise GateError(f"recorded gates require a clean source tree; changed: {shown}")
    commit = git_output(
        root,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        "source commit",
    ).decode("ascii", errors="strict").strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise GateError("Git returned a noncanonical source commit")
    return commit


def rust_host(root: Path) -> str:
    """Return the host target reported by the pinned Rust compiler."""
    completed = subprocess.run(
        ["rustc", "--version", "--verbose"],
        cwd=root,
        env=command_environment(os.environ, {}),
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise GateError("rustc did not report the evidence target")
    for line in completed.stdout.splitlines():
        if line.startswith("host: "):
            target = line.removeprefix("host: ")
            if target:
                return target
    raise GateError("rustc output did not contain a host target")


def artifact_metadata(root: Path, gate: str) -> dict[str, object]:
    """Resolve exact-source metadata and the reviewed evidence inventory."""
    stage = STAGE_GATES.get(gate)
    if stage is None:
        raise GateError(f"gate {gate!r} is not eligible for closure evidence")
    injected = sorted(
        name
        for name in os.environ
        if name in INJECTION_ENVIRONMENT
        or name.startswith(INJECTION_ENVIRONMENT_PREFIXES)
    )
    if injected:
        raise GateError(
            "recorded gates reject process-injection environment variables: "
            + ", ".join(injected)
        )
    source_commit = require_clean_source(root)
    policy = evidence_policy(root)
    try:
        validate_catalog = policy["validate_catalog"]
        canonical_source_sha256 = policy["canonical_source_sha256"]
        commit_blob_sha256 = policy["commit_blob_sha256"]
        required_stage_evidence_ids = policy["required_stage_evidence_ids"]
        closure_evidence_inventory = policy["closure_evidence_inventory"]
        validate_catalog(root)  # type: ignore[operator]
        source_hash = canonical_source_sha256(root, source_commit)  # type: ignore[operator]
        lock_hash = commit_blob_sha256(root, source_commit, "Cargo.lock")  # type: ignore[operator]
        required_ids = required_stage_evidence_ids(  # type: ignore[operator]
            root, stage, source_commit
        )
        inventory = closure_evidence_inventory(required_ids)  # type: ignore[operator]
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise GateError(f"cannot resolve evidence metadata: {error}") from error
    return {
        "stage": stage,
        "source_commit": source_commit,
        "source_sha256": source_hash,
        "lock_sha256": lock_hash,
        "target": rust_host(root),
        "features": ["all-features"],
        "evidence": inventory,
    }


def write_artifact(
    root: Path,
    destination: Path,
    relative: str,
    gate: str,
    metadata: dict[str, object],
    started_at: str,
    ended_at: str,
    command_results: list[CommandResult],
) -> None:
    """Atomically create one passed exact-source gate-run artifact."""
    artifact = {
        "schema_version": 1,
        "gate": gate,
        "gate_manifest_sha256": hashlib.sha256(
            (root / MANIFEST_PATH).read_bytes()
        ).hexdigest(),
        "argv": ["python3", "scripts/run-gate.py", gate],
        "tool": {
            "name": "agenc-ircd-gate-runner",
            "version": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        },
        "source_commit": metadata["source_commit"],
        "source_sha256": metadata["source_sha256"],
        "lock_sha256": metadata["lock_sha256"],
        "target": metadata["target"],
        "features": metadata["features"],
        "started_at": started_at,
        "ended_at": ended_at,
        "result": "passed",
        "exit_code": 0,
        "command_results": command_results,
        "evidence": metadata["evidence"],
    }
    encoded = (json.dumps(artifact, indent=2) + "\n").encode("utf-8")
    if len(encoded) > ARTIFACT_MAX_BYTES:
        raise GateError("evidence artifact exceeds the 4 MiB record limit")
    destination.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o644)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary_path, destination)
        temporary_path.unlink()
        temporary_path = None
        directory_descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError:
                pass
        raise GateError(f"cannot create evidence artifact {relative}: {error}") from error
    print(f"gate evidence artifact: {relative}", flush=True)


def fail(message: str) -> NoReturn:
    """Report one stable gate error and exit unsuccessfully."""
    print(f"gate runner failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Parse the gate name and execute it from the repository root."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("gate")
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        artifact_value = os.environ.get(ARTIFACT_ENVIRONMENT)
        if artifact_value is None:
            execute(root, arguments.gate)
            return
        if artifact_value != "1":
            raise GateError(f"{ARTIFACT_ENVIRONMENT} must be exactly 1")
        metadata = artifact_metadata(root, arguments.gate)
        source_commit = str(metadata["source_commit"])
        destination, relative = evidence_artifact_path(
            root, arguments.gate, source_commit
        )
        started_at = utc_timestamp()
        command_results = execute(root, arguments.gate)
        ended_at = utc_timestamp()
        final_source_commit = require_clean_source(root)
        if final_source_commit != metadata["source_commit"]:
            raise GateError("source HEAD changed while the recorded gate was running")
        write_artifact(
            root,
            destination,
            relative,
            arguments.gate,
            metadata,
            started_at,
            ended_at,
            command_results,
        )
    except (GateError, OSError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
