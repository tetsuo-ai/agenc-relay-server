#!/usr/bin/env python3
"""Execute a reviewed conformance gate without a command shell."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

MANIFEST_PATH = "conformance/gates.toml"
ALLOWED_ENVIRONMENT = {"RUSTC_BOOTSTRAP"}


class GateError(ValueError):
    """A gate manifest or command execution failure."""


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


def execute(root: Path, name: str) -> None:
    """Execute every command in one resolved gate, stopping on first failure."""
    commands = resolve_commands(load_gates(root), name)
    for command in commands:
        argv = command["argv"]
        environment = os.environ.copy()
        environment.update(command.get("environment", {}))
        print("+ " + " ".join(argv), flush=True)
        completed = subprocess.run(argv, cwd=root, env=environment, check=False)
        if completed.returncode != 0:
            raise GateError(f"command failed with status {completed.returncode}: {argv!r}")


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
        execute(root, arguments.gate)
    except (GateError, OSError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
