#!/usr/bin/env python3
"""Run production synchronization models and interpreter/sanitizer checks."""

import os
import sys
from pathlib import Path

from release_qualification.driver import command, context, finish
from release_qualification.records import QualificationError


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    _, _, attempt, target = context(root)
    suites = {
        "federation-model": ["bash", "scripts/run-stage-seven-model.sh"],
        "encrypted-model": ["bash", "scripts/run-stage-eight-model.sh"],
        "loom": ["bash", "scripts/run-stage-six-loom.sh"],
        "runtime": ["cargo", "test", "-p", "agenc-relay-runtime", "--all-features", "--locked"],
        "miri": ["cargo", "+nightly-2026-08-24", "miri", "test", "-p", "agenc-relay-types", "--lib", "--locked"],
    }
    for name, argv in suites.items():
        command(root, attempt, name, argv, 14400)
    environment = dict(os.environ)
    environment["RUSTFLAGS"] = "-Zsanitizer=address"
    environment["CARGO_TARGET_DIR"] = str(root / "target/stage-ten-sanitizer")
    command(root, attempt, "sanitizer", ["cargo", "+nightly-2026-08-24", "test", "-p", "agenc-relay-client-wire", "--all-features", "--locked", "--target", target, "-Zbuild-std"], 14400, environment)
    finish(attempt, "models", {name: True for name in ("models", "loom", "cancellation", "overload", "panic_containment", "shutdown", "miri", "sanitizers")})


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError) as error:
        print(f"Stage 10 models: {error}", file=sys.stderr)
        sys.exit(1)
