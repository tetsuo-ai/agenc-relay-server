"""Run integration-test executables against the immutable candidate daemon."""

from __future__ import annotations

import json
import os
import re
import shutil
from pathlib import Path
from typing import Any

from .driver import command
from .records import QualificationError, canonical, file_digest, read_bytes, safe_path, write_once


class DaemonTests:
    def __init__(self, root: Path, directory: Path, attempt: Path, candidate: dict[str, Any], target: str):
        self.root, self.attempt = root, attempt
        self.artifact = next(item for item in candidate["artifacts"] if item["target"] == target)
        self.binary = safe_path(directory, self.artifact["path"])
        self.target = target
        self.output = attempt / "build"
        self.environment = {**os.environ, "CARGO_TARGET_DIR": str(self.output)}
        self.executables: dict[str, Path] = {}
        # Tests exercise both the current daemon name and the legacy entry point.
        # Both paths must execute the immutable candidate, not a Cargo-built copy.
        self.installed = [self.output / target / "release/arcd"]

    def compile(self, suites: list[str]) -> None:
        argv = ["cargo", "test", "-p", "agenc-relay-server", "--release", "--all-features", "--frozen",
                "--target", self.target, "--no-run", "--message-format=json"]
        for suite in suites:
            if not re.fullmatch(r"[a-z][a-z0-9_]+", suite):
                raise QualificationError("invalid daemon test suite")
            argv.extend(["--test", suite])
        command(self.root, self.attempt, "compile-daemon-tests", argv, 7200, self.environment)
        for line in read_bytes(self.attempt / "evidence/compile-daemon-tests.log", 64 * 1024 * 1024).splitlines():
            if not line.startswith(b"{"):
                continue
            event = json.loads(line)
            if event.get("reason") != "compiler-artifact" or not event.get("profile", {}).get("test"):
                continue
            name = event["target"]["name"]
            if name in suites and event.get("executable"):
                path = Path(event["executable"])
                if not path.is_relative_to(self.output) or path.is_symlink() or not path.is_file() or name in self.executables:
                    raise QualificationError("unexpected integration-test executable")
                self.executables[name] = path
        if set(self.executables) != set(suites):
            raise QualificationError("Cargo omitted a requested integration-test executable")
        # CARGO_BIN_EXE in these executables points to this private target tree.
        # Cargo must not run again after installing the exact release artifact.
        for installed in self.installed:
            if installed.is_symlink():
                raise QualificationError("daemon test output is a symlink")
            installed.unlink(missing_ok=True)
            shutil.copyfile(self.binary, installed)
            installed.chmod(0o500)
        self.verify_binary()
        write_once(self.attempt / "evidence/test-executables.json", canonical({
            "daemon_sha256": self.artifact["sha256"],
            "executables": {name: file_digest(path) for name, path in self.executables.items()},
        }))

    def verify_binary(self) -> None:
        if file_digest(self.binary) != self.artifact["sha256"] or any(file_digest(path) != self.artifact["sha256"] for path in self.installed):
            raise QualificationError("integration test did not retain the frozen daemon binary")

    def run(self, name: str, suite: str, test: str, *, ignored: bool = False,
            environment: dict[str, str] | None = None, timeout: int = 600, wrapper: list[str] | None = None) -> None:
        """Run one test; `wrapper` is an argv prefix such as a delegated-cgroup launcher."""
        self.verify_binary()
        executable = self.executables[suite]
        argv = [*(wrapper or []), str(executable), test, "--exact", "--nocapture"]
        if ignored:
            argv.append("--ignored")
        command(self.root, self.attempt, name, argv, timeout, {**self.environment, **(environment or {})})
        log = read_bytes(self.attempt / f"evidence/{name}.log", 64 * 1024 * 1024).decode("utf-8", errors="replace")
        results = re.findall(r"^test result: ok\. (\d+) passed; (\d+) failed; (\d+) ignored;", log, re.MULTILINE)
        if not results or results[-1] != ("1", "0", "0"):
            raise QualificationError(f"daemon test was absent, ignored, or did not finish: {test}")
        self.verify_binary()
