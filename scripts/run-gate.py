#!/usr/bin/env python3
"""Execute a reviewed conformance gate without a command shell."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Mapping, NoReturn, TypedDict

MANIFEST_PATH = "conformance/gates.toml"
ALLOWED_ENVIRONMENT = {"RUSTC_BOOTSTRAP"}
ARTIFACT_ENVIRONMENT = "AGENC_IRCD_RECORD_GATE"
ARTIFACT_DIRECTORY = Path("conformance/evidence/artifacts")
ARTIFACT_MAX_BYTES = 4 * 1024 * 1024
TOOLCHAIN_PROBE_TIMEOUT_SECONDS = 30
ALLOWED_IGNORED_DIRECTORIES = {b"fuzz/target/", b"target/"}
FIXED_COMMAND_ENVIRONMENT = {
    "CARGO_INCREMENTAL": "0",
    "PYTHONDONTWRITEBYTECODE": "1",
}
STAGE_GATES = {
    "stage-zero-implementation": 0,
    "stage-one-implementation": 1,
    "stage-two-implementation": 2,
    "stage-three-implementation": 3,
    "stage-four-implementation": 4,
    "stage-five-implementation": 5,
    "stage-six-implementation": 6,
    "stage-seven-implementation": 7,
    "stage-eight-implementation": 8,
    "stage-nine-implementation": 9,
}
NATIVE_TARGET_OVERRIDE_ENVIRONMENT = (
    "AR",
    "ARFLAGS",
    "CC",
    "CFLAGS",
    "CXX",
    "CXXFLAGS",
    "CXXSTDLIB",
    "NVCC",
    "RANLIB",
    "RANLIBFLAGS",
)
BUILD_OVERRIDE_ENVIRONMENT = (
    frozenset(NATIVE_TARGET_OVERRIDE_ENVIRONMENT)
    | frozenset(
        f"{build_kind}_{name}"
        for build_kind in ("HOST", "TARGET")
        for name in NATIVE_TARGET_OVERRIDE_ENVIRONMENT
    )
    | frozenset(
        {
            "ASAN_OPTIONS",
            "ASAN_SYMBOLIZER_PATH",
            "CARGO_LLVM_COV_BUILD_DIR",
            "CARGO_LLVM_COV_DENY_WARNINGS",
            "CARGO_LLVM_COV_FLAGS",
            "CARGO_LLVM_COV_SETUP",
            "CARGO_LLVM_COV_SHOW_ENV",
            "CARGO_LLVM_COV_TARGET_DIR",
            "CARGO_LLVM_PROFDATA_FLAGS",
            "CARGO_INCREMENTAL",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTFLAGS",
            "CARGO_ENCODED_RUSTDOCFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CC_ENABLE_DEBUG_OUTPUT",
            "CC_FORCE_DISABLE",
            "CC_KNOWN_WRAPPER_CUSTOM",
            "CC_SHELL_ESCAPED_FLAGS",
            "CLIPPY_CONF_DIR",
            "CRATE_CC_NO_DEFAULTS",
            "CROSS_COMPILE",
            "CUSTOM_LIBFUZZER_PATH",
            "CUSTOM_LIBFUZZER_STD_CXX",
            "LLVM_COV",
            "LLVM_COV_FLAGS",
            "LLVM_PROFDATA",
            "LLVM_PROFDATA_FLAGS",
            "LLVM_PROFILE_FILE",
            "LLVM_PROFILE_FILE_NAME",
            "LLVM_SYMBOLIZER_PATH",
            "LSAN_OPTIONS",
            "MSAN_OPTIONS",
            "PAUTHTEST_RESOURCE_DIR",
            "PAUTHTEST_SYSROOT",
            "RUSTC",
            "RUSTC_BOOTSTRAP",
            "RUSTC_LINKER",
            "RUSTC_STAGE",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "RUSTDOC",
            "RUSTDOCFLAGS",
            "RUSTFMT",
            "RUST_LIBFUZZER_DEBUG_PATH",
            "RUST_LIBC_UNSTABLE_GNU_FILE_OFFSET_BITS",
            "RUST_LIBC_UNSTABLE_GNU_TIME_BITS",
            "RUSTFLAGS",
            "RUSTUP_TOOLCHAIN",
            "TSAN_OPTIONS",
            "UBSAN_OPTIONS",
            "WASI_SYSROOT",
            "WASM_MUSL_SYSROOT",
        }
    )
)
CONTROL_ENVIRONMENT = frozenset({ARTIFACT_ENVIRONMENT})
INJECTION_ENVIRONMENT = frozenset(
    {
        "BASH_ENV",
        "BASHOPTS",
        "CDPATH",
        "ENV",
        "GIT_ALTERNATE_OBJECT_DIRECTORIES",
        "GIT_CONFIG",
        "GIT_CONFIG_COUNT",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_PARAMETERS",
        "GIT_CONFIG_SYSTEM",
        "GIT_COMMON_DIR",
        "GIT_DIR",
        "GIT_EXEC_PATH",
        "GIT_GRAFT_FILE",
        "GIT_INDEX_FILE",
        "GIT_NAMESPACE",
        "GIT_NO_REPLACE_OBJECTS",
        "GIT_OBJECT_DIRECTORY",
        "GIT_REPLACE_REF_BASE",
        "GIT_WORK_TREE",
        "GLOBIGNORE",
        "LD_LIBRARY_PATH",
        "LD_PRELOAD",
        "PYTHONHOME",
        "PYTHONINSPECT",
        "PYTHONPATH",
        "PYTHONSTARTUP",
        "SHELLOPTS",
    }
)
INJECTION_ENVIRONMENT_PREFIXES = (
    "AGENC_STAGE3_",
    "BASH_FUNC_",
    "DYLD_",
    "GIT_",
    "GIT_CONFIG_KEY_",
    "GIT_CONFIG_VALUE_",
    "LD_",
    "PYTHON",
)
BUILD_OVERRIDE_PREFIXES = (
    "CARGO_BUILD_",
    "CARGO_PROFILE_",
    "CARGO_TARGET_",
    "CARGO_LLVM_",
    "__CARGO_LLVM_",
)
NATIVE_TARGET_OVERRIDE_PREFIXES = tuple(
    f"{name}_" for name in NATIVE_TARGET_OVERRIDE_ENVIRONMENT
)


class GateError(ValueError):
    """A gate manifest or command execution failure."""


sys.dont_write_bytecode = True


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
        and not name.startswith(NATIVE_TARGET_OVERRIDE_PREFIXES)
    }
    environment.update(FIXED_COMMAND_ENVIRONMENT)
    environment.update(reviewed)
    return environment


def utc_timestamp() -> str:
    """Return a canonical UTC timestamp for evidence records."""
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace(
        "+00:00", "Z"
    )


EXCLUSIVE_LANE = "exclusive"
DISK_PROFILE = ("--profile", "disk")
LANE_TARGETS = {
    # The exclusive lane reruns the storage suite's build, so it shares that lane's artifacts.
    EXCLUSIVE_LANE: "stage-storage",
}
STAGE_SCRIPT_STAGES = {"six", "seven", "eight"}
# Eighths of the host's cores that a lane's test runner may use. Every test lane running 64
# threads at once starved the daemons under test until their 20-second socket reads timed
# out; a lane's wall time is set by its few long tests, not by its thread count, so the
# lanes share the machine instead. The exclusive lane runs alone and keeps every core.
LANE_TEST_SHARE = {
    "tests": 3,
    "coverage": 3,
    "stage-tests": 1.5,
    "stage-storage": 1.5,
    "scripts": 3,
    "matrix": 1,
}
LANE_BUILD_SHARE = 3
BULK_TARGET_ENVIRONMENT = "AGENC_IRCD_GATE_BULK_TARGET"
BULK_LANES = {
    "check-host",
    "check-x86_64-unknown-linux-gnu",
    "check-aarch64-unknown-linux-gnu",
    "clippy",
    "matrix",
    "stage-tests",
}
# Commands that start real daemons and talk to them under wall-clock timeouts. Those tests
# fail on a saturated host (issue #175), so one such command runs at a time; every other
# command still overlaps with it.
DAEMON_TEST_SCRIPTS = ("-transcripts.sh", "-soak.sh", "-load.sh")


def starts_daemons(argv: list[str]) -> bool:
    """Return whether one reviewed command runs the daemon integration tests."""
    if argv[:2] == ["cargo", "llvm-cov"]:
        return True
    if argv[:3] == ["cargo", "nextest", "run"]:
        return "--workspace" in argv
    return argv[0] == "bash" and argv[-1].endswith(DAEMON_TEST_SCRIPTS)


def gate_lane(argv: list[str]) -> str:
    """Return the lane of one reviewed command.

    Commands of one lane run in manifest order; lanes run concurrently, each Cargo lane in
    its own target directory so no lane waits for another's build lock. The exclusive lane
    runs alone after every other lane has finished: the storage qualification workload
    measures its filesystem's free space to the byte and fails beside any other writer.
    """
    text = " ".join(argv)
    if argv[:3] == ["cargo", "nextest", "run"] and tuple(argv[-2:]) == DISK_PROFILE:
        return EXCLUSIVE_LANE
    if "fuzz" in text:
        return "fuzz"
    if argv[:2] == ["cargo", "llvm-cov"] or argv[:3] == [
        "python3",
        "scripts/check-coverage.py",
        "check",
    ]:
        return "coverage"
    if argv[:2] == ["cargo", "check"]:
        return "check-" + (argv[argv.index("--target") + 1] if "--target" in argv else "host")
    if argv[:2] == ["cargo", "clippy"]:
        return "clippy"
    if argv[:2] == ["cargo", "test"] or (
        argv[:3] == ["cargo", "nextest", "run"] and "--workspace" in argv
    ):
        return "tests"
    if argv[:3] == ["cargo", "nextest", "run"]:
        return "stage-storage" if "agenc-ircd-storage" in argv else "stage-tests"
    if argv[0] == "bash" and argv[1:] == ["scripts/check-stage-nine-matrix.sh"]:
        return "matrix"
    if argv[0] == "bash" and len(argv) == 2 and argv[1].startswith("scripts/run-stage-"):
        stage = argv[1].removeprefix("scripts/run-stage-").split("-", 1)[0]
        if stage in STAGE_SCRIPT_STAGES:
            return "scripts"
    return "static"


def lane_directory(root: Path, lane: str, inherited: Mapping[str, str]) -> Path:
    """Return a lane's target directory.

    Test daemons commit durably, and their commits stall for seconds while other lanes write
    build output to the same filesystem; the daemon tests then miss their socket deadlines.
    A host with a second filesystem names a directory on it in BULK_TARGET_ENVIRONMENT, and
    the lanes that only compile build there. Lanes that start daemons, and the storage lanes
    whose qualification workload needs the build root's filesystem, stay under `target/`.
    """
    name = LANE_TARGETS.get(lane, lane)
    bulk = inherited.get(BULK_TARGET_ENVIRONMENT)
    if bulk and lane in BULK_LANES:
        path = Path(bulk)
        if not path.is_absolute() or not path.is_dir():
            raise GateError(f"{BULK_TARGET_ENVIRONMENT} must name an existing absolute directory")
        return path / "lanes" / name
    return root / "target" / "lanes" / name


def lane_environment(root: Path, lane: str, environment: dict[str, str]) -> dict[str, str]:
    """Give a Cargo lane its own target directory and its share of the host."""
    if lane in {"static", "fuzz"}:
        return environment
    directory = lane_directory(root, lane, os.environ)
    lane_state = {"CARGO_TARGET_DIR": str(directory)}
    if lane != EXCLUSIVE_LANE:
        cores = len(os.sched_getaffinity(0))
        lane_state["CARGO_BUILD_JOBS"] = str(max(4, cores * LANE_BUILD_SHARE // 8))
        share = LANE_TEST_SHARE.get(lane)
        if share is not None:
            lane_state["NEXTEST_TEST_THREADS"] = str(max(2, round(cores * share / 8)))
    return {**environment, **lane_state}


class LaneRunner:
    """Run the lanes of one gate and keep their results in manifest order."""

    def __init__(self, root: Path, commands: list[dict[str, object]]) -> None:
        self.root = root
        self.commands = commands
        self.results: list[CommandResult | None] = [None] * len(commands)
        self.failure: str | None = None
        self.lock = threading.Lock()
        self.daemon_tests = threading.Lock()
        self.running: set[subprocess.Popen[bytes]] = set()

    def run_command(self, index: int, lane: str) -> bool:
        # With the compile-only lanes on another filesystem the daemons' commits no longer
        # queue behind build output, so the daemon commands may overlap as well.
        if os.environ.get(BULK_TARGET_ENVIRONMENT) or not starts_daemons(
            self.commands[index]["argv"]  # type: ignore[arg-type]
        ):
            return self.run_admitted(index, lane)
        with self.daemon_tests:
            return self.run_admitted(index, lane)

    def run_admitted(self, index: int, lane: str) -> bool:
        command = self.commands[index]
        argv = command["argv"]
        reviewed = command.get("environment", {})
        environment = lane_environment(
            self.root, lane, command_environment(os.environ, reviewed)  # type: ignore[arg-type]
        )
        with tempfile.TemporaryFile() as output:
            started_at = utc_timestamp()
            started = time.monotonic()
            with self.lock:
                if self.failure is not None:
                    return False
                process = subprocess.Popen(  # noqa: S603 - reviewed argv, no shell
                    argv,  # type: ignore[arg-type]
                    cwd=self.root,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=output,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
                self.running.add(process)
            returncode = process.wait()
            ended_at = utc_timestamp()
            elapsed = time.monotonic() - started
            output.seek(0)
            with self.lock:
                self.running.discard(process)
                stopped = self.failure is not None
                if not stopped:
                    sys.stdout.write(f"+ [{lane}] " + " ".join(argv) + "\n")  # type: ignore[arg-type]
                    sys.stdout.flush()
                    sys.stdout.buffer.write(output.read())
                    sys.stdout.write(f"= {elapsed:.1f}s [{lane}] " + " ".join(argv) + "\n")  # type: ignore[arg-type]
                    sys.stdout.flush()
                if returncode != 0 and not stopped:
                    self.failure = f"command failed with status {returncode}: {argv!r}"
                    for other in self.running:
                        try:
                            os.killpg(other.pid, signal.SIGTERM)
                        except ProcessLookupError:
                            pass
        if returncode != 0 or stopped:
            return False
        self.results[index] = {
            "argv": list(argv),  # type: ignore[arg-type]
            "environment": dict(reviewed),  # type: ignore[arg-type]
            "started_at": started_at,
            "ended_at": ended_at,
            "exit_code": returncode,
        }
        return True

    def run_lane(self, lane: str, indexes: list[int]) -> None:
        for index in indexes:
            if not self.run_command(index, lane):
                return

    def run(self) -> list[CommandResult]:
        lanes: dict[str, list[int]] = {}
        for index, command in enumerate(self.commands):
            lanes.setdefault(gate_lane(command["argv"]), []).append(index)  # type: ignore[arg-type]
        exclusive = lanes.pop(EXCLUSIVE_LANE, [])
        threads = [
            threading.Thread(target=self.run_lane, args=(lane, indexes), name=lane)
            for lane, indexes in lanes.items()
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join()
        if self.failure is None:
            self.run_lane(EXCLUSIVE_LANE, exclusive)
        if self.failure is not None:
            raise GateError(self.failure)
        if any(result is None for result in self.results):
            raise GateError("a gate lane ended without running every command")
        return [result for result in self.results if result is not None]


def execute(root: Path, name: str) -> list[CommandResult]:
    """Execute one gate and return manifest-ordered, output-free command results."""
    return LaneRunner(root, resolve_commands(load_gates(root), name)).run()


def evidence_policy(root: Path) -> dict[str, object]:
    """Load the checked-in evidence policy without creating a second policy copy."""
    return runpy.run_path(
        str(root / "scripts/check-evidence.py"),
        run_name="agenc_ircd_evidence_policy",
    )


def git_environment(inherited: Mapping[str, str]) -> dict[str, str]:
    """Return process state that cannot redirect or rewrite Git object reads."""
    environment = {
        name: value
        for name, value in command_environment(inherited, {}).items()
        if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_GRAFT_FILE": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return environment


def git_output(root: Path, arguments: list[str], label: str) -> bytes:
    """Run one bounded Git query and return its stdout."""
    completed = subprocess.run(
        [
            "git",
            "--no-replace-objects",
            f"--work-tree={root.resolve()}",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            *arguments,
        ],
        cwd=root,
        env=git_environment(os.environ),
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
    """Return HEAD after matching its index, worktree, and allowed generated files."""
    shallow = git_output(
        root,
        ["rev-parse", "--is-shallow-repository"],
        "repository history",
    ).strip()
    if shallow != b"false":
        if shallow == b"true":
            raise GateError("recorded gates require complete Git history")
        raise GateError("Git returned an invalid shallow-repository state")
    commit = git_output(
        root,
        ["rev-parse", "--verify", "HEAD^{commit}"],
        "source commit",
    ).decode("ascii", errors="strict").strip()
    if len(commit) != 40 or any(character not in "0123456789abcdef" for character in commit):
        raise GateError("Git returned a noncanonical source commit")

    flags = git_output(root, ["ls-files", "-v", "-z", "--"], "Git index flags")
    flagged_paths: list[str] = []
    for record in flags.split(b"\0"):
        if not record:
            continue
        if len(record) < 3 or record[1:2] != b" ":
            raise GateError("Git returned a malformed index-flag record")
        if record[:1] != b"H":
            flagged_paths.append(record[2:].decode("utf-8", errors="replace"))
    if flagged_paths:
        shown = ", ".join(sorted(flagged_paths)[:8])
        if len(flagged_paths) > 8:
            shown += ", ..."
        raise GateError(f"recorded gates reject hidden Git index flags: {shown}")

    index_tree = git_output(root, ["write-tree"], "Git index tree").strip()
    head_tree = git_output(
        root,
        ["rev-parse", "--verify", "HEAD^{tree}"],
        "source tree ID",
    ).strip()
    if index_tree != head_tree:
        raise GateError("recorded gates require the Git index tree to equal HEAD")

    tree = git_output(
        root,
        ["ls-tree", "-rz", "--full-tree", commit],
        "source worktree inventory",
    )
    changed_paths: list[str] = []
    for record in tree.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            mode, kind, object_id = metadata.split(b" ", 2)
        except ValueError as error:
            raise GateError("Git returned a malformed source-tree record") from error
        components = raw_path.split(b"/")
        if (
            not raw_path
            or any(component in {b"", b".", b".."} for component in components)
            or kind != b"blob"
            or mode not in {b"100644", b"100755", b"120000"}
        ):
            display = raw_path.decode("utf-8", errors="replace")
            raise GateError(f"source tree contains an unsupported entry: {display}")
        relative = Path(*(os.fsdecode(component) for component in components))
        candidate = root / relative
        cursor = root
        invalid_parent = False
        for component in relative.parts[:-1]:
            cursor /= component
            try:
                parent_status = cursor.lstat()
            except OSError:
                invalid_parent = True
                break
            if cursor.is_symlink() or not stat.S_ISDIR(parent_status.st_mode):
                invalid_parent = True
                break
        try:
            candidate_status = candidate.lstat()
        except OSError:
            changed_paths.append(raw_path.decode("utf-8", errors="replace"))
            continue
        if invalid_parent:
            changed_paths.append(raw_path.decode("utf-8", errors="replace"))
            continue
        expected = git_output(
            root,
            ["cat-file", "blob", object_id.decode("ascii", errors="strict")],
            raw_path.decode("utf-8", errors="replace"),
        )
        if mode == b"120000":
            if not stat.S_ISLNK(candidate_status.st_mode):
                changed_paths.append(raw_path.decode("utf-8", errors="replace"))
                continue
            observed = os.fsencode(os.readlink(candidate))
        else:
            expected_executable = mode == b"100755"
            observed_executable = bool(candidate_status.st_mode & 0o111)
            if (
                not stat.S_ISREG(candidate_status.st_mode)
                or observed_executable != expected_executable
            ):
                changed_paths.append(raw_path.decode("utf-8", errors="replace"))
                continue
            try:
                observed = candidate.read_bytes()
            except OSError:
                changed_paths.append(raw_path.decode("utf-8", errors="replace"))
                continue
        if observed != expected:
            changed_paths.append(raw_path.decode("utf-8", errors="replace"))
    if changed_paths:
        shown = ", ".join(sorted(changed_paths)[:8])
        if len(changed_paths) > 8:
            shown += ", ..."
        raise GateError(f"recorded gates require worktree bytes from HEAD: {shown}")

    untracked = git_output(
        root,
        ["ls-files", "--others", "--exclude-standard", "-z", "--"],
        "untracked worktree files",
    )
    unexpected_untracked: list[str] = []
    for raw_path in untracked.split(b"\0"):
        if not raw_path:
            continue
        relative = Path(os.fsdecode(raw_path))
        if relative.parent != ARTIFACT_DIRECTORY or relative.suffix != ".json":
            unexpected_untracked.append(raw_path.decode("utf-8", errors="replace"))
    if unexpected_untracked:
        shown = ", ".join(sorted(unexpected_untracked)[:8])
        if len(unexpected_untracked) > 8:
            shown += ", ..."
        raise GateError(f"recorded gates reject untracked source inputs: {shown}")

    ignored = git_output(
        root,
        [
            "ls-files",
            "--others",
            "--ignored",
            "--exclude-standard",
            "--directory",
            "-z",
            "--",
        ],
        "ignored worktree files",
    )
    unexpected_ignored = [
        raw_path.decode("utf-8", errors="replace")
        for raw_path in ignored.split(b"\0")
        if raw_path and raw_path not in ALLOWED_IGNORED_DIRECTORIES
    ]
    if unexpected_ignored:
        shown = ", ".join(sorted(unexpected_ignored)[:8])
        if len(unexpected_ignored) > 8:
            shown += ", ..."
        raise GateError(f"recorded gates reject ignored source inputs: {shown}")
    return commit


def bounded_command_runner() -> object:
    """Load the shared bounded child-process runner."""
    try:
        probe_support = runpy.run_path(
            str(Path(__file__).resolve().with_name("check-rust-components.py")),
            run_name="agenc_ircd_bounded_probe_support",
        )
        run_bounded = probe_support["run_bounded"]
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise GateError(f"cannot load bounded command support: {error}") from error
    if not callable(run_bounded):
        raise GateError("bounded command support is not callable")
    return run_bounded


def rust_host(root: Path) -> str:
    """Return the host target reported by the pinned Rust compiler."""
    run_bounded = bounded_command_runner()
    try:
        completed = run_bounded(  # type: ignore[operator]
            ["rustc", "--version", "--verbose"],
            cwd=root,
            environment=command_environment(os.environ, {}),
            timeout_seconds=TOOLCHAIN_PROBE_TIMEOUT_SECONDS,
        )
    except (OSError, TypeError, ValueError) as error:
        raise GateError(f"cannot query the Rust host target: {error}") from error
    if completed.returncode != 0:
        raise GateError("rustc did not report the evidence target")
    if completed.stderr:
        raise GateError("rustc wrote to stderr while reporting the evidence target")
    try:
        output = completed.stdout.decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise GateError("rustc returned a non-UTF-8 host target report") from error
    for line in output.splitlines():
        if line.startswith("host: "):
            target = line.removeprefix("host: ")
            if target:
                return target
    raise GateError("rustc output did not contain a host target")


def probe_toolchain(
    root: Path, expected_tools: list[dict[str, object]]
) -> list[dict[str, object]]:
    """Probe the reviewed tools and return their exact ordered identities."""
    environment = command_environment(os.environ, {})
    run_bounded = bounded_command_runner()
    observed: list[dict[str, object]] = []
    for expected in expected_tools:
        name = expected.get("name")
        argv = expected.get("argv")
        version = expected.get("version")
        if (
            set(expected) != {"name", "argv", "version"}
            or not isinstance(name, str)
            or not name
            or not isinstance(argv, list)
            or not argv
            or any(not isinstance(argument, str) or not argument for argument in argv)
            or not isinstance(version, str)
            or not version
        ):
            raise GateError("evidence policy returned a malformed toolchain entry")
        try:
            completed = run_bounded(  # type: ignore[operator]
                argv,
                cwd=root,
                environment=environment,
                timeout_seconds=TOOLCHAIN_PROBE_TIMEOUT_SECONDS,
            )
        except (OSError, TypeError, ValueError) as error:
            raise GateError(f"cannot execute toolchain probe {name}: {error}") from error
        if completed.returncode != 0:
            raise GateError(
                f"toolchain probe failed with status {completed.returncode}: {name}"
            )
        if completed.stderr:
            raise GateError(f"toolchain probe wrote to stderr: {name}")
        expected_stdout = (version + "\n").encode("utf-8")
        if completed.stdout != expected_stdout:
            raise GateError(f"toolchain probe returned an unexpected version: {name}")
        observed.append({"name": name, "argv": list(argv), "version": version})
    return observed


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
        load_toolchain_policy = policy["load_toolchain_policy"]
        reviewed_features = policy["REVIEWED_EVIDENCE_FEATURES"]
        reviewed_targets = policy["REVIEWED_EVIDENCE_TARGETS"]
        validate_catalog(root)  # type: ignore[operator]
        source_hash = canonical_source_sha256(root, source_commit)  # type: ignore[operator]
        lock_hash = commit_blob_sha256(root, source_commit, "Cargo.lock")  # type: ignore[operator]
        required_ids = required_stage_evidence_ids(  # type: ignore[operator]
            root, stage, source_commit
        )
        inventory = closure_evidence_inventory(required_ids)  # type: ignore[operator]
        toolchain_policy_sha256, toolchain, limitations = load_toolchain_policy(  # type: ignore[operator]
            root, stage
        )
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise GateError(f"cannot resolve evidence metadata: {error}") from error
    target = rust_host(root)
    if not isinstance(reviewed_targets, tuple) or target not in reviewed_targets:
        raise GateError(f"Rust host target is not conforming for evidence: {target}")
    if reviewed_features != ("all-features",):
        raise GateError("evidence feature profile differs from the reviewed policy")
    return {
        "stage": stage,
        "source_commit": source_commit,
        "source_sha256": source_hash,
        "lock_sha256": lock_hash,
        "target": target,
        "features": list(reviewed_features),
        "toolchain_policy_sha256": toolchain_policy_sha256,
        "toolchain": toolchain,
        "limitations": limitations,
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
        "schema_version": 2,
        "gate": gate,
        "gate_manifest_sha256": hashlib.sha256(
            (root / MANIFEST_PATH).read_bytes()
        ).hexdigest(),
        "toolchain_policy_sha256": metadata["toolchain_policy_sha256"],
        "toolchain": metadata["toolchain"],
        "limitations": metadata["limitations"],
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
    destination_linked = False
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
        destination_linked = True
        temporary_path.unlink()
        temporary_path = None
        directory_descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        rollback_errors: list[str] = []
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError as cleanup_error:
                rollback_errors.append(f"temporary file: {cleanup_error}")
        if destination_linked:
            try:
                destination.unlink()
            except OSError as cleanup_error:
                rollback_errors.append(f"destination: {cleanup_error}")
        rollback = ""
        if rollback_errors:
            rollback = "; rollback failed for " + ", ".join(rollback_errors)
        raise GateError(
            f"cannot create evidence artifact {relative}: {error}{rollback}"
        ) from error
    try:
        print(f"gate evidence artifact: {relative}", flush=True)
    except (OSError, ValueError):
        sys.stdout = None


def fail(message: str) -> NoReturn:
    """Report one stable gate error and exit unsuccessfully."""
    print(f"gate runner failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def record_gate(root: Path, gate: str) -> None:
    """Run and attest one exact-source gate without publishing partial evidence."""
    metadata = artifact_metadata(root, gate)
    source_commit = str(metadata["source_commit"])
    destination, relative = evidence_artifact_path(root, gate, source_commit)
    toolchain_before = probe_toolchain(root, metadata["toolchain"])  # type: ignore[arg-type]
    started_at = utc_timestamp()
    command_results = execute(root, gate)
    ended_at = utc_timestamp()
    toolchain_after = probe_toolchain(root, metadata["toolchain"])  # type: ignore[arg-type]
    if toolchain_after != toolchain_before:
        raise GateError("toolchain identity changed while the recorded gate was running")
    metadata["toolchain"] = toolchain_before
    final_source_commit = require_clean_source(root)
    if final_source_commit != metadata["source_commit"]:
        raise GateError("source HEAD changed while the recorded gate was running")
    write_artifact(
        root,
        destination,
        relative,
        gate,
        metadata,
        started_at,
        ended_at,
        command_results,
    )


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
        record_gate(root, arguments.gate)
    except (GateError, OSError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
