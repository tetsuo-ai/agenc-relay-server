"""Run the required recorded gate and validate complete exact-source evidence."""
from __future__ import annotations

from collections import Counter
import json
import math
import os
from pathlib import Path
import re
import signal
import shutil
import stat
import subprocess
import sys
import threading
import tomllib
import uuid

from .config import Config, digest_file, private_directory
from .containers import ContainerError, stop_owned_container
from .gitops import GitError, _process

GATE = "stage-nine-implementation"
ARTIFACT_PREFIX = "conformance/evidence/artifacts/"
MAX_ARTIFACT_BYTES = 4 * 1024 * 1024
PROTECTED_PATHS = frozenset({
    "scripts/run-gate.py", "scripts/check-stage-nine.sh", "scripts/check-evidence.py",
    "scripts/check-source.py", "scripts/check-coverage.py", "scripts/check-ci.py",
    "scripts/requirements.py", "conformance/toolchain-policy.toml", "rust-toolchain.toml",
})


class GateFailure(RuntimeError):
    """A check failed or evidence could not be authenticated to the source."""


def filesystem_command(config: Config, repo, worktree: Path, output: Path,
                       *, probe_only: bool = False) -> list[str]:
    """Prepare the qualified sandbox while retaining the gate's failure API."""
    from .sandbox import SandboxFailure, filesystem_command as build
    try:
        return build(config, repo, worktree, output, probe_only=probe_only)
    except (SandboxFailure, ValueError, OSError) as error:
        raise GateFailure("gate filesystem containment failed: " + str(error)) from error


def commands(manifest: dict, name: str = GATE, stack: tuple = ()) -> list[dict]:
    """Expand closed, typed commands and coverage-only bootstrap environment."""
    if (type(manifest) is not dict or set(manifest) != {"schema_version", "gate"}
            or type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1
            or not isinstance(manifest["gate"], dict)):
        raise GateFailure("invalid gate manifest schema")
    if name in stack or len(stack) > 100:
        raise GateFailure("gate include cycle or excessive depth")
    gate = manifest["gate"].get(name)
    if not isinstance(gate, dict) or set(gate) - {"includes", "command"}:
        raise GateFailure("invalid required gate")
    includes, raw = gate.get("includes", []), gate.get("command", [])
    if (not isinstance(includes, list) or any(type(item) is not str for item in includes)
            or not isinstance(raw, list)):
        raise GateFailure("invalid gate includes or commands")
    result = []
    for other in includes:
        result.extend(commands(manifest, other, stack + (name,)))
        if len(result) > 10_000:
            raise GateFailure("required gate exceeds the command bound")
    for command in raw:
        if (not isinstance(command, dict) or set(command) - {"argv", "environment"}
                or not isinstance(command.get("argv"), list) or not command["argv"]
                or any(type(v) is not str or not v or "\0" in v for v in command["argv"])
                or not isinstance(command.get("environment", {}), dict)):
            raise GateFailure("invalid gate command")
        environment = command.get("environment", {})
        if set(environment) - {"RUSTC_BOOTSTRAP"} or any(type(v) is not str for v in environment.values()):
            raise GateFailure("unreviewed gate environment")
        if environment and (environment != {"RUSTC_BOOTSTRAP": "1"}
                            or command["argv"][:2] != ["cargo", "llvm-cov"]):
            raise GateFailure("bootstrap is restricted to the coverage invocation")
        result.append({"argv": command["argv"], "environment": environment})
    if not result or len(result) > 10_000:
        raise GateFailure("required gate is empty or exceeds the command bound")
    return result


def check_policy(repo, base: str, candidate: str) -> list[dict]:
    """Ordinary workers cannot weaken policy or rewrite trusted gate machinery."""
    old = tomllib.loads(repo.run(["show", base + ":conformance/gates.toml"]))
    new = tomllib.loads(repo.run(["show", candidate + ":conformance/gates.toml"]))
    required, proposed = commands(old), commands(new)
    canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
    if Counter(map(canonical, required)) - Counter(map(canonical, proposed)):
        raise GateFailure("candidate removes or changes a required gate command; explicit policy review is needed")
    position = 0
    for command in proposed:
        if position < len(required) and command == required[position]:
            position += 1
    if position != len(required):
        raise GateFailure("candidate reorders required gate commands")
    protected = set(PROTECTED_PATHS)
    for command in required:
        protected.update(arg for arg in command["argv"] if arg.startswith("scripts/"))
    changed = repo.run(["diff", "--name-only", "-z", base, candidate, "--"]).split("\0")
    for path in changed:
        if (path in protected or path.startswith("scripts/issue_pipeline")
                or path in {"scripts/issue-pipeline.py", "scripts/test-issue-pipeline.py"}):
            raise GateFailure("candidate changes trusted validation/controller code: " + path)
    for path in ("conformance/critical-coverage.toml", "conformance/release-critical-coverage.toml"):
        before = tomllib.loads(repo.run(["show", base + ":" + path]))
        after = tomllib.loads(repo.run(["show", candidate + ":" + path]))
        for key, value in before.items():
            if key.startswith("minimum_") or key == "critical_region_percent":
                floor = after.get(key)
                if (type(value) not in (int, float) or not math.isfinite(value)
                        or type(floor) not in (int, float) or not math.isfinite(floor)
                        or not value <= floor <= 100):
                    raise GateFailure("candidate lowers or invalidates coverage policy: " + path + ":" + key)
    return proposed


# Isolated imports prevent another checkout's cached requirements module from
# substituting policy. check_policy protects the imported files against edits.
_VALIDATE = r'''
import json, pathlib, runpy, sys, tempfile
root = pathlib.Path(sys.argv[1])
sys.path.insert(0, str(root / "scripts"))
policy = runpy.run_path(str(root / "scripts/check-evidence.py"), run_name="pipeline_evidence")
request = json.load(sys.stdin)
source, tree = request["source"], request["tree"]
actual = policy["git_bytes"](root, ["rev-parse", source + "^{tree}"], "candidate tree").decode().strip()
if actual != tree:
    raise ValueError("candidate tree differs from controller identity")
source_hash = policy["canonical_source_sha256"](root, source)
tool_hash, tools, limitations = policy["source_toolchain_policy"](root, 9, source)
required = policy["required_stage_evidence_ids"](root, 9, source)
with tempfile.TemporaryDirectory(prefix="agenc-gate-validate-") as temporary:
    artifact = pathlib.Path(temporary) / "artifact.json"
    artifact.write_text(json.dumps(request["artifact"], allow_nan=False))
    policy["validate_run_artifact"](
        artifact, [], required, gate_name="stage-nine-implementation",
        runner_hash=policy["commit_blob_sha256"](root, source, "scripts/run-gate.py"),
        gate_hash=policy["commit_blob_sha256"](root, source, "conformance/gates.toml"),
        expected_commands=request["commands"], toolchain_policy_hash=tool_hash,
        expected_toolchain=tools, expected_limitations=limitations,
        source_commit=source, source_hash=source_hash,
        lock_hash=policy["commit_blob_sha256"](root, source, "Cargo.lock"),
    )
print("validated")
'''


def validate_artifact(value: dict, source: str, tree: str, worktree: Path,
                      expected_commands: list[dict]) -> dict:
    """Check the full artifact with the unchanged repository evidence contract."""
    if (type(value) is not dict or type(value.get("schema_version")) is not int
            or value["schema_version"] != 2 or value.get("gate") != GATE
            or value.get("source_commit") != source or value.get("result") != "passed"
            or type(value.get("exit_code")) is not int or value["exit_code"] != 0):
        raise GateFailure("gate artifact is not a passing record for the exact candidate")
    if any(type(sha) is not str or re.fullmatch(r"[0-9a-f]{40}", sha) is None for sha in (source, tree)):
        raise GateFailure("gate requires exact source and tree identities")
    if (value.get("lock_sha256") != digest_file(worktree / "Cargo.lock")
            or value.get("gate_manifest_sha256") != digest_file(worktree / "conformance/gates.toml")):
        raise GateFailure("gate artifact lockfile or manifest differs")
    try:
        if len(json.dumps(value, allow_nan=False).encode()) > MAX_ARTIFACT_BYTES:
            raise GateFailure("gate artifact exceeds its four-MiB bound")
        request = json.dumps({"artifact": value, "source": source, "tree": tree,
                              "commands": expected_commands}, allow_nan=False).encode()
        environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(Path.home())}
        code, result = _process([sys.executable, "-I", "-B", "-c", _VALIDATE, str(worktree)],
                                worktree, 120, request, environment)
    except (OSError, ValueError, GitError) as error:
        raise GateFailure("gate evidence validation could not complete") from error
    if code != 0 or result.strip() != "validated":
        raise GateFailure("gate artifact failed complete source/toolchain/command/timing validation")
    return {"source": source, "tree": tree, "commands": len(expected_commands), "result": "passed"}


def _json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise GateFailure("duplicate artifact JSON field")
        result[key] = value
    return result


def _nonfinite(value):
    raise GateFailure("nonfinite artifact JSON: " + value)


def _read_artifact(artifact: Path) -> bytes:
    """Bound allocation and refuse links, devices, directories or foreign files."""
    for parent in artifact.parents:
        if parent.is_symlink():
            raise GateFailure("gate artifact parent is a symlink")
    fd = os.open(artifact, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or info.st_uid != os.getuid()
                or info.st_size > MAX_ARTIFACT_BYTES):
            raise GateFailure("gate artifact is not a bounded singly owned regular file")
        data = stream.read(MAX_ARTIFACT_BYTES + 1)
        if len(data) > MAX_ARTIFACT_BYTES:
            raise GateFailure("gate artifact grew past its record bound")
        return data


def _retain(artifact: Path, output: Path, data: bytes, successful: bool) -> Path:
    retained = output / ("gate-artifact.json" if successful else "gate-artifact-failed.json")
    with retained.open("xb") as stream:
        stream.write(data)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    artifact.unlink()
    return retained


class GateRunner:
    """Serialize full gates; uncertainty about process cleanup stops the runner."""

    def __init__(self, config: Config):
        self.config = config
        self._lock = threading.Lock()
        self._active_lock = threading.Lock()
        self._active: set[str] = set()
        self._containers: dict[str, Path] = {}
        self._launchers: dict[str, subprocess.Popen] = {}
        self._cancelled = threading.Event()

    def _stop_unit(self, unit: str) -> None:
        # The local systemd client may not have registered its unit yet. Quiesce
        # that client first; otherwise it could submit a start after an absence
        # check. Known container-ID removal also defeats an already queued start.
        with self._active_lock:
            launcher = self._launchers.get(unit)
        try:
            if launcher is not None and launcher.poll() is None:
                try:
                    os.killpg(launcher.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                launcher.wait(timeout=10)
        except (OSError, subprocess.TimeoutExpired) as error:
            self._cancelled.set()
            raise GateFailure("gate launcher cleanup is uncertain; further execution is blocked") from error
        try:
            result = subprocess.run(["systemctl", "--user", "stop", unit], timeout=30,
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            if result.returncode:
                raise GateFailure("initial service stop failed")
        except (OSError, subprocess.TimeoutExpired, GateFailure):
            try:
                subprocess.run(["systemctl", "--user", "kill", "--kill-whom=all", "--signal=KILL", unit],
                               timeout=15, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
                subprocess.run(["systemctl", "--user", "stop", unit], timeout=15,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
        try:
            result = subprocess.run(["systemctl", "--user", "show", unit,
                                     "--property=LoadState,ActiveState,MainPID,ControlPID,ControlGroup"],
                                    timeout=10, capture_output=True, text=True, check=False)
            rows = [line.split("=", 1) for line in result.stdout.splitlines()]
            valid_rows = all(len(row) == 2 for row in rows)
            props = dict(rows) if valid_rows else {}
            expected = {"LoadState", "ActiveState", "MainPID", "ControlPID", "ControlGroup"}
            quiet = (result.returncode == 0 and valid_rows and len(rows) == len(expected)
                     and set(props) == expected and props.get("LoadState") in {"loaded", "not-found"}
                     and props.get("ActiveState") in {"inactive", "failed"}
                     and props.get("MainPID") == "0" and props.get("ControlPID") == "0")
            group = props.get("ControlGroup", "")
            if group:
                if not group.startswith("/") or ".." in Path(group).parts:
                    quiet = False
                else:
                    events = Path("/sys/fs/cgroup") / group.lstrip("/") / "cgroup.events"
                    if events.exists() and "populated 0" not in events.read_text().splitlines():
                        quiet = False
            if not quiet:
                raise GateFailure("gate process group is not confirmed inactive")
            with self._active_lock:
                container_record = self._containers.get(unit)
            if container_record is not None:
                stop_owned_container(container_record, self.config.state)
                policy = json.loads(container_record.with_name("filesystem-policy.json").read_text())
                scratch = Path(policy["bootstrap"]["home_scratch"])
                if scratch.exists() or scratch.is_symlink():
                    raise GateFailure("sandbox scratch escaped into the real HOME")
        except (OSError, subprocess.TimeoutExpired, GateFailure, ContainerError, ValueError, KeyError) as error:
            self._cancelled.set()
            raise GateFailure("gate cleanup is uncertain; further execution is blocked: " + unit) from error

    def cancel(self) -> None:
        self._cancelled.set()
        with self._active_lock:
            names = list(self._active)
        failures = []
        for name in names:
            try:
                self._stop_unit(name)
            except GateFailure as error:
                failures.append(str(error))
        if failures:
            raise GateFailure("; ".join(failures))

    @staticmethod
    def _clean_source(repo, worktree: Path, source: str) -> None:
        if repo.head(worktree) != source:
            raise GateFailure("gate candidate HEAD changed")
        try:
            if repo.run(["diff", "HEAD", "--exit-code"], cwd=worktree):
                raise GateFailure("gate changed tracked source")
        except GitError as error:
            raise GateFailure("gate changed tracked source") from error

    def run(self, repo, worktree: Path, source: str, base: str, output: Path) -> dict:
        with self._lock:
            if self._cancelled.is_set():
                raise GateFailure("controller stopping or prior gate cleanup uncertain")
            if shutil.disk_usage(worktree).free < self.config.minimum_free_gib * 2**30:
                raise GateFailure("insufficient free disk for the isolated full gate")
            if repo.head(worktree) != source or repo.run(["status", "--porcelain"], cwd=worktree):
                raise GateFailure("gate requires the exact clean committed candidate")
            expected = check_policy(repo, base, source)
            tree = repo.tree(source)
            private_directory(output)
            artifact = worktree / ARTIFACT_PREFIX / f"{GATE}-{source}.json"
            if artifact.exists() or artifact.is_symlink():
                raise GateFailure("refusing preexisting gate evidence")
            log = output / "full-gate.log"
            if not self.config.use_systemd:
                raise GateFailure("production full gates require systemd process containment")
            unit = "agenc-ircd-pipeline-gate-" + uuid.uuid4().hex + ".service"
            # Durable ownership must precede any service start. Recovery reads
            # only records beneath this controller's private state directory.
            record = {"unit": unit, "source": source, "state_dir": str(self.config.state),
                      "repository": self.config.repository}
            with (output / "unit.json").open("x", encoding="utf-8") as stream:
                json.dump(record, stream, sort_keys=True)
                stream.flush()
                os.fsync(stream.fileno())
            directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
            try:
                sandboxed = filesystem_command(self.config, repo, worktree, output)
            except GateFailure:
                # An unresolved inert create cannot run code, but its durable
                # ownership must be reconciled before another gate is admitted.
                if (output / "container.json").exists():
                    self._cancelled.set()
                raise
            argv = ["systemd-run", "--user", "--quiet", "--wait", "--collect", "--pipe",
                    "--service-type=exec", "--expand-environment=no", "--unit=" + unit,
                    "-p", "KillMode=control-group", "-p", "TimeoutStopSec=15s",
                    "-p", "RuntimeMaxSec=" + str(self.config.gate_timeout_seconds),
                    "-p", "CPUQuota=" + str(self.config.gate_cpu_percent) + "%",
                    "-p", "MemoryMax=" + str(self.config.gate_memory_gib) + "G",
                    "--working-directory=" + str(worktree), *sandboxed]
            with self._active_lock:
                self._active.add(unit)
                if (output / "container.json").exists():
                    self._containers[unit] = output / "container.json"
                cancelled = self._cancelled.is_set()
            if cancelled:
                self._stop_unit(unit)
                with self._active_lock:
                    self._active.discard(unit)
                    self._containers.pop(unit, None)
                raise GateFailure("controller stopped before gate launch")
            quiescent = False
            retained: Path | None = None
            try:
                try:
                    with log.open("xb") as stream:
                        with self._active_lock:
                            if self._cancelled.is_set():
                                raise GateFailure("controller stopped before gate launch")
                            launcher = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                                        stderr=subprocess.STDOUT, start_new_session=True)
                            self._launchers[unit] = launcher
                        returncode = launcher.wait(timeout=self.config.gate_timeout_seconds + 45)
                        stream.flush()
                        os.fsync(stream.fileno())
                    if returncode:
                        raise GateFailure(f"mandatory gate failed (exit {returncode}); log {log}")
                except subprocess.TimeoutExpired as error:
                    raise GateFailure("mandatory gate timed out: " + str(log)) from error
                except OSError as error:
                    raise GateFailure("mandatory gate launcher failed: " + str(log)) from error
                finally:
                    self._stop_unit(unit)
                    quiescent = True
                if self._cancelled.is_set():
                    raise GateFailure("controller stopped during gate")
                self._clean_source(repo, worktree, source)
                if not artifact.exists() and not artifact.is_symlink():
                    raise GateFailure("successful exit did not produce exact-source gate evidence")
                data = _read_artifact(artifact)
                try:
                    value = json.loads(data, object_pairs_hook=_json_object, parse_constant=_nonfinite)
                except (ValueError, RecursionError) as error:
                    raise GateFailure("gate emitted malformed artifact JSON") from error
                receipt = validate_artifact(value, source, tree, worktree, expected)
                self._clean_source(repo, worktree, source)
                retained = _retain(artifact, output, data, True)
                if repo.run(["status", "--porcelain"], cwd=worktree):
                    raise GateFailure("gate left unexpected uncommitted files")
                receipt.update({"base": base, "artifact_hashes": {
                    "gate": digest_file(retained), "log": digest_file(log)},
                    "artifact": str(retained), "log": str(log)})
                return receipt
            finally:
                if quiescent:
                    with self._active_lock:
                        self._active.discard(unit)
                        self._containers.pop(unit, None)
                        self._launchers.pop(unit, None)
                # Preserve partial/malformed output as diagnostics, never proof.
                # Only remove our exact new regular file after process quiescence.
                if quiescent and retained is None and (artifact.exists() or artifact.is_symlink()):
                    self._clean_source(repo, worktree, source)
                    _retain(artifact, output, _read_artifact(artifact), False)
