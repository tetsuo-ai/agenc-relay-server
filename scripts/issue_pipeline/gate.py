"""Run the required recorded gate and validate complete exact-source evidence."""
from __future__ import annotations

from collections import Counter
import json
import math
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import threading
import tomllib
import uuid

from .config import Config, digest_file, private_directory
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


def prepare_cargo_cache(config: Config) -> Path:
    """Seed a private cache from public crates.io data, never user configuration.

    Host registry sources remain read-only inputs to this one-time copy. Package
    bodies are read-only during candidate execution; index/advisory metadata uses
    this dedicated cache. Missing dependencies require separate trusted prefetch.
    """
    cargo_home = config.state / "gate-cache" / "cargo"
    private_directory(cargo_home)
    marker = cargo_home / ".public-registry-seeded"
    if marker.exists():
        if marker.is_symlink() or marker.read_text() != "public-crates-io-only-v1\n":
            raise GateFailure("private Cargo cache seed marker is invalid")
        return cargo_home
    original = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).resolve()
    for category in ("cache", "src", "index"):
        source = original / "registry" / category
        destination = cargo_home / "registry" / category
        private_directory(destination)
        if source.is_dir() and not source.is_symlink():
            for registry in sorted(source.iterdir()):
                if (registry.is_symlink() or not registry.is_dir()
                        or not (registry.name.startswith("index.crates.io-")
                                or registry.name == "github.com-1ecc6299db9ec823")):
                    continue
                target = destination / registry.name
                if not target.exists():
                    staged = destination / (".seed-" + uuid.uuid4().hex)
                    result = subprocess.run(["cp", "--archive", "--reflink=auto", "--", str(registry), str(staged)],
                                            stdin=subprocess.DEVNULL, capture_output=True,
                                            timeout=180, check=False)
                    if result.returncode:
                        raise GateFailure("public Cargo cache seeding failed; retain partial cache for diagnosis")
                    staged.rename(target)
    for name in ("git", "advisory-db"):
        private_directory(cargo_home / name)
    with marker.open("x") as stream:
        stream.write("public-crates-io-only-v1\n")
        stream.flush()
        os.fsync(stream.fileno())
    return cargo_home


# This bootstrap executes before *any* candidate Python, Rust, test or build script.
# Its controls use only files created by this controller containing benign text.
# Successfully parsing sandbox options is insufficient: some user-systemd builds
# accept filesystem restrictions without enforcing them on the child.
_FILESYSTEM_BOOTSTRAP = r'''
import errno, json, os, pathlib, subprocess, sys, tempfile
request = json.loads(sys.argv[1])
for denied in request["denied"]:
    try:
        fd = os.open(denied, os.O_RDONLY)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR):
            raise RuntimeError("unexpected denial-control failure") from error
    else:
        os.close(fd)
        raise RuntimeError("filesystem isolation did not hide the controller canary")
for readonly in request["readonly"]:
    try:
        fd = os.open(readonly, os.O_WRONLY)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
            raise RuntimeError("unexpected read-only-control failure") from error
    else:
        os.close(fd)
        raise RuntimeError("filesystem isolation permits writes to protected source/receipts")
if pathlib.Path(request["readonly"][0]).read_text() != "benign gate read-only canary\n":
    raise RuntimeError("read-only positive control is not visible")
with tempfile.TemporaryFile(dir=request["scratch"]) as stream:
    stream.write(b"benign gate writable canary")
    stream.seek(0)
    if stream.read() != b"benign gate writable canary":
        raise RuntimeError("private writable scratch failed its positive control")
for command in (["git", "write-tree"], ["cargo", "--version"],
                ["rustc", "--version"], ["python3", "--version"]):
    subprocess.run(command, cwd=request["worktree"], check=True, timeout=30)
print("agenc-pipeline filesystem isolation verified", flush=True)
if not request["probe_only"]:
    os.execvp("bash", ["bash", "scripts/check-stage-nine.sh"])
'''


def filesystem_command(config: Config, repo, worktree: Path, output: Path,
                       *, probe_only: bool = False) -> list[str]:
    """Build the mandatory host-toolchain sandbox command, with executable controls.

    On this host user-systemd mount properties were accepted but silently ignored;
    a root-owned setuid Firejail helper enforces mount/PID isolation inside the
    systemd resource/cleanup unit instead. There is no unsandboxed fallback.
    HOME is unchanged; only explicitly allowed tool/source/cache paths are visible.
    """
    firejail = shutil.which("firejail")
    if firejail is None:
        raise GateFailure("qualified gate filesystem containment requires installed Firejail")
    executable = Path(firejail).resolve(strict=True)
    info = executable.stat()
    if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or not info.st_mode & stat.S_ISUID:
        raise GateFailure("gate requires the qualified root-owned setuid Firejail helper")
    home = Path.home().resolve(strict=True)
    worktree, output = Path(worktree).resolve(strict=True), Path(output).resolve(strict=True)
    common = Path(repo.run(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=worktree).strip()).resolve(strict=True)
    administration = Path(repo.run(["rev-parse", "--absolute-git-dir"], cwd=worktree).strip()).resolve(strict=True)
    if (not administration.is_relative_to(common / "worktrees")
            or not worktree.is_relative_to(config.worktrees.resolve())
            or not output.is_relative_to(config.state)):
        raise GateFailure("gate sandbox requires this controller's detached validation worktree")
    cargo_home = prepare_cargo_cache(config)
    dependency_sources = [cargo_home / "registry/src", cargo_home / "registry/cache",
                          cargo_home / "git/checkouts", cargo_home / "git/db"]
    dependency_canaries = []
    for path in dependency_sources:
        private_directory(path)
        canary_path = path / ".gate-readonly-canary"
        if not canary_path.exists():
            with canary_path.open("x") as stream:
                stream.write("benign dependency read-only canary\n")
        if canary_path.is_symlink() or not canary_path.is_file():
            raise GateFailure("dependency cache read-only control is unsafe")
        dependency_canaries.append(str(canary_path))
    private_directory(cargo_home / "registry/index")
    scratch = config.state / "gate-cache" / "tmp"
    private_directory(scratch)
    rustup_executable = shutil.which("rustup")
    if rustup_executable is None:
        raise GateFailure("qualified gate filesystem containment requires rustup")
    cargo_bin = Path(rustup_executable).absolute().parent
    rustup = Path(os.environ.get("RUSTUP_HOME", str(home / ".rustup"))).resolve(strict=True)
    python_root = Path(sys.base_prefix).resolve(strict=True)
    # Whitelisting HOME itself or its broad ancestors would disclose credentials.
    readable = [cargo_bin, rustup, common, worktree, output, cargo_home, scratch]
    if python_root.is_relative_to(home):
        readable.append(python_root)
    for path in readable:
        if (not path.is_relative_to(home) or path == home or path.is_symlink()
                or any(char in str(path) for char in "\n\r*?[],")):
            raise GateFailure("gate sandbox paths must be explicit nonsymlink paths beneath the existing home")
    generated = [worktree / "target", worktree / "fuzz/target", worktree / ARTIFACT_PREFIX]
    for path in generated:
        if path.is_symlink() or not path.resolve().is_relative_to(worktree):
            raise GateFailure("gate generated directory escapes its worktree")
        path.mkdir(parents=True, exist_ok=True)
    # The source artifact directory may contain historic tracked receipts; protect
    # every existing file while allowing the runner's new exact-source artifact.
    existing_artifacts = [path for path in generated[-1].rglob("*") if path.is_file()]
    if any(path.is_symlink() for path in generated[-1].rglob("*")):
        raise GateFailure("gate artifact directory contains a symlink")
    canary = config.state / ("gate-hidden-canary-" + uuid.uuid4().hex)
    with canary.open("x") as stream:
        stream.write("benign gate hidden canary\n")
    readonly = output / "readonly-canary"
    with readonly.open("x") as stream:
        stream.write("benign gate read-only canary\n")
    bootstrap = {"denied": [str(canary), f"/proc/{os.getpid()}/root{canary}"],
                 "readonly": [str(readonly), str(worktree / "scripts/check-stage-nine.sh"),
                              str(output / "unit.json"), *dependency_canaries],
                 "scratch": str(scratch), "worktree": str(worktree), "probe_only": probe_only}
    # This exact policy is retained alongside the owned-unit record before launch.
    with (output / "filesystem-policy.json").open("x") as stream:
        json.dump({"backend": "firejail", "readable": list(map(str, readable)),
                   "writable": list(map(str, [administration, cargo_home, scratch, *generated])),
                   "bootstrap": bootstrap}, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    argv = [str(executable), "--quiet", "--noprofile", "--caps.drop=all", "--nonewprivs",
            "--nogroups", "--private-dev", "--private-tmp"]
    argv += ["--whitelist=" + str(path) for path in readable]
    argv += ["--read-only=" + str(home), "--read-only=" + str(common),
             "--read-only=" + str(worktree), "--read-only=" + str(output)]
    argv += ["--read-write=" + str(path) for path in [administration, cargo_home, scratch, *generated]]
    # Package bodies and archives are trusted prefetch inputs. Missing packages
    # must be fetched in a separate qualified preparation step, never by allowing
    # candidate build scripts to poison dependency inputs reused by later gates.
    # Protect ancestors too: otherwise a writable Cargo root could rename the
    # registry directory and replace the path with attacker-controlled sources.
    argv += ["--read-only=" + str(cargo_home / "registry"),
             "--read-write=" + str(cargo_home / "registry/index"),
             "--read-only=" + str(cargo_home / "git")]
    argv += ["--read-only=" + str(path) for path in dependency_sources]
    # git write-tree needs the worktree index lock, not permission to redirect
    # HEAD, gitdir or commondir and influence later controller Git operations.
    argv += ["--read-only=" + str(administration / name) for name in ("HEAD", "gitdir", "commondir")
             if (administration / name).is_file()]
    argv += ["--read-only=" + str(path) for path in existing_artifacts]
    argv += ["--blacklist=" + path for path in (f"/run/user/{os.getuid()}", "/run/dbus",
                                               "/run/docker.sock", "/var/run/docker.sock",
                                               "/var/tmp", "/mnt", "/media", "/srv")]
    argv += ["--", "/usr/bin/env", "-i", "PATH=" + os.environ.get("PATH", "/usr/bin:/bin"),
             "HOME=" + str(Path.home()), "USER=" + os.environ.get("USER", ""),
             "CARGO_HOME=" + str(cargo_home), "RUSTUP_HOME=" + str(rustup),
             "TMPDIR=" + str(scratch), "AGENC_IRCD_RECORD_GATE=1",
             "/usr/bin/python3", "-I", "-B", "-c", _FILESYSTEM_BOOTSTRAP,
             json.dumps(bootstrap, separators=(",", ":"))]
    # Clear credentials before the privileged sandbox helper as well as before
    # its child, so a supervisor's inherited environment cannot become a leak.
    return ["/usr/bin/env", "-i", "PATH=" + os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME=" + str(Path.home()), "USER=" + os.environ.get("USER", ""), *argv]


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
        self._cancelled = threading.Event()

    def _stop_unit(self, unit: str) -> None:
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
            props = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
            quiet = (props.get("ActiveState") in {"inactive", "failed"}
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
        except (OSError, subprocess.TimeoutExpired, GateFailure) as error:
            self._cancelled.set()
            raise GateFailure("gate cleanup is uncertain; further execution is blocked: " + unit) from error
        with self._active_lock:
            self._active.discard(unit)

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
            sandboxed = filesystem_command(self.config, repo, worktree, output)
            argv = ["systemd-run", "--user", "--quiet", "--wait", "--collect", "--pipe",
                    "--service-type=exec", "--expand-environment=no", "--unit=" + unit,
                    "-p", "KillMode=control-group", "-p", "TimeoutStopSec=15s",
                    "-p", "RuntimeMaxSec=" + str(self.config.gate_timeout_seconds),
                    "-p", "CPUQuota=" + str(self.config.gate_cpu_percent) + "%",
                    "-p", "MemoryMax=" + str(self.config.gate_memory_gib) + "G",
                    "--working-directory=" + str(worktree), *sandboxed]
            with self._active_lock:
                if self._cancelled.is_set():
                    raise GateFailure("controller stopped before gate launch")
                self._active.add(unit)
            quiescent = False
            retained: Path | None = None
            try:
                try:
                    with log.open("xb") as stream:
                        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=stream,
                                                stderr=subprocess.STDOUT,
                                                timeout=self.config.gate_timeout_seconds + 45, check=False)
                        stream.flush()
                        os.fsync(stream.fileno())
                    if result.returncode:
                        raise GateFailure(f"mandatory gate failed (exit {result.returncode}); log {log}")
                except subprocess.TimeoutExpired as error:
                    raise GateFailure("mandatory gate timed out: " + str(log)) from error
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
                # Preserve partial/malformed output as diagnostics, never proof.
                # Only remove our exact new regular file after process quiescence.
                if quiescent and retained is None and (artifact.exists() or artifact.is_symlink()):
                    self._clean_source(repo, worktree, source)
                    _retain(artifact, output, _read_artifact(artifact), False)
