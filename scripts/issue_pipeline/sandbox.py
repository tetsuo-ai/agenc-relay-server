"""Pinned local-container filesystem boundary with executable refusal controls."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
import uuid

from .config import Config, private_directory
from .containers import ContainerError, record_created_container
from .gitops import GitError, _process

ARTIFACT_PREFIX = "conformance/evidence/artifacts/"
STORAGE_FIXTURE_TARGET = "crates/agenc-ircd-storage/target"
FUZZ_ARTIFACT_TARGET = "fuzz/artifacts"
QUALIFICATION_TEMP_TARGETS = ("target/tmp", "target/llvm-cov-target/tmp")
QUALIFICATION_TEMP_BYTES = 8 * 1024 ** 3
IMAGE = "sha256:a6f81fb630d51837271b89f8193810a5fc493fa4f30a55d7ebcdb3a66f3cc63a"
DOCKER_HOST = "unix:///var/run/docker.sock"
DEPENDENCY_CACHE_PATHS = ("registry/src", "registry/cache", "git/checkouts", "git/db")
CACHE_CONTROL_TEXT = "benign dependency read-only canary\n"
CACHE_SEED_TEXT = "public-crates-io-only-v1\n"
CACHE_SEED_SECONDS = 180
MAX_REGISTRY_ROOTS = 32


class SandboxFailure(RuntimeError):
    """The qualified filesystem boundary could not be prepared."""


def _record(path: Path, value: dict) -> None:
    with path.open("x", encoding="utf-8") as stream:
        os.fchmod(stream.fileno(), 0o600)
        json.dump(value, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _private_cache_directory(path: Path) -> None:
    if any(component.is_symlink() for component in (path, *path.parents)):
        raise SandboxFailure("private Cargo cache must not traverse symlinks")
    try:
        private_directory(path)
    except (OSError, ValueError) as error:
        raise SandboxFailure("private Cargo cache directory is unsafe") from error


def _cache_control_valid(path: Path, expected: str) -> bool:
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise SandboxFailure("private Cargo cache control cannot be safely opened") from error
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or metadata.st_mode & 0o022
                or metadata.st_size != len(expected.encode())
                or stream.read(len(expected.encode()) + 1) != expected.encode()):
            raise SandboxFailure("private Cargo cache control is invalid; preserve it for inspection")
    return True


def _ensure_cache_control(path: Path, expected: str) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    except FileExistsError:
        if not _cache_control_valid(path, expected):
            raise SandboxFailure("private Cargo cache control disappeared")
        return
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(expected.encode())
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _registry_inventory(path: Path, deadline: float):
    with os.scandir(path) as entries:
        count = 0
        for entry in entries:
            if entry.name != ".gate-readonly-canary":
                count += 1
            if count > MAX_REGISTRY_ROOTS:
                raise SandboxFailure("Cargo registry inventory exceeds its startup bound")
            if time.monotonic() >= deadline:
                raise SandboxFailure("public Cargo cache seeding exceeded its startup deadline")
            yield Path(entry.path)


def prepare_cargo_cache(config: Config) -> Path:
    """Prepare all first-session and gate cache inputs after owned child cleanup.

    Host registry sources remain read-only inputs to this one-time copy. Package
    bodies are read-only during candidate execution; index/advisory metadata uses
    this dedicated cache. No host configuration, credentials, bin, git sources or
    private registries are copied. Missing packages require trusted prefetch.
    """
    deadline = time.monotonic() + CACHE_SEED_SECONDS
    cargo_home = config.state / "gate-cache" / "cargo"
    _private_cache_directory(cargo_home)
    marker = cargo_home / ".public-registry-seeded"
    seeded = _cache_control_valid(marker, CACHE_SEED_TEXT)
    for relative in (*DEPENDENCY_CACHE_PATHS, "registry/index", "advisory-db"):
        _private_cache_directory(cargo_home / relative)
    for category in ("cache", "src", "index"):
        for path in _registry_inventory(cargo_home / "registry" / category, deadline):
            if path.name.startswith(".seed-"):
                raise SandboxFailure("interrupted public Cargo seed remains; stop the service and inspect the retained .seed-* directory before retry")
    if not seeded:
        original = Path(os.environ.get("CARGO_HOME", str(Path.home() / ".cargo"))).absolute()
        if any(path.is_symlink() for path in (original, *original.parents)):
            raise SandboxFailure("public Cargo source must not traverse symlinks")
        for category in ("cache", "src", "index"):
            source = original / "registry" / category
            destination = cargo_home / "registry" / category
            if any(path.is_symlink() for path in (source, source.parent)):
                raise SandboxFailure("public Cargo registry source must not traverse symlinks")
            if not source.exists():
                continue
            if not source.is_dir():
                raise SandboxFailure("public Cargo registry source is not a directory")
            for registry in _registry_inventory(source, deadline):
                if not (re.fullmatch(r"index\.crates\.io-[0-9a-f]{16}", registry.name)
                        or registry.name == "github.com-1ecc6299db9ec823"):
                    continue
                if registry.is_symlink() or not registry.is_dir():
                    raise SandboxFailure("public Cargo registry root is unsafe")
                target = destination / registry.name
                if target.exists() or target.is_symlink():
                    _private_cache_directory(target)
                    continue
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise SandboxFailure("public Cargo cache seeding exceeded its startup deadline")
                staged = destination / (".seed-" + uuid.uuid4().hex)
                try:
                    result = subprocess.run(["cp", "--archive", "--reflink=auto", "--", str(registry), str(staged)],
                                            stdin=subprocess.DEVNULL, capture_output=True,
                                            timeout=remaining, check=False)
                except (OSError, subprocess.TimeoutExpired) as error:
                    raise SandboxFailure("public Cargo cache seeding failed; retain partial cache for diagnosis") from error
                if result.returncode:
                    raise SandboxFailure("public Cargo cache seeding failed; retain partial cache for diagnosis")
                if not staged.is_dir() or staged.is_symlink():
                    raise SandboxFailure("public Cargo cache copy did not produce its owned directory")
                _private_cache_directory(staged)
                staged.rename(target)
    for relative in DEPENDENCY_CACHE_PATHS:
        _ensure_cache_control(cargo_home / relative / ".gate-readonly-canary", CACHE_CONTROL_TEXT)
    _ensure_cache_control(marker, CACHE_SEED_TEXT)
    return cargo_home


# This bootstrap executes before *any* candidate Python, Rust, test or build script.
# Its controls use only files created by this controller containing benign text.
# Successfully parsing sandbox options is insufficient: some user-systemd builds
# accept filesystem restrictions without enforcing them on the child.
_FILESYSTEM_BOOTSTRAP = r'''
import errno, json, os, pathlib, stat, subprocess, sys, tempfile
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
if (os.stat(request["scratch"]).st_dev != request["scratch_device"]
        or os.statvfs(request["scratch"]).f_flag != request["scratch_mount_flags"]):
    raise RuntimeError("private scratch changed its bound filesystem tuple")
if os.getuid() != request["uid"] or os.getgid() != request["gid"]:
    raise RuntimeError("gate changed the caller's UID/GID")
if os.statvfs(request["home"]).f_flag != request["home_mount_flags"]:
    raise RuntimeError("private HOME changed qualified filesystem mount flags")
if os.stat(request["home"]).st_dev != request["home_device"]:
    raise RuntimeError("private HOME is not on the bound host filesystem")
if str(pathlib.Path.home()) != request["home"]:
    raise RuntimeError("gate changed the caller's HOME environment")
temporary_devices = set()
mountinfo = pathlib.Path("/proc/self/mountinfo").read_text().splitlines()
for temporary in request["temporary_mounts"]:
    path = temporary["path"]
    metadata = os.stat(path)
    capacity = os.statvfs(path)
    if (metadata.st_dev in request["disk_devices"] or metadata.st_dev in temporary_devices
            or metadata.st_uid != request["uid"] or metadata.st_gid != request["gid"]
            or stat.S_IMODE(metadata.st_mode) != 0o700):
        raise RuntimeError("qualification scratch is not an independent private filesystem")
    if capacity.f_blocks * capacity.f_frsize != temporary["size_bytes"]:
        raise RuntimeError("qualification scratch does not have its exact bounded capacity")
    required_flags = os.ST_NOSUID | os.ST_NODEV | os.ST_NOEXEC
    if capacity.f_flag & required_flags != required_flags:
        raise RuntimeError("qualification scratch lacks its restrictive mount flags")
    entries = []
    for line in mountinfo:
        left, separator, right = line.partition(" - ")
        fields = left.split()
        if not separator or len(fields) < 6:
            raise RuntimeError("invalid private mount inventory")
        target = fields[4]
        for escaped, value in ((r"\040", " "), (r"\011", "\t"), (r"\012", "\n"), (r"\134", "\\")):
            target = target.replace(escaped, value)
        if target == path:
            entries.append(right.split()[0])
    if entries != ["tmpfs"]:
        raise RuntimeError("qualification scratch is not the exact tmpfs mount")
    with tempfile.TemporaryFile(dir=path) as stream:
        stream.write(b"benign isolated qualification fixture")
        stream.seek(0)
        if stream.read() != b"benign isolated qualification fixture":
            raise RuntimeError("isolated qualification fixture write failed")
    temporary_devices.add(metadata.st_dev)
    print("agenc-pipeline private qualification scratch " + json.dumps({
        "path": path, "device": metadata.st_dev, "size_bytes": temporary["size_bytes"],
        "mode": oct(stat.S_IMODE(metadata.st_mode)), "mount_flags": capacity.f_flag}), flush=True)
home_scratch = pathlib.Path(request["home_scratch"])
home_scratch.mkdir(mode=0o700)
(home_scratch / "canary").write_text("benign private HOME fixture canary\n")
if (home_scratch / "canary").read_text() != "benign private HOME fixture canary\n":
    raise RuntimeError("private HOME fixture scratch failed its positive control")
for command in (["git", "write-tree"], ["cargo", "--version"],
                ["rustc", "--version"], ["cc", "--version"], ["python3", "--version"]):
    subprocess.run(command, cwd=request["worktree"], check=True, timeout=30)
print("agenc-pipeline filesystem isolation verified", flush=True)
if not request["probe_only"]:
    os.execvp("bash", ["bash", "scripts/check-stage-nine.sh"])
'''


def filesystem_command(config: Config, repo, worktree: Path, output: Path,
                       *, probe_only: bool = False) -> list[str]:
    """Build a pinned local Docker command, recording ownership before launch.

    HOME and UID are unchanged. A dedicated disk-backed HOME preserves the exact
    storage qualification tuple; host credentials and process/runtime sockets are
    absent. Every candidate begins by executing denial and positive controls.
    """
    docker = shutil.which("docker")
    if docker is None:
        raise SandboxFailure("qualified gate filesystem containment requires local Docker")
    executable = Path(docker).resolve(strict=True)
    info = executable.stat()
    if info.st_uid != 0 or not stat.S_ISREG(info.st_mode) or info.st_mode & 0o022:
        raise SandboxFailure("gate requires a root-owned non-writable Docker client")
    home = Path.home().resolve(strict=True)
    worktree, output = Path(worktree).resolve(strict=True), Path(output).resolve(strict=True)
    private_directory(config.state / "gates")
    common = Path(repo.run(["rev-parse", "--path-format=absolute", "--git-common-dir"], cwd=worktree).strip()).resolve(strict=True)
    administration = Path(repo.run(["rev-parse", "--absolute-git-dir"], cwd=worktree).strip()).resolve(strict=True)
    if (not administration.is_relative_to(common / "worktrees")
            or not worktree.is_relative_to(config.worktrees.resolve())
            or output.parent != config.state / "gates"):
        raise SandboxFailure("gate sandbox requires this controller's detached validation worktree")
    cargo_home = prepare_cargo_cache(config)
    dependency_sources = [cargo_home / relative for relative in DEPENDENCY_CACHE_PATHS]
    dependency_canaries = [str(path / ".gate-readonly-canary") for path in dependency_sources]
    scratch = config.state / "gate-cache" / "tmp"
    private_directory(scratch)
    rustup_executable = shutil.which("rustup")
    if rustup_executable is None:
        raise SandboxFailure("qualified gate filesystem containment requires rustup")
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
            raise SandboxFailure("gate sandbox paths must be explicit nonsymlink paths beneath the existing home")
    generated = [worktree / "target", worktree / "fuzz/target", worktree / ARTIFACT_PREFIX]
    for path in generated:
        if path.is_symlink() or not path.resolve().is_relative_to(worktree):
            raise SandboxFailure("gate generated directory escapes its worktree")
        path.mkdir(parents=True, exist_ok=True)
    # Cargo runs a package's test binaries from that package directory. Storage
    # fixtures create current_dir()/target, independently of Cargo's build target.
    # cargo-fuzz also creates artifacts/<target> before every run, even with an
    # explicit temporary corpus. Keep both source parents immutable and put only
    # these exact output directories on the disk-backed generated root. Never
    # mask tracked inputs or adopt files at an unowned destination.
    fixture_mounts = []
    for label, relative in (("storage", STORAGE_FIXTURE_TARGET), ("fuzz", FUZZ_ARTIFACT_TARGET)):
        fixture_target = worktree / relative
        if (any(path.is_symlink() for path in (fixture_target, *fixture_target.parents))
                or not fixture_target.parent.is_dir()
                or repo.run(["ls-files", "--", relative], cwd=worktree).strip()
                or (fixture_target.exists()
                    and (not fixture_target.is_dir() or any(fixture_target.iterdir())))):
            raise SandboxFailure(label + " fixture mount would mask source or unowned files")
        fixture_target.mkdir(exist_ok=True)
        fixture_backing = generated[0] / (".issue-pipeline-" + label + "-fixtures-" + uuid.uuid4().hex)
        private_directory(fixture_backing)
        fixture_mounts.append((fixture_backing, fixture_target))
    # Qualification tests compare filesystem-wide free-space samples. Isolate
    # their compile-time Cargo temporary roots from unrelated host disk writes.
    temporary_mounts = []
    for relative in QUALIFICATION_TEMP_TARGETS:
        path = worktree / relative
        if (any(parent.is_symlink() for parent in (path, *path.parents))
                or repo.run(["ls-files", "--", relative], cwd=worktree).strip()
                or (path.exists() and (not path.is_dir() or any(path.iterdir())))):
            raise SandboxFailure("qualification temporary mount would mask source or unowned files")
        path.mkdir(parents=True, exist_ok=True)
        temporary_mounts.append({"path": str(path), "size_bytes": QUALIFICATION_TEMP_BYTES})
    # The source artifact directory may contain historic tracked receipts; protect
    # every existing file while allowing the runner's new exact-source artifact.
    existing_artifacts = [path for path in generated[-1].rglob("*") if path.is_file()]
    if any(path.is_symlink() for path in generated[-1].rglob("*")):
        raise SandboxFailure("gate artifact directory contains a symlink")
    canary = config.state / ("gate-hidden-canary-" + uuid.uuid4().hex)
    with canary.open("x") as stream:
        stream.write("benign gate hidden canary\n")
    readonly = output / "readonly-canary"
    with readonly.open("x") as stream:
        stream.write("benign gate read-only canary\n")
    unit_record = json.loads((output / "unit.json").read_text())
    unit = unit_record.get("unit", "")
    source = unit_record.get("source", "")
    if (not re.fullmatch(r"agenc-ircd-pipeline-gate-[0-9a-f]{32}\.service", unit)
            or not re.fullmatch(r"[0-9a-f]{40}", source)
            or unit_record.get("state_dir") != str(config.state)
            or unit_record.get("repository") != config.repository
            or repo.head(worktree) != source):
        raise SandboxFailure("sandbox has no matching durable gate ownership record")
    private_home = config.state / "gate-cache" / "homes" / uuid.uuid4().hex
    private_directory(private_home)
    # runc must find every destination before the private ancestor is remounted
    # read-only; creating a missing child mountpoint would otherwise fail closed.
    for path in readable:
        (private_home / path.relative_to(home)).mkdir(parents=True, exist_ok=True, mode=0o700)
    home_scratch = home / (".agenc-ircd-pipeline-home-probe-" + uuid.uuid4().hex)
    if home_scratch.exists() or home_scratch.is_symlink():
        raise SandboxFailure("private HOME positive-control path already exists on the host")
    bootstrap = {"denied": [str(canary), f"/proc/{os.getpid()}/root{canary}",
                            "/var/run/docker.sock", "/run/user/" + str(os.getuid()) + "/bus"],
                 "readonly": [str(readonly), str(worktree / "scripts/check-stage-nine.sh"),
                              str(output / "unit.json"), *dependency_canaries],
                 "scratch": "/tmp", "scratch_device": os.stat(scratch).st_dev,
                 "scratch_mount_flags": os.statvfs(scratch).f_flag,
                 "home": str(home), "home_scratch": str(home_scratch),
                 "home_mount_flags": os.statvfs(private_home).f_flag,
                 "home_device": os.stat(private_home).st_dev,
                 "temporary_mounts": temporary_mounts,
                 "disk_devices": sorted({os.stat(path).st_dev for path in
                     (private_home, scratch, worktree, output, *generated)}),
                 "uid": os.getuid(), "gid": os.getgid(),
                 "worktree": str(worktree), "probe_only": probe_only}
    # Mount private empty ancestors read-only, not host HOME ancestors. This also
    # prevents rename/replacement of a protected mount's otherwise writable parent.
    readonly_parents = set()
    for path in readable:
        readonly_parents.update(parent for parent in path.parents if parent != home and parent.is_relative_to(home))
    mounts = {}
    def bind(path, target=None, *, readonly=True):
        path, target = Path(path), Path(target or path)
        if any(char in str(path) + str(target) for char in "\n\r,"):
            raise SandboxFailure("unsafe container bind path")
        mounts[str(target)] = {"source": str(path), "target": str(target), "readonly": readonly}
    bind(private_home, home, readonly=False)
    # Unix socket fixtures append unique names; expose the disk-backed scratch
    # at a short private path so their names remain below Linux sun_path limits.
    bind(scratch, Path("/tmp"), readonly=False)
    for backing, target in fixture_mounts:
        bind(backing, target, readonly=False)
    for parent in readonly_parents:
        virtual = private_home / parent.relative_to(home)
        virtual.mkdir(parents=True, exist_ok=True, mode=0o700)
        bind(virtual, parent)
    # Host compiler entrypoints such as /usr/bin/cc resolve through alternatives.
    for path in (Path("/usr"), Path("/etc/alternatives"), Path("/etc/ssl/certs"), *readable):
        bind(path)
    for path in (administration, cargo_home, scratch, *generated):
        bind(path, readonly=False)
    bind(cargo_home / "registry")
    bind(cargo_home / "registry/index", readonly=False)
    bind(cargo_home / "git")
    for path in dependency_sources:
        bind(path)
    for name in ("HEAD", "gitdir", "commondir"):
        if (administration / name).is_file():
            bind(administration / name)
    for path in existing_artifacts:
        bind(path)
    name = unit.removesuffix(".service")
    labels = {"agenc-ircd.pipeline.state": str(config.state),
              "agenc-ircd.pipeline.source": source, "agenc-ircd.pipeline.unit": unit,
              "agenc-ircd.pipeline.purpose": "full-gate",
              "agenc-ircd.pipeline.repository": config.repository}
    _record(output / "container.json", {"version": 1, "backend": "docker", "name": name,
            "image": IMAGE, "source": source, "unit": unit, "state_dir": str(config.state),
            "repository": config.repository, "private_home": str(private_home), "labels": labels})

    # Persist the exact mounts and controls alongside the immutable ownership.
    ordered = [mounts[target] for target in sorted(mounts, key=lambda p: (len(Path(p).parts), p))]
    _record(output / "filesystem-policy.json", {"backend": "docker", "image": IMAGE,
            "mounts": ordered, "temporary_mounts": temporary_mounts, "bootstrap": bootstrap})
    argv = [str(executable), "--host", DOCKER_HOST, "create", "--pull=never", "--log-driver=none", "--name", name,
            "--user", f"{os.getuid()}:{os.getgid()}", "--cap-drop=ALL",
            "--security-opt=no-new-privileges", "--read-only", "--pids-limit=4096",
            "--memory=" + str(config.gate_memory_gib) + "g",
            "--cpus=" + str(config.gate_cpu_percent / 100),
            "--tmpfs", "/run:rw,nosuid,nodev",
            "--tmpfs", "/var/tmp:rw,nosuid,nodev"]
    for key, value in labels.items():
        argv += ["--label", key + "=" + value]
    for mount in ordered:
        value = "type=bind,source=" + mount["source"] + ",target=" + mount["target"]
        argv += ["--mount", value + (",readonly" if mount["readonly"] else "")]
    for temporary in temporary_mounts:
        argv += ["--tmpfs", temporary["path"] + ":rw,nosuid,nodev,noexec,size="
                 + str(temporary["size_bytes"]) + ",uid=" + str(os.getuid())
                 + ",gid=" + str(os.getgid()) + ",mode=0700"]
    argv += ["--workdir", str(worktree), IMAGE, "/usr/bin/env", "-i",
             "PATH=" + os.environ.get("PATH", "/usr/bin:/bin"),
             "HOME=" + str(Path.home()), "USER=" + os.environ.get("USER", ""),
             "CARGO_HOME=" + str(cargo_home), "RUSTUP_HOME=" + str(rustup),
             "TMPDIR=/tmp", "AGENC_IRCD_RECORD_GATE=1",
             "/usr/bin/python3", "-I", "-B", "-c", _FILESYSTEM_BOOTSTRAP,
             json.dumps(bootstrap, separators=(",", ":"))]
    # Creation is inert. A lost response can never authorize candidate execution.
    # Persist the verified immutable ID before the launcher may submit a start;
    # cleanup can then remove that ID even if a delayed start RPC is outstanding.
    cleared = ["/usr/bin/env", "-i", "PATH=" + os.environ.get("PATH", "/usr/bin:/bin"),
               "HOME=" + str(Path.home()), "USER=" + os.environ.get("USER", "")]
    try:
        result, returned_id = _process([*cleared, *argv], worktree, 60)
        if result:
            raise SandboxFailure("inert gate container creation failed; retain ownership for recovery")
        identity = record_created_container(output / "container.json", config.state, returned_id.strip())
    except (GitError, ContainerError) as error:
        raise SandboxFailure("gate container identity is unproven; no start authorized") from error
    return [*cleared, str(executable), "--host", DOCKER_HOST, "start", "--attach", identity]
