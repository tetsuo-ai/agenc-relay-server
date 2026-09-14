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
import uuid

from .config import Config, private_directory
from .containers import ContainerError, record_created_container
from .gitops import GitError, _process

ARTIFACT_PREFIX = "conformance/evidence/artifacts/"
STORAGE_FIXTURE_TARGET = "crates/agenc-ircd-storage/target"
IMAGE = "sha256:a6f81fb630d51837271b89f8193810a5fc493fa4f30a55d7ebcdb3a66f3cc63a"
DOCKER_HOST = "unix:///var/run/docker.sock"


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
            raise SandboxFailure("private Cargo cache seed marker is invalid")
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
                        raise SandboxFailure("public Cargo cache seeding failed; retain partial cache for diagnosis")
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
            raise SandboxFailure("dependency cache read-only control is unsafe")
        dependency_canaries.append(str(canary_path))
    private_directory(cargo_home / "registry/index")
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
    # Keep the package source immutable and put only that exact scratch directory
    # on the existing disk-backed generated root. Never mask tracked inputs or
    # adopt files left at an unowned package-local destination.
    fixture_target = worktree / STORAGE_FIXTURE_TARGET
    if (any(path.is_symlink() for path in (fixture_target, *fixture_target.parents))
            or not fixture_target.parent.is_dir()
            or repo.run(["ls-files", "--", STORAGE_FIXTURE_TARGET], cwd=worktree).strip()
            or (fixture_target.exists()
                and (not fixture_target.is_dir() or any(fixture_target.iterdir())))):
        raise SandboxFailure("storage fixture mount would mask source or unowned files")
    fixture_target.mkdir(exist_ok=True)
    fixture_backing = generated[0] / (".issue-pipeline-storage-fixtures-" + uuid.uuid4().hex)
    private_directory(fixture_backing)
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
    bind(fixture_backing, fixture_target, readonly=False)
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
            "mounts": ordered, "bootstrap": bootstrap})
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
