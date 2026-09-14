"""Exact worker command permissions, qualified with benign controls per session.

Codex permission profiles and legacy --sandbox settings must not be mixed.
https://learn.chatgpt.com/docs/permissions
https://learn.chatgpt.com/docs/config-file/config-reference
"""
from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import shutil
import stat
import sys
import uuid

from .config import private_directory
from .gitops import GitError, _process


@dataclass(frozen=True)
class PermissionProfile:
    argv: tuple[str, ...]
    environment: dict[str, str]
    profile: str
    probe_argv: tuple[str, ...]


def _toml(value):
    if type(value) is str:
        return json.dumps(value)
    if type(value) is bool:
        return "true" if value else "false"
    if type(value) is dict:
        return "{" + ",".join(json.dumps(key) + "=" + _toml(item) for key, item in value.items()) + "}"
    raise ValueError("unsupported permission configuration type")


def _canonical(path: Path) -> Path:
    path = Path(path).absolute()
    if (path != path.resolve(strict=True) or any(parent.is_symlink() for parent in (path, *path.parents))
            or any(char in str(path) for char in "\n\r\x00*?[]")):
        raise ValueError("permission paths must be exact existing canonical paths")
    return path


def _ordinary_file(path: Path) -> Path:
    path = _canonical(path)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
        raise ValueError("evidence permission requires an exact singly owned ordinary file")
    return path


def _tool_roots(codex_path: str) -> list[Path]:
    executable = shutil.which(codex_path)
    rustup = shutil.which("rustup")
    if executable is None or rustup is None:
        raise ValueError("Codex and rustup are required for command permission qualification")
    codex = Path(executable).resolve(strict=True)
    if codex.name == "codex.js" and codex.parent.name == "bin":
        package = codex.parent.parent
        if json.loads((package / "package.json").read_text()).get("name") != "@openai/codex":
            raise ValueError("unrecognized Codex JavaScript launcher")
        codex = package  # Includes the native platform helper invoked inside bwrap.
    return [codex, Path(rustup).absolute().parent,
            Path(os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup"))).resolve(strict=True),
            Path(sys.base_prefix).resolve(strict=True)]


def _private_cargo(shared: Path, temporary: Path) -> Path:
    """Keep mutable Cargo config/index/locks private; package bodies stay read-only."""
    shared = _canonical(shared)
    cargo = temporary / "cargo"
    private_directory(cargo / "registry")
    for name in ("src", "cache"):
        source = _canonical(shared / "registry" / name)
        (cargo / "registry" / name).symlink_to(source, target_is_directory=True)
    index = _canonical(shared / "registry" / "index")
    code, _ = _process(["cp", "--archive", "--reflink=auto", "--", str(index),
                       str(cargo / "registry" / "index")], temporary, 30)
    if code:
        raise ValueError("private Cargo index preparation failed")
    return cargo


_PROBE = r'''
import errno, json, os, pathlib, subprocess, sys
request = json.loads(sys.argv[1])
for path in request["denied"]:
    try:
        descriptor = os.open(path, os.O_RDONLY)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM, errno.ENOENT, errno.ENOTDIR):
            raise RuntimeError("unexpected read denial result") from error
    else:
        os.close(descriptor)
        raise RuntimeError("worker permissions disclosed a hidden control")
for path in request["readonly"]:
    try:
        descriptor = os.open(path, os.O_WRONLY)
    except OSError as error:
        if error.errno not in (errno.EACCES, errno.EPERM, errno.EROFS):
            raise RuntimeError("unexpected write denial result") from error
    else:
        os.close(descriptor)
        raise RuntimeError("worker permissions allow protected input writes")
if pathlib.Path(request["visible"]).read_text() != "benign read-only worker permission canary\n":
    raise RuntimeError("permission read positive control failed")
for path in request["writable"]:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        stream.write("benign scoped worker write\n")
    if pathlib.Path(path).read_text() != "benign scoped worker write\n":
        raise RuntimeError("permission write positive control failed")
    pathlib.Path(path).unlink()
for command in (["git", "rev-parse", "HEAD"], ["cargo", "--version"],
                ["rustc", "--version"], ["cc", "--version"]):
    subprocess.run(command, cwd=request["worktree"], check=True, timeout=5)
print("agenc-pipeline worker permissions verified", flush=True)
'''


def prepare_permissions(worktree: Path, output_dir: Path, role: str, codex_path: str,
                        *, evidence_paths: tuple[Path, ...] = ()) -> PermissionProfile:
    """Prepare exact permissions; the caller must run probe_argv before model work.

    Apply environment to the trusted Codex process, and argv to ``codex exec``
    with --ignore-user-config. Do not pass any legacy --sandbox option. Profile
    configuration marks this exact worktree and its common repository untrusted,
    preventing candidate project config/hooks/rules from overriding this policy.
    evidence_paths is trusted-controller input, never parsed from a task result.
    """
    if role not in {"planner", "worker", "reviewer"}:
        raise ValueError("unknown permission role")
    if type(evidence_paths) is not tuple or len(evidence_paths) > 32:
        raise ValueError("evidence permissions require a bounded tuple")
    worktree, output_dir = _canonical(worktree), _canonical(output_dir)
    if output_dir.is_relative_to(worktree) or not worktree.is_dir() or not output_dir.is_dir():
        raise ValueError("permission output must be outside its worktree")
    try:
        code, result = _process(["git", "rev-parse", "--path-format=absolute", "--git-common-dir"], worktree, 10)
    except GitError as error:
        raise ValueError("cannot resolve owned common Git inputs") from error
    if code:
        raise ValueError("cannot resolve owned common Git inputs")
    common = _canonical(Path(result.strip()))
    if common.name != ".git" or not (common / "worktrees").is_dir():
        raise ValueError("permission profiles require a linked controller worktree")
    state = common.parent.parent
    if not output_dir.is_relative_to(state) or not worktree.is_relative_to(state / "worktrees"):
        raise ValueError("permission paths do not belong to the controller clone")
    temporary = output_dir / "tmp"
    private_directory(temporary)
    shared_cargo = state / "gate-cache" / "cargo"
    cargo = _private_cargo(shared_cargo, temporary)
    tools = [_canonical(path) for path in _tool_roots(codex_path)]
    profile = "agenc-pipeline-" + role
    filesystem = {":root": "deny", ":minimal": "read", ":slash_tmp": "deny",
                  str(worktree): "write" if role == "worker" else "read",
                  str(worktree / ".git"): "read", str(worktree / ".codex"): "read",
                  str(common): "read", str(temporary): "write", str(shared_cargo): "read"}
    for path in tools:
        if path == Path.home() or path == state or path.is_relative_to(worktree):
            raise ValueError("unsafe tool read permission")
        filesystem[str(path)] = "read"
    selected = []
    for path in evidence_paths:
        path = _ordinary_file(path)
        if not path.is_relative_to(state) or path.is_relative_to(worktree) or path in selected:
            raise ValueError("evidence permission is not one distinct archived controller file")
        selected.append(path)
        filesystem[str(path)] = "read"
    hidden = output_dir / "permission-hidden-canary"
    visible = output_dir / "permission-readonly-canary"
    for path, content in ((hidden, "benign hidden worker permission canary\n"),
                          (visible, "benign read-only worker permission canary\n")):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
    filesystem[str(visible)] = "read"
    environment = {"TMPDIR": str(temporary), "CARGO_HOME": str(cargo),
                   "RUSTUP_HOME": str(Path(os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup"))).resolve())}
    command_environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"),
                           "HOME": str(Path.home()), "USER": os.environ.get("USER", ""), **environment}
    settings = {"default_permissions": profile,
                "permissions": {profile: {"filesystem": filesystem, "network": {"enabled": False}}},
                # CLI override keys are not TOML dotted-key parsers. Put exact
                # quoted project paths in an inline value, not in the -c key.
                "projects": {str(worktree): {"trust_level": "untrusted"},
                             str(common.parent): {"trust_level": "untrusted"}},
                "shell_environment_policy": {"inherit": "none", "set": command_environment}}
    argv = tuple(part for key, value in settings.items() for part in ("-c", key + "=" + _toml(value)))
    readonly = [str(visible), str(worktree / ".git"), str(common / "HEAD")]
    for name in ("src", "cache"):
        canary = shared_cargo / "registry" / name / ".gate-readonly-canary"
        if not canary.is_file() or canary.is_symlink():
            raise ValueError("shared public package cache lacks its trusted read-only control")
        readonly.append(str(canary))
        readonly.append(str(cargo / "registry" / name / ".gate-readonly-canary"))
    if role != "worker":
        readonly.append(str(worktree / "Cargo.toml"))
    key = uuid.uuid4().hex
    writable = [str(temporary / ("write-control-" + key))]
    if role == "worker":
        writable.append(str(worktree / (".permission-write-control-" + key)))
    request = {"denied": [str(hidden), f"/proc/{os.getpid()}/root{hidden}",
                           "/var/run/docker.sock", f"/run/user/{os.getuid()}/bus"],
               "readonly": readonly, "visible": str(visible), "writable": writable,
               "worktree": str(worktree)}
    probe_argv = (codex_path, "sandbox", "-P", profile, "-C", str(worktree), *argv,
                  "/usr/bin/python3", "-I", "-c", _PROBE, json.dumps(request, separators=(",", ":")))
    record = {"profile": profile, "filesystem": filesystem, "environment": environment,
              "probe": request, "evidence_paths": list(map(str, selected))}
    descriptor = os.open(output_dir / "permissions.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return PermissionProfile(argv, environment, profile, probe_argv)
