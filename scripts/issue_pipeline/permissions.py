"""Exact per-session command sandbox policy, qualified with benign controls.

Model commands run inside Claude Code's built-in Bash sandbox (bubblewrap on
Linux) under a closed policy passed on the command line: the home directory,
controller state, host credentials and runtime sockets are hidden; only the
worktree, its common Git metadata, private temporary/Cargo directories, the
read-only toolchain and explicitly copied evidence are readable; the network
namespace is removed. The trusted Claude Code process itself keeps the existing
login; its file tools are confined to the worktree by ``--restricted``.

The same policy is executed by the ``srt`` sandbox-runtime CLI, the library
Claude Code embeds, for the benign positive and denial controls that must pass
before any model work begins. Settings paths follow the documented sandbox
schema: https://code.claude.com/docs/en/sandboxing
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

CREDENTIAL_VARIABLES = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
                        "CLAUDE_CODE_MESSAGING_TOKEN", "GH_TOKEN", "GITHUB_TOKEN", "NPM_TOKEN",
                        "SSH_AUTH_SOCK")
ROLE_TOOLS = {"planner": ("Bash", "Read", "Glob", "Grep"),
              "reviewer": ("Bash", "Read", "Glob", "Grep"),
              "worker": ("Bash", "Read", "Edit", "Write", "Glob", "Grep")}
MAX_EVIDENCE_BYTES = 64 * 1024 * 1024


@dataclass(frozen=True)
class PermissionProfile:
    settings: str
    tools: tuple[str, ...]
    add_dirs: tuple[str, ...]
    environment: dict[str, str]
    profile: str
    probe_argv: tuple[str, ...]
    evidence: tuple[str, ...]


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


def sandbox_runtime_root(sandbox_runtime_path: str) -> Path:
    """Resolve the sandbox-runtime package directory behind the ``srt`` launcher."""
    executable = shutil.which(str(Path(sandbox_runtime_path).expanduser()))
    if executable is None:
        raise ValueError("the srt sandbox-runtime launcher is required for permission qualification")
    launcher = Path(executable).resolve(strict=True)
    package = launcher.parent
    while package != package.parent and not (package / "package.json").is_file():
        package = package.parent
    try:
        name = json.loads((package / "package.json").read_text()).get("name")
    except (OSError, ValueError) as error:
        raise ValueError("unrecognized sandbox-runtime launcher") from error
    if name != "@anthropic-ai/sandbox-runtime":
        raise ValueError("unrecognized sandbox-runtime launcher")
    return package


def _tool_roots(sandbox_runtime_path: str) -> list[Path]:
    rustup = shutil.which("rustup")
    if rustup is None:
        raise ValueError("rustup is required for command permission qualification")
    roots = [sandbox_runtime_root(sandbox_runtime_path), Path(rustup).absolute().parent,
             Path(os.environ.get("RUSTUP_HOME", str(Path.home() / ".rustup"))).resolve(strict=True)]
    python_root = Path(sys.base_prefix).resolve(strict=True)
    if python_root.is_relative_to(Path.home()):
        roots.append(python_root)
    return roots


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


def _copy_evidence(evidence_paths, output_dir: Path, state: Path, worktree: Path) -> tuple[Path | None, list[Path]]:
    """Copy exact controller evidence files into one private read-only session directory."""
    if not evidence_paths:
        return None, []
    directory = output_dir / "evidence"
    private_directory(directory)
    copies = []
    total = 0
    for path in evidence_paths:
        path = _ordinary_file(path)
        if not path.is_relative_to(state) or path.is_relative_to(worktree) or path.is_relative_to(output_dir):
            raise ValueError("evidence permission is not one distinct archived controller file")
        target = directory / path.name
        if target.exists() or target.is_symlink():
            raise ValueError("evidence files must have distinct names")
        total += path.stat().st_size
        if total > MAX_EVIDENCE_BYTES:
            raise ValueError("evidence copies exceed their byte bound")
        with open(path, "rb") as source:
            descriptor = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o400)
            with os.fdopen(descriptor, "wb") as stream:
                shutil.copyfileobj(source, stream)
                stream.flush()
                os.fsync(stream.fileno())
        copies.append(target)
    return directory, copies


_PROBE = r'''
import errno, json, os, pathlib, socket, subprocess, sys
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
for path in request["sockets"]:
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.connect(path)
    except OSError:
        pass
    else:
        raise RuntimeError("worker permissions expose a host control socket")
    finally:
        client.close()
try:
    socket.create_connection(("1.1.1.1", 443), timeout=3).close()
except OSError:
    pass
else:
    raise RuntimeError("worker permissions allow network egress")
for command in (["git", "rev-parse", "HEAD"], ["cargo", "--version"],
                ["rustc", "--version"], ["cc", "--version"]):
    subprocess.run(command, cwd=request["worktree"], check=True, timeout=5)
print("agenc-pipeline worker permissions verified", flush=True)
'''


def prepare_permissions(worktree: Path, output_dir: Path, role: str, sandbox_runtime_path: str,
                        *, evidence_paths: tuple[Path, ...] = ()) -> PermissionProfile:
    """Prepare exact permissions; the caller must run probe_argv before model work.

    ``settings`` is passed to ``claude --settings``; ``tools`` to ``--tools`` and
    ``--allowedTools``; ``add_dirs`` (the worktree first) to ``--add-dir``;
    ``environment`` to the trusted process, whose working directory must be
    ``environment["TMPDIR"]``. evidence_paths is trusted-controller input, never parsed
    from a task result; each file is copied into one private read-only session
    directory that the model may read, and the copies are named in ``evidence``.
    """
    if role not in ROLE_TOOLS:
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
    home = Path.home().resolve(strict=True)
    if not state.is_relative_to(home) or state == home:
        raise ValueError("controller state must live beneath the existing home directory")
    temporary = output_dir / "tmp"
    private_directory(temporary)
    # Sandbox proxy sockets and command temporary files live in a short private
    # runtime directory: Unix socket paths are limited to 107 bytes, which a
    # session directory path exceeds. Cargo metadata keeps the session path.
    # The Claude process also starts in this directory: the sandbox masks
    # shell/Git dotfiles in its working directory by creating mount points
    # there, which must never happen inside a read-only source worktree. The
    # worktree is an added working directory for the file tools instead.
    runtime = state / "runtime" / uuid.uuid4().hex[:12]
    private_directory(runtime)
    shared_cargo = state / "gate-cache" / "cargo"
    cargo = _private_cargo(shared_cargo, temporary)
    tools = [_canonical(path) for path in _tool_roots(sandbox_runtime_path)]
    for path in tools:
        if path == home or path == state or path.is_relative_to(worktree) or path.is_relative_to(state):
            raise ValueError("unsafe tool read permission")
    evidence_dir, evidence = _copy_evidence(evidence_paths, output_dir, state, worktree)
    hidden = output_dir / "permission-hidden-canary"
    visible = output_dir / "permission-readonly-canary"
    for path, content in ((hidden, "benign hidden worker permission canary\n"),
                          (visible, "benign read-only worker permission canary\n")):
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        with os.fdopen(descriptor, "w") as stream:
            stream.write(content)
    profile = "agenc-pipeline-" + role
    rustup_home = Path(os.environ.get("RUSTUP_HOME", str(home / ".rustup"))).resolve()
    environment = {"TMPDIR": str(runtime), "CARGO_HOME": str(cargo), "RUSTUP_HOME": str(rustup_home)}
    # Deny the whole home directory, then reopen only exact session inputs. Read
    # allowances take precedence over the broad denial; write denials take
    # precedence over allowances. Runtime sockets are masked so commands cannot
    # reach Docker or the session bus even though seccomp socket filtering is
    # unavailable on hosts that forbid nested user namespaces.
    filesystem = {
        "denyRead": [str(home) + "/", "/run/docker.sock",
                     "/run/user/" + str(os.getuid())],
        "allowRead": sorted({str(path) for path in (worktree, common, temporary, runtime, shared_cargo, visible,
                                                    *tools, *([evidence_dir] if evidence_dir else []))}),
        "allowWrite": [str(temporary), str(runtime)] + ([str(worktree)] if role == "worker" else []),
        "denyWrite": sorted({str(path) for path in (worktree / ".git", common, shared_cargo, visible,
                                                    *([evidence_dir] if evidence_dir else []),
                                                    *([] if role == "worker" else [worktree]))}),
    }
    network = {"allowedDomains": [], "deniedDomains": [], "strictAllowlist": True,
               "allowAllUnixSockets": True, "allowLocalBinding": False}
    settings = {
        "sandbox": {"enabled": True, "failIfUnavailable": True, "autoAllowBashIfSandboxed": True,
                    "allowUnsandboxedCommands": False, "excludedCommands": [],
                    "network": network, "filesystem": filesystem,
                    "credentials": {"envVars": [{"name": name, "mode": "deny"} for name in CREDENTIAL_VARIABLES]}},
        "permissions": {"defaultMode": "dontAsk",
                        "deny": ["Read(//" + str(home / ".claude").lstrip("/") + "/**)",
                                 "Read(//" + str(home / ".claude.json").lstrip("/") + ")",
                                 "WebFetch", "WebSearch", "Agent", "Task", "NotebookEdit"]},
    }
    probe_settings = {"network": {"allowedDomains": [], "deniedDomains": []}, "filesystem": filesystem}
    descriptor = os.open(output_dir / "sandbox-probe.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(probe_settings, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    readonly = [str(visible), str(worktree / ".git"), str(common / "HEAD")]
    for name in ("src", "cache"):
        canary = shared_cargo / "registry" / name / ".gate-readonly-canary"
        if not canary.is_file() or canary.is_symlink():
            raise ValueError("shared public package cache lacks its trusted read-only control")
        readonly.append(str(canary))
        readonly.append(str(cargo / "registry" / name / ".gate-readonly-canary"))
    if role != "worker":
        readonly.append(str(worktree / "Cargo.toml"))
    readonly.extend(map(str, evidence))
    key = uuid.uuid4().hex
    writable = [str(temporary / ("write-control-" + key)), str(runtime / ("write-control-" + key))]
    if role == "worker":
        writable.append(str(worktree / (".permission-write-control-" + key)))
    request = {"denied": [str(hidden), f"/proc/{os.getpid()}/root{hidden}", str(home / ".claude" / ".credentials.json"),
                           str(home / ".ssh"), str(home / ".config" / "gh"),
                           "/var/run/docker.sock", f"/run/user/{os.getuid()}/bus"],
               "readonly": readonly, "visible": str(visible), "writable": writable,
               "sockets": ["/var/run/docker.sock", "/run/docker.sock", f"/run/user/{os.getuid()}/bus"],
               "worktree": str(worktree)}
    launcher = shutil.which(str(Path(sandbox_runtime_path).expanduser()))
    probe_argv = (str(Path(launcher).resolve(strict=True)), "-s", str(output_dir / "sandbox-probe.json"), "--",
                  "/usr/bin/python3", "-I", "-c", _PROBE, json.dumps(request, separators=(",", ":")))
    record = {"profile": profile, "settings": settings, "environment": environment, "tools": list(ROLE_TOOLS[role]),
              "runtime_dir": str(runtime),
              "add_dirs": [str(worktree)] + ([str(evidence_dir)] if evidence_dir else []), "probe": request,
              "evidence_paths": [str(_canonical(path)) for path in evidence_paths],
              "evidence_copies": list(map(str, evidence))}
    descriptor = os.open(output_dir / "permissions.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w") as stream:
        json.dump(record, stream, sort_keys=True)
        stream.flush()
        os.fsync(stream.fileno())
    return PermissionProfile(json.dumps(settings, separators=(",", ":"), sort_keys=True), ROLE_TOOLS[role],
                             (str(worktree),) + ((str(evidence_dir),) if evidence_dir else ()), environment,
                             profile, probe_argv, tuple(map(str, evidence)))
