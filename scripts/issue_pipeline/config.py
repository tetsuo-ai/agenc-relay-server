"""Explicit trusted controller policy; never load policy from an agent worktree."""
from __future__ import annotations

from dataclasses import dataclass, fields
from pathlib import Path
import hashlib
import os
import re
import shutil
import tomllib


@dataclass(frozen=True)
class Config:
    repository: str = "tetsuo-ai/agenc-ircd"
    master_issue: int = 35
    base_branch: str = "main"
    state_dir: str = "~/.local/state/agenc-ircd-pipeline"
    model: str = "gpt-6-astra"
    reasoning_effort: str = "xhigh"
    codex_path: str = "codex"
    max_issues: int = 2
    max_sessions: int = 4
    max_attempts: int = 3
    max_phases: int = 4
    poll_seconds: int = 300
    agent_timeout_seconds: int = 7200
    gate_timeout_seconds: int = 10800
    minimum_free_gib: int = 256
    use_systemd: bool = True
    auto_merge: bool = True
    gate_cpu_percent: int = 1600
    gate_memory_gib: int = 256

    @classmethod
    def load(cls, path: Path) -> "Config":
        value = tomllib.loads(path.read_text())
        version = value.pop("version", None)
        if type(version) is not int or version != 1:
            raise ValueError("pipeline configuration requires version = 1")
        allowed = {f.name for f in fields(cls)}
        if set(value) - allowed:
            raise ValueError("unknown controller configuration keys: " + repr(set(value) - allowed))
        result = cls(**value)
        defaults = cls()
        for field in fields(cls):
            if type(getattr(result, field.name)) is not type(getattr(defaults, field.name)):
                raise ValueError("wrong configuration type: " + field.name)
        if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", result.repository):
            raise ValueError("invalid repository")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]*", result.base_branch) or ".." in result.base_branch:
            raise ValueError("invalid base branch")
        if (result.base_branch.endswith(("/", ".")) or "//" in result.base_branch
                or any(part.startswith(".") or part.endswith(".lock")
                       for part in result.base_branch.split("/"))):
            raise ValueError("invalid base branch")
        for name in ("master_issue", "max_issues", "max_sessions", "max_attempts", "max_phases",
                     "poll_seconds", "agent_timeout_seconds", "gate_timeout_seconds", "minimum_free_gib",
                     "gate_cpu_percent", "gate_memory_gib"):
            if getattr(result, name) < 1:
                raise ValueError(name + " must be positive")
        if result.max_issues > 2 or result.max_sessions > 4 or result.max_phases > 8 or result.max_attempts > 10:
            raise ValueError("controller concurrency/retry safety ceiling exceeded")
        if result.max_sessions < result.max_issues:
            raise ValueError("max_sessions must cover max_issues")
        if not result.model.strip() or result.reasoning_effort not in ("low", "medium", "high", "xhigh", "max", "ultra"):
            raise ValueError("invalid model/effort configuration")
        if not result.codex_path.strip() or not result.state_dir.strip():
            raise ValueError("Codex executable and state directory must be nonempty")
        if not Path(result.state_dir).expanduser().is_absolute():
            raise ValueError("state directory must expand to an absolute path")
        if Path(result.state_dir).expanduser() in (Path("/"), Path.home()):
            raise ValueError("state directory must be a dedicated child directory")
        return result

    @property
    def state(self) -> Path:
        return Path(self.state_dir).expanduser().resolve()

    @property
    def clone(self) -> Path:
        return self.state / "repository"

    @property
    def worktrees(self) -> Path:
        return self.state / "worktrees"

    def executable(self) -> str:
        candidate = shutil.which(self.codex_path)
        if candidate is None:
            raise ValueError("Codex executable is unavailable: " + self.codex_path)
        return candidate


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def private_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("controller directory must not be a symlink")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.stat().st_uid != os.getuid():
        raise ValueError("controller directory belongs to another user")
    path.chmod(0o700)
