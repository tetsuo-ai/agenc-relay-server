"""Install a verified immutable controller bundle and a stopped user service."""

from __future__ import annotations

import ast
import fcntl
import hashlib
import json
import os
import shutil
import stat
import tempfile
import time
from pathlib import Path
from typing import Any

from .config import Config
from .gitops import GitError, SHA, _process

SERVICE = "agenc-ircd-issue-pipeline.service"
MAX_FILE = 2 * 1024 * 1024
MAX_BUNDLE = 16 * 1024 * 1024
MAX_FILES = 256


class InstallError(RuntimeError):
    """Installation refused an untrusted source, unsafe destination or running service."""


def _safe_path(path: Path) -> Path:
    path = Path(path).absolute()
    if any(component in (".", "..") for component in path.parts):
        raise InstallError("installation paths must be canonical absolute paths")
    if any(character in str(path) for character in "\r\n\0"):
        raise InstallError("installation paths must not contain line controls")
    for component in (path, *path.parents):
        if component.is_symlink():
            raise InstallError("installation paths must not traverse symlinks")
    return path


def _private_directory(path: Path) -> None:
    _safe_path(path)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    metadata = path.stat()
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid():
        raise InstallError("installation directory is not owned by this user")
    path.chmod(0o700)


def _read_regular(path: Path, maximum: int = MAX_FILE) -> bytes:
    _safe_path(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as error:
        raise InstallError("installation input cannot be safely opened") from error
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid() or before.st_nlink != 1:
            raise InstallError("installation input must be an owned single-link regular file")
        if before.st_size > maximum:
            raise InstallError("installation input exceeds its byte bound")
        data = source.read(maximum + 1)
        after = os.fstat(source.fileno())
        if len(data) > maximum or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns):
            raise InstallError("installation input changed during its bounded read")
    return data


def _command(argv: list[str], cwd: Path) -> str:
    try:
        code, output = _process(argv, cwd, 60)
    except (GitError, UnicodeError) as error:
        raise InstallError("installation command failed or exceeded its bound") from error
    if code:
        raise InstallError(f"installation command failed with status {code}")
    return output


def _git(root: Path, *args: str) -> str:
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env.update({"GIT_CONFIG_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1", "GIT_GRAFT_FILE": os.devnull,
                "GIT_TERMINAL_PROMPT": "0"})
    try:
        code, output = _process(["git", "--no-replace-objects", "-c", "core.hooksPath=/dev/null",
                                 "-c", "core.fsmonitor=false", *args], root, 60, environment=env)
    except (GitError, UnicodeError) as error:
        raise InstallError("trusted source Git inspection failed") from error
    if code:
        raise InstallError("trusted source Git inspection failed")
    return output


def _systemctl(*args: str) -> str:
    return _command(["systemctl", "--user", *args], Path.home())


def _require_stopped() -> None:
    state = _systemctl("show", "--property=ActiveState", "--value", SERVICE).strip()
    if state not in ("inactive", "failed"):
        raise InstallError("controller service must be stopped before installation")


def _clean_source(root: Path, commit: str) -> None:
    if _git(root, "rev-parse", "--show-toplevel").strip() != str(root):
        raise InstallError("source_root must name the exact repository worktree root")
    if _git(root, "rev-parse", "--verify", "HEAD^{commit}").strip() != commit:
        raise InstallError("source HEAD does not equal the caller's trusted commit")
    if _git(root, "status", "--porcelain=v1", "-z", "--untracked-files=normal"):
        raise InstallError("controller source must be committed and clean")


def _bundle(root: Path, commit: str) -> tuple[dict[str, Any], dict[str, bytes]]:
    _clean_source(root, commit)
    listing = _git(root, "ls-tree", "-r", "--full-tree", "-z", commit, "--",
                   "scripts/issue-pipeline.py", "scripts/issue_pipeline")
    files: dict[str, bytes] = {}
    entries = []
    total = 0
    for row in listing.split("\0"):
        if not row:
            continue
        try:
            metadata, name = row.split("\t", 1)
            mode, kind, blob = metadata.split()
        except ValueError as error:
            raise InstallError("trusted bundle inventory is malformed") from error
        if (mode not in ("100644", "100755") or kind != "blob" or not SHA.fullmatch(blob)
                or not (name == "scripts/issue-pipeline.py" or name.startswith("scripts/issue_pipeline/"))):
            raise InstallError("controller bundle contains a symlink, submodule or unexpected entry")
        if len(files) >= MAX_FILES or name in files:
            raise InstallError("controller bundle inventory exceeds its bound")
        working = _read_regular(root / name)
        # Copy authenticated Git bytes, never a file reread after the clean check.
        encoded = _git(root, "cat-file", "blob", blob).encode("utf-8")
        if working != encoded:
            raise InstallError("controller bundle does not match its trusted source commit")
        if name.endswith(".py"):
            try:
                ast.parse(encoded, filename=name)
            except (SyntaxError, ValueError) as error:
                raise InstallError("controller bundle contains invalid Python source") from error
        total += len(encoded)
        if total > MAX_BUNDLE:
            raise InstallError("controller bundle exceeds its total byte bound")
        files[name] = encoded
        entries.append({"path": name, "git_mode": mode, "sha256": hashlib.sha256(encoded).hexdigest()})
    required = {"scripts/issue-pipeline.py", "scripts/issue_pipeline/__init__.py", "scripts/issue_pipeline/config.py"}
    if not required <= files.keys():
        raise InstallError("trusted source lacks the complete controller entry points")
    _clean_source(root, commit)
    manifest = {"version": 1, "source_commit": commit, "source_tree": _git(root, "rev-parse", f"{commit}^{{tree}}").strip(),
                "files": sorted(entries, key=lambda item: item["path"])}
    return manifest, files


def _canonical(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n").encode()


def _sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _atomic_private(path: Path, content: bytes) -> None:
    _safe_path(path)
    if path.exists():
        _read_regular(path)
    descriptor, temporary = tempfile.mkstemp(prefix=".pipeline-install-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        _sync_directory(path.parent)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _verify_release(path: Path, manifest: bytes, files: dict[str, bytes]) -> None:
    expected = {"manifest.json": manifest, **files}
    expected_directories = {"."}
    for name in expected:
        expected_directories.update(str(parent) for parent in Path(name).parents)
    _safe_path(path)
    directories = [path]
    observed = set()
    for entry in path.rglob("*"):
        if entry.is_symlink():
            raise InstallError("immutable release contains a symlink")
        name = str(entry.relative_to(path))
        if entry.is_dir():
            if name not in expected_directories:
                raise InstallError("immutable release contains an unexpected directory")
            directories.append(entry)
            continue
        if name not in expected or _read_regular(entry) != expected[name]:
            raise InstallError("existing release differs from the trusted content address")
        if stat.S_IMODE(entry.stat().st_mode) != 0o400:
            raise InstallError("immutable release files must be owner-only and read-only")
        observed.add(name)
    if observed != expected.keys():
        raise InstallError("immutable release is incomplete")
    for directory in directories:
        metadata = directory.stat()
        if metadata.st_uid != os.getuid() or stat.S_IMODE(metadata.st_mode) != 0o500:
            raise InstallError("immutable release directories must be owner-only and read-only")


def _publish_release(parent: Path, digest: str, manifest: bytes, files: dict[str, bytes]) -> Path:
    final = parent / digest
    if final.exists() or final.is_symlink():
        _verify_release(final, manifest, files)
        return final
    with tempfile.TemporaryDirectory(prefix=".pipeline-bundle-", dir=parent) as temporary:
        staging = Path(temporary)
        for name, content in {**files, "manifest.json": manifest}.items():
            destination = staging / name
            destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
            _atomic_private(destination, content)
        # Exclusive creation prevents replacing even an empty concurrent candidate.
        final.mkdir(mode=0o700, exist_ok=False)
        identity = final.stat()
        try:
            for entry in staging.iterdir():
                entry.rename(final / entry.name)
            for entry in final.rglob("*"):
                if entry.is_file():
                    entry.chmod(0o400)
            directories = [entry for entry in final.rglob("*") if entry.is_dir()]
            for directory in sorted(directories, key=lambda item: len(item.parts), reverse=True):
                _sync_directory(directory)
                directory.chmod(0o500)
            _sync_directory(final)
            final.chmod(0o500)
            _sync_directory(parent)
            _verify_release(final, manifest, files)
        except BaseException:
            if final.exists() and not final.is_symlink() and (final.stat().st_dev, final.stat().st_ino) == (identity.st_dev, identity.st_ino):
                for entry in final.rglob("*"):
                    if entry.is_dir() and not entry.is_symlink():
                        entry.chmod(0o700)
                final.chmod(0o700)
                shutil.rmtree(final)
            raise
    return final


def _quote(value: str, *, command: bool = False) -> str:
    if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise InstallError("service arguments and environment must contain no control characters")
    value = value.replace("\\", "\\\\").replace('"', '\\"').replace("%", "%%")
    if command:
        value = value.replace("$", "$$")
    return '"' + value + '"'


def _working_directory(state: Path) -> str:
    # systemd unquotes only Exec and Environment values; a quoted
    # WorkingDirectory= is rejected as a non-absolute path.
    value = str(state)
    if (not state.is_absolute() or any(ord(character) <= 32 or ord(character) == 127 for character in value)
            or any(character in value for character in '"\\%;#')):
        raise InstallError("state directory path must be absolute and contain no whitespace, quotes or unit metacharacters: " + repr(value))
    return value


def _unit(cli: Path, config: Path, state: Path, captured_path: str) -> bytes:
    argv = ["/usr/bin/python3", str(cli), "--config", str(config)]
    start = " ".join(_quote(value, command=True) for value in [*argv, "run"])
    stop = " ".join(_quote(value, command=True) for value in [*argv, "halt-children"])
    return ("[Unit]\nDescription=AgenC reviewed issue pipeline\n\n[Service]\nType=exec\n"
            + f"WorkingDirectory={_working_directory(state)}\nEnvironment={_quote('PATH=' + captured_path)}\n"
            + "Environment=PYTHONDONTWRITEBYTECODE=1\nEnvironment=PYTHONNOUSERSITE=1\n"
            + "UnsetEnvironment=PYTHONPATH PYTHONHOME PYTHONSTARTUP\n"
            + f"ExecStart={start}\nExecStopPost={stop}\n"
            # Allow all four bounded model cleanups, gate cleanup and the
            # recovery pass to finish before systemd terminates this service.
            + "Restart=on-failure\nRestartSec=15\nKillMode=control-group\nTimeoutStopSec=900\nUMask=0077\n"
            + "\n[Install]\nWantedBy=default.target\n").encode()


def install(config_path: Path, source_root: Path, source_commit: str) -> dict[str, str]:
    """Install exact reviewed bytes and reload the user manager without starting/enabling.

    The caller supplies the trusted source SHA only after its independent review
    and full gate. No worker candidate can replace the installed controller on
    its own. Existing ChatGPT/GitHub CLI authentication is left untouched: only
    PATH and fixed nonsecret Python settings are written to the service unit.
    """
    if not isinstance(source_commit, str) or not SHA.fullmatch(source_commit):
        raise InstallError("the caller must provide an exact trusted source commit")
    source_root, config_path = _safe_path(source_root), _safe_path(config_path)
    config_bytes = _read_regular(config_path)
    manifest, files = _bundle(source_root, source_commit)
    home = _safe_path(Path.home())
    app = home / ".local" / "share" / "agenc-ircd-pipeline"
    releases = app / "releases"
    _private_directory(app)
    _private_directory(releases)
    # Validate exactly the captured config bytes, never a raced second input read.
    with tempfile.TemporaryDirectory(prefix=".pipeline-config-", dir=app) as temporary:
        snapshot = Path(temporary) / "config.toml"
        _atomic_private(snapshot, config_bytes)
        try:
            config = Config.load(snapshot)
        except (OSError, TypeError, ValueError) as error:
            raise InstallError("controller configuration is invalid") from error
    state = _safe_path(Path(config.state_dir).expanduser())
    unit_directory = home / ".config" / "systemd" / "user"
    installed_config = state / "config.toml"
    unit_path = unit_directory / SERVICE
    manifest_bytes = _canonical(manifest)
    digest = hashlib.sha256(manifest_bytes).hexdigest()
    release = releases / digest
    unit_bytes = _unit(release / "scripts" / "issue-pipeline.py", installed_config, state,
                       os.environ.get("PATH", ""))
    _require_stopped()
    _private_directory(state)
    _private_directory(unit_directory)
    lock_path = app / "install.lock"
    _safe_path(lock_path)
    with lock_path.open("a+b") as lock:
        os.fchmod(lock.fileno(), 0o600)
        deadline = time.monotonic() + 60
        while True:
            try:
                fcntl.flock(lock.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() >= deadline:
                    raise InstallError("another controller installation owns the lock")
                time.sleep(0.02)
        _require_stopped()
        _clean_source(source_root, source_commit)
        _publish_release(releases, digest, manifest_bytes, files)
        previous = {path: _read_regular(path) if path.exists() else None for path in (installed_config, unit_path)}
        written: dict[Path, bytes] = {}
        try:
            for path, content in ((installed_config, config_bytes), (unit_path, unit_bytes)):
                _atomic_private(path, content)
                written[path] = content
            _systemctl("daemon-reload")
            _require_stopped()
        except BaseException:
            for path, content in reversed(list(written.items())):
                if _read_regular(path) != content:
                    continue  # Never roll back another actor's replacement.
                old = previous[path]
                if old is None:
                    path.unlink()
                    _sync_directory(path.parent)
                else:
                    _atomic_private(path, old)
            raise
    return {"release_path": str(release), "config_path": str(installed_config), "unit_path": str(unit_path),
            "cli_path": str(release / "scripts" / "issue-pipeline.py"), "service_name": SERVICE,
            "source_commit": source_commit, "bundle_sha256": digest, "state": "stopped"}
