"""Recover only durably recorded gate containers on the qualified local daemon.

The caller must first stop the launcher cgroup so no new create RPC can start.
A successful daemon query is required to prove absence; CLI failure is never an
absence proof. Every mutation uses a verified immutable container ID, never a
name, and no global Docker cleanup operation is available here.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from .gitops import GitError, _process

DOCKER = "/usr/bin/docker"
DOCKER_HOST = "unix:///var/run/docker.sock"
RECORD_LIMIT = 64 * 1024
OPERATION_TIMEOUT = 8.0
CLEANUP_TIMEOUT = 65.0
NAME = re.compile(r"agenc-ircd-pipeline-gate-[0-9a-f]{32}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
IDENTITY = re.compile(r"[0-9a-f]{64}\Z")
REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
ATTEMPT = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
INSPECT_FORMAT = ('{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Image}},'
                  '"labels":{{json .Config.Labels}},"running":{{json .State.Running}},'
                  '"paused":{{json .State.Paused}},"restarting":{{json .State.Restarting}},'
                  '"status":{{json .State.Status}}}')


class ContainerError(RuntimeError):
    """Container ownership or quiescence cannot be established safely."""


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ContainerError("duplicate container JSON field")
        result[key] = value
    return result


def _json(raw: str | bytes):
    def nonfinite(_value):
        raise ContainerError("nonfinite container JSON")
    try:
        return json.loads(raw, object_pairs_hook=_object, parse_constant=nonfinite)
    except (ValueError, RecursionError) as error:
        raise ContainerError("invalid container JSON") from error


def _canonical(path: Path) -> Path:
    path = Path(path)
    if (not path.is_absolute() or ".." in path.parts
            or str(path) != str(path.resolve(strict=False))
            or any(part.is_symlink() for part in (path, *path.parents))):
        raise ContainerError("container ownership paths must be canonical and contain no symlinks")
    return path


def _private_directory(path: Path) -> None:
    metadata = path.stat()
    if (not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid != os.getuid()
            or metadata.st_mode & 0o077):
        raise ContainerError("container ownership directory must be private and caller-owned")


def _load_container_record(record_path: Path, state_dir: Path) -> dict:
    """Read a bounded, closed, private pre-launch record for one gate attempt.

    This routine performs no filesystem mutations and never reads Docker or
    registry credentials. Missing records are rejected, including during retry.
    """
    path, state_dir = _canonical(record_path), _canonical(state_dir)
    _private_directory(state_dir)
    if (path.name != "container.json" or path.parent.parent != state_dir / "gates"
            or ATTEMPT.fullmatch(path.parent.name) is None):
        raise ContainerError("container record is outside a direct owned gate attempt")
    _private_directory(path.parent.parent)
    _private_directory(path.parent)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_mode & 0o077 or metadata.st_nlink != 1
                or metadata.st_size > RECORD_LIMIT):
            raise ContainerError("container record must be a bounded private ordinary file")
        raw = stream.read(RECORD_LIMIT + 1)
    if len(raw) > RECORD_LIMIT:
        raise ContainerError("container record exceeds its byte limit")
    value = _json(raw)
    fields = {"version", "backend", "name", "image", "source", "unit", "state_dir",
              "repository", "private_home", "labels"}
    if (type(value) is not dict or set(value) != fields or type(value["version"]) is not int
            or value["version"] != 1 or value["backend"] != "docker"):
        raise ContainerError("container record must match the closed version-1 Docker schema")
    for field in ("name", "image", "source", "unit", "state_dir", "repository", "private_home"):
        if type(value[field]) is not str:
            raise ContainerError("invalid container record field type")
    if (NAME.fullmatch(value["name"]) is None or value["unit"] != value["name"] + ".service"
            or SHA.fullmatch(value["source"]) is None
            or not value["image"].startswith("sha256:") or IDENTITY.fullmatch(value["image"][7:]) is None
            or REPOSITORY.fullmatch(value["repository"]) is None or value["state_dir"] != str(state_dir)):
        raise ContainerError("container record identity does not match its owned gate")
    private_home = _canonical(Path(value["private_home"]))
    if (private_home.parent != state_dir / "gate-cache" / "homes"
            or re.fullmatch(r"[0-9a-f]{32}", private_home.name) is None):
        raise ContainerError("container private home lies outside the owned gate cache")
    expected_labels = {"agenc-ircd.pipeline.state": str(state_dir),
                       "agenc-ircd.pipeline.source": value["source"],
                       "agenc-ircd.pipeline.unit": value["unit"],
                       "agenc-ircd.pipeline.purpose": "full-gate",
                       "agenc-ircd.pipeline.repository": value["repository"]}
    if type(value["labels"]) is not dict or value["labels"] != expected_labels:
        raise ContainerError("container ownership labels differ from the recorded identity")
    return value


def load_container_record(record_path: Path, state_dir: Path) -> dict:
    """Read an owned pre-launch record or raise ContainerError without mutation."""
    try:
        return _load_container_record(record_path, state_dir)
    except (OSError, ValueError) as error:
        raise ContainerError("container ownership record could not be read safely") from error


class _Docker:
    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.deadline = time.monotonic() + CLEANUP_TIMEOUT

    def run(self, argv: list[str], *, timeout: float = OPERATION_TIMEOUT) -> tuple[int, str]:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise ContainerError("container cleanup exceeded its total time bound")
        # Select the qualified local socket explicitly and suppress alternate
        # contexts/TLS options. No credential-bearing environment is forwarded.
        environment = {"PATH": "/usr/bin:/bin", "HOME": str(Path.home()),
                       "DOCKER_HOST": DOCKER_HOST, "DOCKER_CLI_HINTS": "false"}
        try:
            return _process([DOCKER, "--host", DOCKER_HOST, *argv], self.state_dir,
                            min(timeout, remaining), environment=environment)
        except (GitError, OSError, ValueError) as error:
            raise ContainerError("Docker command failed or exceeded its execution bound") from error

    def mutate(self, argv: list[str], *, timeout: float = OPERATION_TIMEOUT) -> None:
        """An uncertain mutation response is resolved only by the next readback."""
        try:
            self.run(argv, timeout=timeout)
        except ContainerError:
            pass

    def lookup(self, kind: str, identity: str) -> str | None:
        selected = "name=^/" + identity + "$" if kind == "name" else "id=" + identity
        code, output = self.run(["container", "ls", "--all", "--no-trunc", "--filter", selected,
                                 "--format", "{{json .ID}}"])
        if code:
            raise ContainerError("Docker daemon query failed; container absence is unproven")
        rows = [_json(line) for line in output.splitlines() if line.strip()]
        if (len(rows) > 1 or any(type(row) is not str or IDENTITY.fullmatch(row) is None for row in rows)
                or (kind == "id" and rows and rows[0] != identity)):
            raise ContainerError("Docker daemon returned an ambiguous container identity")
        return rows[0] if rows else None

    def inspect(self, identity: str, record: dict) -> dict | None:
        code, output = self.run(["container", "inspect", "--format", INSPECT_FORMAT, identity])
        if code:
            # An autoremove race is an absence only after a successful daemon
            # query by the immutable ID. Error text is deliberately not parsed.
            if self.lookup("id", identity) is None:
                return None
            raise ContainerError("Docker could not inspect the existing container")
        value = _json(output)
        fields = {"id", "name", "image", "labels", "running", "paused", "restarting", "status"}
        if (type(value) is not dict or set(value) != fields or value["id"] != identity
                or value["name"] != "/" + record["name"] or value["image"] != record["image"]
                or type(value["labels"]) is not dict
                or any(value["labels"].get(key) != item for key, item in record["labels"].items())
                or any(type(value[key]) is not bool for key in ("running", "paused", "restarting"))
                or type(value["status"]) is not str
                or value["status"] not in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}):
            raise ContainerError("Docker container does not match the durable ownership record")
        return value


def _record_digest(record: dict) -> str:
    raw = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    return hashlib.sha256(raw).hexdigest()


def _journal(path: Path) -> dict | None:
    """Read a small private immutable sibling journal, without following links."""
    if not path.exists() and not path.is_symlink():
        return None
    try:
        _canonical(path)
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                    or metadata.st_mode & 0o077 or metadata.st_size > 4096):
                raise ContainerError("container journal must be a bounded private ordinary file")
            raw = stream.read(4097)
        if len(raw) > 4096:
            raise ContainerError("container journal exceeds its byte limit")
        value = _json(raw)
        if type(value) is not dict:
            raise ContainerError("container journal must be a closed JSON object")
        return value
    except (OSError, ValueError) as error:
        raise ContainerError("container journal could not be read safely") from error


def _publish_journal(path: Path, value: dict) -> None:
    """Fsync an exact immutable journal before returning authority to its caller."""
    existing = _journal(path)
    if existing is not None:
        if existing != value:
            raise ContainerError("container journal conflicts with its recorded identity")
        # A prior response can be lost after link publication but before the
        # directory fsync. Re-establish durability before returning start authority.
        try:
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        except OSError as error:
            raise ContainerError("existing container journal could not be synced") from error
        return
    descriptor, name = tempfile.mkstemp(prefix=".container-journal-", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write((json.dumps(value, sort_keys=True) + "\n").encode())
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError:
            if _journal(path) != value:
                raise ContainerError("container journal publication raced a different identity")
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except (OSError, ValueError) as error:
        raise ContainerError("container journal could not be durably published") from error
    finally:
        temporary.unlink(missing_ok=True)


def _identity_journal(record_path: Path, record: dict) -> str | None:
    value = _journal(record_path.with_name("container-id.json"))
    if value is None:
        return None
    if (set(value) != {"version", "container_id", "record_sha256"}
            or type(value["version"]) is not int or value["version"] != 1
            or type(value["container_id"]) is not str or IDENTITY.fullmatch(value["container_id"]) is None
            or value["record_sha256"] != _record_digest(record)):
        raise ContainerError("container ID journal differs from the launch record")
    return value["container_id"]


def _bind_identity(record_path: Path, record: dict, identity: str) -> None:
    _publish_journal(record_path.with_name("container-id.json"),
                     {"version": 1, "container_id": identity, "record_sha256": _record_digest(record)})


def _terminal_value(record: dict, identity: str) -> dict:
    return {"version": 1, "container_id": identity,
            "record_sha256": _record_digest(record), "result": "removed"}


def container_cleanup_complete(record_path: Path, state_dir: Path) -> bool:
    """Validate terminal proof without any Docker or systemd subprocess calls."""
    record = load_container_record(record_path, state_dir)
    identity = _identity_journal(record_path, record)
    terminal = _journal(record_path.with_name("container-cleanup.json"))
    if terminal is None:
        return False
    if (identity is None or terminal != _terminal_value(record, identity)
            or type(terminal.get("version")) is not int):
        raise ContainerError("container cleanup journal differs from the recorded immutable ID")
    return True


def record_created_container(record_path: Path, state_dir: Path, returned_id: str) -> str:
    """Bind a verified inert create result durably before any start-by-ID call.

    The launch record must already exist. The exact container is inspected and
    must still be in Docker's never-started ``created`` state. Returning this ID
    is start authority only after container-id.json and its directory are synced.
    Lost create responses cannot reach this API and therefore cannot run code.
    """
    record = load_container_record(record_path, state_dir)
    if (type(returned_id) is not str or len(returned_id) > 256
            or IDENTITY.fullmatch(returned_id.strip()) is None):
        raise ContainerError("Docker create did not return exactly one immutable container ID")
    identity = returned_id.strip()
    bound = _identity_journal(record_path, record)
    if bound is not None and bound != identity:
        raise ContainerError("Docker create differs from the already recorded container ID")
    if _journal(record_path.with_name("container-cleanup.json")) is not None:
        raise ContainerError("a cleaned gate attempt cannot authorize another container start")
    observed = _Docker(_canonical(state_dir)).inspect(identity, record)
    if (observed is None or observed["status"] != "created"
            or observed["running"] or observed["paused"] or observed["restarting"]):
        raise ContainerError("Docker create result must be verified inert before start authorization")
    _bind_identity(record_path, record, identity)
    return identity


def stop_owned_container(record_path: Path, state_dir: Path) -> None:
    """Reconcile only durably owned IDs and record definitive terminal cleanup.

    The launcher must first be quiescent. A delayed start RPC cannot recreate an
    ID after successful removal. A create with no durable ID may still be in
    flight: if its name is absent, preserve the attempt as unresolved rather
    than asserting cleanup. Completed immutable IDs never require another daemon
    query, so historical attempts cannot consume future shutdown deadlines.
    """
    record = load_container_record(record_path, state_dir)
    identity = _identity_journal(record_path, record)
    terminal = _journal(record_path.with_name("container-cleanup.json"))
    if terminal is not None:
        if identity is None or terminal != _terminal_value(record, identity) or type(terminal.get("version")) is not int:
            raise ContainerError("container cleanup journal differs from the recorded immutable ID")
        return
    docker = _Docker(_canonical(state_dir))
    if identity is None:
        identity = docker.lookup("name", record["name"])
        if identity is None:
            raise ContainerError("inert create outcome remains unresolved; start was never authorized; preserve and reconcile this attempt")
        observed = docker.inspect(identity, record)
        if observed is None:
            raise ContainerError("unbound create disappeared before ownership could be inspected; preserve this attempt")
        # This also safely captures a legacy owned container for cleanup. It does
        # not authorize start: record_created_container separately requires the
        # never-started state before returning launch authority.
        _bind_identity(record_path, record, identity)
    for _attempt in range(3):
        if docker.lookup("id", identity) is None:
            break
        observed = docker.inspect(identity, record)
        if observed is None:
            break
        if observed["running"] or observed["paused"] or observed["restarting"]:
            docker.mutate(["container", "stop", "--time", "5", identity], timeout=12)
            observed = docker.inspect(identity, record)
            if observed is None:
                break
            if observed["running"] or observed["paused"] or observed["restarting"]:
                docker.mutate(["container", "kill", identity])
                observed = docker.inspect(identity, record)
                if observed is None:
                    break
            if observed["running"] or observed["paused"] or observed["restarting"]:
                continue
        docker.mutate(["container", "rm", identity])
        if docker.lookup("id", identity) is None:
            break
        # A delayed start can race the first rm of a created container. Reinspect
        # the same immutable ID and stop it on the next bounded sweep.
    else:
        raise ContainerError("owned container remains present or active after bounded cleanup")
    _publish_journal(record_path.with_name("container-cleanup.json"), _terminal_value(record, identity))
