"""Durable scheduler records and atomic ownership, independent of agent output.

Use one ``SupervisorLock`` for the lifetime of the controller. SQLite claims
remain transactional across separate processes; interrupted tasks retain all
claims, worktree metadata and receipts until the supervisor reconciles them.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import re
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Iterator, Mapping

STATUSES = frozenset({
    "pending", "planning", "working", "reviewing", "gating", "publishing",
    "merging", "complete", "blocked",
})
ACTIVE_STATUSES = STATUSES - {"pending", "complete", "blocked"}
RECEIPT_STATUSES = frozenset({"passed", "failed", "accepted", "rejected"})


class StateError(ValueError):
    """State input is invalid or an immutable record conflicts."""


class ClaimConflict(StateError):
    """Another owner holds a required file or integration scope."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")


def _json(value: object) -> str:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (TypeError, ValueError, RecursionError) as error:
        raise StateError(f"state must be finite JSON: {error}") from error


def _issue(number: object) -> int:
    if type(number) is not int or number <= 0:
        raise StateError("issue must be a positive integer")
    return number


def _name(value: object, label: str) -> str:
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise StateError(f"{label} must be nonempty trimmed text")
    return value


def _file(value: object) -> str:
    value = _name(value, "file claim")
    path = PurePosixPath(value)
    if (path.is_absolute() or str(path) != value or value == "."
            or ".." in path.parts or "\\" in value or "\x00" in value):
        raise StateError("file claims must be canonical repository-relative POSIX paths")
    return value


def _overlaps(first: str, second: str) -> bool:
    return first == second or first.startswith(second + "/") or second.startswith(first + "/")


class SupervisorLock:
    """Nonblocking process-lifetime lock; metadata survives a crash for diagnosis."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.fd: int | None = None

    def acquire(self) -> SupervisorLock:
        if self.fd is not None:
            raise StateError("supervisor lock is already held by this object")
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(self.path, os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            os.close(fd)
            raise ClaimConflict("another supervisor holds the pipeline lock") from error
        try:
            start_ticks: str | None = None
            try:
                stat = Path(f"/proc/{os.getpid()}/stat").read_text(encoding="utf-8")
                start_ticks = stat.rsplit(")", 1)[1].split()[19]
            except (OSError, IndexError):
                pass
            record = _json({"pid": os.getpid(), "acquired_at": _now(),
                            "process_start_ticks": start_ticks}).encode()
            os.ftruncate(fd, 0)
            os.write(fd, record)
            os.fsync(fd)
        except BaseException:
            os.close(fd)
            raise
        self.fd = fd
        return self

    def release(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self) -> SupervisorLock:
        return self.acquire()

    def __exit__(self, *_: object) -> None:
        self.release()


class State:
    """WAL-backed task/claim/receipt storage with explicit transaction boundaries."""

    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        self._mutex = threading.RLock()
        self.connection = sqlite3.connect(self.path, timeout=30, isolation_level=None,
                                          check_same_thread=False)
        self.connection.row_factory = sqlite3.Row
        self.connection.execute("PRAGMA journal_mode=WAL")
        self.connection.execute("PRAGMA synchronous=FULL")
        self.connection.execute("PRAGMA foreign_keys=ON")
        self.connection.executescript("""
            CREATE TABLE IF NOT EXISTS tasks (
                issue INTEGER PRIMARY KEY, status TEXT NOT NULL, data TEXT NOT NULL,
                updated_at TEXT NOT NULL, interrupted_from TEXT
            );
            CREATE TABLE IF NOT EXISTS claims (
                issue INTEGER NOT NULL REFERENCES tasks(issue), owner TEXT NOT NULL,
                kind TEXT NOT NULL, value TEXT NOT NULL, acquired_at TEXT NOT NULL,
                PRIMARY KEY (kind, value)
            );
            CREATE TABLE IF NOT EXISTS receipts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                issue INTEGER NOT NULL REFERENCES tasks(issue), kind TEXT NOT NULL,
                source TEXT NOT NULL, tree TEXT NOT NULL, base TEXT NOT NULL,
                artifact_hashes TEXT NOT NULL, status TEXT NOT NULL, data TEXT NOT NULL,
                created_at TEXT NOT NULL, digest TEXT NOT NULL UNIQUE
            );
            CREATE TRIGGER IF NOT EXISTS immutable_receipt_update
                BEFORE UPDATE ON receipts BEGIN
                    SELECT RAISE(ABORT, 'receipts are immutable');
                END;
            CREATE TRIGGER IF NOT EXISTS immutable_receipt_delete
                BEFORE DELETE ON receipts BEGIN
                    SELECT RAISE(ABORT, 'receipts are immutable');
                END;
        """)

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        with self._mutex:
            self.connection.execute("BEGIN IMMEDIATE")
            try:
                yield self.connection
                self.connection.execute("COMMIT")
            except BaseException:
                self.connection.execute("ROLLBACK")
                raise

    def close(self) -> None:
        with self._mutex:
            self.connection.close()

    def __enter__(self) -> State:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    @staticmethod
    def _task(row: sqlite3.Row) -> dict[str, object]:
        result = dict(row)
        result["data"] = json.loads(result["data"])
        return result

    def get_task(self, issue: int) -> dict[str, object] | None:
        with self._mutex:
            row = self.connection.execute("SELECT * FROM tasks WHERE issue=?", (_issue(issue),)).fetchone()
        return self._task(row) if row is not None else None

    def set_task(self, issue: int, status: str, data: object = None) -> dict[str, object]:
        """Replace phase/data atomically; omitted data preserves existing metadata."""
        issue = _issue(issue)
        if status not in STATUSES:
            raise StateError(f"unknown task status: {status}")
        encoded = _json(data) if data is not None else None
        with self._transaction() as connection:
            previous = connection.execute("SELECT data FROM tasks WHERE issue=?", (issue,)).fetchone()
            payload = encoded if encoded is not None else (previous[0] if previous else "{}")
            connection.execute("""
                INSERT INTO tasks VALUES (?, ?, ?, ?, NULL)
                ON CONFLICT(issue) DO UPDATE SET status=excluded.status, data=excluded.data,
                    updated_at=excluded.updated_at, interrupted_from=NULL
            """, (issue, status, payload, _now()))
        result = self.get_task(issue)
        if result is None:
            raise StateError("task disappeared after write")
        return result

    def list_tasks(self, status: str | None = None) -> list[dict[str, object]]:
        if status is not None and status not in STATUSES:
            raise StateError(f"unknown task status: {status}")
        with self._mutex:
            if status is None:
                rows = self.connection.execute("SELECT * FROM tasks ORDER BY issue").fetchall()
            else:
                rows = self.connection.execute("SELECT * FROM tasks WHERE status=? ORDER BY issue", (status,)).fetchall()
        return [self._task(row) for row in rows]

    def claim(self, issue: int, scopes: tuple[str, ...] = (), files: tuple[str, ...] = (),
              owner: str | None = None) -> None:
        """Acquire all claims or none; repeated claims by the same owner are safe."""
        issue = _issue(issue)
        owner = _name(owner if owner is not None else str(issue), "owner")
        scopes = tuple(_name(scope, "scope") for scope in scopes)
        files = tuple(_file(path) for path in files)
        if len(scopes) != len(set(scopes)) or len(files) != len(set(files)):
            raise StateError("duplicate claims")
        with self._transaction() as connection:
            if connection.execute("SELECT 1 FROM tasks WHERE issue=?", (issue,)).fetchone() is None:
                raise StateError("create a task record before claiming it")
            current = connection.execute("SELECT * FROM claims").fetchall()
            for row in current:
                if row["issue"] == issue and row["owner"] != owner:
                    raise ClaimConflict(f"issue #{issue} is already claimed by {row['owner']}")
                if row["issue"] == issue and row["owner"] == owner:
                    continue
                conflict = (row["kind"] == "scope" and row["value"] in scopes) or (
                    row["kind"] == "file" and any(_overlaps(row["value"], path) for path in files)
                )
                if conflict:
                    raise ClaimConflict(f"{row['kind']} {row['value']} is held by issue #{row['issue']}")
            now = _now()
            for kind, values in (("issue", (str(issue),)), ("scope", scopes), ("file", files)):
                for value in values:
                    connection.execute("INSERT OR IGNORE INTO claims VALUES (?, ?, ?, ?, ?)",
                                       (issue, owner, kind, value, now))

    def release(self, issue: int, owner: str | None = None) -> None:
        """Release an issue's claims; an explicit mismatched owner fails closed."""
        issue = _issue(issue)
        with self._transaction() as connection:
            if owner is not None and connection.execute(
                "SELECT 1 FROM claims WHERE issue=? AND owner!=?", (issue, owner)
            ).fetchone() is not None:
                raise ClaimConflict("cannot release another owner's claims")
            connection.execute("DELETE FROM claims WHERE issue=?", (issue,))

    def claims(self) -> list[dict[str, object]]:
        with self._mutex:
            rows = self.connection.execute("SELECT * FROM claims ORDER BY kind, value").fetchall()
        return [dict(row) for row in rows]

    def recover_interrupted(self) -> list[dict[str, object]]:
        """Mark interrupted phases pending for reconciliation, preserving all proof.

        ``interrupted_from`` is authoritative: the controller must reconcile
        remote effects and live child processes before restarting these tasks.
        Recovery intentionally does not release claims or delete worktrees.
        """
        with self._transaction() as connection:
            placeholders = ",".join("?" for _ in ACTIVE_STATUSES)
            connection.execute(f"""
                UPDATE tasks SET interrupted_from=status, status='pending', updated_at=?
                WHERE status IN ({placeholders})
            """, (_now(), *sorted(ACTIVE_STATUSES)))
            rows = connection.execute(
                "SELECT * FROM tasks WHERE interrupted_from IS NOT NULL ORDER BY issue"
            ).fetchall()
        return [self._task(row) for row in rows]

    def add_receipt(self, issue: int, kind: str, source: str, tree: str, base: str,
                    artifact_hashes: Mapping[str, str], status: str,
                    data: object = None) -> dict[str, object]:
        """Append immutable exact-source proof; an identical retry is idempotent."""
        issue = _issue(issue)
        kind = _name(kind, "receipt kind")
        for name, value in (("source", source), ("tree", tree), ("base", base)):
            if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
                raise StateError(f"receipt {name} must be a full lowercase Git SHA-1")
        if not isinstance(artifact_hashes, Mapping) or not artifact_hashes:
            raise StateError("receipts must bind at least one artifact SHA-256")
        for name, digest in artifact_hashes.items():
            _name(name, "artifact name")
            if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
                raise StateError("artifact hashes must be lowercase SHA-256 values")
        if status not in RECEIPT_STATUSES:
            raise StateError(f"unknown receipt status: {status}")
        payload = {"issue": issue, "kind": kind, "source": source, "tree": tree,
                   "base": base, "artifact_hashes": dict(artifact_hashes),
                   "status": status, "data": data}
        identity = hashlib.sha256(_json(payload).encode()).hexdigest()
        with self._transaction() as connection:
            if connection.execute("SELECT 1 FROM tasks WHERE issue=?", (issue,)).fetchone() is None:
                raise StateError("create a task record before adding receipts")
            connection.execute("""
                INSERT OR IGNORE INTO receipts
                    (issue,kind,source,tree,base,artifact_hashes,status,data,created_at,digest)
                VALUES (?,?,?,?,?,?,?,?,?,?)
            """, (issue, kind, source, tree, base, _json(dict(artifact_hashes)), status,
                  _json(data), _now(), identity))
            row = connection.execute("SELECT * FROM receipts WHERE digest=?", (identity,)).fetchone()
        if row is None:
            raise StateError("receipt disappeared after append")
        return self._receipt(row)

    @staticmethod
    def _receipt(row: sqlite3.Row) -> dict[str, object]:
        result = dict(row)
        result["data"] = json.loads(result["data"])
        result["artifact_hashes"] = json.loads(result["artifact_hashes"])
        return result

    def receipts(self, issue: int, kind: str | None = None) -> list[dict[str, object]]:
        issue = _issue(issue)
        with self._mutex:
            if kind is None:
                rows = self.connection.execute("SELECT * FROM receipts WHERE issue=? ORDER BY id", (issue,)).fetchall()
            else:
                rows = self.connection.execute(
                    "SELECT * FROM receipts WHERE issue=? AND kind=? ORDER BY id", (issue, kind)
                ).fetchall()
        return [self._receipt(row) for row in rows]
