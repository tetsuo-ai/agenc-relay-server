"""Candidate-wide and per-job advisory locks so campaigns can share one host."""

from __future__ import annotations

import fcntl
import os
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .records import QualificationError

CANDIDATE_LOCK = ".runner.lock"
JOB_LOCK = ".lock"


def _open_lock(path: Path) -> int:
    if path.is_symlink():
        raise QualificationError("lock file may not be a symlink")
    return os.open(path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)


@contextmanager
def candidate_lock(directory: Path, *, shared: bool) -> Iterator[None]:
    """Shared for running or reading; exclusive for closing a release decision."""
    descriptor = _open_lock(directory / CANDIDATE_LOCK)
    try:
        try:
            fcntl.flock(descriptor, (fcntl.LOCK_SH if shared else fcntl.LOCK_EX) | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise QualificationError("another runner is using this candidate") from error
        yield
    finally:
        os.close(descriptor)


def exclusive(directory: Path):
    return candidate_lock(directory, shared=False)


def shared(directory: Path):
    return candidate_lock(directory, shared=True)


@contextmanager
def job_lock(attempts: Path) -> Iterator[None]:
    """One active attempt per job directory; other jobs may run at the same time."""
    descriptor = _open_lock(attempts / JOB_LOCK)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise QualificationError("this job is already running on this host") from error
        yield
    finally:
        os.close(descriptor)


def job_running(attempts: Path) -> bool:
    lock = attempts / JOB_LOCK
    if not lock.exists():
        return False
    descriptor = _open_lock(lock)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def attempt_entries(attempts: Path) -> list[Path]:
    """Attempt directories in order, rejecting anything except the job lock."""
    entries = []
    for path in sorted(attempts.iterdir()):
        if path.name == JOB_LOCK and not path.is_symlink() and path.is_file():
            continue
        if path.is_symlink() or not path.is_dir() or not path.name.isdecimal():
            raise QualificationError("unexpected entry in attempt history")
        entries.append(path)
    return entries
