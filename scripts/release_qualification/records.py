"""Bounded, immutable records shared by release builders and qualification jobs."""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

MAX_RECORD_BYTES = 4 * 1024 * 1024
MAX_LOG_BYTES = 64 * 1024 * 1024
SHA256 = re.compile(r"[0-9a-f]{64}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
IDENTIFIER = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
TARGETS = ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu")
CLAIMS = ("core-v1", "federated-v1", "encrypted-v1", "wss", "history")


class QualificationError(ValueError):
    """A qualification input, execution, or evidence check failed."""


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?Z", value):
        raise QualificationError("timestamp must use UTC Z notation")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise QualificationError("invalid timestamp") from error
    return parsed


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical(value: Any) -> bytes:
    try:
        encoded = (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode("utf-8")
    except (ValueError, TypeError) as error:
        raise QualificationError("record is not finite JSON") from error
    if len(encoded) > MAX_RECORD_BYTES:
        raise QualificationError("record exceeds 4 MiB")
    return encoded


def unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for name, value in pairs:
        if name in result:
            raise QualificationError(f"duplicate JSON field: {name}")
        result[name] = value
    return result


def reject_constant(value: str) -> None:
    raise QualificationError(f"non-finite JSON constant: {value}")


def finite_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed):
        raise QualificationError("JSON number exceeds the finite measurement range")
    return parsed


def read_bytes(path: Path, maximum: int = MAX_RECORD_BYTES) -> bytes:
    """Read a regular file without following a final symlink or blocking on a FIFO."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            metadata = os.fstat(source.fileno())
            if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum:
                raise QualificationError(f"input is not a bounded regular file: {path}")
            data = source.read(maximum + 1)
    except OSError as error:
        raise QualificationError(f"cannot read input {path}: {error.strerror}") from error
    if len(data) > maximum:
        raise QualificationError(f"input exceeds its size limit: {path}")
    return data


def read_record(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(read_bytes(path), object_pairs_hook=unique_object,
                           parse_constant=reject_constant, parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError, RecursionError) as error:
        raise QualificationError(f"invalid JSON record: {path}") from error
    if not isinstance(value, dict):
        raise QualificationError("record must be a JSON object")
    return value


def file_digest(path: Path) -> str:
    """Hash an opened regular artifact with bounded memory."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as source:
            before = os.fstat(source.fileno())
            if not stat.S_ISREG(before.st_mode):
                raise QualificationError(f"artifact is not a regular file: {path}")
            result = hashlib.sha256()
            for block in iter(lambda: source.read(1024 * 1024), b""):
                result.update(block)
            after = os.fstat(source.fileno())
    except OSError as error:
        raise QualificationError(f"cannot hash artifact {path}: {error.strerror}") from error
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
        raise QualificationError(f"artifact changed during hashing: {path}")
    return result.hexdigest()


def safe_path(root: Path, relative: Any) -> Path:
    if not isinstance(relative, str) or not relative or "\\" in relative:
        raise QualificationError("artifact path must be a relative POSIX path")
    parts = relative.split("/")
    if any(part in ("", ".", "..") for part in parts):
        raise QualificationError("artifact path contains an empty or traversing component")
    cursor = root
    for part in parts:
        cursor /= part
        if cursor.is_symlink():
            raise QualificationError("artifact path may not traverse a symlink")
    if not cursor.resolve().is_relative_to(root.resolve()):
        raise QualificationError("artifact path escapes its record directory")
    return cursor


def require_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise QualificationError(f"{label} has missing or unknown fields")
    return value


def require_hash(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise QualificationError(f"{label} must be a SHA-256 digest")
    return value


def require_integer(value: Any, minimum: int, maximum: int, label: str) -> int:
    if type(value) is not int or not minimum <= value <= maximum:
        raise QualificationError(f"{label} is outside its integer range")
    return value


def sync_directory(directory: Path) -> None:
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def write_once(path: Path, data: bytes) -> None:
    """Durably publish one complete record without replacing existing evidence."""
    if path.parent.is_symlink():
        raise QualificationError("evidence directory may not be a symlink")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor, temporary = tempfile.mkstemp(prefix=".record-", dir=path.parent)
    scratch = Path(temporary)
    try:
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(data)
            destination.flush()
            os.fsync(destination.fileno())
        os.link(scratch, path)
        sync_directory(path.parent)
    except OSError as error:
        raise QualificationError(f"cannot publish evidence {path}: {error.strerror}") from error
    finally:
        scratch.unlink(missing_ok=True)
