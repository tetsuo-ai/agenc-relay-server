"""Bound and retain public fuzz corpora independently of the artifact catalog."""

from __future__ import annotations

import gzip
import io
import os
import re
import tarfile
from pathlib import Path

from .records import QualificationError, canonical, digest, read_bytes, sync_directory

MAX_INPUT_BYTES = 1_048_576
MAX_CORPUS_FILES = 16_384
MAX_CORPUS_BYTES = 64 * 1024 * 1024
CORPUS_NAME = re.compile(r"[A-Za-z0-9_.-]{1,100}\Z")


def seed_directory(root: Path, target: str) -> Path:
    if target in {"tcp_framing", "websocket", "parse_render", "client_state"}:
        relative = f"client-wire/{target}"
    elif target in {"storage_codecs", "backup_stream", "wss_frame", "wss_upgrade", "history_records"}:
        relative = target
    else:
        relative = target.replace("_", "-")
    directory = root / "test-data/fuzz-corpus" / relative
    if directory.is_symlink() or not directory.is_dir():
        raise QualificationError(f"fuzz target has no committed seed corpus: {target}")
    return directory


def corpus_entries(directory: Path) -> list[Path]:
    entries = []
    # Stop enumeration at the limit instead of materializing an unbounded list.
    for path in directory.iterdir():
        if len(entries) >= MAX_CORPUS_FILES:
            raise QualificationError("fuzz corpus exceeds its file limit")
        if not CORPUS_NAME.fullmatch(path.name) or path.name in {".", ".."}:
            raise QualificationError("fuzz corpus has an invalid entry name")
        entries.append(path)
    if not entries:
        raise QualificationError("fuzz corpus is empty")
    return sorted(entries)


def snapshot_corpus(directory: Path, archive: Path | None = None) -> str:
    """Hash a stopped corpus; optionally retain the same bounded bytes in gzip tar.

    Archives contain only flat regular files. Read and hash the bytes added to
    the archive together so its identity cannot describe an earlier file.
    """
    entries = corpus_entries(directory)
    records = []
    total = 0
    descriptor = None
    if archive is not None:
        descriptor = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        with io.BytesIO() if descriptor is None else os.fdopen(descriptor, "wb") as output:
            with gzip.GzipFile(filename="", mode="wb", fileobj=output, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w|", format=tarfile.USTAR_FORMAT) as packed:
                    for path in entries:
                        content = read_bytes(path, MAX_INPUT_BYTES)
                        total += len(content)
                        if total > MAX_CORPUS_BYTES:
                            raise QualificationError("fuzz corpus exceeds its byte limit")
                        records.append({"name": path.name, "bytes": len(content), "sha256": digest(content)})
                        if archive is not None:
                            entry = tarfile.TarInfo(path.name)
                            entry.size, entry.mode, entry.mtime = len(content), 0o600, 0
                            packed.addfile(entry, io.BytesIO(content))
            if archive is not None:
                output.flush()
                os.fsync(output.fileno())
        if archive is not None:
            sync_directory(archive.parent)
    except BaseException:
        # A partial archive remains evidence of the failed attempt; no report
        # may claim that it represents a completed corpus.
        raise
    return digest(canonical(records))
