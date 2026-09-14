"""One comment creation attempt per durable repository/issue/marker identity."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import stat

from .config import private_directory


class CommentPublicationError(RuntimeError):
    """Preserve the original intent; an absent marker cannot disprove a POST."""


def _encoded(value):
    return (json.dumps(value, sort_keys=True, allow_nan=False) + "\n").encode()


def _sync_directory(path):
    directory = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


def _write(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(_encoded(value))
        stream.flush()
        os.fsync(stream.fileno())
    _sync_directory(path.parent)


def _read(path):
    def object_pairs(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("duplicate comment journal field")
            value[key] = item
        return value

    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        metadata = os.fstat(stream.fileno())
        if (not stat.S_ISREG(metadata.st_mode) or metadata.st_uid != os.getuid()
                or metadata.st_nlink != 1 or metadata.st_mode & 0o077 or metadata.st_size > 512 * 1024):
            raise CommentPublicationError("unsafe comment journal; preserve " + str(path))
        raw = stream.read(512 * 1024 + 1)
    value = json.loads(raw, object_pairs_hook=object_pairs,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite journal")))
    if type(value) is not dict:
        raise CommentPublicationError("comment journal must be an object")
    return value


def _matches(github, number, marker):
    rows = [row for row in github.comments(number)
            if isinstance(row.get("body"), str) and marker in row["body"]]
    if len(rows) > 1:
        raise CommentPublicationError("duplicate comment publication marker; preserve the original intent")
    if rows and (type(rows[0].get("id")) is not int or rows[0]["id"] <= 0
                 or rows[0]["body"].count(marker) != 1):
        raise CommentPublicationError("comment publication has invalid identity or repeated marker")
    return rows


def ensure_comment(github, state: Path, number, marker, body, source, *, mutable=False):
    """Return the one read-back comment; callers serialize this with the graph lock.

    ``source`` may be a lazy callable: ordinary recorded polls never fetch merely
    to recreate the original source binding. Mutable comments keep their original
    creation body until acceptance; only then may the caller PATCH their fixed ID.
    """
    if (type(number) is not int or number <= 0 or type(mutable) is not bool
            or not isinstance(marker, str) or not 1 <= len(marker) <= 512
            or not re.fullmatch(r"<!-- agenc-pipeline-[^<>\r\n]+ -->", marker)
            or not isinstance(body, str) or len(body.encode()) > 60000 or body.count(marker) != 1):
        raise CommentPublicationError("invalid bounded comment publication")
    identity = hashlib.sha256(_encoded([github.repo, number, marker])).hexdigest()
    directory = state / "comment-publications" / identity
    for parent in (state, state / "comment-publications", directory):
        private_directory(parent)
        _sync_directory(parent.parent)  # Persist new directory names before dispatch.
    intent_path, dispatch_path, accepted_path = (directory / name for name in (
        "intent.json", "dispatch.json", "accepted.json"))
    rows = _matches(github, number, marker)
    if intent_path.exists():
        intent = _read(intent_path)
    else:
        if dispatch_path.exists() or accepted_path.exists():
            raise CommentPublicationError("comment publication lost its original intent; preserve " + str(directory))
        if rows and not mutable and rows[0]["body"] != body:
            raise CommentPublicationError("existing comment differs from its exact intended body")
        bound_source = source() if callable(source) else source
        if not isinstance(bound_source, str) or not re.fullmatch(r"[0-9a-f]{40}", bound_source):
            raise CommentPublicationError("comment publication requires an exact source")
        intent = {"version": 1, "repository": github.repo, "issue": number, "marker": marker,
                  "body": rows[0]["body"] if rows and mutable else body,
                  "source": bound_source, "mutable": mutable}
        _write(intent_path, intent)
    if (set(intent) != {"version", "repository", "issue", "marker", "body", "source", "mutable"}
            or type(intent["version"]) is not int or intent["version"] != 1
            or type(intent["issue"]) is not int or intent["issue"] != number
            or intent["repository"] != github.repo or intent["marker"] != marker
            or type(intent["mutable"]) is not bool or intent["mutable"] != mutable
            or not isinstance(intent["source"], str) or not re.fullmatch(r"[0-9a-f]{40}", intent["source"])
            or not isinstance(intent["body"], str) or len(intent["body"].encode()) > 60000
            or intent["body"].count(marker) != 1 or (not mutable and intent["body"] != body)):
        raise CommentPublicationError("comment request differs from its original source/marker/body intent")
    binding = hashlib.sha256(_encoded(intent)).hexdigest()
    dispatch = {"version": 1, "intent_sha256": binding}
    if dispatch_path.exists():
        observed_dispatch = _read(dispatch_path)
        if type(observed_dispatch.get("version")) is not int or observed_dispatch != dispatch:
            raise CommentPublicationError("comment dispatch differs from its original intent")
    accepted = _read(accepted_path) if accepted_path.exists() else None
    if accepted is not None:
        if (set(accepted) != {"version", "intent_sha256", "comment_id"}
                or type(accepted["version"]) is not int or accepted["version"] != 1
                or accepted["intent_sha256"] != binding or type(accepted["comment_id"]) is not int
                or accepted["comment_id"] <= 0 or not rows or rows[0]["id"] != accepted["comment_id"]
                or (not mutable and rows[0]["body"] != intent["body"])):
            raise CommentPublicationError("accepted comment is absent or changed; preserve " + str(directory))
        return rows[0]
    if not rows:
        if dispatch_path.exists():
            raise CommentPublicationError("comment POST remains uncertain; preserve " + str(directory)
                                          + " and reconcile its original marker without another POST")
        _write(dispatch_path, dispatch)  # Durable ambiguity boundary before any send.
        github.comment(number, intent["body"])
        rows = _matches(github, number, marker)
    if not rows or rows[0]["body"] != intent["body"]:
        raise CommentPublicationError("comment publication lacks its exact original readback; preserve " + str(directory))
    _write(accepted_path, {"version": 1, "intent_sha256": binding, "comment_id": rows[0]["id"]})
    return rows[0]
