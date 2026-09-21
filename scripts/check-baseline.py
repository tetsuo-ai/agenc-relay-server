#!/usr/bin/env python3
"""Validate the frozen normative specification baseline."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import Mapping, NoReturn

ARTIFACTS = {
    "architecture": "docs/arc-architecture-and-implementation-spec.md",
    "e2ee-companion": "docs/arc-mls-e2ee-extension.md",
    "federation-registry": "docs/federation-v1-profile.registry",
    "source-ledger": "docs/protocol-sources-and-decisions.md",
    "specification-manifest": "docs/specification-manifest.txt",
    "specification-validator": "scripts/check-spec.sh",
}
PROFILES = {
    "base_federation_v1": "base-federation-v1",
    "e2ee_mls_v1": "e2ee-mls-v1",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")


class BaselineError(ValueError):
    """A frozen-baseline validation failure."""


def sha256_file(path: Path) -> str:
    """Return the lowercase SHA-256 digest of one file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def git_environment(inherited: Mapping[str, str]) -> dict[str, str]:
    """Return process state that cannot redirect or rewrite Git object reads."""
    environment = {
        name: value for name, value in inherited.items() if not name.startswith("GIT_")
    }
    environment.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_GRAFT_FILE": os.devnull,
            "GIT_NO_REPLACE_OBJECTS": "1",
        }
    )
    return environment


def git_bytes(root: Path, arguments: list[str], label: str) -> bytes:
    """Run one bounded Git lookup and return its raw standard output."""
    try:
        completed = subprocess.run(
            ["git", "--no-replace-objects", *arguments],
            cwd=root,
            env=git_environment(os.environ),
            capture_output=True,
            check=False,
        )
    except OSError as error:
        raise BaselineError(f"cannot execute Git for {label}: {error}") from error
    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).decode("utf-8", errors="replace").strip()
        raise BaselineError(f"Git lookup failed for {label}: {details}")
    return completed.stdout


def require_complete_history(root: Path) -> None:
    """Reject shallow history before making ancestry claims."""
    shallow = git_bytes(
        root,
        ["rev-parse", "--is-shallow-repository"],
        "repository history",
    ).strip()
    if shallow != b"false":
        if shallow == b"true":
            raise BaselineError("frozen baseline validation requires complete Git history")
        raise BaselineError("Git returned an invalid shallow-repository state")


def validate_frozen_commit(root: Path, commit: str) -> None:
    """Require the recorded source commit to exist in the current history."""
    require_complete_history(root)
    git_bytes(root, ["cat-file", "-e", f"{commit}^{{commit}}"], "frozen commit")
    git_bytes(root, ["merge-base", "--is-ancestor", commit, "HEAD"], "frozen ancestry")


def frozen_blob(root: Path, commit: str, path: str) -> bytes:
    """Read one tracked artifact from the recorded frozen commit."""
    return git_bytes(root, ["cat-file", "blob", f"{commit}:{path}"], path)


def frozen_mode(root: Path, commit: str, path: str) -> str:
    """Read one artifact mode from the recorded frozen tree."""
    entry = git_bytes(root, ["ls-tree", commit, "--", path], path)
    try:
        metadata, recorded_path = entry.rstrip(b"\n").split(b"\t", 1)
        mode, kind, _object_id = metadata.split(b" ", 2)
    except ValueError as error:
        raise BaselineError(f"frozen tree entry is malformed: {path}") from error
    if kind != b"blob" or recorded_path.decode("utf-8", errors="replace") != path:
        raise BaselineError(f"frozen tree entry is not an exact blob: {path}")
    return mode.decode("ascii")


def parse_manifest(path: Path) -> tuple[dict[str, str], dict[str, dict[str, str]]]:
    """Parse the deliberately simple frozen specification manifest."""
    file_hashes: dict[str, str] = {}
    profile_values: dict[str, dict[str, str]] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        fields = line.split("|")
        if fields == ["manifest", "version", "1"]:
            continue
        if len(fields) != 3:
            raise BaselineError(f"manifest line {line_number} is not a triple")
        kind, name, value = fields
        if kind == "sha256":
            file_hashes[name] = value
        elif kind in {"profile-sha256", "profile-base64url"}:
            profile_values.setdefault(name, {})[kind] = value
        else:
            raise BaselineError(f"manifest line {line_number} has unknown kind {kind!r}")
    return file_hashes, profile_values


def validate(root: Path) -> None:
    """Validate all hashes, roles, profiles, and the original checker."""
    baseline_path = root / "conformance/spec-baseline.toml"
    try:
        baseline = tomllib.loads(baseline_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise BaselineError(f"cannot read baseline: {error}") from error

    if baseline.get("schema_version") != 1:
        raise BaselineError("baseline schema_version must be 1")
    frozen_commit = baseline.get("frozen_at_commit")
    if not isinstance(frozen_commit, str) or COMMIT_RE.fullmatch(frozen_commit) is None:
        raise BaselineError("frozen_at_commit must be a full lowercase Git object ID")
    validate_frozen_commit(root, frozen_commit)

    records = baseline.get("artifacts")
    if not isinstance(records, list):
        raise BaselineError("baseline artifacts must be an array")
    by_role: dict[str, dict[str, object]] = {}
    for record in records:
        if not isinstance(record, dict):
            raise BaselineError("each baseline artifact must be a table")
        role = record.get("role")
        if not isinstance(role, str) or role in by_role:
            raise BaselineError(f"invalid or duplicate artifact role: {role!r}")
        by_role[role] = record
    if set(by_role) != set(ARTIFACTS):
        raise BaselineError("baseline artifact roles do not match the required closed set")

    for role, expected_path in ARTIFACTS.items():
        record = by_role[role]
        if record.get("path") != expected_path:
            raise BaselineError(f"artifact {role!r} must name {expected_path!r}")
        expected_hash = record.get("sha256")
        if not isinstance(expected_hash, str) or SHA256_RE.fullmatch(expected_hash) is None:
            raise BaselineError(f"artifact {role!r} has an invalid SHA-256 value")
        artifact_path = root / expected_path
        if not artifact_path.is_file():
            raise BaselineError(f"frozen artifact is missing: {expected_path}")
        if artifact_path.is_symlink():
            raise BaselineError(f"frozen artifact may not be a symbolic link: {expected_path}")
        expected_mode = "100755" if role == "specification-validator" else "100644"
        actual_mode = "100755" if artifact_path.stat().st_mode & 0o111 else "100644"
        if actual_mode != expected_mode:
            raise BaselineError(
                f"frozen artifact mode changed: {expected_path}: "
                f"{actual_mode} != {expected_mode}"
            )
        committed_mode = frozen_mode(root, frozen_commit, expected_path)
        if committed_mode != expected_mode:
            raise BaselineError(
                f"frozen commit mode disagrees for {expected_path}: "
                f"{committed_mode} != {expected_mode}"
            )
        actual_hash = sha256_file(artifact_path)
        if actual_hash != expected_hash:
            raise BaselineError(
                f"frozen artifact changed: {expected_path}: {actual_hash} != {expected_hash}"
            )
        committed_hash = hashlib.sha256(
            frozen_blob(root, frozen_commit, expected_path)
        ).hexdigest()
        if committed_hash != expected_hash:
            raise BaselineError(
                f"frozen commit disagrees for {expected_path}: "
                f"{committed_hash} != {expected_hash}"
            )

    manifest_hashes, manifest_profiles = parse_manifest(
        root / ARTIFACTS["specification-manifest"]
    )
    for role in (
        "architecture",
        "e2ee-companion",
        "federation-registry",
        "source-ledger",
        "specification-validator",
    ):
        record = by_role[role]
        path = ARTIFACTS[role]
        if manifest_hashes.get(path) != record["sha256"]:
            raise BaselineError(f"manifest and baseline disagree for {path}")

    profiles = baseline.get("profiles")
    if not isinstance(profiles, dict) or set(profiles) != set(PROFILES):
        raise BaselineError("baseline profiles do not match the required closed set")
    for baseline_name, manifest_name in PROFILES.items():
        profile = profiles[baseline_name]
        if not isinstance(profile, dict):
            raise BaselineError(f"profile {baseline_name!r} must be a table")
        sha256 = profile.get("sha256")
        encoded = profile.get("base64url")
        if not isinstance(sha256, str) or SHA256_RE.fullmatch(sha256) is None:
            raise BaselineError(f"profile {baseline_name!r} has an invalid SHA-256 value")
        if not isinstance(encoded, str):
            raise BaselineError(f"profile {baseline_name!r} has no base64url value")
        calculated = base64.urlsafe_b64encode(bytes.fromhex(sha256)).rstrip(b"=").decode("ascii")
        if encoded != calculated:
            raise BaselineError(f"profile {baseline_name!r} base64url does not encode its hash")
        manifest_profile = manifest_profiles.get(manifest_name, {})
        if manifest_profile.get("profile-sha256") != sha256:
            raise BaselineError(f"manifest SHA-256 disagrees for profile {manifest_name}")
        if manifest_profile.get("profile-base64url") != encoded:
            raise BaselineError(f"manifest base64url disagrees for profile {manifest_name}")

    completed = subprocess.run(
        ["bash", "scripts/check-spec.sh"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).strip()
        raise BaselineError(f"frozen specification checker failed: {details}")


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"baseline check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Run the baseline check from the repository root."""
    root = Path(__file__).resolve().parent.parent
    try:
        validate(root)
    except BaselineError as error:
        fail(str(error))
    print("specification baseline: ok")


if __name__ == "__main__":
    main()
