#!/usr/bin/env python3
"""Generate a stage evidence manifest from one recorded gate artifact."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import runpy
import sys
import tempfile
from pathlib import Path
from typing import NoReturn

ARTIFACT_DIRECTORY = Path("conformance/evidence/artifacts")
MANIFEST_DIRECTORY = Path("conformance/evidence")
GATE_STAGES = {
    "stage-zero-implementation": 0,
    "stage-one-implementation": 1,
    "stage-two-implementation": 2,
    "stage-three-implementation": 3,
    "stage-four-implementation": 4,
    "stage-five-implementation": 5,
    "stage-six-implementation": 6,
}


class GenerationError(ValueError):
    """One evidence manifest could not be generated safely."""


def repository_path(
    root: Path,
    value: str,
    expected_parent: Path,
    *,
    must_exist: bool,
) -> tuple[Path, str]:
    """Resolve one canonical repository-local JSON path."""
    relative = Path(value)
    if (
        relative.is_absolute()
        or relative.as_posix() != value
        or ".." in relative.parts
        or relative.suffix != ".json"
        or relative.parent != expected_parent
    ):
        raise GenerationError(
            f"path must name a JSON file directly under {expected_parent.as_posix()}"
        )
    candidate = root / relative
    cursor = root
    for part in relative.parent.parts:
        cursor /= part
        if cursor.is_symlink():
            raise GenerationError("evidence paths may not traverse symbolic links")
    if must_exist:
        try:
            resolved = candidate.resolve(strict=True)
        except OSError as error:
            raise GenerationError(f"cannot read {value}: {error}") from error
        expected_directory = (root / expected_parent).resolve(strict=True)
        if not resolved.is_relative_to(expected_directory) or not resolved.is_file():
            raise GenerationError(f"path is not a regular file under {expected_parent}")
        if candidate.is_symlink():
            raise GenerationError("evidence paths may not traverse symbolic links")
    elif candidate.exists() or candidate.is_symlink():
        raise GenerationError(f"output already exists: {value}")
    return candidate, relative.as_posix()


def load_policy(root: Path) -> dict[str, object]:
    """Load the checked-in evidence validator as the generation authority."""
    return runpy.run_path(
        str(root / "scripts/check-evidence.py"),
        run_name="agenc_ircd_evidence_policy",
    )


def require_artifact_identity(
    artifact_relative: str,
    gate: str,
    source_commit: str,
) -> None:
    """Require the deterministic filename bound to a gate and source commit."""
    expected = (ARTIFACT_DIRECTORY / f"{gate}-{source_commit}.json").as_posix()
    if artifact_relative != expected:
        raise GenerationError("artifact path does not match its gate and source commit")


def build_manifest(
    root: Path,
    artifact_path: Path,
    artifact_relative: str,
) -> dict[str, object]:
    """Build and validate one manifest without changing repository state."""
    policy = load_policy(root)
    try:
        load_json = policy["load_json"]
        validate_catalog = policy["validate_catalog"]
        canonical_source_sha256 = policy["canonical_source_sha256"]
        commit_blob_sha256 = policy["commit_blob_sha256"]
        required_stage_evidence_ids = policy["required_stage_evidence_ids"]
        source_gate_policy = policy["source_gate_policy"]
        source_toolchain_policy = policy["source_toolchain_policy"]
        validate_manifest = policy["validate_manifest"]
        validate_run_artifact = policy["validate_run_artifact"]

        artifact = load_json(artifact_path)  # type: ignore[operator]
        gate = artifact.get("gate")
        if not isinstance(gate, str) or gate not in GATE_STAGES:
            raise GenerationError("artifact does not name a closable stage gate")
        stage = GATE_STAGES[gate]
        source_commit = artifact.get("source_commit")
        if not isinstance(source_commit, str):
            raise GenerationError("artifact does not name a source commit")
        require_artifact_identity(artifact_relative, gate, source_commit)

        bindings = validate_catalog(root)  # type: ignore[operator]
        source_hash = canonical_source_sha256(root, source_commit)  # type: ignore[operator]
        lock_hash = commit_blob_sha256(  # type: ignore[operator]
            root, source_commit, "Cargo.lock"
        )
        required_ids = required_stage_evidence_ids(  # type: ignore[operator]
            root, stage, source_commit
        )
        gate_name, runner_hash, gate_hash, commands = source_gate_policy(  # type: ignore[operator]
            root, stage, source_commit
        )
        toolchain_policy_hash, expected_toolchain, expected_limitations = (  # type: ignore[operator]
            source_toolchain_policy(root, stage, source_commit)
        )
    except (KeyError, OSError, TypeError, ValueError) as error:
        raise GenerationError(f"cannot resolve evidence policy: {error}") from error

    artifact_hash = hashlib.sha256(artifact_path.read_bytes()).hexdigest()
    tool = artifact.get("tool")
    features = artifact.get("features")
    argv = artifact.get("argv")
    if (
        not isinstance(tool, dict)
        or not isinstance(features, list)
        or not isinstance(argv, list)
        or any(not isinstance(argument, str) for argument in argv)
    ):
        raise GenerationError("artifact metadata is malformed")

    entries: list[dict[str, object]] = []
    for evidence_id in sorted(required_ids):
        claims = bindings.get(evidence_id)
        if claims is None:
            raise GenerationError(f"evidence ID has no catalog binding: {evidence_id}")
        entries.append(
            {
                "evidence_id": evidence_id,
                "claim_ids": claims,
                "command": " ".join(argv),
                "tool": tool,
                "toolchain_policy_sha256": artifact.get(
                    "toolchain_policy_sha256"
                ),
                "toolchain": artifact.get("toolchain"),
                "source_commit": source_commit,
                "source_sha256": source_hash,
                "lock_sha256": lock_hash,
                "target": artifact.get("target"),
                "features": features,
                "started_at": artifact.get("started_at"),
                "ended_at": artifact.get("ended_at"),
                "result": artifact.get("result"),
                "artifact": {
                    "label": f"Stage {stage:02d} exact-source gate run",
                    "sha256": artifact_hash,
                    "path": artifact_relative,
                },
                "limitations": artifact.get("limitations"),
            }
        )

    manifest = {
        "schema_version": 2,
        "manifest_id": (
            f"EVID-MANIFEST-STAGE-{stage:02d}-{source_commit[:16].upper()}"
        ),
        "source_commit": source_commit,
        "source_sha256": source_hash,
        "lock_sha256": lock_hash,
        "entries": entries,
    }
    try:
        validate_manifest(manifest, bindings)  # type: ignore[operator]
        validate_run_artifact(  # type: ignore[operator]
            artifact_path,
            entries,
            required_ids,
            gate_name=gate_name,
            runner_hash=runner_hash,
            gate_hash=gate_hash,
            expected_commands=commands,
            toolchain_policy_hash=toolchain_policy_hash,
            expected_toolchain=expected_toolchain,
            expected_limitations=expected_limitations,
            source_commit=source_commit,
            source_hash=source_hash,
            lock_hash=lock_hash,
        )
    except (OSError, TypeError, ValueError) as error:
        raise GenerationError(f"generated manifest does not validate: {error}") from error
    return manifest


def manifest_path(
    root: Path,
    manifest: dict[str, object],
) -> tuple[Path, str]:
    """Derive the deterministic output path from validated manifest identity."""
    manifest_id = manifest.get("manifest_id")
    source_commit = manifest.get("source_commit")
    prefix = "EVID-MANIFEST-STAGE-"
    if (
        not isinstance(manifest_id, str)
        or not manifest_id.startswith(prefix)
        or not isinstance(source_commit, str)
    ):
        raise GenerationError("generated manifest identity is malformed")
    stage_text = manifest_id[len(prefix) : len(prefix) + 2]
    if not stage_text.isdigit():
        raise GenerationError("generated manifest has a noncanonical stage")
    relative = MANIFEST_DIRECTORY / f"stage-{stage_text}-{source_commit}.json"
    return repository_path(
        root,
        relative.as_posix(),
        MANIFEST_DIRECTORY,
        must_exist=False,
    )


def write_manifest(destination: Path, relative: str, manifest: dict[str, object]) -> None:
    """Atomically create one canonical JSON manifest without overwriting data."""
    encoded = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    temporary_path: Path | None = None
    destination_linked = False
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=destination.parent,
        )
        temporary_path = Path(temporary_name)
        with os.fdopen(descriptor, "wb") as output:
            os.fchmod(output.fileno(), 0o644)
            output.write(encoded)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary_path, destination)
        destination_linked = True
        temporary_path.unlink()
        temporary_path = None
        directory_descriptor = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError as error:
        rollback_errors: list[str] = []
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except OSError as cleanup_error:
                rollback_errors.append(f"temporary file: {cleanup_error}")
        if destination_linked:
            try:
                destination.unlink()
            except OSError as cleanup_error:
                rollback_errors.append(f"destination: {cleanup_error}")
        rollback = ""
        if rollback_errors:
            rollback = "; rollback failed for " + ", ".join(rollback_errors)
        raise GenerationError(
            f"cannot create evidence manifest {relative}: {error}{rollback}"
        ) from error
    try:
        print(f"evidence manifest: {relative}", flush=True)
    except (OSError, ValueError):
        sys.stdout = None


def fail(message: str) -> NoReturn:
    """Report one stable generation error and exit unsuccessfully."""
    print(f"gate evidence generation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Generate one manifest from one passed gate-run artifact."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", required=True)
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        artifact_path, artifact_relative = repository_path(
            root,
            arguments.artifact,
            ARTIFACT_DIRECTORY,
            must_exist=True,
        )
        manifest = build_manifest(root, artifact_path, artifact_relative)
        output_path, output_relative = manifest_path(root, manifest)
        write_manifest(output_path, output_relative, manifest)
    except (GenerationError, OSError, UnicodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
