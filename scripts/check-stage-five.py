#!/usr/bin/env python3
"""Validate the closed Stage-05 storage implementation profile and surfaces."""

from __future__ import annotations

import argparse
import copy
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

PROFILE_PATH = "conformance/stage-five-storage-profile.toml"
EXPECTED_MODULES = {
    "backup.rs", "codec.rs", "construction.rs", "construction_directory.rs",
    "construction_runtime.rs", "construction_schema.rs", "control.rs", "domain_records.rs", "engine.rs", "error.rs",
    "fault.rs", "e2ee_records.rs",
    "migration.rs", "migration_command.rs", "migration_profile.rs", "migration_v2.rs",
    "federation_records.rs", "initialize.rs", "integrity.rs", "lib.rs", "login_index.rs",
    "mutation.rs", "owner.rs", "platform.rs", "qualification.rs", "qualification_workload.rs",
    "records.rs",
    "recovery.rs", "redb_store.rs", "restore_command.rs", "schema.rs", "sealed.rs", "source_validation.rs",
}
EXPECTED_TASKS = [f"S05-{number:03d}" for number in range(1, 16)]
QUALIFICATION_TARGETS = (
    "aarch64-unknown-linux-gnu",
    "x86_64-unknown-linux-gnu",
)
QUALIFICATION_CASES = {
    "insert-empty", "insert-one", "replace-min", "delete-one",
    "insert-max-value", "replace-max-value", "delete-max-value",
    "insert-max-key", "insert-max-records", "delete-max-records",
    "mixed-max-records", "btree-split", "btree-merge", "fragmented",
    "checkpoint", "guard-temp-fsync", "guard-rename",
    "guard-directory-fsync", "reserve-equal", "reserve-minus-one",
    "reserve-plus-one",
}
REQUIRED_SURFACES = (
    "pub struct SealedRecord",
    "pub struct StateMeta",
    "pub struct StorageMutationBatch",
    "pub struct StorageOwner",
    "pub struct StoragePort",
    "pub enum RecoveryDisposition",
    "pub struct IntegrityManifest",
    "pub struct IntegrityCheckpoint",
    "pub struct RollbackGuard",
    "pub struct StorageConstruction",
    "pub struct BackupStreamWriter",
    "pub struct BackupOutput",
    "pub enum LoginIndexKeyState",
    "pub struct ConstructionTarget",
    "pub struct ConstructionDirectory",
    "pub struct StorageQualificationReport",
    "pub struct StorageFaultSchedule",
    "pub struct PersistentRecordValue",
)


class StageFiveError(ValueError):
    """One Stage-05 policy check failed."""


def load_profile(path: Path) -> dict[str, object]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StageFiveError(f"cannot read storage profile: {error}") from error


def validate_profile(profile: dict[str, object]) -> None:
    if profile.get("schema_version") != 1 or profile.get("stage") != 5:
        raise StageFiveError("storage profile header is invalid")
    if profile.get("tasks") != EXPECTED_TASKS:
        raise StageFiveError("storage profile task set is stale")
    database = profile.get("database")
    if not isinstance(database, dict) or database != {
        "engine": "redb", "version": "4.2.0", "database_format": 1,
        "schema_generation": 3, "table_count": 27, "durability": "Immediate",
        "two_phase_commit": True, "writer_threads": 1,
        "request_queue_capacity": 2, "handoff_slot_bytes": 58_720_240,
    }:
        raise StageFiveError("database profile differs from the reviewed contract")
    limits = profile.get("limits")
    if not isinstance(limits, dict) or limits.get("physical_growth_bytes") != 268_435_456:
        raise StageFiveError("storage limit profile is missing the fixed growth allowance")
    if limits.get("checkpoint_manifests") != 100_000:
        raise StageFiveError("storage limit profile is missing the checkpoint target")
    closure = profile.get("closure")
    if not isinstance(closure, dict) or closure != {
        "implementation_gate": "stage-five-implementation",
        "exact_sha_checkpoint_required": True,
        "release_growth_signature_required": True,
    }:
        raise StageFiveError("Stage-05 closure requirements are stale")


def validate_sources(root: Path) -> None:
    source_root = root / "crates/agenc-ircd-storage/src"
    modules = {path.name for path in source_root.glob("*.rs")}
    if modules != EXPECTED_MODULES:
        raise StageFiveError("storage module inventory is missing or unexpected")
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source_root.glob("*.rs"))
    if any(surface not in combined for surface in REQUIRED_SURFACES):
        raise StageFiveError("storage crate is missing a required Stage-05 surface")
    manifest = tomllib.loads((root / "crates/agenc-ircd-storage/Cargo.toml").read_text())
    if set(manifest.get("dependencies", {})) != {
        "agenc-ircd-crypto", "agenc-ircd-domain", "agenc-ircd-e2ee",
        "agenc-ircd-types", "redb", "rustix", "subtle", "zeroize",
    }:
        raise StageFiveError("storage dependency boundary differs from the closed set")
    fuzz = tomllib.loads((root / "fuzz/Cargo.toml").read_text())
    bins = {entry.get("name") for entry in fuzz.get("bin", [])}
    if not {"storage_codecs", "backup_stream"}.issubset(bins):
        raise StageFiveError("Stage-05 fuzz targets are missing")
    evidence_root = root / "conformance/evidence/storage-qualification"
    expected_artifacts = {"release-public-key.bin"}
    for target in QUALIFICATION_TARGETS:
        expected_artifacts.update(
            {
                f"{target}-ext4.log",
                f"{target}-ext4.report",
                f"{target}-ext4.unsigned",
            }
        )
    actual_artifacts = {path.name for path in evidence_root.iterdir() if path.is_file()}
    if actual_artifacts != expected_artifacts:
        raise StageFiveError("storage qualification artifact set is incomplete or unexpected")
    if (evidence_root / "release-public-key.bin").stat().st_size != 32:
        raise StageFiveError("storage qualification release key has the wrong size")
    for target in QUALIFICATION_TARGETS:
        log = (evidence_root / f"{target}-ext4.log").read_text(encoding="ascii")
        case_names = [line.partition("|")[0] for line in log.splitlines()]
        if len(case_names) != len(QUALIFICATION_CASES) or set(case_names) != QUALIFICATION_CASES:
            raise StageFiveError(f"{target} qualification log has a stale case set")
        report_paths = (
            evidence_root / f"{target}-ext4.report",
            evidence_root / f"{target}-ext4.unsigned",
        )
        if any(path.stat().st_size == 0 for path in report_paths):
            raise StageFiveError(f"{target} qualification report is empty")


def self_test(root: Path) -> int:
    profile = load_profile(root / PROFILE_PATH)
    cases = 0
    for field, value in (("stage", 4), ("tasks", EXPECTED_TASKS[:-1])):
        changed = copy.deepcopy(profile)
        changed[field] = value
        try:
            validate_profile(changed)
        except StageFiveError:
            cases += 1
        else:
            raise StageFiveError(f"self-test accepted changed {field}")
    return cases


def fail(message: str) -> NoReturn:
    print(f"Stage-05 validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    command = parser.parse_args().command
    root = Path(__file__).resolve().parent.parent
    try:
        if command == "check":
            validate_profile(load_profile(root / PROFILE_PATH))
            validate_sources(root)
            print(f"Stage-05 storage profile: ok ({len(EXPECTED_MODULES)} modules, 2 fuzz targets)")
        else:
            print(f"Stage-05 storage profile self-test: ok ({self_test(root)} rejection cases)")
    except (OSError, StageFiveError, tomllib.TOMLDecodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
