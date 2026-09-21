#!/usr/bin/env python3
"""Qualify the frozen daemon's production storage path on this host's native tuple."""

from __future__ import annotations

import json
import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from release_qualification.driver import command, context, finish
from release_qualification.process import execute
from release_qualification.records import QualificationError, canonical, file_digest, read_bytes, read_record, safe_path, write_once

EXT4_SUPER_MAGIC = 0xEF53
QUALIFIED_GROWTH_CEILING = 134_217_728
PHYSICAL_GROWTH_RESERVE = 268_435_456
REQUIRED_CASES = [
    "insert-empty", "insert-one", "replace-min", "delete-one", "insert-max-value", "replace-max-value",
    "delete-max-value", "insert-max-key", "insert-max-records", "delete-max-records", "mixed-max-records",
    "btree-split", "btree-merge", "fragmented", "checkpoint", "guard-temp-fsync", "guard-rename",
    "guard-directory-fsync", "reserve-equal", "reserve-minus-one", "reserve-plus-one",
]
BACKUP_CASES = ["backup-reserve-equal", "backup-reserve-minus-one", "backup-reserve-plus-one"]
PHASE_CASES = ["phase-guard-file-sync", "phase-guard-rename", "phase-guard-directory-sync", "phase-transaction-begin",
               "phase-checkpoint-install", "phase-manifest", "phase-backup-file-sync", "phase-backup-rename",
               "phase-backup-directory-sync"]
CASE_NAME = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
CONSTRUCTION_TESTS = re.compile(rb"^test stage_five_completion::(\w+) \.\.\. ok$", re.MULTILINE)
FAULT_TESTS = re.compile(rb"^test recovery_matrix::(\w+) \.\.\. ok$", re.MULTILINE)


def validate_summary(summary: dict[str, Any], target: str) -> dict[str, Any]:
    """Check the binary's JSON summary against the fixed release requirements."""
    if summary.get("schema_version") != 1 or summary.get("target") != target:
        raise QualificationError("storage summary belongs to another schema or target")
    if summary.get("filesystem_type") != EXT4_SUPER_MAGIC:
        raise QualificationError("storage qualification ran on a filesystem other than ext4")
    block = summary.get("block_size")
    if type(block) is not int or block <= 0 or block & (block - 1):
        raise QualificationError("storage summary block size is not a power of two")
    if type(summary.get("mount_flags")) is not int or type(summary.get("sample_count")) is not int or summary["sample_count"] < 1:
        raise QualificationError("storage summary omits mount flags or boundary samples")
    if summary.get("qualified_growth_ceiling") != QUALIFIED_GROWTH_CEILING or summary.get("physical_growth_reserve") != PHYSICAL_GROWTH_RESERVE:
        raise QualificationError("storage summary reports different growth constants")
    cases = summary.get("cases")
    if not isinstance(cases, list) or not cases or len(cases) > 65_535:
        raise QualificationError("storage summary has no cases")
    seen: dict[str, dict[str, Any]] = {}
    maximum = 0
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"name", "allocated_before", "allocated_after", "positive_delta"}:
            raise QualificationError("storage case has unknown fields")
        name = case["name"]
        if not isinstance(name, str) or not CASE_NAME.fullmatch(name) or name in seen:
            raise QualificationError("storage case name is invalid or repeated")
        for field in ("allocated_before", "allocated_after", "positive_delta"):
            if type(case[field]) is not int or case[field] < 0:
                raise QualificationError(f"storage case {name} has a non-integer {field}")
        if case["positive_delta"] != max(case["allocated_after"] - case["allocated_before"], 0):
            raise QualificationError(f"storage case {name} misreports its delta")
        if case["positive_delta"] > QUALIFIED_GROWTH_CEILING:
            raise QualificationError(f"storage case {name} exceeds the qualified growth ceiling")
        maximum = max(maximum, case["positive_delta"])
        seen[name] = case
    if summary.get("maximum_observed_growth") != maximum:
        raise QualificationError("storage summary maximum differs from its cases")
    missing = [name for name in REQUIRED_CASES + BACKUP_CASES + PHASE_CASES if name not in seen]
    if missing:
        raise QualificationError("storage summary omits cases: " + ", ".join(missing))
    for refused in ("reserve-plus-one", "backup-reserve-plus-one"):
        if seen[refused]["positive_delta"] != 0:
            raise QualificationError(f"{refused} must be a side-effect-free refusal")
    for admitted in ("reserve-equal", "reserve-minus-one", "backup-reserve-equal", "backup-reserve-minus-one"):
        if seen[admitted]["allocated_after"] < seen[admitted]["allocated_before"]:
            raise QualificationError(f"{admitted} did not admit a durable write")
    return seen


def embedded_tuple(metadata: dict[str, Any], target: str) -> dict[str, Any]:
    tuples = metadata.get("storage_qualification", {}).get("tuples")
    if not isinstance(tuples, list) or len(tuples) != 1:
        raise QualificationError("binary does not report exactly one embedded storage tuple")
    embedded = tuples[0]
    if embedded.get("target") != target or embedded.get("filesystem_type") != EXT4_SUPER_MAGIC:
        raise QualificationError("embedded storage tuple is not this target's ext4 tuple")
    if type(embedded.get("maximum_observed_growth")) is not int or embedded["maximum_observed_growth"] > QUALIFIED_GROWTH_CEILING:
        raise QualificationError("embedded storage report exceeds the qualified growth ceiling")
    return embedded


def tmpfs_root() -> Path:
    for candidate in (Path("/dev/shm"), Path("/run/user") / str(os.getuid())):
        try:
            if candidate.is_dir() and os.statvfs(candidate).f_bsize and os.access(candidate, os.W_OK):
                return candidate
        except OSError:
            continue
    raise QualificationError("no writable tmpfs directory is available to prove tuple refusal")


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    candidate, directory, attempt, target = context(root)
    artifact = next(item for item in candidate["artifacts"] if item["target"] == target)
    binary = safe_path(directory, artifact["path"])
    evidence = attempt / "evidence"
    work = attempt / "work"
    work.mkdir(mode=0o700, exist_ok=True)
    evidence.mkdir(mode=0o700, exist_ok=True)
    command(root, attempt, "conformance", [str(binary), "conformance", "--json"], 30)
    metadata = read_record(attempt / "evidence/conformance.log")
    embedded = embedded_tuple(metadata, target)
    qualify = [str(binary), "storage", "qualify", "--state-dir", str(work / "state"), "--scratch-dir", str(work / "scratch"),
               "--unsigned-report", str(evidence / "storage-qualification.unsigned"), "--raw-log", str(evidence / "storage-qualification.log"),
               "--json", str(evidence / "storage-qualification.json")]
    command(root, attempt, "storage-qualify", qualify, 7200)
    if file_digest(binary) != artifact["sha256"]:
        raise QualificationError("candidate binary changed during storage qualification")
    summary = read_record(evidence / "storage-qualification.json")
    cases = validate_summary(summary, target)
    for field in ("filesystem_type", "block_size", "mount_flags"):
        if summary[field] != embedded[field]:
            raise QualificationError(f"fresh measurement tuple differs from the embedded report: {field}")
    refusal_root = tmpfs_root() / f"agenc-stage10-storage-{os.getpid()}"
    refusal_root.mkdir(mode=0o700)
    try:
        refusal = [str(binary), "storage", "qualify", "--state-dir", str(refusal_root / "state"), "--scratch-dir", str(refusal_root / "scratch"),
                   "--unsigned-report", str(refusal_root / "report"), "--raw-log", str(refusal_root / "log")]
        measured = execute(refusal, root, dict(os.environ), evidence / "tmpfs-refusal.log", 600)
    finally:
        shutil.rmtree(refusal_root, ignore_errors=True)
    refusal_log = read_bytes(evidence / "tmpfs-refusal.log")
    if measured["exit_code"] == 0 or measured["failure"] is not None or b"storage qualify failed" not in refusal_log:
        raise QualificationError("the frozen daemon admitted an unqualified filesystem tuple")
    write_once(evidence / "tmpfs-refusal.json", canonical({"argv": refusal, "measurement": measured, "tmpfs_root": str(refusal_root.parent)}))
    fault_environment = {**os.environ, "CARGO_TARGET_DIR": str(work / "target")}
    command(root, attempt, "storage-fault-matrix", ["cargo", "test", "-p", "agenc-relay-storage", "--test", "stage_five", "--frozen", "--release", "--", "--test-threads=4"], 7200, fault_environment)
    fault_log = read_bytes(evidence / "storage-fault-matrix.log", 64 * 1024 * 1024)
    construction = set(CONSTRUCTION_TESTS.findall(fault_log))
    faults = set(FAULT_TESTS.findall(fault_log))
    if len(construction) < 4 or len(faults) < 4 or b"test result: ok." not in fault_log or b"FAILED" in fault_log:
        raise QualificationError("the frozen storage fault and construction matrix did not pass completely")
    write_once(evidence / "storage-summary.json", canonical({
        "embedded_tuple": embedded, "fresh_maximum_observed_growth": summary["maximum_observed_growth"],
        "unsigned_report_sha256": file_digest(evidence / "storage-qualification.unsigned"),
        "raw_log_sha256": file_digest(evidence / "storage-qualification.log"),
        "construction_tests": sorted(name.decode() for name in construction), "fault_tests": sorted(name.decode() for name in faults),
        "cases": {name: case["positive_delta"] for name, case in cases.items()},
    }))
    finish(attempt, "storage", {"native_tuple": True, "production_storage_path": True, "all_growth_cases": True,
                                "sync_rename_phases": True, "reserve_boundaries": True, "backup_boundaries": True,
                                "construction_boundaries": True, "signed_measurements": True})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QualificationError, OSError, ValueError, KeyError, TypeError, json.JSONDecodeError) as error:
        print(f"storage qualification: {error}", file=sys.stderr)
        sys.exit(1)
