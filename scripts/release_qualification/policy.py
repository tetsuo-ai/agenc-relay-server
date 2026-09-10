"""Resolve the committed release contract without caller-supplied test commands."""

from __future__ import annotations

import os
import runpy
import tomllib
from pathlib import Path
from typing import Any

from .records import (
    CLAIMS, COMMIT, IDENTIFIER, TARGETS, QualificationError, canonical, digest,
    read_bytes, require_fields, require_integer,
)

POLICY_PATH = "conformance/stage-ten-qualification.toml"
POLICY_FIELDS = {
    "schema_version", "targets", "release_features", "claims", "minimum_branch_percent",
    "minimum_line_percent", "critical_percent", "fuzz_cpu_seconds_per_target",
    "soak_elapsed_seconds", "maximum_log_bytes", "maximum_record_bytes", "maximum_workers",
    "external_review_task", "job",
}
JOB_FIELDS = {"id", "tasks", "kind", "argv", "timeout_seconds"}
REQUIRED_JOBS = {
    "workspace": ["S10-002", "S10-003"], "models": ["S10-004"],
    "interoperability": ["S10-005"], "storage": ["S10-006"],
    "capacity": ["S10-007"], "soak": ["S10-007"],
    "drills": ["S10-008", "S10-009"], "reproducibility": ["S10-010"],
    "sources": ["S10-011"], "claims": ["S10-012"],
}


PROBE_TIMEOUT_SECONDS = 60
PROBE_OUTPUT_BYTES = 4 * 1024 * 1024


def checked_run(root: Path, argv: list[str]) -> str:
    """Run a short tool probe with its output bounded while it executes."""
    import tempfile

    from .process import execute

    with tempfile.TemporaryDirectory(prefix="agenc-probe-") as scratch:
        log = Path(scratch) / "probe.log"
        result = execute(argv, root, dict(os.environ), log, PROBE_TIMEOUT_SECONDS, PROBE_OUTPUT_BYTES)
        if result["exit_code"] != 0 or result["failure"] is not None:
            raise QualificationError(f"tool probe refused: {argv[0]}")
        output = read_bytes(log, PROBE_OUTPUT_BYTES)
    try:
        return output.decode("utf-8").strip()
    except UnicodeError as error:
        raise QualificationError("tool probe returned non-UTF-8 output") from error


def load_policy(root: Path, *, require_drivers: bool = True) -> dict[str, Any]:
    try:
        policy = tomllib.loads(read_bytes(root / POLICY_PATH).decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as error:
        raise QualificationError("invalid Stage 10 policy") from error
    require_fields(policy, POLICY_FIELDS, "Stage 10 policy")
    required = {
        "schema_version": 1, "targets": list(TARGETS), "release_features": ["history", "wss"],
        "claims": list(CLAIMS), "minimum_branch_percent": 90, "minimum_line_percent": 90,
        "critical_percent": 100, "fuzz_cpu_seconds_per_target": 86400,
        "soak_elapsed_seconds": 604800, "maximum_log_bytes": 67108864,
        "maximum_record_bytes": 4194304, "maximum_workers": 16, "external_review_task": "S08-039",
    }
    for field, expected in required.items():
        if type(policy[field]) is not type(expected) or policy[field] != expected:
            raise QualificationError(f"qualification policy weakens or changes {field}")
    jobs = policy["job"]
    if not isinstance(jobs, list) or len(jobs) != len(REQUIRED_JOBS):
        raise QualificationError("qualification policy has an incomplete job inventory")
    seen: set[str] = set()
    for job in jobs:
        require_fields(job, JOB_FIELDS, "qualification job")
        name = job["id"]
        if not isinstance(name, str) or name not in REQUIRED_JOBS or name in seen:
            raise QualificationError("unknown or duplicate qualification job")
        seen.add(name)
        if job["tasks"] != REQUIRED_JOBS[name] or job["kind"] != ("soak" if name == "soak" else "command"):
            raise QualificationError("qualification task binding or job kind changed")
        require_integer(job["timeout_seconds"], 1, 612000, "job timeout")
        argv = job["argv"]
        if not isinstance(argv, list) or not 2 <= len(argv) <= 16 or not all(isinstance(arg, str) and arg and "\0" not in arg for arg in argv):
            raise QualificationError("invalid qualification argument vector")
        if argv[0] not in ("python3", "bash") or not argv[1].startswith("scripts/") or ".." in Path(argv[1]).parts:
            raise QualificationError("qualification command must invoke a repository driver")
        if require_drivers and not (root / argv[1]).is_file():
            raise QualificationError(f"qualification driver is missing: {argv[1]}")
    return policy


def fuzz_jobs(root: Path) -> list[dict[str, Any]]:
    """Every committed fuzz binary must accumulate its own candidate CPU budget."""
    manifest = tomllib.loads(read_bytes(root / "fuzz/Cargo.toml").decode("utf-8"))
    jobs = []
    seen: set[str] = set()
    for binary in manifest.get("bin", []):
        name = binary.get("name")
        if not isinstance(name, str) or not IDENTIFIER.fullmatch(name) or name in seen:
            raise QualificationError("invalid fuzz target inventory")
        seen.add(name)
        jobs.append({
            "id": f"fuzz.{name}", "tasks": ["S10-004"], "kind": "fuzz",
            "argv": ["python3", "scripts/run-stage-ten-fuzz.py", name],
            "timeout_seconds": 90000,
        })
    if not jobs:
        raise QualificationError("release candidate has no fuzz targets")
    return sorted(jobs, key=lambda job: job["id"])


def source_identity(root: Path) -> dict[str, str]:
    """Reuse the existing recorder's clean detached-source and environment checks."""
    gate = runpy.run_path(str(root / "scripts/run-gate.py"))
    injected = [name for name in os.environ if name in gate["INJECTION_ENVIRONMENT"] or name.startswith(gate["INJECTION_ENVIRONMENT_PREFIXES"])]
    if injected:
        raise QualificationError("candidate preparation rejects injection variables: " + ", ".join(sorted(injected)))
    try:
        commit = gate["require_clean_source"](root)
        evidence = gate["evidence_policy"](root)
        return {
            "commit": commit,
            "source_sha256": evidence["canonical_source_sha256"](root, commit),
            "lock_sha256": evidence["commit_blob_sha256"](root, commit, "Cargo.lock"),
        }
    except (ValueError, OSError) as error:
        raise QualificationError(str(error)) from error


def host_target(root: Path) -> str:
    verbose = checked_run(root, ["rustc", "-vV"])
    hosts = [line.removeprefix("host: ") for line in verbose.splitlines() if line.startswith("host: ")]
    if len(hosts) != 1 or hosts[0] not in TARGETS:
        raise QualificationError("qualification requires a declared native Rust host")
    return hosts[0]


def policy_identity(root: Path) -> dict[str, str]:
    inputs = [POLICY_PATH, "conformance/toolchain-policy.toml", "conformance/critical-coverage.toml", "fuzz/Cargo.toml", "fuzz/Cargo.lock"]
    inputs.extend(path.relative_to(root).as_posix() for path in sorted((root / "scripts/release_qualification").glob("*.py")))
    return {name: digest(read_bytes(root / name)) for name in sorted(inputs)}
