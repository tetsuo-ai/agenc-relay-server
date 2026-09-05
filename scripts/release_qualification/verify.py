"""Validate retained execution records before counting any release evidence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from .locks import attempt_entries, job_running
from .records import (MAX_LOG_BYTES, QualificationError, canonical, digest, file_digest,
                      read_record, require_fields, require_hash, require_integer, safe_path, target_scope, timestamp)

RESULT_FIELDS = {"schema_version", "candidate_sha256", "start_sha256", "finished_at", "job_id", "target", "outcome", "measurement", "report_sha256"}
MEASUREMENT_FIELDS = {"exit_code", "failure", "elapsed_ns", "cpu_user_ns", "cpu_system_ns", "maximum_rss_kib", "log_sha256", "log_bytes"}
REPORT_FIELDS = {"schema_version", "job_id", "candidate_sha256", "target", "facts", "artifacts"}
# Boolean qualification facts every driver of that job must attest; each must be exactly true.
REQUIRED_FACTS = {
    "models": {"models", "loom", "cancellation", "overload", "panic_containment", "shutdown", "miri", "sanitizers"},
    "interoperability": {"weechat", "irssi", "native_accounts", "openmls", "mls_rs", "federation", "tls", "wss", "tor_v3", "socks_isolation", "packet_capture", "dns_leaks", "metadata_canaries", "timing_classes", "trust_presentation", "safe_rendering"},
    "storage": {"native_tuple", "production_storage_path", "all_growth_cases", "sync_rename_phases", "reserve_boundaries", "backup_boundaries", "construction_boundaries", "signed_measurements"},
    "drills": {"restore", "disaster_restore", "migration", "deletion", "rekey", "index_transition", "tls_rotation", "federation_rotation", "sequencer_rotation", "backup_rotation", "audit_rotation", "compromise", "rollback", "resynchronization", "host_hardening", "observability"},
    "sources": {"primary_sources", "advisories", "dependency_policy", "decisions_current"},
    "claims": {"binary_identity", "separate_claims", "privacy_limits", "documentation_current", "decision_inspection"},
}


def verify_report(attempt: Path, report: dict[str, Any], job: dict[str, Any], candidate_hash: str, target: str) -> None:
    require_fields(report, REPORT_FIELDS, "driver report")
    if report["schema_version"] != 1 or type(report["schema_version"]) is not int or report["job_id"] != job["id"] or report["candidate_sha256"] != candidate_hash or report["target"] != target:
        raise QualificationError("driver report belongs to another candidate, job, or target")
    artifacts = report["artifacts"]
    if not isinstance(artifacts, dict) or not artifacts or len(artifacts) > 4096:
        raise QualificationError("driver report omits raw evidence or exceeds its artifact bound")
    for name, expected in artifacts.items():
        if file_digest(safe_path(attempt, name)) != require_hash(expected, "driver artifact"):
            raise QualificationError(f"driver artifact changed: {name}")
    facts = report["facts"]
    if not isinstance(facts, dict):
        raise QualificationError("driver facts must be an object")
    name = job["id"]
    if name == "workspace":
        require_fields(facts, {"feature_combinations", "branch_percent", "line_percent", "critical_percent", "critical_categories", "critical_inventory_complete"}, "workspace facts")
        if facts["feature_combinations"] != [[], ["history"], ["wss"], ["history", "wss"]]:
            raise QualificationError("feature matrix is incomplete")
        for field, minimum in (("branch_percent", 90), ("line_percent", 90), ("critical_percent", 100)):
            if type(facts[field]) not in (int, float) or not minimum <= facts[field] <= 100:
                raise QualificationError(f"release coverage requirement failed: {field}")
        if facts["critical_inventory_complete"] is not True or facts["critical_categories"] != ["authorization-decisions", "parser-error-discriminants", "persistence-recovery", "protocol-enum-arms", "section-27-invariant-checkers"]:
            raise QualificationError("critical coverage inventory is incomplete")
    elif name.startswith("fuzz."):
        require_fields(facts, {"fuzz_target", "cpu_ns", "sanitizer", "corpus_before", "corpus_after", "crashes"}, "fuzz facts")
        require_integer(facts["crashes"], 0, 0, "fuzz crashes")
        if facts["fuzz_target"] != name.removeprefix("fuzz.") or facts["sanitizer"] != "address":
            raise QualificationError("fuzz target, sanitizer, or crash result differs")
        require_integer(facts["cpu_ns"], 86400 * 10**9, 10**18, "fuzz CPU time")
        require_hash(facts["corpus_before"], "initial corpus")
        require_hash(facts["corpus_after"], "final corpus")
    elif name in ("capacity", "soak"):
        require_fields(facts, {"elapsed_ns", "samples", "missed_events", "envelope_violations", "returned_to_envelope", "scenario_counts", "latency_classes", "capacity_demonstrated", "hardware", "resource_source", "messages_refused"}, "capacity facts")
        require_integer(facts["elapsed_ns"], (604800 if name == "soak" else 300) * 10**9, 10**18, "campaign duration")
        if facts["resource_source"] not in ("cgroup", "procfs"):
            raise QualificationError("capacity evidence does not name how daemon resources were measured")
        require_integer(facts["messages_refused"], 0, 10**12, "refused messages")
        require_integer(facts["samples"], 2, 10**9, "campaign samples")
        require_integer(facts["missed_events"], 0, 0, "missed events")
        require_integer(facts["envelope_violations"], 0, 0, "envelope violations")
        if facts["returned_to_envelope"] is not True or facts["capacity_demonstrated"] is not True:
            raise QualificationError("capacity or sustained-operation envelope failed")
        require_fields(facts["scenario_counts"], {"reconnect", "churn", "rekey", "index_transition", "snapshot", "backup", "disk_pressure", "peer_loss"}, "campaign scenarios")
        for scenario in ("reconnect", "churn", "rekey", "index_transition", "snapshot", "backup", "disk_pressure", "peer_loss"):
            require_integer(facts["scenario_counts"].get(scenario), 1, 10**9, scenario)
        if facts["latency_classes"] != ["admission", "durable_mutation", "fanout", "message", "opaque", "snapshot"] or not isinstance(facts["hardware"], str) or not facts["hardware"].strip():
            raise QualificationError("capacity evidence omits latency classes or named hardware")
    elif name == "reproducibility":
        require_fields(facts, {"independent_builds", "native_target", "binary_sha256"}, "reproducibility facts")
        require_integer(facts["independent_builds"], 2, 2, "independent builds")
        if facts["native_target"] != target:
            raise QualificationError("reproducibility requires two native clean builds")
        require_hash(facts["binary_sha256"], "reproduced binary")
    else:
        require_fields(facts, REQUIRED_FACTS[name], f"{name} facts")
        if any(value is not True for value in facts.values()):
            raise QualificationError(f"{name} has incomplete qualification checks")


def verify_attempt(directory: Path, candidate: dict[str, Any], attempt: Path) -> dict[str, Any]:
    result = read_record(attempt / "result.json")
    start = read_record(attempt / "start.json")
    require_fields(result, RESULT_FIELDS, "job result")
    require_fields(start, {"schema_version", "candidate_sha256", "started_at", "job", "host"}, "job start")
    candidate_hash = digest(canonical(candidate))
    if result["schema_version"] != 1 or type(result["schema_version"]) is not int or start["schema_version"] != 1 or type(start["schema_version"]) is not int:
        raise QualificationError("unknown attempt schema")
    if result["candidate_sha256"] != candidate_hash or start["candidate_sha256"] != candidate_hash or result["start_sha256"] != file_digest(attempt / "start.json"):
        raise QualificationError("attempt identity or start record changed")
    jobs = {job["id"]: job for job in candidate["jobs"]}
    job = jobs.get(result["job_id"])
    target = result["target"]
    if job is None or start["job"] != job or target != start["host"]["target"] or target not in [item["target"] for item in candidate["artifacts"]]:
        raise QualificationError("attempt command or native target differs")
    relative = attempt.relative_to(directory).parts
    if len(relative) != 4 or relative[:3] != ("runs", target, job["id"]) or not relative[3].isdecimal():
        raise QualificationError("attempt was moved to another job")
    if timestamp(result["finished_at"]) < timestamp(start["started_at"]):
        raise QualificationError("attempt finished before it started")
    measurement = require_fields(result["measurement"], MEASUREMENT_FIELDS, "execution measurement")
    for field in ("elapsed_ns", "cpu_user_ns", "cpu_system_ns", "maximum_rss_kib"):
        require_integer(measurement[field], 0, 10**18, field)
    require_integer(measurement["log_bytes"], 0, MAX_LOG_BYTES, "log length")
    if measurement["log_sha256"] != file_digest(attempt / "output.log") or measurement["log_bytes"] != (attempt / "output.log").stat().st_size:
        raise QualificationError("raw command log changed")
    if result["outcome"] not in ("passed", "failed"):
        raise QualificationError("unknown execution outcome")
    if result["report_sha256"] is not None:
        if file_digest(attempt / "report.json") != require_hash(result["report_sha256"], "driver report"):
            raise QualificationError("driver report changed")
    if result["outcome"] == "passed":
        if measurement["exit_code"] != 0 or type(measurement["exit_code"]) is not int or measurement["failure"] is not None or result["report_sha256"] is None:
            raise QualificationError("failed execution cannot be counted as passing")
        report = read_record(attempt / "report.json")
        verify_report(attempt, report, job, candidate_hash, target)
        if job["kind"] == "soak" and measurement["elapsed_ns"] < report["facts"]["elapsed_ns"]:
            raise QualificationError("soak report exceeds measured execution time")
        if job["kind"] == "fuzz" and measurement["cpu_user_ns"] + measurement["cpu_system_ns"] < report["facts"]["cpu_ns"]:
            raise QualificationError("fuzz report exceeds measured child CPU time")
    return result


def status(directory: Path, candidate: dict[str, Any], targets: list[str] | None = None) -> dict[str, Any]:
    """Summarize every target/job pair in scope; a running job is neither passed nor interrupted.

    The scope defaults to every candidate target. A decision for fewer targets
    summarizes only those, so evidence missing for one target blocks only the
    claims that target would carry.
    """
    scope = target_scope(candidate["targets"], targets)
    output = {"candidate_sha256": digest(canonical(candidate)), "targets": scope, "passed": [], "failed": [],
              "interrupted": [], "running": [], "pending": [], "attempts": {}}
    for artifact in candidate["artifacts"]:
        if artifact["target"] not in scope:
            continue
        for job in candidate["jobs"]:
            name = f"{artifact['target']}/{job['id']}"
            attempts = safe_path(directory, f"runs/{name}")
            found_pass = False
            if attempts.exists():
                running = job_running(attempts)
                for attempt in attempt_entries(attempts):
                    if not (attempt / "result.json").exists():
                        output["running" if running else "interrupted"].append(f"{name}/{attempt.name}")
                        continue
                    result = verify_attempt(directory, candidate, attempt)
                    output["attempts"][attempt.relative_to(directory).as_posix()] = file_digest(attempt / "result.json")
                    if result["outcome"] == "passed":
                        found_pass = True
                    else:
                        output["failed"].append(f"{name}/{attempt.name}")
            output["passed" if found_pass else "pending"].append(name)
    output["ready"] = not any(output[field] for field in ("pending", "failed", "interrupted", "running"))
    return output
