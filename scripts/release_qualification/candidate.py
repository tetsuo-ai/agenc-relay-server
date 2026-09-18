"""Candidate identities and append-only per-host job attempts."""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path
from typing import Any

from .locks import attempt_entries, job_lock, shared
from .policy import checked_run, fuzz_jobs, host_target, load_policy, policy_identity, source_identity
from .process import execute
from .records import (
    CLAIMS, COMMIT, QualificationError, canonical, digest, file_digest,
    read_bytes, read_record, require_fields, require_hash, require_targets, safe_path, timestamp,
    utc_now, write_once,
)

CANDIDATE_FIELDS = {"schema_version", "created_at", "source", "policy", "jobs", "artifacts", "claims", "targets", "tools"}
ARTIFACT_FIELDS = {"target", "path", "sha256", "build_record", "build_record_sha256"}
TOOLS_FIELDS = {"schema_version", "target", "image", "clients", "tor_tools", "dockerfile_sha256", "build_log_sha256"}
TOOLS_ENTRY_FIELDS = {"target", "record", "record_sha256"}


def validate_tools(root: Path, record: dict[str, Any], targets: list[str]) -> None:
    """A client tools record must name the committed client pins and Dockerfile.

    The interoperability job runs the pinned WeeChat, Irssi, Tor, and packet
    capture tools from this image; the image is separate from the release
    build image and is bound into the candidate by its own record.
    """
    import tomllib

    from .build import immutable_image

    require_fields(record, TOOLS_FIELDS, "client tools record")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1 or record["target"] not in targets:
        raise QualificationError("client tools record has an unknown schema or a target outside the candidate")
    immutable_image(record["image"])
    require_hash(record["build_log_sha256"], "client tools build log")
    if record["dockerfile_sha256"] != file_digest(root / "conformance/clients/Dockerfile"):
        raise QualificationError("client tools image was built from another Dockerfile")
    versions = tomllib.loads(read_bytes(root / "conformance/clients/versions.toml").decode("utf-8"))
    tor_tools = tomllib.loads(read_bytes(root / "conformance/clients/tor-tools.toml").decode("utf-8"))
    if record["clients"] != versions["client"] or record["tor_tools"] != tor_tools:
        raise QualificationError("client tools image does not carry the committed client and Tor tool pins")


def prepare(root: Path, destination: Path, builds: list[Path], targets: list[str], tools: list[Path]) -> str:
    """Create a candidate for the named native targets from one build record each.

    A candidate may cover a subset of the native targets. Jobs run only for
    the recorded targets, and a decision can claim only those targets, so an
    x86_64 candidate can exist while aarch64 evidence is produced elsewhere.
    Each target also needs the record of its client tools image.
    """
    scope = require_targets(sorted(set(targets)))
    policy = load_policy(root)
    source = source_identity(root)
    if destination.exists():
        raise QualificationError("candidate destination already exists")
    tool_records = []
    for record_path in tools:
        record = read_record(record_path)
        validate_tools(root, record, scope)
        tool_records.append({"target": record["target"], "record": f"tools/{record['target']}/tools.json",
                             "record_sha256": digest(canonical(record))})
    if sorted(item["target"] for item in tool_records) != scope:
        raise QualificationError("prepare requires exactly one client tools record for each named target")
    artifacts = []
    for record_path in builds:
        record = read_record(record_path)
        from .build import validate_build
        validate_build(record_path.parent, record, source)
        target = record["target"]
        binary = safe_path(record_path.parent, record["binary"])
        artifacts.append({"target": target, "path": f"artifacts/{target}/agenc-ircd",
                          "sha256": file_digest(binary), "build_record": f"artifacts/{target}/build.json",
                          "build_record_sha256": digest(canonical(record))})
    if sorted(item["target"] for item in artifacts) != scope:
        raise QualificationError("prepare requires exactly one reproducible build for each named target")
    record = {"schema_version": 1, "created_at": utc_now(), "source": source,
              "policy": policy_identity(root), "jobs": policy["job"] + fuzz_jobs(root),
              "artifacts": sorted(artifacts, key=lambda item: item["target"]), "claims": list(CLAIMS),
              "targets": scope, "tools": sorted(tool_records, key=lambda item: item["target"])}
    destination.mkdir(mode=0o700, parents=True)
    for record_path in tools:
        tools_record = read_record(record_path)
        write_once(destination / "tools" / tools_record["target"] / "tools.json", canonical(tools_record))
    for record_path in builds:
        build = read_record(record_path)
        target_directory = destination / "artifacts" / build["target"]
        target_directory.mkdir(mode=0o700, parents=True)
        names = [build["binary"], build["sbom"], build["notices"], build["archive"]]
        names.extend(log["path"] for log in build["logs"])
        for name in names:
            original = safe_path(record_path.parent, name)
            copied = target_directory / original.name
            with original.open("rb") as source_file, copied.open("xb") as output:
                shutil.copyfileobj(source_file, output, 1024 * 1024)
                output.flush()
                os.fsync(output.fileno())
        (target_directory / "agenc-ircd").chmod(0o500)
        write_once(target_directory / "build.json", canonical(build))
    if source_identity(root) != source:
        raise QualificationError("source changed while preparing the candidate")
    write_once(destination / "candidate.json", canonical(record))
    return digest(canonical(record))


def validate_candidate(root: Path, directory: Path, *, check_source: bool = True) -> dict[str, Any]:
    record = read_record(directory / "candidate.json")
    require_fields(record, CANDIDATE_FIELDS, "candidate")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1 or record["claims"] != list(CLAIMS):
        raise QualificationError("unsupported candidate schema or claim set")
    timestamp(record["created_at"])
    require_fields(record["source"], {"commit", "source_sha256", "lock_sha256"}, "candidate source")
    if not isinstance(record["source"]["commit"], str) or not COMMIT.fullmatch(record["source"]["commit"]):
        raise QualificationError("invalid source commit")
    for name in ("source_sha256", "lock_sha256"):
        require_hash(record["source"][name], name)
    policy = load_policy(root)
    if record["policy"] != policy_identity(root) or record["jobs"] != policy["job"] + fuzz_jobs(root):
        raise QualificationError("candidate policy or commands differ from this source")
    if check_source and record["source"] != source_identity(root):
        raise QualificationError("candidate cannot resume on a different or modified source")
    targets = require_targets(record["targets"])
    artifacts = record["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != len(targets):
        raise QualificationError("incomplete candidate artifacts")
    seen = []
    for artifact in artifacts:
        require_fields(artifact, ARTIFACT_FIELDS, "candidate artifact")
        target = artifact["target"]
        if target not in targets or target in seen:
            raise QualificationError("unknown or repeated artifact target")
        seen.append(target)
        if artifact["path"] != f"artifacts/{target}/agenc-ircd" or artifact["build_record"] != f"artifacts/{target}/build.json":
            raise QualificationError("noncanonical artifact location")
        for path_key, hash_key in (("path", "sha256"), ("build_record", "build_record_sha256")):
            require_hash(artifact[hash_key], hash_key)
            if file_digest(safe_path(directory, artifact[path_key])) != artifact[hash_key]:
                raise QualificationError(f"candidate artifact changed: {artifact[path_key]}")
        from .build import validate_build
        build_path = safe_path(directory, artifact["build_record"])
        validate_build(build_path.parent, read_record(build_path), record["source"])
    tools = record["tools"]
    if not isinstance(tools, list) or [item.get("target") for item in tools if isinstance(item, dict)] != targets:
        raise QualificationError("candidate lacks one client tools record per target")
    for entry in tools:
        require_fields(entry, TOOLS_ENTRY_FIELDS, "candidate tools entry")
        if entry["record"] != f"tools/{entry['target']}/tools.json":
            raise QualificationError("noncanonical client tools record location")
        require_hash(entry["record_sha256"], "client tools record")
        tools_record = read_record(safe_path(directory, entry["record"]))
        if digest(canonical(tools_record)) != entry["record_sha256"] or tools_record["target"] != entry["target"]:
            raise QualificationError("candidate client tools record changed")
        validate_tools(root, tools_record, targets)
    return record


def host_identity(root: Path) -> dict[str, Any]:
    tools = {}
    for name, argv in {"rustc": ["rustc", "-vV"], "cargo": ["cargo", "--version"],
                       "python": ["python3", "--version"], "cc": ["cc", "--version"],
                       "ld": ["ld", "--version"], "git": ["git", "--version"],
                       "docker": ["docker", "--version"], "openssl": ["openssl", "version"],
                       "cargo-fuzz": ["cargo-fuzz", "--version"],
                       "cargo-llvm-cov": ["cargo-llvm-cov", "llvm-cov", "--version"],
                       "cargo-nextest": ["cargo-nextest", "nextest", "-V"],
                       "cargo-audit": ["cargo-audit", "--version"],
                       "cargo-deny": ["cargo-deny", "--version"]}.items():
        executable = shutil.which(argv[0])
        if executable is None:
            raise QualificationError(f"required host tool is absent: {argv[0]}")
        tools[name] = {"path": str(Path(executable).resolve()),
                       "sha256": file_digest(Path(executable).resolve()),
                       "version": checked_run(root, argv)}
    return {"target": host_target(root), "kernel": platform.release(),
            "cpu_affinity": sorted(os.sched_getaffinity(0)), "tools": tools,
            "cpu_model_sha256": digest("\n".join(line for line in read_bytes(Path("/proc/cpuinfo")).decode().splitlines()
                if line.split(":", 1)[0].strip() in {"vendor_id", "model name", "cpu family", "model", "stepping", "flags", "Features", "CPU implementer", "CPU architecture", "CPU variant", "CPU part", "CPU revision"}).encode()),
            "os_release_sha256": digest(read_bytes(Path("/etc/os-release").resolve()))}


def run_job(root: Path, directory: Path, job_id: str, *, resume: bool = False) -> dict[str, Any]:
    """Run one job under a shared candidate lock and an exclusive per-job lock.

    Long campaigns for different jobs may share a host. A release decision
    takes the exclusive candidate lock, so it cannot be signed while any job
    is still running.
    """
    with shared(directory):
        record = validate_candidate(root, directory)
        candidate_hash = digest(canonical(record))
        jobs = {job["id"]: job for job in record["jobs"]}
        if job_id not in jobs:
            raise QualificationError("unknown candidate job")
        host = host_identity(root)
        target = host["target"]
        if target not in [item["target"] for item in record["artifacts"]]:
            raise QualificationError("this candidate has no artifact for the host target")
        attempts = safe_path(directory, f"runs/{target}/{job_id}")
        attempts.mkdir(mode=0o700, parents=True, exist_ok=True)
        with job_lock(attempts):
            return run_attempt(root, directory, record, candidate_hash, jobs[job_id], host, attempts, resume=resume)


def run_attempt(root: Path, directory: Path, record: dict[str, Any], candidate_hash: str, job: dict[str, Any],
                host: dict[str, Any], attempts: Path, *, resume: bool) -> dict[str, Any]:
    target = host["target"]
    job_id = job["id"]
    existing = attempt_entries(attempts)
    if len(existing) >= 1000:
        raise QualificationError("invalid or exhausted job attempt directory")
    if existing and not resume:
        raise QualificationError("job already attempted; use resume to retain and inspect earlier attempts")
    from .verify import verify_attempt
    for previous in existing:
        if (previous / "result.json").exists():
            prior = verify_attempt(directory, record, previous)
            if prior["outcome"] == "passed":
                if read_record(previous / "start.json")["host"] != host:
                    raise QualificationError("passing attempt belongs to a different host tool identity")
                return prior
    attempt = attempts / f"{len(existing) + 1:04d}"
    attempt.mkdir(mode=0o700)
    start = {"schema_version": 1, "candidate_sha256": candidate_hash, "started_at": utc_now(),
             "job": job, "host": host}
    write_once(attempt / "start.json", canonical(start))
    environment = {key: value for key, value in os.environ.items() if not key.startswith("AGENC_")}
    environment.update({"AGENC_RELEASE_CANDIDATE": str(directory.resolve()),
                        "AGENC_RELEASE_ATTEMPT": str(attempt.resolve()),
                        "AGENC_RELEASE_TARGET": target,
                        "PYTHONDONTWRITEBYTECODE": "1"})
    measured = execute(job["argv"], root, environment, attempt / "output.log", job["timeout_seconds"])
    outcome = "passed" if measured["exit_code"] == 0 and measured["failure"] is None else "failed"
    report_hash = None
    try:
        if source_identity(root) != record["source"]:
            raise QualificationError("source changed during execution")
        if (attempt / "report.json").exists():
            report_hash = file_digest(attempt / "report.json")
            if outcome == "passed":
                from .verify import verify_report
                verify_report(attempt, read_record(attempt / "report.json"), job, candidate_hash, target)
        elif outcome == "passed":
            raise QualificationError("driver omitted its qualification report")
    except (QualificationError, KeyError, TypeError, ValueError):
        outcome = "failed"
        measured["failure"] = "input_or_report_changed"
    result = {"schema_version": 1, "candidate_sha256": candidate_hash,
              "start_sha256": file_digest(attempt / "start.json"), "finished_at": utc_now(),
              "job_id": job_id, "target": target, "outcome": outcome,
              "measurement": measured, "report_sha256": report_hash}
    write_once(attempt / "result.json", canonical(result))
    return verify_attempt(directory, record, attempt)
