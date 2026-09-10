"""Shared setup and immutable output for the fixed qualification drivers."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from .process import execute
from .records import QualificationError, canonical, digest, file_digest, read_record, safe_path, write_once


def context(root: Path) -> tuple[dict[str, Any], Path, Path, str]:
    try:
        directory = Path(os.environ["AGENC_RELEASE_CANDIDATE"]).resolve()
        attempt = Path(os.environ["AGENC_RELEASE_ATTEMPT"]).resolve()
        target = os.environ["AGENC_RELEASE_TARGET"]
    except KeyError as error:
        raise QualificationError("run this driver through qualify-release.py run") from error
    start = read_record(attempt / "start.json")
    candidate = read_record(directory / "candidate.json")
    if start["candidate_sha256"] != digest(canonical(candidate)) or start["host"]["target"] != target or not attempt.is_relative_to(directory / "runs"):
        raise QualificationError("driver candidate context differs")
    return candidate, directory, attempt, target


def command(root: Path, attempt: Path, name: str, argv: list[str], timeout: int = 3600,
            environment: dict[str, str] | None = None) -> dict[str, Any]:
    (attempt / "evidence").mkdir(mode=0o700, exist_ok=True)
    result = execute(argv, root, environment or dict(os.environ), safe_path(attempt, f"evidence/{name}.log"), timeout)
    write_once(safe_path(attempt, f"evidence/{name}.json"), canonical({"argv": argv, "measurement": result}))
    if result["exit_code"] != 0 or result["failure"]:
        raise QualificationError(f"qualification command failed: {name}")
    return result


def finish(attempt: Path, job_id: str, facts: dict[str, Any]) -> None:
    start = read_record(attempt / "start.json")
    if job_id != start["job"]["id"]:
        raise QualificationError("driver completed a different job")
    artifacts = {}
    for path in sorted((attempt / "evidence").rglob("*")):
        if path.is_file():
            relative = path.relative_to(attempt).as_posix()
            artifacts[relative] = file_digest(safe_path(attempt, relative))
    if not artifacts:
        raise QualificationError("driver produced no raw evidence")
    report = {"schema_version": 1, "job_id": job_id, "candidate_sha256": start["candidate_sha256"],
              "target": start["host"]["target"], "facts": facts, "artifacts": artifacts}
    from .verify import verify_report
    verify_report(attempt, report, start["job"], start["candidate_sha256"], start["host"]["target"])
    write_once(attempt / "report.json", canonical(report))
