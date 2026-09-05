#!/usr/bin/env python3
"""Accumulate at least 24 measured CPU hours for one frozen fuzz target."""

from __future__ import annotations

import os
import re
import shutil
import sys
from pathlib import Path
from typing import Any

from release_qualification.driver import command, context, finish
from release_qualification.fuzz import CORPUS_NAME, MAX_CORPUS_FILES, seed_directory, snapshot_corpus
from release_qualification.policy import checked_run, fuzz_jobs, load_policy
from release_qualification.records import QualificationError, canonical, digest, file_digest, read_bytes, write_once
from release_qualification.workers import execute_group

NIGHTLY = "+nightly-2026-08-24"
CAMPAIGN_SEED = 20260905
SEGMENT_SECONDS = 600
SEGMENT_TIMEOUT_SECONDS = 660
MAX_SEGMENTS = 200
DEVELOPMENT_SMOKE_SECONDS = 20
LOCKFILES = ("Cargo.lock", "fuzz/Cargo.lock")
SANITIZER_FLAG = re.compile(r"-Z\s*sanitizer=address")
RUSTC_INVOCATION = re.compile(rb"Running `.*?rustc --crate-name (\w+) .*?`", re.DOTALL)


def lock_identities(root: Path) -> dict[str, str]:
    return {name: digest(read_bytes(root / name)) for name in LOCKFILES}


def copy_seeds(seed: Path, corpus: Path) -> int:
    count = 0
    for path in sorted(seed.iterdir()):
        if path.is_symlink() or not path.is_file() or not CORPUS_NAME.fullmatch(path.name):
            raise QualificationError("seed corpus contains a non-regular or misnamed entry")
        count += 1
        if count > MAX_CORPUS_FILES:
            raise QualificationError("seed corpus exceeds its file limit")
        shutil.copyfile(path, corpus / path.name)
    return count


def frozen_build(root: Path, attempt: Path, name: str, target: str, target_dir: Path) -> dict[str, Any]:
    """Build with cargo-fuzz's own instrumentation flags while forbidding lockfile change.

    cargo-fuzz 0.13.2 does not expose ``--frozen``. Offline resolution plus an
    unchanged lockfile digest before and after the build is the equivalent
    contract; the private target directory keeps the artifact out of any cache.
    """
    before = lock_identities(root)
    environment = dict(os.environ)
    environment.update({"CARGO_NET_OFFLINE": "true", "CARGO_TARGET_DIR": str(target_dir)})
    argv = ["cargo", NIGHTLY, "fuzz", "build", "--verbose", "--target-dir", str(target_dir),
            "--features", "wss", "--sanitizer", "address", name]
    command(root / "fuzz", attempt, "build", argv, 3600, environment)
    if lock_identities(root) != before:
        raise QualificationError("fuzz build changed a lockfile; the campaign is not frozen")
    log = read_bytes(attempt / "evidence/build.log", 64 * 1024 * 1024)
    invocation = None
    for match in RUSTC_INVOCATION.finditer(log):
        if match.group(1) == name.encode():
            invocation = match.group(0)
    if invocation is None or not SANITIZER_FLAG.search(invocation.decode("utf-8", errors="replace")):
        raise QualificationError("build log does not show the sanitized fuzz-target compilation")
    executable = target_dir / target / "release" / name
    if executable.is_symlink() or not executable.is_file():
        raise QualificationError("cargo-fuzz did not produce the expected native target")
    cargo_fuzz = shutil.which("cargo-fuzz")
    if cargo_fuzz is None:
        raise QualificationError("cargo-fuzz is absent")
    record = {
        "target": target,
        "fuzz_target": name,
        "sha256": file_digest(executable),
        "cargo_fuzz": {"path": str(Path(cargo_fuzz).resolve()), "sha256": file_digest(Path(cargo_fuzz).resolve()),
                       "version": checked_run(root, ["cargo-fuzz", "--version"])},
        "rustc_invocation_sha256": digest(invocation),
        "sanitizer": "address",
        "lockfiles": before,
    }
    write_once(attempt / "evidence/fuzz-binary.json", canonical(record))
    return record


def worker_count(root: Path) -> int:
    policy = load_policy(root)
    return max(1, min(int(policy["maximum_workers"]), len(os.sched_getaffinity(0))))


def run_segment(executable: Path, corpus: Path, evidence: Path, work: Path, segment: int, workers: int,
                seconds: int) -> tuple[list[dict[str, Any]], int]:
    commands = []
    seeds = []
    for index in range(workers):
        seed = CAMPAIGN_SEED + (segment - 1) * workers + index
        seeds.append(seed)
        argv = [str(executable), str(corpus), f"-seed={seed}", f"-max_total_time={seconds}", "-timeout=10",
                "-rss_limit_mb=1024", "-reload=1", f"-artifact_prefix={evidence}/failure-", "-print_final_stats=1"]
        commands.append((argv, evidence / f"campaign-{segment:03d}-{index:02d}.log"))
    results = execute_group(commands, work, dict(os.environ), seconds + SEGMENT_TIMEOUT_SECONDS - SEGMENT_SECONDS)
    cpu_ns = sum(result["cpu_user_ns"] + result["cpu_system_ns"] for result in results)
    write_once(evidence / f"campaign-{segment:03d}.json", canonical({"segment": segment, "seeds": seeds, "workers": results}))
    return results, cpu_ns


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    _, _, attempt, target = context(root)
    arguments = sys.argv[1:]
    development = False
    if len(arguments) == 2 and arguments[1] == "--development-smoke":
        development = True
        arguments = arguments[:1]
    if len(arguments) != 1 or arguments[0] not in [job["id"].removeprefix("fuzz.") for job in fuzz_jobs(root)]:
        raise QualificationError("unknown fuzz target")
    name = arguments[0]
    policy = load_policy(root)
    budget_ns = int(policy["fuzz_cpu_seconds_per_target"]) * 10**9
    evidence = attempt / "evidence"
    work = attempt / "work"
    corpus = work / "corpus"
    target_dir = work / "target"
    for path in (evidence, corpus, target_dir):
        path.mkdir(mode=0o700, parents=True)
    copied = copy_seeds(seed_directory(root, name), corpus)
    before = snapshot_corpus(corpus, evidence / "corpus-before.tar.gz")
    binary = frozen_build(root, attempt, name, target, target_dir)
    executable = target_dir / target / "release" / name
    workers = worker_count(root)
    cpu_ns = 0
    segment = 0
    seconds = DEVELOPMENT_SMOKE_SECONDS if development else SEGMENT_SECONDS
    while cpu_ns < budget_ns:
        segment += 1
        if segment > MAX_SEGMENTS:
            raise QualificationError("fuzz campaign could not accumulate its CPU budget within its segment bound")
        results, segment_cpu_ns = run_segment(executable, corpus, evidence, work, segment, workers, seconds)
        cpu_ns += segment_cpu_ns
        failures = [result for result in results if result["exit_code"] != 0 or result["failure"]]
        write_once(evidence / f"progress-{segment:03d}.json", canonical({
            "segments": segment, "workers": workers, "cpu_ns": cpu_ns, "seed_files": copied,
            "failed_workers": [result["index"] for result in failures],
            "artifacts": sorted(path.name for path in evidence.glob("failure-*")),
        }))
        if failures:
            raise QualificationError(f"fuzz worker failed in segment {segment}; artifacts and sanitizer output are retained")
        if file_digest(executable) != binary["sha256"]:
            raise QualificationError("fuzz binary changed during the campaign")
        if development:
            print(f"development smoke: {segment} segment, {workers} workers, {cpu_ns} CPU ns; no report was written",
                  file=sys.stderr)
            return 3
    after = snapshot_corpus(corpus, evidence / "corpus-after.tar.gz")
    finish(attempt, f"fuzz.{name}", {"fuzz_target": name, "cpu_ns": cpu_ns, "sanitizer": "address",
                                     "corpus_before": before, "corpus_after": after, "crashes": 0})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QualificationError, OSError, ValueError) as error:
        print(f"Stage 10 fuzz: {error}", file=sys.stderr)
        sys.exit(1)
