#!/usr/bin/env python3
"""Prepare, run, resume, inspect, and close an exact-source release campaign."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from release_qualification.candidate import prepare, run_job, validate_candidate
from release_qualification.decision import verify_decision
from release_qualification.locks import exclusive, shared
from release_qualification.policy import fuzz_jobs, load_policy
from release_qualification.records import CLAIMS, QualificationError
from release_qualification.signing import close
from release_qualification.verify import status


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("check")
    create = sub.add_parser("prepare")
    create.add_argument("--output", type=Path, required=True)
    create.add_argument("--build", type=Path, action="append", required=True)
    for name in ("run", "resume", "status", "close", "verify"):
        command = sub.add_parser(name)
        command.add_argument("--candidate", type=Path, required=True)
        if name in ("run", "resume"):
            command.add_argument("--job", required=True)
        if name == "verify":
            command.add_argument("--public-key", type=Path, required=True)
        if name == "close":
            command.add_argument("--signing-key", type=Path, required=True)
            command.add_argument("--public-key", type=Path, required=True)
            command.add_argument("--claim", choices=CLAIMS, action="append", required=True)
            command.add_argument("--external-review", type=Path)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.command == "check":
        policy = load_policy(root)
        jobs = policy["job"] + fuzz_jobs(root)
        print(json.dumps({"jobs": [job["id"] for job in jobs], "native_targets": policy["targets"], "release_branch_floor": 90}, indent=2))
        return 0
    if args.command == "prepare":
        print(prepare(root, args.output.resolve(), [path.resolve() for path in args.build]))
        return 0
    directory = args.candidate.resolve()
    if args.command == "verify":
        with shared(directory):
            print(json.dumps(verify_decision(root, directory, args.public_key), indent=2))
        return 0
    if args.command in ("run", "resume"):
        result = run_job(root, directory, args.job, resume=args.command == "resume")
        print(json.dumps(result, indent=2))
        return 0 if result["outcome"] == "passed" else 1
    if args.command == "status":
        with shared(directory):
            candidate = validate_candidate(root, directory, check_source=False)
            report = status(directory, candidate)
        print(json.dumps(report, indent=2))
        return 0
    with exclusive(directory):
        decision = close(root, directory, args.signing_key, args.public_key, args.claim, args.external_review)
    print(json.dumps(decision, indent=2))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QualificationError, OSError, ValueError, KeyError, TypeError) as error:
        print(f"release qualification: {error}", file=sys.stderr)
        sys.exit(1)
