#!/usr/bin/env python3
"""Build and verify the immutable native release artifacts."""

import argparse
import sys
from pathlib import Path

from release_qualification.build import build, check_dependency_decisions, load_dependency_decisions, validate_build
from release_qualification.records import QualificationError, canonical, read_record, safe_path, write_once


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    create = sub.add_parser("build")
    create.add_argument("--image", required=True)
    create.add_argument("--output", type=Path, required=True)
    sub.add_parser("verify")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    if args.command == "build":
        result = build(root, args.output.resolve(), args.image)
        print(f"reproduced {result['target']} {result['binary_sha256']}")
    else:
        from release_qualification.driver import context, finish
        candidate, directory, attempt, target = context(root)
        artifact = next(item for item in candidate["artifacts"] if item["target"] == target)
        path = safe_path(directory, artifact["build_record"])
        record = read_record(path)
        validate_build(path.parent, record, candidate["source"])
        # Every NOASSERTION the SBOM still carries needs a reviewed decision.
        sbom = read_record(safe_path(path.parent, record["sbom"]))
        decisions = check_dependency_decisions(sbom, load_dependency_decisions(root), record["tools"]["native_libraries"])
        write_once(attempt / "evidence/build.json", canonical(record))
        write_once(attempt / "evidence/dependency-decisions.json", canonical(decisions))
        finish(attempt, "reproducibility", {"independent_builds": 2, "native_target": target,
                                            "binary_sha256": artifact["sha256"]})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QualificationError, OSError, ValueError, KeyError, TypeError, StopIteration) as error:
        print(f"release build: {error}", file=sys.stderr)
        sys.exit(1)
