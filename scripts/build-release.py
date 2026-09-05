#!/usr/bin/env python3
"""Build and verify the immutable native release artifacts."""

import argparse
import os
import sys
from pathlib import Path

from release_qualification.build import build, validate_build
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
        validate_build(path.parent, read_record(path), candidate["source"])
        write_once(attempt / "evidence/build.json", canonical(read_record(path)))
        finish(attempt, "reproducibility", {"independent_builds": 2, "native_target": target,
                                            "binary_sha256": artifact["sha256"]})
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QualificationError, OSError, ValueError) as error:
        print(f"release build: {error}", file=sys.stderr)
        sys.exit(1)
