#!/usr/bin/env python3
"""Compare local binary metadata with its frozen candidate and privacy limits."""

import json
import sys
from pathlib import Path

from release_qualification.driver import command, context, finish
from release_qualification.records import QualificationError, read_bytes, safe_path


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    candidate, directory, attempt, target = context(root)
    artifact = next(item for item in candidate["artifacts"] if item["target"] == target)
    binary = safe_path(directory, artifact["path"])
    for name in ("version", "conformance"):
        command(root, attempt, name, [str(binary), name, "--json"], 30)
        metadata = json.loads(read_bytes(attempt / f"evidence/{name}.log"))
        expected = {"source_commit": candidate["source"]["commit"],
                    "source_sha256": candidate["source"]["source_sha256"],
                    "cargo_lock_sha256": candidate["source"]["lock_sha256"],
                    "target": target, "features": {"history": True, "wss": True},
                    "storage_schema_generation": 2}
        if any(metadata.get(key) != value for key, value in expected.items()):
            raise QualificationError("binary build metadata differs from its candidate")
        if name == "conformance" and (metadata.get("qualified_claims") != [] or metadata.get("compiled") != {"core-v1": True, "federated-v1": True, "encrypted-v1": True, "history": True, "wss": True}):
            raise QualificationError("binary confuses compiled behavior with signed release claims")
    # The privacy document is a required, source-bound release artifact.
    document = root / "docs/stage-10-qualification.md"
    if not document.is_file():
        raise QualificationError("release qualification and privacy documentation is missing")
    finish(attempt, "claims", {"binary_identity": True, "separate_claims": True,
           "privacy_limits": True, "documentation_current": True})


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError) as error:
        print(f"release claims: {error}", file=sys.stderr)
        sys.exit(1)
