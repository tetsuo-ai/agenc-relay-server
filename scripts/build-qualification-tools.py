#!/usr/bin/env python3
"""Build pinned conventional clients with the exact AgenC ALPN support."""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

from release_qualification.policy import checked_run, host_target
from release_qualification.process import execute
from release_qualification.records import QualificationError, canonical, file_digest, read_bytes, write_once


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    destination = args.output.resolve()
    if destination.exists():
        raise QualificationError("qualification-tool output already exists")
    destination.mkdir(parents=True, mode=0o700)
    versions = tomllib.loads(read_bytes(root / "conformance/clients/versions.toml").decode())
    tor_tools = tomllib.loads(read_bytes(root / "conformance/clients/tor-tools.toml").decode())
    with tempfile.TemporaryDirectory(prefix="agenc-qualification-tools-") as temporary:
        context = Path(temporary)
        for client in versions["client"]:
            checkout = context / client["name"]
            commands = [["git", "clone", "--filter=blob:none", "--no-checkout", client["repository"], str(checkout)],
                        ["git", "-C", str(checkout), "checkout", "--detach", client["commit"]]]
            for index, argv in enumerate(commands):
                result = execute(argv, root, dict(os.environ), destination / f"{client['name']}-fetch-{index}.log", 600)
                if result["exit_code"] or result["failure"]:
                    raise QualificationError("pinned client acquisition failed")
            if checked_run(checkout, ["git", "rev-parse", "HEAD"]) != client["commit"] or file_digest(checkout / client["patched_file"]) != client["source_sha256"] or file_digest(root / client["patch"]) != client["patch_sha256"]:
                raise QualificationError("client source or patch differs from the reviewed pin")
            subprocess.run(["git", "apply", "--check", str(root / client["patch"])], cwd=checkout, check=True)
            subprocess.run(["git", "apply", str(root / client["patch"])], cwd=checkout, check=True)
        chutney = context / "chutney"
        for index, argv in enumerate([
            ["git", "clone", "--filter=blob:none", "--no-checkout", tor_tools["repository"], str(chutney)],
            ["git", "-C", str(chutney), "checkout", "--detach", tor_tools["commit"]],
        ]):
            result = execute(argv, root, dict(os.environ), destination / f"chutney-fetch-{index}.log", 600)
            if result["exit_code"] or result["failure"]:
                raise QualificationError("pinned Tor test tool acquisition failed")
        if checked_run(chutney, ["git", "rev-parse", "HEAD"]) != tor_tools["commit"]:
            raise QualificationError("Tor test tool source differs from the reviewed pin")
        toolchain = Path(checked_run(root, ["rustc", "--print", "sysroot"]))
        if not checked_run(root, ["rustc", "--version"]).startswith("rustc 1.98.0 "):
            raise QualificationError("qualification image requires the pinned Rust compiler")
        shutil.copytree(toolchain, context / "rust-toolchain", symlinks=True)
        shutil.copyfile(root / "conformance/clients/Dockerfile", context / "Dockerfile")
        image_id = destination / "image-id.txt"
        result = execute(["docker", "build", "--iidfile", str(image_id), str(context)], root, dict(os.environ), destination / "build.log", 7200)
        if result["exit_code"] or result["failure"]:
            raise QualificationError("qualification image build failed; inspect build.log")
    identity = read_bytes(image_id, 128).decode().strip()
    record = {"schema_version": 1, "target": host_target(root), "image": identity,
              "clients": versions["client"], "tor_tools": tor_tools,
              "dockerfile_sha256": file_digest(root / "conformance/clients/Dockerfile"),
              "build_log_sha256": result["log_sha256"]}
    write_once(destination / "tools.json", canonical(record))
    print(identity)


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError, subprocess.SubprocessError) as error:
        print(f"qualification tools: {error}", file=sys.stderr)
        sys.exit(1)
