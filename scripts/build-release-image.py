#!/usr/bin/env python3
"""Build the native release image and record what it contains.

The image is Ubuntu 24.04 pinned by digest with build-essential and Python,
plus the host's pinned Rust 1.98.0 sysroot copied in. The record names the
image ID, the Dockerfile digest, the base image, the compiler, and the digest
of the installed package list, so a build record's image reference can be
traced back to exact package versions.
"""

from __future__ import annotations

import argparse
import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from release_qualification.policy import checked_run, host_target
from release_qualification.process import execute
from release_qualification.records import QualificationError, canonical, digest, file_digest, read_bytes, write_once

DOCKERFILE = "conformance/release/Dockerfile"
PINNED_COMPILER = "rustc 1.98.0 "
MAX_PACKAGE_LIST_BYTES = 1024 * 1024


def base_image(dockerfile: str) -> str:
    lines = [line.strip() for line in dockerfile.splitlines() if line.strip().startswith("FROM ")]
    if len(lines) != 1 or not re.fullmatch(r"FROM [a-z0-9./_-]+@sha256:[0-9a-f]{64}", lines[0]):
        raise QualificationError("the release Dockerfile must start from exactly one digest-pinned base image")
    return lines[0].removeprefix("FROM ")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    destination = args.output.resolve()
    if destination.exists():
        raise QualificationError("release image output already exists")
    destination.mkdir(parents=True, mode=0o700)
    target = host_target(root)
    compiler = checked_run(root, ["rustc", "--version"])
    if not compiler.startswith(PINNED_COMPILER):
        raise QualificationError("the release image requires the pinned Rust compiler on the host")
    dockerfile = read_bytes(root / DOCKERFILE)
    base = base_image(dockerfile.decode("utf-8"))
    with tempfile.TemporaryDirectory(prefix="agenc-release-image-") as temporary:
        context = Path(temporary)
        toolchain = Path(checked_run(root, ["rustc", "--print", "sysroot"]))
        shutil.copytree(toolchain, context / "rust-toolchain", symlinks=True)
        shutil.copyfile(root / DOCKERFILE, context / "Dockerfile")
        image_id = destination / "image-id.txt"
        result = execute(["docker", "build", "--pull=false", "--iidfile", str(image_id), str(context)],
                         root, dict(os.environ), destination / "build.log", 7200)
        if result["exit_code"] or result["failure"]:
            raise QualificationError("release image build failed; inspect build.log")
    identity = read_bytes(image_id, 128).decode().strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", identity):
        raise QualificationError("docker did not report an image ID")
    try:
        packages = subprocess.check_output(["docker", "run", "--rm", "--network=none", identity, "cat", "/opt/release-packages.txt"],
                                           stdin=subprocess.DEVNULL, timeout=300)
        image_compiler = subprocess.check_output(["docker", "run", "--rm", "--network=none", identity, "rustc", "-vV"],
                                                 stdin=subprocess.DEVNULL, timeout=300, text=True).strip()
    except (OSError, subprocess.SubprocessError) as error:
        raise QualificationError("could not read the built image") from error
    if len(packages) > MAX_PACKAGE_LIST_BYTES or not packages.strip():
        raise QualificationError("the image package list is empty or exceeds its bound")
    if f"host: {target}" not in image_compiler.splitlines() or not image_compiler.startswith(PINNED_COMPILER):
        raise QualificationError("the image does not carry the pinned native compiler")
    write_once(destination / "packages.txt", packages)
    record = {"schema_version": 1, "target": target, "image": identity, "base_image": base,
              "dockerfile_sha256": digest(dockerfile), "packages_sha256": digest(packages),
              "rustc": image_compiler, "build_log_sha256": result["log_sha256"],
              "dockerfile": DOCKERFILE}
    write_once(destination / "image.json", canonical(record))
    print(identity)


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError) as error:
        print(f"release image: {error}", file=sys.stderr)
        sys.exit(1)
