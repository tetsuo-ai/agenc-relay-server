#!/usr/bin/env python3
"""The fixed offline build executed inside each read-only native container."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path

from release_qualification.records import canonical, digest, file_digest, write_once


def main() -> None:
    output = Path("/build")
    environment = {"PATH": os.environ["PATH"], "HOME": "/tmp", "CARGO_HOME": "/tmp/cargo",
                   "CARGO_TARGET_DIR": "/build/target", "CARGO_INCREMENTAL": "0",
                   "CARGO_NET_OFFLINE": "true", "LC_ALL": "C", "TZ": "UTC",
                   "RUSTFLAGS": "--remap-path-prefix=/source=/usr/src/agenc-ircd --remap-path-prefix=/dependencies=/usr/src/dependencies"}
    environment.update({key: os.environ[key] for key in ("SOURCE_DATE_EPOCH", "AGENC_BUILD_COMMIT", "AGENC_BUILD_SOURCE_SHA256", "AGENC_BUILD_LOCK_SHA256")})
    # Rustup images need their installed, read-only toolchain home.
    if "RUSTUP_HOME" in os.environ:
        environment["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]
    def run(argv: list[str]) -> str:
        return subprocess.check_output(argv, env=environment, text=True).strip()
    target = os.environ["AGENC_RELEASE_TARGET"]
    rustc = run(["rustc", "-vV"])
    if f"host: {target}" not in rustc.splitlines() or not rustc.startswith("rustc 1.98.0 "):
        raise ValueError("release build requires the pinned compiler on its native target")
    subprocess.run(["cargo", "build", "-p", "agenc-ircd", "--release", "--all-features", "--frozen", "--target", target], env=environment, check=True)
    binary = output / "target" / target / "release/agenc-ircd"
    shutil.copyfile(binary, output / "agenc-ircd")
    linked = run(["ldd", str(binary)])
    libraries = []
    for line in linked.splitlines():
        path = next((part for part in line.split() if part.startswith("/")), None)
        if path:
            libraries.append({"path": path, "sha256": file_digest(Path(path).resolve())})
    tools = {"rustc": rustc, "cargo": run(["cargo", "--version"]), "cc": run(["cc", "--version"]),
             "ld": run(["ld", "--version"]), "native_libraries": sorted(libraries, key=lambda row: row["path"])}
    metadata = json.loads(run(["cargo", "metadata", "--all-features", "--frozen", "--format-version", "1"]))
    lock = tomllib.loads(Path("Cargo.lock").read_text())
    checksums = {(item["name"], item["version"], item.get("source")): item.get("checksum") for item in lock["package"]}
    packages, notices = [], []
    for index, package in enumerate(sorted(metadata["packages"], key=lambda item: item["id"])):
        checksum = checksums.get((package["name"], package["version"], package["source"]))
        item = {"SPDXID": f"SPDXRef-Package-{index}", "name": package["name"], "versionInfo": package["version"],
                "downloadLocation": package["source"] or "NOASSERTION", "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION", "licenseDeclared": package["license"] or "NOASSERTION",
                "copyrightText": "NOASSERTION"}
        if checksum:
            item["checksums"] = [{"algorithm": "SHA256", "checksumValue": checksum}]
        packages.append(item)
        notices.append(f"{package['name']} {package['version']}\nDeclared license: {package['license'] or 'NOASSERTION'}\n")
        parent = Path(package["manifest_path"]).parent
        for notice in sorted(parent.iterdir()):
            if notice.is_file() and notice.name.upper().startswith(("LICENSE", "COPYING", "NOTICE")):
                notices.append(notice.name + "\n" + notice.read_text(errors="replace") + "\n")
    for index, library in enumerate(tools["native_libraries"]):
        packages.append({"SPDXID": f"SPDXRef-Native-{index}", "name": Path(library["path"]).name,
                         "downloadLocation": "NOASSERTION", "filesAnalyzed": False,
                         "licenseConcluded": "NOASSERTION", "licenseDeclared": "NOASSERTION",
                         "copyrightText": "NOASSERTION", "checksums": [{"algorithm": "SHA256", "checksumValue": library["sha256"]}]})
    created = datetime.fromtimestamp(int(environment["SOURCE_DATE_EPOCH"]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "agenc-ircd release dependencies including build and test tools",
            "documentNamespace": f"https://agenc.ag/spdx/{environment['AGENC_BUILD_SOURCE_SHA256']}/{target}",
            "creationInfo": {"creators": ["Tool: agenc-ircd-release-builder"], "created": created},
            "packages": packages, "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": item["SPDXID"]} for item in packages]}
    write_once(output / "tools.json", canonical(tools))
    write_once(output / "sbom.spdx.json", canonical(sbom))
    write_once(output / "THIRD-PARTY-NOTICES.txt", "\n".join(notices).encode())


if __name__ == "__main__":
    main()
