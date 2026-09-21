#!/usr/bin/env python3
"""The fixed offline build executed inside each read-only native container.

Besides the binary, the build writes an SPDX 2.3 report of every crate in the
dependency graph and of every native library the binary links. Native
libraries are resolved to their Ubuntu package, version, and architecture
with dpkg, and the package's copyright file is hashed. The SPDX license
expression for a native package comes only from a reviewed entry in
conformance/release-dependency-decisions.toml that names the same package,
version, architecture, and copyright digest; anything else stays
NOASSERTION for the verify step to refuse.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from release_qualification.records import canonical, digest, file_digest, write_once

DECISIONS_PATH = Path("conformance/release-dependency-decisions.toml")
DPKG_OWNER = re.compile(r"([a-z0-9][a-z0-9+.-]*)(?::([a-z0-9-]+))?: (/.+)")


def parse_dpkg_search(text: str, path: str) -> tuple[str, str] | None:
    """The owning package and architecture for one path from `dpkg -S` output."""
    for line in text.splitlines():
        match = DPKG_OWNER.fullmatch(line.strip())
        if match is not None and match.group(3) == path:
            return match.group(1), match.group(2) or "all"
    return None


def native_decision(decisions: dict[str, Any], package: str, version: str, architecture: str, copyright_sha256: str | None) -> str | None:
    """The reviewed SPDX expression for an exact native package, or nothing."""
    for entry in decisions.get("native", []):
        if (entry.get("package"), entry.get("version"), entry.get("architecture"), entry.get("copyright_sha256")) == (package, version, architecture, copyright_sha256):
            return str(entry["license"])
    return None


def native_package(path: str, run, decisions: dict[str, Any]) -> dict[str, Any]:
    """Resolve one linked library path to its package facts and reviewed license."""
    real = str(Path(path).resolve())
    owner = parse_dpkg_search(run(["dpkg", "-S", real], check=False), real)
    facts: dict[str, Any] = {"path": path, "resolved_path": real, "sha256": file_digest(Path(real))}
    if owner is None:
        return {**facts, "license": "NOASSERTION"}
    package, architecture = owner
    version = run(["dpkg-query", "-W", "-f", "${Version}", f"{package}:{architecture}" if architecture != "all" else package])
    copyright_file = Path("/usr/share/doc") / package / "copyright"
    copyright_sha256 = file_digest(copyright_file.resolve()) if copyright_file.is_file() else None
    reviewed = native_decision(decisions, package, version, architecture, copyright_sha256)
    return {**facts, "package": package, "version": version, "architecture": architecture,
            "purl": f"pkg:deb/ubuntu/{package}@{version}?arch={architecture}",
            "copyright_sha256": copyright_sha256, "license": reviewed or "NOASSERTION"}


def native_spdx_package(index: int, library: dict[str, Any]) -> dict[str, Any]:
    item = {"SPDXID": f"SPDXRef-Native-{index}", "name": Path(library["path"]).name, "downloadLocation": "NOASSERTION",
            "filesAnalyzed": False, "licenseConcluded": "NOASSERTION", "licenseDeclared": library["license"],
            "copyrightText": "NOASSERTION", "checksums": [{"algorithm": "SHA256", "checksumValue": library["sha256"]}]}
    if "purl" in library:
        item["versionInfo"] = library["version"]
        references = [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": library["purl"]}]
        if library["copyright_sha256"] is not None:
            references.append({"referenceCategory": "OTHER", "referenceType": "copyright-file-sha256", "referenceLocator": library["copyright_sha256"]})
        item["externalRefs"] = references
    return item


def main() -> None:
    output = Path("/build")
    environment = {"PATH": os.environ["PATH"], "HOME": "/tmp", "CARGO_HOME": "/tmp/cargo",
                   "CARGO_TARGET_DIR": "/build/target", "CARGO_INCREMENTAL": "0",
                   "CARGO_NET_OFFLINE": "true", "LC_ALL": "C", "TZ": "UTC",
                   "RUSTFLAGS": "--remap-path-prefix=/source=/usr/src/agenc-relay-server --remap-path-prefix=/dependencies=/usr/src/dependencies"}
    environment.update({key: os.environ[key] for key in ("SOURCE_DATE_EPOCH", "AGENC_BUILD_COMMIT", "AGENC_BUILD_SOURCE_SHA256", "AGENC_BUILD_LOCK_SHA256")})
    # Rustup images need their installed, read-only toolchain home.
    if "RUSTUP_HOME" in os.environ:
        environment["RUSTUP_HOME"] = os.environ["RUSTUP_HOME"]

    def run(argv: list[str], check: bool = True) -> str:
        completed = subprocess.run(argv, env=environment, text=True, capture_output=True, check=check)
        return completed.stdout.strip()

    target = os.environ["AGENC_RELEASE_TARGET"]
    rustc = run(["rustc", "-vV"])
    if f"host: {target}" not in rustc.splitlines() or not rustc.startswith("rustc 1.98.0 "):
        raise ValueError("release build requires the pinned compiler on its native target")
    subprocess.run(["cargo", "build", "-p", "agenc-ircd", "--bin", "arcd", "--release", "--all-features", "--frozen", "--target", target], env=environment, check=True)
    binary = output / "target" / target / "release/arcd"
    shutil.copyfile(binary, output / "arcd")
    decisions = tomllib.loads(DECISIONS_PATH.read_text(encoding="utf-8")) if DECISIONS_PATH.is_file() else {}
    libraries = []
    for line in run(["ldd", str(binary)]).splitlines():
        path = next((part for part in line.split() if part.startswith("/")), None)
        if path:
            libraries.append(native_package(path, run, decisions))
    libraries.sort(key=lambda row: row["path"])
    tools = {"rustc": rustc, "cargo": run(["cargo", "--version"]), "cc": run(["cc", "--version"]),
             "ld": run(["ld", "--version"]), "native_libraries": [{"path": row["path"], "sha256": row["sha256"]} for row in libraries]}
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
    for index, library in enumerate(libraries):
        packages.append(native_spdx_package(index, library))
    created = datetime.fromtimestamp(int(environment["SOURCE_DATE_EPOCH"]), timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    sbom = {"spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT",
            "name": "AgenC Relay release dependencies including build and test tools",
            "documentNamespace": f"https://agenc.ag/spdx/{environment['AGENC_BUILD_SOURCE_SHA256']}/{target}",
            "creationInfo": {"creators": ["Tool: arcd-release-builder"], "created": created},
            "packages": packages, "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": item["SPDXID"]} for item in packages]}
    write_once(output / "tools.json", canonical(tools))
    write_once(output / "sbom.spdx.json", canonical(sbom))
    write_once(output / "THIRD-PARTY-NOTICES.txt", "\n".join(notices).encode())


if __name__ == "__main__":
    main()
