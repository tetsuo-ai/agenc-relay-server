"""Build twice in independent, network-disabled native containers."""

from __future__ import annotations

import gzip
import io
import os
import re
import shutil
import subprocess
import tarfile
import tempfile
import tomllib
import uuid
from pathlib import Path
from typing import Any

from .policy import checked_run, host_target, source_identity
from .process import execute
from .records import (TARGETS, QualificationError, canonical, digest, file_digest, read_bytes,
                      read_record, require_fields, require_hash, safe_path, write_once)

BUILD_FIELDS = {"schema_version", "source", "target", "features", "image", "source_date_epoch",
                "binary", "binary_sha256", "replica_sha256", "sbom", "sbom_sha256", "notices",
                "notices_sha256", "archive", "archive_sha256", "tools", "logs"}


def immutable_image(value: object) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"(?:[A-Za-z0-9./:_-]+@)?sha256:[0-9a-f]{64}", value):
        raise QualificationError("use an immutable container image digest")
    return value


def container_build(argv: list[str], root: Path, environment: dict[str, str], log: Path) -> dict[str, Any]:
    name = f"agenc-release-{uuid.uuid4().hex}"
    try:
        return execute([*argv[:2], "--name", name, *argv[2:]], root, environment, log, 7200)
    finally:
        # Terminating the Docker CLI does not terminate its container. Remove
        # only this invocation's unpredictable name, including after timeout.
        try:
            subprocess.run(["docker", "rm", "--force", name], stdin=subprocess.DEVNULL,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
        except (OSError, subprocess.SubprocessError) as error:
            raise QualificationError(f"could not clean up release container {name}") from error


def validate_build(directory: Path, record: dict[str, Any], source: dict[str, str]) -> None:
    require_fields(record, BUILD_FIELDS, "release build")
    if type(record["schema_version"]) is not int or record["schema_version"] != 1 or record["source"] != source:
        raise QualificationError("build belongs to another source or schema")
    if record["target"] not in TARGETS or record["features"] != ["history", "wss"]:
        raise QualificationError("build has an undeclared target or feature set")
    immutable_image(record["image"])
    if record["binary"] != "agenc-ircd" or record["sbom"] != "sbom.spdx.json" or record["notices"] != "THIRD-PARTY-NOTICES.txt":
        raise QualificationError("noncanonical build artifact name")
    for name in ("binary", "sbom", "notices", "archive"):
        expected = require_hash(record[f"{name}_sha256"], name)
        if file_digest(safe_path(directory, record[name])) != expected:
            raise QualificationError(f"build artifact differs: {name}")
    if record["replica_sha256"] != record["binary_sha256"]:
        raise QualificationError("independent builds differ")
    if not isinstance(record["tools"], dict) or not {"rustc", "cargo", "cc", "ld", "native_libraries"} <= record["tools"].keys():
        raise QualificationError("build omits compiler or native component identities")
    if not isinstance(record["logs"], list) or len(record["logs"]) != 2:
        raise QualificationError("build omits its two raw logs")
    for log in record["logs"]:
        require_fields(log, {"path", "sha256"}, "build log")
        if file_digest(safe_path(directory, log["path"])) != require_hash(log["sha256"], "build log"):
            raise QualificationError("build log differs")


def export_source(root: Path, destination: Path) -> None:
    names = checked_run(root, ["git", "ls-files", "-z"]).split("\0")
    for name in filter(None, names):
        original = safe_path(root, name)
        output = safe_path(destination, name)
        output.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original, output)
        output.chmod(original.stat().st_mode & 0o777)


def release_archive(binary: bytes, name: str, epoch: int) -> bytes:
    tar_bytes = io.BytesIO()
    with tarfile.open(fileobj=tar_bytes, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        entry = tarfile.TarInfo(name)
        entry.size, entry.mode, entry.mtime = len(binary), 0o755, epoch
        entry.uid, entry.gid, entry.uname, entry.gname = 0, 0, "", ""
        archive.addfile(entry, io.BytesIO(binary))
    compressed = io.BytesIO()
    with gzip.GzipFile(filename="", mode="wb", fileobj=compressed, mtime=epoch, compresslevel=9) as output:
        output.write(tar_bytes.getvalue())
    return compressed.getvalue()


def build(root: Path, destination: Path, image: str) -> dict[str, Any]:
    immutable_image(image)
    source = source_identity(root)
    target = host_target(root)
    epoch = int(checked_run(root, ["git", "show", "-s", "--format=%ct", source["commit"]]))
    if destination.exists():
        raise QualificationError("release build directory already exists")
    destination.mkdir(parents=True, mode=0o700)
    environment = dict(os.environ)
    logs = []
    with tempfile.TemporaryDirectory(prefix="agenc-release-build-") as scratch:
        temporary = Path(scratch)
        exported = temporary / "source"
        exported.mkdir()
        export_source(root, exported)
        dependencies = temporary / "dependencies"
        vendor_log = destination / "vendor.log"
        vendor = execute(["cargo", "vendor", "--locked", "--versioned-dirs", str(dependencies)],
                         root, environment, vendor_log, 1800)
        if vendor["exit_code"] != 0 or vendor["failure"]:
            raise QualificationError("locked dependency acquisition failed; inspect vendor.log")
        # cargo vendor supplies registry dependencies; the committed opaque-ke
        # patch remains in the exported source and is covered by its source hash.
        (exported / ".cargo").mkdir(exist_ok=True)
        if (exported / ".cargo/config.toml").exists() or (exported / ".cargo/config").exists():
            raise QualificationError("release dependency configuration must not replace committed Cargo settings")
        (exported / ".cargo/config.toml").write_text(
            '[source.crates-io]\nreplace-with = "release-vendor"\n'
            '[source.release-vendor]\ndirectory = "/dependencies"\n', encoding="utf-8")
        results = []
        for replica in ("a", "b"):
            output = temporary / replica
            output.mkdir()
            argv = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
                    "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pids-limit=512",
                    "--user", f"{os.getuid()}:{os.getgid()}", "--tmpfs", "/tmp:rw,nosuid,nodev,size=1g",
                    "--mount", f"type=bind,src={exported},dst=/source,readonly",
                    "--mount", f"type=bind,src={dependencies},dst=/dependencies,readonly",
                    "--mount", f"type=bind,src={output},dst=/build", "--workdir=/source",
                    "--env", f"SOURCE_DATE_EPOCH={epoch}",
                    "--env", f"AGENC_BUILD_COMMIT={source['commit']}",
                    "--env", f"AGENC_BUILD_SOURCE_SHA256={source['source_sha256']}",
                    "--env", f"AGENC_BUILD_LOCK_SHA256={source['lock_sha256']}",
                    "--env", f"AGENC_RELEASE_TARGET={target}", image,
                    "python3", "scripts/release-build-container.py"]
            log_path = destination / f"build-{replica}.log"
            measured = container_build(argv, root, environment, log_path)
            logs.append({"path": log_path.name, "sha256": measured["log_sha256"]})
            if measured["exit_code"] != 0 or measured["failure"]:
                raise QualificationError(f"native build {replica} failed; inspect {log_path.name}")
            results.append((file_digest(output / "agenc-ircd"), read_record(output / "tools.json"),
                            file_digest(output / "sbom.spdx.json"), file_digest(output / "THIRD-PARTY-NOTICES.txt")))
        if results[0] != results[1]:
            raise QualificationError("independent native binary or tool identities differ")
        primary = temporary / "a"
        for name in ("agenc-ircd", "sbom.spdx.json", "THIRD-PARTY-NOTICES.txt"):
            shutil.copyfile(primary / name, destination / name)
        (destination / "agenc-ircd").chmod(0o500)
        archive_name = f"agenc-ircd-{source['commit'][:12]}-{target}.tar.gz"
        binary = read_bytes(destination / "agenc-ircd", 256 * 1024 * 1024)
        write_once(destination / archive_name, release_archive(binary, "agenc-ircd", epoch))
        record = {"schema_version": 1, "source": source, "target": target, "features": ["history", "wss"],
                  "image": image, "source_date_epoch": epoch, "binary": "agenc-ircd", "binary_sha256": results[0][0],
                  "replica_sha256": results[1][0], "sbom": "sbom.spdx.json",
                  "sbom_sha256": file_digest(destination / "sbom.spdx.json"), "notices": "THIRD-PARTY-NOTICES.txt",
                  "notices_sha256": file_digest(destination / "THIRD-PARTY-NOTICES.txt"),
                  "archive": archive_name, "archive_sha256": file_digest(destination / archive_name),
                  "tools": results[0][1], "logs": logs}
    if source_identity(root) != source:
        raise QualificationError("source changed during release build")
    validate_build(destination, record, source)
    write_once(destination / "build.json", canonical(record))
    return record
