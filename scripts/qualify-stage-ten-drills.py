#!/usr/bin/env python3
"""Run the restore, deletion, key-lifecycle, hardening, and observability drills."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

from release_qualification.daemon_tests import DaemonTests
from release_qualification.driver import command, context, finish
from release_qualification.process import execute
from release_qualification.records import QualificationError, canonical, read_record, write_once

DRILLS = ["restore", "disaster_restore", "deletion", "rekey", "index_transition", "tls_rotation",
          "federation_rotation", "sequencer_rotation", "backup_rotation", "audit_rotation", "compromise", "rollback",
          "resynchronization", "host_hardening", "observability"]
DRILL_TIMEOUT = 900
MAX_STEPS = 256
MAX_FACTS = 256
DEPLOY_PROFILES = ["direct.conf", "dual.conf", "onion-local-admin.conf", "onion-remote-admin.conf"]
FORBIDDEN_HOST_PATTERNS = "LISTEN_FDS|LISTEN_PID|SOCKS_PROXY|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY|resolve_addr|lookup_host"


def validate_record(record: dict[str, Any], name: str) -> bool:
    """Check one drill record's shape and return whether the drill passed."""
    if record.get("schema_version") != 1 or record.get("drill") != name:
        raise QualificationError(f"drill record for {name} belongs to another schema or drill")
    if type(record.get("elapsed_ns")) is not int or record["elapsed_ns"] < 0:
        raise QualificationError(f"drill {name} has no elapsed time")
    steps = record.get("steps")
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        raise QualificationError(f"drill {name} recorded no steps")
    for step in steps:
        if not isinstance(step, dict) or set(step) != {"name", "elapsed_ns", "detail"} or type(step["elapsed_ns"]) is not int:
            raise QualificationError(f"drill {name} has a malformed step")
    facts = record.get("facts")
    if not isinstance(facts, dict) or len(facts) > MAX_FACTS or any(not isinstance(value, str) for value in facts.values()):
        raise QualificationError(f"drill {name} has malformed facts")
    if record.get("passed") not in (True, False):
        raise QualificationError(f"drill {name} has no verdict")
    if record["passed"] and "error" in facts:
        raise QualificationError(f"drill {name} claims a pass while recording an error")
    return bool(record["passed"])


def host_checks(root: Path, attempt: Path) -> dict[str, bool]:
    """Deployment-profile checks that need no daemon: the shipped units, tor, and forbidden paths."""
    results: dict[str, bool] = {}
    command(root, attempt, "check-deploy", ["python3", "scripts/check-deploy.py", "check"], 300)
    results["check_deploy"] = True
    with tempfile.TemporaryDirectory(prefix="agenc-stage10-deploy-") as scratch:
        scratch_root = Path(scratch)
        (scratch_root / "usr/bin").mkdir(parents=True)
        dropin = scratch_root / "etc/systemd/system/agenc-ircd.service.d"
        dropin.mkdir(parents=True)
        for tool in ("agenc-ircd", "setfacl"):
            shutil.copyfile("/bin/true", scratch_root / "usr/bin" / tool)
            (scratch_root / "usr/bin" / tool).chmod(0o755)
        shutil.copyfile(root / "deploy/systemd/agenc-ircd.service", scratch_root / "etc/systemd/system/agenc-ircd.service")
        for target in ("sysinit", "basic", "multi-user", "network-online"):
            (scratch_root / f"etc/systemd/system/{target}.target").write_text("[Unit]\nDescription=Stage 10 drill target\n")
        for profile in DEPLOY_PROFILES:
            shutil.copyfile(root / "deploy/systemd/profiles" / profile, dropin / "20-address-families.conf")
            command(root, attempt, f"systemd-analyze-{profile}",
                    ["systemd-analyze", f"--root={scratch_root}", "verify", "agenc-ircd.service"], 300)
        results["systemd_profiles"] = True
        tor_root = scratch_root / "tor"
        for name in ("data", "onion"):
            (tor_root / name).mkdir(parents=True, mode=0o700)
        torrc = tor_root / "torrc"
        torrc.write_text("\n".join([f"DataDirectory {tor_root}/data", "ClientOnly 1", "DisableNetwork 1", "SocksPort 0",
                                    "DNSPort 0", "SafeSocks 1", "TestSocks 1", f"HiddenServiceDir {tor_root}/onion",
                                    "HiddenServiceVersion 3", f"HiddenServicePort 6697 unix:{tor_root}/onion.sock", ""]))
        torrc.chmod(0o600)
        command(root, attempt, "tor-verify-config", ["tor", "--verify-config", "-f", str(torrc)], 300)
        results["tor_verify_config"] = True
    scan = execute(["rg", "-n", "--hidden", "--glob", "!target/**", "--glob", "!fuzz/target/**", FORBIDDEN_HOST_PATTERNS,
                    "crates", "deploy"], root, dict(os.environ), attempt / "evidence/forbidden-paths.log", 300)
    if scan["failure"] is not None or scan["exit_code"] not in (0, 1):
        raise QualificationError("forbidden socket, proxy, or DNS path scan did not run")
    if scan["exit_code"] == 0:
        raise QualificationError("forbidden socket, proxy, or DNS path found in the source or deployment tree")
    results["forbidden_paths_absent"] = True
    return results


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    candidate, directory, attempt, target = context(root)
    for tool in ("systemd-analyze", "tor", "rg"):
        if shutil.which(tool) is None:
            raise QualificationError(f"drills need {tool} on this host")
    tests = DaemonTests(root, directory, attempt, candidate, target)
    tests.compile(["stage_eight_e2ee"])
    drills = attempt / "work/drills"
    drills.mkdir(mode=0o700, parents=True)
    host = host_checks(root, attempt)
    outcomes: dict[str, bool] = {}
    for name in DRILLS:
        try:
            tests.run(f"drill-{name}", "stage_eight_e2ee", f"stage_ten_drills::drill_{name}", ignored=True,
                      environment={"AGENC_STAGE10_DRILL_DIR": str(drills)}, timeout=DRILL_TIMEOUT)
            ran = True
        except QualificationError:
            ran = False
        record_path = drills / f"{name}.json"
        if not record_path.is_file():
            outcomes[name] = False
            continue
        record = read_record(record_path)
        outcomes[name] = validate_record(record, name) and ran
        shutil.copyfile(record_path, attempt / "evidence" / f"drill-{name}.json")
    for extra in ("compromise-audit-export.txt", "observability-stats.txt"):
        if (drills / extra).is_file():
            shutil.copyfile(drills / extra, attempt / "evidence" / f"drill-{extra}")
    facts = {name: outcomes[name] for name in DRILLS}
    facts["host_hardening"] = facts["host_hardening"] and all(host.values())
    write_once(attempt / "evidence/drills-summary.json", canonical({"drills": outcomes, "host": host}))
    finish(attempt, "drills", facts)
    failed = [name for name in DRILLS if not facts[name]]
    if failed:
        raise QualificationError("drills did not pass: " + ", ".join(failed))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (QualificationError, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        print(f"drills: {error}", file=sys.stderr)
        sys.exit(1)
