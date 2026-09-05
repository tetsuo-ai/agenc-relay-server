#!/usr/bin/env python3
"""Qualify real client sessions, private routing, and isolated Tor transport."""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import uuid
from pathlib import Path

from release_qualification.daemon_tests import DaemonTests
from release_qualification.driver import command, context, finish
from release_qualification.policy import checked_run
from release_qualification.records import QualificationError, canonical, read_record, safe_path, write_once


def tor_network(root: Path, attempt: Path, tests: DaemonTests, image: str) -> None:
    work = attempt / "tor-work"
    work.mkdir(mode=0o700)
    name = f"agenc-tor-{uuid.uuid4().hex}"
    argv = ["docker", "run", "--init", "--rm", "--name", name, "--pull=never", "--network=none", "--read-only",
            "--cap-drop=ALL", "--cap-add=NET_RAW", "--cap-add=DAC_OVERRIDE", "--cap-add=SETUID",
            "--cap-add=SETGID", "--cap-add=CHOWN", "--cap-add=KILL", "--security-opt=no-new-privileges",
            "--pids-limit=256", "--tmpfs", "/tmp:rw,nosuid,nodev,size=256m",
            "--mount", f"type=bind,src={root},dst={root},readonly",
            "--mount", f"type=bind,src={attempt},dst={attempt},readonly",
            "--mount", f"type=bind,src={work},dst=/work", "--workdir", str(root), image,
            "python3", "scripts/run-isolated-tor.py", "--test-executable", str(tests.executables["stage_six_daemon"]),
            "--work", "/work", "--native-uid", str(os.getuid()), "--native-gid", str(os.getgid())]
    try:
        command(root, attempt, "tor-network", argv, 600)
    finally:
        subprocess.run(["docker", "rm", "--force", name], stdin=subprocess.DEVNULL,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30, check=False)
        for path in (work / "tor-public").glob("*"):
            shutil.copyfile(safe_path(work, path.relative_to(work).as_posix()), attempt / "evidence" / f"tor-{path.name}")
    tests.verify_binary()
    report = read_record(work / "tor-result.json")
    if report["different_contexts_use_different_circuits"] is not True or report["kernel_dropped_packets"] != 0 or report["dns_packets"] != 0 or report["plaintext_canary_found"] is not False:
        raise QualificationError("isolated Tor packet or circuit qualification failed")
    for name in ("native-client.log", "bootstrap.log", "stop.log", "capture.log", "packets.pcap",
                 "control-events.log", "dns-packets.log", "tor-result.json", "network.py"):
        shutil.copyfile(safe_path(work, name), attempt / "evidence" / f"tor-{name}")


def main() -> None:
    root = Path(__file__).resolve().parent.parent
    candidate, directory, attempt, target = context(root)
    # The client tools image is bound into the candidate by its own record;
    # it is not the release build image.
    tools = next(item for item in candidate["tools"] if item["target"] == target)
    tools_record = read_record(safe_path(directory, tools["record"]))
    image = checked_run(root, ["docker", "image", "inspect", "--format={{.Id}}", tools_record["image"]])
    from release_qualification.build import immutable_image
    immutable_image(image)
    command(root, attempt, "client-tool-versions", ["docker", "run", "--rm", "--pull=never", "--network=none",
            image, "python3", "-c", "import subprocess; [subprocess.run(a,check=True) for a in [['weechat-headless','--version'],['irssi','--version'],['tor','--version'],['tcpdump','--version']]]"])
    write_once(attempt / "evidence/tool-image.json", canonical({"tools_image": tools_record["image"], "image_id": image,
                                                                "tools_record_sha256": tools["record_sha256"]}))
    tests = DaemonTests(root, directory, attempt, candidate, target)
    tests.compile(["stage_six_daemon", "stage_seven_federation", "stage_eight_e2ee"])
    tests.run("conventional-clients", "stage_six_daemon",
              "stage_ten::conventional_clients_exchange_public_messages_and_cannot_enter_secret_channels",
              ignored=True, environment={"AGENC_STAGE10_TOOL_IMAGE": image})
    tests.run("native-account-lifecycle", "stage_six_daemon", "production_daemon_serves_restarts_reconciles_and_stops")
    tests.run("tls-admin", "stage_six_daemon", "production_daemon_core_v1_and_admin_mtls_are_byte_exact")
    tests.run("wss-policy", "stage_six_daemon", "wss::wss_origin_reload_and_alpn_are_enforced_by_the_live_listener")
    tests.run("wss-equivalence", "stage_six_daemon", "wss::equivalence::tcp_text_and_binary_wss_have_identical_transcripts_and_durable_state")
    tests.run("federation", "stage_seven_federation", "clients_on_two_edges_share_channels_through_the_coordinator")
    tests.run("mls-engines", "stage_eight_e2ee", "encrypted_clients_on_two_edges_bind_a_channel_through_the_coordinator")
    tor_network(root, attempt, tests, image)
    command(root, attempt, "native-tor-refusals", ["cargo", "test", "-p", "agenc-ircd-runtime", "--test", "tor_client", "--all-features", "--locked"])
    command(root, attempt, "account-canaries-and-timing", ["cargo", "test", "-p", "agenc-ircd-auth", "--test", "stage_four_security", "--locked"])
    command(root, attempt, "client-trust-and-rendering", ["cargo", "test", "-p", "agenc-ircd-testkit", "--test", "client_policy", "--locked"])
    finish(attempt, "interoperability", {name: True for name in (
        "weechat", "irssi", "native_accounts", "openmls", "mls_rs", "federation", "tls", "wss", "tor_v3",
        "socks_isolation", "packet_capture", "dns_leaks", "metadata_canaries", "timing_classes", "trust_presentation", "safe_rendering")})


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        print(f"network qualification: {error}", file=sys.stderr)
        sys.exit(1)
