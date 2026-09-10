#!/usr/bin/env python3
"""Exercise the native client and daemon inside a network-disabled container."""

from __future__ import annotations

import argparse
import json
import os
import re
import selectors
import shutil
import signal
import socket
import subprocess
import time
from pathlib import Path

CANARY = b"agenc-stage-ten-private-plaintext-canary"
MAX_CAPTURE = 64 * 1024 * 1024
TEST = "stage_ten_tor::native_tor_v3_sessions_preserve_context_isolation"


def wait_file(path: Path, child: subprocess.Popen, seconds: int) -> str:
    deadline = time.monotonic() + seconds
    while not path.exists():
        if child.poll() is not None or time.monotonic() > deadline:
            raise RuntimeError(f"Tor fixture did not produce {path.name}")
        time.sleep(0.1)
    if path.stat().st_size > 512:
        raise RuntimeError("Tor fixture metadata exceeds its bound")
    return path.read_text().strip()


def configure(work: Path, port: int) -> tuple[Path, dict[str, str]]:
    network = work / "network.py"
    network.write_text(
        'Authority = Node(tag="a", authority=1, relay=1, extra_raw_torrc="NumCPUs 1\\n")\n'
        'Relay = Node(tag="r", relay=1, extra_raw_torrc="NumCPUs 1\\n")\n'
        'Client = Node(tag="c", client=1, '
        'extra_raw_torrc="NumCPUs 1\\nSafeSocks 1\\n")\n'
        'Service = Node(tag="h", hs=1, extra_raw_torrc="NumCPUs 1\\n")\n'
        "ConfigureNodes(Authority.getN(4) + Relay.getN(3) + Client.getN(1) + Service.getN(1))\n"
    )
    environment = {**os.environ, "CHUTNEY_DATA_DIR": str(work / "tor"), "CHUTNEY_START_TIME": "240",
                   "CHUTNEY_DNS_CONF": "/dev/null", "CHUTNEY_DISABLE_IPV6": "1",
                   "CHUTNEY_CONTROLLING_PID": str(os.getpid()), "CHUTNEY_TOR_SANDBOX": "0"}
    return network, environment


def control_socket(work: Path) -> socket.socket:
    client = work / "tor/nodes/007c"
    configuration = (client / "torrc").read_text()
    endpoint = re.findall(r"^ControlSocket (.+)$", configuration, re.MULTILINE)
    if len(endpoint) != 1:
        raise RuntimeError("Tor client did not expose its local control socket")
    control = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    control.settimeout(10)
    try:
        control.connect(endpoint[0])
        cookie = (client / "control_auth_cookie").read_bytes()
        if len(cookie) != 32:
            raise RuntimeError("Tor control cookie has an unexpected length")
        for command in (b"AUTHENTICATE " + cookie.hex().encode(), b"SETEVENTS STREAM"):
            control.sendall(command + b"\r\n")
            reply = bytearray()
            while not reply.endswith(b"\r\n") and len(reply) <= 4096:
                block = control.recv(1)
                if not block:
                    raise RuntimeError("Tor control socket closed")
                reply.extend(block)
            if reply != b"250 OK\r\n":
                raise RuntimeError("Tor control authentication or subscription failed")
        control.setblocking(False)
        return control
    except BaseException:
        control.close()
        raise


def collect_events(control: socket.socket, child: subprocess.Popen, capture: Path) -> bytes:
    events = bytearray()
    deadline = time.monotonic() + 150
    with selectors.DefaultSelector() as selector:
        selector.register(control, selectors.EVENT_READ)
        while child.poll() is None:
            if time.monotonic() > deadline:
                raise RuntimeError("native Tor client exceeded its test budget")
            if capture.exists() and capture.stat().st_size > MAX_CAPTURE:
                raise RuntimeError("Tor packet capture exceeds its bound")
            for _, _ in selector.select(0.1):
                block = control.recv(16384)
                if not block:
                    raise RuntimeError("Tor event stream closed during qualification")
                events.extend(block)
                if len(events) > 4 * 1024 * 1024:
                    raise RuntimeError("Tor control transcript exceeds its bound")
        # Drain events already queued when the native test exited.
        while selector.select(0.1):
            block = control.recv(16384)
            if not block:
                break
            events.extend(block)
            if len(events) > 4 * 1024 * 1024 or time.monotonic() > deadline:
                raise RuntimeError("Tor control drain exceeds its bound")
    return bytes(events)


def validate_events(events: bytes, onion: str) -> dict[str, object]:
    succeeded = []
    for line in events.decode("ascii").splitlines():
        fields = line.split()
        if len(fields) < 6 or fields[:2] != ["650", "STREAM"] or fields[3] != "SUCCEEDED" or fields[5] != f"{onion}:5858":
            continue
        credentials = re.findall(r'SOCKS_(?:USERNAME|PASSWORD)="([ab]{32})"', line)
        if len(credentials) != 2 or credentials[0] != credentials[1] or not fields[4].isdecimal() or fields[4] == "0":
            raise RuntimeError("Tor omitted the fixture's stream isolation binding")
        succeeded.append({"stream": fields[2], "circuit": fields[4], "context": credentials[0][0]})
    if [row["context"] for row in succeeded] != ["a", "b", "a"]:
        raise RuntimeError("Tor did not establish the three requested isolation contexts")
    first = {row["circuit"] for row in succeeded if row["context"] == "a"}
    second = {row["circuit"] for row in succeeded if row["context"] == "b"}
    if first & second:
        raise RuntimeError("different SOCKS contexts shared a Tor circuit")
    return {"streams": succeeded, "different_contexts_use_different_circuits": True}


def packet_evidence(work: Path) -> dict[str, object]:
    capture = work / "packets.pcap"
    if not 24 < capture.stat().st_size <= MAX_CAPTURE:
        raise RuntimeError("Tor packet evidence is empty or exceeds its bound")
    if CANARY in capture.read_bytes():
        raise RuntimeError("plaintext canary appeared in the packet capture")
    dropped = re.findall(r"(\d+) packets dropped by kernel", (work / "capture.log").read_text())
    if dropped != ["0"]:
        raise RuntimeError("packet capture dropped packets or omitted loss accounting")
    dns = subprocess.run(["tcpdump", "-nn", "-r", str(capture), "port", "53"],
                         check=True, capture_output=True, timeout=30)
    (work / "dns-packets.log").write_bytes(dns.stdout + dns.stderr)
    if dns.stdout:
        raise RuntimeError("DNS packets appeared during native onion sessions")
    return {"capture_bytes": capture.stat().st_size, "kernel_dropped_packets": 0,
            "dns_packets": 0, "plaintext_canary_found": False}


def retain_public_logs(work: Path, uid: int, gid: int) -> None:
    public = work / "tor-public"
    public.mkdir(mode=0o700)
    nodes = work / "tor/nodes"
    for node in ("000a", "001a", "002a", "003a", "004r", "005r", "006r", "007c", "008h"):
        for name in ("torrc", "notice.log", "info.log"):
            source = nodes / node / name
            if source.is_file():
                if source.stat().st_size > 16 * 1024 * 1024:
                    raise RuntimeError("Tor node log exceeds its retention bound")
                shutil.copyfile(source, public / f"{node}-{name}")
    # Test onion keys and authority secrets are not release evidence.
    if (work / "tor").exists():
        shutil.rmtree(work / "tor")
    for path in [*public.iterdir(), public, *work.iterdir()]:
        if not path.is_symlink():
            os.chown(path, uid, gid)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--test-executable", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--native-uid", type=int, required=True)
    parser.add_argument("--native-gid", type=int, required=True)
    args = parser.parse_args()
    if sorted(path.name for path in Path("/sys/class/net").iterdir()) != ["lo"]:
        raise RuntimeError("Tor qualification must run with the whole container network disabled")
    work = args.work.resolve()
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    if any(work.iterdir()):
        raise RuntimeError("Tor qualification work directory must be empty")
    home = work / "home"
    home.mkdir(mode=0o700)
    if args.native_uid <= 0 or args.native_gid <= 0:
        raise RuntimeError("the production daemon test must run without root privileges")
    os.chown(home, args.native_uid, args.native_gid)
    environment = {**os.environ, "HOME": str(home), "AGENC_STAGE10_TOR_COORDINATION": str(work)}
    native_log = (work / "native-client.log").open("xb")
    child = subprocess.Popen([str(args.test_executable), TEST, "--exact", "--ignored", "--nocapture"],
                             env=environment, user=args.native_uid, group=args.native_gid, extra_groups=[],
                             stdin=subprocess.DEVNULL, stdout=native_log, stderr=subprocess.STDOUT)
    network = None
    tor_environment = None
    capture = None
    capture_log = None
    try:
        port = int(wait_file(work / "daemon-port", child, 30))
        if not 1 <= port <= 65535:
            raise RuntimeError("daemon port is invalid")
        network, tor_environment = configure(work, port)
        with (work / "bootstrap.log").open("xb") as log:
            for operation in (["init", "--net-from-script-path", str(network)], ["configure"]):
                subprocess.run(["/opt/tor-tools/bin/chutney", *operation], env=tor_environment,
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=60)
            service_config = work / "tor/nodes/008h/torrc"
            text = service_config.read_text()
            text, count = re.subn(r"^HiddenServicePort 5858 127\.0\.0\.1:4747$", f"HiddenServicePort 5858 127.0.0.1:{port}", text, flags=re.MULTILINE)
            if count != 1:
                raise RuntimeError("onion service target differs from the pinned Chutney configuration")
            service_config.write_text(text)
            client_config = work / "tor/nodes/007c/torrc"
            text = client_config.read_text()
            text, count = re.subn(r"^SocksPort .+$", "SocksPort 127.0.0.1:9007 IsolateSOCKSAuth", text, flags=re.MULTILINE)
            if count != 1:
                raise RuntimeError("Tor client exposes an unexpected proxy configuration")
            client_config.write_text(text)
            for operation in ("start", "wait_for_bootstrap"):
                subprocess.run(["/opt/tor-tools/bin/chutney", operation], env=tor_environment,
                               stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, check=True, timeout=300)
        onion = (work / "tor/nodes/008h/hidden_service/hostname").read_text().strip()
        if not re.fullmatch(r"[a-z2-7]{56}\.onion", onion):
            raise RuntimeError("Tor did not create a version 3 onion service")
        with control_socket(work) as control:
            capture_log = (work / "capture.log").open("xb")
            capture = subprocess.Popen(["tcpdump", "-Z", "root", "-i", "any", "-U", "-s", "0", "-w", str(work / "packets.pcap"),
                                        "tcp or udp port 53"], stdin=subprocess.DEVNULL, stdout=capture_log, stderr=subprocess.STDOUT)
            deadline = time.monotonic() + 10
            while not (work / "packets.pcap").exists():
                if capture.poll() is not None or time.monotonic() > deadline:
                    raise RuntimeError("packet capture did not start")
                time.sleep(0.05)
            temporary = work / "network-ready.tmp"
            temporary.write_text(f"{onion}\n127.0.0.1:9007\n")
            temporary.rename(work / "network-ready")
            events = collect_events(control, child, work / "packets.pcap")
        if child.wait(timeout=10) != 0:
            raise RuntimeError("native Tor client integration test failed")
        (work / "control-events.log").write_bytes(events)
        facts = validate_events(events, onion)
        capture.send_signal(signal.SIGINT)
        if capture.wait(timeout=10) != 0:
            raise RuntimeError("packet capture failed")
        capture_log.close()
        facts.update(packet_evidence(work))
        (work / "tor-result.json").write_text(json.dumps(facts, sort_keys=True, indent=2) + "\n")
    finally:
        if capture is not None and capture.poll() is None:
            capture.kill()
            capture.wait()
        if capture_log is not None:
            capture_log.close()
        if child.poll() is None:
            child.kill()
        child.wait()
        native_log.close()
        if network is not None:
            try:
                with (work / "stop.log").open("xb") as log:
                    subprocess.run(["/opt/tor-tools/bin/chutney", "stop"], env=tor_environment,
                                   stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, timeout=30, check=True)
            finally:
                retain_public_logs(work, args.native_uid, args.native_gid)


if __name__ == "__main__":
    main()
