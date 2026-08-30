#!/usr/bin/env python3
"""Validate the shipped Stage 06 deployment profile."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "deploy/systemd/agenc-ircd.service"
SOCKET = ROOT / "deploy/systemd/agenc-ircd.socket"
SYSUSERS = ROOT / "deploy/sysusers.d/agenc-ircd.conf"
TMPFILES = ROOT / "deploy/tmpfiles.d/agenc-ircd.conf"
TOR = ROOT / "deploy/tor/agenc-ircd.torrc.snippet"

SERVICE_LINES = {
    "User=agenc-ircd",
    "Group=agenc-ircd",
    "NoNewPrivileges=yes",
    "ProtectSystem=strict",
    "ProtectHome=yes",
    "PrivateTmp=yes",
    "PrivateDevices=yes",
    "ProtectKernelModules=yes",
    "ProtectKernelTunables=yes",
    "ProtectControlGroups=yes",
    "ProtectProc=invisible",
    "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6",
    "RestrictNamespaces=yes",
    "LockPersonality=yes",
    "MemoryDenyWriteExecute=yes",
    "SystemCallFilter=@system-service",
    "SystemCallFilter=~@privileged @resources @debug @mount @raw-io",
    "SystemCallArchitectures=native",
    "CapabilityBoundingSet=",
    "LimitCORE=0",
    "LimitMEMLOCK=infinity",
    "RuntimeDirectory=agenc-ircd",
    "RuntimeDirectoryMode=0750",
    "StateDirectory=agenc-ircd",
    "ReadWritePaths=/var/lib/agenc-ircd/state /var/lib/agenc-ircd/backups /run/agenc-ircd",
    "ExecStartPre=/usr/bin/agenc-ircd check-config --config /etc/agenc-ircd/config.toml",
    "ExecStart=/usr/bin/agenc-ircd serve --config /etc/agenc-ircd/config.toml",
    "KillSignal=SIGTERM",
    "TimeoutStopSec=120",
}

SOCKET_LINES = {
    "ListenStream=6697",
    "NoDelay=true",
    "Service=agenc-ircd.service",
}

TOR_LINES = {
    "HiddenServiceDir /var/lib/tor/agenc-ircd",
    "HiddenServiceVersion 3",
    "HiddenServicePort 6697 unix:/run/agenc-ircd/onion.sock",
}


def significant_lines(text: str) -> set[str]:
    return {
        line.strip()
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith(("#", "["))
    }


def require_lines(text: str, required: set[str], label: str) -> list[str]:
    present = significant_lines(text)
    return [f"{label}: missing {line}" for line in sorted(required - present)]


def validate(service: str, socket: str, sysusers: str, tmpfiles: str, tor: str) -> list[str]:
    errors = require_lines(service, SERVICE_LINES, "service")
    errors.extend(require_lines(socket, SOCKET_LINES, "socket"))
    errors.extend(require_lines(tor, TOR_LINES, "tor"))
    if "u agenc-ircd" not in sysusers:
        errors.append("sysusers: dedicated account is missing")
    for path in ["/var/lib/agenc-ircd/keys", "/var/lib/agenc-ircd/state", "/var/lib/agenc-ircd/trust"]:
        if f"d {path} 0700 agenc-ircd agenc-ircd" not in tmpfiles:
            errors.append(f"tmpfiles: protected directory is missing: {path}")
    return errors


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def check() -> list[str]:
    return validate(read(SERVICE), read(SOCKET), read(SYSUSERS), read(TMPFILES), read(TOR))


def self_test() -> list[str]:
    service = read(SERVICE)
    socket = read(SOCKET)
    sysusers = read(SYSUSERS)
    tmpfiles = read(TMPFILES)
    tor = read(TOR)
    failures: list[str] = []
    if validate(service, socket, sysusers, tmpfiles, tor):
        failures.append("self-test: valid fixture was rejected")
    cases = [
        (service.replace("NoNewPrivileges=yes", "NoNewPrivileges=no"), socket, sysusers, tmpfiles, tor),
        (service, socket.replace("NoDelay=true", "NoDelay=false"), sysusers, tmpfiles, tor),
        (service, socket, "", tmpfiles, tor),
        (service, socket, sysusers, "", tor),
        (service, socket, sysusers, tmpfiles, tor.replace("HiddenServiceVersion 3", "")),
    ]
    for index, case in enumerate(cases):
        if not validate(*case):
            failures.append(f"self-test: invalid fixture {index} was accepted")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("check", "self-test"))
    command = parser.parse_args().command
    errors = check() if command == "check" else self_test()
    if errors:
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(f"deployment {command}: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
