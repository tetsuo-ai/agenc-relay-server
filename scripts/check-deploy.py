#!/usr/bin/env python3
"""Validate the shipped Stage 06 deployment profile."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "deploy/systemd/agenc-ircd.service"
SOCKET = ROOT / "deploy/systemd/agenc-ircd.socket"
PROFILE_DIRECTORY = ROOT / "deploy/systemd/profiles"
SYSUSERS = ROOT / "deploy/sysusers.d/agenc-ircd.conf"
TMPFILES = ROOT / "deploy/tmpfiles.d/agenc-ircd.conf"
TOR = ROOT / "deploy/tor/agenc-ircd.torrc.snippet"

SOCKET_ACCESS_GROUP = "agenc-ircd-sockets"
TOR_HIDDEN_SERVICE_DIRECTORY = "/var/lib/tor/agenc-ircd"
TOR_INACCESSIBLE_PATH = f"-{TOR_HIDDEN_SERVICE_DIRECTORY}"
SOCKET_ACCESS_COMMAND = (
    "/usr/bin/setfacl --modify "
    f"group:{SOCKET_ACCESS_GROUP}:r-x,"
    f"default:group:{SOCKET_ACCESS_GROUP}:rw- /run/agenc-ircd"
)
SYSUSER_LINES = [
    f"g {SOCKET_ACCESS_GROUP} -",
    'u agenc-ircd - "AgenC IRC daemon" /var/lib/agenc-ircd',
]

PROFILE_FAMILIES = {
    "direct.conf": "AF_UNIX AF_INET AF_INET6",
    "dual.conf": "AF_UNIX AF_INET AF_INET6",
    "onion-local-admin.conf": "AF_UNIX",
    "onion-remote-admin.conf": "AF_UNIX AF_INET AF_INET6",
}

SERVICE_VALUES = {
    ("Unit", "Description"): "AgenC IRC daemon",
    ("Unit", "After"): "network-online.target",
    ("Unit", "Wants"): "network-online.target",
    ("Service", "Type"): "simple",
    ("Service", "User"): "agenc-ircd",
    ("Service", "Group"): "agenc-ircd",
    ("Service", "UMask"): "0077",
    ("Service", "NoNewPrivileges"): "yes",
    ("Service", "ProtectSystem"): "strict",
    ("Service", "ProtectHome"): "yes",
    ("Service", "InaccessiblePaths"): TOR_INACCESSIBLE_PATH,
    ("Service", "PrivateTmp"): "yes",
    ("Service", "PrivateDevices"): "yes",
    ("Service", "ProtectKernelModules"): "yes",
    ("Service", "ProtectKernelTunables"): "yes",
    ("Service", "ProtectControlGroups"): "yes",
    ("Service", "ProtectProc"): "invisible",
    ("Service", "RestrictAddressFamilies"): "AF_UNIX",
    ("Service", "RestrictNamespaces"): "yes",
    ("Service", "RestrictSUIDSGID"): "yes",
    ("Service", "LockPersonality"): "yes",
    ("Service", "MemoryDenyWriteExecute"): "yes",
    ("Service", "SystemCallArchitectures"): "native",
    ("Service", "CapabilityBoundingSet"): "",
    ("Service", "AmbientCapabilities"): "",
    ("Service", "LimitCORE"): "0",
    ("Service", "LimitMEMLOCK"): "infinity",
    ("Service", "RuntimeDirectory"): "agenc-ircd",
    ("Service", "RuntimeDirectoryMode"): "0750",
    ("Service", "StateDirectory"): "agenc-ircd/state agenc-ircd/backups agenc-ircd/logs",
    ("Service", "StateDirectoryMode"): "0700",
    ("Service", "LogsDirectory"): "agenc-ircd",
    ("Service", "LogsDirectoryMode"): "0700",
    ("Service", "ReadOnlyPaths"): "/var/lib/agenc-ircd/keys /var/lib/agenc-ircd/trust",
    ("Service", "ReadWritePaths"): "/var/lib/agenc-ircd/state /var/lib/agenc-ircd/backups /var/lib/agenc-ircd/logs /var/log/agenc-ircd /run/agenc-ircd",
    ("Service", "ExecStart"): "/usr/bin/agenc-ircd serve --config /etc/agenc-ircd/config.toml",
    ("Service", "KillSignal"): "SIGTERM",
    ("Service", "TimeoutStopSec"): "120",
    ("Service", "Restart"): "on-failure",
    ("Install", "WantedBy"): "multi-user.target",
}

SERVICE_MULTI_VALUES = {
    ("Service", "ExecStartPre"): [
        SOCKET_ACCESS_COMMAND,
        "/usr/bin/agenc-ircd check-config --config /etc/agenc-ircd/config.toml",
    ],
    ("Service", "SystemCallFilter"): [
        "@system-service",
        "~@privileged @resources @debug @mount @raw-io",
    ]
}

TMPFILE_VALUES = {
    "/etc/agenc-ircd": ("d", "0750", "root", "agenc-ircd", "-"),
    "/etc/agenc-ircd/tls": ("d", "0750", "root", "agenc-ircd", "-"),
    "/var/lib/agenc-ircd": ("d", "0700", "agenc-ircd", "agenc-ircd", "-"),
    "/var/lib/agenc-ircd/backups": (
        "d",
        "0700",
        "agenc-ircd",
        "agenc-ircd",
        "-",
    ),
    "/var/lib/agenc-ircd/keys": ("d", "0700", "agenc-ircd", "agenc-ircd", "-"),
    "/var/lib/agenc-ircd/logs": ("d", "0700", "agenc-ircd", "agenc-ircd", "-"),
    "/var/lib/agenc-ircd/state": ("d", "0700", "agenc-ircd", "agenc-ircd", "-"),
    "/var/lib/agenc-ircd/trust": ("d", "0700", "agenc-ircd", "agenc-ircd", "-"),
    "/var/log/agenc-ircd": ("d", "0700", "agenc-ircd", "agenc-ircd", "-"),
}


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def parse_unit(text: str, label: str) -> tuple[dict[tuple[str, str], list[str]], list[str]]:
    values: dict[tuple[str, str], list[str]] = {}
    errors: list[str] = []
    section: str | None = None
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
            continue
        if section is None or "=" not in line:
            errors.append(f"{label}:{line_number}: malformed unit line")
            continue
        key, value = line.split("=", 1)
        values.setdefault((section, key), []).append(value)
    return values, errors


def validate_service(text: str) -> tuple[list[str], dict[tuple[str, str], list[str]]]:
    values, errors = parse_unit(text, "service")
    for key, expected in SERVICE_VALUES.items():
        actual = values.get(key, [])
        if actual != [expected]:
            errors.append(
                f"service: {key[0]}.{key[1]} must occur once with value {expected!r}"
            )
    for key, expected in SERVICE_MULTI_VALUES.items():
        if values.get(key, []) != expected:
            errors.append(f"service: {key[0]}.{key[1]} has an invalid directive set")
    allowed_multi = set(SERVICE_MULTI_VALUES)
    allowed = set(SERVICE_VALUES) | allowed_multi
    for key, entries in values.items():
        if key not in allowed:
            errors.append(f"service: unreviewed directive {key[0]}.{key[1]}")
        if len(entries) > 1 and key not in allowed_multi:
            errors.append(f"service: duplicate directive {key[0]}.{key[1]}")
    if "ListenStream=" in text or "LISTEN_FDS" in text:
        errors.append("service: socket activation is not supported")
    return errors, values


def validate_profiles(profiles: dict[str, str]) -> list[str]:
    errors: list[str] = []
    if set(profiles) != set(PROFILE_FAMILIES):
        errors.append("profiles: file set does not match the four reviewed profiles")
    for name, expected in PROFILE_FAMILIES.items():
        text = profiles.get(name)
        if text is None:
            continue
        values, parse_errors = parse_unit(text, f"profile {name}")
        errors.extend(parse_errors)
        expected_values = ["", expected]
        if values != {("Service", "RestrictAddressFamilies"): expected_values}:
            errors.append(f"profile {name}: address-family reset or value is invalid")
        families = set(expected.split())
        if "AF_UNIX" not in families:
            errors.append(f"profile {name}: AF_UNIX is required for local administration")
        if name == "onion-local-admin.conf" and families != {"AF_UNIX"}:
            errors.append("profile onion-local-admin.conf: IP sockets are forbidden")
    return errors


def parse_tmpfiles(
    text: str,
) -> tuple[dict[str, list[tuple[str, str, str, str, str]]], list[str]]:
    entries: dict[str, list[tuple[str, str, str, str, str]]] = {}
    errors: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split()
        if len(fields) != 6:
            errors.append(f"tmpfiles:{line_number}: malformed entry")
            continue
        kind, path, mode, user, group, age = fields
        entries.setdefault(path, []).append((kind, mode, user, group, age))
    return entries, errors


def validate_tmpfiles(
    text: str,
) -> tuple[list[str], dict[str, list[tuple[str, str, str, str, str]]]]:
    entries, errors = parse_tmpfiles(text)
    for path, expected in TMPFILE_VALUES.items():
        if entries.get(path, []) != [expected]:
            errors.append(f"tmpfiles: {path} must occur once with mode and ownership {expected}")
    for path in sorted(set(entries) - set(TMPFILE_VALUES)):
        errors.append(f"tmpfiles: unreviewed path {path}")
    return errors, entries


def parse_tor(text: str) -> tuple[dict[str, list[str]], list[str]]:
    values: dict[str, list[str]] = {}
    errors: list[str] = []
    for line_number, raw_line in enumerate(text.splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        fields = line.split(maxsplit=1)
        if len(fields) != 2:
            errors.append(f"tor:{line_number}: malformed directive")
            continue
        values.setdefault(fields[0], []).append(fields[1])
    return values, errors


def is_within(path: PurePosixPath, directory: PurePosixPath) -> bool:
    return path == directory or directory in path.parents


def managed_paths(
    values: dict[tuple[str, str], list[str]],
    key: str,
    prefix: str,
) -> list[str]:
    return [
        f"{prefix}/{name}"
        for entry in values.get(("Service", key), [])
        for name in entry.split()
    ]


def validate_tor(
    text: str,
    service_values: dict[tuple[str, str], list[str]],
    tmpfile_entries: dict[str, list[tuple[str, str, str, str, str]]],
) -> list[str]:
    values, errors = parse_tor(text)
    expected = {
        "HiddenServiceDir": [TOR_HIDDEN_SERVICE_DIRECTORY],
        "HiddenServiceVersion": ["3"],
        "HiddenServicePort": ["6697 unix:/run/agenc-ircd/onion.sock"],
    }
    if values != expected:
        errors.append("tor: hidden-service directives do not match the reviewed profile")
        return errors

    hidden = PurePosixPath(values["HiddenServiceDir"][0])
    if service_values.get(("Service", "InaccessiblePaths"), []) != [
        f"-{hidden}"
    ]:
        errors.append("tor: hidden-service keys are not masked from the daemon")
    writable = service_values.get(("Service", "ReadWritePaths"), [""])[0].split()
    writable.extend(managed_paths(service_values, "StateDirectory", "/var/lib"))
    writable.extend(managed_paths(service_values, "LogsDirectory", "/var/log"))
    writable.extend(managed_paths(service_values, "RuntimeDirectory", "/run"))
    if any(is_within(hidden, PurePosixPath(path)) for path in writable):
        errors.append("tor: hidden-service keys are inside a daemon-writable service path")

    for path_text in tmpfile_entries:
        path = PurePosixPath(path_text)
        if is_within(path, hidden) or is_within(hidden, path):
            errors.append("tor: hidden-service directory ownership must be left to Tor")
    return errors


def validate(
    service: str,
    profiles: dict[str, str],
    sysusers: str,
    tmpfiles: str,
    tor: str,
    socket_present: bool,
) -> list[str]:
    errors, service_values = validate_service(service)
    errors.extend(validate_profiles(profiles))
    if socket_present:
        errors.append("deployment: the unsupported socket unit is present")
    sysuser_lines = [
        line.strip()
        for line in sysusers.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    if sysuser_lines != SYSUSER_LINES:
        errors.append("sysusers: the daemon account or socket-access group is invalid")
    tmpfile_errors, tmpfile_entries = validate_tmpfiles(tmpfiles)
    errors.extend(tmpfile_errors)
    errors.extend(validate_tor(tor, service_values, tmpfile_entries))
    return errors


def read_profiles() -> dict[str, str]:
    return {path.name: read(path) for path in sorted(PROFILE_DIRECTORY.glob("*.conf"))}


def check() -> list[str]:
    return validate(
        read(SERVICE),
        read_profiles(),
        read(SYSUSERS),
        read(TMPFILES),
        read(TOR),
        SOCKET.exists(),
    )


def self_test() -> list[str]:
    service = read(SERVICE)
    profiles = read_profiles()
    sysusers = read(SYSUSERS)
    tmpfiles = read(TMPFILES)
    tor = read(TOR)
    failures: list[str] = []
    if validate(service, profiles, sysusers, tmpfiles, tor, False):
        failures.append("self-test: valid fixture was rejected")

    cases = [
        (service.replace("NoNewPrivileges=yes", "NoNewPrivileges=no"), profiles, sysusers, tmpfiles, tor, False),
        (service + "\n[Service]\nNoNewPrivileges=no\n", profiles, sysusers, tmpfiles, tor, False),
        (service + "\n[Service]\nSupplementaryGroups=debian-tor\n", profiles, sysusers, tmpfiles, tor, False),
        (service.replace("InaccessiblePaths=-/var/lib/tor/agenc-ircd\n", ""), profiles, sysusers, tmpfiles, tor, False),
        (service.replace("@resources ", ""), profiles, sysusers, tmpfiles, tor, False),
        (service.replace("StateDirectory=agenc-ircd/state agenc-ircd/backups agenc-ircd/logs", "StateDirectory=agenc-ircd"), profiles, sysusers, tmpfiles, tor, False),
        (service.replace("/var/lib/agenc-ircd/state", "/var/lib"), profiles, sysusers, tmpfiles, tor, False),
        (service, profiles, sysusers, tmpfiles, tor, True),
        (service, profiles, "", tmpfiles, tor, False),
        (service, profiles, sysusers, tmpfiles.replace("/var/lib/agenc-ircd/keys 0700", "/var/lib/agenc-ircd/keys 0755"), tor, False),
        (service, profiles, sysusers, tmpfiles.replace("/var/lib/agenc-ircd/keys 0700 agenc-ircd agenc-ircd -", "/var/lib/agenc-ircd/keys 0700 agenc-ircd agenc-ircd 1s"), tor, False),
        (service, {**profiles, "direct.conf": profiles["direct.conf"].replace("AF_UNIX ", "")}, sysusers, tmpfiles, tor, False),
        (service, {**profiles, "onion-local-admin.conf": profiles["onion-local-admin.conf"].replace("AF_UNIX", "AF_UNIX AF_INET")}, sysusers, tmpfiles, tor, False),
        (service, profiles, sysusers, tmpfiles, tor.replace("/var/lib/tor/agenc-ircd", "/var/lib/agenc-ircd/tor"), False),
        (service, profiles, sysusers, tmpfiles + "\nd /var/lib/tor/agenc-ircd 0700 agenc-ircd agenc-ircd -\n", tor, False),
        (service, profiles, sysusers, tmpfiles + "\nd /var/lib/tor/agenc-ircd 0700 root root -\n", tor, False),
        (service, profiles, sysusers, tmpfiles + "\nd /run/other 0700 agenc-ircd agenc-ircd -\n", tor, False),
        (service.replace(SOCKET_ACCESS_COMMAND, SOCKET_ACCESS_COMMAND.replace("r-x", "rwx", 1)), profiles, sysusers, tmpfiles, tor, False),
        (service.replace(",default:group:agenc-ircd-sockets:rw-", ""), profiles, sysusers, tmpfiles, tor, False),
        (service, profiles, sysusers.replace("g agenc-ircd-sockets -\n", ""), tmpfiles, tor, False),
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
            print(error)
        return 1
    print(f"deployment {command}: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
