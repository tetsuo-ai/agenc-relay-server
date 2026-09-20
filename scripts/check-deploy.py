#!/usr/bin/env python3
"""Validate the shipped Stage 06 deployment profile."""

from __future__ import annotations

import argparse
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
SERVICE = ROOT / "deploy/systemd/arcd.service"
SOCKET = ROOT / "deploy/systemd/arcd.socket"
PROFILE_DIRECTORY = ROOT / "deploy/systemd/profiles"
SYSUSERS = ROOT / "deploy/sysusers.d/arcd.conf"
TMPFILES = ROOT / "deploy/tmpfiles.d/arcd.conf"
TOR = ROOT / "deploy/tor/arcd.torrc.snippet"

SOCKET_ACCESS_GROUP = "arcd-sockets"
TOR_HIDDEN_SERVICE_DIRECTORY = "/var/lib/tor/arcd"
OPERATOR_AUTHORITY_DIRECTORY = "/var/lib/arcd-operator"
INACCESSIBLE_PATHS = (
    f"-{TOR_HIDDEN_SERVICE_DIRECTORY} {OPERATOR_AUTHORITY_DIRECTORY}"
)
SOCKET_ACCESS_COMMAND = (
    "/usr/bin/setfacl --modify "
    f"group:{SOCKET_ACCESS_GROUP}:r-x,"
    f"default:group:{SOCKET_ACCESS_GROUP}:rw- /run/arcd"
)
SYSUSER_LINES = [
    f"g {SOCKET_ACCESS_GROUP} -",
    'u arcd - "Agency Relay daemon (ARCD)" /var/lib/arcd',
]

PROFILE_FAMILIES = {
    "direct.conf": "AF_UNIX AF_INET AF_INET6",
    "dual.conf": "AF_UNIX AF_INET AF_INET6",
    "onion-local-admin.conf": "AF_UNIX",
    "onion-remote-admin.conf": "AF_UNIX AF_INET AF_INET6",
}

SERVICE_VALUES = {
    ("Unit", "Description"): "Agency Relay daemon (ARCD)",
    ("Unit", "After"): "network-online.target",
    ("Unit", "Wants"): "network-online.target",
    ("Service", "Type"): "simple",
    ("Service", "User"): "arcd",
    ("Service", "Group"): "arcd",
    ("Service", "UMask"): "0077",
    ("Service", "NoNewPrivileges"): "yes",
    ("Service", "ProtectSystem"): "strict",
    ("Service", "ProtectHome"): "yes",
    ("Service", "InaccessiblePaths"): INACCESSIBLE_PATHS,
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
    ("Service", "RuntimeDirectory"): "arcd",
    ("Service", "RuntimeDirectoryMode"): "0750",
    ("Service", "RuntimeDirectoryPreserve"): "yes",
    ("Service", "StateDirectory"): "arcd/state arcd/backups arcd/logs",
    ("Service", "StateDirectoryMode"): "0700",
    ("Service", "LogsDirectory"): "arcd",
    ("Service", "LogsDirectoryMode"): "0700",
    ("Service", "ReadOnlyPaths"): "/var/lib/arcd/keys /var/lib/arcd/trust",
    ("Service", "ReadWritePaths"): "/var/lib/arcd/state /var/lib/arcd/backups /var/lib/arcd/logs /var/log/arcd /run/arcd",
    ("Service", "ExecStart"): "/usr/bin/arcd serve --config /etc/arcd/config.toml",
    ("Service", "KillSignal"): "SIGTERM",
    ("Service", "TimeoutStopSec"): "120",
    ("Service", "Restart"): "on-failure",
    ("Install", "WantedBy"): "multi-user.target",
}

SERVICE_MULTI_VALUES = {
    ("Service", "ExecStartPre"): [
        SOCKET_ACCESS_COMMAND,
        "/usr/bin/arcd check-config --config /etc/arcd/config.toml",
    ],
    ("Service", "SystemCallFilter"): [
        "@system-service",
        "~@privileged @resources @debug @mount @raw-io",
    ]
}

TMPFILE_VALUES = {
    "/etc/arcd": ("d", "0750", "root", "arcd", "-"),
    "/etc/arcd/tls": ("d", "0750", "root", "arcd", "-"),
    OPERATOR_AUTHORITY_DIRECTORY: ("d", "0700", "root", "root", "-"),
    "/run/arcd": ("d", "0750", "arcd", "arcd", "-"),
    "/var/lib/arcd": ("d", "0700", "arcd", "arcd", "-"),
    "/var/lib/arcd/backups": (
        "d",
        "0700",
        "arcd",
        "arcd",
        "-",
    ),
    "/var/lib/arcd/keys": ("d", "0700", "arcd", "arcd", "-"),
    "/var/lib/arcd/logs": ("d", "0700", "arcd", "arcd", "-"),
    "/var/lib/arcd/state": ("d", "0700", "arcd", "arcd", "-"),
    "/var/lib/arcd/trust": ("d", "0700", "arcd", "arcd", "-"),
    "/var/log/arcd": ("d", "0700", "arcd", "arcd", "-"),
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
        "HiddenServicePort": ["6697 unix:/run/arcd/onion.sock"],
    }
    if values != expected:
        errors.append("tor: hidden-service directives do not match the reviewed profile")
        return errors

    hidden = PurePosixPath(values["HiddenServiceDir"][0])
    if service_values.get(("Service", "InaccessiblePaths"), []) != [INACCESSIBLE_PATHS]:
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
        (service.replace(f"InaccessiblePaths={INACCESSIBLE_PATHS}\n", ""), profiles, sysusers, tmpfiles, tor, False),
        (service.replace(f" {OPERATOR_AUTHORITY_DIRECTORY}", ""), profiles, sysusers, tmpfiles, tor, False),
        (service.replace("RuntimeDirectoryPreserve=yes", "RuntimeDirectoryPreserve=no"), profiles, sysusers, tmpfiles, tor, False),
        (service.replace("@resources ", ""), profiles, sysusers, tmpfiles, tor, False),
        (service.replace("StateDirectory=arcd/state arcd/backups arcd/logs", "StateDirectory=arcd"), profiles, sysusers, tmpfiles, tor, False),
        (service.replace("/var/lib/arcd/state", "/var/lib"), profiles, sysusers, tmpfiles, tor, False),
        (service, profiles, sysusers, tmpfiles, tor, True),
        (service, profiles, "", tmpfiles, tor, False),
        (service, profiles, sysusers, tmpfiles.replace("/var/lib/arcd/keys 0700", "/var/lib/arcd/keys 0755"), tor, False),
        (service, profiles, sysusers, tmpfiles.replace("/var/lib/arcd/keys 0700 arcd arcd -", "/var/lib/arcd/keys 0700 arcd arcd 1s"), tor, False),
        (service, profiles, sysusers, tmpfiles.replace(f"{OPERATOR_AUTHORITY_DIRECTORY} 0700 root root", f"{OPERATOR_AUTHORITY_DIRECTORY} 0700 arcd arcd"), tor, False),
        (service, profiles, sysusers, tmpfiles.replace("/run/arcd 0750 arcd arcd", "/run/arcd 0700 arcd arcd"), tor, False),
        (service, {**profiles, "direct.conf": profiles["direct.conf"].replace("AF_UNIX ", "")}, sysusers, tmpfiles, tor, False),
        (service, {**profiles, "onion-local-admin.conf": profiles["onion-local-admin.conf"].replace("AF_UNIX", "AF_UNIX AF_INET")}, sysusers, tmpfiles, tor, False),
        (service, profiles, sysusers, tmpfiles, tor.replace("/var/lib/tor/arcd", "/var/lib/arcd/tor"), False),
        (service, profiles, sysusers, tmpfiles + "\nd /var/lib/tor/arcd 0700 arcd arcd -\n", tor, False),
        (service, profiles, sysusers, tmpfiles + "\nd /var/lib/tor/arcd 0700 root root -\n", tor, False),
        (service, profiles, sysusers, tmpfiles + "\nd /run/other 0700 arcd arcd -\n", tor, False),
        (service.replace(SOCKET_ACCESS_COMMAND, SOCKET_ACCESS_COMMAND.replace("r-x", "rwx", 1)), profiles, sysusers, tmpfiles, tor, False),
        (service.replace(",default:group:arcd-sockets:rw-", ""), profiles, sysusers, tmpfiles, tor, False),
        (service, profiles, sysusers.replace("g arcd-sockets -\n", ""), tmpfiles, tor, False),
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
