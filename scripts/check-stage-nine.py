#!/usr/bin/env python3
"""Validate the Stage 09 optional-profile and exact migration contracts."""

from __future__ import annotations

import argparse
import copy
from pathlib import Path
import tomllib


HISTORY = {
    "feature": "history", "default_enabled": False, "capability": "draft/chathistory",
    "policies_seconds": [3600, 86400, 604800], "table": 19, "key_bytes": 24,
    "message_kind": 1, "control_kind": 2, "control_sequence": 0,
    "channels": 4096, "messages": 262144, "channel_messages": 65536,
    "channel_bytes": 67108864, "total_bytes": 1073741824,
    "database_fraction_denominator": 4, "index_bytes": 268435456,
    "pool_fraction_denominator": 8, "delete_batch": 1000,
    "query_messages": 100, "page_messages": 7, "page_bytes": 65536,
    "active_queries": 256, "queries_per_origin": 1,
    "cursor_idle_seconds": 60, "query_absolute_seconds": 600,
    "history_page_result": 9, "history_expired_result": 10,
    "coordinator_metadata_kind": 5, "edge_metadata_kind": 6,
    "encrypted_history": False, "durable_result_bodies": False, "targets_query": False,
}
MIGRATION = {
    "registry": "docs/storage-migration-1-to-2.registry", "source_generation": 1,
    "target_generation": 2, "database_format": 1, "sealed_record_schema": 1,
    "registry_rules": 24, "source_modified": False, "live_migration": False,
    "required_backup": True, "legacy_history_rows": "reject",
    "legacy_non_off_channel": "preserve policy and initialize empty control",
}
WSS_LIMITS = {
    "request_line_bytes": 2048, "header_line_bytes": 4096, "header_fields": 64,
    "header_bytes": 16384, "upgrade_seconds": 5, "registration_seconds_from_tls_completion": 30,
}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_history(profile: dict[str, object]) -> None:
    require(set(profile) == {"schema_version", "stage", "tasks", "history", "migration", "test"}, "unexpected history profile fields")
    require(profile["schema_version"] == 1 and profile["stage"] == 9, "invalid history profile version")
    require(profile["tasks"] == ["S09-003", "S09-004", "S09-005"], "history task ownership changed")
    require(profile["history"] == HISTORY, "history limits or privacy policy changed")
    require(profile["migration"] == MIGRATION, "migration contract changed")


def migration_registry(data: bytes) -> None:
    tables = list(range(1, 14)) + [17, 18] + list(range(20, 25)) + [26]
    rules = [f"rule|{table}|{table}|1|{table}|1|preserve-validated-record" for table in tables]
    rules += ["rule|19|19|1|absent|0|reject-legacy-history", "rule|25|25|1|absent|0|reject-live-construction", "rule|27|8|1|19|1|initialize-legacy-history-control"]
    expected = ("\n".join(sorted(rules)) + "\n").encode("ascii")
    require(data == expected, "migration registry must match the exact 24 canonical rules")
    tuples = [tuple(row.split("|")[2:6]) for row in rules]
    require(len(tuples) == len(set(tuples)), "duplicate source/target tuple")


def validate_wss(profile: dict[str, object]) -> None:
    require(profile.get("schema_version") == 1 and profile.get("stage") == 9, "invalid WSS profile version")
    require(profile.get("tasks") == ["S09-001", "S09-002"], "WSS task ownership changed")
    require(profile.get("default_enabled") is False and profile.get("feature") == "wss", "WSS must be independent and opt-in")
    upgrade = profile.get("upgrade")
    require(isinstance(upgrade, dict), "missing WSS upgrade limits")
    require(all(upgrade.get(key) == value for key, value in WSS_LIMITS.items()), "WSS upgrade limits changed")
    require([upgrade.get(key) for key in ("tls", "alpn", "method", "path", "http_version")] == ["1.3", "http/1.1", "GET", "/irc", "1.1"], "WSS transport profile changed")
    framing = profile.get("framing", {})
    require(framing.get("message_bytes") == 8701 and framing.get("utf8_for_both_subprotocols") is True, "WSS line semantics changed")
    matrix = profile.get("matrix", {})
    require(matrix.get("builds") == ["none", "wss", "history", "wss,history"] and matrix.get("runtime_configurations_per_build") == 4, "optional feature matrix incomplete")
    require(matrix.get("admitted") == 9 and matrix.get("refused_before_storage_writes") == 7, "optional feature matrix counts changed")


def test_inventory(root: Path, profile: dict[str, object]) -> None:
    tests = profile.get("test")
    require(isinstance(tests, list) and bool(tests), "missing test inventory")
    for entry in tests:
        require(isinstance(entry, dict) and set(entry) == {"file", "names"}, "invalid test inventory entry")
        source = (root / entry["file"]).read_text(encoding="utf-8")
        require(all(f"fn {name}(" in source for name in entry["names"]), "test inventory names a missing test")


def self_test(history: dict[str, object], wss: dict[str, object], registry: bytes) -> int:
    cases = 0
    for key in HISTORY:
        changed = copy.deepcopy(history)
        del changed["history"][key]
        try:
            validate_history(changed)
        except ValueError:
            cases += 1
        else:
            raise ValueError(f"history validator accepted missing {key}")
    for key in WSS_LIMITS:
        changed = copy.deepcopy(wss)
        changed["upgrade"][key] += 1
        try:
            validate_wss(changed)
        except ValueError:
            cases += 1
        else:
            raise ValueError(f"WSS validator accepted changed {key}")
    for changed in (registry[:-1], registry + registry.splitlines(keepends=True)[0], registry.replace(b"|8|1|19|1|", b"|9|1|19|1|")):
        try:
            migration_registry(changed)
        except ValueError:
            cases += 1
        else:
            raise ValueError("migration validator accepted changed rules")
    return cases


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    command = parser.parse_args().command
    root = Path(__file__).resolve().parent.parent
    history = tomllib.loads((root / "conformance/stage-nine-history.toml").read_text())
    wss = tomllib.loads((root / "conformance/stage-nine-wss.toml").read_text())
    registry = (root / MIGRATION["registry"]).read_bytes()
    validate_history(history)
    validate_wss(wss)
    migration_registry(registry)
    if command == "self-test":
        print(f"Stage 09 profile self-test: ok ({self_test(history, wss, registry)} rejections)")
    else:
        test_inventory(root, history)
        test_inventory(root, wss)
        print("Stage 09 profile: ok (independent WSS/history, schema 1-to-2 migration)")


if __name__ == "__main__":
    main()
