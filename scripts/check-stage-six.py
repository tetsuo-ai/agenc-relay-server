#!/usr/bin/env python3
"""Validate the closed Stage 06 runtime profile and proof inventory."""

from __future__ import annotations

import argparse
import copy
import hashlib
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

PROFILE_PATH = "conformance/stage-six-runtime-profile.toml"
TRANSCRIPT_PATH = "conformance/stage-six-transcripts.toml"
QUALIFICATION_PATH = "conformance/stage-six-qualification.toml"
EXPECTED_TASKS = [f"S06-{number:03d}" for number in range(1, 16)]
EXPECTED_TRANSCRIPTS = {
    "client-tls-core-v1": {
        "transport": "client_tls",
        "file": "crates/agenc-ircd/tests/stage_six_daemon.rs",
        "test": "production_daemon_core_v1_and_admin_mtls_are_byte_exact",
        "fixture": "test-data/transcripts/stage-six-core-v1.transcript",
    },
    "client-onion-core-v1": {
        "transport": "client_onion",
        "file": "crates/agenc-ircd-runtime/tests/tor_client.rs",
        "test": "profiles_send_only_the_selected_hostname_through_socks",
    },
    "admin-local-isolation": {
        "transport": "admin_local",
        "file": "crates/agenc-ircd-runtime/tests/listener_accept.rs",
        "test": "local_admin_lines_never_enter_the_public_client_inbox",
    },
    "admin-tls-isolation": {
        "transport": "admin_tls",
        "file": "crates/agenc-ircd-runtime/tests/listener_accept.rs",
        "test": "admin_tls_lines_never_enter_the_public_client_inbox",
    },
    "admin-mtls-exporter": {
        "transport": "admin_tls",
        "file": "crates/agenc-ircd/tests/stage_six_daemon.rs",
        "test": "production_daemon_core_v1_and_admin_mtls_are_byte_exact",
    },
    "admin-command-registry": {
        "transport": "admin_session",
        "file": "crates/agenc-ircd-admin/src/command.rs",
        "test": "every_registered_command_parses_with_its_permission_and_rules",
    },
    "admin-proof-counter-permission": {
        "transport": "admin_session",
        "file": "crates/agenc-ircd-admin/src/session.rs",
        "test": "authenticated_lines_enforce_counter_signature_form_and_permission",
    },
    "admin-confirmation": {
        "transport": "admin_session",
        "file": "crates/agenc-ircd-admin/src/session.rs",
        "test": "two_step_confirmation_binds_token_command_permissions_and_time",
    },
    "admin-authority-reload": {
        "transport": "admin_session",
        "file": "crates/agenc-ircd-admin/src/session.rs",
        "test": "authority_reload_updates_permissions_consumes_confirmation_and_disconnects_mismatch",
    },
    "admin-observed-output": {
        "transport": "admin_owner",
        "file": "crates/agenc-ircd-runtime/src/admin.rs",
        "test": "observed_output_waits_for_the_durable_audit_reply",
    },
    "admin-atomic-account-mutation": {
        "transport": "admin_owner",
        "file": "crates/agenc-ircd-runtime/src/admin.rs",
        "test": "account_mutation_waits_for_one_atomic_state_core_commit",
    },
    "admin-die-intent": {
        "transport": "admin_owner",
        "file": "crates/agenc-ircd-runtime/src/admin.rs",
        "test": "confirmed_die_commits_intent_before_requesting_stop",
    },
    "admin-framing": {
        "transport": "admin_owner",
        "file": "crates/agenc-ircd-runtime/src/admin.rs",
        "test": "reader_rejects_lf_only_and_overlong_frames",
    },
    "admin-shutdown-order": {
        "transport": "admin_owner",
        "file": "crates/agenc-ircd-runtime/src/admin.rs",
        "test": "writer_acknowledges_after_the_final_admin_frame_and_transport_close",
    },
    "public-oper-denial": {
        "transport": "client_wire",
        "file": "crates/agenc-ircd/tests/stage_six_daemon.rs",
        "test": "production_daemon_core_v1_and_admin_mtls_are_byte_exact",
    },
    "tls-hybrid-and-alpn": {
        "transport": "client_tls",
        "file": "crates/agenc-ircd-runtime/tests/tls_endpoint.rs",
        "test": "hybrid_key_exchange_and_exact_alpn_carry_bytes_both_ways",
    },
}
CORE_V1_FIXTURE_SHA256 = "d541e9c5809bb34172dbe1d4808b754289ed66ccde86146179710c58edc385b0"
EXPECTED_QUALIFICATION = {
    "deployment-policy",
    "systemd-profiles",
    "tor-configuration",
    "host-and-secret-modes",
    "crash-signals-and-reopen",
}
REQUIRED_RUNTIME_SURFACES = (
    "pub enum DaemonExit",
    "pub struct ConfigRevision",
    "pub struct RuntimeConfigSnapshot",
    "pub struct RuntimeConfigHandle",
    "pub struct PreparedReload",
    "pub struct RuntimeObserver",
    "pub struct ReadinessGate",
    "pub struct Liveness",
)
REQUIRED_DOMAIN_SURFACES = ("pub struct OperationalLimits",)
REQUIRED_ADMIN_TEXT = (
    "const STORAGE_FIELDS: [&str; 14]",
    "health readiness={} liveness={}",
    "FAIL {} UNAVAILABLE",
)


class StageSixError(ValueError):
    """One Stage 06 policy check failed."""


def load(path: Path, label: str) -> dict[str, object]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StageSixError(f"cannot read {label}: {error}") from error


def validate_profile(profile: dict[str, object]) -> None:
    if profile.get("schema_version") != 1 or profile.get("stage") != 6:
        raise StageSixError("runtime profile header is invalid")
    if profile.get("tasks") != EXPECTED_TASKS:
        raise StageSixError("runtime profile task set is stale")
    target = profile.get("target")
    if target != {
        "name": "core-v1",
        "standalone": True,
        "public_tls": True,
        "public_onion": True,
        "admin_local": True,
        "admin_tls": True,
        "http_metrics": False,
        "socket_activation": False,
    }:
        raise StageSixError("core-v1 target profile is stale")
    admin = profile.get("admin")
    if not isinstance(admin, dict) or admin.get("storage_stats_fields") != 14:
        raise StageSixError("administrative STATS STORAGE count is not 14")
    if admin.get("input_line_bytes") != 4610:
        raise StageSixError("administrative framing limit is stale")
    health = profile.get("health")
    if not isinstance(health, dict) or health.get("transport") != (
        "signed authenticated admin INFO"
    ):
        raise StageSixError("health transport is not the authenticated INFO command")
    if health.get("payload") != "health readiness=<0|1> liveness=<0|1>":
        raise StageSixError("health payload is stale")
    excluded = profile.get("excluded")
    if excluded != {
        "wss": "Stage 09",
        "federation": "Stage 07",
        "e2ee": "Stage 08",
        "production_soak": "S10-007",
    }:
        raise StageSixError("core-v1 exclusions are stale")
    closure = profile.get("closure")
    if closure != {
        "implementation_gate": "stage-six-implementation",
        "exact_sha_checkpoint_required": True,
        "evidence_schema": 2,
        "stage_records": 55,
    }:
        raise StageSixError("Stage 06 closure requirements are stale")


def validate_named_records(
    data: dict[str, object], field: str, expected: set[str], label: str
) -> list[dict[str, object]]:
    if data.get("schema_version") != 1 or data.get("stage") != 6:
        raise StageSixError(f"{label} header is invalid")
    records = data.get(field)
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise StageSixError(f"{label} records are missing")
    identifiers = [row.get("id") for row in records]
    if len(identifiers) != len(set(identifiers)) or set(identifiers) != expected:
        raise StageSixError(f"{label} record set is stale")
    return records


def validate_transcripts(root: Path, data: dict[str, object]) -> None:
    records = validate_named_records(
        data, "transcript", set(EXPECTED_TRANSCRIPTS), "transcript catalog"
    )
    for record in records:
        identifier = record.get("id")
        if not isinstance(identifier, str):
            raise StageSixError("transcript has an invalid ID")
        expected = {"id": identifier, **EXPECTED_TRANSCRIPTS[identifier]}
        if record != expected:
            raise StageSixError(f"transcript {identifier} mapping is stale")
        relative = expected["file"]
        test = expected["test"]
        path = root / relative
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as error:
            raise StageSixError(f"cannot read transcript source {relative}: {error}") from error
        if f"fn {test}" not in source:
            raise StageSixError(f"transcript test is missing: {relative}:{test}")
        fixture = expected.get("fixture")
        if fixture is not None:
            try:
                fixture_bytes = (root / fixture).read_bytes()
            except OSError as error:
                raise StageSixError(f"cannot read transcript fixture {fixture}: {error}") from error
            if hashlib.sha256(fixture_bytes).hexdigest() != CORE_V1_FIXTURE_SHA256:
                raise StageSixError("core-v1 byte-exact transcript fixture is stale")


def validate_qualification(data: dict[str, object]) -> None:
    records = validate_named_records(
        data, "check", EXPECTED_QUALIFICATION, "qualification contract"
    )
    if data.get("report_kind") != "controlled qualification contract":
        raise StageSixError("qualification report kind is stale")
    for record in records:
        if set(record) != {"id", "command", "proves"}:
            raise StageSixError(f"qualification {record.get('id')} has invalid fields")
        command = record.get("command")
        proves = record.get("proves")
        if not isinstance(command, list) or not command or any(
            not isinstance(item, str) or not item for item in command
        ):
            raise StageSixError(f"qualification {record.get('id')} has no command")
        if not isinstance(proves, list) or not proves or any(
            not isinstance(item, str) or not item for item in proves
        ):
            raise StageSixError(f"qualification {record.get('id')} has no proof set")


def validate_sources(root: Path) -> None:
    runtime = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (root / "crates/agenc-ircd-runtime/src").rglob("*.rs")
    )
    domain = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (root / "crates/agenc-ircd-domain/src").rglob("*.rs")
    )
    admin = "\n".join(
        path.read_text(encoding="utf-8")
        for path in (
            root / "crates/agenc-ircd-admin/src",
            root / "crates/agenc-ircd-runtime/src",
        )
        for path in path.rglob("*.rs")
    )
    for surface in REQUIRED_RUNTIME_SURFACES:
        if surface not in runtime:
            raise StageSixError(f"runtime surface is missing: {surface}")
    for surface in REQUIRED_DOMAIN_SURFACES:
        if surface not in domain:
            raise StageSixError(f"domain surface is missing: {surface}")
    for text in REQUIRED_ADMIN_TEXT:
        if text not in admin:
            raise StageSixError(f"administrative contract is missing: {text}")
    if (root / "deploy/systemd/agenc-ircd.socket").exists():
        raise StageSixError("unsupported socket activation unit is present")
    fuzz = tomllib.loads((root / "fuzz/Cargo.toml").read_text(encoding="utf-8"))
    bins = {entry.get("name") for entry in fuzz.get("bin", [])}
    if not {"config_document", "admin_command"}.issubset(bins):
        raise StageSixError("Stage 06 fuzz targets are missing")
    for corpus in ("config-document", "admin-command"):
        entries = list((root / "test-data/fuzz-corpus" / corpus).glob("*"))
        if not entries or any(not path.is_file() for path in entries):
            raise StageSixError(f"fuzz corpus is missing: {corpus}")


def check(root: Path) -> tuple[int, int]:
    validate_profile(load(root / PROFILE_PATH, "runtime profile"))
    transcripts = load(root / TRANSCRIPT_PATH, "transcript catalog")
    qualification = load(root / QUALIFICATION_PATH, "qualification contract")
    validate_transcripts(root, transcripts)
    validate_qualification(qualification)
    validate_sources(root)
    return len(EXPECTED_TRANSCRIPTS), len(EXPECTED_QUALIFICATION)


def self_test(root: Path) -> int:
    profile = load(root / PROFILE_PATH, "runtime profile")
    transcripts = load(root / TRANSCRIPT_PATH, "transcript catalog")
    cases = 0
    for label, changed, fragment in (
        (
            "target",
            {**profile, "target": {**profile["target"], "socket_activation": True}},
            "target profile",
        ),
        (
            "stats",
            {**profile, "admin": {**profile["admin"], "storage_stats_fields": 13}},
            "STATS STORAGE",
        ),
        (
            "health",
            {**profile, "health": {**profile["health"], "transport": "HTTP"}},
            "health transport",
        ),
    ):
        try:
            validate_profile(changed)
        except StageSixError as error:
            if fragment not in str(error):
                raise StageSixError(f"self-test {label} reached the wrong branch: {error}") from error
        else:
            raise StageSixError(f"self-test {label} was accepted")
        cases += 1
    missing = copy.deepcopy(transcripts)
    missing["transcript"].pop()
    try:
        validate_transcripts(root, missing)
    except StageSixError as error:
        if "record set" not in str(error):
            raise StageSixError(f"self-test transcript reached the wrong branch: {error}") from error
    else:
        raise StageSixError("self-test transcript was accepted")
    remapped = copy.deepcopy(transcripts)
    remapped["transcript"][0]["transport"] = "admin_local"
    try:
        validate_transcripts(root, remapped)
    except StageSixError as error:
        if "mapping is stale" not in str(error):
            raise StageSixError(
                f"self-test transcript mapping reached the wrong branch: {error}"
            ) from error
    else:
        raise StageSixError("self-test transcript mapping was accepted")
    return cases + 2


def fail(message: str) -> NoReturn:
    print(f"Stage 06 validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    command = parser.parse_args().command
    root = Path(__file__).resolve().parent.parent
    try:
        if command == "check":
            transcripts, qualifications = check(root)
            print(
                "Stage 06 runtime profile: ok "
                f"({transcripts} transcripts, {qualifications} qualification checks)"
            )
        else:
            print(f"Stage 06 runtime profile self-test: ok ({self_test(root)} rejection cases)")
    except (OSError, StageSixError, tomllib.TOMLDecodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
