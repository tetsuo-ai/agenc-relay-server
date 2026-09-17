#!/usr/bin/env python3
"""Validate the closed Stage 08 encrypted profile and proof inventory."""

from __future__ import annotations

import argparse
import copy
import hashlib
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

PROFILE_PATH = "conformance/stage-eight-e2ee-profile.toml"
TRANSCRIPT_PATH = "conformance/stage-eight-transcripts.toml"
MODEL_PATH = "conformance/stage-eight-model.toml"
CORPUS_PATH = "conformance/e2ee-mls-corpus.toml"
WIRE_BUDGET_PATH = "conformance/e2ee-wire-budget.toml"
INTEROP_PATH = "conformance/e2ee-interop-matrix.toml"
REVIEW_PACKAGE = "conformance/review"
EXPECTED_TASKS = [f"S08-{number:03d}" for number in range(1, 45)]
PROFILE_TOKEN = "N3G6svCQJGRNBGjQBK8w-6PQBAPk3G8CBa6iCnUmXkU"
EXPECTED_TARGET = {
    "name": "encrypted-v1",
    "profile_version": 1,
    "profile_token": PROFILE_TOKEN,
    "capability": "agenc.ag/e2ee-mls",
    "capability_value": (
        f"v1,profile={PROFILE_TOKEN},seg=2940,obj=262144,parts=90,welcome=4194304"
    ),
    "mls_version": 1,
    "enabled_suites": [1, 3],
    "signature_scheme": 2055,
    "credential_type": 1,
    "context_extension": 61889,
    "roster_update_proposal": 61890,
    "join_auth_bundle_extension": 61891,
    "mls_client_in_production": False,
}
EXPECTED_OBJECTS = {
    "application_mls": 65_536,
    "live": 262_144,
    "key_package": 65_536,
    "identity": 65_536,
    "root_chain": 1_048_576,
    "roster": 65_536,
    "capability": 65_536,
    "binding": 262_144,
    "finalization": 4_190_000,
    "abort": 1_048_576,
    "reinit": 4_190_000,
    "sequencer_record": 4_194_304,
    "close": 32_768,
    "device_attach": 4_096,
    "federation_control": 65_536,
    "welcome_mailbox": 4_194_304,
}
EXPECTED_FRAGMENTS = {
    "raw_bytes": 2_940,
    "live_parts": 90,
    "mailbox_parts": 1_427,
    "open_per_local_sender": 1,
    "open_per_remote_sender": 8,
    "open_per_connection": 32,
    "live_absolute_seconds": 120,
    "live_idle_seconds": 15,
    "mailbox_absolute_seconds": 600,
    "mailbox_idle_seconds": 30,
    "recent_object_seconds": 1_800,
}
EXPECTED_WIRE = {
    "client_tag_budget": 4_094,
    "server_tag_budget": 4_094,
    "combined_tag_budget": 8_191,
    "server_prefix_bytes": 127,
    "candidate_receipt_tag": 462,
    "batch_objects": 32,
    "batch_fragments": 1_427,
}
EXPECTED_FEDERATION = {
    "line_parameters": 16,
    "state_entries_per_edge": 1_000_000,
    "state_snapshot_bytes_per_edge": 536_870_912,
    "state_snapshot_token_seconds": 900,
    "state_page_entries": 32,
    "unacked_events_per_edge": 262_144,
    "unacked_event_bytes_per_edge": 1_073_741_824,
    "cross_profile_parts_per_edge": 2_048,
    "cross_profile_bytes_per_edge": 16_777_216,
    "acked_replay_rows_per_edge": 1_000_000,
    "replay_retention_seconds": 86_400,
    "origins_durable": False,
    "delivery_generation_restarts": False,
}
EXPECTED_EDGE = {
    "plaintext_on_bound_route": "FAIL <command> E2EE_REQUIRED",
    "partition": "FAIL <command> E2EE_SYNCING",
    "queue_while_syncing": False,
    "private_topic": "Encrypted channel - topic protected by IRC-MLS",
    "requests_resent_after_ready": True,
}
EXPECTED_COORDINATOR = {
    "handlers": 41,
    "candidates_per_epoch": 1,
    "finality_quorum_checked_by": "coordinator-and-endpoints",
    "bootstrap_activation_rule": "BootstrapActivation",
    "reload_tables": [22, 23],
}
EXPECTED_REVIEW_STATE = "blocked-external"
FUZZ_TARGETS = (
    "e2ee_object",
    "e2ee_mls_outer",
    "e2ee_fragment",
    "e2ee_identity_chain",
    "e2ee_tags",
)
FUZZ_CORPORA = (
    "e2ee-object",
    "e2ee-mls-outer",
    "e2ee-fragment",
    "e2ee-identity-chain",
    "e2ee-tags",
)
TRANSCRIPT_SURFACES = {
    "e2ee_wire",
    "e2ee_objects",
    "identity",
    "authority",
    "federation_frames",
    "domain",
    "storage",
    "coordinator",
    "edge",
    "daemon",
    "model",
    "vectors",
}
MINIMUM_TRANSCRIPTS = 60
EXPECTED_MODEL = {
    "accounts": 2,
    "devices": 2,
    "conversations": 2,
    "depth": 6,
    "violations": 0,
    "invariants": ["E2E-02", "E2E-03", "E2E-05", "E2E-06"],
}
REQUIRED_SOURCE_SURFACES = (
    ("crates/agenc-ircd-e2ee/src", "pub fn verify_root_identity"),
    ("crates/agenc-ircd-e2ee/src", "pub fn verify_roster"),
    ("crates/agenc-ircd-e2ee/src", "pub fn verify_binding_package"),
    ("crates/agenc-ircd-e2ee/src", "pub fn verify_commit_object"),
    ("crates/agenc-ircd-e2ee/src", "pub fn parse_mls_message"),
    ("crates/agenc-ircd-e2ee/src", "pub struct E2eeAssembler"),
    ("crates/agenc-ircd-e2ee/src", "pub enum CompanionFrame"),
    ("crates/agenc-ircd-e2ee/src", "pub struct EcapTuple"),
    ("crates/agenc-ircd-domain/src/e2ee", "pub struct RouteTable"),
    ("crates/agenc-ircd-domain/src/e2ee", "pub struct SequencerLog"),
    ("crates/agenc-ircd-domain/src/e2ee", "pub struct Lifecycle"),
    ("crates/agenc-ircd-domain/src/e2ee", "pub struct Directory"),
    ("crates/agenc-ircd-domain/src/e2ee", "pub struct Mailboxes"),
    ("crates/agenc-ircd-domain/src/e2ee", "pub struct RouteEntitlements"),
    ("crates/agenc-ircd-storage/src", "pub enum SequencerRow"),
    ("crates/agenc-ircd-storage/src", "pub struct RouteRow"),
    ("crates/agenc-ircd-runtime/src/e2ee", "pub struct CompanionCoordinator"),
    ("crates/agenc-ircd-runtime/src/e2ee", "pub struct E2eeEdge"),
    ("crates/agenc-ircd-runtime/src/e2ee", "pub(super) fn rebuild"),
    ("crates/agenc-ircd-runtime/src/federation", "pub(super) struct BarrierState"),
    ("crates/agenc-ircd-runtime/src", "E2EE_SYNCING"),
    ("crates/agenc-ircd-runtime/src", "E2EE_REQUIRED"),
    ("crates/agenc-ircd-testkit/src", "pub fn explore_e2ee(bounds: E2eeModelBounds)"),
)
FORBIDDEN_PRODUCTION_CRATES = ("openmls", "mls-rs", "mls_rs")
PRODUCTION_MANIFESTS = (
    "crates/agenc-ircd-e2ee/Cargo.toml",
    "crates/agenc-ircd-domain/Cargo.toml",
    "crates/agenc-ircd-storage/Cargo.toml",
    "crates/agenc-ircd-runtime/Cargo.toml",
    "crates/agenc-ircd/Cargo.toml",
)


class StageEightError(ValueError):
    """One Stage 08 policy check failed."""


def load(path: Path, label: str) -> dict[str, object]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StageEightError(f"cannot read {label}: {error}") from error


def validate_profile(profile: dict[str, object]) -> None:
    if profile.get("schema_version") != 1 or profile.get("stage") != 8:
        raise StageEightError("encrypted profile header is invalid")
    if profile.get("tasks") != EXPECTED_TASKS:
        raise StageEightError("encrypted profile task set is stale")
    for key, expected in (
        ("target", EXPECTED_TARGET),
        ("objects", EXPECTED_OBJECTS),
        ("fragments", EXPECTED_FRAGMENTS),
        ("wire", EXPECTED_WIRE),
        ("federation", EXPECTED_FEDERATION),
        ("edge", EXPECTED_EDGE),
        ("coordinator", EXPECTED_COORDINATOR),
    ):
        if profile.get(key) != expected:
            raise StageEightError(f"{key} profile is stale")
    admin = profile.get("admin")
    if admin != {"stats_fields": 9, "stats_selector": "E2EE"}:
        raise StageEightError("administrative STATS E2EE count is not 9")
    review = profile.get("review")
    if not isinstance(review, dict) or review.get("task") != "S08-039":
        raise StageEightError("review record does not name S08-039")
    if review.get("state") != EXPECTED_REVIEW_STATE:
        raise StageEightError("review state is not recorded as blocked-external")
    if review.get("package") != REVIEW_PACKAGE or not str(review.get("reason", "")):
        raise StageEightError("review record lacks its package or reason")
    fuzz = profile.get("fuzz")
    if not isinstance(fuzz, dict) or fuzz.get("targets") != list(FUZZ_TARGETS):
        raise StageEightError("fuzz targets are stale")
    closure = profile.get("closure")
    if closure != {
        "implementation_gate": "stage-eight-implementation",
        "exact_sha_checkpoint_required": True,
        "evidence_schema": 2,
        "stage_records": 160,
    }:
        raise StageEightError("Stage 08 closure requirements are stale")


def validate_transcripts(root: Path, data: dict[str, object]) -> int:
    if data.get("schema_version") != 1 or data.get("stage") != 8:
        raise StageEightError("transcript catalog header is invalid")
    records = data.get("transcript")
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise StageEightError("transcript records are missing")
    if len(records) < MINIMUM_TRANSCRIPTS:
        raise StageEightError("transcript record set is stale")
    seen: set[str] = set()
    surfaces: set[str] = set()
    for record in records:
        if set(record) != {"id", "surface", "file", "test", "gates"}:
            raise StageEightError(f"transcript {record.get('id')} mapping is stale")
        identifier = record.get("id")
        surface = record.get("surface")
        relative = record.get("file")
        test = record.get("test")
        gates = record.get("gates")
        if not all(isinstance(value, str) and value for value in (identifier, surface, relative, test)):
            raise StageEightError("transcript has an invalid field")
        if (
            not isinstance(gates, list)
            or not gates
            or any(type(gate) is not int or not 1 <= gate <= 22 for gate in gates)
        ):
            raise StageEightError(f"transcript {identifier} names no Section 21 gate")
        if identifier in seen:
            raise StageEightError(f"duplicate transcript {identifier}")
        seen.add(str(identifier))
        if surface not in TRANSCRIPT_SURFACES:
            raise StageEightError(f"transcript {identifier} names an unknown surface")
        surfaces.add(str(surface))
        try:
            source = (root / str(relative)).read_text(encoding="utf-8")
        except OSError as error:
            raise StageEightError(f"cannot read transcript source {relative}: {error}") from error
        if f"fn {test}" not in source:
            raise StageEightError(f"transcript test is missing: {relative}:{test}")
    if surfaces != TRANSCRIPT_SURFACES:
        raise StageEightError("transcript surfaces do not cover every encrypted layer")
    covered = {gate for record in records for gate in record["gates"]}
    missing_gates = sorted(set(range(1, 23)) - {13} - covered)
    if missing_gates:
        raise StageEightError(f"transcripts leave Section 21 gates uncovered: {missing_gates}")
    return len(records)


def validate_model(root: Path, data: dict[str, object]) -> None:
    if data.get("schema_version") != 1 or data.get("stage") != 8:
        raise StageEightError("model record header is invalid")
    for key, expected in EXPECTED_MODEL.items():
        if data.get(key) != expected:
            raise StageEightError(f"model record {key} is stale")
    for key in ("actions", "states", "transitions", "paths", "refusals"):
        value = data.get(key)
        if type(value) is not int or value <= 0:
            raise StageEightError(f"model record {key} is not a positive count")
    states = data.get("states")
    transitions = data.get("transitions")
    if not isinstance(states, int) or not isinstance(transitions, int) or transitions < states:
        raise StageEightError("model record counts are inconsistent")
    for key in ("source", "test"):
        relative = data.get(key)
        if not isinstance(relative, str) or not (root / relative).is_file():
            raise StageEightError(f"model record {key} does not name a file")
    test_source = (root / str(data.get("test"))).read_text(encoding="utf-8")
    if MODEL_PATH not in test_source:
        raise StageEightError("model test does not bind the conformance record")


def validate_corpus(root: Path, data: dict[str, object]) -> int:
    if data.get("schema_version") != 1 or data.get("stage") != 8:
        raise StageEightError("corpus pin header is invalid")
    repository = data.get("repository")
    if repository != "https://github.com/mlswg/mls-implementations":
        raise StageEightError("corpus repository is not the MLS WG interoperability repository")
    commit = data.get("commit")
    if not isinstance(commit, str) or len(commit) != 40 or set(commit) - set("0123456789abcdef"):
        raise StageEightError("corpus commit is not a full revision")
    if data.get("suites") != [1, 3]:
        raise StageEightError("corpus suite set is stale")
    upstream = data.get("upstream")
    if not isinstance(upstream, list) or not upstream:
        raise StageEightError("corpus upstream file set is missing")
    upstream_paths: set[str] = set()
    for entry in upstream:
        if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "bytes"}:
            raise StageEightError("corpus upstream record is malformed")
        digest = entry.get("sha256")
        if not isinstance(digest, str) or len(digest) != 64 or set(digest) - set("0123456789abcdef"):
            raise StageEightError("corpus upstream digest is malformed")
        if type(entry.get("bytes")) is not int or entry["bytes"] <= 0:
            raise StageEightError("corpus upstream size is malformed")
        upstream_paths.add(str(entry.get("path")))
    local = data.get("local")
    if not isinstance(local, list) or not local:
        raise StageEightError("corpus local file set is missing")
    for entry in local:
        if not isinstance(entry, dict) or set(entry) != {
            "path",
            "sha256",
            "bytes",
            "derived_from",
            "selection",
        }:
            raise StageEightError("corpus local record is malformed")
        if entry.get("derived_from") not in upstream_paths:
            raise StageEightError(f"corpus file {entry.get('path')} names no pinned upstream source")
        path = root / str(entry.get("path"))
        if not path.is_file() or path.stat().st_size != entry.get("bytes"):
            raise StageEightError(f"corpus file is missing or resized: {entry.get('path')}")
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry.get("sha256"):
            raise StageEightError(f"corpus file digest differs: {entry.get('path')}")
    return len(local)


def validate_interop(data: dict[str, object]) -> int:
    if data.get("schema_version") != 1 or data.get("stage") != 8:
        raise StageEightError("interop matrix header is invalid")
    libraries = data.get("library")
    if not isinstance(libraries, list) or len(libraries) < 2:
        raise StageEightError("interop matrix names fewer than two libraries")
    for library in libraries:
        if not isinstance(library, dict) or set(library) != {"name", "version", "role"}:
            raise StageEightError("interop library record is malformed")
    results = data.get("result")
    if not isinstance(results, list) or not results:
        raise StageEightError("interop results are missing")
    for result in results:
        if not isinstance(result, dict) or set(result) != {
            "id",
            "suite",
            "producer",
            "consumer",
            "outcome",
            "test",
        }:
            raise StageEightError("interop result record is malformed")
        if result.get("outcome") not in {"agree", "deviation-recorded"}:
            raise StageEightError(f"interop result {result.get('id')} has an unknown outcome")
    lifecycle = data.get("lifecycle")
    if not isinstance(lifecycle, list) or len(lifecycle) < 8:
        raise StageEightError("interop lifecycle rules are missing (gate 3 needs the full lifecycle)")
    for rule in lifecycle:
        if not isinstance(rule, dict) or set(rule) != {
            "id",
            "creator",
            "joiner",
            "suite",
            "outcome",
            "claim",
            "test",
        }:
            raise StageEightError("interop lifecycle record is malformed")
        if rule.get("creator") == rule.get("joiner"):
            raise StageEightError("interop lifecycle rule must cross two libraries")
        if rule.get("outcome") not in {"agree", "deviation-recorded"}:
            raise StageEightError(f"interop lifecycle {rule.get('id')} has an unknown outcome")
    return len(results) + len(lifecycle)


def validate_wire_budget(data: dict[str, object]) -> None:
    budgets = data.get("budget")
    if not isinstance(budgets, dict) or not budgets:
        raise StageEightError("wire budget table is missing")
    for key, value in budgets.items():
        if type(value) is not int or value <= 0:
            raise StageEightError(f"wire budget {key} is not a positive byte count")
    if budgets.get("receipt_tag_with_separator") != 462:
        raise StageEightError("wire budget receipt tag width is stale")


def validate_sources(root: Path) -> None:
    for directory, surface in REQUIRED_SOURCE_SURFACES:
        text = "\n".join(
            path.read_text(encoding="utf-8") for path in (root / directory).rglob("*.rs")
        )
        if surface not in text:
            raise StageEightError(f"encrypted surface is missing: {directory}: {surface}")
    fuzz = tomllib.loads((root / "fuzz/Cargo.toml").read_text(encoding="utf-8"))
    bins = {entry.get("name") for entry in fuzz.get("bin", [])}
    if not set(FUZZ_TARGETS).issubset(bins):
        raise StageEightError("Stage 08 fuzz targets are missing")
    for corpus in FUZZ_CORPORA:
        entries = list((root / "test-data/fuzz-corpus" / corpus).glob("*"))
        if not entries or any(not path.is_file() for path in entries):
            raise StageEightError(f"fuzz corpus is missing: {corpus}")
    for manifest in PRODUCTION_MANIFESTS:
        tables = tomllib.loads((root / manifest).read_text(encoding="utf-8"))
        # The daemon binary crate may link MLS clients from its integration
        # tests only (companion Section 21 gate 3); no production table may.
        test_only = manifest == "crates/agenc-ircd/Cargo.toml"
        for table_name in ("dependencies", "build-dependencies", "dev-dependencies"):
            if test_only and table_name == "dev-dependencies":
                continue
            table = tables.get(table_name, {})
            names = table.keys() if isinstance(table, dict) else ()
            if any(name.startswith(FORBIDDEN_PRODUCTION_CRATES) for name in names):
                raise StageEightError(f"production manifest names an MLS client crate: {manifest}")
    review = root / REVIEW_PACKAGE
    for name in ("README.md", "findings.md"):
        if not (review / name).is_file():
            raise StageEightError(f"review package is incomplete: {name}")


def check(root: Path) -> tuple[int, int, int, int]:
    validate_profile(load(root / PROFILE_PATH, "encrypted profile"))
    transcripts = validate_transcripts(root, load(root / TRANSCRIPT_PATH, "transcript catalog"))
    model = load(root / MODEL_PATH, "model record")
    validate_model(root, model)
    corpus = validate_corpus(root, load(root / CORPUS_PATH, "corpus pin"))
    interop = validate_interop(load(root / INTEROP_PATH, "interop matrix"))
    validate_wire_budget(load(root / WIRE_BUDGET_PATH, "wire budget"))
    validate_sources(root)
    states = model.get("states")
    return transcripts, states if isinstance(states, int) else 0, corpus, interop


def self_test(root: Path) -> int:
    profile = load(root / PROFILE_PATH, "encrypted profile")
    transcripts = load(root / TRANSCRIPT_PATH, "transcript catalog")
    model = load(root / MODEL_PATH, "model record")
    corpus = load(root / CORPUS_PATH, "corpus pin")
    interop = load(root / INTEROP_PATH, "interop matrix")
    cases = 0
    for label, changed, fragment in (
        (
            "target",
            {**profile, "target": {**profile["target"], "enabled_suites": [1]}},
            "target profile",
        ),
        (
            "fragments",
            {**profile, "fragments": {**profile["fragments"], "raw_bytes": 2941}},
            "fragments profile",
        ),
        (
            "stats",
            {**profile, "admin": {**profile["admin"], "stats_fields": 8}},
            "STATS E2EE",
        ),
        (
            "review",
            {**profile, "review": {**profile["review"], "state": "complete"}},
            "review state",
        ),
        (
            "edge",
            {**profile, "edge": {**profile["edge"], "queue_while_syncing": True}},
            "edge profile",
        ),
    ):
        try:
            validate_profile(changed)
        except StageEightError as error:
            if fragment not in str(error):
                raise StageEightError(
                    f"self-test {label} reached the wrong branch: {error}"
                ) from error
        else:
            raise StageEightError(f"self-test {label} was accepted")
        cases += 1
    missing = copy.deepcopy(transcripts)
    missing["transcript"] = [
        row for row in missing["transcript"] if row.get("surface") != "daemon"
    ]
    try:
        validate_transcripts(root, missing)
    except StageEightError as error:
        if "every encrypted layer" not in str(error) and "record set" not in str(error):
            raise StageEightError(
                f"self-test transcript surface reached the wrong branch: {error}"
            ) from error
    else:
        raise StageEightError("self-test transcript surface was accepted")
    cases += 1
    renamed = copy.deepcopy(transcripts)
    renamed["transcript"][0]["test"] = "no_such_test"
    try:
        validate_transcripts(root, renamed)
    except StageEightError as error:
        if "test is missing" not in str(error):
            raise StageEightError(
                f"self-test transcript test reached the wrong branch: {error}"
            ) from error
    else:
        raise StageEightError("self-test transcript test was accepted")
    cases += 1
    ungated = copy.deepcopy(transcripts)
    for row in ungated["transcript"]:
        row["gates"] = [gate for gate in row["gates"] if gate != 22]
        if not row["gates"]:
            row["gates"] = [1]
    try:
        validate_transcripts(root, ungated)
    except StageEightError as error:
        if "gates uncovered" not in str(error):
            raise StageEightError(
                f"self-test transcript gate reached the wrong branch: {error}"
            ) from error
    else:
        raise StageEightError("self-test transcript gate was accepted")
    cases += 1
    drifted = copy.deepcopy(model)
    drifted["violations"] = 1
    try:
        validate_model(root, drifted)
    except StageEightError as error:
        if "violations is stale" not in str(error):
            raise StageEightError(f"self-test model reached the wrong branch: {error}") from error
    else:
        raise StageEightError("self-test model was accepted")
    cases += 1
    tampered = copy.deepcopy(corpus)
    tampered["local"][0]["sha256"] = "0" * 64
    try:
        validate_corpus(root, tampered)
    except StageEightError as error:
        if "digest differs" not in str(error):
            raise StageEightError(f"self-test corpus reached the wrong branch: {error}") from error
    else:
        raise StageEightError("self-test corpus was accepted")
    cases += 1
    single = copy.deepcopy(interop)
    single["library"] = single["library"][:1]
    try:
        validate_interop(single)
    except StageEightError as error:
        if "fewer than two" not in str(error):
            raise StageEightError(f"self-test interop reached the wrong branch: {error}") from error
    else:
        raise StageEightError("self-test interop was accepted")
    cases += 1
    return cases


def fail(message: str) -> NoReturn:
    print(f"Stage 08 validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    command = parser.parse_args().command
    root = Path(__file__).resolve().parent.parent
    try:
        if command == "check":
            transcripts, states, corpus, interop = check(root)
            print(
                "Stage 08 encrypted profile: ok "
                f"({transcripts} transcripts, {states} model states, "
                f"{corpus} corpus files, {interop} interop results)"
            )
        else:
            print(f"Stage 08 encrypted profile self-test: ok ({self_test(root)} rejection cases)")
    except (OSError, StageEightError, tomllib.TOMLDecodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
