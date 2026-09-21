#!/usr/bin/env python3
"""Validate the closed Stage 07 federation profile and proof inventory."""

from __future__ import annotations

import argparse
import copy
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

PROFILE_PATH = "conformance/stage-seven-federation-profile.toml"
TRANSCRIPT_PATH = "conformance/stage-seven-transcripts.toml"
MODEL_PATH = "conformance/stage-seven-model.toml"
EXPECTED_TASKS = [f"S07-{number:03d}" for number in range(1, 14)]
EXPECTED_LINK = {
    "hello_bytes": 260,
    "hello_line_bytes": 508,
    "hello_deadline_seconds": 5,
    "line_bytes": 8703,
    "fragment_bytes": 2940,
    "fragment_idle_seconds": 15,
    "ingress_bytes": 16_777_216,
    "inbound_items": 256,
    "outbound_items": 1024,
    "keepalive_idle_seconds": 15,
    "keepalive_timeout_seconds": 10,
    "reconnect_min_seconds": 1,
    "reconnect_max_seconds": 60,
}
EXPECTED_MODEL = {
    "edges": 2,
    "clients": 3,
    "channels": 2,
    "actions": 36,
    "depth": 5,
    "violations": 0,
    "invariants": ["FED-05", "FED-06", "FED-07", "STA-01"],
}
TRANSCRIPT_SURFACES = {
    "federation_wire",
    "domain",
    "storage",
    "federation_link",
    "coordinator",
    "edge",
    "admin",
    "daemon",
    "model",
}
MINIMUM_TRANSCRIPTS = 24
REQUIRED_SOURCE_SURFACES = (
    ("crates/agenc-relay-federation-wire/src", "pub struct FragmentAssembler"),
    ("crates/agenc-relay-federation-wire/src", "pub enum FederationFrame"),
    ("crates/agenc-relay-domain/src/federation", "pub struct OriginTable"),
    ("crates/agenc-relay-domain/src/federation", "pub struct CoordinatorProjection"),
    ("crates/agenc-relay-domain/src/federation", "pub struct EdgeReplica"),
    ("crates/agenc-relay-domain/src/federation", "pub struct QueryCursorTable"),
    ("crates/agenc-relay-storage/src", "pub struct FederationPeerRecord"),
    ("crates/agenc-relay-runtime/src/federation", "pub struct FederationCoordinator"),
    ("crates/agenc-relay-runtime/src/federation", "pub struct EdgeFederation"),
    ("crates/agenc-relay-runtime/src/federation", "pub async fn run_accept_owner"),
    ("crates/agenc-relay-runtime/src/federation", "pub async fn run_dial_owner"),
    ("crates/agenc-relay-runtime/src/federation", "pub async fn exchange_hello"),
    ("crates/agenc-relay-runtime/src/federation", "pub async fn run_link"),
    ("crates/agenc-relay-runtime/src/state_core", "pub struct FederationProjector"),
    ("crates/agenc-relay-runtime/src/observe", "Federation,"),
    ("crates/agenc-relay-runtime/src", "NETWORK_UNAVAILABLE"),
    ("crates/agenc-relay-testkit/src", "pub fn explore(bounds: ModelBounds)"),
)
FUZZ_TARGETS = ("federation_object", "federation_fragment")
FUZZ_CORPORA = ("federation-object", "federation-fragment")


class StageSevenError(ValueError):
    """One Stage 07 policy check failed."""


def load(path: Path, label: str) -> dict[str, object]:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StageSevenError(f"cannot read {label}: {error}") from error


def validate_profile(profile: dict[str, object]) -> None:
    if profile.get("schema_version") != 1 or profile.get("stage") != 7:
        raise StageSevenError("federation profile header is invalid")
    if profile.get("tasks") != EXPECTED_TASKS:
        raise StageSevenError("federation profile task set is stale")
    target = profile.get("target")
    if target != {
        "name": "federated-v1",
        "coordinator": True,
        "edges": True,
        "max_peers": 64,
        "link_alpn": "agenc-chat-fed/1",
        "exporter_label": "EXPORTER-agenc-chat-federation-v1",
        "san_uri_prefix": "urn:agenc-chat:server:",
    }:
        raise StageSevenError("federated-v1 target profile is stale")
    if profile.get("link") != EXPECTED_LINK:
        raise StageSevenError("link limits are stale")
    origin = profile.get("origin")
    if not isinstance(origin, dict) or origin.get("grace_seconds") != 120:
        raise StageSevenError("origin grace interval is stale")
    snapshot = profile.get("snapshot")
    if snapshot != {"max_bytes": 536_870_912, "token_seconds": 900}:
        raise StageSevenError("snapshot ceilings are stale")
    query = profile.get("query")
    if query != {
        "cursor_idle_seconds": 60,
        "cursor_absolute_seconds": 600,
        "reply_page_bytes": 65_536,
    }:
        raise StageSevenError("query cursor bounds are stale")
    edge = profile.get("edge")
    if not isinstance(edge, dict) or edge.get("partition") != (
        "FAIL <command> NETWORK_UNAVAILABLE"
    ):
        raise StageSevenError("edge partition behaviour is stale")
    if edge.get("readiness_requires_active_link") is not True:
        raise StageSevenError("edge readiness rule is stale")
    admin = profile.get("admin")
    if not isinstance(admin, dict) or admin.get("federation_stats_fields") != 7:
        raise StageSevenError("administrative STATS FEDERATION count is not 7")
    if admin.get("federation_commands") != ["CONNECT", "SQUIT", "PEER QUARANTINE"]:
        raise StageSevenError("administrative federation command set is stale")
    excluded = profile.get("excluded")
    if excluded != {
        "wss": "Stage 09",
        "e2ee": "Stage 08",
        "cross_profile_barrier": "Stage 08",
        "account_envelopes_over_federation": "deferred",
    }:
        raise StageSevenError("federated-v1 exclusions are stale")
    fuzz = profile.get("fuzz")
    if not isinstance(fuzz, dict) or fuzz.get("targets") != list(FUZZ_TARGETS):
        raise StageSevenError("fuzz targets are stale")
    closure = profile.get("closure")
    if closure != {
        "implementation_gate": "stage-seven-implementation",
        "exact_sha_checkpoint_required": True,
        "evidence_schema": 2,
        "stage_records": 38,
    }:
        raise StageSevenError("Stage 07 closure requirements are stale")


def validate_transcripts(root: Path, data: dict[str, object]) -> int:
    if data.get("schema_version") != 1 or data.get("stage") != 7:
        raise StageSevenError("transcript catalog header is invalid")
    records = data.get("transcript")
    if not isinstance(records, list) or any(not isinstance(row, dict) for row in records):
        raise StageSevenError("transcript records are missing")
    if len(records) < MINIMUM_TRANSCRIPTS:
        raise StageSevenError("transcript record set is stale")
    seen: set[str] = set()
    surfaces: set[str] = set()
    for record in records:
        if set(record) != {"id", "surface", "file", "test"}:
            raise StageSevenError(f"transcript {record.get('id')} mapping is stale")
        identifier = record.get("id")
        surface = record.get("surface")
        relative = record.get("file")
        test = record.get("test")
        if not all(isinstance(value, str) and value for value in (identifier, surface, relative, test)):
            raise StageSevenError("transcript has an invalid field")
        if identifier in seen:
            raise StageSevenError(f"duplicate transcript {identifier}")
        seen.add(str(identifier))
        if surface not in TRANSCRIPT_SURFACES:
            raise StageSevenError(f"transcript {identifier} names an unknown surface")
        surfaces.add(str(surface))
        try:
            source = (root / str(relative)).read_text(encoding="utf-8")
        except OSError as error:
            raise StageSevenError(f"cannot read transcript source {relative}: {error}") from error
        if f"fn {test}" not in source:
            raise StageSevenError(f"transcript test is missing: {relative}:{test}")
    if surfaces != TRANSCRIPT_SURFACES:
        raise StageSevenError("transcript surfaces do not cover every federation layer")
    return len(records)


def validate_model(root: Path, data: dict[str, object]) -> None:
    if data.get("schema_version") != 1 or data.get("stage") != 7:
        raise StageSevenError("model record header is invalid")
    for key, expected in EXPECTED_MODEL.items():
        if data.get(key) != expected:
            raise StageSevenError(f"model record {key} is stale")
    for key in ("states", "transitions", "paths", "refusals"):
        value = data.get(key)
        if type(value) is not int or value <= 0:
            raise StageSevenError(f"model record {key} is not a positive count")
    states = data.get("states")
    transitions = data.get("transitions")
    if not isinstance(states, int) or not isinstance(transitions, int) or transitions < states:
        raise StageSevenError("model record counts are inconsistent")
    for key in ("source", "test"):
        relative = data.get(key)
        if not isinstance(relative, str) or not (root / relative).is_file():
            raise StageSevenError(f"model record {key} does not name a file")
    test_source = (root / str(data.get("test"))).read_text(encoding="utf-8")
    if MODEL_PATH not in test_source:
        raise StageSevenError("model test does not bind the conformance record")


def validate_sources(root: Path) -> None:
    for directory, surface in REQUIRED_SOURCE_SURFACES:
        text = "\n".join(
            path.read_text(encoding="utf-8") for path in (root / directory).rglob("*.rs")
        )
        if surface not in text:
            raise StageSevenError(f"federation surface is missing: {directory}: {surface}")
    fuzz = tomllib.loads((root / "fuzz/Cargo.toml").read_text(encoding="utf-8"))
    bins = {entry.get("name") for entry in fuzz.get("bin", [])}
    if not set(FUZZ_TARGETS).issubset(bins):
        raise StageSevenError("Stage 07 fuzz targets are missing")
    for corpus in FUZZ_CORPORA:
        entries = list((root / "test-data/fuzz-corpus" / corpus).glob("*"))
        if not entries or any(not path.is_file() for path in entries):
            raise StageSevenError(f"fuzz corpus is missing: {corpus}")


def check(root: Path) -> tuple[int, int]:
    validate_profile(load(root / PROFILE_PATH, "federation profile"))
    transcripts = validate_transcripts(root, load(root / TRANSCRIPT_PATH, "transcript catalog"))
    model = load(root / MODEL_PATH, "model record")
    validate_model(root, model)
    validate_sources(root)
    states = model.get("states")
    return transcripts, states if isinstance(states, int) else 0


def self_test(root: Path) -> int:
    profile = load(root / PROFILE_PATH, "federation profile")
    transcripts = load(root / TRANSCRIPT_PATH, "transcript catalog")
    model = load(root / MODEL_PATH, "model record")
    cases = 0
    for label, changed, fragment in (
        (
            "target",
            {**profile, "target": {**profile["target"], "max_peers": 65}},
            "target profile",
        ),
        (
            "link",
            {**profile, "link": {**profile["link"], "fragment_bytes": 2941}},
            "link limits",
        ),
        (
            "stats",
            {**profile, "admin": {**profile["admin"], "federation_stats_fields": 6}},
            "STATS FEDERATION",
        ),
        (
            "partition",
            {**profile, "edge": {**profile["edge"], "partition": "queue"}},
            "partition behaviour",
        ),
    ):
        try:
            validate_profile(changed)
        except StageSevenError as error:
            if fragment not in str(error):
                raise StageSevenError(
                    f"self-test {label} reached the wrong branch: {error}"
                ) from error
        else:
            raise StageSevenError(f"self-test {label} was accepted")
        cases += 1
    missing = copy.deepcopy(transcripts)
    missing["transcript"] = [
        row for row in missing["transcript"] if row.get("surface") != "daemon"
    ]
    try:
        validate_transcripts(root, missing)
    except StageSevenError as error:
        if "every federation layer" not in str(error) and "record set" not in str(error):
            raise StageSevenError(
                f"self-test transcript surface reached the wrong branch: {error}"
            ) from error
    else:
        raise StageSevenError("self-test transcript surface was accepted")
    cases += 1
    renamed = copy.deepcopy(transcripts)
    renamed["transcript"][0]["test"] = "no_such_test"
    try:
        validate_transcripts(root, renamed)
    except StageSevenError as error:
        if "test is missing" not in str(error):
            raise StageSevenError(
                f"self-test transcript test reached the wrong branch: {error}"
            ) from error
    else:
        raise StageSevenError("self-test transcript test was accepted")
    cases += 1
    drifted = copy.deepcopy(model)
    drifted["violations"] = 1
    try:
        validate_model(root, drifted)
    except StageSevenError as error:
        if "violations is stale" not in str(error):
            raise StageSevenError(f"self-test model reached the wrong branch: {error}") from error
    else:
        raise StageSevenError("self-test model was accepted")
    cases += 1
    return cases


def fail(message: str) -> NoReturn:
    print(f"Stage 07 validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    command = parser.parse_args().command
    root = Path(__file__).resolve().parent.parent
    try:
        if command == "check":
            transcripts, states = check(root)
            print(
                "Stage 07 federation profile: ok "
                f"({transcripts} transcripts, {states} model states)"
            )
        else:
            print(f"Stage 07 federation profile self-test: ok ({self_test(root)} rejection cases)")
    except (OSError, StageSevenError, tomllib.TOMLDecodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
