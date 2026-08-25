#!/usr/bin/env python3
"""Validate evidence catalogs, manifests, and their cross-record bindings."""

from __future__ import annotations

import argparse
import copy
import json
import re
import sys
import tomllib
from datetime import datetime, timezone
from pathlib import Path
from typing import NoReturn

CATALOG_PATH = "conformance/evidence-catalog.toml"
LEDGER_PATH = "conformance/requirements.toml"
SCHEMA_PATH = "conformance/evidence-manifest.schema.json"
EXAMPLE_PATH = "conformance/evidence-manifest.example.json"

STAGE_BINDINGS = {
    "EVID-S00-001-BASELINE": (["S00-001"], "specification-baseline"),
    "EVID-S00-002-REQUIREMENTS": (["S00-002"], "requirement-ledger"),
    "EVID-S00-003-BUILD-CONTRACT": (["S00-003"], "build-contract"),
    "EVID-S00-004-CRATE-GRAPH": (["S00-004"], "workspace-graph"),
    "EVID-S00-005-SOURCE-POLICY": (["S00-005"], "source-policy"),
    "EVID-S00-006-DEPENDENCIES": (["S00-006"], "dependency-policy"),
    "EVID-S00-007-EVIDENCE-LAYOUT": (["S00-007"], "test-evidence-layout"),
    "EVID-S00-008-TESTKIT-ISOLATION": (["S00-008"], "testkit-isolation"),
    "EVID-S00-009-CI-BASELINE": (["S00-009"], "continuous-integration"),
    "EVID-S00-010-MANIFEST-SCHEMA": (["S00-010"], "evidence-schema"),
    "EVID-S00-900-STAGE-GATE": (["S00-900"], "stage-gate"),
}
TOP_FIELDS = {
    "schema_version",
    "manifest_id",
    "source_commit",
    "source_sha256",
    "lock_sha256",
    "entries",
}
ENTRY_FIELDS = {
    "evidence_id",
    "claim_ids",
    "command",
    "tool",
    "source_commit",
    "source_sha256",
    "lock_sha256",
    "target",
    "features",
    "started_at",
    "ended_at",
    "result",
    "artifact",
    "limitations",
}
TOOL_FIELDS = {"name", "version"}
ARTIFACT_FIELDS = {"label", "sha256"}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
COMMIT_RE = re.compile(r"[0-9a-f]{40}")
MANIFEST_ID_RE = re.compile(r"EVID-MANIFEST-[A-Z0-9][A-Z0-9_-]{0,63}")
EVIDENCE_ID_RE = re.compile(r"EVID-[A-Z0-9][A-Z0-9_-]{2,127}")
CLAIM_ID_RE = re.compile(r"(?:S\d{2}-(?:\d{3}|900)|(?:ARCH|E2EE)-[A-Z0-9-]+)")
TARGET_RE = re.compile(r"[a-z0-9_]+-[a-z0-9_]+-[a-z0-9_.-]+")
FEATURE_RE = re.compile(r"[A-Za-z0-9_+.-]{1,128}")
TIMESTAMP_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z")


class EvidenceError(ValueError):
    """An evidence schema or manifest validation failure."""


def load_json(path: Path) -> dict[str, object]:
    """Load one JSON object with duplicate-key rejection."""
    def object_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in pairs:
            if key in result:
                raise EvidenceError(f"duplicate JSON key {key!r} in {path}")
            result[key] = value
        return result

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=object_pairs)
    except (OSError, json.JSONDecodeError) as error:
        raise EvidenceError(f"cannot read {path}: {error}") from error
    if not isinstance(value, dict):
        raise EvidenceError(f"{path} must contain one JSON object")
    return value


def load_toml(path: Path) -> dict[str, object]:
    """Load one TOML document."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise EvidenceError(f"cannot read {path}: {error}") from error


def validate_catalog(root: Path) -> dict[str, list[str]]:
    """Validate Stage-00 and normative requirement evidence bindings."""
    catalog = load_toml(root / CATALOG_PATH)
    if set(catalog) != {"schema_version", "evidence"} or catalog.get("schema_version") != 1:
        raise EvidenceError("evidence catalog has an invalid top-level schema")
    raw_entries = catalog.get("evidence")
    if not isinstance(raw_entries, list):
        raise EvidenceError("evidence catalog entries must be an array")

    stage_records: dict[str, tuple[list[str], str]] = {}
    for index, record in enumerate(raw_entries):
        if not isinstance(record, dict) or set(record) != {"id", "claim_ids", "kind"}:
            raise EvidenceError(f"catalog record {index} has invalid fields")
        evidence_id = record.get("id")
        claim_ids = record.get("claim_ids")
        kind = record.get("kind")
        if not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
            raise EvidenceError(f"catalog record {index} has an invalid evidence ID")
        if evidence_id in stage_records:
            raise EvidenceError(f"duplicate catalog evidence ID: {evidence_id}")
        if (
            not isinstance(claim_ids, list)
            or not claim_ids
            or any(not isinstance(claim, str) for claim in claim_ids)
        ):
            raise EvidenceError(f"catalog record {evidence_id} has invalid claims")
        if not isinstance(kind, str) or not kind:
            raise EvidenceError(f"catalog record {evidence_id} has an invalid kind")
        stage_records[evidence_id] = (claim_ids, kind)
    if stage_records != STAGE_BINDINGS:
        raise EvidenceError("Stage-00 evidence catalog is missing, stale, or differently bound")

    ledger = load_toml(root / LEDGER_PATH)
    raw_requirements = ledger.get("requirement")
    if not isinstance(raw_requirements, list):
        raise EvidenceError("requirement ledger has no requirement records")
    bindings = {evidence_id: claims for evidence_id, (claims, _kind) in stage_records.items()}
    for record in raw_requirements:
        if not isinstance(record, dict):
            raise EvidenceError("requirement ledger contains a non-table record")
        identifier = record.get("id")
        evidence_ids = record.get("evidence_ids")
        if not isinstance(identifier, str) or not isinstance(evidence_ids, list) or not evidence_ids:
            raise EvidenceError("requirement ledger contains an unbound record")
        for evidence_id in evidence_ids:
            if not isinstance(evidence_id, str) or EVIDENCE_ID_RE.fullmatch(evidence_id) is None:
                raise EvidenceError(f"requirement {identifier} has an invalid evidence ID")
            if evidence_id in bindings:
                raise EvidenceError(f"duplicate evidence binding: {evidence_id}")
            bindings[evidence_id] = [identifier]
    return bindings


def validate_schema(root: Path) -> None:
    """Ensure the published JSON Schema describes the enforced closed shape."""
    schema = load_json(root / SCHEMA_PATH)
    if schema.get("$schema") != "https://json-schema.org/draft/2020-12/schema":
        raise EvidenceError("evidence schema must use JSON Schema draft 2020-12")
    if schema.get("type") != "object" or schema.get("additionalProperties") is not False:
        raise EvidenceError("evidence schema top level must be a closed object")
    if set(schema.get("required", [])) != TOP_FIELDS:
        raise EvidenceError("evidence schema top-level required fields are stale")
    definitions = schema.get("$defs")
    if not isinstance(definitions, dict):
        raise EvidenceError("evidence schema has no definitions")
    evidence = definitions.get("evidence")
    if not isinstance(evidence, dict):
        raise EvidenceError("evidence schema has no evidence definition")
    if evidence.get("additionalProperties") is not False:
        raise EvidenceError("evidence entries must be closed objects")
    if set(evidence.get("required", [])) != ENTRY_FIELDS:
        raise EvidenceError("evidence schema entry required fields are stale")


def require_string(
    value: object,
    label: str,
    *,
    minimum: int = 1,
    maximum: int,
    pattern: re.Pattern[str] | None = None,
) -> str:
    """Validate and return one bounded string."""
    if not isinstance(value, str) or not minimum <= len(value) <= maximum:
        raise EvidenceError(f"{label} must be a string of {minimum}..{maximum} characters")
    if pattern is not None and pattern.fullmatch(value) is None:
        raise EvidenceError(f"{label} has an invalid format")
    return value


def parse_timestamp(value: object, label: str) -> datetime:
    """Parse one canonical UTC evidence timestamp."""
    text = require_string(value, label, maximum=40, pattern=TIMESTAMP_RE)
    try:
        parsed = datetime.fromisoformat(text[:-1] + "+00:00")
    except ValueError as error:
        raise EvidenceError(f"{label} is not a valid timestamp") from error
    if parsed.tzinfo != timezone.utc:
        raise EvidenceError(f"{label} must be UTC")
    return parsed


def validate_hash(value: object, label: str) -> str:
    """Validate one lowercase SHA-256 value."""
    return require_string(value, label, minimum=64, maximum=64, pattern=SHA256_RE)


def validate_manifest(manifest: dict[str, object], bindings: dict[str, list[str]]) -> None:
    """Validate one complete evidence manifest and all catalog bindings."""
    if set(manifest) != TOP_FIELDS:
        raise EvidenceError("manifest is missing required fields or has unknown fields")
    if manifest.get("schema_version") != 1:
        raise EvidenceError("manifest schema_version must be 1")
    require_string(manifest.get("manifest_id"), "manifest_id", maximum=78, pattern=MANIFEST_ID_RE)
    source_commit = require_string(
        manifest.get("source_commit"),
        "source_commit",
        minimum=40,
        maximum=40,
        pattern=COMMIT_RE,
    )
    source_hash = validate_hash(manifest.get("source_sha256"), "source_sha256")
    lock_hash = validate_hash(manifest.get("lock_sha256"), "lock_sha256")
    entries = manifest.get("entries")
    if not isinstance(entries, list) or not entries:
        raise EvidenceError("manifest entries must be a nonempty array")

    seen_evidence: set[str] = set()
    for index, raw_entry in enumerate(entries):
        label = f"entries[{index}]"
        if not isinstance(raw_entry, dict) or set(raw_entry) != ENTRY_FIELDS:
            raise EvidenceError(f"{label} is missing required fields or has unknown fields")
        entry = raw_entry
        evidence_id = require_string(
            entry.get("evidence_id"), f"{label}.evidence_id", maximum=132, pattern=EVIDENCE_ID_RE
        )
        if evidence_id in seen_evidence:
            raise EvidenceError(f"duplicate manifest evidence ID: {evidence_id}")
        seen_evidence.add(evidence_id)
        expected_claims = bindings.get(evidence_id)
        if expected_claims is None:
            raise EvidenceError(f"unbound evidence ID: {evidence_id}")

        claims = entry.get("claim_ids")
        if not isinstance(claims, list) or not claims:
            raise EvidenceError(f"{label}.claim_ids must be a nonempty array")
        if len(claims) != len(set(map(str, claims))):
            raise EvidenceError(f"{label}.claim_ids contains a duplicate")
        for claim in claims:
            require_string(claim, f"{label}.claim_ids", maximum=128, pattern=CLAIM_ID_RE)
        if claims != expected_claims:
            raise EvidenceError(f"{evidence_id} claims do not match its catalog binding")

        require_string(entry.get("command"), f"{label}.command", maximum=4096)
        tool = entry.get("tool")
        if not isinstance(tool, dict) or set(tool) != TOOL_FIELDS:
            raise EvidenceError(f"{label}.tool must contain only name and version")
        require_string(tool.get("name"), f"{label}.tool.name", maximum=128)
        require_string(tool.get("version"), f"{label}.tool.version", maximum=256)

        if entry.get("source_commit") != source_commit:
            raise EvidenceError(f"{label} has a stale source commit")
        entry_source_hash = validate_hash(entry.get("source_sha256"), f"{label}.source_sha256")
        if entry_source_hash != source_hash:
            raise EvidenceError(f"{label} has a stale source hash")
        entry_lock_hash = validate_hash(entry.get("lock_sha256"), f"{label}.lock_sha256")
        if entry_lock_hash != lock_hash:
            raise EvidenceError(f"{label} has a stale lock hash")
        require_string(entry.get("target"), f"{label}.target", maximum=128, pattern=TARGET_RE)

        features = entry.get("features")
        if not isinstance(features, list):
            raise EvidenceError(f"{label}.features must be an array")
        if features != sorted(features) or len(features) != len(set(map(str, features))):
            raise EvidenceError(f"{label}.features must be sorted and unique")
        for feature in features:
            require_string(feature, f"{label}.features", maximum=128, pattern=FEATURE_RE)

        started = parse_timestamp(entry.get("started_at"), f"{label}.started_at")
        ended = parse_timestamp(entry.get("ended_at"), f"{label}.ended_at")
        if ended < started:
            raise EvidenceError(f"{label} ended before it started")
        if entry.get("result") not in {"passed", "failed", "not-run"}:
            raise EvidenceError(f"{label}.result has an invalid value")

        artifact = entry.get("artifact")
        if not isinstance(artifact, dict) or set(artifact) != ARTIFACT_FIELDS:
            raise EvidenceError(f"{label}.artifact must contain only label and sha256")
        require_string(artifact.get("label"), f"{label}.artifact.label", maximum=256)
        validate_hash(artifact.get("sha256"), f"{label}.artifact.sha256")

        limitations = entry.get("limitations")
        if not isinstance(limitations, list) or len(limitations) > 64:
            raise EvidenceError(f"{label}.limitations must be an array of at most 64 items")
        for limitation in limitations:
            require_string(limitation, f"{label}.limitations", maximum=2048)


def validate(root: Path) -> tuple[int, int]:
    """Validate schema, catalogs, and the positive example."""
    validate_schema(root)
    bindings = validate_catalog(root)
    example = load_json(root / EXAMPLE_PATH)
    validate_manifest(example, bindings)
    return len(bindings), len(example["entries"])  # type: ignore[arg-type]


def expect_rejection(
    label: str,
    manifest: dict[str, object],
    bindings: dict[str, list[str]],
    fragment: str,
) -> None:
    """Require a malformed fixture to reach its intended rejection branch."""
    try:
        validate_manifest(manifest, bindings)
    except EvidenceError as error:
        if fragment not in str(error):
            raise EvidenceError(f"self-test {label!r} reached the wrong branch: {error}") from error
        return
    raise EvidenceError(f"self-test {label!r} was accepted")


def self_test(root: Path) -> int:
    """Exercise positive validation and every negative contract category."""
    validate_schema(root)
    bindings = validate_catalog(root)
    valid = load_json(root / EXAMPLE_PATH)
    validate_manifest(valid, bindings)
    cases = 0

    def reject(label: str, mutation: callable, fragment: str) -> None:  # type: ignore[valid-type]
        nonlocal cases
        malformed = copy.deepcopy(valid)
        mutation(malformed)
        expect_rejection(label, malformed, bindings, fragment)
        cases += 1

    reject("missing field", lambda value: value.pop("lock_sha256"), "missing required")
    reject(
        "duplicate evidence",
        lambda value: value["entries"].append(copy.deepcopy(value["entries"][0])),  # type: ignore[union-attr,index]
        "duplicate manifest evidence ID",
    )
    reject(
        "unbound evidence",
        lambda value: value["entries"][0].__setitem__("evidence_id", "EVID-UNKNOWN-GATE"),  # type: ignore[index,union-attr]
        "unbound evidence ID",
    )
    reject(
        "wrong claims",
        lambda value: value["entries"][0].__setitem__("claim_ids", ["S00-009"]),  # type: ignore[index,union-attr]
        "claims do not match",
    )
    reject(
        "duplicate claim",
        lambda value: value["entries"][0].__setitem__("claim_ids", ["S00-010", "S00-010"]),  # type: ignore[index,union-attr]
        "contains a duplicate",
    )
    reject(
        "stale commit",
        lambda value: value["entries"][0].__setitem__("source_commit", "1" * 40),  # type: ignore[index,union-attr]
        "stale source commit",
    )
    reject(
        "stale source",
        lambda value: value["entries"][0].__setitem__("source_sha256", "1" * 64),  # type: ignore[index,union-attr]
        "stale source hash",
    )
    reject(
        "stale lock",
        lambda value: value["entries"][0].__setitem__("lock_sha256", "1" * 64),  # type: ignore[index,union-attr]
        "stale lock hash",
    )
    reject(
        "bad target",
        lambda value: value["entries"][0].__setitem__("target", "linux"),  # type: ignore[index,union-attr]
        "target has an invalid format",
    )
    reject(
        "unsorted features",
        lambda value: value["entries"][0].__setitem__("features", ["z", "a"]),  # type: ignore[index,union-attr]
        "sorted and unique",
    )
    reject(
        "reverse time",
        lambda value: value["entries"][0].__setitem__("ended_at", "2026-08-23T23:59:59Z"),  # type: ignore[index,union-attr]
        "ended before",
    )
    reject(
        "bad result",
        lambda value: value["entries"][0].__setitem__("result", "unknown"),  # type: ignore[index,union-attr]
        "invalid value",
    )
    reject(
        "bad artifact hash",
        lambda value: value["entries"][0]["artifact"].__setitem__("sha256", "bad"),  # type: ignore[index,union-attr]
        "artifact.sha256 must be",
    )
    reject(
        "empty command",
        lambda value: value["entries"][0].__setitem__("command", ""),  # type: ignore[index,union-attr]
        "command must be",
    )
    reject(
        "empty limitation",
        lambda value: value["entries"][0].__setitem__("limitations", [""]),  # type: ignore[index,union-attr]
        "limitations must be",
    )
    return cases


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"evidence validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch positive validation and negative self-tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "check":
            bindings, entries = validate(root)
            print(f"evidence schema: ok ({bindings} bindings, {entries} example entry)")
        else:
            cases = self_test(root)
            print(f"evidence schema self-test: ok ({cases} rejection cases)")
    except (EvidenceError, OSError, UnicodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
