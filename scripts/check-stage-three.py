#!/usr/bin/env python3
"""Validate Stage-03 domain boundaries, generated cases, and reference independence."""

from __future__ import annotations

import argparse
import copy
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

EXPECTED_MODULES = {
    "command.rs",
    "decision.rs",
    "error.rs",
    "history.rs",
    "model.rs",
    "persist.rs",
    "projection.rs",
}
EXPECTED_TESTS = {
    "domain_channels.rs",
    "domain_commands.rs",
    "domain_lifecycle.rs",
    "domain_reference_model.rs",
    "domain_secret_admission.rs",
    "domain_stage_three_matrix.rs",
}
EXPECTED_TASKS = tuple(f"S03-{number:03d}" for number in range(1, 13)) + ("S03-900",)
IMPLEMENTATION_TASKS = EXPECTED_TASKS[:-1]
SCHEMA_VERSION = 2
GENERATOR_VERSION = 2
SEED_COUNT = 256
MAX_STEPS = 64
SEED_BASE = 0xA63C_0300_0000_0001
SEED_STRIDE = 0x9E37_79B9_7F4A_7C15
REGRESSIONS = (
    ("invite-metadata-parity", 0, 16, 0x28E9_87FA_8CC9_23A5),
    ("account-delete-multi-session", 0, 26, 0x1F32_FDCF_E748_A2EC),
)
REQUIRED_MODEL_TEST_MARKERS = (
    "seeded_valid_and_invalid_sequences_match_complete_snapshots",
    "reference.validate_invariants()",
    "ReferenceDomainStep::ApplyModeVector",
    "ReferenceModeOperation::Remove",
    "creation_revision: invite.creation_revision",
    "expires_at: invite.expires_at",
    "minimal_failing_prefix",
    "promotion_record=REGRESSION|",
    "if after.production != after.reference",
)
FORBIDDEN_DOMAIN_MARKERS = (
    "std::net",
    "std::fs",
    "std::time::SystemTime",
    "std::time::Instant",
    "tokio::",
    "getrandom",
    "rand::",
    "agenc_relay_storage",
    "agenc_relay_runtime",
    "agenc_relay_crypto",
)
REQUIRED_SURFACES = (
    "pub struct DomainState",
    "pub struct CanonicalCommand",
    "pub struct AuthorizedCommand",
    "pub struct MutationPlan",
    "pub enum ExternalInputRequest",
    "pub enum ProjectionDecision",
    "plan_session_account_switch",
    "plan_account_deleted",
    "plan_sanction",
    "apply_prepared",
)


class StageThreeError(ValueError):
    """A Stage-03 conformance failure."""


def load_toml(path: Path) -> dict[str, object]:
    """Load one TOML document with a bounded diagnostic."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StageThreeError(f"cannot read {path}: {error}") from error


def validate_domain_boundary(root: Path) -> None:
    """Require the complete pure-domain module set and forbidden-import boundary."""
    source_root = root / "crates/agenc-relay-domain/src"
    modules = {path.name for path in source_root.glob("*.rs") if path.name != "lib.rs"}
    if modules != EXPECTED_MODULES:
        raise StageThreeError("domain module set is missing or unexpected")
    sources = [path.read_text(encoding="utf-8") for path in source_root.glob("*.rs")]
    combined = "\n".join(sources)
    if any(marker in combined for marker in FORBIDDEN_DOMAIN_MARKERS):
        raise StageThreeError("domain crossed its pure clock, entropy, I/O, or crate boundary")
    if any(surface not in combined for surface in REQUIRED_SURFACES):
        raise StageThreeError("domain is missing a required Stage-03 surface")
    tests = {
        path.name
        for path in (root / "crates/agenc-relay-testkit/tests").glob("domain_*.rs")
    }
    if tests != EXPECTED_TESTS:
        raise StageThreeError("Stage-03 integration-test set is missing or unexpected")


def extract_post_registration_names(source: str) -> list[str]:
    """Extract the frozen post-registration command vector."""
    match = re.search(
        r"pub const POST_REGISTRATION_COMMANDS: &\[&str\] = &\[(.*?)\];",
        source,
        flags=re.DOTALL,
    )
    if match is None:
        raise StageThreeError("post-registration command registry is absent")
    return re.findall(r'"([A-Z]+)"', match.group(1))


def extract_command_match_names(source: str) -> set[str]:
    """Extract exact command spellings from one closed match table."""
    return set(re.findall(r'^\s*"([A-Z]+)"\s*=>\s*Ok\(Self::', source, flags=re.MULTILINE))


def validate_command_coverage(root: Path) -> None:
    """Prove production and independent models cover the same frozen registry."""
    client = (root / "crates/agenc-relay-client-wire/src/registration_command.rs").read_text(
        encoding="utf-8"
    )
    expected = {"NICK", "QUIT", *extract_post_registration_names(client)}
    domain = extract_command_match_names(
        (root / "crates/agenc-relay-domain/src/command.rs").read_text(encoding="utf-8")
    )
    reference_path = root / "crates/agenc-relay-testkit/src/domain_reference.rs"
    reference_source = reference_path.read_text(encoding="utf-8")
    reference = extract_command_match_names(reference_source)
    if domain != expected or reference != expected or len(expected) != 31:
        raise StageThreeError("domain/reference command coverage differs from the frozen registry")
    forbidden = ("agenc_relay_domain", "DomainState", "CanonicalCommand", "MutationPlan")
    if any(marker in reference_source for marker in forbidden):
        raise StageThreeError("reference model calls or embeds production domain transitions")


def seed_at(index: int) -> int:
    """Return one wrapped 64-bit seed from the reviewed arithmetic range."""
    return (SEED_BASE + SEED_STRIDE * index) & ((1 << 64) - 1)


def expected_regressions() -> tuple[tuple[str, int, int, int], ...]:
    """Return the exact retained replay-prefix records."""
    return tuple(
        (name, seed_at(index), steps, fingerprint)
        for name, index, steps, fingerprint in REGRESSIONS
    )


def validate_generated_summary(document: dict[str, object]) -> None:
    """Validate task bindings and executable sequence-test bounds."""
    if document.get("schema_version") != SCHEMA_VERSION:
        raise StageThreeError("Stage-03 generated schema version is invalid")
    expected_scalars = {
        "generator_version": GENERATOR_VERSION,
        "seed_count": SEED_COUNT,
        "max_steps": MAX_STEPS,
        "minimum_step_checks": SEED_COUNT * MAX_STEPS,
        "snapshot_cadence": "after-every-step",
        "rejection_atomicity": "both-models",
        "failure_shrink": "minimal-failing-prefix",
        "regression_count": len(REGRESSIONS),
        "seed_base": SEED_BASE,
        "seed_stride": SEED_STRIDE,
    }
    if any(document.get(name) != value for name, value in expected_scalars.items()):
        raise StageThreeError("Stage-03 generated model-test bounds are stale")
    tasks = document.get("task")
    if not isinstance(tasks, list):
        raise StageThreeError("Stage-03 generated task list is absent")
    task_ids = tuple(record.get("id") for record in tasks if isinstance(record, dict))
    if task_ids != EXPECTED_TASKS:
        raise StageThreeError("Stage-03 generated task order or coverage is stale")
    regressions = document.get("regression")
    if not isinstance(regressions, list):
        raise StageThreeError("Stage-03 retained regression list is absent")
    actual = tuple(
        (
            record.get("name"),
            record.get("seed"),
            record.get("steps"),
            record.get("fingerprint"),
        )
        for record in regressions
        if isinstance(record, dict)
    )
    if actual != expected_regressions():
        raise StageThreeError("Stage-03 retained regression prefixes are stale")


def validate_sequence_fixture(path: Path) -> None:
    """Validate the seed range, execution bounds, and replay prefixes."""
    config: dict[str, str] = {}
    seed_range: tuple[int, int, int] | None = None
    regressions: list[tuple[str, int, int, int]] = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if fields[:1] == ["CONFIG"] and len(fields) == 3:
            _, name, value = fields
            if name in config:
                raise StageThreeError("generated sequence config key is duplicated")
            config[name] = value
        elif fields[:1] == ["SEED-RANGE"] and len(fields) == 4:
            if seed_range is not None:
                raise StageThreeError("generated sequence has multiple seed ranges")
            try:
                seed_range = (int(fields[1], 0), int(fields[2], 0), int(fields[3]))
            except ValueError as error:
                raise StageThreeError("generated seed range is malformed") from error
        elif fields[:1] == ["REGRESSION"] and len(fields) == 5:
            try:
                regressions.append(
                    (fields[1], int(fields[2], 0), int(fields[3]), int(fields[4], 0))
                )
            except ValueError as error:
                raise StageThreeError("generated regression prefix is malformed") from error
        else:
            raise StageThreeError(f"generated sequence line {line_number} has unknown shape")
    expected_config = {
        "schema-version": str(SCHEMA_VERSION),
        "generator-version": str(GENERATOR_VERSION),
        "seed-count": str(SEED_COUNT),
        "max-steps": str(MAX_STEPS),
        "snapshot-cadence": "after-every-step",
    }
    if config != expected_config:
        raise StageThreeError("generated sequence execution config is stale")
    if seed_range != (SEED_BASE, SEED_STRIDE, SEED_COUNT):
        raise StageThreeError("generated sequence seed range is stale")
    if tuple(regressions) != expected_regressions():
        raise StageThreeError("generated sequence regression prefixes are stale")


def validate_model_test_source(root: Path) -> None:
    """Require the Rust test to execute both models at every generated step."""
    source = (
        root / "crates/agenc-relay-testkit/tests/domain_reference_model.rs"
    ).read_text(encoding="utf-8")
    missing = [marker for marker in REQUIRED_MODEL_TEST_MARKERS if marker not in source]
    if missing:
        raise StageThreeError("Stage-03 executable model-test proof is incomplete")


def check_generator(root: Path) -> None:
    """Run the Stage-03 generator's nonmutating comparison."""
    completed = subprocess.run(
        ["python3", "scripts/generate-stage-three.py", "--check"],
        cwd=root,
        check=False,
        capture_output=True,
        text=True,
    )
    if completed.returncode != 0:
        raise StageThreeError(completed.stderr.strip() or completed.stdout.strip())


def validate_roadmap(root: Path) -> None:
    """Require each Stage-03 implementation task to be checked."""
    source = (root / "TODO.md").read_text(encoding="utf-8")
    for task in IMPLEMENTATION_TASKS:
        if re.search(rf"^- \[x\] `{task}`", source, flags=re.MULTILINE) is None:
            raise StageThreeError(f"roadmap task is not complete: {task}")


def validate(root: Path) -> None:
    """Validate every independent Stage-03 conformance surface."""
    validate_domain_boundary(root)
    validate_command_coverage(root)
    validate_generated_summary(load_toml(root / "conformance/generated-stage-three.toml"))
    validate_sequence_fixture(root / "test-data/property/domain-stage-three-v1.steps")
    validate_model_test_source(root)
    validate_roadmap(root)
    check_generator(root)


def self_test(root: Path) -> int:
    """Prove malformed generated metadata is rejected without filesystem mutation."""
    valid = load_toml(root / "conformance/generated-stage-three.toml")
    malformed = copy.deepcopy(valid)
    malformed["seed_count"] = SEED_COUNT - 1
    try:
        validate_generated_summary(malformed)
    except StageThreeError:
        pass
    else:
        raise StageThreeError("self-test accepted a stale seed count")
    malformed = copy.deepcopy(valid)
    regressions = malformed.get("regression")
    if not isinstance(regressions, list) or not regressions:
        raise StageThreeError("self-test fixture has no regression prefixes")
    regressions.pop()
    try:
        validate_generated_summary(malformed)
    except StageThreeError:
        pass
    else:
        raise StageThreeError("self-test accepted an incomplete regression vector")
    malformed = copy.deepcopy(valid)
    regressions = malformed.get("regression")
    if not isinstance(regressions, list) or not regressions:
        raise StageThreeError("self-test fixture has no regression fingerprints")
    fingerprint = regressions[0].get("fingerprint")
    if not isinstance(fingerprint, int):
        raise StageThreeError("self-test fixture has no numeric regression fingerprint")
    regressions[0]["fingerprint"] = fingerprint ^ 1
    try:
        validate_generated_summary(malformed)
    except StageThreeError:
        return 3
    raise StageThreeError("self-test accepted a stale regression fingerprint")


def fail(message: str) -> NoReturn:
    """Print one stable failure and exit unsuccessfully."""
    print(f"Stage-03 conformance failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch validation and negative self-test commands."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "check":
            validate(root)
            print("Stage-03 conformance: ok")
        else:
            cases = self_test(root)
            print(f"Stage-03 conformance self-test: ok ({cases} rejection cases)")
    except (OSError, UnicodeError, StageThreeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
