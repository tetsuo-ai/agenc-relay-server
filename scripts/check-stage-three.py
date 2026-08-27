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

EXPECTED_MODULES = {"command.rs", "decision.rs", "error.rs", "model.rs", "projection.rs"}
EXPECTED_TESTS = {
    "domain_channels.rs",
    "domain_commands.rs",
    "domain_lifecycle.rs",
    "domain_reference_model.rs",
    "domain_stage_three_matrix.rs",
}
EXPECTED_TASKS = tuple(f"S03-{number:03d}" for number in range(1, 13)) + ("S03-900",)
REQUIRED_REJECTIONS = {
    "duplicate-nickname": "Duplicate",
    "stale-channel-instance": "Stale",
    "role-escalation": "Forbidden",
    "stale-session-generation": "Stale",
    "federation-duplicate": "Stale",
    "federation-gap": "Gap",
    "stale-account-deletion": "Stale",
}
SCENARIO_FAMILIES = (
    "membership-role-mode",
    "nickname-reuse-recreation",
    "invite-account-switch",
    "account-deletion-federation",
)
VISIBILITIES = ("listed", "unlisted", "secret")
EXPECTED_SCENARIOS = tuple(
    (case, VISIBILITIES[case % len(VISIBILITIES)], SCENARIO_FAMILIES[case // 3])
    for case in range(12)
)
FORBIDDEN_DOMAIN_MARKERS = (
    "std::net",
    "std::fs",
    "std::time::SystemTime",
    "std::time::Instant",
    "tokio::",
    "getrandom",
    "rand::",
    "agenc_ircd_storage",
    "agenc_ircd_runtime",
    "agenc_ircd_crypto",
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
    source_root = root / "crates/agenc-ircd-domain/src"
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
        for path in (root / "crates/agenc-ircd-testkit/tests").glob("domain_*.rs")
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
    client = (root / "crates/agenc-ircd-client-wire/src/registration_command.rs").read_text(
        encoding="utf-8"
    )
    expected = {"NICK", "QUIT", *extract_post_registration_names(client)}
    domain = extract_command_match_names(
        (root / "crates/agenc-ircd-domain/src/command.rs").read_text(encoding="utf-8")
    )
    reference_path = root / "crates/agenc-ircd-testkit/src/domain_reference.rs"
    reference_source = reference_path.read_text(encoding="utf-8")
    reference = extract_command_match_names(reference_source)
    if domain != expected or reference != expected or len(expected) != 31:
        raise StageThreeError("domain/reference command coverage differs from the frozen registry")
    forbidden = ("agenc_ircd_domain", "DomainState", "CanonicalCommand", "MutationPlan")
    if any(marker in reference_source for marker in forbidden):
        raise StageThreeError("reference model calls or embeds production domain transitions")


def validate_generated_summary(document: dict[str, object]) -> None:
    """Validate task bindings and the finite generated-case dimensions."""
    if document.get("schema_version") != 1:
        raise StageThreeError("Stage-03 generated schema version is invalid")
    if document.get("generated_cases") != 12 or document.get("rejection_cases") != 7:
        raise StageThreeError("Stage-03 generated case counts are stale")
    tasks = document.get("task")
    if not isinstance(tasks, list):
        raise StageThreeError("Stage-03 generated task list is absent")
    task_ids = tuple(record.get("id") for record in tasks if isinstance(record, dict))
    if task_ids != EXPECTED_TASKS:
        raise StageThreeError("Stage-03 generated task order or coverage is stale")
    scenarios = document.get("scenario")
    if not isinstance(scenarios, list):
        raise StageThreeError("Stage-03 generated scenario list is absent")
    actual_scenarios = tuple(
        (
            record.get("case"),
            record.get("visibility"),
            record.get("name"),
        )
        for record in scenarios
        if isinstance(record, dict)
    )
    expected_scenarios = tuple(
        (case, visibility, f"{visibility}-{family}")
        for case, visibility, family in EXPECTED_SCENARIOS
    )
    if actual_scenarios != expected_scenarios:
        raise StageThreeError("Stage-03 generated scenarios are stale")
    rejections = document.get("rejection")
    if not isinstance(rejections, list):
        raise StageThreeError("Stage-03 generated rejection list is absent")
    actual = {
        str(record.get("name")): str(record.get("error"))
        for record in rejections
        if isinstance(record, dict) and record.get("unchanged") is True
    }
    if actual != REQUIRED_REJECTIONS:
        raise StageThreeError("Stage-03 rejection matrix is incomplete")


def validate_sequence_fixture(path: Path) -> None:
    """Validate canonical records and complete visibility/rejection coverage."""
    cases: list[tuple[int, str, str]] = []
    rejections: dict[str, str] = {}
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 4:
            raise StageThreeError(f"generated sequence line {line_number} is malformed")
        kind, identity, outcome, scenario = fields
        if kind == "CASE":
            try:
                cases.append((int(identity), outcome, scenario))
            except ValueError as error:
                raise StageThreeError("generated case identity is not decimal") from error
        elif kind == "REJECT" and scenario == "state-unchanged":
            rejections[identity] = outcome
        else:
            raise StageThreeError(f"generated sequence line {line_number} has unknown shape")
    expected_cases = [
        (case, visibility, f"{visibility}-{family}")
        for case, visibility, family in EXPECTED_SCENARIOS
    ]
    if cases != expected_cases or rejections != REQUIRED_REJECTIONS:
        raise StageThreeError("generated sequence coverage is stale")


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
    """Require every Stage-03 task to be checked only with complete gate evidence."""
    source = (root / "TODO.md").read_text(encoding="utf-8")
    for task in EXPECTED_TASKS:
        if re.search(rf"^- \[x\] `{task}`", source, flags=re.MULTILINE) is None:
            raise StageThreeError(f"roadmap task is not complete: {task}")


def validate(root: Path) -> None:
    """Validate every independent Stage-03 conformance surface."""
    validate_domain_boundary(root)
    validate_command_coverage(root)
    validate_generated_summary(load_toml(root / "conformance/generated-stage-three.toml"))
    validate_sequence_fixture(root / "test-data/property/domain-stage-three-v1.steps")
    validate_roadmap(root)
    check_generator(root)


def self_test(root: Path) -> int:
    """Prove malformed generated metadata is rejected without filesystem mutation."""
    valid = load_toml(root / "conformance/generated-stage-three.toml")
    malformed = copy.deepcopy(valid)
    malformed["generated_cases"] = 11
    try:
        validate_generated_summary(malformed)
    except StageThreeError:
        pass
    else:
        raise StageThreeError("self-test accepted a stale generated case count")
    malformed = copy.deepcopy(valid)
    tasks = malformed.get("task")
    if not isinstance(tasks, list) or not tasks:
        raise StageThreeError("self-test fixture has no tasks")
    tasks.pop()
    try:
        validate_generated_summary(malformed)
    except StageThreeError:
        return 2
    raise StageThreeError("self-test accepted an incomplete task vector")


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
