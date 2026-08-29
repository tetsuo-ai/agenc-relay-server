#!/usr/bin/env python3
"""Independently validate Stage-02 wire surfaces, fixtures, and fuzz policy."""

from __future__ import annotations

import argparse
import copy
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

EXPECTED_BUDGETS = {
    "stream": {
        "traditional_with_crlf": 512,
        "command_without_crlf": 8701,
        "client_tag_data": 4094,
        "server_tag_data": 4094,
        "combined_tag_section": 8191,
        "physical_with_crlf": 8703,
    },
    "websocket": {"command_without_crlf": 8701, "message_without_crlf": 8701},
    "tags": {
        "client_only_count": 16,
        "ordinary_value_decoded": 256,
        "ordinary_total_decoded": 1024,
    },
    "registration": {
        "pending_messages": 16,
        "pending_bytes": 32768,
        "registration_millis": 30000,
        "keepalive_idle_millis": 120000,
        "keepalive_pong_millis": 30000,
    },
    "account_carriers": {
        "request_bytes": 4726,
        "response_bytes": 4342,
        "sasl_request_characters": 6304,
        "sasl_response_characters": 5792,
        "account_request_characters": 6302,
        "account_response_characters": 5790,
    },
    "replies": {"batch_nesting": 16},
}
EXPECTED_FUZZ_TARGETS = ("tcp_framing", "websocket", "parse_render", "client_state")
EXPECTED_LATER_FUZZ_TARGETS = (
    "account_service_envelope",
    "crypto_wrappers",
    "storage_codecs",
    "backup_stream",
)
EXPECTED_FUZZ_POLICY = {
    "schema_version": 1,
    "nightly": "nightly-2026-08-24",
    "rustc": "rustc 1.100.0-nightly (fb6531d55 2026-08-23)",
    "cargo_fuzz_version": "0.13.2",
    "cargo_fuzz_checksum": "5acfd01930e49823e58c30dd8012d3338a620377d7c7d4cc140ca4b2169400e2",
    "libfuzzer_sys_version": "0.4.13",
    "libfuzzer_sys_checksum": "a9fd2f41a1cba099f79a0b6b6c35656cf7c03351a7bae8ff0f28f25270f929d2",
    "native_build_license": "NCSA",
    "full_campaign_task": "S10-004",
}
EXPECTED_FUZZ_SMOKE = {
    "schema_version": 1,
    "evidence_id": "EVID-S02-011-FUZZ",
    "toolchain": "nightly-2026-08-24",
    "cargo_fuzz": "0.13.2",
    "seed": 20260824,
    "runs_per_target": 10000,
    "max_len": 32768,
    "timeout_seconds": 2,
    "rss_limit_mb": 512,
    "executed_on": "2026-08-26",
    "result": "pass",
    "targets": list(EXPECTED_FUZZ_TARGETS),
    "limitations": "The 24 CPU-hour parser campaign remains S10-004 release evidence.",
}
EXPECTED_MODULES = {
    "auth_transport.rs",
    "capability.rs",
    "framing.rs",
    "limits.rs",
    "message.rs",
    "registration.rs",
    "registration_command.rs",
    "render.rs",
    "tags.rs",
    "text.rs",
    "websocket.rs",
}
REQUIRED_CAPABILITIES = {
    "cap-notify",
    "standard-replies",
    "agenc.ag/privacy",
    "sts",
    "agenc.ag/account-create",
}
EVIDENCE_RE = re.compile(r"EVID-S02-[A-Z0-9-]+")


class StageTwoError(ValueError):
    """A Stage-02 conformance failure."""


def load_toml(path: Path) -> dict[str, object]:
    """Load one TOML document with a bounded diagnostic."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StageTwoError(f"cannot read {path}: {error}") from error


def validate_budgets(document: dict[str, object]) -> None:
    """Validate the exact independently reviewed wire-budget table."""
    if document.get("schema_version") != 1 or document.get("evidence_id") != "EVID-S02-008-RENDER":
        raise StageTwoError("wire-budget header is invalid")
    actual = {key: value for key, value in document.items() if key not in {"schema_version", "evidence_id"}}
    if actual != EXPECTED_BUDGETS:
        raise StageTwoError("wire budgets differ from the reviewed exact values")


def validate_capabilities(root: Path) -> None:
    """Require bare, unique generated capability names and mandatory entries."""
    source = (root / "crates/agenc-ircd-types/src/generated_registry.rs").read_text(encoding="utf-8")
    match = re.search(r"pub const CAPABILITIES: &\[&str\] = &\[(.*?)\];", source, re.DOTALL)
    if match is None:
        raise StageTwoError("generated capability registry is absent")
    capabilities = re.findall(r'"([^"]+)"', match.group(1))
    if len(capabilities) != len(set(capabilities)) or any("=" in value for value in capabilities):
        raise StageTwoError("capability registry contains duplicates or value-bearing names")
    if not REQUIRED_CAPABILITIES.issubset(capabilities):
        raise StageTwoError("capability registry omits a mandatory Stage-02 name")


def validate_modules(root: Path) -> None:
    """Validate the complete pure wire module boundary and forbidden imports."""
    source_root = root / "crates/agenc-ircd-client-wire/src"
    modules = {path.name for path in source_root.glob("*.rs") if path.name != "lib.rs"}
    if modules != EXPECTED_MODULES:
        raise StageTwoError("client-wire module set is missing or unexpected")
    combined = "\n".join(path.read_text(encoding="utf-8") for path in source_root.glob("*.rs"))
    forbidden = ("std::net", "tokio::net", "agenc_ircd_runtime", "agenc_ircd_auth", "opaque_ke", "hpke::")
    if any(marker in combined for marker in forbidden):
        raise StageTwoError("client-wire crossed its socket, runtime, or crypto boundary")
    required = ("StreamFramer", "WebSocketWire", "ParsedMessage", "CapabilityState", "RegistrationState", "SaslTransport", "AccountTransfer", "MeasuredMessage", "BatchStack")
    if any(marker not in combined for marker in required):
        raise StageTwoError("client-wire is missing a required Stage-02 surface")


def validate_corrected_semantics(root: Path) -> None:
    """Pin security-relevant Stage-02 behavior that broad surface checks miss."""
    wire_root = root / "crates/agenc-ircd-client-wire"
    capability = (wire_root / "src/capability.rs").read_text(encoding="utf-8")
    registration = (wire_root / "src/registration.rs").read_text(encoding="utf-8")
    grammar = (wire_root / "src/registration_command.rs").read_text(encoding="utf-8")
    auth = (wire_root / "src/auth_transport.rs").read_text(encoding="utf-8")
    render = (wire_root / "src/render.rs").read_text(encoding="utf-8")
    transcript = (
        root / "crates/agenc-ircd-testkit/src/client_transcript.rs"
    ).read_text(encoding="utf-8")

    obsolete_dependency = (
        '"account-tag" | "server-time" | "message-ids" | "batch"'
        ' => &["message-tags"]'
    )
    required_dependencies = (
        '"labeled-response" => &["batch"]',
        '"extended-join" => &["account-notify"]',
        '"draft/chathistory" => &["batch", "server-time", "message-ids"]',
    )
    if obsolete_dependency in capability or any(
        dependency not in capability for dependency in required_dependencies
    ):
        raise StageTwoError("capability dependency graph differs from Appendix A.3")

    multiline_markers = (
        "ensure_enabled_list_renderable(&projected, self.version_302)",
        "multiline: self.cap.supports_multiline()",
        'queue_capability_tokens(&target, "LIST", multiline, &tokens)',
        "if !multiline",
    )
    if any(
        marker not in capability + registration + transcript
        for marker in multiline_markers
    ):
        raise StageTwoError("CAP 302 LIST continuation behavior is not enforced")
    if "pub const MAX_BATCH_NESTING: usize = 16;" not in render:
        raise StageTwoError("batch nesting hard maximum is not 16")
    if not re.search(
        r"fn cap_end_message\([^)]*\).*?"
        r"self\.phase == RegistrationPhase::Registered.*?return Ok\(Vec::new\(\)\)",
        registration,
        re.DOTALL,
    ):
        raise StageTwoError("registered CAP END is not ignored")
    if (
        "SaslAction::Numeric(SaslNumeric::TooLong)" not in auth
        or not re.search(
            r"token\.len\(\) > AUTH_CHUNK_CHARACTERS\s*\{\s*"
            r"return Ok\(RegistrationCommand::Authenticate\)",
            grammar,
        )
    ):
        raise StageTwoError("oversized AUTHENTICATE cannot reach numeric 905")
    if "impl fmt::Debug for SecretBytes" in registration or "impl fmt::Debug for SecretText" in auth:
        raise StageTwoError("secret-bearing client-wire types implement Debug")


def validate_fixture(path: Path, known_evidence: set[str]) -> int:
    """Validate one four-field ASCII/hex transcript or vector fixture."""
    count = 0
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line or line.startswith("#"):
            continue
        fields = line.split("|")
        if len(fields) != 4:
            raise StageTwoError(f"{path.name}:{line_number} is not one four-field record")
        evidence, _surface, encoding, payload = fields
        if evidence not in known_evidence or EVIDENCE_RE.fullmatch(evidence) is None:
            raise StageTwoError(f"{path.name}:{line_number} has an unbound evidence ID")
        if encoding not in {"ascii", "hex"}:
            raise StageTwoError(f"{path.name}:{line_number} has an unknown encoding")
        if encoding == "hex" and (len(payload) % 2 or re.fullmatch(r"[0-9a-f]*", payload) is None):
            raise StageTwoError(f"{path.name}:{line_number} has noncanonical hex")
        if encoding == "ascii" and (not payload.isascii() or any(character in payload for character in "\r\n")):
            raise StageTwoError(f"{path.name}:{line_number} has invalid ASCII")
        count += 1
    if count == 0:
        raise StageTwoError(f"{path.name} has no fixture records")
    return count


def validate_fuzz(root: Path) -> None:
    """Validate the isolated pinned fuzz workspace and seed coverage."""
    manifest = load_toml(root / "fuzz/Cargo.toml")
    binaries = manifest.get("bin")
    if not isinstance(binaries, list):
        raise StageTwoError("fuzz manifest has no binary targets")
    names = tuple(record.get("name") for record in binaries if isinstance(record, dict))
    if names != EXPECTED_FUZZ_TARGETS + EXPECTED_LATER_FUZZ_TARGETS or manifest.get(
        "workspace"
    ) != {"members": ["."]}:
        raise StageTwoError("fuzz workspace target set or isolation is invalid")
    policy = load_toml(root / "fuzz/toolchain-policy.toml")
    validate_fuzz_policy(policy)
    lock = load_toml(root / "fuzz/Cargo.lock")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise StageTwoError("fuzz lockfile has no packages")
    libfuzzer = next((item for item in packages if isinstance(item, dict) and item.get("name") == "libfuzzer-sys"), None)
    if not isinstance(libfuzzer, dict) or libfuzzer.get("version") != "0.4.13" or libfuzzer.get("checksum") != EXPECTED_FUZZ_POLICY["libfuzzer_sys_checksum"]:
        raise StageTwoError("libfuzzer-sys lock pin or checksum is invalid")
    for target in EXPECTED_FUZZ_TARGETS:
        source = root / f"fuzz/fuzz_targets/{target}.rs"
        corpus = root / f"test-data/fuzz-corpus/client-wire/{target}"
        if not source.is_file() or "#![forbid(unsafe_code)]" not in source.read_text(encoding="utf-8"):
            raise StageTwoError(f"fuzz target is missing safe-Rust policy: {target}")
        if "data.len() > 32_768" not in source.read_text(encoding="utf-8"):
            raise StageTwoError(f"fuzz target does not admit the recorded input ceiling: {target}")
        if not corpus.is_dir() or not any(path.is_file() for path in corpus.iterdir()):
            raise StageTwoError(f"fuzz target has no seed corpus: {target}")
    state_source = (root / "fuzz/fuzz_targets/client_state.rs").read_text(encoding="utf-8")
    structured_seeds = sorted(
        (root / "test-data/fuzz-corpus/client-wire/client_state").glob("post-*")
    )
    if "validate_post_registration_command" not in state_source or len(structured_seeds) != 29:
        raise StageTwoError("client-state fuzzing omits a structured Appendix-A command family")
    smoke = load_toml(root / "conformance/stage-two-fuzz-smoke.toml")
    validate_fuzz_smoke(smoke)


def validate_fuzz_policy(document: dict[str, object]) -> None:
    """Require every reviewed fuzz toolchain field and checksum."""
    if document != EXPECTED_FUZZ_POLICY:
        raise StageTwoError("fuzz toolchain policy differs from its reviewed pins")


def validate_fuzz_smoke(document: dict[str, object]) -> None:
    """Require the complete checked-in deterministic smoke-run record."""
    if document != EXPECTED_FUZZ_SMOKE:
        raise StageTwoError("fuzz smoke record is missing, stale, or failed")


def check_generator(root: Path) -> None:
    """Run the Stage-02 generator's nonmutating comparison."""
    completed = subprocess.run(
        ["python3", "scripts/generate-stage-two.py", "--check"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        raise StageTwoError("Stage-02 generated surface is stale")


def validate(root: Path) -> tuple[int, int]:
    """Run the complete independent Stage-02 artifact check."""
    budgets = load_toml(root / "test-data/vectors/client-wire-budgets.toml")
    validate_budgets(budgets)
    validate_capabilities(root)
    validate_modules(root)
    validate_corrected_semantics(root)
    catalog = load_toml(root / "conformance/evidence-catalog.toml")
    records = catalog.get("evidence")
    if not isinstance(records, list):
        raise StageTwoError("evidence catalog has no entries")
    known = {record.get("id") for record in records if isinstance(record, dict) and isinstance(record.get("id"), str)}
    transcript_count = validate_fixture(root / "test-data/transcripts/client-registration-v1.transcript", known)
    vector_count = validate_fixture(root / "test-data/vectors/client-wire-v1.vectors", known)
    validate_fuzz(root)
    check_generator(root)
    return transcript_count, vector_count


def expect_failure(label: str, action: object) -> None:
    """Require one seeded malformed fixture to be rejected."""
    if not callable(action):
        raise StageTwoError(f"self-test {label} is not callable")
    try:
        action()
    except StageTwoError:
        return
    raise StageTwoError(f"self-test accepted malformed {label}")


def self_test(root: Path) -> int:
    """Exercise exact budget, capability, fixture, and fuzz-pin rejection."""
    budgets = load_toml(root / "test-data/vectors/client-wire-budgets.toml")
    changed = copy.deepcopy(budgets)
    changed["stream"]["physical_with_crlf"] = 8704
    expect_failure("wire budget", lambda: validate_budgets(changed))
    catalog = load_toml(root / "conformance/evidence-catalog.toml")
    records = catalog.get("evidence", [])
    known = {record.get("id") for record in records if isinstance(record, dict)}
    malformed = root / "test-data/vectors/client-wire-v1.vectors"
    original = malformed.read_text(encoding="utf-8")
    temporary = root / "target/stage-two-malformed.fixture"
    temporary.parent.mkdir(parents=True, exist_ok=True)
    temporary.write_text(original.replace("|hex|0d0a", "|hex|0d0", 1), encoding="utf-8")
    expect_failure("fixture hex", lambda: validate_fixture(temporary, known))
    policy = load_toml(root / "fuzz/toolchain-policy.toml")
    changed_policy = copy.deepcopy(policy)
    changed_policy["cargo_fuzz_version"] = "0.13.3"
    expect_failure("fuzz pin", lambda: validate_fuzz_policy(changed_policy))
    smoke = load_toml(root / "conformance/stage-two-fuzz-smoke.toml")
    changed_smoke = copy.deepcopy(smoke)
    changed_smoke["runs_per_target"] = 9999
    expect_failure("fuzz smoke", lambda: validate_fuzz_smoke(changed_smoke))
    return 4


def fail(message: str) -> NoReturn:
    """Print one stable failure and exit unsuccessfully."""
    print(f"Stage-02 check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch the Stage-02 check or malformed-fixture self-test."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "check":
            transcripts, vectors = validate(root)
            print(f"Stage-02 artifacts: ok ({transcripts} transcript steps, {vectors} vectors)")
        else:
            cases = self_test(root)
            print(f"Stage-02 artifact self-test: ok ({cases} rejection cases)")
    except (OSError, UnicodeError, StageTwoError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
