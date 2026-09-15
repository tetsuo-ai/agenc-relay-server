#!/usr/bin/env python3
"""Independently validate Stage-01 sources, generated artifacts, and vectors."""

from __future__ import annotations

import base64
import hashlib
import re
import subprocess
import sys
from pathlib import Path
from typing import NoReturn

RAW_HASHES = {
    "docs/ircd-architecture-and-implementation-spec.md": (
        "f542c23cab2724a88476d4650a501043bc367c71c66d45dfac676362f1fb0958"
    ),
    "docs/irc-mls-e2ee-extension.md": (
        "0620b993c63529dca24cc7b2e54eba158ebdf5401ecf54dc081ded73501a76f6"
    ),
    "docs/federation-v1-profile.registry": (
        "1b94cb7b43dc458ff683ddcfd86eed1939128a7a6d0229b89342bd6816eb5411"
    ),
    "docs/protocol-sources-and-decisions.md": (
        "a55a3fbbe929b601726097967152af672f90569ab4daefdd26dc6d65d3c75f7c"
    ),
}
PROFILE_HASHES = {
    "base-federation-v1": (
        "7b00e0d0844270626411d398f15f7520224ea906117738e3da9741a611dc67b3"
    ),
    "e2ee-mls-v1": (
        "618080b4c92aa6b92196ce823369e5c0dd36b4916049670fd82bdabb09f78f07"
    ),
}
PROFILE_LABELS = {
    "base-federation-v1": b"agenc-chat base federation profile registry v1\0",
    "e2ee-mls-v1": b"agenc-chat IRC-MLS specification profile v1\0",
}
CATEGORY_COUNTS = {
    "constant": 62,
    "crypto": 4,
    "enum": 29,
    "hash": 6,
    "mapping": 33,
    "mode": 18,
    "order": 15,
    "schema": 132,
    "wire": 23,
}
UNION_ARMS = {
    "session": (1, "FederationSessionProjection"),
    "channel_detail": (3, "FederationChannelDetail"),
    "account": (7, "FederationAccountProjection"),
}
VECTOR_PATH = "test-data/vectors/base-federation-v1.vectors"
HEX_RE = re.compile(r"[0-9a-f]*")
SHA256_RE = re.compile(r"[0-9a-f]{64}")


class StageOneError(ValueError):
    """A Stage-01 conformance failure."""


def digest(data: bytes) -> str:
    """Return one lowercase SHA-256 digest."""
    return hashlib.sha256(data).hexdigest()


def checked_sources(root: Path) -> dict[str, bytes]:
    """Read and validate every frozen Stage-01 source byte string."""
    sources: dict[str, bytes] = {}
    for relative, expected in RAW_HASHES.items():
        path = root / relative
        if not path.is_file():
            raise StageOneError(f"missing frozen source: {relative}")
        content = path.read_bytes()
        actual = digest(content)
        if actual != expected:
            raise StageOneError(f"frozen source changed: {relative}: {actual} != {expected}")
        sources[relative] = content
    return sources


def profile_digests(sources: dict[str, bytes]) -> dict[str, bytes]:
    """Derive both protocol profiles from their exact domain-separated bytes."""
    registry = sources["docs/federation-v1-profile.registry"]
    e2ee = sources["docs/irc-mls-e2ee-extension.md"]
    values = {
        "base-federation-v1": hashlib.sha256(
            PROFILE_LABELS["base-federation-v1"] + registry
        ).digest(),
        "e2ee-mls-v1": hashlib.sha256(
            PROFILE_LABELS["e2ee-mls-v1"] + e2ee
        ).digest(),
    }
    for name, value in values.items():
        if value.hex() != PROFILE_HASHES[name]:
            raise StageOneError(f"derived profile changed: {name}")
        token = base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")
        if len(token) != 43 or "=" in token:
            raise StageOneError(f"derived profile token is not canonical: {name}")
    return values


def reject_single_byte_changes(sources: dict[str, bytes]) -> None:
    """Prove each raw and derived binding changes after one source-byte change."""
    for relative, original in sources.items():
        if not original:
            raise StageOneError(f"frozen source is empty: {relative}")
        changed = bytes([original[0] ^ 1]) + original[1:]
        if digest(changed) == RAW_HASHES[relative]:
            raise StageOneError(f"single-byte raw-hash negative failed: {relative}")
    registry = sources["docs/federation-v1-profile.registry"]
    changed_registry = bytes([registry[0] ^ 1]) + registry[1:]
    changed_base = hashlib.sha256(
        PROFILE_LABELS["base-federation-v1"] + changed_registry
    ).hexdigest()
    if changed_base == PROFILE_HASHES["base-federation-v1"]:
        raise StageOneError("single-byte base-profile negative failed")
    e2ee = sources["docs/irc-mls-e2ee-extension.md"]
    changed_e2ee = bytes([e2ee[0] ^ 1]) + e2ee[1:]
    changed_profile = hashlib.sha256(
        PROFILE_LABELS["e2ee-mls-v1"] + changed_e2ee
    ).hexdigest()
    if changed_profile == PROFILE_HASHES["e2ee-mls-v1"]:
        raise StageOneError("single-byte E2EE-profile negative failed")


def parse_registry(content: bytes) -> dict[str, list[tuple[str, str]]]:
    """Parse the closed sorted three-field federation registry."""
    if not content.endswith(b"\n") or content.endswith(b"\n\n") or b"\r" in content:
        raise StageOneError("registry does not use exactly one terminal LF")
    try:
        lines = content.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise StageOneError("registry is not ASCII") from error
    if not lines or lines != sorted(lines) or len(lines) != len(set(lines)):
        raise StageOneError("registry is empty, unsorted, or contains duplicate lines")
    records: dict[str, list[tuple[str, str]]] = {}
    keys: set[tuple[str, str]] = set()
    for line_number, line in enumerate(lines, 1):
        fields = line.split("|")
        if len(fields) != 3 or any(not field for field in fields):
            raise StageOneError(f"registry line {line_number} is not one nonempty triple")
        category, name, value = fields
        key = (category, name)
        if key in keys:
            raise StageOneError(f"duplicate registry key: {category}|{name}")
        keys.add(key)
        records.setdefault(category, []).append((name, value))
    actual_counts = {category: len(values) for category, values in records.items()}
    if actual_counts != CATEGORY_COUNTS:
        raise StageOneError(
            f"registry category counts changed: {actual_counts!r} != {CATEGORY_COUNTS!r}"
        )
    return records


def enum_values(records: dict[str, list[tuple[str, str]]]) -> dict[str, list[int]]:
    """Parse explicit closed enum discriminants without declaration-order use."""
    values: dict[str, list[int]] = {}
    for name, raw_entries in records["enum"]:
        entries: list[int] = []
        seen_names: set[str] = set()
        for raw_entry in raw_entries.split(","):
            fields = raw_entry.split("=")
            if len(fields) != 2 or not fields[1].isascii() or not fields[1].isdecimal():
                raise StageOneError(f"malformed enum entry: {name}.{raw_entry}")
            if fields[0] in seen_names:
                raise StageOneError(f"duplicate enum name: {name}.{fields[0]}")
            seen_names.add(fields[0])
            entries.append(int(fields[1]))
        if len(entries) != len(set(entries)):
            raise StageOneError(f"duplicate enum discriminant: {name}")
        values[name] = entries
    return values


def length_prefix(maximum: int, value: int) -> bytes:
    """Encode a minimal fixed-width Appendix-B length prefix."""
    if maximum <= 0xFF:
        width = 1
    elif maximum <= 0xFFFF:
        width = 2
    elif maximum <= 0xFFFFFF:
        width = 3
    else:
        width = 4
    return value.to_bytes(width, "big")


def minimum_vectors(records: dict[str, list[tuple[str, str]]]) -> dict[str, bytes]:
    """Independently encode one minimum object for every frozen schema."""
    schemas = dict(records["schema"])
    enums = enum_values(records)
    account_id = b"a_" + base64.urlsafe_b64encode(bytes(16)).rstrip(b"=")
    semantic_integers = {
        ("AccountCreationInviteTBS", "expires_at"): 1,
        ("AccountCreationInviteTBS", "use_limit"): 1,
        ("FederationAccountProjection", "account_session_generation"): 1,
        ("FederationAccountProjection", "account_revision"): 1,
        ("FederationChannelDetail", "channel_revision"): 1,
        ("FederationChannelDetail", "simple_mode_bits"): 4,
        ("FederationDepartedChannel", "resulting_revision"): 1,
        ("FederationDeliveredMessage", "channel_event_sequence"): 1,
        ("FederationDeliveredMessage", "target_revision"): 1,
        ("FederationEvent", "coordinator_state_generation"): 1,
        ("FederationHistoryAuthorization", "session_generation"): 1,
        ("FederationHistoryAuthorization", "membership_revision"): 1,
        ("FederationHistoryAuthorization", "history_authorization_generation"): 1,
        ("FederationHistoryMessage", "channel_event_sequence"): 1,
        ("FederationHistoryMessage", "received_unix_milliseconds"): 1,
        ("FederationHistoryMessage", "expires_unix_milliseconds"): 3_600_001,
        ("FederationInviteProjection", "creation_revision"): 1,
        ("FederationInviteProjection", "expires_at"): 1,
        ("FederationMessageTarget", "expected_target_revision"): 1,
        ("FederationMembership", "membership_revision"): 1,
        ("FederationModeListEntry", "mode_code"): 1,
        ("FederationModeChange", "mode_code"): 1,
        ("FederationProjectedModeChange", "mode_code"): 1,
        ("FederationSessionProjection", "session_revision"): 1,
        ("FederationSessionProjection", "user_mode_bits"): 1,
        ("directory.channel_mode_list", "mode_code"): 1,
        ("directory.whowas", "count"): 1,
        ("event.channel_destroyed", "final_revision"): 1,
        ("event.channel_hidden", "last_revision"): 1,
        ("event.channel_memberships_recomputed", "resulting_revision"): 1,
        ("event.channel_modes_changed", "resulting_revision"): 1,
        ("event.invite_removed", "resulting_revision"): 1,
        ("event.kicked", "resulting_revision"): 1,
        ("event.member_parted", "resulting_revision"): 1,
        ("event.request_completed", "resulting_state_generation"): 1,
        ("event.session_hidden", "last_revision"): 1,
        ("event.topic_changed", "resulting_revision"): 1,
        ("operation.account_settings", "expected_account_revision"): 1,
        ("operation.away", "expected_session_revision"): 1,
        ("operation.channel_mode", "expected_channel_revision"): 1,
        ("operation.channel_register", "expected_channel_revision"): 1,
        ("operation.channel_settings", "expected_channel_revision"): 1,
        ("operation.channel_unregister", "expected_channel_revision"): 1,
        ("operation.history_query", "limit"): 1,
        ("operation.invite", "expected_channel_revision"): 1,
        ("operation.join", "expected_session_revision"): 1,
        ("operation.kick", "expected_channel_revision"): 1,
        ("operation.nick_change", "expected_session_revision"): 1,
        ("operation.part", "expected_session_revision"): 1,
        ("operation.setname", "expected_session_revision"): 1,
        ("operation.topic", "expected_channel_revision"): 1,
        ("operation.user_mode", "expected_session_revision"): 1,
        ("result.account_created", "account_revision"): 1,
        ("result.authenticated", "account_session_generation"): 1,
        ("result.committed", "resulting_state_generation"): 1,
        ("result.history_page", "snapshot_state_generation"): 1,
        ("result.session_registered", "session_revision"): 1,
        ("result.session_registered", "resulting_state_generation"): 1,
    }
    semantic_enums = {("operation.part", "all_channels"): 1}
    account_service_operation_kinds = {
        "operation.account_create_start": 1,
        "operation.account_create_finish": 2,
        "operation.opaque_auth_start": 3,
        "operation.opaque_auth_finish": 4,
        "operation.credential_change_start": 5,
        "operation.credential_change_finish": 6,
    }

    def semantic_enum(
        schema_name: str,
        field_name: str,
        registry_name: str,
        active: tuple[str, ...],
    ) -> int:
        if (
            schema_name == "FederationActorView"
            and field_name == "user_present"
            and "event.topic_changed" in active
        ):
            return 1
        if (schema_name, field_name) == ("AccountServiceRequestHeader", "message_kind"):
            for owner, value in account_service_operation_kinds.items():
                if owner in active:
                    return value
        return semantic_enums.get((schema_name, field_name), min(enums[registry_name]))

    def encode_schema(name: str, active: tuple[str, ...] = ()) -> bytes:
        if name in active:
            raise StageOneError(f"recursive frozen schema: {name}")
        fields = schemas.get(name)
        if fields is None:
            raise StageOneError(f"unknown nested schema: {name}")
        if fields == "empty":
            return b""
        output = bytearray()
        for field in fields.split(","):
            field_parts = field.split(":", 1)
            if len(field_parts) != 2:
                raise StageOneError(f"malformed schema field: {name}.{field}")
            output.extend(
                encode_field(name, field_parts[0], field_parts[1], active + (name,))
            )
        return bytes(output)

    def semantic_opaque(
        schema_name: str,
        field_name: str,
        minimum: int,
        maximum: int,
        active: tuple[str, ...],
    ) -> bytes | None:
        direct = {
            ("AccountCreateStart", "normalized_login"): b"aaa",
            ("AccountSettingsChange", "value"): b"a",
            ("AuthStart", "normalized_login"): b"aaa",
            ("FederationChannelName", "value"): b"#a",
            ("FederationClientTag", "key"): b"+a",
            ("FederationMessageTarget", "value"): bytes(16),
            ("FederationDeliveredMessage", "body"): b"x",
            ("FederationHistoryMessage", "body"): b"x",
            ("FederationNickname", "value"): b"a",
            ("FederationParameter", "value"): b"a",
            ("FederationReply", "command"): b"FAIL",
            ("FederationTypedMask", "value"): account_id,
            ("PrincipalRef", "identifier"): account_id,
            ("event.network_notice", "code"): b"NOTICE",
            ("event.network_notice", "safe_text"): b"x",
            ("operation.nick_change", "nickname"): b"a",
            ("operation.message", "body"): b"x",
            ("operation.session_open", "nickname"): b"a",
            ("result.failed", "reply_code"): b"AUTH_REQUIRED",
        }
        selected = direct.get((schema_name, field_name))
        if selected is not None:
            return selected
        if (
            schema_name == "FederationActorView"
            and field_name == "source"
            and "event.topic_changed" in active
        ):
            return encode_schema("FederationSourceView", active)
        if field_name == "account_id" and minimum == maximum == 24:
            return account_id
        embedded = {
            ("DirectoryQuery", "query"): "directory.list",
            ("FederationEvent", "event"): "event.session_visible",
            ("FederationProjectionValue", "value"): "FederationSessionProjection",
            ("FederationRequest", "operation"): "operation.session_open",
            ("FederationResult", "result"): "result.failed",
            ("FederationModeChange", "argument"): "FederationTypedMask",
            ("FederationProjectedModeChange", "argument"): "FederationModeListEntry",
        }
        nested = embedded.get((schema_name, field_name))
        if nested is not None:
            return encode_schema(nested, active)
        if (schema_name, field_name) == ("AccountServiceRequestPlaintext", "zero_padding"):
            return bytes(4_514)
        if (schema_name, field_name) == ("AccountServiceResponsePlaintext", "zero_padding"):
            return bytes(4_150)
        return None

    def encode_field(
        schema_name: str,
        field_name: str,
        grammar: str,
        active: tuple[str, ...],
    ) -> bytes:
        integer = re.fullmatch(r"uint(8|16|24|32|64)", grammar)
        if integer is not None:
            width = int(integer.group(1)) // 8
            value = semantic_integers.get((schema_name, field_name), 0)
            if (
                schema_name == "FederationActorView"
                and field_name == "user_present"
                and "event.topic_changed" in active
            ):
                value = 1
            if field_name in {"profile_version", "padding_version"}:
                value = 1
            return value.to_bytes(width, "big")
        fixed = re.fullmatch(r"opaque\[(\d+)\]", grammar)
        if fixed is not None:
            length = int(fixed.group(1))
            if (schema_name, field_name) in {
                ("FederationPublicCloak", "user_component"),
                ("FederationPublicCloak", "host_component"),
            }:
                return b"a" * length
            if field_name == "account_id" and schema_name in {
                "CredentialChangeStart",
                "FederationAccountProjection",
            }:
                return account_id
            if field_name == "snapshot_token" and schema_name in {
                "result.reply_page", "result.history_page"
            }:
                return bytes([1]) + bytes(length - 1)
            return bytes(length)
        opaque = re.fullmatch(r"opaque<(\d+)\.\.(\d+)>", grammar)
        if opaque is not None:
            minimum, maximum = map(int, opaque.groups())
            semantic = semantic_opaque(schema_name, field_name, minimum, maximum, active)
            value = bytes(minimum) if semantic is None else semantic
            if not minimum <= len(value) <= maximum:
                raise StageOneError(
                    f"semantic minimum outside bounds: {schema_name}.{field_name}"
                )
            return length_prefix(maximum, len(value)) + value
        enumeration = re.fullmatch(r"enum\(([^)]+)\)", grammar)
        if enumeration is not None:
            name = enumeration.group(1)
            if name not in enums:
                raise StageOneError(f"unknown enum in schema: {name}")
            value = semantic_enum(schema_name, field_name, name, active)
            return value.to_bytes(2, "big")
        structure = re.fullmatch(r"struct\(([^)]+)\)", grammar)
        if structure is not None:
            return encode_schema(structure.group(1), active)
        vector = re.fullmatch(r"vector\(([^)]+)\)<(\d+)\.\.(\d+)>", grammar)
        if vector is not None:
            schema, minimum_text, maximum_text = vector.groups()
            minimum = int(minimum_text)
            maximum = int(maximum_text)
            if (schema_name, field_name) == ("operation.user_mode", "changes"):
                element = (
                    (1).to_bytes(2, "big")
                    + (17).to_bytes(2, "big")
                    + (0).to_bytes(2, "big")
                )
            else:
                element = encode_schema(schema, active)
            return length_prefix(maximum, minimum) + element * minimum
        union = re.fullmatch(r"union\(([^)]+)\)", grammar)
        if union is not None:
            arm = UNION_ARMS.get(union.group(1))
            if arm is None:
                raise StageOneError(f"unknown projection union arm: {union.group(1)}")
            discriminant, schema = arm
            return discriminant.to_bytes(2, "big") + encode_schema(schema, active)
        raise StageOneError(f"unknown field grammar: {grammar}")

    return {name: encode_schema(name) for name in sorted(schemas)}


def validate_vectors(content: str, expected: dict[str, bytes]) -> None:
    """Validate vector identity, coverage, hashes, and independent bytes."""
    lines = content.splitlines()
    if lines[:2] != [
        "# agenc-ircd federation vector manifest v1",
        "# id|schema|lowercase-hex|decoded-sha256|provenance",
    ]:
        raise StageOneError("vector manifest header changed")
    records = lines[2:]
    if len(records) != len(expected):
        raise StageOneError("vector count does not equal the schema count")
    seen: set[str] = set()
    for index, line in enumerate(records, 1):
        fields = line.split("|")
        if len(fields) != 5:
            raise StageOneError(f"vector {index} is not one five-field record")
        identifier, schema, encoded, expected_hash, provenance = fields
        if identifier != f"VEC-B-{index:03d}":
            raise StageOneError(f"vector identifier sequence changed at {index}")
        if schema in seen or schema not in expected:
            raise StageOneError(f"duplicate or unknown vector schema: {schema}")
        seen.add(schema)
        if HEX_RE.fullmatch(encoded) is None or len(encoded) % 2:
            raise StageOneError(f"vector hex is not canonical: {identifier}")
        decoded = bytes.fromhex(encoded)
        if SHA256_RE.fullmatch(expected_hash) is None or digest(decoded) != expected_hash:
            raise StageOneError(f"vector hash mismatch: {identifier}")
        if provenance != "frozen-registry-minimum" or decoded != expected[schema]:
            raise StageOneError(f"vector provenance or bytes changed: {identifier}")
    if seen != set(expected):
        raise StageOneError("vector schema coverage is incomplete")


def validate_independent_reference(root: Path) -> None:
    """Ensure the reference encoder does not reuse the production codec."""
    source = (root / "crates/agenc-ircd-testkit/src/reference_codec.rs").read_text(
        encoding="utf-8"
    )
    forbidden = (
        "CanonicalEncode",
        "DecodeBudget",
        "SchemaObject",
        "WireValue",
        "agenc_ircd_federation_wire",
    )
    used = [name for name in forbidden if name in source]
    if used:
        raise StageOneError(f"reference codec reuses production surfaces: {used!r}")


def rust_function_body(source: str, name: str) -> str:
    """Extract one reviewed Rust function body with balanced braces."""
    match = re.search(rf"\bfn\s+{re.escape(name)}\s*\(", source)
    if match is None:
        raise StageOneError(f"missing nonrecursive parser function: {name}")
    opening = source.find("{", match.end())
    if opening < 0:
        raise StageOneError(f"parser function has no body: {name}")
    depth = 0
    for position in range(opening, len(source)):
        character = source[position]
        if character == "{":
            depth += 1
        elif character == "}":
            depth -= 1
            if depth == 0:
                return source[opening + 1 : position]
    raise StageOneError(f"parser function has an unterminated body: {name}")


def validate_nonrecursive_parser(codec: str, semantics: str) -> None:
    """Require explicit parser stacks and reject direct parser recursion."""
    required = (
        "enum DecodeFrame",
        "enum ObjectWalkFrame",
        "MAX_STATIC_SCHEMA_DEPTH",
    )
    if any(marker not in codec for marker in required):
        raise StageOneError("federation parser is missing its explicit bounded stack")
    forbidden = ("fn decode_schema(", "fn decode_value(", "fn decode_vector(")
    if any(marker in codec for marker in forbidden):
        raise StageOneError("federation parser contains a recursive decoder shape")
    parser_functions = (
        "decode_one_without_embedded",
        "decode_schema_iterative",
        "validate_embedded_tree",
        "validate_embedded_in_object_graph",
    )
    for name in parser_functions:
        body = rust_function_body(codec, name)
        if re.search(rf"\b{re.escape(name)}\s*\(", body):
            raise StageOneError(f"federation parser function recurses: {name}")
    if "SchemaObject::decode_exact" in semantics:
        raise StageOneError("embedded federation validation re-enters the public parser")


def check_generator(root: Path) -> None:
    """Run the generator's nonmutating checked-output comparison."""
    completed = subprocess.run(
        ["python3", "scripts/generate-stage-one.py", "--check"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).strip()
        raise StageOneError(f"generated artifacts are stale: {details}")


def validate(root: Path) -> tuple[int, int, int]:
    """Run the complete independent Stage-01 artifact check."""
    sources = checked_sources(root)
    profile_digests(sources)
    reject_single_byte_changes(sources)
    records = parse_registry(sources["docs/federation-v1-profile.registry"])
    vectors = minimum_vectors(records)
    vector_text = (root / VECTOR_PATH).read_text(encoding="utf-8")
    validate_vectors(vector_text, vectors)
    validate_independent_reference(root)
    validate_nonrecursive_parser(
        (root / "crates/agenc-ircd-federation-wire/src/codec.rs").read_text(
            encoding="utf-8"
        ),
        (root / "crates/agenc-ircd-federation-wire/src/semantics.rs").read_text(
            encoding="utf-8"
        ),
    )
    check_generator(root)
    return len(records["constant"]), len(records["schema"]), len(vectors)


def expect_failure(label: str, operation: object) -> None:
    """Require one callable malformed fixture to be rejected."""
    if not callable(operation):
        raise StageOneError(f"self-test {label} is not callable")
    try:
        operation()
    except StageOneError:
        return
    raise StageOneError(f"self-test accepted malformed {label}")


def self_test(root: Path) -> int:
    """Exercise independent registry and vector rejection branches."""
    sources = checked_sources(root)
    registry = sources["docs/federation-v1-profile.registry"]
    records = parse_registry(registry)
    vectors = minimum_vectors(records)
    vector_text = (root / VECTOR_PATH).read_text(encoding="utf-8")
    expect_failure("registry terminal LF", lambda: parse_registry(registry.rstrip(b"\n")))
    first_line = registry.splitlines()[0]
    duplicate_registry = registry + first_line + b"\n"
    expect_failure("duplicate registry line", lambda: parse_registry(duplicate_registry))
    changed_hash = vector_text.replace("|frozen-registry-minimum", "|broken", 1)
    expect_failure("vector provenance", lambda: validate_vectors(changed_hash, vectors))
    missing_vector = "\n".join(vector_text.splitlines()[:-1]) + "\n"
    expect_failure("missing vector", lambda: validate_vectors(missing_vector, vectors))
    malformed_hex = vector_text.replace("|00", "|0z", 1)
    expect_failure("vector hex", lambda: validate_vectors(malformed_hex, vectors))
    codec = (root / "crates/agenc-ircd-federation-wire/src/codec.rs").read_text(
        encoding="utf-8"
    )
    semantics = (root / "crates/agenc-ircd-federation-wire/src/semantics.rs").read_text(
        encoding="utf-8"
    )
    recursive = codec.replace(
        "    let root = new_schema_frame",
        "    decode_schema_iterative(schema, decoder, budget, initial_depth)?;\n"
        "    let root = new_schema_frame",
        1,
    )
    expect_failure(
        "recursive parser", lambda: validate_nonrecursive_parser(recursive, semantics)
    )
    return 6


def fail(message: str) -> NoReturn:
    """Print one stable failure and exit unsuccessfully."""
    print(f"Stage-01 check failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch the Stage-01 check or its malformed-fixture self-test."""
    root = Path(__file__).resolve().parent.parent
    command = sys.argv[1:] or ["check"]
    try:
        if command == ["check"]:
            constants, schemas, vectors = validate(root)
            print(
                "Stage-01 artifacts: ok "
                f"({constants} constants, {schemas} schemas, {vectors} vectors)"
            )
        elif command == ["self-test"]:
            cases = self_test(root)
            print(f"Stage-01 artifact self-test: ok ({cases} rejection cases)")
        else:
            raise StageOneError("usage: check-stage-one.py [check|self-test]")
    except (OSError, UnicodeError, StageOneError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
