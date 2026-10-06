#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$repo_root" <<'PY'
from __future__ import annotations

import base64
import hashlib
import re
import sys
from pathlib import Path

root = Path(sys.argv[1])
spec = root / "docs/arc-architecture-and-implementation-spec.md"
e2ee = root / "docs/arc-mls-e2ee-extension.md"
registry = root / "docs/federation-v1-profile.registry"
sources = root / "docs/protocol-sources-and-decisions.md"
manifest = root / "docs/specification-manifest.txt"

expected_files = {
    "rfcs/rfc1459-irc-protocol.txt": "d1fdc86169252b234b17c2f501c0ba7f512ba697ddf8a13b3da7ee4491a76799",
    "rfcs/rfc2810-irc-architecture.txt": "b00c6ae92ef66b1b2c3a15df86e6e1ab8268bcb40ebbadd388d75531bf6e62f6",
    "rfcs/rfc2811-irc-channel-management.txt": "41e2b24141669f0094e78896f5d2c54d26db2cbed8a299cf9b0bb1aca42d3a96",
    "rfcs/rfc2812-irc-client-protocol.txt": "9337603057716c2e74809e8c57b557ee0bdbfca60cc5c852e240df0e5ba53479",
    "rfcs/rfc2813-irc-server-protocol.txt": "f67d31f2d4a23fda979ace02e3279c9b3d1ab33e279c8a41e1add7ab293991ba",
    "rfcs/rfc7194-irc-over-tls.txt": "7848ebe7e8e7efda651a3488b1122a2db91f3de6253e0fcd9c2eb285256da4ec",
    "rfcs/rfc8446-tls-1.3.txt": "47871bc8820a2c3b6ea89f061055577058862cf543686b82d10131239702b3bd",
    "rfcs/rfc9180-hpke.txt": "f45a8b7c30231b26d668b1e8168074e5ab514b174d656b67e859895117f1f8f6",
    "rfcs/rfc9325-secure-tls-recommendations.txt": "e3475381d056bde1eed65252954cce68250168454387f6799b38660806f215bc",
    "rfcs/rfc9420-mls-protocol.txt": "251ab11076c43fd4b8dc080a068a8caaf55e2fc5e6aa61d4274961627f32624b",
    "rfcs/rfc9525-tls-service-identity.txt": "ed8116c2435376dffe37ec2ca688c3a8515e36820852b29e0b6cdfbe92abd2c5",
    "rfcs/rfc9750-mls-architecture.txt": "6aa156c5592f99802aae9c39510bf347cacee4abdb1c34baab4c933a6cd992dd",
    "docs/arc-mls-e2ee-extension.md": "4fa947bf4edfe146de8f6a72932b93625828b0fd6eea46976e699ab06719658c",
    "docs/federation-v1-profile.registry": "1b94cb7b43dc458ff683ddcfd86eed1939128a7a6d0229b89342bd6816eb5411",
}

errors: list[str] = []

for relative, expected in expected_files.items():
    path = root / relative
    if not path.is_file():
        errors.append(f"missing pinned source: {relative}")
        continue
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        errors.append(f"hash mismatch for {relative}: {actual} != {expected}")

registry_bytes = registry.read_bytes()
if not registry_bytes.endswith(b"\n") or registry_bytes.endswith(b"\n\n"):
    errors.append("registry must end in exactly one LF")
if b"\r" in registry_bytes:
    errors.append("registry contains CR")
if any(byte != 10 and not 32 <= byte <= 126 for byte in registry_bytes):
    errors.append("registry contains bytes outside printable ASCII plus LF")

registry_lines = registry_bytes.decode("ascii").splitlines()
if not registry_lines or any(not line for line in registry_lines):
    errors.append("registry is empty or contains a blank line")
if registry_lines != sorted(registry_lines):
    errors.append("registry lines are not bytewise sorted")
if len(registry_lines) != len(set(registry_lines)):
    errors.append("registry contains a duplicate line")

registry_keys: set[tuple[str, str]] = set()
registry_values: dict[tuple[str, str], str] = {}
allowed_registry_categories = {
    "constant", "crypto", "enum", "hash", "mapping", "mode", "order",
    "schema", "wire",
}
for line_number, line in enumerate(registry_lines, 1):
    fields = line.split("|")
    if len(fields) != 3 or any(not field for field in fields):
        errors.append(f"registry line {line_number} is not one nonempty triple")
        continue
    if fields[0] not in allowed_registry_categories:
        errors.append(
            f"registry line {line_number} has unknown category {fields[0]!r}"
        )
    if not re.fullmatch(r"[A-Za-z0-9_.-]+", fields[1]):
        errors.append(f"registry line {line_number} has invalid key {fields[1]!r}")
    key = (fields[0], fields[1])
    if key in registry_keys:
        errors.append(f"registry has duplicate key {key!r}")
    registry_keys.add(key)
    registry_values[key] = fields[2]

present_categories = {category for category, _ in registry_keys}
if present_categories != allowed_registry_categories:
    errors.append(
        "registry category set is "
        f"{sorted(present_categories)!r}, expected "
        f"{sorted(allowed_registry_categories)!r}"
    )


def registry_enum(name: str) -> dict[str, int]:
    raw = registry_values.get(("enum", name))
    if raw is None:
        errors.append(f"registry enum missing: {name}")
        return {}
    parsed: dict[str, int] = {}
    used_values: set[int] = set()
    for item in raw.split(","):
        if item.count("=") != 1:
            errors.append(f"registry enum {name} has malformed item {item!r}")
            continue
        variant, encoded = item.split("=", 1)
        if not re.fullmatch(r"[a-z][a-z0-9_]*", variant):
            errors.append(f"registry enum {name} has invalid variant {variant!r}")
            continue
        if not encoded.isascii() or not encoded.isdecimal():
            errors.append(f"registry enum {name} has invalid value {encoded!r}")
            continue
        value = int(encoded)
        if variant in parsed or value in used_values:
            errors.append(f"registry enum {name} repeats {item!r}")
            continue
        parsed[variant] = value
        used_values.add(value)
    return parsed


opcodes = registry_enum("FederationOpcode")
result_kinds = registry_enum("FederationResultKind")
event_kinds = registry_enum("FederationEventKind")
directory_kinds = registry_enum("FederationDirectoryQueryKind")
projection_kinds = registry_enum("FederationProjectionKind")

expected_account_constants = {
    "account_service_envelope_bytes": "4726",
    "account_service_hpke_aead_id": "3",
    "account_service_hpke_kdf_id": "1",
    "account_service_hpke_kem_id": "32",
    "account_service_opaque_ke1_bytes": "96",
    "account_service_opaque_ke2_bytes": "320",
    "account_service_opaque_ke3_bytes": "64",
    "account_service_opaque_registration_record_bytes": "192",
    "account_service_opaque_registration_request_bytes": "32",
    "account_service_opaque_registration_response_bytes": "64",
    "account_service_padding_version": "1",
    "account_service_request_plaintext_bytes": "4592",
    "account_service_response_bytes": "4342",
    "account_service_response_plaintext_bytes": "4208",
}
for constant_name, expected_value in expected_account_constants.items():
    actual_value = registry_values.get(("constant", constant_name))
    if actual_value != expected_value:
        errors.append(
            f"registry constant {constant_name} is {actual_value!r}, "
            f"expected {expected_value!r}"
        )

expected_account_crypto = {
    "account_service_request": (
        'RFC9180-Base(kem=32,kdf=1,aead=3);info="agenc-chat account service '
        'hpke request v1"+TLS-encode(recovery_epoch,header);aad="agenc-chat '
        'account service request aad v1"+TLS-encode(header,enc);sequence=0'
    ),
    "account_service_response": (
        'ChaCha20Poly1305;response_salt=random[32];key=HPKE-Export("agenc-chat '
        'account service response key v1"+recovery_epoch+response_salt,32);'
        'nonce=HPKE-Export("agenc-chat account service response nonce v1"+'
        'recovery_epoch+response_salt,12);aad="agenc-chat account service '
        'response aad v1"+TLS-encode(header);one-use;count=StateMeta.'
        'account_service_response_count;count-role=coordinator;'
        'count-max=18446744073709551615;edge-count=0;stored-replay=no-reseal'
    ),
}
for crypto_name, expected_value in expected_account_crypto.items():
    actual_value = registry_values.get(("crypto", crypto_name))
    if actual_value != expected_value:
        errors.append(
            f"registry crypto {crypto_name} is {actual_value!r}, "
            f"expected {expected_value!r}"
        )

expected_account_enums = {
    "AccountServiceCompletionStatus": {"rejected": 1, "committed": 2},
    "AccountServiceMessageKind": {
        "account_create_start": 1,
        "account_create_finish": 2,
        "opaque_auth_start": 3,
        "opaque_auth_finish": 4,
        "credential_change_start": 5,
        "credential_change_finish": 6,
    },
    "AccountServiceResponseKind": {
        "account_create_challenge": 1,
        "opaque_auth_challenge": 2,
        "account_create_complete": 3,
        "opaque_auth_complete": 4,
        "credential_change_challenge": 5,
        "credential_change_complete": 6,
    },
    "FederationSessionHideKind": {
        "client_quit": 1,
        "transport_lost": 2,
        "origin_expired": 3,
        "account_deleted": 4,
        "operator_removed": 5,
        "security_fenced": 6,
    },
}
for enum_name, expected_values in expected_account_enums.items():
    actual_values = registry_enum(enum_name)
    if actual_values != expected_values:
        errors.append(
            f"registry enum {enum_name} is {actual_values!r}, "
            f"expected {expected_values!r}"
        )

expected_account_schemas = {
    "AccountCreateFinish": (
        "profile_version:uint16,network_id:opaque[32],transaction_id:opaque[16],"
        "registration_record:opaque<192..192>"
    ),
    "AccountCreateStart": (
        "profile_version:uint16,network_id:opaque[32],normalized_login:opaque<3..64>,"
        "registration_request:opaque<32..32>,creation_invite:opaque<0..132>"
    ),
    "AccountServiceChallenge": (
        "profile_version:uint16,transaction_id:opaque[16],"
        "opaque_credential_id:opaque[32],opaque_message:opaque<64..320>"
    ),
    "AccountServiceCompletion": (
        "profile_version:uint16,transaction_id:opaque[16],"
        "status:enum(AccountServiceCompletionStatus),account_id:opaque[24],"
        "account_session_generation:uint64"
    ),
    "AccountServiceEnvelope": (
        "header:struct(AccountServiceRequestHeader),enc:opaque[32],"
        "ciphertext:opaque<4608..4608>"
    ),
    "AccountServiceRequestHeader": (
        "profile_version:uint16,network_id:opaque[32],recipient_key_id:opaque[32],"
        "client_request_id:opaque[16],message_kind:enum(AccountServiceMessageKind)"
    ),
    "AccountServiceRequestPlaintext": (
        "padding_version:uint16,inner_payload:opaque<72..265>,"
        "zero_padding:opaque<4321..4514>"
    ),
    "AccountServiceResponse": (
        "header:struct(AccountServiceResponseHeader),ciphertext:opaque<4224..4224>"
    ),
    "AccountServiceResponseHeader": (
        "profile_version:uint16,network_id:opaque[32],recipient_key_id:opaque[32],"
        "client_request_id:opaque[16],response_kind:enum(AccountServiceResponseKind),"
        "response_salt:opaque[32]"
    ),
    "AccountServiceResponsePlaintext": (
        "padding_version:uint16,payload:opaque<52..372>,"
        "zero_padding:opaque<3830..4150>"
    ),
    "AuthFinish": (
        "profile_version:uint16,network_id:opaque[32],transaction_id:opaque[16],"
        "ke3:opaque<64..64>"
    ),
    "AuthStart": (
        "profile_version:uint16,network_id:opaque[32],normalized_login:opaque<3..64>,"
        "ke1:opaque<96..96>"
    ),
    "CredentialChangeFinish": (
        "profile_version:uint16,network_id:opaque[32],transaction_id:opaque[16],"
        "registration_record:opaque<192..192>"
    ),
    "CredentialChangeStart": (
        "profile_version:uint16,network_id:opaque[32],account_id:opaque[24],"
        "registration_request:opaque<32..32>"
    ),
}
for schema_name, expected_schema in expected_account_schemas.items():
    actual_schema = registry_values.get(("schema", schema_name))
    if actual_schema != expected_schema:
        errors.append(
            f"registry schema {schema_name} is {actual_schema!r}, "
            f"expected {expected_schema!r}"
        )

expected_account_response_mapping = (
    "account_create_start=account_create_challenge,"
    "account_create_finish=account_create_complete,"
    "opaque_auth_start=opaque_auth_challenge,"
    "opaque_auth_finish=opaque_auth_complete,"
    "credential_change_start=credential_change_challenge,"
    "credential_change_finish=credential_change_complete"
)
if registry_values.get(
    ("mapping", "account-service-response-by-request-kind")
) != expected_account_response_mapping:
    errors.append("registry account-service request/response mapping is not exact")

if opcodes.get("credential_change_start") != 25:
    errors.append("credential_change_start opcode must be 25")
if opcodes.get("credential_change_finish") != 26:
    errors.append("credential_change_finish opcode must be 26")
if 23 in opcodes.values():
    errors.append("federation opcode 23 must remain reserved")
if registry_values.get(("mapping", "result.credential_change_start")) != (
    "failed,auth_challenge"
):
    errors.append("credential-change start result mapping is not exact")
if registry_values.get(("mapping", "result.credential_change_finish")) != (
    "failed,committed"
):
    errors.append("credential-change finish result mapping is not exact")
if registry_values.get(("mapping", "session-hide-security-fenced")) != (
    'reason="connection closed";cause-redacted'
):
    errors.append("security-fenced session-hide mapping is not exact")

# Independently prove the fixed account-service size arithmetic rather than
# merely comparing prose constants.
request_header_bytes = 2 + 32 + 32 + 16 + 2
request_envelope_bytes = request_header_bytes + 32 + 2 + 4608
response_header_bytes = 2 + 32 + 32 + 16 + 2 + 32
response_envelope_bytes = response_header_bytes + 2 + 4224
account_create_start_lengths = {
    2 + 32 + 1 + login_bytes + 1 + 32 + 1 + invite_bytes
    for login_bytes in (3, 64)
    for invite_bytes in (0, 132)
}
request_arm_lengths = account_create_start_lengths | {
    2 + 32 + 16 + 1 + 192,
    2 + 32 + 1 + 3 + 1 + 96,
    2 + 32 + 1 + 64 + 1 + 96,
    2 + 32 + 16 + 1 + 64,
    2 + 32 + 24 + 1 + 32,
}
challenge_lengths = {
    2 + 16 + 32 + 2 + 64,
    2 + 16 + 32 + 2 + 320,
}
completion_bytes = 2 + 16 + 2 + 24 + 8
if request_envelope_bytes != 4726:
    errors.append(f"account-service request arithmetic produced {request_envelope_bytes}")
if response_envelope_bytes != 4342:
    errors.append(f"account-service response arithmetic produced {response_envelope_bytes}")
if (min(request_arm_lengths), max(request_arm_lengths)) != (72, 265):
    errors.append(
        "account-service request-arm bounds are "
        f"{(min(request_arm_lengths), max(request_arm_lengths))!r}"
    )
if (min(challenge_lengths | {completion_bytes}), max(challenge_lengths)) != (52, 372):
    errors.append("account-service response-payload bounds are not 52..372")
if 4586 - max(request_arm_lengths) != 4321:
    errors.append("account-service minimum request padding is not 4321")
if 4586 - min(request_arm_lengths) != 4514:
    errors.append("account-service maximum request padding is not 4514")
if 4202 - max(challenge_lengths) != 3830:
    errors.append("account-service minimum response padding is not 3830")
if 4202 - completion_bytes != 4150:
    errors.append("account-service maximum response padding is not 4150")
if len(base64.urlsafe_b64encode(bytes(4726)).rstrip(b"=")) != 6302:
    errors.append("account-service request base64url length is not 6302")
if len(base64.urlsafe_b64encode(bytes(4342)).rstrip(b"=")) != 5790:
    errors.append("account-service response base64url length is not 5790")
if len(base64.b64encode(bytes(4726))) != 6304:
    errors.append("account-service request padded-Base64 length is not 6304")
if len(base64.b64encode(bytes(4342))) != 5792:
    errors.append("account-service response padded-Base64 length is not 5792")

for opcode in opcodes:
    if ("schema", f"operation.{opcode}") not in registry_keys:
        errors.append(f"registry operation schema missing for opcode {opcode}")
    mapping_key = ("mapping", f"result.{opcode}")
    if mapping_key not in registry_keys:
        errors.append(f"registry result mapping missing for opcode {opcode}")
        continue
    mapped = registry_values[mapping_key].split(",")
    if not mapped or mapped[0] != "failed" or len(mapped) != len(set(mapped)):
        errors.append(f"registry result mapping malformed for opcode {opcode}")
    unknown = set(mapped) - set(result_kinds)
    if unknown:
        errors.append(
            f"registry result mapping for {opcode} names unknown kinds "
            f"{sorted(unknown)!r}"
        )

for result_kind in result_kinds:
    if ("schema", f"result.{result_kind}") not in registry_keys:
        errors.append(f"registry schema missing for result kind {result_kind}")
for event_kind in event_kinds:
    if ("schema", f"event.{event_kind}") not in registry_keys:
        errors.append(f"registry schema missing for event kind {event_kind}")
for directory_kind in directory_kinds:
    if ("schema", f"directory.{directory_kind}") not in registry_keys:
        errors.append(f"registry schema missing for directory kind {directory_kind}")
for projection_kind in projection_kinds:
    if ("order", f"projection_primary.{projection_kind}") not in registry_keys:
        errors.append(
            f"registry primary-key order missing for projection {projection_kind}"
        )

completion_mapping = registry_values.get(("mapping", "completion-event-by-result-kind"))
if completion_mapping is None:
    errors.append("registry completion-event mapping is missing")
else:
    completion_keys = {
        item.split("=", 1)[0]
        for item in completion_mapping.split(",")
        if item.count("=") == 1
    }
    if completion_keys != set(result_kinds):
        errors.append(
            "registry completion-event mapping covers "
            f"{sorted(completion_keys)!r}, expected {sorted(result_kinds)!r}"
        )

mode_keys = {key for category, key in registry_keys if category == "mode"}
if mode_keys != {str(number) for number in range(1, 19)}:
    errors.append(f"registry mode keys are {sorted(mode_keys)!r}, expected 1..18")

expected_wire_keys = {
    "FACK", "FEVENT", "FHELLO", "FORIGIN_ACK", "FORIGIN_ADD",
    "FORIGIN_DEL", "FORIGIN_READY", "FORIGIN_RESET", "FORIGIN_UPDATE",
    "FPING", "FPONG", "FREADY", "FREQUEST", "FRESULT", "FRESUME",
    "FRESUME_OK", "FRESUME_SNAPSHOT", "FSNAPSHOT_ACTIVE",
    "FSNAPSHOT_BEGIN", "FSNAPSHOT_END", "FSNAPSHOT_ENTRY",
    "FSNAPSHOT_READY", "fragment_tag",
}
wire_keys = {key for category, key in registry_keys if category == "wire"}
if wire_keys != expected_wire_keys:
    errors.append(
        f"registry wire keys are {sorted(wire_keys)!r}, expected "
        f"{sorted(expected_wire_keys)!r}"
    )

profile_hash = hashlib.sha256(
    b"agenc-chat base federation profile registry v1\0" + registry_bytes
).hexdigest()
expected_profile_hash = "7b00e0d0844270626411d398f15f7520224ea906117738e3da9741a611dc67b3"
if profile_hash != expected_profile_hash:
    errors.append(f"profile hash mismatch: {profile_hash} != {expected_profile_hash}")

e2ee_bytes = e2ee.read_bytes()
e2ee_profile_digest = hashlib.sha256(
    b"agenc-chat ARC-MLS specification profile v1\0" + e2ee_bytes
).digest()
e2ee_profile_hash = e2ee_profile_digest.hex()
e2ee_profile_token = base64.urlsafe_b64encode(
    e2ee_profile_digest
).rstrip(b"=").decode("ascii")
expected_e2ee_profile_hash = (
    "0b3985c1e19f77e561734139d65131fb1c1fc5cb7a63a1119ca03b5a61583525"
)
if e2ee_profile_hash != expected_e2ee_profile_hash:
    errors.append(
        "E2EE profile hash mismatch: "
        f"{e2ee_profile_hash} != {expected_e2ee_profile_hash}"
    )
if len(e2ee_profile_token) != 43 or "=" in e2ee_profile_token:
    errors.append("E2EE profile token is not canonical 43-character base64url")

profile_digest = bytes.fromhex(profile_hash)
profile_token = base64.urlsafe_b64encode(profile_digest).rstrip(b"=").decode("ascii")
manifest_raw_targets = (
    "docs/federation-v1-profile.registry",
    "docs/arc-mls-e2ee-extension.md",
    "docs/arc-architecture-and-implementation-spec.md",
    "docs/protocol-sources-and-decisions.md",
    "scripts/check-spec.sh",
)
expected_manifest_lines = [
    "manifest|version|1",
    f"profile-base64url|base-federation-v1|{profile_token}",
    f"profile-base64url|e2ee-mls-v1|{e2ee_profile_token}",
    f"profile-sha256|base-federation-v1|{profile_hash}",
    f"profile-sha256|e2ee-mls-v1|{e2ee_profile_hash}",
]
expected_manifest_lines.extend(
    f"sha256|{relative}|{hashlib.sha256((root / relative).read_bytes()).hexdigest()}"
    for relative in manifest_raw_targets
)
expected_manifest_lines.sort()
if not manifest.is_file():
    errors.append("specification manifest is missing")
else:
    manifest_bytes = manifest.read_bytes()
    if not manifest_bytes.endswith(b"\n") or manifest_bytes.endswith(b"\n\n"):
        errors.append("specification manifest must end in exactly one LF")
    if b"\r" in manifest_bytes:
        errors.append("specification manifest contains CR")
    if any(byte != 10 and not 32 <= byte <= 126 for byte in manifest_bytes):
        errors.append("specification manifest is not printable ASCII plus LF")
    try:
        manifest_lines = manifest_bytes.decode("ascii").splitlines()
    except UnicodeDecodeError:
        manifest_lines = []
    if manifest_lines != expected_manifest_lines:
        errors.append(
            "specification manifest content mismatch: expected "
            f"{expected_manifest_lines!r}, got {manifest_lines!r}"
        )
    if len(manifest_lines) != len(set(manifest_lines)):
        errors.append("specification manifest contains a duplicate line")
    for line_number, line in enumerate(manifest_lines, 1):
        if len(line.split("|")) != 3:
            errors.append(
                f"specification manifest line {line_number} is not one triple"
            )

spec_bytes = spec.read_bytes()
if b"\r" in spec_bytes:
    errors.append("main spec contains CR")
if not spec_bytes.endswith(b"\n") or spec_bytes.endswith(b"\n\n"):
    errors.append("main spec must end in exactly one LF")
spec_text = spec_bytes.decode("utf-8")
spec_lines = spec_text.splitlines()
if any(line.endswith((" ", "\t")) for line in spec_lines):
    errors.append("main spec contains trailing whitespace")
if sum(line.startswith("```") for line in spec_lines) % 2:
    errors.append("main spec has an unbalanced fenced code block")

main_headings = []
appendix_headings = []
heading_texts: set[str] = set()
for line_number, line in enumerate(spec_lines, 1):
    match = re.fullmatch(r"## (\d+)\. .+", line)
    if match:
        main_headings.append(int(match.group(1)))
    match = re.fullmatch(r"## Appendix ([A-E])\. .+", line)
    if match:
        appendix_headings.append(match.group(1))
    if line.startswith("## "):
        if line in heading_texts:
            errors.append(f"duplicate level-two heading at line {line_number}: {line}")
        heading_texts.add(line)

if main_headings != list(range(1, 31)):
    errors.append(f"main section sequence is {main_headings!r}, expected 1..30")
if appendix_headings != list("ABCDE"):
    errors.append(f"appendix sequence is {appendix_headings!r}, expected A..E")

for match in re.finditer(r"\bSection (\d+)(?:\.\d+)*", spec_text):
    number = int(match.group(1))
    if not 1 <= number <= 30:
        errors.append(f"reference to nonexistent main Section {number}")
for match in re.finditer(r"\bAppendix ([A-Z])\b", spec_text):
    if match.group(1) not in "ABCDE":
        errors.append(f"reference to nonexistent Appendix {match.group(1)}")

for token in ("TODO", "TBD", "FIXME", "XXX"):
    if re.search(rf"\b{token}\b", spec_text):
        errors.append(f"unresolved marker in main spec: {token}")

required_phrases = (
    "TLS 1.3",
    "X25519MLKEM768",
    "RFC 9807",
    "OPAQUE",
    "RFC 9420",
    "Tor",
    "onion",
    "StateCore",
    "redb 4.2.0",
    "#![forbid(unsafe_code)]",
    "No task is detached",
    "profile_hash",
    expected_profile_hash,
    profile_token,
    e2ee_profile_token,
    "No novel security proof is a release requirement.",
    "QueryCursorBindingTBS",
    "process_cursor_key",
    "pending_storage_constructions",
    "NOTE STATS VALUE",
    "ACCTCRED COMPLETE 4342",
    "syntactically valid dummy `AuthFinish.ke3`",
    "There is deliberately no password reset",
    "FederationSessionHideKind.security_fenced",
    "uint64 account_service_response_count;",
    "uint64 previous_account_service_response_count;\n    uint64 resulting_account_service_response_count;",
    "uint64 cut_account_service_response_count;",
    "uint64 finalization_account_service_response_count;",
    "less than `2^-129`",
    "protocol-sources-and-decisions.md",
)
for phrase in required_phrases:
    if phrase not in spec_text:
        errors.append(f"required specification phrase missing: {phrase}")

expected_invariant_ranges = {
    "TRN": 6,
    "ID": 7,
    "AUTH": 11,
    "PRV": 4,
    "STA": 10,
    "E2E": 7,
    "FED": 13,
    "DUR": 12,
    "CON": 5,
    "OPS": 5,
}
expected_invariant_ids = {
    f"{prefix}-{number:02d}"
    for prefix, maximum in expected_invariant_ranges.items()
    for number in range(1, maximum + 1)
}
defined_invariant_ids = re.findall(
    r"^\| `([A-Z0-9]+-[0-9]{2})` \|", spec_text, re.MULTILINE
)
if len(defined_invariant_ids) != len(set(defined_invariant_ids)):
    errors.append("main specification repeats an invariant definition")
if set(defined_invariant_ids) != expected_invariant_ids:
    errors.append(
        "main invariant definitions are "
        f"{sorted(set(defined_invariant_ids))!r}, expected "
        f"{sorted(expected_invariant_ids)!r}"
    )

mandatory_capabilities_match = re.search(
    r"### 9\.3 Advertised capabilities.*?Every full node implements and advertises:\n\n"
    r"```text\n(?P<body>.*?)\n```",
    spec_text,
    re.DOTALL,
)
expected_mandatory_capabilities = {
    "account-notify", "account-tag", "away-notify", "batch", "cap-notify",
    "echo-message", "extended-join", "invite-notify", "labeled-response",
    "message-ids", "message-tags", "monitor", "multi-prefix",
    "sasl=AGENC-OPAQUE", "server-time", "setname", "standard-replies",
    "userhost-in-names", "utf8only", "agenc.ag/privacy=v1",
    "agenc.ag/account-controls=v1", "agenc.ag/account-credentials=v1",
    "agenc.ag/channel-controls=v1",
    "agenc.ag/recovery=v1.<22-char-recovery-epoch>",
}
if mandatory_capabilities_match is None:
    errors.append("mandatory capability block is missing")
else:
    mandatory_capabilities = mandatory_capabilities_match.group("body").split()
    if len(mandatory_capabilities) != len(set(mandatory_capabilities)):
        errors.append("mandatory capability block contains a duplicate")
    if set(mandatory_capabilities) != expected_mandatory_capabilities:
        errors.append(
            "mandatory capabilities are "
            f"{sorted(set(mandatory_capabilities))!r}, expected "
            f"{sorted(expected_mandatory_capabilities)!r}"
        )

traceability_match = re.search(
    r"## Appendix D\. Requirement traceability\n.*?"
    r"\| Required surface \| Normative definition \| Exact artifact/invariants \| Mandatory evidence \|\n"
    r"\| --- \| --- \| --- \| --- \|\n(?P<body>(?:\|[^\n]*\n)+)",
    spec_text,
    re.DOTALL,
)
expected_traceability_surfaces = [
    "historical/base behavior",
    "familiar channels/direct messages",
    "public/unlisted/secret discovery",
    "nicknames, display names, cloaks",
    "pseudonymous accounts",
    "private account service and OPAQUE",
    "simple onboarding/recovery",
    "TLS and WebSocket",
    "Tor and onion service",
    "metadata minimization",
    "MLS E2EE",
    "moderation/user safety",
    "abuse resistance",
    "federation authority",
    "federation transport/auth",
    "requests/idempotency and paged queries",
    "events/projections",
    "state ownership/concurrency",
    "persistence/recovery",
    "Rust module boundaries",
    "safe/legible Rust",
    "crypto/dependency policy",
    "configuration/admin",
    "observability/host hardening",
    "compatibility/versioning",
    "exhaustive release testing",
]
if traceability_match is None:
    errors.append("requirement traceability matrix is missing")
else:
    traceability_surfaces = [
        line.split("|", 2)[1].strip()
        for line in traceability_match.group("body").splitlines()
    ]
    if traceability_surfaces != expected_traceability_surfaces:
        errors.append(
            "traceability surfaces are "
            f"{traceability_surfaces!r}, expected "
            f"{expected_traceability_surfaces!r}"
        )

for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", spec_text):
    if "://" in target or target.startswith("#"):
        continue
    local_target = target.split("#", 1)[0]
    if local_target and not (spec.parent / local_target).is_file():
        errors.append(f"broken local Markdown target: {target}")

expected_reply_codes = {
    "ALREADY_AUTHENTICATED", "AUTH_REQUIRED", "BAD_SEQUENCE", "BAD_STATE",
    "CHALLENGE", "CHANGED", "CHANNEL_FULL", "CHECKPOINT", "CONFIRM", "CREATED",
    "DELETE_CHALLENGE", "E2EE_REQUIRED", "E2EE_SYNCING", "EVENT",
    "INVALID_ARGUMENT", "NETWORK_UNAVAILABLE", "NOT_ALLOWED",
    "ORIGIN_EXPIRED", "ORIGIN_GAP", "QUERY_EXPIRED", "RATE_LIMITED",
    "RECOVERY_EPOCH", "REGISTRATION_REQUIRED", "SECRET_UNAVAILABLE",
    "SERVER_BUSY", "SLOW_CONSUMER", "STALE_STATE", "STORAGE_UNAVAILABLE",
    "TOO_LARGE", "UNAVAILABLE", "UNSAFE_CTCP", "UPDATED", "VALUE",
}
expected_federation_failed_codes = {
    "ALREADY_AUTHENTICATED", "AUTH_REQUIRED", "BAD_SEQUENCE", "BAD_STATE",
    "CHANNEL_FULL", "E2EE_REQUIRED", "E2EE_SYNCING", "INVALID_ARGUMENT",
    "NOT_ALLOWED", "ORIGIN_EXPIRED", "ORIGIN_GAP", "QUERY_EXPIRED",
    "RATE_LIMITED", "REGISTRATION_REQUIRED", "SECRET_UNAVAILABLE",
    "SERVER_BUSY", "STALE_STATE", "STORAGE_UNAVAILABLE", "TOO_LARGE",
    "UNAVAILABLE",
}
federation_failed_mapping = registry_values.get(
    ("mapping", "federation-failed-reply-codes")
)
if federation_failed_mapping is None:
    errors.append("registry federation failed-reply mapping is missing")
else:
    federation_failed_codes = set(federation_failed_mapping.split(","))
    if federation_failed_codes != expected_federation_failed_codes:
        errors.append(
            "registry federation failed-reply codes are "
            f"{sorted(federation_failed_codes)!r}, expected "
            f"{sorted(expected_federation_failed_codes)!r}"
        )
    if not federation_failed_codes <= expected_reply_codes:
        errors.append("registry federation failed-reply mapping escapes base registry")
reply_registry_match = re.search(
    r"The closed base standard-reply code registry is:\n\n"
    r"```text\n(?P<codes>[A-Z0-9_\n ]+)\n```",
    spec_text,
)
if reply_registry_match is None:
    errors.append("closed base standard-reply registry block is missing")
else:
    reply_codes = set(reply_registry_match.group("codes").split())
    if reply_codes != expected_reply_codes:
        errors.append(
            f"base standard-reply codes are {sorted(reply_codes)!r}, expected "
            f"{sorted(expected_reply_codes)!r}"
        )

required_admin_frames = (
    "NOTE OPER CHALLENGE <admin-session-id> <challenge> <local-or-tls> "
    "<transport-binding> :Authenticate this administrative session",
    "NOTE STATS VALUE <selector> <field-name> <uint64> :Statistic value",
    "NOTE AUDIT CHECKPOINT <base64url-AdminAuditCheckpoint> :Audit checkpoint",
    "NOTE AUDIT EVENT <base64url-AdminAuditEvent> :Audit event",
)
for frame in required_admin_frames:
    if frame not in spec_text:
        errors.append(f"required administrative frame missing: {frame}")

if "| `storage.compaction_enabled` |" in spec_text:
    errors.append("removed storage.compaction_enabled key remains in schema")

config_prefixes = (
    "network|server|listeners|tls|federation|storage|accounts|limits|privacy|"
    "moderation|e2ee|admin"
)
referenced_config_keys = set(re.findall(
    rf"`((?:{config_prefixes})\.[a-z][a-z0-9_]*)`", spec_text
))
declared_config_keys = set(re.findall(
    rf"^\| `((?:{config_prefixes})\.[a-z][a-z0-9_]*)` \|",
    spec_text,
    re.MULTILINE,
))
limits_section_match = re.search(
    r"### C\.6 Resource and rate limits\n(?P<body>.*?)\n### C\.7 ",
    spec_text,
    re.DOTALL,
)
if limits_section_match is None:
    errors.append("configuration limits section is missing")
else:
    declared_config_keys.update(
        "limits." + key
        for key in re.findall(
            r"^\| `([a-z][a-z0-9_]*)` \|",
            limits_section_match.group("body"),
            re.MULTILINE,
        )
    )
unregistered_config_references = referenced_config_keys - declared_config_keys
if unregistered_config_references != {"storage.compaction_enabled"}:
    errors.append(
        "unregistered dotted configuration references are "
        f"{sorted(unregistered_config_references)!r}, expected only the "
        "deliberately rejected storage.compaction_enabled"
    )
if spec_text.count("`storage.compaction_enabled`") != 1:
    errors.append("removed storage.compaction_enabled must appear once in its rejection test")


def validate_markdown(
    path: Path,
    label: str,
    expected_sections: list[int],
    expected_appendices: list[str],
) -> str:
    if not path.is_file():
        errors.append(f"{label} is missing")
        return ""
    data = path.read_bytes()
    if b"\r" in data:
        errors.append(f"{label} contains CR")
    if not data.endswith(b"\n") or data.endswith(b"\n\n"):
        errors.append(f"{label} must end in exactly one LF")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as error:
        errors.append(f"{label} is not UTF-8: {error}")
        return ""
    lines = text.splitlines()
    if any(line.endswith((" ", "\t")) for line in lines):
        errors.append(f"{label} contains trailing whitespace")
    if sum(line.startswith("```") for line in lines) % 2:
        errors.append(f"{label} has an unbalanced fenced code block")

    outside_fence: list[bool] = []
    in_fence = False
    for line in lines:
        outside_fence.append(not in_fence and not line.startswith("```"))
        if line.startswith("```"):
            in_fence = not in_fence
    for index in range(len(lines) - 1):
        if not outside_fence[index] or not outside_fence[index + 1]:
            continue
        header = lines[index]
        separator = lines[index + 1]
        if not header.startswith("|") or not header.endswith("|"):
            continue
        if not separator.startswith("|") or not separator.endswith("|"):
            continue
        separator_cells = [
            cell.strip()
            for cell in re.split(r"(?<!\\)\|", separator[1:-1])
        ]
        if not separator_cells or not all(
            re.fullmatch(r":?-{3,}:?", cell) for cell in separator_cells
        ):
            continue
        expected_columns = len(separator_cells)
        header_columns = len(re.split(r"(?<!\\)\|", header[1:-1]))
        if header_columns != expected_columns:
            errors.append(
                f"{label} Markdown table header at line {index + 1} has "
                f"{header_columns} columns, separator has {expected_columns}"
            )
        row_index = index + 2
        while row_index < len(lines) and lines[row_index].startswith("|"):
            if not outside_fence[row_index] or not lines[row_index].endswith("|"):
                break
            row_columns = len(re.split(
                r"(?<!\\)\|", lines[row_index][1:-1]
            ))
            if row_columns != expected_columns:
                errors.append(
                    f"{label} Markdown table row at line {row_index + 1} has "
                    f"{row_columns} columns, expected {expected_columns}"
                )
            row_index += 1

    sections: list[int] = []
    appendices: list[str] = []
    headings: set[str] = set()
    for line_number, line in enumerate(lines, 1):
        match = re.fullmatch(r"## (\d+)\. .+", line)
        if match:
            sections.append(int(match.group(1)))
        match = re.fullmatch(r"## Appendix ([A-Z])\. .+", line)
        if match:
            appendices.append(match.group(1))
        if line.startswith("## "):
            if line in headings:
                errors.append(
                    f"duplicate {label} level-two heading at line "
                    f"{line_number}: {line}"
                )
            headings.add(line)
    if sections != expected_sections:
        errors.append(
            f"{label} section sequence is {sections!r}, expected "
            f"{expected_sections!r}"
        )
    if appendices != expected_appendices:
        errors.append(
            f"{label} appendix sequence is {appendices!r}, expected "
            f"{expected_appendices!r}"
        )

    for token in ("TODO", "TBD", "FIXME", "XXX"):
        if re.search(rf"\b{token}\b", text):
            errors.append(f"unresolved marker in {label}: {token}")
    for target in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
        if "://" in target or target.startswith("#"):
            continue
        local_target = target.split("#", 1)[0]
        if local_target and not (path.parent / local_target).is_file():
            errors.append(f"broken local Markdown target in {label}: {target}")
    return text


e2ee_text = validate_markdown(
    e2ee, "companion E2EE spec", list(range(1, 25)), list("AB")
)
sources_text = validate_markdown(
    sources, "protocol source ledger", list(range(1, 10)), []
)
for match in re.finditer(r"\bSection (\d+)(?:\.\d+)*", e2ee_text):
    number = int(match.group(1))
    if not 1 <= number <= 24:
        errors.append(f"companion reference to nonexistent main Section {number}")

required_e2ee_phrases = (
    "RFC 9852",
    "Suite `0x0004`, every other registered suite",
    '"agenc-chat ARC-MLS specification profile v1\\0"',
    "agenc.ag/e2ee-mls=v1,profile=<profile-hash>,seg=2940,obj=262144,parts=90,welcome=4194304",
    ":<server-name> ECAP ARCMLS OFFER 1 <profile-hash>",
    ":<server-name> ECAP ARCMLS ACK 1 <profile-hash>",
    "maximum generation width, and",
    "the OFFER is exactly at most 360 bytes and the ACK at most 358 bytes",
    "close the old link without draining its",
    "| 4,096 | 4,096 | 0 |",
    "| 4,097 | 5,120 | 1,023 |",
    "one byte too little/much padding",
    "protocol-sources-and-decisions.md",
)
for phrase in required_e2ee_phrases:
    if phrase not in e2ee_text:
        errors.append(f"required companion phrase missing: {phrase}")

if "agenc.ag/e2ee-mls=v1,seg=2940" in e2ee_text:
    errors.append("companion contains an unbound E2EE capability advertisement")

ecap_templates = {
    "OFFER": (
        ":<server-name> ECAP ARCMLS OFFER 1 <profile-hash> <network-id> "
        "<coordinator-server-id> 2940 262144 4194304 4094 4094 8191 "
        "<key-set-generation> <key-set-hash>"
    ),
    "ACK": (
        ":<server-name> ECAP ARCMLS ACK 1 <profile-hash> <network-id> "
        "<coordinator-server-id> 2940 262144 4194304 4094 4094 8191 "
        "<key-set-generation> <key-set-hash>"
    ),
}
for subcommand, template in ecap_templates.items():
    if e2ee_text.count(template) != 1:
        errors.append(f"companion must contain exactly one canonical ECAP {subcommand}")
    if len(template.split()) != 16:
        errors.append(f"validator ECAP {subcommand} template arity drifted")

max_prefix = ":" + ("s" * 126)
ecap_common = (
    " 1 " + ("p" * 43) + " " + ("n" * 43) + " " + ("c" * 22)
    + " 2940 262144 4194304 4094 4094 8191 " + ("9" * 20)
    + " " + ("k" * 43) + "\r\n"
)
expected_ecap_lengths = {"OFFER": 360, "ACK": 358}
for subcommand, expected_length in expected_ecap_lengths.items():
    rendered = max_prefix + " ECAP ARCMLS " + subcommand + ecap_common
    if len(rendered.encode("ascii")) != expected_length:
        errors.append(
            f"validator ECAP {subcommand} length is "
            f"{len(rendered.encode('ascii'))}, expected {expected_length}"
        )


def numbered(names: list[str]) -> list[tuple[str, int]]:
    return [(name, index) for index, name in enumerate(names, 1)]


expected_companion_enums = {
    "ArcWireObjectKind": numbered([
        "application_mls", "commit_mls", "commit_approval", "commit_ack",
        "finalization_request", "finalization_certificate", "abort_request",
        "abort_certificate", "welcome_mls", "root_identity",
        "root_identity_chain", "device_roster", "device_capabilities",
        "key_package_mls", "conversation_binding", "close_authorization",
        "reservation", "reinit_attempt", "staged_reinit", "reinit_ack",
        "reinit_activation_request", "reinit_activation_certificate",
        "reinit_abort_request", "reinit_abort_certificate",
        "sequencer_record", "device_attach_challenge", "device_attach",
        "root_binding_lock", "federation_state", "federation_origin",
        "federation_request", "federation_result", "federation_event",
        "policy", "recovery_submission", "witness_resolution",
        "leaf_membership_proof",
    ]),
    "ArcFederationOpcode": numbered([
        "application_channel", "application_direct", "reserve_channel",
        "reserve_direct", "bind_group", "query_channel", "query_direct",
        "close_group", "submit_candidate", "submit_authorization",
        "submit_commit_ack", "submit_finalization", "submit_abort",
        "submit_reinit_attempt", "submit_reinit_ack",
        "submit_reinit_activate", "submit_reinit_abort", "fetch_object",
        "fetch_authorizations", "fetch_acks", "fetch_receipts",
        "fetch_identity", "fetch_root_chain", "publish_identity",
        "fetch_roster", "publish_roster", "fetch_capabilities",
        "publish_capabilities", "fetch_binding_locks", "whoami",
        "attach_begin", "attach_finish", "claim_package", "claim_status",
        "publish_package", "revoke_package", "deliver_binding",
        "deliver_welcome", "fetch_mailbox", "acknowledge_mailbox",
        "submit_policy", "submit_recovery", "submit_recovery_element",
        "submit_membership",
    ]),
    "ArcFederationStoreKind": numbered([
        "store_authorization", "store_identity", "store_roster",
        "store_capabilities", "store_package", "store_application",
        "store_binding", "store_welcome", "store_staged_reinit",
        "store_policy", "store_membership",
    ]),
    "ArcFederationPendingKind": numbered([
        "pending_finalization", "pending_abort", "pending_reinit_attempt",
        "pending_reinit_activate", "pending_reinit_abort",
    ]),
    "ArcFederationEmptyKind": numbered([
        "empty_authorizations", "empty_acks", "empty_receipts",
        "empty_objects", "empty_identity", "empty_root_chain",
        "empty_roster", "empty_capabilities", "empty_package",
        "empty_application", "empty_binding", "empty_binding_lock",
        "empty_welcome", "empty_staged_reinit",
    ]),
    "ArcFederationPackageKind": [("normal_package", 1)],
    "ArcFederationMailboxKind": numbered([
        "mailbox_application", "mailbox_binding", "mailbox_welcome",
        "mailbox_staged_reinit",
    ]),
    "ArcFederationResultKind": numbered([
        "failed", "accepted_event", "bound", "closed", "stored",
        "commit_acked", "pending", "empty", "account", "attached",
        "attach_challenge", "revoked", "reserved", "finalized", "aborted",
        "claimed", "object_page", "mailbox_page", "reinit_staged",
        "reinit_acked", "reinit_activated", "reinit_aborted",
        "mailbox_acked", "recovery_accepted", "recovery_extended",
        "recovery_closed", "recovery_conflict",
    ]),
    "ArcFederationEventKind": numbered([
        "channel_application", "direct_application", "candidate_event",
        "commit_ack_event", "finalized_event", "aborted_event",
        "reinit_activated_event", "reinit_aborted_event", "closed_event",
        "route_state_changed", "request_completed", "route_state_hidden",
        "reinit_staged_event", "reinit_ack_event",
    ]),
    "ArcRouteStateKind": [
        ("active_route", 1), ("encrypted_tombstone", 2),
    ],
}

enum_pattern = re.compile(
    r"enum\s*\{(?P<body>[^}]*)\}\s*(?P<name>[A-Za-z][A-Za-z0-9_]*);",
    re.DOTALL,
)
companion_enums: dict[str, list[tuple[str, int]]] = {}
for enum_match in enum_pattern.finditer(e2ee_text):
    enum_name = enum_match.group("name")
    enum_body = enum_match.group("body")
    enum_items = [
        (name, int(value))
        for name, value in re.findall(r"([a-z][a-z0-9_]*)\((\d+)\)", enum_body)
    ]
    residue = re.sub(r"[a-z][a-z0-9_]*\(\d+\)", "", enum_body)
    if residue.replace(",", "").strip():
        errors.append(f"companion enum {enum_name} has unparsed syntax")
    if not enum_items:
        errors.append(f"companion enum {enum_name} has no variants")
    if len({name for name, _ in enum_items}) != len(enum_items):
        errors.append(f"companion enum {enum_name} repeats a variant")
    if len({value for _, value in enum_items}) != len(enum_items):
        errors.append(f"companion enum {enum_name} repeats a discriminant")
    if enum_name in companion_enums:
        errors.append(f"companion enum {enum_name} is defined more than once")
    companion_enums[enum_name] = enum_items

for enum_name, expected_items in expected_companion_enums.items():
    actual_items = companion_enums.get(enum_name)
    if actual_items != expected_items:
        errors.append(
            f"companion enum {enum_name} is {actual_items!r}, expected "
            f"{expected_items!r}"
        )

defined_irc_types = set(re.findall(
    r"}\s*(Arc[A-Z][A-Za-z0-9_]*)\s*;", e2ee_text
))
referenced_irc_types = set(re.findall(
    r"\b(Arc[A-Z][A-Za-z0-9_]*)\b", e2ee_text
))
if referenced_irc_types != defined_irc_types:
    errors.append(
        "companion Arc type definition/reference mismatch: undefined "
        f"{sorted(referenced_irc_types - defined_irc_types)!r}, unreferenced "
        f"{sorted(defined_irc_types - referenced_irc_types)!r}"
    )


def markdown_table(header: str) -> list[list[str]]:
    lines = e2ee_text.splitlines()
    indexes = [index for index, line in enumerate(lines) if line == header]
    if len(indexes) != 1:
        errors.append(
            f"companion table header {header!r} occurs {len(indexes)} times"
        )
        return []
    index = indexes[0]
    column_count = len(re.split(r"(?<!\\)\|", header[1:-1]))
    if index + 1 >= len(lines) or not lines[index + 1].startswith("| ---"):
        errors.append(f"companion table {header!r} has no separator")
        return []
    rows: list[list[str]] = []
    for line in lines[index + 2:]:
        if not line.startswith("|"):
            break
        cells = [
            cell.strip()
            for cell in re.split(r"(?<!\\)\|", line[1:-1])
        ]
        if len(cells) != column_count:
            errors.append(
                f"companion table {header!r} row has {len(cells)} columns, "
                f"expected {column_count}: {line}"
            )
            continue
        rows.append(cells)
    if not rows:
        errors.append(f"companion table {header!r} has no data rows")
    return rows


def require_exact_table_coverage(
    rows: list[list[str]],
    column: int,
    expected: set[str],
    label: str,
) -> None:
    covered: list[str] = []
    for row in rows:
        covered.extend(re.findall(r"`([a-z][a-z0-9_]*)`", row[column]))
    duplicates = sorted({item for item in covered if covered.count(item) > 1})
    if duplicates:
        errors.append(f"companion {label} repeats {duplicates!r}")
    if set(covered) != expected:
        errors.append(
            f"companion {label} covers {sorted(set(covered))!r}, expected "
            f"{sorted(expected)!r}"
        )


expected_signature_labels = {
    "ARC-MLS/1 root identity", "ARC-MLS/1 root continuity",
    "ARC-MLS/1 device enrollment possession",
    "ARC-MLS/1 device enrollment approval", "ARC-MLS/1 device certificate",
    "ARC-MLS/1 device roster", "ARC-MLS/1 device capabilities",
    "ARC-MLS/1 leaf authorization", "ARC-MLS/1 sequencer continuity",
    "ARC-MLS/1 policy approval", "ARC-MLS/1 conversation binding",
    "ARC-MLS/1 root binding lock", "ARC-MLS/1 commit authorization",
    "ARC-MLS/1 reinit attempt authorization", "ARC-MLS/1 reservation",
    "ARC-MLS/1 close authorization", "ARC-MLS/1 device attach challenge",
    "ARC-MLS/1 device attach possession", "ARC-MLS/1 candidate receipt",
    "ARC-MLS/1 commit processed", "ARC-MLS/1 disposition vote",
    "ARC-MLS/1 commit finalization", "ARC-MLS/1 candidate abort",
    "ARC-MLS/1 reinit attempt", "ARC-MLS/1 reinit attempt receipt",
    "ARC-MLS/1 reinit processed", "ARC-MLS/1 reinit disposition",
    "ARC-MLS/1 reinit activation", "ARC-MLS/1 reinit attempt abort",
    "ARC-MLS/1 recovery submission", "ARC-MLS/1 leaf membership",
    "ARC-MLS/1 leaf membership possession",
}
signature_rows = markdown_table("| Label | TBS content | Signing key |")
signature_labels: list[str] = []
for row in signature_rows:
    label_match = re.fullmatch(r"`(ARC-MLS/1 [a-z][a-z0-9 ]*)`", row[0])
    if label_match is None:
        errors.append(f"companion signature registry has malformed label {row[0]!r}")
        continue
    label = label_match.group(1)
    signature_labels.append(label)
    tbs_types = re.findall(r"`(Arc[A-Z][A-Za-z0-9_]*)`", row[1])
    if len(tbs_types) != 1 or tbs_types[0] not in defined_irc_types:
        errors.append(
            f"companion signature label {label!r} has invalid TBS cell {row[1]!r}"
        )
    if e2ee_text.count(label) < 2:
        errors.append(f"companion signature label {label!r} has no operational use")
if len(signature_labels) != len(set(signature_labels)):
    errors.append("companion signature registry repeats a label")
if set(signature_labels) != expected_signature_labels:
    errors.append(
        "companion signature labels are "
        f"{sorted(set(signature_labels))!r}, expected "
        f"{sorted(expected_signature_labels)!r}"
    )

expected_semantic_ids = [
    "root_fingerprint", "account_id_digest", "enrollment_id",
    "device_certificate_id", "roster_id", "capability_id",
    "leaf_signature_key_digest", "leaf_capabilities_digest", "safety_number",
    "conversation_id", "route_binding", "route_binding", "policy_id",
    "binding_id", "root_binding_lock_id", "semantic_route_lock_id",
    "sequencer_credential_id", "sequencer_key_set_digest",
    "initial_member_plan_id", "key_package_plan_id", "context_core_id",
    "context_digest", "close_intent_id", "close_id",
    "commit_authorization_id", "genesis_state_id", "candidate_id",
    "group_context_digest", "ratchet_tree_digest", "group_info_digest",
    "old_credential_hash", "resulting_leaf_credential_hash",
    "finalization_id", "abort_id", "target_context_digest",
    "initial_commit_digest", "reinit_attempt_authorization_id",
    "reinit_attempt_id", "reinit_activation_id", "reinit_abort_id",
    "federation_origin_state_id", "canonical_channel_name_hash",
    "federation_snapshot_digest", "acknowledgement_set_digest",
    "reinit_acknowledgement_set_digest", "recovery_submission_id",
    "leaf_membership_id",
]
semantic_rows = markdown_table("| ID or digest | Exact formula |")
semantic_ids: list[str] = []
semantic_sha_labels: set[str] = set()
for row in semantic_rows:
    identifiers = re.findall(r"`([a-z][a-z0-9_]*)`", row[0])
    if len(identifiers) != 1:
        errors.append(f"companion semantic registry has malformed ID cell {row[0]!r}")
        continue
    semantic_ids.append(identifiers[0])
    rendered_formula = row[1].replace(r"\|", "|")
    if not re.fullmatch(r"`SHA256\(.+\)`", rendered_formula):
        errors.append(
            f"companion semantic ID {identifiers[0]!r} lacks one exact SHA256 formula"
        )
    semantic_sha_labels.update(re.findall(
        r'SHA256\("(ARC-MLS/1 [^"]+)"', rendered_formula
    ))
if semantic_ids != expected_semantic_ids:
    errors.append(
        f"companion semantic-ID sequence is {semantic_ids!r}, expected "
        f"{expected_semantic_ids!r}"
    )
all_companion_sha_labels = set(re.findall(
    r'SHA256\("(ARC-MLS/1 [^"]+)"', e2ee_text
))
if semantic_sha_labels != all_companion_sha_labels:
    errors.append(
        "companion SHA256 domain registry mismatch: missing "
        f"{sorted(all_companion_sha_labels - semantic_sha_labels)!r}, extra "
        f"{sorted(semantic_sha_labels - all_companion_sha_labels)!r}"
    )

companion_limit_references = set(re.findall(
    r"\b(?:MAX|MIN|DEFAULT|ACKED)_[A-Z0-9_]+\b", e2ee_text
))
companion_limit_definitions = set(re.findall(
    r"^\| `((?:MAX|MIN|DEFAULT|ACKED)_[A-Z0-9_]+)` \|",
    e2ee_text,
    re.MULTILINE,
))
if companion_limit_references != companion_limit_definitions:
    errors.append(
        "companion named-limit definition/reference mismatch: undefined "
        f"{sorted(companion_limit_references - companion_limit_definitions)!r}, "
        "unreferenced "
        f"{sorted(companion_limit_definitions - companion_limit_references)!r}"
    )

opcode_names = {name for name, _ in expected_companion_enums["ArcFederationOpcode"]}
result_names = {name for name, _ in expected_companion_enums["ArcFederationResultKind"]}
event_names = {name for name, _ in expected_companion_enums["ArcFederationEventKind"]}
wire_kind_names = {name for name, _ in expected_companion_enums["ArcWireObjectKind"]}

operation_rows = markdown_table(
    "| Opcode | Parameter fields in exact order | Required payload kind |"
)
require_exact_table_coverage(
    operation_rows, 0, opcode_names, "federation operation table"
)
for row in operation_rows:
    payload_kinds = set(re.findall(r"`([a-z][a-z0-9_]*)`", row[2]))
    unknown_payload_kinds = payload_kinds - wire_kind_names
    if unknown_payload_kinds:
        errors.append(
            "companion operation table has unknown payload kinds "
            f"{sorted(unknown_payload_kinds)!r}"
        )

result_rows = markdown_table("| Result kind | Exact fields in order |")
require_exact_table_coverage(
    result_rows, 0, result_names, "federation result-shape table"
)

success_rows = markdown_table(
    "| Opcode | Permitted success result | Completion |"
)
require_exact_table_coverage(
    success_rows, 0, opcode_names, "federation success/completion table"
)
for row in success_rows:
    for semantic_event in re.findall(r"semantic:([a-z][a-z0-9_]*)", row[2]):
        if semantic_event not in event_names:
            errors.append(
                f"companion completion table names unknown event {semantic_event}"
            )

event_rows = markdown_table(
    "| Event kind | Required data object | `encoded_event_result` |"
)
require_exact_table_coverage(
    event_rows, 0, event_names, "federation event-selector table"
)
for row in event_rows:
    data_kinds = set(re.findall(r"`([a-z][a-z0-9_]*)`", row[1]))
    unknown_data_kinds = data_kinds - wire_kind_names
    if unknown_data_kinds:
        errors.append(
            "companion event table has unknown data kinds "
            f"{sorted(unknown_data_kinds)!r}"
        )

expected_companion_reply_codes = {
    "E2EE_CAP_REQUIRED", "E2EE_ACCOUNT_REQUIRED", "E2EE_DEVICE_REQUIRED",
    "E2EE_INVALID_FRAGMENT", "E2EE_OBJECT_TOO_LARGE",
    "E2EE_REASSEMBLY_LIMIT", "E2EE_HASH_MISMATCH", "E2EE_ROUTE_INVALID",
    "E2EE_GROUP_CONFLICT", "E2EE_BINDING_AUTH_INVALID",
    "E2EE_CANDIDATE_ACTIVE", "E2EE_FINALITY_REQUIRED", "E2EE_EPOCH_STALE",
    "E2EE_OBJECT_NOT_FOUND", "E2EE_RATE_LIMITED", "E2EE_KEY_UNAVAILABLE",
    "E2EE_OPERATION_CONFLICT", "E2EE_DELIVERY_UNCERTAIN", "E2EE_SYNCING",
    "E2EE_REQUIRED", "E2EE_POLICY_INVALID", "E2EE_POLICY_REQUIRED",
}
reply_rows = markdown_table("| Code | Meaning |")
companion_reply_codes = {
    match.group(1)
    for row in reply_rows
    if (match := re.fullmatch(r"`([A-Z][A-Z0-9_]*)`", row[0])) is not None
}
if companion_reply_codes != expected_companion_reply_codes:
    errors.append(
        "companion reply registry is "
        f"{sorted(companion_reply_codes)!r}, expected "
        f"{sorted(expected_companion_reply_codes)!r}"
    )

required_failed_result_phrase = (
    "A failed result has\n`coordinator_state_generation=0`, an empty completion "
    "Event ID, empty snapshot"
)
if required_failed_result_phrase not in e2ee_text:
    errors.append("companion failed-result zero-state contract is missing")

required_source_phrases = (
    "RFC 9846 | Proposed Standard",
    "RFC 9852 | BCP 195",
    "RFC 9807 | Informational IRTF/CFRG",
    "RFC 10024 | Proposed Standard",
    "draft-ietf-mls-pq-ciphersuites-06",
    "bc5ebcad4d5545efc9a527ee33ec039c66d7cdf3",
    "202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed",
    "0d41d731c7d2f962d1ccc364cec258de3c0e93b38c2fb3ba97ac74513048d634",
    "no production compaction call",
    "random-salt collision claim an explicit bound",
    "specification-manifest.txt",
)
for phrase in required_source_phrases:
    if phrase not in sources_text:
        errors.append(f"required source-ledger phrase missing: {phrase}")

if errors:
    for error in errors:
        print(f"ERROR: {error}", file=sys.stderr)
    raise SystemExit(1)

print(
    "spec checks passed: "
    f"{len(spec_lines)} main lines, {len(e2ee_text.splitlines())} companion "
    f"lines, {len(registry_lines)} registry entries, base profile "
    f"{profile_hash}, E2EE profile {e2ee_profile_hash}"
)
PY
