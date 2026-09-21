#!/usr/bin/env python3
"""Generate independent companion-object vectors for the Stage 08 gates.

This generator is deliberately separate from the Rust codec: it encodes the
TLS presentation language, computes semantic identifiers, and signs with
Ed25519 through the `cryptography` package. The Rust crate must decode
every vector, recompute every identifier, and verify every signature. Keys
are derived from fixed seeds so the output is reproducible.

Two sets are written. The identity set under `test-data/vectors/e2ee/identity`
covers Section 8 objects. The recovery set under
`test-data/vectors/e2ee/recovery` covers the Section 12.5.1 witness
resolution, the Section 13.7.3 leaf-membership proof and the Section 13.7.4
recovery submission as complete `ArcWireObject` envelopes, with sequencer
records and a close authorization as elements. The recovery set is
synthetic public-envelope evidence: its chain is structurally valid under the
contract's encoding, identifier and signature rules, but it is not a real
MLS endpoint transcript, and its Rust consumers belong to ENC-02 through
ENC-05.

Usage: python3 scripts/generate-e2ee-vectors.py [--check]
"""

from __future__ import annotations

import hashlib
import struct
import sys
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parent.parent
OUTPUT = ROOT / "test-data/vectors/e2ee/identity"
RECOVERY_OUTPUT = ROOT / "test-data/vectors/e2ee/recovery"

NETWORK = bytes([1] * 32)
ACCOUNT = b"a" * 24

# --- TLS presentation encoding -------------------------------------------


def width_for(maximum: int) -> int:
    if maximum <= 0xFF:
        return 1
    if maximum <= 0xFFFF:
        return 2
    if maximum <= 0xFFFFFF:
        return 3
    return 4


def opaque(data: bytes, maximum: int) -> bytes:
    return len(data).to_bytes(width_for(maximum), "big") + data


def vector(items: list[bytes], maximum: int) -> bytes:
    return opaque(b"".join(items), maximum)


def u8(value: int) -> bytes:
    return struct.pack(">B", value)


def u16(value: int) -> bytes:
    return struct.pack(">H", value)


def u32(value: int) -> bytes:
    return struct.pack(">I", value)


def u64(value: int) -> bytes:
    return struct.pack(">Q", value)


# --- signatures and identifiers ---------------------------------------------


def key(seed: int) -> Ed25519PrivateKey:
    return Ed25519PrivateKey.from_private_bytes(bytes([seed] * 32))


def public(private: Ed25519PrivateKey) -> bytes:
    from cryptography.hazmat.primitives import serialization

    return private.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )


def irc_signature_input(label: str, content: bytes) -> bytes:
    """`ArcSignatureInput { opaque label<1..255>; opaque content<0..2^24-1>; }`."""
    return opaque(label.encode(), 255) + opaque(content, 0xFFFFFF)


def sign(private: Ed25519PrivateKey, label: str, tbs: bytes) -> bytes:
    return private.sign(irc_signature_input(f"ARC-MLS/1 {label}", tbs))


def semantic_id(label: str, encoding: bytes) -> bytes:
    return hashlib.sha256(f"ARC-MLS/1 {label}".encode() + encoding).digest()


def mls_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    return (value | 0x8000_0000).to_bytes(4, "big")


def opaque_v(data: bytes) -> bytes:
    return mls_varint(len(data)) + data


def mls_sign(private: Ed25519PrivateKey, label: str, content: bytes) -> bytes:
    """RFC 9420 `SignWithLabel`: `SignContent { "MLS 1.0 " || label, content }`."""
    full = ("MLS 1.0 " + label).encode()
    return private.sign(opaque_v(full) + opaque_v(content))


# --- objects -----------------------------------------------------------------

ROOT_INTERVAL = (0, 2_000_000)
ROSTER_INTERVAL = (100, 100 + 6 * 24 * 3600)


def root_tbs(private: Ed25519PrivateKey, generation: int, interval: tuple[int, int], previous_fp: bytes) -> bytes:
    return (
        u16(1)
        + NETWORK
        + opaque(ACCOUNT, 255)
        + u64(generation)
        + public(private)
        + u64(interval[0])
        + u64(interval[1])
        + previous_fp
    )


def root_identity(private: Ed25519PrivateKey, generation: int, interval: tuple[int, int], previous: tuple[Ed25519PrivateKey, bytes] | None) -> tuple[bytes, bytes]:
    previous_fp = semantic_id("root fingerprint", previous[1]) if previous else bytes(32)
    tbs = root_tbs(private, generation, interval, previous_fp)
    continuity = sign(previous[0], "root continuity", tbs) if previous else b""
    return tbs, tbs + sign(private, "root identity", tbs) + opaque(continuity, 64)


def certificate(root_private: Ed25519PrivateKey, root_fp: bytes, device_seed: int, serial: int, target_generation: int) -> tuple[bytes, bytes]:
    device = key(device_seed)
    enrollment_tbs = (
        u16(1)
        + NETWORK
        + opaque(ACCOUNT, 255)
        + u64(0)
        + root_fp
        + u64(target_generation)
        + bytes([device_seed + 100] * 32)
        + bytes([device_seed] * 16)
        + public(device)
        + u64(90)
        + u64(100)
    )
    enrollment = (
        enrollment_tbs
        + sign(device, "device enrollment possession", enrollment_tbs)
        + sign(root_private, "device enrollment approval", enrollment_tbs)
    )
    tbs = (
        u16(1)
        + NETWORK
        + opaque(ACCOUNT, 255)
        + u64(0)
        + root_fp
        + bytes([device_seed] * 16)
        + public(device)
        + u64(target_generation)
        + bytes([device_seed + 100] * 32)
        + semantic_id("enrollment id", enrollment_tbs)
        + u64(serial)
        + u32(3)
        + u64(0)
        + u64(1_000_000)
    )
    return tbs, tbs + enrollment + sign(root_private, "device certificate", tbs)


def roster(root_private: Ed25519PrivateKey, root_fp: bytes, certificates: list[tuple[int, bytes]]) -> tuple[bytes, bytes]:
    active = [bytes([seed] * 16) + encoded for seed, encoded in certificates]
    tbs = (
        u16(1)
        + NETWORK
        + opaque(ACCOUNT, 255)
        + u64(0)
        + root_fp
        + u64(0)
        + u64(ROSTER_INTERVAL[0])
        + u64(ROSTER_INTERVAL[1])
        + bytes(32)
        + vector(active, 65_535)
        + vector([], 65_535)
    )
    return tbs, tbs + sign(root_private, "device roster", tbs)


def capabilities(device_seed: int, root_fp: bytes, roster_id: bytes) -> tuple[bytes, bytes]:
    device = key(device_seed)
    tbs = (
        u16(1)
        + NETWORK
        + opaque(ACCOUNT, 255)
        + root_fp
        + u64(0)
        + roster_id
        + bytes([device_seed] * 16)
        + u64(0)
        + bytes(32)
        + u64(100)
        + u64(200)
        + vector([u16(1)], 32)
        + vector([u16(1), u16(3)], 64)
        + vector([u16(0xF1C1), u16(0xF1C3)], 128)
        + vector([u16(0xF1C2)], 128)
        + vector([u16(1)], 32)
    )
    return tbs, tbs + sign(device, "device capabilities", tbs)


CAPABILITY_VECTORS = [u16(1), u16(1) + u16(3), b"", b"", u16(1)]


def encoded_capabilities() -> bytes:
    return b"".join(opaque_v(item) for item in CAPABILITY_VECTORS)


def leaf_authorization(device_seed: int, leaf_seed: int, root_fp: bytes, roster_id: bytes) -> tuple[bytes, bytes]:
    device = key(device_seed)
    tbs = (
        u16(1)
        + NETWORK
        + opaque(ACCOUNT, 255)
        + u64(0)
        + root_fp
        + u64(0)
        + roster_id
        + bytes([device_seed] * 16)
        + u64(0)
        + u16(1)
        + u16(1)
        + u16(0x0807)
        + opaque(public(key(leaf_seed)), 255)
        + semantic_id("leaf capabilities", encoded_capabilities())
        + bytes([leaf_seed] * 32)
        + u8(0)
        + u64(100)
        + u64(1000)
    )
    return tbs, tbs + sign(device, "leaf authorization", tbs)


def key_package(identity: bytes, leaf_seed: int) -> bytes:
    leaf_private = key(leaf_seed)
    leaf = (
        opaque_v(bytes([11] * 32))
        + opaque_v(public(leaf_private))
        + u16(1)
        + opaque_v(identity)
        + encoded_capabilities()
        + u8(1)
        + u64(100)
        + u64(1000)
        + opaque_v(b"")
    )
    leaf += opaque_v(mls_sign(leaf_private, "LeafNodeTBS", leaf))
    tbs = u16(1) + u16(1) + opaque_v(bytes([12] * 32)) + leaf + opaque_v(b"")
    return u16(1) + u16(5) + tbs + opaque_v(mls_sign(leaf_private, "KeyPackageTBS", tbs))


def build() -> tuple[dict[str, bytes], dict[str, str]]:
    files, ids, _ = build_identity()
    return files, ids


def build_identity() -> tuple[dict[str, bytes], dict[str, str], dict[str, object]]:
    root_private = key(40)
    root0_tbs, root0 = root_identity(root_private, 0, ROOT_INTERVAL, None)
    root_fp = semantic_id("root fingerprint", root0_tbs)
    successor_private = key(2)
    root1_tbs, root1 = root_identity(successor_private, 1, (500, 3_000_000), (root_private, root0_tbs))
    cert7_tbs, cert7 = certificate(root_private, root_fp, 7, 1, 0)
    cert8_tbs, cert8 = certificate(root_private, root_fp, 8, 1, 0)
    roster_tbs, roster_bytes = roster(root_private, root_fp, [(7, cert7), (8, cert8)])
    roster_id = semantic_id("roster id", roster_tbs)
    caps_tbs, caps = capabilities(7, root_fp, roster_id)
    leaf_tbs, leaf = leaf_authorization(7, 30, root_fp, roster_id)
    bundle = root0 + cert7 + leaf
    package = key_package(bundle, 30)
    chain = opaque(ACCOUNT, 255) + vector([root0, root1], 1_048_576)
    files = {
        "root-generation-0.bin": root0,
        "root-generation-1.bin": root1,
        "root-chain.bin": chain,
        "certificate-7.bin": cert7,
        "roster.bin": roster_bytes,
        "capabilities-7.bin": caps,
        "leaf-authorization-7.bin": leaf,
        "credential-bundle-7.bin": bundle,
        "key-package-7.bin": package,
    }
    ids = {
        "root_fingerprint": root_fp.hex(),
        "successor_root_fingerprint": semantic_id("root fingerprint", root1_tbs).hex(),
        "certificate_7_id": semantic_id("device certificate id", cert7_tbs).hex(),
        "certificate_8_id": semantic_id("device certificate id", cert8_tbs).hex(),
        "roster_id": roster_id.hex(),
        "capability_7_id": semantic_id("capability id", caps_tbs).hex(),
        "leaf_7_signature_key": public(key(30)).hex(),
        "leaf_7_capabilities_hash": semantic_id("leaf capabilities", encoded_capabilities()).hex(),
        "leaf_authorization_tbs_sha256": hashlib.sha256(leaf_tbs).hexdigest(),
    }
    cert8_leaf_tbs, cert8_leaf = leaf_authorization(8, 31, root_fp, roster_id)
    state = {
        "root_fp": root_fp,
        "roster_id": roster_id,
        "cert7_id": semantic_id("device certificate id", cert7_tbs),
        "cert8_id": semantic_id("device certificate id", cert8_tbs),
        "bundle_7": bundle,
        "bundle_8": root0 + cert8 + cert8_leaf,
    }
    return files, ids, state


# --- recovery, membership and witness-resolution set --------------------------

# ArcWireObjectKind discriminants used by the recovery set.
KIND_COMMIT_ACK = 4
KIND_CLOSE_AUTHORIZATION = 16
KIND_SEQUENCER_RECORD = 25
KIND_RECOVERY_SUBMISSION = 35
KIND_WITNESS_RESOLUTION = 36
KIND_LEAF_MEMBERSHIP_PROOF = 37
KIND_NAMES = {
    KIND_COMMIT_ACK: "commit_ack",
    KIND_CLOSE_AUTHORIZATION: "close_authorization",
    KIND_SEQUENCER_RECORD: "sequencer_record",
    KIND_RECOVERY_SUBMISSION: "recovery_submission",
    KIND_WITNESS_RESOLUTION: "witness_resolution",
    KIND_LEAF_MEMBERSHIP_PROOF: "leaf_membership_proof",
}
CANDIDATE_RECORD = 1  # ArcSequencerRecordKind.candidate_record
RECORD_ELEMENT, CLOSE_ELEMENT = 1, 2  # ArcRecoveryElementKind
CONTINUING, REMOVED = 1, 2  # ArcLeafDispositionKind
ED25519_SCHEME = 0x0807

CONVERSATION = bytes([0x43] * 32)
OTHER_CONVERSATION = bytes([0x44] * 32)
RECOVERY_EPOCH = bytes([0x45] * 16)
RESTORED_BINDING = bytes([0x46] * 32)
RESTORED_STATE = bytes([0x47] * 32)
ANCHOR = bytes([0x48] * 32)  # restored head: the ReInit activation anchor
GUARD = bytes([0x49] * 32)
WITNESSED_HEAD = bytes([0x4A] * 32)
RESOLUTION_TOKEN = bytes([0x4B] * 16)
COORDINATOR_SID = bytes([0x4C] * 16)
EDGE_SID = bytes([0x4D] * 16)
REMOVAL_FINALIZATION = bytes([0x4E] * 32)
SEQUENCER_SEED = 50


def wire_object(kind: int, body: bytes) -> bytes:
    """`ArcWireObject { uint16 profile_version; ArcWireObjectKind kind; opaque body<1..4194298>; }`."""
    return u16(1) + u8(kind) + opaque(body, 4_194_298)


def object_id(encoded: bytes) -> bytes:
    return hashlib.sha256(encoded).digest()


def sequencer_key_id() -> bytes:
    tbs = u16(1) + NETWORK + u64(0) + public(key(SEQUENCER_SEED)) + u64(0) + u64(4_000_000) + bytes(32)
    return semantic_id("sequencer key", tbs)


def candidate_receipt(route_sequence: int, predecessor: bytes, commit_seed: int, prior_epoch: int) -> tuple[bytes, bytes]:
    tbs = (
        u16(1)
        + NETWORK
        + CONVERSATION
        + u64(route_sequence)
        + u64(prior_epoch)
        + u64(prior_epoch + 1)
        + u32(0)
        + bytes([commit_seed] * 32)
        + predecessor
        + predecessor
        + u64(1_700_000_000 + route_sequence)
        + sequencer_key_id()
    )
    return tbs, tbs + sign(key(SEQUENCER_SEED), "candidate receipt", tbs)


def sequencer_record_object(receipt: bytes) -> bytes:
    return wire_object(KIND_SEQUENCER_RECORD, u8(CANDIDATE_RECORD) + receipt)


def close_authorization(state: dict[str, object], authorizing_terminal_id: bytes) -> tuple[bytes, bytes]:
    intent = u16(1) + u64(1_700_000_100)
    tbs = (
        u16(1)
        + NETWORK
        + CONVERSATION
        + RESTORED_BINDING
        + authorizing_terminal_id
        + intent
        + semantic_id("close intent id", intent)
    )
    approvals = b"".join(
        state["root_fp"] + bytes([seed] * 16) + state[f"cert{seed}_id"] + sign(key(seed), "close authorization", tbs)
        for seed in (7, 8)
    )
    return tbs, tbs + opaque(approvals, 16_384)


def submission(
    element_kind: int,
    element_object_kind: int,
    element: bytes,
    route_sequence: int,
    predecessor: bytes,
    *,
    device_seed: int = 7,
    conversation: bytes = CONVERSATION,
    recovery_epoch: bytes = RECOVERY_EPOCH,
    guard: bytes = GUARD,
    restored_head: bytes = ANCHOR,
) -> tuple[bytes, bytes]:
    tbs = (
        u16(1)
        + NETWORK
        + conversation
        + recovery_epoch
        + RESTORED_BINDING
        + RESTORED_STATE
        + restored_head
        + guard
        + u64(route_sequence)
        + predecessor
        + u8(element_kind)
        + u8(element_object_kind)
        + object_id(element)
        + opaque(ACCOUNT, 255)
        + bytes([device_seed] * 16)
    )
    return tbs, wire_object(KIND_RECOVERY_SUBMISSION, tbs + sign(key(device_seed), "recovery submission", tbs))


def old_credential_hash(bundle: bytes) -> bytes:
    return semantic_id("old credential hash", opaque_v(bundle))


def membership_proof(
    state: dict[str, object],
    device_seed: int,
    leaf_seed: int,
    leaf_index: int,
    disposition: int,
    *,
    credential_bundle: bytes,
    epoch: int = 3,
) -> tuple[bytes, bytes]:
    tbs = (
        u16(1)
        + NETWORK
        + CONVERSATION
        + u64(epoch)
        + u32(leaf_index)
        + old_credential_hash(credential_bundle)
        + u16(ED25519_SCHEME)
        + opaque(public(key(leaf_seed)), 255)
        + opaque(ACCOUNT, 255)
        + bytes([device_seed] * 16)
        + u64(0)
        + state["root_fp"]
        + u64(0)
        + state["roster_id"]
        + u64(0)
        + u8(disposition)
        + (REMOVAL_FINALIZATION if disposition == REMOVED else bytes(32))
    )
    possession = sign(key(leaf_seed), "leaf membership possession", tbs) if disposition == CONTINUING else b""
    body = tbs + sign(key(device_seed), "leaf membership", tbs) + opaque(possession, 255)
    return tbs, wire_object(KIND_LEAF_MEMBERSHIP_PROOF, body)


def commit_ack(leaf_seed: int, leaf_index: int, credential_bundle: bytes, candidate_id: bytes) -> bytes:
    tbs = (
        u16(1)
        + NETWORK
        + CONVERSATION
        + u64(3)
        + candidate_id
        + bytes([0x51] * 32)
        + u32(leaf_index)
        + old_credential_hash(credential_bundle)
        + u64(4)
        + bytes([0x52] * 32)
        + bytes([0x53] * 32)
        + bytes([0x54] * 32)
    )
    return wire_object(KIND_COMMIT_ACK, tbs + opaque(sign(key(leaf_seed), "commit processed", tbs), 255))


def witness_resolution(entries: list[bytes], expected_sequence: int, expected_head: bytes, new_head_sequence: int, new_head: bytes) -> bytes:
    body = (
        u16(1)
        + NETWORK
        + COORDINATOR_SID
        + EDGE_SID
        + CONVERSATION
        + RESOLUTION_TOKEN
        + u64(expected_sequence)
        + expected_head
        + u32(len(entries))
        + u64(new_head_sequence)
        + new_head
        + opaque(b"".join(object_id(entry) for entry in entries), 32_768)
    )
    return wire_object(KIND_WITNESS_RESOLUTION, body)


def build_recovery(state: dict[str, object]) -> list[dict[str, object]]:
    """Return ordered vector records: name, kind, bytes, ids, seeds and disposition."""
    bundle_7 = state["bundle_7"]
    bundle_8 = state["bundle_8"]
    vectors: list[dict[str, object]] = []

    def add(name: str, kind: int, data: bytes, disposition: str, **ids: bytes | str) -> None:
        vectors.append({"name": name, "kind": kind, "data": data, "disposition": disposition, "ids": ids})

    continuing_tbs, continuing = membership_proof(state, 7, 30, 0, CONTINUING, credential_bundle=bundle_7)
    add(
        "membership-continuing.bin", KIND_LEAF_MEMBERSHIP_PROOF, continuing,
        "accepted: STORED MEMBERSHIP; continuing proof for leaf 0 held by device 7",
        leaf_membership_id=semantic_id("leaf membership id", continuing_tbs),
        device_seed="7", leaf_seed="30",
    )
    removed_tbs, removed = membership_proof(state, 8, 31, 1, REMOVED, credential_bundle=bundle_8)
    add(
        "membership-removed.bin", KIND_LEAF_MEMBERSHIP_PROOF, removed,
        "accepted: STORED MEMBERSHIP; removed proof for leaf 1 held by device 8, empty possession field",
        leaf_membership_id=semantic_id("leaf membership id", removed_tbs),
        device_seed="8", leaf_seed="31",
    )

    receipt_a_tbs, receipt_a = candidate_receipt(1, ANCHOR, 0x61, 3)
    candidate_a = semantic_id("candidate id", receipt_a_tbs)
    element_a = sequencer_record_object(receipt_a)
    sub1_tbs, sub1 = submission(RECORD_ELEMENT, KIND_SEQUENCER_RECORD, element_a, 1, ANCHOR)
    add(
        "submission-01-anchor.bin", KIND_RECOVERY_SUBMISSION, sub1,
        "accepted: RECOVERY-ACCEPTED; first submission at the empty head, route sequence 1 after the activation anchor",
        recovery_submission_id=semantic_id("recovery submission id", sub1_tbs), element_object_id=object_id(element_a), device_seed="7",
    )
    add(
        "element-01-candidate.bin", KIND_SEQUENCER_RECORD, element_a,
        "accepted: RECOVERY-EXTENDED; candidate A becomes the head at route sequence 1, gate stays pending",
        candidate_id=candidate_a, sequencer_seed=str(SEQUENCER_SEED),
    )

    close_tbs, close = close_authorization(state, candidate_a)
    close_object = wire_object(KIND_CLOSE_AUTHORIZATION, close)
    sub2_tbs, sub2 = submission(CLOSE_ELEMENT, KIND_CLOSE_AUTHORIZATION, close_object, 2, candidate_a)
    add(
        "submission-02-close.bin", KIND_RECOVERY_SUBMISSION, sub2,
        "accepted: RECOVERY-ACCEPTED; close element at route sequence 2 after candidate A",
        recovery_submission_id=semantic_id("recovery submission id", sub2_tbs), element_object_id=object_id(close_object), device_seed="7",
    )
    add(
        "element-02-close.bin", KIND_CLOSE_AUTHORIZATION, close_object,
        "accepted: RECOVERY-CLOSED; the close ID becomes the head at route sequence 2 and the gate installs closed; "
        "synthetic: authorizing_terminal_id names the head record rather than a real finalization certificate",
        close_id=semantic_id("close authorization id", close_tbs), approver_seeds="7,8",
    )

    receipt_b_tbs, receipt_b = candidate_receipt(1, ANCHOR, 0x62, 3)
    candidate_b = semantic_id("candidate id", receipt_b_tbs)
    element_b = sequencer_record_object(receipt_b)
    sub3a_tbs, sub3a = submission(RECORD_ELEMENT, KIND_SEQUENCER_RECORD, element_a, 1, ANCHOR, device_seed=8)
    sub3b_tbs, sub3b = submission(RECORD_ELEMENT, KIND_SEQUENCER_RECORD, element_b, 1, ANCHOR, device_seed=8)
    add(
        "submission-03-fork-a.bin", KIND_RECOVERY_SUBMISSION, sub3a,
        "accepted: RECOVERY-ACCEPTED; fork branch A at route sequence 1, submitted by device 8",
        recovery_submission_id=semantic_id("recovery submission id", sub3a_tbs), element_object_id=object_id(element_a), device_seed="8",
    )
    add(
        "element-03-fork-a.bin", KIND_SEQUENCER_RECORD, element_a,
        "accepted: RECOVERY-EXTENDED; candidate A installed at route sequence 1",
        candidate_id=candidate_a, sequencer_seed=str(SEQUENCER_SEED),
    )
    add(
        "submission-03-fork-b.bin", KIND_RECOVERY_SUBMISSION, sub3b,
        "accepted: RECOVERY-ACCEPTED; fork branch B at route sequence 1, same predecessor as branch A",
        recovery_submission_id=semantic_id("recovery submission id", sub3b_tbs), element_object_id=object_id(element_b), device_seed="8",
    )
    add(
        "element-03-fork-b.bin", KIND_SEQUENCER_RECORD, element_b,
        "accepted: RECOVERY-CONFLICT naming candidate A and candidate B; a second record valid under the same committed credential "
        "at an installed position installs conflict permanently",
        candidate_id=candidate_b, sequencer_seed=str(SEQUENCER_SEED),
    )

    entry_tbs, entry_receipt = candidate_receipt(5, WITNESSED_HEAD, 0x63, 7)
    entry = sequencer_record_object(entry_receipt)
    entry_id = semantic_id("candidate id", entry_tbs)
    begin = witness_resolution([entry], 5, WITNESSED_HEAD, 5, entry_id)
    add(
        "witness-resolution-begin.bin", KIND_WITNESS_RESOLUTION, begin,
        "accepted: EWITNESS BEGIN object; one record extends the witnessed head at expected sequence 5, new head equals the entry candidate ID",
        entry_object_id=object_id(entry), new_head_id=entry_id,
    )
    add(
        "witness-resolution-entry.bin", KIND_SEQUENCER_RECORD, entry,
        "accepted: EWITNESS ENTRY 0; the edge installs (5, new_head_id) and deletes the witness row before RESOLVED",
        candidate_id=entry_id, sequencer_seed=str(SEQUENCER_SEED),
    )

    _, wrong_guard = submission(RECORD_ELEMENT, KIND_SEQUENCER_RECORD, element_a, 1, ANCHOR, guard=bytes([0x99] * 32))
    add("reject-wrong-guard.bin", KIND_RECOVERY_SUBMISSION, wrong_guard,
        "rejected: E2EE_ROUTE_INVALID; source_rollback_guard_hash differs from the durable gate", device_seed="7")
    _, wrong_epoch = submission(RECORD_ELEMENT, KIND_SEQUENCER_RECORD, element_a, 1, ANCHOR, recovery_epoch=bytes([0x99] * 16))
    add("reject-wrong-epoch.bin", KIND_RECOVERY_SUBMISSION, wrong_epoch,
        "rejected: E2EE_ROUTE_INVALID; recovery_epoch differs from the durable gate", device_seed="7")
    _, wrong_head = submission(RECORD_ELEMENT, KIND_SEQUENCER_RECORD, element_a, 1, ANCHOR, restored_head=bytes([0x99] * 32))
    add("reject-wrong-head.bin", KIND_RECOVERY_SUBMISSION, wrong_head,
        "rejected: E2EE_ROUTE_INVALID; restored_sequencer_head_id differs from the durable gate", device_seed="7")
    _, unrelated = submission(RECORD_ELEMENT, KIND_SEQUENCER_RECORD, element_a, 1, ANCHOR, conversation=OTHER_CONVERSATION)
    add("reject-unrelated-context.bin", KIND_RECOVERY_SUBMISSION, unrelated,
        "rejected: E2EE_ROUTE_INVALID; conversation_id names an unrelated conversation and context", device_seed="7")

    _, revoked = membership_proof(state, 9, 32, 2, CONTINUING, credential_bundle=bundle_7)
    add("reject-revoked-device.bin", KIND_LEAF_MEMBERSHIP_PROOF, revoked,
        "rejected: E2EE_DEVICE_REQUIRED; device 9 is not active in the roster named by roster_id", device_seed="9", leaf_seed="32")
    _, duplicate = membership_proof(state, 8, 30, 0, CONTINUING, credential_bundle=bundle_7)
    add("reject-duplicate-continuing-leaf.bin", KIND_LEAF_MEMBERSHIP_PROOF, duplicate,
        "rejected: E2EE_OPERATION_CONFLICT; device 8 claims leaf 0 and the old credential hash already held by device 7's continuing proof",
        device_seed="8", leaf_seed="30")

    ack = commit_ack(33, 3, bundle_8, candidate_a)
    add("commit-ack-without-membership.bin", KIND_COMMIT_ACK, ack,
        "rejected: E2EE_BINDING_AUTH_INVALID; no stored continuing proof matches (leaf 3, old credential hash), so the signer cannot be identified; "
        "a ReInit activation request whose ACK set omits membership-continuing is refused with the same code as a missing continuing leaf",
        leaf_seed="33")

    _, incomplete = submission(RECORD_ELEMENT, KIND_SEQUENCER_RECORD, b"never uploaded element", 1, ANCHOR)
    add("incomplete-chain-submission.bin", KIND_RECOVERY_SUBMISSION, incomplete,
        "accepted: RECOVERY-ACCEPTED; its element is never supplied, so the gate stays pending, the submission expires after "
        "MAX_RECOVERY_SUBMISSION_SECONDS with no state change, and a late element is refused with E2EE_OBJECT_NOT_FOUND",
        device_seed="7")
    return vectors


def render_recovery_manifest(vectors: list[dict[str, object]]) -> str:
    lines = [
        "# Generated by scripts/generate-e2ee-vectors.py; do not edit by hand.",
        "schema_version = 1",
        'generator = "python cryptography Ed25519, independent TLS encoder"',
        'evidence_class = "synthetic public-envelope vectors; not a real MLS endpoint transcript"',
        f'network_id = "{NETWORK.hex()}"',
        f'account_id = "{ACCOUNT.decode()}"',
        f'conversation_id = "{CONVERSATION.hex()}"',
        f'recovery_epoch = "{RECOVERY_EPOCH.hex()}"',
        f'restored_binding_id = "{RESTORED_BINDING.hex()}"',
        f'restored_accepted_state_id = "{RESTORED_STATE.hex()}"',
        f'restored_sequencer_head_id = "{ANCHOR.hex()}"',
        f'source_rollback_guard_hash = "{GUARD.hex()}"',
        f'sequencer_key_id = "{sequencer_key_id().hex()}"',
        f'witnessed_head_id = "{WITNESSED_HEAD.hex()}"',
        f'resolution_token = "{RESOLUTION_TOKEN.hex()}"',
        "",
    ]
    for entry in vectors:
        data = entry["data"]
        lines.append("[[vectors]]")
        lines.append(f'file = "{entry["name"]}"')
        lines.append(f'kind = "{KIND_NAMES[int(entry["kind"])]}"')
        lines.append(f"kind_discriminant = {int(entry['kind'])}")
        lines.append(f"encoded_length = {len(data)}")
        lines.append(f'object_id = "{object_id(data).hex()}"')
        for name, value in entry["ids"].items():
            rendered = value.hex() if isinstance(value, bytes) else value
            lines.append(f'{name} = "{rendered}"')
        lines.append(f'disposition = "{entry["disposition"]}"')
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def render_manifest(files: dict[str, bytes], ids: dict[str, str]) -> str:
    lines = [
        "# Generated by scripts/generate-e2ee-vectors.py; do not edit by hand.",
        "schema_version = 1",
        'generator = "python cryptography Ed25519, independent TLS encoder"',
        f'network_id = "{NETWORK.hex()}"',
        f'account_id = "{ACCOUNT.decode()}"',
        "",
        "[ids]",
    ]
    lines.extend(f'{name} = "{value}"' for name, value in ids.items())
    lines.append("")
    lines.append("[files]")
    lines.extend(f'"{name}" = "{hashlib.sha256(data).hexdigest()}"' for name, data in files.items())
    return "\n".join(lines) + "\n"


def main() -> None:
    files, ids, state = build_identity()
    manifest = render_manifest(files, ids)
    recovery = build_recovery(state)
    recovery_files = {str(entry["name"]): bytes(entry["data"]) for entry in recovery}
    if len(recovery_files) != len(recovery):
        raise SystemExit("recovery vector names collide")
    recovery_manifest = render_recovery_manifest(recovery)
    if "--check" in sys.argv[1:]:
        for name, data in files.items():
            if (OUTPUT / name).read_bytes() != data:
                print(f"stale vector: {name}", file=sys.stderr)
                sys.exit(1)
        if (OUTPUT / "manifest.toml").read_text(encoding="utf-8") != manifest:
            print("stale manifest", file=sys.stderr)
            sys.exit(1)
        for name, data in recovery_files.items():
            if (RECOVERY_OUTPUT / name).read_bytes() != data:
                print(f"stale recovery vector: {name}", file=sys.stderr)
                sys.exit(1)
        if (RECOVERY_OUTPUT / "manifest.toml").read_text(encoding="utf-8") != recovery_manifest:
            print("stale recovery manifest", file=sys.stderr)
            sys.exit(1)
        print(f"e2ee identity vectors: ok ({len(files)} files); recovery vectors: ok ({len(recovery_files)} files)")
        return
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (OUTPUT / name).write_bytes(data)
    (OUTPUT / "manifest.toml").write_text(manifest, encoding="utf-8")
    RECOVERY_OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, data in recovery_files.items():
        (RECOVERY_OUTPUT / name).write_bytes(data)
    (RECOVERY_OUTPUT / "manifest.toml").write_text(recovery_manifest, encoding="utf-8")
    print(f"e2ee identity vectors: wrote {len(files)} files; recovery vectors: wrote {len(recovery_files)} files")


if __name__ == "__main__":
    main()
