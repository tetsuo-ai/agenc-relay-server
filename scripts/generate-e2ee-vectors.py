#!/usr/bin/env python3
"""Generate independent companion-object vectors for the Stage 08 gates.

This generator is deliberately separate from the Rust codec: it encodes the
TLS presentation language, computes semantic identifiers, and signs with
Ed25519 through the `cryptography` package. The Rust crate must decode
every vector, recompute every identifier, and verify every signature. Keys
are derived from fixed seeds so the output is reproducible.

Three sets are written. The identity set under `test-data/vectors/e2ee/identity`
covers Section 8 objects. The recovery set under
`test-data/vectors/e2ee/recovery` covers the Section 12.5.1 witness
resolution, the Section 13.7.3 leaf-membership proof and the Section 13.7.4
recovery submission as complete `ArcWireObject` envelopes, with sequencer
records and a close authorization as elements. The recovery set is
synthetic public-envelope evidence: its chain is structurally valid under the
contract's encoding, identifier and signature rules, but it is not a real
MLS endpoint transcript, and its Rust consumers belong to ENC-02 through
ENC-05.

The ReInit set under `test-data/vectors/e2ee/reinit` covers the Section 13.8
target: for successor suites 0x0001 and 0x0003, the Proposal's extension list,
the target reconstructed from it, and one conversation's complete sequencer
records from its pinned genesis through the bootstrap activation, a ReInit
candidate whose authorization commits the target digest, its finalization, an
attempt naming that finalization and digest, and the activation, with the
ReInit binding-chain and policy-chain entries a later joiner of that successor
checks against the activation, and the old genesis entry they follow. A second
suite-0x0001 chain authorizes the same target after a finalized self-update
and a candidate abort, and activates it with a second attempt after the first
aborted. Rejection files carry a malformed or mismatched extension list, a
later joiner's GroupContext extensions (its own pending join), the
pre-revision target layout, a successor initial Commit naming its activation,
and an attempt carrying another target's digest. A continuous rotation of one
member's root reaches a successor whose roster heads, binding principals,
policy and plan name the new root, through activation and a later joiner's
entries, and the same rotation is also written with a suite change from
0x0001 to 0x0003. Its rejection files carry a forged continuity signature, a
sibling root the rotation does not descend from, a fresh root that does not
continue the old one, a successor binding that keeps the old root, a rotated
channel-authority root, and a successor whose context, binding and policy
name another conversation kind than the semantic route it keeps, as an
extension list and as the target built from it. Signatures are real; MLS
inputs are synthetic.

Usage: python3 scripts/generate-e2ee-vectors.py [--check]
"""

from __future__ import annotations

import copy
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


# --- ReInit target set (companion 13.8 with 9.3 to 9.5 and 12.2 to 12.4) ------
#
# One conversation from its pinned genesis through the bootstrap activation to
# a ReInit: the target reconstructed from the Proposal's extension list, the
# candidate whose authorization commits the target digest, the finalization
# that authorizes it, an attempt naming that finalization and digest, and the
# activation. Every structure is encoded from the companion's presentation
# language, not from the Rust codec, and every signature is a real Ed25519
# signature from a fixed seed. MLS inputs (Commit objects, GroupContext, tree
# and GroupInfo encodings, exporter values, and the initial Commit's
# ciphertext) are synthetic: the chain is valid under the public rules, but it
# is not a real MLS endpoint transcript.

REINIT_OUTPUT = ROOT / "test-data/vectors/e2ee/reinit"
KIND_ROOT_IDENTITY = 10
KIND_DEVICE_ROSTER = 12
KIND_CONVERSATION_BINDING = 15
KIND_REINIT_ATTEMPT = 18
KIND_POLICY = 34
FINALIZATION_RECORD, ABORT_RECORD = 2, 3  # ArcSequencerRecordKind
REINIT_ATTEMPT_RECORD, REINIT_ACTIVATION_RECORD, REINIT_ABORT_RECORD = 4, 5, 6
FINALIZE, ABORT = 1, 2  # ArcDisposition and ArcReInitDisposition
ROUTINE_SELF_UPDATE, CONTROLLED_TRANSITION, BOOTSTRAP_ACTIVATION = 1, 3, 6
POLICY_BIT, BOOTSTRAP_BIT, REINIT_BIT = 0x08, 0x200, 0x80
CREATOR_STATE, WELCOME_JOIN = 1, 2  # ArcReInitAckKind
ROOT_LOCKED_GENESIS, REINIT_TARGET_TRANSITION = 1, 3  # ArcBindingProofKind
POLICY_REINIT_TARGET_TRANSITION = 3  # ArcPolicyProofKind
CHANNEL, MODERATED, ACTIVE = 1, 2, 1
DIRECT = 2  # ArcConversationKind
ARC_MLS_CONTEXT_EXTENSION = 0xF1C1
REQUIRED_CAPABILITIES_EXTENSION = 0x0003
PROFILE_LABEL = b"agenc-chat ARC-MLS specification profile v1\0"

R_ACCOUNTS = (b"c" * 24, b"d" * 24)
R_ROOT_SEEDS = (110, 111)
R_DEVICE_SEEDS = (112, 114)
R_OLD_LEAF_SEEDS = (120, 121)
R_SEQUENCER_SEED = 115
R_ROTATED_ROOT_SEEDS = (132, 133)
R_FORGED_CONTINUITY_SEED = 134
R_ROTATED_ROOT_INTERVAL = (100, 2_000_000)
R_FRESH_ROOT_SEED = 135
R_SIBLING_ROOT_SEED = 136
R_OLD_GROUP = bytes([0x31] * 32)
R_INSTANCE = bytes([0x3C] * 16)
R_CHANNEL = b"#pc001"
R_GENESIS_TIME = 120
R_SUCCESSOR_TIME = 140
R_REINIT_TIME = 150
R_INITIAL_COMMIT_TIME = 155
R_ROSTER_INTERVAL = (100, 100 + 6 * 24 * 3600)
R_REQUIRED_CAPABILITIES = (
    opaque_v(u16(ARC_MLS_CONTEXT_EXTENSION) + u16(0xF1C3)) + opaque_v(u16(0xF1C2)) + opaque_v(u16(1))
)


def opaque4(data: bytes) -> bytes:
    """A vector with the four-byte prefix of an unbounded proof-set digest."""
    return opaque(data, 0xFFFF_FFFF)


def r_root(account: bytes, private: Ed25519PrivateKey) -> tuple[bytes, bytes]:
    tbs = (
        u16(1) + NETWORK + opaque(account, 255) + u64(0) + public(private)
        + u64(ROOT_INTERVAL[0]) + u64(ROOT_INTERVAL[1]) + bytes(32)
    )
    return tbs, tbs + sign(private, "root identity", tbs) + opaque(b"", 64)


def r_certificate(account: bytes, root_private: Ed25519PrivateKey, root_fp: bytes, seed: int,
                  root_generation: int = 0) -> tuple[bytes, bytes]:
    device = key(seed)
    challenge = bytes([seed + 100] * 32)
    enrollment_tbs = (
        u16(1) + NETWORK + opaque(account, 255) + u64(root_generation) + root_fp + u64(0) + challenge
        + bytes([seed] * 16) + public(device) + u64(90) + u64(100)
    )
    enrollment = (
        enrollment_tbs
        + sign(device, "device enrollment possession", enrollment_tbs)
        + sign(root_private, "device enrollment approval", enrollment_tbs)
    )
    tbs = (
        u16(1) + NETWORK + opaque(account, 255) + u64(root_generation) + root_fp + bytes([seed] * 16)
        + public(device) + u64(0) + challenge + semantic_id("enrollment id", enrollment_tbs)
        + u64(1) + u32(3) + u64(0) + u64(1_000_000)
    )
    return tbs, tbs + enrollment + sign(root_private, "device certificate", tbs)


def r_roster(account: bytes, root_private: Ed25519PrivateKey, root_fp: bytes, seed: int, cert: bytes,
             root_generation: int = 0) -> tuple[bytes, bytes]:
    tbs = (
        u16(1) + NETWORK + opaque(account, 255) + u64(root_generation) + root_fp + u64(0)
        + u64(R_ROSTER_INTERVAL[0]) + u64(R_ROSTER_INTERVAL[1]) + bytes(32)
        + vector([bytes([seed] * 16) + cert], 65_535) + vector([], 65_535)
    )
    return tbs, tbs + sign(root_private, "device roster", tbs)


def r_capability_id(account: bytes, seed: int, root_fp: bytes, roster_id: bytes) -> bytes:
    tbs = (
        u16(1) + NETWORK + opaque(account, 255) + root_fp + u64(0) + roster_id + bytes([seed] * 16)
        + u64(0) + bytes(32) + u64(100) + u64(200) + vector([u16(1)], 32) + vector([u16(1), u16(3)], 64)
        + vector([u16(0xF1C1), u16(0xF1C3)], 128) + vector([u16(0xF1C2)], 128) + vector([u16(1)], 32)
    )
    return semantic_id("capability id", tbs)


class RPrincipal:
    """One binding principal: a root, one device with binding and policy authority, and its old leaf."""

    def __init__(self, index: int) -> None:
        self.account = R_ACCOUNTS[index]
        self.root_key = key(R_ROOT_SEEDS[index])
        self.root_tbs, self.root = r_root(self.account, self.root_key)
        self.fp = semantic_id("root fingerprint", self.root_tbs)
        self.seed = R_DEVICE_SEEDS[index]
        self.device = key(self.seed)
        self.device_id = bytes([self.seed] * 16)
        cert_tbs, cert = r_certificate(self.account, self.root_key, self.fp, self.seed)
        self.cert_id = semantic_id("device certificate id", cert_tbs)
        self.roster_tbs, self.roster = r_roster(self.account, self.root_key, self.fp, self.seed, cert)
        self.roster_id = semantic_id("roster id", self.roster_tbs)
        self.capability_id = r_capability_id(self.account, self.seed, self.fp, self.roster_id)
        self.old_leaf = key(R_OLD_LEAF_SEEDS[index])
        self.old_leaf_index = index
        self.old_credential_hash = semantic_id("old credential hash", opaque_v(self.root + cert))
        self.root_generation = 0

    def approval(self, label: str, tbs: bytes) -> bytes:
        """`ArcPolicyApproval`, `ArcBindingApproval`, `ArcCommitApproval` and `ArcFinalityVote` share this layout."""
        return self.fp + self.device_id + self.cert_id + sign(self.device, label, tbs)

    def principal_entry(self) -> bytes:
        return opaque(self.account, 255) + self.fp + u64(0) + self.roster_id

    def roster_head(self) -> bytes:
        digest = semantic_id("account id", NETWORK + opaque(self.account, 255))
        return digest + u64(self.root_generation) + self.fp + u64(0) + self.roster_id


def r_rotated(old: RPrincipal, root_seed: int, continuity: Ed25519PrivateKey | None = None) -> RPrincipal:
    """`old`'s account after a continuous root rotation (companion 8.2): a generation-one root whose
    continuity signature is by `continuity` (the old root key unless given), a new certificate for the
    same device and a new generation-zero roster under the new root, and a new capability ID. The old
    leaf and credential stay `old`'s: they are what the old group's ACKs name."""
    new = copy.copy(old)
    new.root_key = key(root_seed)
    new.root_generation = 1
    new.root_tbs = (
        u16(1) + NETWORK + opaque(old.account, 255) + u64(1) + public(new.root_key)
        + u64(R_ROTATED_ROOT_INTERVAL[0]) + u64(R_ROTATED_ROOT_INTERVAL[1]) + old.fp
    )
    signer = old.root_key if continuity is None else continuity
    new.root = (
        new.root_tbs + sign(new.root_key, "root identity", new.root_tbs)
        + opaque(sign(signer, "root continuity", new.root_tbs), 64)
    )
    new.fp = semantic_id("root fingerprint", new.root_tbs)
    cert_tbs, cert = r_certificate(old.account, new.root_key, new.fp, old.seed, root_generation=1)
    new.cert_id = semantic_id("device certificate id", cert_tbs)
    new.roster_tbs, new.roster = r_roster(old.account, new.root_key, new.fp, old.seed, cert, root_generation=1)
    new.roster_id = semantic_id("roster id", new.roster_tbs)
    new.capability_id = r_capability_id(old.account, old.seed, new.fp, new.roster_id)
    return new


def r_fresh(old: RPrincipal, root_seed: int) -> RPrincipal:
    """`old`'s account under a new generation-zero root that does not continue the old one, an identity
    discontinuity (companion 8.2), with a new certificate and roster under it."""
    new = copy.copy(old)
    new.root_key = key(root_seed)
    new.root_generation = 0
    new.root_tbs, new.root = r_root(old.account, new.root_key)
    new.fp = semantic_id("root fingerprint", new.root_tbs)
    cert_tbs, cert = r_certificate(old.account, new.root_key, new.fp, old.seed)
    new.cert_id = semantic_id("device certificate id", cert_tbs)
    new.roster_tbs, new.roster = r_roster(old.account, new.root_key, new.fp, old.seed, cert)
    new.roster_id = semantic_id("roster id", new.roster_tbs)
    new.capability_id = r_capability_id(old.account, old.seed, new.fp, new.roster_id)
    return new


def canonical(items: list[bytes]) -> bytes:
    return b"".join(sorted(items))


def r_policy(conversation: bytes, generation: int, previous: bytes, controllers: list[RPrincipal],
             council: list[RPrincipal], suite: int, approvers: list[RPrincipal],
             kind: int = CHANNEL) -> tuple[bytes, bytes]:
    allowed = [1, 3] if suite == 1 else [suite, 1]
    tbs = (
        u16(1) + NETWORK + conversation + u64(generation) + previous + u8(kind) + u8(MODERATED)
        + u16(1) + u16(suite) + opaque(b"".join(u16(item) for item in allowed), 32)
        + opaque(canonical([p.fp for p in controllers]), 2048) + u16(1)
        + opaque(canonical([p.fp + p.device_id + p.cert_id for p in council]), 5120)
        + u16(0) + u8(0) + u16(8) + u32(16)
    )
    approvals = canonical([p.approval("policy approval", tbs) for p in approvers])
    return tbs, tbs + opaque(approvals, 16_384)


def r_semantic_route(authority: RPrincipal) -> bytes:
    return (
        u16(1) + NETWORK + u8(CHANNEL) + opaque(b"", 24) + opaque(b"", 24) + opaque(R_CHANNEL, 255)
        + authority.fp + u64(0) + bytes(32)
    )


def r_plan(members: list[RPrincipal]) -> bytes:
    entries = [opaque(p.account, 255) + p.fp + p.device_id + p.capability_id for p in members]
    return opaque(canonical(entries), 1_048_576)


def r_core(suite: int, group: bytes, conversation: bytes, lock: bytes, route: bytes, time: int,
           initial_policy: bytes, operational_policy: bytes, pending: int, plan_id: bytes, sequencer_id: bytes,
           kind: int = CHANNEL) -> bytes:
    return (
        u16(1) + u16(1) + u16(suite) + opaque(group, 255) + NETWORK + conversation + u8(kind)
        + lock + route + u64(time) + initial_policy + operational_policy + u8(pending) + plan_id
        + sequencer_id + opaque(R_REQUIRED_CAPABILITIES, 65_535)
    )


def r_binding_tbs(generation: int, previous: bytes, route_tbs: bytes, lock: bytes, group: bytes, conversation: bytes,
                  route: bytes, suite: int, initial_policy: bytes, operational_policy: bytes, plan_id: bytes,
                  core_id: bytes, sequencer_id: bytes, principals: list[RPrincipal], kind: int = CHANNEL) -> bytes:
    return (
        u16(1) + NETWORK + u8(kind) + u64(generation) + previous + route_tbs + lock
        + opaque(R_INSTANCE, 16) + opaque(b"", 32) + opaque(group, 255) + conversation + route
        + u16(1) + u16(suite) + initial_policy + operational_policy + plan_id + core_id + sequencer_id
        + opaque(canonical([p.principal_entry() for p in principals]), 65_535)
    )


def r_mls_extensions(context: bytes, *, contexts: int = 1, required: bool = True) -> bytes:
    """The encoded `Extension extensions<V>` list of a ReInit Proposal."""
    body = u16(REQUIRED_CAPABILITIES_EXTENSION) + opaque_v(R_REQUIRED_CAPABILITIES) if required else b""
    body += (u16(ARC_MLS_CONTEXT_EXTENSION) + opaque_v(context)) * contexts
    return opaque_v(body)


def r_result_digests(suite: int, marker: int) -> tuple[bytes, bytes, bytes]:
    """Registered result digests over synthetic MLS encodings."""
    return (
        semantic_id("group context digest", u16(suite) + opaque(bytes([marker] * 48), 1_048_576)),
        semantic_id("ratchet tree digest", u16(suite) + opaque(bytes([marker + 1] * 96), 4_194_304)),
        semantic_id("group info digest", u16(suite) + opaque(bytes([marker + 2] * 80), 4_194_304)),
    )


class RLog:
    """The sequencer's view of the old conversation's log, and the chain state it signs over."""

    def __init__(self, world: "RWorld") -> None:
        self.world = world
        self.route_sequence = 0
        self.head = world.genesis_id
        self.epoch = 0
        self.accepted = world.genesis_id
        self.candidate_sequence = 0
        self.policy_id = world.bootstrap_policy_id

    def copy(self) -> "RLog":
        other = RLog(self.world)
        other.__dict__.update(self.__dict__)
        return other

    def sequencer_sign(self, label: str, tbs: bytes) -> bytes:
        return sign(key(R_SEQUENCER_SEED), label, tbs)

    def record(self, kind: int, body: bytes, semantic: bytes) -> bytes:
        self.route_sequence += 1
        self.head = semantic
        return wire_object(KIND_SEQUENCER_RECORD, u8(kind) + body)

    def candidate(self, commit_object: bytes) -> tuple[bytes, bytes, bytes]:
        tbs = (
            u16(1) + NETWORK + self.world.conversation + u64(self.route_sequence) + u64(self.epoch)
            + u64(self.epoch + 1) + u32(self.candidate_sequence) + commit_object + self.accepted + self.head
            + u64(1_700_000_000 + self.route_sequence) + self.world.sequencer_id
        )
        receipt = tbs + self.sequencer_sign("candidate receipt", tbs)
        candidate_id = semantic_id("candidate id", tbs)
        self.slot = (self.epoch, self.accepted, self.candidate_sequence, self.head)
        return self.record(CANDIDATE_RECORD, receipt, candidate_id), receipt, candidate_id

    def vote_tbs(self, candidate_id: bytes, disposition: int, terminal: bytes, reason: int) -> bytes:
        epoch, accepted, candidate_sequence, predecessor = self.slot
        return (
            u16(1) + NETWORK + self.world.conversation + u64(epoch) + accepted + u32(candidate_sequence)
            + predecessor + candidate_id + u8(disposition) + terminal + u16(reason)
        )

    def finalization(self, receipt: bytes, candidate_id: bytes, commit_object: bytes, rule: int, bits: int,
                     resulting_policy: bytes, target: bytes, approvers: list[RPrincipal],
                     voters: list[RPrincipal]) -> tuple[bytes, bytes, bytes]:
        w = self.world
        context_digest, tree_digest, _ = r_result_digests(1, 0x50 + self.route_sequence)
        authorization_tbs = (
            u16(1) + NETWORK + w.conversation + u64(self.epoch) + self.accepted + candidate_id + commit_object
            + u64(R_REINIT_TIME if bits == REINIT_BIT else 130 + self.route_sequence) + self.policy_id
            + u8(rule) + u32(bits) + resulting_policy + context_digest + tree_digest + target
        )
        approvals = canonical([p.approval("commit authorization", authorization_tbs) for p in approvers])
        authorization = authorization_tbs + opaque(approvals, 16_384)
        authenticator = bytes([0x70 + self.route_sequence] * 32)
        sender = w.principals[0]
        ack_tbs = (
            u16(1) + NETWORK + w.conversation + u64(self.epoch) + candidate_id + commit_object
            + u32(sender.old_leaf_index) + sender.old_credential_hash + u64(self.epoch + 1)
            + context_digest + tree_digest + authenticator
        )
        ack = ack_tbs + opaque(sign(sender.old_leaf, "commit processed", ack_tbs), 255)
        core = (
            u16(1) + NETWORK + w.conversation + u64(self.epoch) + self.accepted + candidate_id + commit_object
            + u64(self.epoch + 1) + self.policy_id + semantic_id("commit authorization id", authorization_tbs)
            + semantic_id("commit acknowledgement set", opaque4(ack_tbs)) + context_digest + tree_digest
            + authenticator
        )
        finalization_id = semantic_id("finalization id", core)
        vote = self.vote_tbs(candidate_id, FINALIZE, finalization_id, 0)
        votes = canonical([p.approval("disposition vote", vote) for p in voters])
        request = core + receipt + authorization + opaque(ack, 262_144) + opaque(votes, 16_384)
        tbs = (
            u16(1) + NETWORK + w.conversation + u64(self.route_sequence) + self.head + finalization_id
            + w.sequencer_id + request
        )
        certificate = tbs + self.sequencer_sign("commit finalization", tbs)
        record = self.record(FINALIZATION_RECORD, certificate, finalization_id)
        self.epoch += 1
        self.accepted = finalization_id
        self.candidate_sequence = 0
        self.policy_id = resulting_policy
        return record, finalization_id, authorization_tbs

    def abort(self, receipt: bytes, candidate_id: bytes, voters: list[RPrincipal]) -> tuple[bytes, bytes]:
        w = self.world
        reason = 1  # sender_withdrawn
        core = (
            u16(1) + NETWORK + w.conversation + self.accepted + candidate_id + u64(self.epoch) + u8(reason)
            + bytes([0x65] * 32)
        )
        abort_id = semantic_id("abort id", core)
        vote = self.vote_tbs(candidate_id, ABORT, abort_id, reason)
        votes = canonical([p.approval("disposition vote", vote) for p in voters])
        request = core + receipt + opaque(votes, 16_384)
        tbs = u16(1) + NETWORK + w.conversation + u64(self.route_sequence) + self.head + abort_id + w.sequencer_id + request
        certificate = tbs + self.sequencer_sign("candidate abort", tbs)
        record = self.record(ABORT_RECORD, certificate, abort_id)
        self.candidate_sequence += 1
        return record, abort_id


class RAttempt:
    """One ReInit attempt of a target: its KeyPackage plan, initial Commit, and object, which carries the
    target (`ArcReInitAttempt.target`) right after its TBS."""

    def __init__(self, world: "RWorld", target: "RTarget", finalization_id: bytes, sequence: int, marker: int,
                 *, digest: bytes | None = None, carried: bytes | None = None) -> None:
        creator, joiner = world.principals
        self.sequence = sequence
        self.finalization_id = finalization_id
        self.target = target
        self.digest = target.digest if digest is None else digest
        self.carried = target.tbs if carried is None else carried
        self.joiner_ref = hashlib.sha256(b"synthetic KeyPackageRef" + bytes([marker])).digest()
        leaves = {creator.seed: key(marker), joiner.seed: key(marker + 1)}
        entries = []
        for p in target.members:
            is_creator = p.seed == creator.seed
            leaf_digest = semantic_id("leaf signature key", u16(ED25519_SCHEME) + opaque(public(leaves[p.seed]), 255))
            entries.append(
                opaque(p.account, 255) + p.fp + p.device_id + p.capability_id
                + opaque(b"" if is_creator else self.joiner_ref, 255) + u16(ED25519_SCHEME) + leaf_digest
                + u8(1 if is_creator else 0)
            )
        self.plan = opaque(canonical(entries), 1_048_576)
        self.initial_commit = world.initial_commit(target, finalization_id, marker)
        self.results = r_result_digests(target.suite, marker) + (bytes([marker + 3] * 32),)
        context_digest, tree_digest, info_digest, exporter = self.results
        common = (
            creator.old_credential_hash, target.new_conversation, self.digest, target.binding_id,
            target.plan_id, semantic_id("key package plan id", self.plan),
            semantic_id("reinit initial commit", self.initial_commit),
        )
        authorization_tbs = (
            u16(1) + NETWORK + world.conversation + finalization_id + u32(sequence) + u32(creator.old_leaf_index)
            + common[0] + common[1] + common[2] + common[3] + common[4] + common[5] + common[6]
            + info_digest + context_digest + tree_digest + exporter
        )
        approvals = canonical([creator.approval("reinit attempt authorization", authorization_tbs)])
        self.tbs = (
            u16(1) + NETWORK + world.conversation + target.new_conversation + finalization_id + u32(sequence)
            + u32(creator.old_leaf_index) + common[0] + opaque(target.group, 255) + u16(1) + u16(target.suite)
            + common[2] + common[3] + common[4] + common[5] + common[6]
            + semantic_id("reinit attempt authorization id", authorization_tbs)
            + info_digest + context_digest + tree_digest + exporter
        )
        body = (
            self.tbs + self.carried + self.plan + opaque(self.initial_commit, 3_145_728)
            + authorization_tbs + opaque(approvals, 16_384)
            + opaque(sign(creator.old_leaf, "reinit attempt", self.tbs), 255)
        )
        self.object = wire_object(KIND_REINIT_ATTEMPT, body)
        self.body = body
        self.attempt_id = semantic_id("reinit attempt id", self.tbs)

    def ack_tbs(self, principal: RPrincipal, kind: int) -> bytes:
        context_digest, tree_digest, info_digest, exporter = self.results
        reference = b"" if kind == CREATOR_STATE else self.joiner_ref
        return (
            u16(1) + NETWORK + self.target.world.conversation + self.target.new_conversation
            + self.finalization_id + self.attempt_id + u8(kind) + info_digest + context_digest + tree_digest
            + exporter + u32(principal.old_leaf_index) + principal.old_credential_hash
            + u32(principal.old_leaf_index) + opaque(reference, 255)
        )


class RTarget:
    """The successor of one suite: its context, extension list and target. `members` are the principals
    its roster heads, policy and plan name (the old ones unless given, such as after a root rotation);
    `binding_members` are its binding's principals (the members unless given); `kind` is the
    conversation kind its context, binding, policy and core name (the old channel's unless given),
    while it keeps the old channel's semantic route."""

    def __init__(self, world: "RWorld", suite: int, *, members: tuple[RPrincipal, ...] | None = None,
                 binding_members: tuple[RPrincipal, ...] | None = None, group: bytes | None = None,
                 kind: int = CHANNEL) -> None:
        self.world = world
        self.suite = suite
        self.kind = kind
        self.group = bytes([0x40 + suite] * 32) if group is None else group
        self.new_conversation = semantic_id("conversation", NETWORK + opaque(self.group, 255))
        self.members = tuple(world.principals) if members is None else members
        self.binding_members = self.members if binding_members is None else binding_members
        members = list(self.members)
        policy_tbs, self.policy = r_policy(self.new_conversation, 0, bytes(32), members, members, suite, [members[0]],
                                           kind)
        self.policy_id = semantic_id("policy id", policy_tbs)
        self.plan_id = semantic_id("initial member plan id", r_plan(members))
        core = r_core(suite, self.group, self.new_conversation, world.lock, world.route, R_SUCCESSOR_TIME,
                      self.policy_id, self.policy_id, 0, self.plan_id, world.sequencer_id, kind)
        self.core_id = semantic_id("context core id", core)
        self.context = self.context_with(self.core_id)
        self.binding_id = semantic_id("binding id", self.binding_tbs(self.core_id))
        self.extensions = r_mls_extensions(self.context)
        self.tbs = (
            u16(1) + NETWORK + world.conversation + self.new_conversation + opaque(self.group, 255) + u16(1)
            + u16(suite) + self.core_id + self.binding_id + self.plan_id + opaque(self.extensions, 1_048_576)
        )
        self.digest = semantic_id("reinit target", self.tbs)

    def binding_tbs(self, core_id: bytes) -> bytes:
        w = self.world
        return r_binding_tbs(1, w.binding_id, w.route_tbs, w.lock, self.group, self.new_conversation, w.route,
                             self.suite, self.policy_id, self.policy_id, self.plan_id, core_id, w.sequencer_id,
                             list(self.binding_members), self.kind)

    def context_with(self, core_id: bytes, pending_joins: bytes = b"") -> bytes:
        w = self.world
        binding = self.binding_tbs(core_id) + opaque(b"", 65_535)
        heads = canonical([p.roster_head() for p in self.members])
        return (
            u16(1) + NETWORK + self.new_conversation + u8(self.kind) + w.route + u64(R_SUCCESSOR_TIME)
            + self.policy + w.credential + binding + u8(ACTIVE) + bytes(32) + opaque(b"", 4096) + u8(0)
            + opaque(heads, 65_535) + opaque(pending_joins, 65_535)
        )

    def binding_entry(self) -> bytes:
        """The join bundle's ReInit `ArcBindingChainEntry`: the unapproved replacement package."""
        package = (
            self.binding_tbs(self.core_id) + opaque(b"", 65_535) + r_plan(list(self.members))
            + opaque(b"", 65_535)
        )
        return package + u8(REINIT_TARGET_TRANSITION)

    def policy_entry(self) -> bytes:
        """The join bundle's ReInit `ArcPolicyChainEntry`: the successor's generation-zero policy."""
        return self.policy + u8(POLICY_REINIT_TARGET_TRANSITION)

    def later_joiner_extensions(self) -> bytes:
        """A later joiner's GroupContext extensions: the same context with that joiner's own pending join."""
        pending = u32(2) + opaque(hashlib.sha256(b"synthetic later joiner KeyPackageRef").digest(), 255)
        return r_mls_extensions(self.context_with(self.core_id, pending))

    def pinned_layout(self, finalization_id: bytes) -> bytes:
        """The pre-revision layout, which carried the finalization ID and could not be constructed."""
        w = self.world
        return (
            u16(1) + NETWORK + w.conversation + finalization_id + self.new_conversation + opaque(self.group, 255)
            + u16(1) + u16(self.suite) + self.core_id + self.binding_id + self.plan_id
            + opaque(self.extensions, 1_048_576)
        )


class RWorld:
    """The old conversation's genesis: principals, policies, binding, core and sequencer credential."""

    def __init__(self) -> None:
        self.principals = (RPrincipal(0), RPrincipal(1))
        creator, other = self.principals
        self.conversation = semantic_id("conversation", NETWORK + opaque(R_OLD_GROUP, 255))
        credential_tbs = (
            u16(1) + NETWORK + u64(0) + public(key(R_SEQUENCER_SEED)) + u64(0) + u64(4_000_000) + bytes(32)
        )
        self.credential = credential_tbs + opaque(b"", 64)
        self.sequencer_id = semantic_id("sequencer key", credential_tbs)
        bootstrap_tbs, self.bootstrap_policy = r_policy(self.conversation, 0, bytes(32), [creator], [creator], 1, [creator])
        self.bootstrap_policy_id = semantic_id("policy id", bootstrap_tbs)
        operational_tbs, self.operational_policy = r_policy(
            self.conversation, 1, self.bootstrap_policy_id, list(self.principals), list(self.principals), 1, [creator]
        )
        self.operational_policy_id = semantic_id("policy id", operational_tbs)
        self.route_tbs = r_semantic_route(creator)
        self.lock = semantic_id("semantic route lock", self.route_tbs)
        self.route = semantic_id("channel route", NETWORK + R_INSTANCE)
        plan = r_plan(list(self.principals))
        plan_id = semantic_id("initial member plan id", plan)
        self.core = r_core(1, R_OLD_GROUP, self.conversation, self.lock, self.route, R_GENESIS_TIME,
                           self.bootstrap_policy_id, self.operational_policy_id, 1, plan_id, self.sequencer_id)
        self.core_id = semantic_id("context core id", self.core)
        binding_tbs = r_binding_tbs(0, bytes(32), self.route_tbs, self.lock, R_OLD_GROUP, self.conversation,
                                    self.route, 1, self.bootstrap_policy_id, self.operational_policy_id, plan_id,
                                    self.core_id, self.sequencer_id, list(self.principals))
        self.binding_id = semantic_id("binding id", binding_tbs)
        approvals = canonical([p.approval("conversation binding", binding_tbs) for p in self.principals])
        locks = []
        for p in self.principals:
            lock_tbs = (
                u16(1) + NETWORK + opaque(p.account, 255) + p.fp + u64(0) + bytes(32) + self.lock
                + self.binding_id + u64(0) + p.roster_id
            )
            locks.append(lock_tbs + sign(p.root_key, "root binding lock", lock_tbs))
        self.binding_package = (
            binding_tbs + opaque(approvals, 65_535) + plan + opaque(canonical(locks), 65_535)
        )
        self.genesis_id = semantic_id(
            "group genesis id", NETWORK + self.conversation + opaque(R_OLD_GROUP, 255) + self.binding_id + self.core_id
        )

    def initial_commit(self, target: RTarget, prior_state: bytes, marker: int) -> bytes:
        """The successor initial Commit's public `PrivateMessage` frame; its ciphertext is synthetic."""
        aad = u16(1) + NETWORK + target.new_conversation + self.route + u64(R_INITIAL_COMMIT_TIME) + prior_state
        return (
            u16(1) + u16(2) + opaque_v(target.group) + u64(0) + u8(3) + opaque_v(aad)
            + opaque_v(bytes([marker] * 32)) + opaque_v(bytes([marker + 1] * 64))
        )

    def bootstrap(self, log: RLog) -> list[tuple[str, bytes, dict[str, object]]]:
        creator, other = self.principals
        record, receipt, candidate_id = log.candidate(bytes([0xB0] * 32))
        out = [("record-00-bootstrap-candidate.bin", record, {"semantic_id": candidate_id, "route_sequence": "0"})]
        record, finalization_id, _ = log.finalization(
            receipt, candidate_id, bytes([0xB0] * 32), BOOTSTRAP_ACTIVATION, POLICY_BIT | BOOTSTRAP_BIT,
            self.operational_policy_id, bytes(32), [creator], [creator, other],
        )
        out.append(("record-01-bootstrap-finalization.bin", record,
                    {"semantic_id": finalization_id, "route_sequence": "1", "policy_object": "policy-operational.bin"}))
        return out


def r_attempt_records(log: RLog, attempt: RAttempt, prefix: str) -> list[tuple[str, bytes, dict[str, object]]]:
    """The attempt object and the sequencer's receipt for it."""
    w = log.world
    tbs = (
        u16(1) + NETWORK + w.conversation + attempt.finalization_id + u64(log.route_sequence) + u32(attempt.sequence)
        + log.head + attempt.attempt_id + object_id(attempt.object) + u64(1_700_000_100 + log.route_sequence)
        + w.sequencer_id
    )
    attempt.receipt = tbs + log.sequencer_sign("reinit attempt receipt", tbs)
    attempt.receipt_predecessor = log.head
    sequence = log.route_sequence
    record = log.record(REINIT_ATTEMPT_RECORD, attempt.receipt, attempt.attempt_id)
    object_name = f"{prefix}-attempt-{attempt.sequence}.bin"
    return [
        (object_name, attempt.object, {"reinit_attempt_id": attempt.attempt_id,
                                        "initial_commit_digest": semantic_id("reinit initial commit", attempt.initial_commit)}),
        (f"{prefix}-record-{sequence:02d}-attempt-{attempt.sequence}-receipt.bin", record,
         {"semantic_id": attempt.attempt_id, "route_sequence": str(sequence), "attempt_object": object_name}),
    ]


def r_reinit_vote(log: RLog, attempt: RAttempt, disposition: int, terminal: bytes, reason: int) -> bytes:
    return (
        u16(1) + NETWORK + log.world.conversation + attempt.finalization_id + u32(attempt.sequence)
        + attempt.receipt_predecessor + attempt.attempt_id + u8(disposition) + terminal + u16(reason)
    )


def r_activation(log: RLog, attempt: RAttempt, prefix: str) -> tuple[str, bytes, dict[str, object]]:
    w = log.world
    creator, joiner = w.principals
    acks_tbs = [attempt.ack_tbs(creator, CREATOR_STATE), attempt.ack_tbs(joiner, WELCOME_JOIN)]
    acks = b"".join(
        tbs + opaque(sign(p.old_leaf, "reinit processed", tbs), 255) for tbs, p in zip(acks_tbs, (creator, joiner))
    )
    context_digest, tree_digest, info_digest, exporter = attempt.results
    core = (
        u16(1) + NETWORK + w.conversation + attempt.target.new_conversation + attempt.finalization_id
        + u32(attempt.sequence) + attempt.attempt_id + info_digest + context_digest + tree_digest + exporter
        + semantic_id("reinit acknowledgement set", opaque4(b"".join(acks_tbs)))
    )
    activation_id = semantic_id("reinit activation id", core)
    vote = r_reinit_vote(log, attempt, FINALIZE, activation_id, 0)
    votes = canonical([p.approval("reinit disposition", vote) for p in w.principals])
    request = core + attempt.receipt + attempt.body + opaque(acks, 1_048_576) + opaque(votes, 16_384)
    sequence = log.route_sequence
    tbs = u16(1) + NETWORK + w.conversation + u64(sequence) + log.head + activation_id + w.sequencer_id + request
    record = log.record(REINIT_ACTIVATION_RECORD, tbs + log.sequencer_sign("reinit activation", tbs), activation_id)
    return (f"{prefix}-record-{sequence:02d}-activation.bin", record,
            {"semantic_id": activation_id, "route_sequence": str(sequence)})


def r_attempt_abort(log: RLog, attempt: RAttempt, prefix: str) -> tuple[str, bytes, dict[str, object]]:
    w = log.world
    reason = 5
    core = (
        u16(1) + NETWORK + w.conversation + attempt.finalization_id + u32(attempt.sequence)
        + attempt.receipt_predecessor + attempt.attempt_id + u16(reason) + bytes([0x94] * 32)
    )
    abort_id = semantic_id("reinit abort id", core)
    vote = r_reinit_vote(log, attempt, ABORT, abort_id, reason)
    votes = canonical([p.approval("reinit disposition", vote) for p in w.principals])
    request = core + attempt.receipt + attempt.body + opaque(votes, 16_384)
    sequence = log.route_sequence
    tbs = u16(1) + NETWORK + w.conversation + u64(sequence) + log.head + abort_id + w.sequencer_id + request
    record = log.record(REINIT_ABORT_RECORD, tbs + log.sequencer_sign("reinit attempt abort", tbs), abort_id)
    return (f"{prefix}-record-{sequence:02d}-attempt-abort.bin", record,
            {"semantic_id": abort_id, "route_sequence": str(sequence)})


def r_reinit(log: RLog, target: RTarget, prefix: str, marker: int) -> tuple[list[tuple[str, bytes, dict[str, object]]], bytes]:
    """A ReInit candidate at the log's current accepted state and the finalization that authorizes `target`."""
    creator, other = log.world.principals
    commit_object = bytes([marker] * 32)
    sequence = log.route_sequence
    record, receipt, candidate_id = log.candidate(commit_object)
    out = [(f"{prefix}-record-{sequence:02d}-reinit-candidate.bin", record,
            {"semantic_id": candidate_id, "route_sequence": str(sequence), "prior_state_id": log.accepted})]
    sequence = log.route_sequence
    record, finalization_id, authorization_tbs = log.finalization(
        receipt, candidate_id, commit_object, CONTROLLED_TRANSITION, REINIT_BIT, log.policy_id, target.digest,
        [creator], [creator, other],
    )
    out.append((f"{prefix}-record-{sequence:02d}-reinit-finalization.bin", record,
                {"semantic_id": finalization_id, "route_sequence": str(sequence),
                 "commit_authorization_id": semantic_id("commit authorization id", authorization_tbs),
                 "transition_target_digest": target.digest}))
    return out, finalization_id


def build_reinit() -> tuple[list[tuple[str, bytes, dict[str, object]]], dict[str, str]]:
    """Return ordered `(name, bytes, ids)` entries and the manifest's global values."""
    w = RWorld()
    creator, other = w.principals
    entries: list[tuple[str, bytes, dict[str, object]]] = [
        ("genesis-binding.bin", wire_object(KIND_CONVERSATION_BINDING, w.binding_package), {"binding_id": w.binding_id}),
        ("genesis-context-core.bin", w.core, {"context_core_id": w.core_id}),
        ("policy-bootstrap.bin", wire_object(KIND_POLICY, w.bootstrap_policy), {"policy_id": w.bootstrap_policy_id}),
        ("policy-operational.bin", wire_object(KIND_POLICY, w.operational_policy), {"policy_id": w.operational_policy_id}),
        ("sequencer-credential.bin", w.credential, {"sequencer_credential_id": w.sequencer_id}),
    ]
    for p, name in ((creator, "c"), (other, "d")):
        entries.append((f"root-{name}.bin", wire_object(KIND_ROOT_IDENTITY, p.root), {"root_fingerprint": p.fp}))
        entries.append((f"roster-{name}.bin", wire_object(KIND_DEVICE_ROSTER, p.roster), {"roster_id": p.roster_id}))
    entries.append(("join-genesis-binding-entry.bin", w.binding_package + u8(ROOT_LOCKED_GENESIS),
                    {"binding_id": w.binding_id}))
    log = RLog(w)
    entries.extend(w.bootstrap(log))
    targets = {suite: RTarget(w, suite) for suite in (1, 3)}
    for suite, target in targets.items():
        prefix = f"suite-{suite:04x}"
        entries.append((f"{prefix}-extensions.bin", target.extensions,
                        {"group_id": target.group, "cipher_suite": str(suite), "new_conversation_id": target.new_conversation}))
        entries.append((f"{prefix}-target.bin", target.tbs,
                        {"target_context_digest": target.digest, "target_binding_id": target.binding_id,
                         "target_context_core_id": target.core_id, "initial_member_plan_id": target.plan_id,
                         "route_binding": w.route}))
        entries.append((f"{prefix}-join-binding-entry.bin", target.binding_entry(),
                        {"binding_id": target.binding_id}))
        entries.append((f"{prefix}-join-policy-entry.bin", target.policy_entry(), {"policy_id": target.policy_id}))
        branch = log.copy()
        records, finalization_id = r_reinit(branch, target, prefix, 0xC0 + suite)
        entries.extend(records)
        attempt = RAttempt(w, target, finalization_id, 0, 0x90 + suite)
        entries.append((f"{prefix}-initial-commit-0.bin", attempt.initial_commit, {"prior_state_id": finalization_id}))
        entries.extend(r_attempt_records(branch, attempt, prefix))
        entries.append(r_activation(branch, attempt, prefix))
        if suite == 1:
            direct = (branch, attempt, finalization_id)
    # The same suite-1 target, authorized after the accepted state advanced
    # through a routine self-update and a candidate abort, then activated by a
    # second attempt after the first attempt aborted.
    target = targets[1]
    advanced = log.copy()
    commit_object = bytes([0xA2] * 32)
    sequence = advanced.route_sequence
    record, receipt, candidate_id = advanced.candidate(commit_object)
    entries.append((f"advanced-record-{sequence:02d}-routine-candidate.bin", record,
                    {"semantic_id": candidate_id, "route_sequence": str(sequence)}))
    sequence = advanced.route_sequence
    record, routine_id, _ = advanced.finalization(
        receipt, candidate_id, commit_object, ROUTINE_SELF_UPDATE, 0, advanced.policy_id, bytes(32), [], [creator, other]
    )
    entries.append((f"advanced-record-{sequence:02d}-routine-finalization.bin", record,
                    {"semantic_id": routine_id, "route_sequence": str(sequence)}))
    sequence = advanced.route_sequence
    record, receipt, candidate_id = advanced.candidate(bytes([0xA4] * 32))
    entries.append((f"advanced-record-{sequence:02d}-reinit-candidate-aborted.bin", record,
                    {"semantic_id": candidate_id, "route_sequence": str(sequence)}))
    sequence = advanced.route_sequence
    record, abort_id = advanced.abort(receipt, candidate_id, [creator, other])
    entries.append((f"advanced-record-{sequence:02d}-candidate-abort.bin", record,
                    {"semantic_id": abort_id, "route_sequence": str(sequence)}))
    records, advanced_finalization = r_reinit(advanced, target, "advanced", 0xA6)
    entries.extend(records)
    first = RAttempt(w, target, advanced_finalization, 0, 0xD0)
    entries.append(("advanced-initial-commit-0.bin", first.initial_commit, {"prior_state_id": advanced_finalization}))
    entries.extend(r_attempt_records(advanced, first, "advanced"))
    entries.append(r_attempt_abort(advanced, first, "advanced"))
    second = RAttempt(w, target, advanced_finalization, 1, 0xD4)
    entries.append(("advanced-initial-commit-1.bin", second.initial_commit, {"prior_state_id": advanced_finalization}))
    entries.extend(r_attempt_records(advanced, second, "advanced"))
    entries.append(r_activation(advanced, second, "advanced"))

    # Root rotation (P-03): d's account continuously rotates its root, and the successor's roster heads,
    # binding principals, policy and plan name d's new root while the old council activates it. The
    # same rotation with a suite change from 0x0001 to 0x0003 is reconstructed only.
    rotated_d = r_rotated(other, R_ROTATED_ROOT_SEEDS[1])
    entries.append(("root-d-1.bin", wire_object(KIND_ROOT_IDENTITY, rotated_d.root),
                    {"root_fingerprint": rotated_d.fp, "root_generation": "1", "previous_root_fingerprint": other.fp}))
    entries.append(("roster-d-1.bin", wire_object(KIND_DEVICE_ROSTER, rotated_d.roster), {"roster_id": rotated_d.roster_id}))
    rotations = {
        1: RTarget(w, 1, members=(creator, rotated_d), group=bytes([0x61] * 32)),
        3: RTarget(w, 3, members=(creator, rotated_d), group=bytes([0x63] * 32)),
    }
    for suite, rotation in rotations.items():
        prefix = "rotation" if suite == 1 else "rotation-0003"
        entries.append((f"{prefix}-extensions.bin", rotation.extensions,
                        {"group_id": rotation.group, "cipher_suite": str(suite),
                         "new_conversation_id": rotation.new_conversation}))
        entries.append((f"{prefix}-target.bin", rotation.tbs,
                        {"target_context_digest": rotation.digest, "target_binding_id": rotation.binding_id,
                         "target_context_core_id": rotation.core_id, "initial_member_plan_id": rotation.plan_id,
                         "route_binding": w.route}))
    rotation = rotations[1]
    entries.append(("rotation-join-binding-entry.bin", rotation.binding_entry(), {"binding_id": rotation.binding_id}))
    entries.append(("rotation-join-policy-entry.bin", rotation.policy_entry(), {"policy_id": rotation.policy_id}))
    branch = log.copy()
    records, finalization_id = r_reinit(branch, rotation, "rotation", 0xE1)
    entries.extend(records)
    attempt = RAttempt(w, rotation, finalization_id, 0, 0xE4)
    entries.append(("rotation-initial-commit-0.bin", attempt.initial_commit, {"prior_state_id": finalization_id}))
    entries.extend(r_attempt_records(branch, attempt, "rotation"))
    entries.append(r_activation(branch, attempt, "rotation"))

    # Rejections of successor rosters (P-03). d's generation-one root with a continuity signature by
    # another key (the same TBS, so the same fingerprint the rotation names); another valid
    # generation-one root of d, a sibling of the rotation's, from which the rotation does not descend;
    # a generation-zero root that does not continue d's; a successor whose heads, policy and plan name
    # d's new root while its binding keeps d's old one; and a rotation of c's root, which the old
    # semantic route lock names as the channel-authority root.
    forged_d = r_rotated(other, R_ROTATED_ROOT_SEEDS[1], continuity=key(R_FORGED_CONTINUITY_SEED))
    assert forged_d.fp == rotated_d.fp and forged_d.root != rotated_d.root
    entries.append(("reject-root-d-1-forged-continuity.bin", wire_object(KIND_ROOT_IDENTITY, forged_d.root),
                    {"root_fingerprint": forged_d.fp, "expected": "E2eeError::SignatureInvalid"}))
    sibling_d = r_rotated(other, R_SIBLING_ROOT_SEED)
    assert sibling_d.fp != rotated_d.fp
    entries.append(("root-d-1-sibling.bin", wire_object(KIND_ROOT_IDENTITY, sibling_d.root),
                    {"root_fingerprint": sibling_d.fp, "root_generation": "1", "previous_root_fingerprint": other.fp}))
    fresh_d = r_fresh(other, R_FRESH_ROOT_SEED)
    entries.append(("root-d-fresh.bin", wire_object(KIND_ROOT_IDENTITY, fresh_d.root), {"root_fingerprint": fresh_d.fp}))
    entries.append(("roster-d-fresh.bin", wire_object(KIND_DEVICE_ROSTER, fresh_d.roster), {"roster_id": fresh_d.roster_id}))
    fresh = RTarget(w, 1, members=(creator, fresh_d), group=bytes([0x65] * 32))
    stale = RTarget(w, 1, members=(creator, rotated_d), binding_members=(creator, other), group=bytes([0x64] * 32))
    rotated_c = r_rotated(creator, R_ROTATED_ROOT_SEEDS[0])
    entries.append(("root-c-1.bin", wire_object(KIND_ROOT_IDENTITY, rotated_c.root),
                    {"root_fingerprint": rotated_c.fp, "root_generation": "1", "previous_root_fingerprint": creator.fp}))
    entries.append(("roster-c-1.bin", wire_object(KIND_DEVICE_ROSTER, rotated_c.roster), {"roster_id": rotated_c.roster_id}))
    authority = RTarget(w, 1, members=(rotated_c, other), group=bytes([0x62] * 32))
    for name, rejected in (("fresh-root", fresh), ("stale-principal", stale), ("channel-authority", authority)):
        entries.append((f"reject-rotation-{name}-extensions.bin", rejected.extensions,
                        {"group_id": rejected.group, "cipher_suite": "1", "new_conversation_id": rejected.new_conversation,
                         "expected": "E2eeError::InvalidValue"}))

    # A successor binding has the shape of a binding of the semantic route it keeps (companion 9.4 and
    # 13.8): one whose context, binding, policy and core all name the direct kind while it keeps the old
    # channel's semantic route, lock, channel instance and route binding is refused, both as the
    # Proposal's extension list and as the target a sender carrying that list would build.
    kind_changed = RTarget(w, 1, group=bytes([0x66] * 32), kind=DIRECT)
    entries.append(("reject-extensions-kind-changed.bin", kind_changed.extensions,
                    {"group_id": kind_changed.group, "cipher_suite": "1",
                     "new_conversation_id": kind_changed.new_conversation, "expected": "E2eeError::InvalidValue"}))
    entries.append(("reject-target-kind-changed.bin", kind_changed.tbs,
                    {"target_context_digest": kind_changed.digest, "target_binding_id": kind_changed.binding_id,
                     "target_context_core_id": kind_changed.core_id, "initial_member_plan_id": kind_changed.plan_id,
                     "expected": "E2eeError::InvalidValue"}))

    # Rejections.
    suite_one = targets[1]
    entries.append(("reject-extensions-duplicate-context.bin", r_mls_extensions(suite_one.context, contexts=2),
                    {"expected": "E2eeError::NonCanonical"}))
    entries.append(("reject-extensions-missing-required-capabilities.bin",
                    r_mls_extensions(suite_one.context, required=False), {"expected": "E2eeError::InvalidValue"}))
    entries.append(("reject-extensions-later-joiner-context.bin", suite_one.later_joiner_extensions(),
                    {"expected": "E2eeError::InvalidValue"}))
    entries.append(("reject-extensions-context-core-mismatch.bin",
                    r_mls_extensions(suite_one.context_with(bytes([0xEE] * 32))), {"expected": "E2eeError::InvalidValue"}))
    branch, attempt, finalization_id = direct
    entries.append(("reject-target-pinned-layout.bin", suite_one.pinned_layout(finalization_id),
                    {"finalization_id": finalization_id}))
    activation_id = entries[[name for name, _, _ in entries].index("suite-0001-record-05-activation.bin")][2]["semantic_id"]
    entries.append(("reject-initial-commit-names-activation.bin",
                    w.initial_commit(suite_one, activation_id, 0x91), {"prior_state_id": activation_id}))
    # An attempt naming another target's digest (and carrying that target),
    # and an attempt naming the authorized digest while carrying another
    # target, each sequenced right after the suite-1 finalization.
    wrong = RAttempt(w, suite_one, finalization_id, 0, 0x98, digest=targets[3].digest, carried=targets[3].tbs)
    replay = log.copy()
    records, _ = r_reinit(replay, suite_one, "unused", 0xC1)
    records = r_attempt_records(replay, wrong, "reject-other-digest")
    entries.extend(records)
    swapped = RAttempt(w, suite_one, finalization_id, 0, 0x9A, carried=targets[3].tbs)
    replay = log.copy()
    records, _ = r_reinit(replay, suite_one, "unused", 0xC1)
    records = r_attempt_records(replay, swapped, "reject-carried-target")
    entries.extend(records)
    values = {
        "network_id": NETWORK.hex(),
        "old_conversation_id": w.conversation.hex(),
        "old_group_id": R_OLD_GROUP.hex(),
        "genesis_binding_id": w.binding_id.hex(),
        "genesis_id": w.genesis_id.hex(),
        "sequencer_credential_id": w.sequencer_id.hex(),
        "bootstrap_policy_id": w.bootstrap_policy_id.hex(),
        "operational_policy_id": w.operational_policy_id.hex(),
        "route_binding": w.route.hex(),
    }
    return entries, values


def render_reinit_manifest(entries: list[tuple[str, bytes, dict[str, object]]], values: dict[str, str]) -> str:
    lines = [
        "# Generated by scripts/generate-e2ee-vectors.py; do not edit by hand.",
        "schema_version = 1",
        'generator = "python cryptography Ed25519, independent TLS encoder"',
        'evidence_class = "synthetic public-envelope chain with real signatures; MLS inputs are synthetic"',
    ]
    lines.extend(f'{name} = "{value}"' for name, value in values.items())
    lines.append("")
    for name, data, ids in entries:
        lines.append("[[vectors]]")
        lines.append(f'file = "{name}"')
        lines.append(f"encoded_length = {len(data)}")
        lines.append(f'sha256 = "{hashlib.sha256(data).hexdigest()}"')
        for key_name, value in ids.items():
            rendered = value.hex() if isinstance(value, bytes) else value
            lines.append(f'{key_name} = "{rendered}"')
        lines.append("")
    return "\n".join(lines).rstrip("\n") + "\n"


def main() -> None:
    files, ids, state = build_identity()
    manifest = render_manifest(files, ids)
    recovery = build_recovery(state)
    recovery_files = {str(entry["name"]): bytes(entry["data"]) for entry in recovery}
    if len(recovery_files) != len(recovery):
        raise SystemExit("recovery vector names collide")
    recovery_manifest = render_recovery_manifest(recovery)
    reinit, reinit_values = build_reinit()
    reinit_files = {name: data for name, data, _ in reinit}
    if len(reinit_files) != len(reinit):
        raise SystemExit("reinit vector names collide")
    reinit_manifest = render_reinit_manifest(reinit, reinit_values)
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
        on_disk = {path.name for path in REINIT_OUTPUT.glob("*.bin")}
        if on_disk != set(reinit_files):
            print("reinit vector set differs from the generated files", file=sys.stderr)
            sys.exit(1)
        for name, data in reinit_files.items():
            if (REINIT_OUTPUT / name).read_bytes() != data:
                print(f"stale reinit vector: {name}", file=sys.stderr)
                sys.exit(1)
        if (REINIT_OUTPUT / "manifest.toml").read_text(encoding="utf-8") != reinit_manifest:
            print("stale reinit manifest", file=sys.stderr)
            sys.exit(1)
        print(
            f"e2ee identity vectors: ok ({len(files)} files); recovery vectors: ok ({len(recovery_files)} files); "
            f"reinit vectors: ok ({len(reinit_files)} files)"
        )
        return
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (OUTPUT / name).write_bytes(data)
    (OUTPUT / "manifest.toml").write_text(manifest, encoding="utf-8")
    RECOVERY_OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, data in recovery_files.items():
        (RECOVERY_OUTPUT / name).write_bytes(data)
    (RECOVERY_OUTPUT / "manifest.toml").write_text(recovery_manifest, encoding="utf-8")
    REINIT_OUTPUT.mkdir(parents=True, exist_ok=True)
    for stale in REINIT_OUTPUT.glob("*.bin"):
        if stale.name not in reinit_files:
            stale.unlink()
    for name, data in reinit_files.items():
        (REINIT_OUTPUT / name).write_bytes(data)
    (REINIT_OUTPUT / "manifest.toml").write_text(reinit_manifest, encoding="utf-8")
    print(
        f"e2ee identity vectors: wrote {len(files)} files; recovery vectors: wrote {len(recovery_files)} files; "
        f"reinit vectors: wrote {len(reinit_files)} files"
    )


if __name__ == "__main__":
    main()
