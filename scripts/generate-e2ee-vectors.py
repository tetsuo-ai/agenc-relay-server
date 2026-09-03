#!/usr/bin/env python3
"""Generate independent companion-object vectors for the Stage 08 gates.

This generator is deliberately separate from the Rust codec: it encodes the
TLS presentation language, computes semantic identifiers, and signs with
Ed25519 through the `cryptography` package. The Rust crate must decode
every vector, recompute every identifier, and verify every signature. Keys
are derived from fixed seeds so the output is reproducible.

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
    """`IrcSignatureInput { opaque label<1..255>; opaque content<0..2^24-1>; }`."""
    return opaque(label.encode(), 255) + opaque(content, 0xFFFFFF)


def sign(private: Ed25519PrivateKey, label: str, tbs: bytes) -> bytes:
    return private.sign(irc_signature_input(f"IRC-MLS/1 {label}", tbs))


def semantic_id(label: str, encoding: bytes) -> bytes:
    return hashlib.sha256(f"IRC-MLS/1 {label}".encode() + encoding).digest()


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
    return files, ids


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
    files, ids = build()
    manifest = render_manifest(files, ids)
    if "--check" in sys.argv[1:]:
        for name, data in files.items():
            if (OUTPUT / name).read_bytes() != data:
                print(f"stale vector: {name}", file=sys.stderr)
                sys.exit(1)
        if (OUTPUT / "manifest.toml").read_text(encoding="utf-8") != manifest:
            print("stale manifest", file=sys.stderr)
            sys.exit(1)
        print(f"e2ee identity vectors: ok ({len(files)} files)")
        return
    OUTPUT.mkdir(parents=True, exist_ok=True)
    for name, data in files.items():
        (OUTPUT / name).write_bytes(data)
    (OUTPUT / "manifest.toml").write_text(manifest, encoding="utf-8")
    print(f"e2ee identity vectors: wrote {len(files)} files")


if __name__ == "__main__":
    main()
