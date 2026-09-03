#!/usr/bin/env python3
"""Write the structured seed corpora for the Stage 08 E2EE fuzz targets.

The seeds are built by an independent TLS encoder so a divergence between
this script and the Rust codec surfaces as a rejected seed rather than a
shared mistake. Run from the repository root; the output is deterministic.
"""

from __future__ import annotations

import hashlib
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OBJECT_CORPUS = ROOT / "test-data/fuzz-corpus/e2ee-object"
MLS_CORPUS = ROOT / "test-data/fuzz-corpus/e2ee-mls-outer"


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


def envelope(kind: int, body: bytes) -> bytes:
    return u16(1) + u8(kind) + opaque(body, 4_194_298)


def mls_varint(value: int) -> bytes:
    if value < 0x40:
        return bytes([value])
    if value < 0x4000:
        return (value | 0x4000).to_bytes(2, "big")
    return (value | 0x8000_0000).to_bytes(4, "big")


def opaque_v(data: bytes) -> bytes:
    return mls_varint(len(data)) + data


ACCOUNT = b"a" * 24


def root_identity_tbs() -> bytes:
    return (
        u16(1)
        + bytes([1] * 32)
        + opaque(ACCOUNT, 255)
        + u64(0)
        + bytes([2] * 32)
        + u64(10)
        + u64(20)
        + bytes(32)
    )


def root_identity() -> bytes:
    return root_identity_tbs() + bytes([3] * 64) + opaque(b"", 64)


def candidate_receipt() -> bytes:
    tbs = (
        u16(1)
        + bytes([1] * 32)
        + bytes([20] * 32)
        + u64(0)
        + u64(0)
        + u64(1)
        + u32(0)
        + bytes([49] * 32)
        + bytes([50] * 32)
        + bytes([50] * 32)
        + u64(7)
        + bytes([31] * 32)
    )
    return tbs + bytes([51] * 64)


def attach_challenge() -> bytes:
    tbs = (
        u16(1)
        + bytes([1] * 32)
        + opaque(ACCOUNT, 255)
        + bytes([7] * 16)
        + bytes([96] * 32)
        + bytes([97] * 32)
        + u64(1)
        + u64(1)
        + u64(61)
    )
    return tbs + bytes([98] * 64)


def commit_ack() -> bytes:
    tbs = (
        u16(1)
        + bytes([1] * 32)
        + bytes([20] * 32)
        + u64(0)
        + bytes([52] * 32)
        + bytes([49] * 32)
        + u32(0)
        + bytes([55] * 32)
        + u64(1)
        + bytes([53] * 32)
        + bytes([54] * 32)
        + bytes([56] * 32)
    )
    return tbs + opaque(bytes([57] * 64), 255)


def federation_origin() -> bytes:
    return (
        u16(1)
        + bytes([1] * 32)
        + bytes([102] * 16)
        + bytes([103] * 16)
        + bytes([104] * 16)
        + u64(0)
        + bytes(32)
        + bytes([114] * 16)
        + opaque(bytes([115] * 16), 16)
        + opaque(bytes([113] * 16), 16)
        + opaque(ACCOUNT, 24)
        + u64(1)
        + bytes([96] * 32)
        + opaque(bytes([7] * 16), 16)
        + u64(1)
    )


def private_message(content_type: int) -> bytes:
    return (
        u16(1)
        + u16(2)
        + opaque_v(bytes([7] * 32))
        + u64(9)
        + u8(content_type)
        + opaque_v(b"aad")
        + opaque_v(bytes([1] * 40))
        + opaque_v(bytes([2] * 300))
    )


def welcome() -> bytes:
    secrets = b"".join(
        opaque_v(bytes([member] * 32)) + opaque_v(bytes([5] * 32)) + opaque_v(bytes([6] * 64))
        for member in (3, 4)
    )
    return u16(1) + u16(3) + u16(1) + opaque_v(secrets) + opaque_v(bytes([8] * 500))


def key_package() -> bytes:
    leaf = (
        opaque_v(bytes([11] * 32))
        + opaque_v(bytes([12] * 32))
        + u16(1)
        + opaque_v(b"identity bundle bytes")
        + opaque_v(u16(1))
        + opaque_v(u16(1) + u16(3))
        + opaque_v(b"")
        + opaque_v(b"")
        + opaque_v(u16(1))
        + u8(1)
        + u64(100)
        + u64(200)
        + opaque_v(b"")
        + opaque_v(bytes([13] * 64))
    )
    tbs = u16(1) + u16(1) + opaque_v(bytes([14] * 32)) + leaf + opaque_v(b"")
    return u16(1) + u16(5) + tbs + opaque_v(bytes([15] * 64))


def write(directory: Path, name: str, data: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


def main() -> None:
    seeds = {
        "root-identity": envelope(10, root_identity()),
        "sequencer-record-candidate": envelope(25, u8(1) + candidate_receipt()),
        "device-attach-challenge": envelope(26, attach_challenge()),
        "commit-ack": envelope(4, commit_ack()),
        "federation-origin": envelope(30, federation_origin()),
        "application-mls": envelope(1, private_message(1)),
        "commit-mls": envelope(2, private_message(3)),
        "key-package-mls": envelope(14, key_package()),
    }
    for name, data in seeds.items():
        write(OBJECT_CORPUS, name, data)
    mls = {
        "private-application": private_message(1),
        "private-commit": private_message(3),
        "welcome": welcome(),
        "key-package": key_package(),
    }
    for name, data in mls.items():
        write(MLS_CORPUS, name, data)
    digest = hashlib.sha256(b"".join(seeds.values()) + b"".join(mls.values())).hexdigest()
    print(f"e2ee fuzz seeds: {len(seeds)} object, {len(mls)} mls-outer, sha256 {digest}")


if __name__ == "__main__":
    main()
