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
CHAIN_CORPUS = ROOT / "test-data/fuzz-corpus/e2ee-identity-chain"
TAG_CORPUS = ROOT / "test-data/fuzz-corpus/e2ee-tags"


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


def root_chain(count: int) -> bytes:
    roots = []
    for generation in range(count):
        tbs = (
            u16(1)
            + bytes([1] * 32)
            + opaque(ACCOUNT, 255)
            + u64(generation)
            + bytes([2 + generation] * 32)
            + u64(10)
            + u64(20)
            + (bytes(32) if generation == 0 else bytes([2 + generation - 1] * 32))
        )
        roots.append(tbs + bytes([3] * 64) + opaque(b"" if generation == 0 else bytes([4] * 64), 64))
    return opaque(ACCOUNT, 255) + vector(roots, 1_048_576)


def b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def tag_seeds() -> dict[str, bytes]:
    object_id = b64(bytes([5] * 32))
    segment = bytes(range(64))
    fragment = f"v1.{object_id}.0.1.{len(segment)}.{b64(segment)}"
    receipt = f"v1.{b64(bytes([6] * 32))}.{b64(bytes([7] * 80))}"
    return {
        "fragment-single": fragment.encode(),
        "fragment-first-of-two": f"v1.{object_id}.0.2.3000.{b64(bytes([8] * 2940))}".encode(),
        "receipt": receipt.encode(),
        "client-tags": f"+agenc.ag/e2ee={fragment};label=abc12".encode(),
        "client-tags-receipt": f"agenc.ag/e2ee-receipt={receipt};batch=b1".encode(),
        "decimal": b"4294967295",
        "base64url": b64(bytes([9] * 24)).encode(),
        "cursor-star": b"*",
    }


def write(directory: Path, name: str, data: bytes) -> None:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / name).write_bytes(data)


def check(directory: Path, name: str, data: bytes) -> bool:
    path = directory / name
    return path.is_file() and path.read_bytes() == data


def main() -> None:
    import sys

    checking = "--check" in sys.argv[1:]
    stale: list[str] = []

    def emit(directory: Path, name: str, data: bytes) -> None:
        if checking:
            if not check(directory, name, data):
                stale.append(f"{directory.name}/{name}")
        else:
            write(directory, name, data)

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
        emit(OBJECT_CORPUS, name, data)
    mls = {
        "private-application": private_message(1),
        "private-commit": private_message(3),
        "welcome": welcome(),
        "key-package": key_package(),
    }
    for name, data in mls.items():
        emit(MLS_CORPUS, name, data)
    chains = {
        "root-chain-one": root_chain(1),
        "root-chain-three": root_chain(3),
    }
    for name, data in chains.items():
        emit(CHAIN_CORPUS, name, data)
    tags = tag_seeds()
    for name, data in tags.items():
        emit(TAG_CORPUS, name, data)
    if stale:
        print("e2ee fuzz seeds are stale: " + ", ".join(stale), file=sys.stderr)
        raise SystemExit(1)
    every = list(seeds.values()) + list(mls.values()) + list(chains.values()) + list(tags.values())
    digest = hashlib.sha256(b"".join(every)).hexdigest()
    print(
        f"e2ee fuzz seeds: {len(seeds)} object, {len(mls)} mls-outer, {len(chains)} identity-chain, "
        f"{len(tags)} tags, sha256 {digest}"
    )


if __name__ == "__main__":
    main()
