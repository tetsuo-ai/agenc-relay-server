#!/usr/bin/env python3
"""Regenerate public, deterministic ARC release-decision fixtures."""

from __future__ import annotations

import copy
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from release_qualification.signing import DOMAIN

ROOT = Path(__file__).resolve().parent.parent
SEED = b"AgenC Relay release fixture seed"
EXECUTABLE = b"arcd release decision fixture executable\n"


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: object) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def public_pem(key: Ed25519PrivateKey) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def main() -> None:
    key = Ed25519PrivateKey.from_private_bytes(SEED)
    public = public_pem(key)
    target = "x86_64-unknown-linux-gnu"
    record = {
        "schema_version": 1,
        "source": {
            "commit": "f" * 40,
            "lock_sha256": digest(b"ARC fixture lock"),
            "source_sha256": digest(b"ARC fixture source"),
        },
        "candidate_sha256": digest(b"ARC fixture candidate"),
        "qualification_sha256": digest(b"ARC fixture qualification"),
        "public_key_sha256": digest(public),
        "targets": [target],
        "claims": ["core-v1", "federated-v1", "wss"],
        "decided_at": "2026-09-20T12:00:00Z",
        "artifacts": [{
            "target": target,
            "path": f"artifacts/{target}/arcd",
            "sha256": digest(EXECUTABLE),
            "build_record": f"artifacts/{target}/build.json",
            "build_record_sha256": digest(b"ARC fixture build"),
        }],
    }
    payload = canonical(record)
    fixture = ROOT / "test-data/release-decision"
    (fixture / "release.json").write_bytes(payload)
    (fixture / "release.sig").write_bytes(key.sign(DOMAIN + payload))
    (fixture / "release-public.pem").write_bytes(public)
    untrusted = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(b"ARC untrusted fixture").digest())
    (fixture / "untrusted-public.pem").write_bytes(public_pem(untrusted))
    corpus = ROOT / "test-data/fuzz-corpus/release-decision"
    (corpus / "canonical").write_bytes(payload)
    (corpus / "public-key").write_bytes(public)
    (corpus / "truncated").write_bytes(payload[:len(payload) // 2])
    (corpus / "unsorted-keys").write_bytes(payload.replace(b'"artifacts"', b'"zartifacts"', 1))
    (corpus / "whitespace").write_bytes(payload.replace(b":", b": "))
    both = copy.deepcopy(record)
    arm = "aarch64-unknown-linux-gnu"
    both["targets"].insert(0, arm)
    artifact = copy.deepcopy(both["artifacts"][0])
    artifact.update(target=arm, path=f"artifacts/{arm}/arcd", build_record=f"artifacts/{arm}/build.json")
    both["artifacts"].insert(0, artifact)
    (corpus / "two-targets").write_bytes(canonical(both))


if __name__ == "__main__":
    main()
