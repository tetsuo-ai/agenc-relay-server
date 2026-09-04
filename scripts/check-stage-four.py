#!/usr/bin/env python3
"""Validate Stage-04 cryptographic profiles, boundaries, dependencies, and evidence."""

from __future__ import annotations

import argparse
import copy
import hashlib
import re
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

PROFILE_PATH = "conformance/stage-four-crypto-profile.toml"
EXPECTED_TASKS = tuple(f"S04-{number:03d}" for number in range(1, 15))
EXPECTED_CRYPTO_MODULES = {
    "account_hpke.rs",
    "entropy.rs",
    "error.rs",
    "hash.rs",
    "secret.rs",
    "signature.rs",
    "storage.rs",
    "storage_integrity.rs",
    "tls_ticket.rs",
    "worker.rs",
}
EXPECTED_AUTH_MODULES = {
    "channel_key.rs",
    "error.rs",
    "invitation.rs",
    "opaque.rs",
    "service.rs",
    "transaction.rs",
    "wire.rs",
}
EXPECTED_CRYPTO_DEPENDENCIES = {
    "agenc-ircd-types",
    "chacha20poly1305",
    "ed25519-dalek",
    "getrandom",
    "hkdf",
    "hmac",
    "hpke",
    "sha2",
    "subtle",
    "tokio",
    "zeroize",
}
EXPECTED_AUTH_DEPENDENCIES = {
    "agenc-ircd-crypto",
    "agenc-ircd-types",
    "argon2",
    "opaque-ke",
    "opaque-sha2",
    "subtle",
    "tls_codec",
    "zeroize",
}
EXPECTED_PRIMITIVES = {
    "opaque": {
        "suite": "ristretto255-SHA512, TripleDH, HKDF-SHA512, HMAC-SHA512",
        "argon2_memory_kib": 65_536,
        "argon2_iterations": 3,
        "argon2_lanes": 4,
        "argon2_output_bytes": 64,
        "registration_request_bytes": 32,
        "registration_response_bytes": 64,
        "registration_record_bytes": 192,
        "ke1_bytes": 96,
        "ke2_bytes": 320,
        "ke3_bytes": 64,
    },
    "hpke": {
        "mode": "base",
        "kem": "DHKEM-X25519-HKDF-SHA256",
        "kdf": "HKDF-SHA256",
        "aead": "ChaCha20Poly1305",
        "request_envelope_bytes": 4_726,
        "response_envelope_bytes": 4_342,
    },
    "storage": {
        "aead": "XChaCha20Poly1305",
        "key_bytes": 32,
        "nonce_bytes": 24,
        "tag_bytes": 16,
    },
    "signature": {"algorithm": "Ed25519", "verification": "verify_strict"},
}
EXPECTED_WORKER = {
    "channel_job_limit_max": 64,
    "opaque_job_limit_max": 128,
    "worker_max": 128,
    "physical_queue_slots_per_worker": 2,
    "reserved_bytes_per_worker": 75_497_472,
}
EXPECTED_FUZZ = {
    "targets": ["account_service_envelope", "crypto_wrappers"],
    "seed": 20_260_827,
    "runs": 10_000,
    "max_len": 4_726,
    "timeout_seconds": 2,
    "rss_limit_mb": 512,
}
EXPECTED_FUZZ_SMOKE = {
    "schema_version": 1,
    "evidence_id": "EVID-S04-014-VERIFICATION",
    "toolchain": "nightly-2026-08-24",
    "cargo_fuzz": "0.13.2",
    "seed": 20_260_827,
    "runs": 10_000,
    "max_len": 4_726,
    "timeout_seconds": 2,
    "rss_limit_mb": 512,
    "executed_on": "2026-08-27",
    "result": "pass",
    "targets": ["account_service_envelope", "crypto_wrappers"],
    "limitations": "The 24 CPU-hour release campaign for each parser target remains S10-004 evidence.",
}
EXPECTED_SOURCE_PATCH = {
    "package": "opaque-ke",
    "version": "4.0.1",
    "path": "vendor/opaque-ke-4.0.1",
    "upstream_registry": "https://github.com/rust-lang/crates.io-index",
    "upstream_checksum": "ded22991b43cd15561b62b2e1cf9ace1344a8534eebec96202d5c96a77a6616a",
    "tree_sha256": "8f745b2d6dd9918602ef67313be5cfd7b0185fa1314ea38530560403cd57d96e",
    "modified_files": ["src/opaque.rs"],
    "reason": "zeroize password-derived intermediates and the server-finish session key",
}
EXPECTED_VECTOR_FILES = {
    "test-data/vectors/stage-four-crypto-v1.vectors": {
        "sha256": "a3c88fc13fdf701d4ca5b2798b2a8db43269e2b1e3debd9ade81ea256b740ede",
        "generator": "crates/agenc-ircd-crypto/tests/generate_stage_four_vectors.rs",
        "generator_sha256": "12c23093367bc95fde8381accef1340ee977974c279948772c49d270ecdaa37a",
        "records": {
            "VEC-S04-003-SHA256",
            "VEC-S04-003-LOGIN-HMAC",
            "VEC-S04-003-FAKE-HMAC",
            "VEC-S04-003-004-STORAGE",
            "VEC-S04-005-ED25519",
            "VEC-S04-006-HPKE",
        },
        "source": "project-reference",
    },
    "test-data/vectors/stage-four-opaque-v1.vectors": {
        "sha256": "a0134c2b46c08def5d5081a58d2a6212b3d90fe4ef55f9242f563452440abf3f",
        "generator": "crates/agenc-ircd-auth/tests/generate_stage_four_vectors.rs",
        "generator_sha256": "3f1afff29e1f54e6d1eda0fd24b58f69742f0c5bc2dffb20f7c70f707d378270",
        "records": {"VEC-S04-007-OPAQUE"},
        "source": "opaque-ke-4.0.1-reference",
    },
}
EXPECTED_CONSTANT_TIME_SURFACES = {
    "crates/agenc-ircd-auth/src/service.rs",
    "crates/agenc-ircd-auth/src/opaque.rs",
    "crates/agenc-ircd-crypto/src/hash.rs",
    "crates/agenc-ircd-crypto/src/storage.rs",
    "vendor/opaque-ke-4.0.1/src/opaque.rs",
    "vendor/opaque-ke-4.0.1/src/key_exchange/tripledh.rs",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
EXPECTED_DEPENDENCIES = (
    ("argon2", "argon2", "0.5.3", "3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072", ["alloc"]),
    ("chacha20poly1305", "chacha20poly1305", "0.11.0", "9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb", ["alloc", "zeroize"]),
    ("ed25519-dalek", "ed25519-dalek", "3.0.0", "6ebaa1a2bf1290ab3bfe5a7b771d050ebffab2711c19a81691c683a5144a25de", ["fast", "zeroize"]),
    ("getrandom", "getrandom", "0.4.3", "300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099", ["std"]),
    ("hkdf", "hkdf", "0.13.0", "4aaa26c720c68b866f2c96ef5c1264b3e6f473fe5d4ce61cd44bbe913e553018", []),
    ("hmac", "hmac", "0.13.0", "6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f", ["zeroize"]),
    ("hpke", "hpke", "0.14.0", "dd5130e119706b4d8c2180da6126f7e60b6c38c2d340d539219f57051f0a7af7", ["alloc", "chacha", "x25519", "hkdfsha2"]),
    ("opaque-ke", "opaque-ke", "4.0.1", "ded22991b43cd15561b62b2e1cf9ace1344a8534eebec96202d5c96a77a6616a", ["ristretto255", "argon2", "std"]),
    ("opaque-sha2", "sha2", "0.10.9", "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283", []),
    ("sha2", "sha2", "0.11.0", "446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4", ["zeroize"]),
    ("subtle", "subtle", "2.6.1", "13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292", []),
    ("tls_codec", "tls_codec", "0.5.0", "18cc98286004cea38f717e2b03d990fc774fbfd38a82720de40e5c94365067c8", ["std", "mls"]),
    ("tokio", "tokio", "1.53.1", "202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed", ["rt-multi-thread", "net", "io-util", "time", "signal", "sync", "macros"]),
    ("zeroize", "zeroize", "1.9.0", "e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e", ["alloc"]),
)
EXPECTED_DUPLICATE_GENERATIONS = {
    "const-oid": {"0.9.6", "0.10.2"},
    "curve25519-dalek": {"4.1.3", "5.0.0"},
    "getrandom": {"0.2.17", "0.4.3"},
    "hkdf": {"0.12.4", "0.13.0"},
    "hmac": {"0.12.1", "0.13.0"},
    "sha2": {"0.10.9", "0.11.0"},
}
EXPECTED_DENY_SKIPS = {
    "block-buffer@0.10.4": "opaque-ke 4.0.1 retains the reviewed RustCrypto 0.10 generation",
    "cpufeatures@0.2.17": "opaque-ke 4.0.1 retains the reviewed RustCrypto 0.10 generation",
    "crypto-common@0.1.7": "opaque-ke 4.0.1 retains the reviewed RustCrypto 0.10 generation",
    "curve25519-dalek@4.1.3": "opaque-ke 4.0.1 pins the RFC-9807-compatible curve generation",
    "digest@0.10.7": "opaque-ke 4.0.1 retains the reviewed RustCrypto 0.10 generation",
    "hkdf@0.12.4": "opaque-ke 4.0.1 retains its audited internal HKDF generation",
    "hmac@0.12.1": "opaque-ke 4.0.1 retains its audited internal HMAC generation",
    "rand_core@0.6.4": "opaque-ke 4.0.1 retains its audited internal RNG trait generation",
    "sha2@0.10.9": "opaque-ke 4.0.1 uses the reviewed SHA-512 generation through a scoped alias",
    "syn@2.0.119": "the reviewed crypto derive graph and current proc macros span syn 2 and 3",
    "const-oid@0.10.2": "the test-only MLS clients (openmls, mls-rs) for the Stage 08 interoperability gate use the current RustCrypto generation",
    "getrandom@0.4.3": "the test-only MLS clients (openmls, mls-rs) for the Stage 08 interoperability gate use the current getrandom generation",
}
REQUIRED_SURFACES = (
    "pub(crate) struct SecretBytes",
    "pub struct OsEntropy",
    "pub enum SemanticHashDomain",
    "pub fn seal_storage_record",
    "pub fn verify_canonical",
    "pub fn seal_account_request",
    "pub struct BoundedCryptoPool",
    "pub trait CryptoPort",
    "pub struct OpaqueProfile",
    "pub struct AccountServiceEnvelope",
    "pub fn begin_account_creation",
    "pub fn begin_authentication",
    "pub fn begin_credential_change",
    "pub fn begin_account_deletion",
)


class StageFourError(ValueError):
    """A Stage-04 conformance failure."""


def load_toml(path: Path) -> dict[str, object]:
    """Load one TOML file with one stable error class."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise StageFourError(f"cannot read {path}: {error}") from error


def vendored_tree_sha256(path: Path) -> str:
    """Hash every path and byte in the reviewed OPAQUE source tree."""
    digest = hashlib.sha256()
    files = sorted(path.rglob("*"), key=lambda value: value.relative_to(path).as_posix())
    if not files:
        raise StageFourError(f"vendored dependency tree is empty: {path}")
    file_count = 0
    for candidate in files:
        if candidate.is_symlink():
            raise StageFourError(f"vendored dependency contains a symlink: {candidate}")
        if not candidate.is_file():
            continue
        relative = candidate.relative_to(path).as_posix().encode("utf-8")
        contents = candidate.read_bytes()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
        file_count += 1
    if file_count == 0:
        raise StageFourError(f"vendored dependency tree has no files: {path}")
    return digest.hexdigest()


def file_sha256(path: Path) -> str:
    """Return the SHA-256 digest of one immutable evidence input."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def decode_vector_hex(value: str) -> bytes:
    """Decode one canonical lowercase hexadecimal vector field."""
    if len(value) % 2 != 0 or re.fullmatch(r"[0-9a-f]*", value) is None:
        raise StageFourError("golden vector field is not canonical lowercase hexadecimal")
    try:
        return bytes.fromhex(value)
    except ValueError as error:
        raise StageFourError("golden vector field cannot be decoded") from error


def parse_vector_records(path: Path) -> dict[str, tuple[str, dict[str, str]]]:
    """Parse the closed pipe-delimited Stage-04 vector format."""
    records: dict[str, tuple[str, dict[str, str]]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split("|")
        if len(parts) < 4:
            raise StageFourError(f"golden vector record is malformed: {path}")
        record_id, _kind, source, *encoded_fields = parts
        if record_id in records:
            raise StageFourError(f"golden vector record is duplicated: {record_id}")
        fields: dict[str, str] = {}
        for encoded_field in encoded_fields:
            name, separator, value = encoded_field.partition("=")
            if not separator or not name or name in fields:
                raise StageFourError(f"golden vector field is malformed: {record_id}")
            fields[name] = value
        records[record_id] = (source, fields)
    return records


def vector_output_fields(record_id: str) -> tuple[str, ...]:
    """Return the reviewed output digest order for one vector record."""
    fields = {
        "VEC-S04-003-SHA256": ("expected",),
        "VEC-S04-003-LOGIN-HMAC": ("expected",),
        "VEC-S04-003-FAKE-HMAC": ("expected",),
        "VEC-S04-003-004-STORAGE": (
            "record_key",
            "index_key",
            "index",
            "ciphertext",
        ),
        "VEC-S04-005-ED25519": ("signature",),
        "VEC-S04-006-HPKE": (
            "encapsulated",
            "request_ciphertext",
            "response_salt",
            "response_key",
            "response_nonce",
            "response_ciphertext",
        ),
        "VEC-S04-007-OPAQUE": (
            "setup",
            "fake_record",
            "registration_request",
            "registration_response",
            "registration_upload",
            "registration_record",
            "ke1",
            "ke2",
            "ke3",
            "server_login_state",
            "session_key",
            "fake_ke1",
            "fake_ke2",
            "fake_server_login_state",
            "dummy_ke1",
            "dummy_ke2",
            "dummy_server_login_state",
            "dummy_ke3",
        ),
    }
    try:
        return fields[record_id]
    except KeyError as error:
        raise StageFourError(f"golden vector record is not registered: {record_id}") from error


def expected_dependency_records() -> list[dict[str, object]]:
    """Build the reviewed dependency records in their canonical order."""
    return [
        {
            "logical_name": logical_name,
            "package": package,
            "version": version,
            "checksum": checksum,
            "features": features,
        }
        for logical_name, package, version, checksum, features in EXPECTED_DEPENDENCIES
    ]


def validate_profile(document: dict[str, object]) -> None:
    """Validate the complete independently reviewed Stage-04 profile."""
    if set(document) != {
        "schema_version",
        "evidence_id",
        "source_patch",
        "primitive",
        "worker",
        "fuzz",
        "dependency",
    }:
        raise StageFourError("crypto profile has missing or unknown top-level fields")
    if document.get("schema_version") != 1 or document.get("evidence_id") != "EVID-S04-013-DEPENDENCIES":
        raise StageFourError("crypto profile header is invalid")
    if document.get("primitive") != EXPECTED_PRIMITIVES:
        raise StageFourError("cryptographic primitive profile differs from the specification")
    if document.get("worker") != EXPECTED_WORKER:
        raise StageFourError("crypto worker limits differ from the specification")
    if document.get("fuzz") != EXPECTED_FUZZ:
        raise StageFourError("account-envelope fuzz policy differs from the reviewed values")
    if document.get("source_patch") != EXPECTED_SOURCE_PATCH:
        raise StageFourError("vendored OPAQUE source profile differs from the reviewed patch")
    if document.get("dependency") != expected_dependency_records():
        raise StageFourError("cryptographic dependency records differ from the reviewed pins")


def validate_modules(root: Path) -> None:
    """Require the closed module sets, safe-Rust policy, and crate boundaries."""
    roots = {
        root / "crates/agenc-ircd-crypto/src": EXPECTED_CRYPTO_MODULES,
        root / "crates/agenc-ircd-auth/src": EXPECTED_AUTH_MODULES,
    }
    sources: list[str] = []
    for source_root, expected_modules in roots.items():
        modules = {path.name for path in source_root.glob("*.rs") if path.name != "lib.rs"}
        if modules != expected_modules:
            raise StageFourError(f"{source_root.parent.name} module set is missing or unexpected")
        for path in source_root.glob("*.rs"):
            source = path.read_text(encoding="utf-8")
            if "#![forbid(unsafe_code)]" not in source and path.name == "lib.rs":
                raise StageFourError(f"safe-Rust policy is absent from {path}")
            sources.append(source)
    combined = "\n".join(sources)
    if any(surface not in combined for surface in REQUIRED_SURFACES):
        raise StageFourError("a required Stage-04 adapter or state-machine surface is absent")
    forbidden = (
        "serde::",
        "#[derive(Serialize",
        "#[derive(Deserialize",
        "hazmat",
        "verify_batch",
        "unbounded_channel",
    )
    if any(marker in combined for marker in forbidden):
        raise StageFourError("crypto/auth source exposes a forbidden algorithm or serialization surface")


def validate_manifests(root: Path, profile: dict[str, object]) -> None:
    """Check exact direct dependency sets, features, sources, and checksums."""
    crypto = load_toml(root / "crates/agenc-ircd-crypto/Cargo.toml")
    auth = load_toml(root / "crates/agenc-ircd-auth/Cargo.toml")
    if set(crypto.get("dependencies", {})) != EXPECTED_CRYPTO_DEPENDENCIES:
        raise StageFourError("crypto crate dependency surface is missing or unexpected")
    if set(auth.get("dependencies", {})) != EXPECTED_AUTH_DEPENDENCIES:
        raise StageFourError("auth crate dependency surface is missing or unexpected")

    workspace = load_toml(root / "Cargo.toml")
    workspace_dependencies = workspace.get("workspace", {}).get("dependencies", {})
    if not isinstance(workspace_dependencies, dict):
        raise StageFourError("workspace dependency table is absent")
    expected_patch = {"crates-io": {"opaque-ke": {"path": EXPECTED_SOURCE_PATCH["path"]}}}
    if workspace.get("patch") != expected_patch:
        raise StageFourError("root source patch differs from the reviewed OPAQUE override")
    patch_root = root / str(EXPECTED_SOURCE_PATCH["path"])
    if vendored_tree_sha256(patch_root) != EXPECTED_SOURCE_PATCH["tree_sha256"]:
        raise StageFourError("vendored OPAQUE tree digest differs from the reviewed source")
    dependencies = profile.get("dependency")
    if not isinstance(dependencies, list):
        raise StageFourError("crypto profile dependency list is absent")
    for record in dependencies:
        if not isinstance(record, dict):
            raise StageFourError("crypto profile contains a malformed dependency record")
        logical_name = record["logical_name"]
        configured = workspace_dependencies.get(logical_name)
        expected = {
            "version": f"={record['version']}",
            "default-features": False,
        }
        features = record["features"]
        if features:
            expected["features"] = features
        if logical_name != record["package"]:
            expected["package"] = record["package"]
        if configured != expected:
            raise StageFourError(f"workspace profile differs for {logical_name}")

    lock = load_toml(root / "Cargo.lock")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise StageFourError("Cargo.lock has no package records")
    for package in packages:
        if not isinstance(package, dict):
            raise StageFourError("Cargo.lock contains a malformed package record")
        source = package.get("source")
        if isinstance(source, str) and source.startswith("git+"):
            raise StageFourError("Cargo.lock contains a forbidden Git dependency")
    for record in dependencies:
        matches = [
            package
            for package in packages
            if isinstance(package, dict)
            and package.get("name") == record["package"]
            and package.get("version") == record["version"]
        ]
        if len(matches) != 1:
            raise StageFourError(f"Cargo.lock pin differs for {record['logical_name']}")
        if record["logical_name"] == "opaque-ke":
            if "checksum" in matches[0] or "source" in matches[0]:
                raise StageFourError("Cargo.lock does not select the reviewed local OPAQUE patch")
        else:
            if matches[0].get("checksum") != record["checksum"]:
                raise StageFourError(
                    f"Cargo.lock checksum differs for {record['logical_name']}"
                )
            if matches[0].get("source") != "registry+https://github.com/rust-lang/crates.io-index":
                raise StageFourError(f"Cargo.lock source differs for {record['logical_name']}")
    for package_name, expected_versions in EXPECTED_DUPLICATE_GENERATIONS.items():
        actual_versions = {
            str(package.get("version"))
            for package in packages
            if isinstance(package, dict) and package.get("name") == package_name
        }
        if actual_versions != expected_versions:
            raise StageFourError(f"reviewed duplicate generations differ for {package_name}")
    deny = load_toml(root / "deny.toml")
    bans = deny.get("bans")
    if not isinstance(bans, dict):
        raise StageFourError("cargo-deny bans policy is absent")
    skip = bans.get("skip")
    if not isinstance(skip, list):
        raise StageFourError("cargo-deny duplicate exceptions are absent")
    actual_skips = {
        record.get("crate"): record.get("reason")
        for record in skip
        if isinstance(record, dict)
    }
    if actual_skips != EXPECTED_DENY_SKIPS or len(skip) != len(EXPECTED_DENY_SKIPS):
        raise StageFourError("cargo-deny duplicate exceptions differ from the reviewed set")


def validate_fuzz(root: Path) -> None:
    """Require both Stage-04 parser targets, seed corpora, and smoke records."""
    manifest = load_toml(root / "fuzz/Cargo.toml")
    binaries = manifest.get("bin")
    if not isinstance(binaries, list):
        raise StageFourError("fuzz manifest has no binary targets")
    targets = {
        "account_service_envelope": {
            "path": "fuzz_targets/account_service_envelope.rs",
            "corpus": "account-service-envelope",
            "markers": (
                "AccountServiceEnvelope::parse",
                "AccountServiceResponse::parse",
                "open_and_parse_request",
                "open_and_parse_response",
            ),
        },
        "crypto_wrappers": {
            "path": "fuzz_targets/crypto_wrappers.rs",
            "corpus": "crypto-wrappers",
            "markers": (
                "OpaqueRegistrationRequest::from_bytes",
                "OpaqueServerLoginState::from_persisted_bytes",
                "AccountCreationInvite::parse",
                "verify_canonical",
                "SealedStorageRecord::from_bytes",
                "open_storage_record",
            ),
        },
    }
    if list(targets) != EXPECTED_FUZZ["targets"]:
        raise StageFourError("Stage-04 fuzz target registry differs from the profile")
    for name, expected in targets.items():
        target = next(
            (record for record in binaries if isinstance(record, dict) and record.get("name") == name),
            None,
        )
        expected_record = {
            "name": name,
            "path": expected["path"],
            "test": False,
            "doc": False,
            "bench": False,
        }
        if target != expected_record:
            raise StageFourError(f"{name} fuzz target is absent or malformed")
        source = (root / "fuzz" / str(expected["path"])).read_text(encoding="utf-8")
        required_markers = ("#![no_main]", "#![forbid(unsafe_code)]", *expected["markers"])
        if any(marker not in source for marker in required_markers):
            raise StageFourError(f"{name} fuzz target misses a required parser boundary")
        corpus = root / "test-data/fuzz-corpus" / str(expected["corpus"])
        if not corpus.is_dir() or not any(path.is_file() for path in corpus.iterdir()):
            raise StageFourError(f"{name} fuzz corpus is empty")
    smoke = load_toml(root / "conformance/stage-four-fuzz-smoke.toml")
    if smoke != EXPECTED_FUZZ_SMOKE:
        raise StageFourError("Stage-04 fuzz smoke record is missing, stale, or failed")


def validate_vectors(root: Path) -> None:
    """Require immutable generator-bound vectors and independent consumers."""
    for relative_path, expected in EXPECTED_VECTOR_FILES.items():
        vector_path = root / relative_path
        if not vector_path.is_file() or file_sha256(vector_path) != expected["sha256"]:
            raise StageFourError(f"golden vector file is absent or changed: {relative_path}")
        generator_path = root / str(expected["generator"])
        if not generator_path.is_file() or file_sha256(generator_path) != expected["generator_sha256"]:
            raise StageFourError(f"golden vector generator is absent or changed: {generator_path}")
        generator_source = generator_path.read_text(encoding="utf-8")
        if (
            "#[ignore = \"manual reviewed golden-vector generation\"]" not in generator_source
            or "output_sha256" not in generator_source
        ):
            raise StageFourError(f"golden vector generator is not manual and digest-bound: {generator_path}")
        production_adapter = (
            "agenc_ircd_crypto::"
            if "agenc-ircd-crypto" in str(generator_path)
            else "agenc_ircd_auth::"
        )
        if production_adapter in generator_source:
            raise StageFourError(f"golden vector generator calls a production adapter: {generator_path}")
        vector_source = vector_path.read_text(encoding="utf-8")
        if f"# generated by {expected['generator']}" not in vector_source:
            raise StageFourError(f"golden vector provenance is absent: {relative_path}")
        records = parse_vector_records(vector_path)
        if set(records) != expected["records"]:
            raise StageFourError(f"golden vector record set differs: {relative_path}")
        for record_id, (source, fields) in records.items():
            if source != expected["source"]:
                raise StageFourError(f"golden vector source differs: {record_id}")
            digest = fields.get("output_sha256")
            if not isinstance(digest, str) or SHA256_RE.fullmatch(digest) is None:
                raise StageFourError(f"golden vector output digest is malformed: {record_id}")
            output = bytearray()
            for name in vector_output_fields(record_id):
                value = fields.get(name)
                if value is None:
                    raise StageFourError(f"golden vector output field is absent: {record_id}.{name}")
                output.extend(decode_vector_hex(value))
            if hashlib.sha256(output).hexdigest() != digest:
                raise StageFourError(f"golden vector output digest differs: {record_id}")

    crypto_test = root / "crates/agenc-ircd-crypto/tests/stage_four_vectors.rs"
    auth_test = root / "crates/agenc-ircd-auth/tests/stage_four_vectors.rs"
    security_test = root / "crates/agenc-ircd-auth/tests/stage_four_security.rs"
    for path in (crypto_test, auth_test, security_test):
        if not path.is_file():
            raise StageFourError(f"Stage-04 vector or security test is absent: {path}")
    crypto_source = crypto_test.read_text(encoding="utf-8")
    auth_source = auth_test.read_text(encoding="utf-8")
    security_source = security_test.read_text(encoding="utf-8")
    crypto_markers = (
        "stage-four-crypto-v1.vectors",
        "immutable_storage_vector_rejects_tamper_and_context_substitution",
        "immutable_strict_ed25519_vector_matches_and_rejects_substitution",
        "immutable_hpke_vector_rejects_binding_substitution_and_tamper",
    )
    auth_markers = (
        "stage-four-opaque-v1.vectors",
        "immutable_opaque_vector_rejects_setup_record_identity_and_ke3_substitution",
        "nonzero_padding_request_envelope",
        "request_below_min_plaintext",
        "response_above_max_plaintext",
    )
    security_markers = (
        "secret_canary_never_enters_error_or_worker_capture_text",
        "shuffled_known_and_unknown_opaque_starts_share_one_timing_class",
        "CryptoWorkerError::WorkerPanicked",
        "CryptoWorkerError::CancelledBeforeStart",
    )
    if any(marker not in crypto_source for marker in crypto_markers):
        raise StageFourError("crypto golden-vector suite misses a required negative")
    if any(marker not in auth_source for marker in auth_markers):
        raise StageFourError("auth golden-vector suite misses a required negative")
    if any(marker not in security_source for marker in security_markers):
        raise StageFourError("Stage-04 security suite misses timing or secret-canary coverage")


def validate_constant_time_review(root: Path) -> None:
    """Bind the constant-time integration review to every inspected source."""
    path = root / "conformance/stage-four-constant-time-review.toml"
    review = load_toml(path)
    if (
        review.get("schema_version") != 1
        or review.get("evidence_id") != "EVID-S04-014-CONSTANT-TIME"
        or review.get("worktree_state") != "dirty-source-hash-bound"
        or re.fullmatch(r"[0-9a-f]{40}", str(review.get("reviewed_revision"))) is None
    ):
        raise StageFourError("constant-time review header is absent or malformed")
    measurement = review.get("measurement")
    if not isinstance(measurement, dict) or measurement.get("role") != (
        "Supplemental regression signal only. The source-bound path review is the primary evidence."
    ):
        raise StageFourError("constant-time measurement is not labeled as supplemental")
    gate = review.get("gate")
    if not isinstance(gate, dict) or gate.get("status") != "evidence-only":
        raise StageFourError("constant-time review incorrectly claims gate closure")
    surfaces = review.get("surface")
    if not isinstance(surfaces, list):
        raise StageFourError("constant-time review source list is absent")
    actual_paths = {
        str(surface.get("path"))
        for surface in surfaces
        if isinstance(surface, dict)
    }
    if actual_paths != EXPECTED_CONSTANT_TIME_SURFACES or len(surfaces) != len(actual_paths):
        raise StageFourError("constant-time review source set differs")
    for surface in surfaces:
        if not isinstance(surface, dict):
            raise StageFourError("constant-time review source record is malformed")
        relative_path = surface.get("path")
        digest = surface.get("sha256")
        symbols = surface.get("symbols")
        if (
            not isinstance(relative_path, str)
            or not isinstance(digest, str)
            or SHA256_RE.fullmatch(digest) is None
            or not isinstance(symbols, list)
            or not symbols
        ):
            raise StageFourError("constant-time review source record is incomplete")
        if file_sha256(root / relative_path) != digest:
            raise StageFourError(f"constant-time reviewed source changed: {relative_path}")


def validate_tests_and_roadmap(root: Path) -> None:
    """Require public-boundary suites and completed implementation tasks."""
    required_tests = (
        root / "crates/agenc-ircd-auth/tests/stage_four.rs",
        root / "crates/agenc-ircd-auth/tests/stage_four_vectors.rs",
        root / "crates/agenc-ircd-auth/tests/stage_four_security.rs",
        root / "crates/agenc-ircd-crypto/tests/stage_four.rs",
        root / "crates/agenc-ircd-crypto/tests/stage_four_vectors.rs",
        root / "crates/agenc-ircd-testkit/tests/stage_four_domain_auth.rs",
    )
    if any(not path.is_file() for path in required_tests):
        raise StageFourError("a Stage-04 public-boundary test suite is absent")
    roadmap = (root / "TODO.md").read_text(encoding="utf-8")
    for task in EXPECTED_TASKS:
        if re.search(rf"^- \[x\] `{task}`", roadmap, flags=re.MULTILINE) is None:
            raise StageFourError(f"roadmap implementation task is not complete: {task}")


def validate(root: Path) -> None:
    """Validate every independent Stage-04 conformance surface."""
    profile = load_toml(root / PROFILE_PATH)
    validate_profile(profile)
    validate_modules(root)
    validate_manifests(root, profile)
    validate_fuzz(root)
    validate_vectors(root)
    validate_constant_time_review(root)
    validate_tests_and_roadmap(root)


def expect_rejection(label: str, document: dict[str, object], fragment: str) -> None:
    """Require one profile mutation to reach its intended rejection."""
    try:
        validate_profile(document)
    except StageFourError as error:
        if fragment not in str(error):
            raise StageFourError(f"self-test {label!r} reached the wrong branch: {error}") from error
        return
    raise StageFourError(f"self-test {label!r} was accepted")


def self_test(root: Path) -> int:
    """Exercise primitive, worker, and dependency-profile rejection paths."""
    valid = load_toml(root / PROFILE_PATH)
    validate_profile(valid)
    malformed = copy.deepcopy(valid)
    malformed["primitive"]["opaque"]["ke2_bytes"] = 288  # type: ignore[index]
    expect_rejection("OPAQUE KE2 length", malformed, "primitive profile")
    malformed = copy.deepcopy(valid)
    malformed["worker"]["opaque_job_limit_max"] = 129  # type: ignore[index]
    expect_rejection("worker bound", malformed, "worker limits")
    malformed = copy.deepcopy(valid)
    malformed["dependency"][0]["checksum"] = "0" * 64  # type: ignore[index]
    expect_rejection("dependency checksum", malformed, "dependency records")
    malformed = copy.deepcopy(valid)
    malformed["source_patch"]["tree_sha256"] = "0" * 64  # type: ignore[index]
    expect_rejection("vendored patch digest", malformed, "source profile")
    return 4


def fail(message: str) -> NoReturn:
    """Print one stable failure and exit unsuccessfully."""
    print(f"Stage-04 conformance failed: {message}", file=sys.stderr)
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
            print("Stage-04 conformance: ok")
        else:
            cases = self_test(root)
            print(f"Stage-04 conformance self-test: ok ({cases} rejection cases)")
    except (OSError, UnicodeError, StageFourError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
