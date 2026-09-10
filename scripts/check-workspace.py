#!/usr/bin/env python3
"""Validate the pinned workspace, crate graph, and dependency-source policy."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from typing import NoReturn

TOOLCHAIN = "1.98.0"
TOOLCHAIN_POLICY_SHA256 = "3f125bad8eeb2ef52f3cb49d2296e9453a76b14d6d288d75b3e3fdd2fbe13095"
EDITION = "2024"
RUST_VERSION = "1.98"
TARGETS = ["aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu"]
CRATE_NAMES = {
    "agenc-ircd",
    "agenc-ircd-admin",
    "agenc-ircd-auth",
    "agenc-ircd-client-wire",
    "agenc-ircd-config",
    "agenc-ircd-crypto",
    "agenc-ircd-domain",
    "agenc-ircd-e2ee",
    "agenc-ircd-federation-wire",
    "agenc-ircd-runtime",
    "agenc-ircd-storage",
    "agenc-ircd-testkit",
    "agenc-ircd-types",
}
EXPECTED_FEATURES = {'agenc-ircd': {'default': [],
                'wss': ['agenc-ircd-config/wss', 'agenc-ircd-runtime/wss'],
                'history': ['agenc-ircd-config/history', 'agenc-ircd-runtime/history']},
 'agenc-ircd-client-wire': {'default': [], 'wss': [], 'history': []},
 'agenc-ircd-config': {'default': [], 'wss': [], 'history': []},
 'agenc-ircd-crypto': {'default': [], 'wss': ['dep:aws-lc-rs']},
 'agenc-ircd-domain': {'default': [], 'history': []},
 'agenc-ircd-federation-wire': {'default': [], 'history': []},
 'agenc-ircd-runtime': {'default': [],
                        'wss': ['agenc-ircd-client-wire/wss',
                                'agenc-ircd-config/wss',
                                'agenc-ircd-crypto/wss'],
                        'history': ['agenc-ircd-domain/history',
                                    'agenc-ircd-federation-wire/history',
                                    'agenc-ircd-config/history',
                                    'agenc-ircd-client-wire/history']}}

EXPECTED_EDGES = {
    "agenc-ircd-types": set(),
    "agenc-ircd-client-wire": {"agenc-ircd-types"},
    "agenc-ircd-federation-wire": {"agenc-ircd-types"},
    "agenc-ircd-crypto": {"agenc-ircd-types"},
    "agenc-ircd-auth": {"agenc-ircd-types", "agenc-ircd-crypto"},
    "agenc-ircd-domain": {"agenc-ircd-types"},
    "agenc-ircd-e2ee": {
        "agenc-ircd-types",
        "agenc-ircd-crypto",
        "agenc-ircd-domain",
        "agenc-ircd-federation-wire",
    },
    "agenc-ircd-storage": {
        "agenc-ircd-types",
        "agenc-ircd-crypto",
        "agenc-ircd-domain",
        "agenc-ircd-e2ee",
    },
    "agenc-ircd-config": {"agenc-ircd-types"},
    "agenc-ircd-admin": {
        "agenc-ircd-types",
        "agenc-ircd-crypto",
        "agenc-ircd-domain",
    },
    "agenc-ircd-runtime": {
        "agenc-ircd-types",
        "agenc-ircd-client-wire",
        "agenc-ircd-federation-wire",
        "agenc-ircd-crypto",
        "agenc-ircd-auth",
        "agenc-ircd-domain",
        "agenc-ircd-e2ee",
        "agenc-ircd-storage",
        "agenc-ircd-config",
        "agenc-ircd-admin",
    },
    "agenc-ircd-testkit": {
        "agenc-ircd-client-wire",
        "agenc-ircd-crypto",
        "agenc-ircd-domain",
        "agenc-ircd-e2ee",
        "agenc-ircd-federation-wire",
        "agenc-ircd-types",
    },
    "agenc-ircd": {"agenc-ircd-runtime", "agenc-ircd-config", "agenc-ircd-storage"},
}
BINARY_TEST_WORKSPACE_DEPENDENCIES = frozenset(
    {
        "agenc-ircd-admin",
        "agenc-ircd-auth",
        "agenc-ircd-crypto",
        "agenc-ircd-testkit",
        "agenc-ircd-types",
    }
)
# Package-name prefixes of MLS client engines. Companion Section 20 and
# architecture Section 24.1 forbid any production daemon crate from depending
# on one; only the dev-only testkit may, for cross-implementation tests.
MLS_CLIENT_ENGINE_PREFIXES = ("openmls", "mls-rs", "mls_rs")
MLS_CLIENT_ALLOWED_PACKAGE = "agenc-ircd-testkit"
# The daemon binary crate; its integration tests may link MLS client engines.
BINARY_PACKAGE = "agenc-ircd"
BINARY_TEST_EXTERNAL_DEPENDENCIES = frozenset(
    {
        "argon2",
        "base64",
        "mls-rs",
        "mls-rs-crypto-rustcrypto",
        "openmls",
        "openmls_basic_credential",
        "openmls_rust_crypto",
        "opaque-ke",
        "opaque-sha2",
        "rustix",
        "rustls",
        "tokio",
    }
)
EXTERNAL_DEPENDENCIES = {
    "argon2": ("=0.5.3", {"alloc"}),
    "aws-lc-rs": ("=1.18.0", {"non-fips"}),
    "base64": ("=0.23.1", {"alloc"}),
    "chacha20poly1305": ("=0.11.0", {"alloc", "zeroize"}),
    "ed25519-dalek": ("=3.0.0", {"fast", "zeroize"}),
    "getrandom": ("=0.4.3", {"std"}),
    "hkdf": ("=0.13.0", set()),
    "hmac": ("=0.13.0", {"zeroize"}),
    "hpke": ("=0.14.0", {"alloc", "chacha", "hkdfsha2", "x25519"}),
    "opaque-ke": ("=4.0.1", {"argon2", "ristretto255", "std"}),
    "opaque-sha2": ("=0.10.9", set()),
    "precis-profiles": ("=0.1.13", set()),
    "redb": ("=4.2.0", {"std"}),
    "loom": ("=0.7.2", set()),
    "rustix": ("=1.1.4", {"fs", "mm", "process", "std"}),
    "rustls": ("=0.23.43", {"aws_lc_rs", "prefer-post-quantum", "std"}),
    "sha2": ("=0.11.0", {"zeroize"}),
    "subtle": ("=2.6.1", set()),
    "tls_codec": ("=0.5.0", {"mls", "std"}),
    "tokio": (
        "=1.53.1",
        {"io-util", "macros", "net", "rt-multi-thread", "signal", "sync", "time"},
    ),
    "toml": ("=1.1.4", {"parse", "serde", "std"}),
    "mls-rs": ("=0.56.0", {"fast_serialize", "rayon", "rfc_compliant", "std", "tree_index"}),
    "mls-rs-crypto-rustcrypto": ("=0.22.1", {"std"}),
    "openmls": ("=0.9.0", set()),
    "openmls_basic_credential": ("=0.6.0", set()),
    "openmls_rust_crypto": ("=0.6.0", set()),
    "zeroize": ("=1.9.0", {"alloc"}),
}
DIRECT_CHECKSUMS = {
    "aws-lc-rs": "ce2b2dcc879c3bae0d371e77c99f2238400ef24ec001394befa67b6e543add9e",
    "argon2": "3c3610892ee6e0cbce8ae2700349fcf8f98adb0dbfbee85aec3c9179d29cc072",
    "base64": "ac07cdecf99051d9a5238b80f35af32cdeba5b336e55d957b318b50137e18da5",
    "chacha20poly1305": "9b89e1c441e926b9c82a8d023f6e1b7ae0adcfaa7d621814e4d60789bac751cb",
    "ed25519-dalek": "6ebaa1a2bf1290ab3bfe5a7b771d050ebffab2711c19a81691c683a5144a25de",
    "getrandom": "300e883d756b2e4ec94e02791f39b04b522276138852cfc41d9fb7e904106099",
    "hkdf": "4aaa26c720c68b866f2c96ef5c1264b3e6f473fe5d4ce61cd44bbe913e553018",
    "hmac": "6303bc9732ae41b04cb554b844a762b4115a61bfaa81e3e83050991eeb56863f",
    "hpke": "dd5130e119706b4d8c2180da6126f7e60b6c38c2d340d539219f57051f0a7af7",
    "loom": "419e0dc8046cb947daa77eb95ae174acfbddb7673b4151f56d1eed8e93fbfaca",
    "mls-rs": "4392c3b3ed7d835ca8f318f85ca65d3f0d3e879538d6e70679827a2f3af72029",
    "mls-rs-crypto-rustcrypto": "eda8f08b88f84c46924dc0d1cf50c9d3ea2a6e2ac5192c38d8de465724032a2c",
    "openmls": "b6b08d90fc020cb5354d5f08ca17711b84c82e2bcc7331753fd94f000d99a8c8",
    "openmls_basic_credential": "dbd3f0c3422e7c7a8496f042b547b0c28d0793f8ba97feb401966e58196a1e40",
    "openmls_rust_crypto": "36bf3fe824ead6e81d22f49a9cd7feffca3494979fac14c1248e19516e3625f1",
    "opaque-ke": "ded22991b43cd15561b62b2e1cf9ace1344a8534eebec96202d5c96a77a6616a",
    "opaque-sha2": "a7507d819769d01a365ab707794a4084392c824f54a7a6a7862f8c3d0892b283",
    "precis-profiles": "31e2768890a47af73a032af9f0cedbddce3c9d06cf8de201d5b8f2436ded7674",
    "redb": "de6c3b63e007e90ce536ec2ae4690826136a20ec8dbbbb400daef1bb999d2e36",
    "rustix": "b6fe4565b9518b83ef4f91bb47ce29620ca828bd32cb7e408f0062e9930ba190",
    "rustls": "0283386ce02abc0151e1761d08802dfe86c173b0b494af5cbc086574e453da06",
    "sha2": "446ba717509524cb3f22f17ecc096f10f4822d76ab5c0b9822c5f9c284e825f4",
    "subtle": "13c2bddecc57b384dee18652358fb23172facb8a2c51ccc10d74c157bdea3292",
    "tls_codec": "18cc98286004cea38f717e2b03d990fc774fbfd38a82720de40e5c94365067c8",
    "tokio": "202caea871b69668250d242070849eb495be178ed697a3e98aebce5bc81a0bed",
    "toml": "3aace63f4bbcdfc2c965b059de67119c89c4017a70d633be6c104910f67056f5",
    "zeroize": "e13c156562582aa81c60cb29407084cdb54c4164760106ab78e6c5b0858cf64e",
}
EXTERNAL_PACKAGE_ALIASES = {"opaque-sha2": "sha2"}
# Dependencies reviewed after the initial ledger; each stage records its
# additions in its own conformance manifest.
LATER_STAGE_DEPENDENCIES = {
    "aws-lc-rs",
    "loom",
    "mls-rs",
    "mls-rs-crypto-rustcrypto",
    "openmls",
    "openmls_basic_credential",
    "openmls_rust_crypto",
    "rustix",
    "toml",
}
DEPENDENCY_TABLE_NAMES = {"dependencies", "dev-dependencies", "build-dependencies"}
EXPECTED_EXTERNAL_EDGES = {
    "agenc-ircd-types": {"base64", "precis-profiles", "subtle", "zeroize"},
    "agenc-ircd-client-wire": {"base64", "zeroize"},
    "agenc-ircd-federation-wire": {"base64", "sha2", "tls_codec", "zeroize"},
    "agenc-ircd-e2ee": {"sha2"},
    "agenc-ircd-crypto": {
        "aws-lc-rs",
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
    },
    "agenc-ircd-auth": {
        "argon2",
        "opaque-ke",
        "opaque-sha2",
        "subtle",
        "tls_codec",
        "tokio",
        "zeroize",
    },
    "agenc-ircd-storage": {"redb", "rustix", "subtle", "zeroize"},
    "agenc-ircd-config": {"base64", "rustix", "toml", "zeroize"},
    "agenc-ircd-admin": {"base64", "subtle", "zeroize"},
    "agenc-ircd-runtime": {"loom", "rustix", "rustls", "subtle", "tokio", "zeroize"},
    "agenc-ircd-testkit": {
        "ed25519-dalek",
        "mls-rs",
        "mls-rs-crypto-rustcrypto",
        "openmls",
        "openmls_basic_credential",
        "openmls_rust_crypto",
        "sha2",
        "subtle",
    },
}
CRATES_IO_SOURCES = {
    "registry+https://github.com/rust-lang/crates.io-index",
    "sparse+https://index.crates.io/",
}
SHA256_RE = re.compile(r"[0-9a-f]{64}")
VENDORED_PATCH_PATH = "vendor/opaque-ke-4.0.1"
VENDORED_PATCH_TREE_SHA256 = "3365ac7382b2ed771d71c933c7bd1cf772e024042ed8db0899045ea1497a9678"


class WorkspaceError(ValueError):
    """A workspace or dependency policy violation."""


def load_toml(path: Path) -> dict[str, object]:
    """Load one TOML document."""
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise WorkspaceError(f"cannot read {path}: {error}") from error


def vendored_tree_sha256(path: Path) -> str:
    """Hash every path and byte in one reviewed vendored dependency tree."""
    digest = hashlib.sha256()
    files = sorted(path.rglob("*"), key=lambda value: value.relative_to(path).as_posix())
    if not files:
        raise WorkspaceError(f"vendored dependency tree is empty: {path}")
    file_count = 0
    for candidate in files:
        if candidate.is_symlink():
            raise WorkspaceError(f"vendored dependency contains a symlink: {candidate}")
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
        raise WorkspaceError(f"vendored dependency tree has no files: {path}")
    return digest.hexdigest()


def validate_vendored_patches(
    root: Path, evidence: dict[str, object] | None = None
) -> None:
    """Validate the sole reviewed source patch and its complete tree digest."""
    if evidence is None:
        evidence = load_toml(root / "conformance/vendored-dependencies.toml")
    expected = {
        "schema_version": 1,
        "patch": [
            {
                "package": "opaque-ke",
                "version": "4.0.1",
                "path": VENDORED_PATCH_PATH,
                "upstream_registry": "https://github.com/rust-lang/crates.io-index",
                "upstream_checksum": DIRECT_CHECKSUMS["opaque-ke"],
                "tree_sha256": VENDORED_PATCH_TREE_SHA256,
                "modified_files": ["src/key_exchange/sigma_i/mod.rs", "src/opaque.rs"],
                "reason": "zeroize password-derived intermediates and the server-finish session key; gate the shared pre-hash helper on its consuming features",
            }
        ],
    }
    if evidence != expected:
        raise WorkspaceError("vendored dependency evidence differs from its reviewed closed form")
    patch_root = root / VENDORED_PATCH_PATH
    if vendored_tree_sha256(patch_root) != VENDORED_PATCH_TREE_SHA256:
        raise WorkspaceError("vendored opaque-ke tree digest differs from reviewed source")


def validate_toolchain_policy(policy_bytes: bytes) -> None:
    """Validate the complete reviewed gate-toolchain policy bytes."""
    if hashlib.sha256(policy_bytes).hexdigest() != TOOLCHAIN_POLICY_SHA256:
        raise WorkspaceError("toolchain policy differs from its reviewed closed bytes")
    try:
        policy = tomllib.loads(policy_bytes.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise WorkspaceError(f"cannot parse toolchain policy: {error}") from error
    expected_policy = {
        "schema_version": 1,
        "rust": TOOLCHAIN,
        "cargo_deny": "0.20.2",
        "cargo_audit": "0.22.2",
        "cargo_llvm_cov": "0.9.0",
        "checkout_action_commit": "df4cb1c069e1874edd31b4311f1884172cec0e10",
        "targets": TARGETS,
        "branch_coverage_instrumentation": "coverage-only RUSTC_BOOTSTRAP=1 on pinned rustc; forbidden for build, test, and release compilation",
    }
    if (
        set(policy) != set(expected_policy) | {"limitations", "tool"}
        or any(policy.get(key) != value for key, value in expected_policy.items())
    ):
        raise WorkspaceError("toolchain policy differs from the reviewed CI pin set")


def validate_toolchain(root: Path) -> None:
    """Validate the exact compiler, components, and target contract."""
    toolchain = load_toml(root / "rust-toolchain.toml").get("toolchain")
    if not isinstance(toolchain, dict):
        raise WorkspaceError("rust-toolchain.toml has no toolchain table")
    if toolchain.get("channel") != TOOLCHAIN or toolchain.get("profile") != "minimal":
        raise WorkspaceError("Rust toolchain channel/profile does not match the frozen contract")
    if toolchain.get("components") != ["clippy", "llvm-tools-preview", "rustfmt"]:
        raise WorkspaceError("Rust toolchain components do not match the frozen contract")
    if toolchain.get("targets") != TARGETS:
        raise WorkspaceError("Rust targets do not match the frozen sorted target list")
    try:
        policy_bytes = (root / "conformance/toolchain-policy.toml").read_bytes()
    except OSError as error:
        raise WorkspaceError(f"cannot read toolchain policy: {error}") from error
    validate_toolchain_policy(policy_bytes)


def validate_workspace_manifest(root: Path) -> dict[str, object]:
    """Validate root workspace metadata and frozen dependency profiles."""
    manifest = load_toml(root / "Cargo.toml")
    if "package" in manifest or "replace" in manifest:
        raise WorkspaceError("root must be virtual and may not replace sources")
    expected_patch = {"crates-io": {"opaque-ke": {"path": VENDORED_PATCH_PATH}}}
    if manifest.get("patch") != expected_patch:
        raise WorkspaceError("root source patch differs from the reviewed opaque-ke patch")
    workspace = manifest.get("workspace")
    if not isinstance(workspace, dict):
        raise WorkspaceError("root Cargo.toml has no workspace table")
    if workspace.get("resolver") != "3":
        raise WorkspaceError("workspace resolver must be 3")
    package = workspace.get("package")
    if not isinstance(package, dict):
        raise WorkspaceError("workspace.package is missing")
    expected_package = {
        "version": "0.0.0",
        "edition": EDITION,
        "rust-version": RUST_VERSION,
        "publish": False,
    }
    if package != expected_package:
        raise WorkspaceError("workspace package metadata differs from the frozen contract")

    members = workspace.get("members")
    expected_members = {f"crates/{name}" for name in CRATE_NAMES}
    if not isinstance(members, list) or set(members) != expected_members or len(members) != 13:
        raise WorkspaceError("workspace members do not name the exact 13-crate graph")

    dependencies = workspace.get("dependencies")
    if not isinstance(dependencies, dict):
        raise WorkspaceError("workspace.dependencies is missing")
    validate_dependency_profiles(dependencies)
    return manifest


def validate_dependency_profiles(dependencies: dict[str, object]) -> None:
    """Validate every root dependency declaration exactly."""
    expected_names = CRATE_NAMES - {"agenc-ircd"}
    if set(dependencies) != expected_names | set(EXTERNAL_DEPENDENCIES):
        raise WorkspaceError("workspace dependency names differ from the frozen closed set")

    for name in expected_names:
        declaration = dependencies.get(name)
        if not isinstance(declaration, dict):
            raise WorkspaceError(f"workspace dependency {name} must be a table")
        expected = {"version": "=0.0.0", "path": f"crates/{name}"}
        if declaration != expected:
            raise WorkspaceError(f"workspace dependency {name} has a forbidden declaration")

    for name, (version, features) in EXTERNAL_DEPENDENCIES.items():
        declaration = dependencies.get(name)
        if not isinstance(declaration, dict):
            raise WorkspaceError(f"external dependency {name} must be a table")
        if declaration.get("version") != version:
            raise WorkspaceError(f"external dependency {name} is not pinned to {version}")
        if declaration.get("default-features") is not False:
            raise WorkspaceError(f"external dependency {name} enables default features")
        declared_features = declaration.get("features", [])
        if not isinstance(declared_features, list) or set(declared_features) != features:
            raise WorkspaceError(f"external dependency {name} has a stale feature profile")
        package = EXTERNAL_PACKAGE_ALIASES.get(name)
        if declaration.get("package") != package:
            raise WorkspaceError(f"external dependency {name} has a stale package alias")
        expected_keys = {"version", "default-features"} | (
            {"features"} if features else set()
        ) | ({"package"} if package is not None else set())
        if set(declaration) != expected_keys:
            raise WorkspaceError(f"external dependency {name} has forbidden source/profile keys")


def is_mls_client_engine(name: object) -> bool:
    """Return whether a dependency name denotes an MLS client engine."""
    return isinstance(name, str) and name.startswith(MLS_CLIENT_ENGINE_PREFIXES)


def mls_client_edge_allowed(package_name: object, dev_only: bool) -> bool:
    """Whether an MLS client engine edge is a test-only edge: the testkit
    holds them, and the daemon binary crate may name them only from its
    integration tests (companion Section 21 gate 3)."""
    return package_name == MLS_CLIENT_ALLOWED_PACKAGE or (
        package_name == BINARY_PACKAGE and dev_only
    )


def validate_mls_client_separation(packages: dict[str, dict[str, object]]) -> int:
    """Reject any MLS client engine edge outside the test-only surfaces."""
    engine_edges = 0
    for name, package in packages.items():
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list):
            raise WorkspaceError(f"package {name} has invalid dependency metadata")
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                continue
            dependency_name = dependency.get("name")
            if not is_mls_client_engine(dependency_name):
                continue
            if not mls_client_edge_allowed(name, dependency.get("kind") == "dev"):
                raise WorkspaceError(
                    f"MLS client engine {dependency_name} reaches production crate {name}"
                )
            engine_edges += 1
    return engine_edges


def dependency_tables(document: dict[str, object]) -> list[tuple[str, dict[str, object]]]:
    """Return dependency tables, including target-conditional tables."""
    tables: list[tuple[str, dict[str, object]]] = []
    for name in DEPENDENCY_TABLE_NAMES:
        table = document.get(name)
        if isinstance(table, dict):
            tables.append((name, table))
    targets = document.get("target")
    if isinstance(targets, dict):
        for target_name, target in targets.items():
            if not isinstance(target, dict):
                continue
            for name in DEPENDENCY_TABLE_NAMES:
                table = target.get(name)
                if isinstance(table, dict):
                    tables.append((f"target.{target_name}.{name}", table))
    return tables


def validate_package_manifest(manifest_path: Path, manifest: dict[str, object]) -> None:
    """Validate one package manifest against its production and test-only roles."""
    if "patch" in manifest or "replace" in manifest:
        raise WorkspaceError(f"source override is forbidden in {manifest_path}")
    package = manifest.get("package")
    if not isinstance(package, dict) or package.get("name") not in CRATE_NAMES:
        raise WorkspaceError(f"invalid package metadata in {manifest_path}")
    for field in ("version", "edition", "rust-version", "publish"):
        if package.get(field) != {"workspace": True}:
            raise WorkspaceError(f"{manifest_path} does not inherit package.{field}")
    if manifest.get("lints") != {"workspace": True}:
        raise WorkspaceError(f"{manifest_path} does not inherit workspace lints")
    package_name = str(package["name"])
    if manifest.get("features", {}) != EXPECTED_FEATURES.get(package_name, {}):
        raise WorkspaceError(f"package {package_name} exposes an unexpected production feature")
    actual_external: set[str] = set()
    for table_name, table in dependency_tables(manifest):
        for dependency_name, declaration in table.items():
            expected_declaration = {"workspace": True}
            if (package_name, table_name, dependency_name) == (
                "agenc-ircd-crypto", "dependencies", "aws-lc-rs"
            ):
                expected_declaration["optional"] = True
            if (package_name, table_name, dependency_name) == (
                "agenc-ircd-runtime", "dev-dependencies", "tokio"
            ):
                # Paused clocks make connection deadline tests deterministic.
                expected_declaration["features"] = ["test-util"]
            if (package_name, table_name, dependency_name) == (
                "agenc-ircd-runtime", "dependencies", "rustix"
            ):
                # Durable snapshot deadlines use the pinned Linux monotonic
                # clock with a separately verified boot/time-namespace identity.
                expected_declaration["features"] = ["time"]
            if declaration != expected_declaration:
                raise WorkspaceError(
                    f"{manifest_path} {table_name}.{dependency_name} must inherit the root pin"
                )
            if is_mls_client_engine(dependency_name) and not mls_client_edge_allowed(
                package_name, table_name == "dev-dependencies"
            ):
                raise WorkspaceError(
                    f"MLS client engine {dependency_name} reaches production crate {package_name}"
                )
            if dependency_name in EXTERNAL_DEPENDENCIES:
                if not table_name.endswith("dependencies"):
                    raise WorkspaceError(
                        f"{manifest_path} places {dependency_name} in an invalid dependency table"
                    )
                if (
                    package_name == "agenc-ircd"
                    and dependency_name in BINARY_TEST_EXTERNAL_DEPENDENCIES
                    and table_name != "dev-dependencies"
                ):
                    raise WorkspaceError(
                        f"{manifest_path} must keep {dependency_name} test-only"
                    )
                actual_external.add(dependency_name)
                continue
            if dependency_name not in CRATE_NAMES:
                raise WorkspaceError(
                    f"{manifest_path} names unknown dependency {dependency_name}"
                )
            if dependency_name == "agenc-ircd-testkit" and table_name == "dependencies":
                raise WorkspaceError(
                    f"{manifest_path} has a production dependency on testkit"
                )
            if package_name == "agenc-ircd" and dependency_name in (
                BINARY_TEST_WORKSPACE_DEPENDENCIES
            ):
                if table_name != "dev-dependencies":
                    raise WorkspaceError(
                        f"{manifest_path} must keep {dependency_name} test-only"
                    )
                continue
            if table_name == "dependencies":
                continue
            if table_name == "dev-dependencies" and dependency_name == "agenc-ircd-testkit":
                continue
            raise WorkspaceError(
                f"{manifest_path} has forbidden {table_name}.{dependency_name} edge"
            )
    expected_external = set(EXPECTED_EXTERNAL_EDGES.get(package_name, set()))
    if package_name == "agenc-ircd":
        expected_external.update(BINARY_TEST_EXTERNAL_DEPENDENCIES)
    if actual_external != expected_external:
        raise WorkspaceError(
            f"{manifest_path} external dependency set differs: "
            f"expected={sorted(expected_external)}, actual={sorted(actual_external)}"
        )


def validate_package_manifests(root: Path) -> None:
    """Validate inherited package dependencies and their ownership roles."""
    for manifest_path in sorted((root / "crates").glob("*/Cargo.toml")):
        validate_package_manifest(manifest_path, load_toml(manifest_path))


def validate_direct_dependency_evidence(root: Path) -> None:
    """Compare root pins with the initial ledger and reviewed stage additions."""
    source_path = root / "docs/protocol-sources-and-decisions.md"
    try:
        source = source_path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as error:
        raise WorkspaceError(f"cannot read dependency source ledger: {error}") from error
    start = source.find("## 5. Initial Rust dependency evidence")
    end = source.find("## 6. Update and review procedure", start)
    if start == -1 or end == -1:
        raise WorkspaceError("dependency source ledger section boundaries are missing")
    records = {
        name: (version, checksum)
        for name, version, checksum in re.findall(
            r"^\| `([^`]+)` \| ([0-9.]+) \| `([0-9a-f]{64})` \|",
            source[start:end],
            flags=re.MULTILINE,
        )
    }
    expected_records = {
        name: (version.removeprefix("="), DIRECT_CHECKSUMS[name])
        for name, (version, _features) in EXTERNAL_DEPENDENCIES.items()
        if name not in LATER_STAGE_DEPENDENCIES
    }
    if records != expected_records:
        raise WorkspaceError("root dependency pins and frozen crates.io checksum evidence disagree")
    stage_five = load_toml(root / "conformance/stage-five-dependencies.toml")
    expected_stage_five = {
        "schema_version": 1,
        "dependency": [
            {
                "name": "rustix",
                "version": "1.1.4",
                "checksum": DIRECT_CHECKSUMS["rustix"],
                "default_features": False,
                "features": ["fs", "std"],
                "purpose": "safe Linux directory-relative filesystem, metadata, capacity, rename, sync, and lock operations",
                "reviewed_on": "2026-08-27",
            },
            {
                "name": "toml",
                "version": "1.1.4",
                "checksum": DIRECT_CHECKSUMS["toml"],
                "default_features": False,
                "features": ["parse", "serde", "std"],
                "purpose": "strict parsing of stopped-daemon maintenance configuration and backup trust manifests",
                "reviewed_on": "2026-08-29",
            },
        ],
    }
    if stage_five != expected_stage_five:
        raise WorkspaceError("Stage 05 dependency evidence differs from its reviewed closed form")
    stage_six = load_toml(root / "conformance/stage-six-dependencies.toml")
    expected_stage_six = {
        "schema_version": 1,
        "dependency": [
            {
                "name": "loom",
                "version": "0.7.2",
                "checksum": DIRECT_CHECKSUMS["loom"],
                "default_features": False,
                "features": [],
                "scope": "dev",
                "purpose": "exhaustive schedule exploration of the Stage 06 runtime ownership, receipt, permit, and shutdown models under dev-only compilation",
                "reviewed_on": "2026-08-29",
            },
            {
                "name": "rustix",
                "version": "1.1.4",
                "checksum": DIRECT_CHECKSUMS["rustix"],
                "default_features": False,
                "features": ["fs", "mm", "process", "std"],
                "scope": "production",
                "purpose": "Stage 06 adds process identity, core-dump control, and secret memory locking to the reviewed filesystem profile",
                "reviewed_on": "2026-08-29",
            },
            {
                "name": "rustls",
                "version": "0.23.43",
                "checksum": DIRECT_CHECKSUMS["rustls"],
                "default_features": False,
                "features": ["aws_lc_rs", "prefer-post-quantum", "std"],
                "scope": "production",
                "purpose": "TLS 1.3 only client, onion, and administrative listeners on the explicit aws-lc provider with the hybrid key-exchange order",
                "reviewed_on": "2026-08-29",
            },
            {
                "name": "tokio",
                "version": "1.53.1",
                "checksum": DIRECT_CHECKSUMS["tokio"],
                "default_features": False,
                "features": ["io-util", "macros", "net", "rt-multi-thread", "signal", "sync", "time"],
                "scope": "production",
                "purpose": "the owned Stage 06 task tree, bounded channels, listeners, timers, and signal handling",
                "reviewed_on": "2026-08-29",
            },
        ],
    }
    if stage_six != expected_stage_six:
        raise WorkspaceError("Stage 06 dependency evidence differs from its reviewed closed form")
    stage_eight = load_toml(root / "conformance/stage-eight-dependencies.toml")
    expected_stage_eight = {
        "schema_version": 1,
        "dependency": [
            {
                "name": "mls-rs",
                "version": "0.56.0",
                "checksum": DIRECT_CHECKSUMS["mls-rs"],
                "default_features": False,
                "features": ['fast_serialize', 'rayon', 'rfc_compliant', 'std', 'tree_index'],
                "scope": "dev",
                "purpose": "second independent MLS client for the Stage 08 cross-implementation gate; test-only in the testkit and the daemon's integration tests, never a production dependency",
                "reviewed_on": "2026-09-04",
            },
            {
                "name": "mls-rs-crypto-rustcrypto",
                "version": "0.22.1",
                "checksum": DIRECT_CHECKSUMS["mls-rs-crypto-rustcrypto"],
                "default_features": False,
                "features": ['std'],
                "scope": "dev",
                "purpose": "RustCrypto cipher suite provider for the mls-rs test client",
                "reviewed_on": "2026-09-04",
            },
            {
                "name": "openmls",
                "version": "0.9.0",
                "checksum": DIRECT_CHECKSUMS["openmls"],
                "default_features": False,
                "features": [],
                "scope": "dev",
                "purpose": "first independent MLS client for the Stage 08 cross-implementation gate; test-only in the testkit and the daemon's integration tests, never a production dependency",
                "reviewed_on": "2026-09-04",
            },
            {
                "name": "openmls_basic_credential",
                "version": "0.6.0",
                "checksum": DIRECT_CHECKSUMS["openmls_basic_credential"],
                "default_features": False,
                "features": [],
                "scope": "dev",
                "purpose": "basic credential and Ed25519 signature keys for the openmls test client",
                "reviewed_on": "2026-09-04",
            },
            {
                "name": "openmls_rust_crypto",
                "version": "0.6.0",
                "checksum": DIRECT_CHECKSUMS["openmls_rust_crypto"],
                "default_features": False,
                "features": [],
                "scope": "dev",
                "purpose": "RustCrypto provider for the openmls test client",
                "reviewed_on": "2026-09-04",
            },
        ],
    }
    if stage_eight != expected_stage_eight:
        raise WorkspaceError("Stage 08 dependency evidence differs from its reviewed closed form")
    stage_nine = load_toml(root / "conformance/stage-nine-dependencies.toml")
    expected_stage_nine = {
        "schema_version": 1,
        "dependency": [{
            "name": "aws-lc-rs",
            "version": "1.18.0",
            "checksum": DIRECT_CHECKSUMS["aws-lc-rs"],
            "default_features": False,
            "features": ["non-fips"],
            "scope": "optional-wss",
            "purpose": "RFC 6455 accept digest over the public handshake nonce through the private crypto adapter; reuses the locked TLS provider",
            "reviewed_on": "2026-09-04",
        }],
    }
    if stage_nine != expected_stage_nine:
        raise WorkspaceError("Stage 09 dependency evidence differs from its reviewed closed form")


def cargo_metadata(root: Path) -> dict[str, object]:
    """Load Cargo's authoritative package graph without third-party dependencies."""
    completed = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1", "--locked"],
        cwd=root,
        capture_output=True,
        check=False,
        text=True,
    )
    if completed.returncode != 0:
        details = (completed.stderr or completed.stdout).strip()
        raise WorkspaceError(f"cargo metadata failed: {details}")
    try:
        metadata = json.loads(completed.stdout)
    except json.JSONDecodeError as error:
        raise WorkspaceError(f"cargo metadata returned invalid JSON: {error}") from error
    if not isinstance(metadata, dict):
        raise WorkspaceError("cargo metadata did not return an object")
    return metadata


def packages_from_metadata(metadata: dict[str, object]) -> dict[str, dict[str, object]]:
    """Index Cargo package objects by unique workspace name."""
    packages = metadata.get("packages")
    workspace_members = metadata.get("workspace_members")
    if not isinstance(packages, list) or not isinstance(workspace_members, list):
        raise WorkspaceError("cargo metadata is missing packages or workspace_members")
    member_ids = set(workspace_members)
    indexed: dict[str, dict[str, object]] = {}
    for package in packages:
        if not isinstance(package, dict) or package.get("id") not in member_ids:
            continue
        name = package.get("name")
        if not isinstance(name, str) or name in indexed:
            raise WorkspaceError(f"invalid or duplicate workspace package name: {name!r}")
        indexed[name] = package
    return indexed


def graph_from_packages(packages: dict[str, dict[str, object]]) -> dict[str, set[str]]:
    """Build the workspace-only normal dependency graph."""
    graph: dict[str, set[str]] = {}
    for name, package in packages.items():
        dependencies = package.get("dependencies")
        if not isinstance(dependencies, list):
            raise WorkspaceError(f"package {name} has invalid dependency metadata")
        edges: set[str] = set()
        for dependency in dependencies:
            if not isinstance(dependency, dict):
                raise WorkspaceError(f"package {name} has a malformed dependency")
            dependency_name = dependency.get("name")
            if dependency_name not in CRATE_NAMES:
                continue
            kind = dependency.get("kind")
            if kind == "dev":
                allowed = dependency_name == "agenc-ircd-testkit" or (
                    name == "agenc-ircd"
                    and dependency_name in BINARY_TEST_WORKSPACE_DEPENDENCIES
                    | {"agenc-ircd-storage"}
                )
                if not allowed:
                    raise WorkspaceError(
                        f"workspace dev edge {name} -> {dependency_name} is not reviewed"
                    )
                continue
            if kind not in {None, "normal"} or dependency.get("target") is not None:
                raise WorkspaceError(
                    f"workspace edge {name} -> {dependency_name} is not unconditional normal"
                )
            edges.add(str(dependency_name))
        graph[name] = edges
    return graph


def validate_graph(packages: dict[str, dict[str, object]]) -> dict[str, set[str]]:
    """Validate package metadata and the exact Section-24 edge set."""
    if set(packages) != CRATE_NAMES:
        missing = sorted(CRATE_NAMES - set(packages))
        extra = sorted(set(packages) - CRATE_NAMES)
        raise WorkspaceError(f"workspace package set differs; missing={missing}, extra={extra}")
    for name, package in packages.items():
        if package.get("edition") != EDITION or package.get("rust_version") != RUST_VERSION:
            raise WorkspaceError(f"package {name} has stale edition or rust-version metadata")
        if package.get("version") != "0.0.0":
            raise WorkspaceError(f"package {name} version differs from required 0.0.0")
        features = package.get("features")
        if features != EXPECTED_FEATURES.get(name, {}):
            raise WorkspaceError(f"package {name} exposes an unexpected production feature")

        targets = package.get("targets")
        if not isinstance(targets, list):
            raise WorkspaceError(f"package {name} has invalid target metadata")
        product_kinds: list[str] = []
        for target in targets:
            if not isinstance(target, dict):
                continue
            kinds = target.get("kind")
            if not isinstance(kinds, list):
                continue
            for kind in kinds:
                if kind in {"lib", "bin"}:
                    product_kinds.append(kind)
        expected_kind = ["bin"] if name == "agenc-ircd" else ["lib"]
        if product_kinds != expected_kind:
            raise WorkspaceError(f"package {name} product target must be exactly {expected_kind}")

    graph = graph_from_packages(packages)
    if graph != EXPECTED_EDGES:
        differences = {
            name: {
                "expected": sorted(EXPECTED_EDGES.get(name, set())),
                "actual": sorted(graph.get(name, set())),
            }
            for name in sorted(CRATE_NAMES)
            if graph.get(name) != EXPECTED_EDGES.get(name)
        }
        raise WorkspaceError(f"workspace dependency graph differs: {differences}")
    validate_acyclic(graph)
    validate_release_closure(graph)
    return graph


def validate_acyclic(graph: dict[str, set[str]]) -> None:
    """Reject every workspace dependency cycle."""
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visiting:
            raise WorkspaceError(f"workspace dependency cycle reaches {name}")
        if name in visited:
            return
        visiting.add(name)
        for dependency in graph.get(name, set()):
            visit(dependency)
        visiting.remove(name)
        visited.add(name)

    for name in graph:
        visit(name)


def validate_release_closure(graph: dict[str, set[str]]) -> None:
    """Prove testkit is absent and every production library is composed."""
    closure: set[str] = set()
    pending = ["agenc-ircd"]
    while pending:
        name = pending.pop()
        if name in closure:
            continue
        closure.add(name)
        pending.extend(graph.get(name, set()))
    if "agenc-ircd-testkit" in closure:
        raise WorkspaceError("agenc-ircd-testkit entered the release dependency closure")
    expected_closure = CRATE_NAMES - {"agenc-ircd-testkit"}
    if closure != expected_closure:
        raise WorkspaceError("release binary does not compose every production library")
    for owner, dependencies in graph.items():
        if owner != "agenc-ircd-testkit" and "agenc-ircd-testkit" in dependencies:
            raise WorkspaceError(f"production package {owner} depends on testkit")
        if "agenc-ircd" in dependencies:
            raise WorkspaceError(f"library package {owner} depends on the binary")


def validate_lockfile(root: Path) -> int:
    """Validate lockfile source/checksum integrity and return package count."""
    lock_path = root / "Cargo.lock"
    if not lock_path.is_file():
        raise WorkspaceError("Cargo.lock is required")
    lock = load_toml(lock_path)
    if lock.get("version") != 4:
        raise WorkspaceError("Cargo.lock must use lockfile format version 4")
    packages = lock.get("package")
    if not isinstance(packages, list):
        raise WorkspaceError("Cargo.lock has no package array")
    for package in packages:
        if not isinstance(package, dict):
            raise WorkspaceError("Cargo.lock contains a malformed package")
        source = package.get("source")
        checksum = package.get("checksum")
        if source is None:
            if checksum is not None:
                raise WorkspaceError("workspace/path lock package unexpectedly has a checksum")
            continue
        if source not in CRATES_IO_SOURCES:
            raise WorkspaceError(f"Cargo.lock contains forbidden source {source!r}")
        if not isinstance(checksum, str) or SHA256_RE.fullmatch(checksum) is None:
            raise WorkspaceError("registry lock package has no valid checksum")
        package_name = package.get("name")
        version = package.get("version")
        for logical_name, direct in EXTERNAL_DEPENDENCIES.items():
            expected_package = EXTERNAL_PACKAGE_ALIASES.get(logical_name, logical_name)
            if package_name != expected_package or version != direct[0].removeprefix("="):
                continue
            if checksum != DIRECT_CHECKSUMS[logical_name]:
                raise WorkspaceError(
                    f"direct dependency {logical_name} checksum differs from frozen evidence"
                )
    return len(packages)


def validate_dependency_exception(root: Path) -> None:
    """Validate the one closed duplicate-crypto generation exception."""
    policy = load_toml(root / "conformance/dependency-policy.toml")
    if set(policy) != {
        "schema_version",
        "default_registry",
        "lockfile_required",
        "offline_after_fetch",
        "reviewed_duplicate_crypto_generation",
    }:
        raise WorkspaceError("dependency policy has unknown or missing top-level fields")
    if (
        policy.get("schema_version") != 1
        or policy.get("default_registry") != "https://github.com/rust-lang/crates.io-index"
        or policy.get("lockfile_required") is not True
        or policy.get("offline_after_fetch") is not True
    ):
        raise WorkspaceError("dependency policy baseline fields are invalid")
    exceptions = policy.get("reviewed_duplicate_crypto_generation")
    if not isinstance(exceptions, list) or len(exceptions) != 1:
        raise WorkspaceError("exactly one duplicate-crypto exception must be documented")
    expected = {
        "id": "DEP-EXCEPTION-OPAQUE-0001",
        "root_package": "opaque-ke",
        "root_version": "=4.0.1",
        "status": "approved-when-reachable",
        "allowed_duplicate_packages": ["curve25519-dalek", "digest", "hmac", "sha2"],
        "reason": "RFC 9807 OPAQUE retains its audited digest, HMAC, and curve dependency generation while direct adapters use the frozen current RustCrypto generation.",
        "constraints": "The exception is reachable only below opaque-ke 4.0.1; its types never cross into direct primitive adapters; byte-identical vectors cover both graphs; no second exception is implicit.",
    }
    if exceptions[0] != expected:
        raise WorkspaceError("duplicate-crypto exception differs from its reviewed closed form")


def validate(root: Path) -> tuple[int, int]:
    """Run the complete workspace and dependency-source check."""
    validate_toolchain(root)
    validate_workspace_manifest(root)
    validate_vendored_patches(root)
    validate_package_manifests(root)
    validate_direct_dependency_evidence(root)
    metadata = cargo_metadata(root)
    packages = packages_from_metadata(metadata)
    validate_graph(packages)
    validate_mls_client_separation(packages)
    lock_packages = validate_lockfile(root)
    validate_dependency_exception(root)
    return len(packages), lock_packages


def expect_rejection(label: str, action: object, fragment: str) -> None:
    """Require one seeded policy violation to reach its intended branch."""
    if not callable(action):
        raise WorkspaceError(f"self-test {label!r} is not callable")
    try:
        action()
    except WorkspaceError as error:
        if fragment not in str(error):
            raise WorkspaceError(f"self-test {label!r} reached the wrong branch: {error}") from error
        return
    raise WorkspaceError(f"self-test {label!r} was accepted")


def self_test(root: Path) -> int:
    """Exercise graph, metadata, source, feature, and pin rejection paths."""
    validate_toolchain(root)
    manifest = validate_workspace_manifest(root)
    evidence = load_toml(root / "conformance/vendored-dependencies.toml")
    validate_vendored_patches(root, evidence)
    validate_package_manifests(root)
    validate_direct_dependency_evidence(root)
    packages = packages_from_metadata(cargo_metadata(root))
    validate_graph(packages)
    validate_mls_client_separation(packages)
    validate_lockfile(root)
    validate_dependency_exception(root)
    cases = 0

    e2ee_manifest_path = root / "crates/agenc-ircd-e2ee/Cargo.toml"
    engine_manifest = copy.deepcopy(load_toml(e2ee_manifest_path))
    engine_manifest["dependencies"]["openmls"] = {"workspace": True}  # type: ignore[index]
    expect_rejection(
        "MLS client engine in a production manifest",
        lambda: validate_package_manifest(e2ee_manifest_path, engine_manifest),
        "MLS client engine openmls reaches production crate agenc-ircd-e2ee",
    )
    cases += 1

    engine_metadata = copy.deepcopy(packages)
    engine_metadata["agenc-ircd-runtime"]["dependencies"].append(  # type: ignore[index]
        {"name": "mls-rs", "kind": None}
    )
    expect_rejection(
        "MLS client engine in production metadata",
        lambda: validate_mls_client_separation(engine_metadata),
        "MLS client engine mls-rs reaches production crate agenc-ircd-runtime",
    )
    cases += 1

    baseline_edges = validate_mls_client_separation(packages)
    testkit_metadata = copy.deepcopy(packages)
    testkit_metadata["agenc-ircd-testkit"]["dependencies"].append(  # type: ignore[index]
        {"name": "openmls", "kind": None}
    )
    if validate_mls_client_separation(testkit_metadata) != baseline_edges + 1:
        raise WorkspaceError("self-test: testkit MLS client edge was not counted")
    cases += 1

    binary_manifest_path = root / "crates/agenc-ircd/Cargo.toml"
    binary_manifest = load_toml(binary_manifest_path)
    extra_internal_dev = copy.deepcopy(binary_manifest)
    extra_internal_dev["dev-dependencies"]["agenc-ircd-domain"] = {  # type: ignore[index]
        "workspace": True
    }
    expect_rejection(
        "unreviewed binary workspace dev dependency",
        lambda: validate_package_manifest(binary_manifest_path, extra_internal_dev),
        "forbidden dev-dependencies.agenc-ircd-domain edge",
    )
    cases += 1

    extra_external_dev = copy.deepcopy(binary_manifest)
    extra_external_dev["dev-dependencies"]["sha2"] = {  # type: ignore[index]
        "workspace": True
    }
    expect_rejection(
        "unreviewed binary external dev dependency",
        lambda: validate_package_manifest(binary_manifest_path, extra_external_dev),
        "external dependency set differs",
    )
    cases += 1

    runtime_manifest_path = root / "crates/agenc-ircd-runtime/Cargo.toml"
    runtime_manifest = load_toml(runtime_manifest_path)
    production_clock = copy.deepcopy(runtime_manifest)
    production_clock["dependencies"]["tokio"] = {  # type: ignore[index]
        "workspace": True, "features": ["test-util"]
    }
    expect_rejection(
        "test clock in production dependency",
        lambda: validate_package_manifest(runtime_manifest_path, production_clock),
        "dependencies.tokio must inherit the root pin",
    )
    cases += 1
    extra_clock_feature = copy.deepcopy(runtime_manifest)
    extra_clock_feature["dev-dependencies"]["tokio"] = {  # type: ignore[index]
        "workspace": True, "features": ["test-util", "tracing"]
    }
    expect_rejection(
        "unreviewed test clock feature",
        lambda: validate_package_manifest(runtime_manifest_path, extra_clock_feature),
        "dev-dependencies.tokio must inherit the root pin",
    )
    cases += 1

    for features in ([], ["time", "thread"]):
        wrong_recovery_clock = copy.deepcopy(runtime_manifest)
        wrong_recovery_clock["dependencies"]["rustix"] = {  # type: ignore[index]
            "workspace": True, "features": features
        }
        expect_rejection(
            "unreviewed recovery clock feature set",
            lambda: validate_package_manifest(runtime_manifest_path, wrong_recovery_clock),
            "dependencies.rustix must inherit the root pin",
        )
        cases += 1
    config_manifest_path = root / "crates/agenc-ircd-config/Cargo.toml"
    unrelated_clock = copy.deepcopy(load_toml(config_manifest_path))
    unrelated_clock["dependencies"]["rustix"] = {  # type: ignore[index]
        "workspace": True, "features": ["time"]
    }
    expect_rejection(
        "runtime recovery clock feature on another crate",
        lambda: validate_package_manifest(config_manifest_path, unrelated_clock),
        "dependencies.rustix must inherit the root pin",
    )
    cases += 1

    policy_bytes = (root / "conformance/toolchain-policy.toml").read_bytes()
    changed_policy = policy_bytes.replace(b"cargo-deny 0.20.2", b"cargo-deny 0.20.3", 1)
    if changed_policy == policy_bytes:
        raise WorkspaceError("self-test cannot mutate the reviewed toolchain policy")
    expect_rejection(
        "toolchain policy bytes",
        lambda: validate_toolchain_policy(changed_policy),
        "reviewed closed bytes",
    )
    cases += 1

    forbidden = copy.deepcopy(packages)
    forbidden["agenc-ircd-types"]["dependencies"].append(
        copy.deepcopy(forbidden["agenc-ircd-client-wire"]["dependencies"][0])
    )
    expect_rejection("forbidden edge", lambda: validate_graph(forbidden), "graph differs")
    cases += 1

    cycle_graph = copy.deepcopy(EXPECTED_EDGES)
    cycle_graph["agenc-ircd-types"] = {"agenc-ircd-runtime"}
    expect_rejection("cycle", lambda: validate_acyclic(cycle_graph), "cycle")
    cases += 1

    testkit_graph = copy.deepcopy(EXPECTED_EDGES)
    testkit_graph["agenc-ircd-runtime"] = set(testkit_graph["agenc-ircd-runtime"])
    testkit_graph["agenc-ircd-runtime"].add("agenc-ircd-testkit")
    expect_rejection(
        "testkit release edge", lambda: validate_release_closure(testkit_graph), "testkit"
    )
    cases += 1

    missing = copy.deepcopy(packages)
    missing.pop("agenc-ircd-types")
    expect_rejection("missing crate", lambda: validate_graph(missing), "package set differs")
    cases += 1

    stale_metadata = copy.deepcopy(packages)
    stale_metadata["agenc-ircd-types"]["rust_version"] = "1.97"
    expect_rejection("MSRV", lambda: validate_graph(stale_metadata), "stale edition")
    cases += 1

    feature = copy.deepcopy(packages)
    feature["agenc-ircd-runtime"]["features"] = {"deterministic-entropy": []}
    expect_rejection("production feature", lambda: validate_graph(feature), "unexpected production feature")
    cases += 1

    for feature_name in ("wss", "history"):
        enabled = copy.deepcopy(packages)
        enabled["agenc-ircd"]["features"]["default"] = [feature_name]
        expect_rejection("default optional profile", lambda: validate_graph(enabled),
                         "unexpected production feature")
        cases += 1
    coupled = copy.deepcopy(packages)
    coupled["agenc-ircd"]["features"]["wss"].append("history")
    expect_rejection("coupled profiles", lambda: validate_graph(coupled),
                     "unexpected production feature")
    cases += 1
    crypto_path = root / "crates/agenc-ircd-crypto/Cargo.toml"
    unconditional = copy.deepcopy(load_toml(crypto_path))
    unconditional["dependencies"]["aws-lc-rs"].pop("optional")
    expect_rejection("unconditional handshake provider",
                     lambda: validate_package_manifest(crypto_path, unconditional),
                     "must inherit the root pin")
    cases += 1

    workspace = manifest["workspace"]
    dependencies = copy.deepcopy(workspace["dependencies"])
    dependencies["tokio"]["version"] = "*"
    expect_rejection("wildcard", lambda: validate_dependency_profiles(dependencies), "not pinned")
    cases += 1

    git_dependency = copy.deepcopy(workspace["dependencies"])
    git_dependency["tokio"]["git"] = "https://example.invalid/tokio"
    expect_rejection(
        "Git dependency", lambda: validate_dependency_profiles(git_dependency), "forbidden source"
    )
    cases += 1

    default_features = copy.deepcopy(workspace["dependencies"])
    default_features["rustls"]["default-features"] = True
    expect_rejection(
        "default features",
        lambda: validate_dependency_profiles(default_features),
        "enables default features",
    )
    cases += 1

    package_alias = copy.deepcopy(workspace["dependencies"])
    package_alias["opaque-sha2"]["package"] = "sha3"
    expect_rejection(
        "package alias",
        lambda: validate_dependency_profiles(package_alias),
        "stale package alias",
    )
    cases += 1

    stale_patch = copy.deepcopy(evidence)
    stale_patch["patch"][0]["tree_sha256"] = "0" * 64
    expect_rejection(
        "vendored patch digest",
        lambda: validate_vendored_patches(root, stale_patch),
        "reviewed closed form",
    )
    cases += 1

    return cases


def fail(message: str) -> NoReturn:
    """Print a stable command-line error and exit unsuccessfully."""
    print(f"workspace validation failed: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    """Dispatch the workspace check and seeded negative tests."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("check", "self-test"))
    arguments = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    try:
        if arguments.command == "check":
            workspace_packages, lock_packages = validate(root)
            print(
                f"workspace policy: ok ({workspace_packages} workspace packages, "
                f"{lock_packages} locked packages)"
            )
        else:
            cases = self_test(root)
            print(f"workspace policy self-test: ok ({cases} rejection cases)")
    except (WorkspaceError, OSError, UnicodeError) as error:
        fail(str(error))


if __name__ == "__main__":
    main()
