# AgenC `opaque-ke` 4.0.1 patch

This directory starts from the crates.io `opaque-ke` 4.0.1 source whose
published checksum is recorded in `conformance/stage-four-crypto-profile.toml`.

The local patch makes two secret-lifetime changes without changing protocol
bytes, algorithms, features, or the crate version:

- password-derived OPRF and KSF outputs are held in `Zeroizing` wrappers while
  `get_password_derived_key` constructs its HKDF state; and
- the server-finish session key is returned in a move-only, non-`Debug`
  `Zeroizing` field.

The deterministic Stage 4 vectors must remain byte-identical to the published
crate. `scripts/check-workspace.py` verifies the complete patched tree digest
before accepting this source override.
