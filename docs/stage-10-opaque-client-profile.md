# Public OPAQUE profile and client modules

This record covers X-08 of the SDK program (2026-10-01, outside master #35):
the exact OPAQUE profile of Architecture Section 11.2 and the client half of
the account protocol are public modules of `agenc-relay-auth`, so a client
can compute registration and login with the same suite, key-stretching
function, context and identities the coordinator verifies, without restating
them. No wire byte, stored byte, accepted input or daemon behaviour changes.

## What changed

`agenc_relay_auth::profile` owns what `opaque.rs` kept private:

- `AgencOpaqueSuite`: ristretto255-SHA512 OPRF, TripleDH over ristretto255
  with SHA-512, and the fixed key-stretching function;
- `FixedArgon2id` and the `OPAQUE_ARGON2_*` constants (Argon2id v1.3,
  65,536 KiB, three passes, four lanes, a 64-byte output, sixteen zero salt
  bytes), which refuses any other input width;
- `OPAQUE_CONTEXT_LABEL` and `opaque_context`, the label followed by the 32
  Network-ID bytes in a fixed 68-byte array;
- `opaque_identifiers`: the credential ID as the client identity and the
  Network ID as the server identity;
- `FallibleOpaqueRng`, now generic over an `EntropySource`, with the same
  latch: the first failed draw writes a nonzero sentinel and stays failed,
  and every caller discards the library's result.

`opaque.rs` consumes the module, and every server caller still draws from
`OsEntropy`. The registry test of the profile compares the constants with
the frozen `opaque_profile` descriptor.

`agenc_relay_auth::client` computes the client half over exact-size arrays:
`registration_start` and `registration_finish`, `login_start` and
`login_finish`. Every message it produces is the exact serialization the
coordinator's validators take. The client states are move-only wrappers the
library zeroizes on drop. The library returns the export and session keys
unzeroized, so each finish moves them into zeroizing arrays and wipes the
library's copies as soon as the library returns them, including from a
result that the random-number latch then discards: the library still
returns a registration whose envelope-nonce draw failed. Every call also
refuses a generator that has already latched before it does any work. A
login finish draws nothing, so the library would otherwise complete the
login and derive live keys under a failed generator. Passwords follow
Section 11.1 (UTF-8 by type, 12 through 1,024 bytes). `OpaqueClientError` keeps the library's invalid login, which
Section 11.4 answers with a dummy KE3 the caller sends, apart from a
malformed or reflected server message, failed entropy and an internal
failure. The daemon does not call the client module.

The daemon's own suites use the public profile: the test-local suites of
`crates/agenc-relay-auth/tests/stage_four.rs`,
`crates/agenc-relay-server/tests/stage_six_daemon.rs` and
`crates/agenc-relay-server/tests/stage_eight_e2ee.rs` (with its credential
replacement module) are gone. The fourth test-local suite, in the manual
generator `crates/agenc-relay-auth/tests/generate_stage_four_vectors.rs`,
stays as it was: `scripts/check-stage-four.py` pins the generator's bytes
and refuses it if it calls an `agenc-relay-auth` adapter, because the
vectors are an independent `opaque-ke-4.0.1-reference`.

## Gates

`scripts/check-stage-four.py` names both modules and their public surfaces,
and requires the new `crates/agenc-relay-auth/tests/opaque_client.rs` suite
and its markers. The constant-time review in
`conformance/stage-four-constant-time-review.toml` re-binds `opaque.rs`
after re-reading its real and fake login paths, and also binds `profile.rs`,
because the random-number adapter it reviewed inside `opaque.rs` lives
there now. Both coverage inventories are refreshed; no reviewed region names
an auth source.

## Evidence

- `public_modules_reproduce_vec_s04_007_opaque_byte_for_byte` reproduces
  every field of the immutable `VEC-S04-007-OPAQUE` vector and its output
  digest through the public profile and client calls, from the vector's own
  seeds; the server half calls the pinned library with the public suite.
- `client_calls_interoperate_with_the_coordinator_profile` registers and
  authenticates against `OpaqueProfile` and `finish_authentication`; a wrong
  password, an unknown login (the fixed fake record) and a client bound to
  another Network ID end in the invalid login.
- `reflected_or_undecodable_server_messages_are_refused` and
  `failed_entropy_and_out_of_profile_passwords_are_refused` cover the other
  refusals.
- `a_latched_generator_is_refused_before_any_work` hands each call a
  generator that has already latched, with an out-of-profile password, an
  undecodable server message or a KE2 for a real record, and every call
  reports the entropy failure. The client module's unit tests show that a
  result the latch discards had its key wiped before it dropped, and that
  taking a key wipes the library's copy even when the copy fails. Each of
  these tests fails with its part of the fix reverted: the latch checked
  before the keys are taken, any one of the four refusals removed, or the
  wipe removed.
- `cargo nextest run -p agenc-relay-auth --all-features --locked` passes 83
  tests with the generator skipped; the migrated daemon suites pass under
  `cargo nextest run -p agenc-relay-server --all-features --locked`.

## Limits

- This is an extraction, not a repair: no earlier behaviour was wrong, so no
  regression test fails at the base revision other than by not compiling.
- The server crate's `argon2` and `opaque-sha2` test dependencies are no
  longer named by its tests. They stay, because the workspace checker pins
  the binary's test dependency set and removing them changes `Cargo.lock`.
- The SDK keeps its own OPAQUE module and comparison tests until the owner
  accepts this extraction.

No Stage 04 or Stage 10 task changes state.
