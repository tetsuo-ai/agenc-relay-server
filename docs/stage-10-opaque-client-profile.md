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
Section 11.1 (UTF-8 by type, 12 through 1,024 bytes). `OpaqueClientError`
keeps the library's invalid login, which Section 11.4 answers with a dummy
KE3 the caller sends, apart from a malformed or reflected server message,
failed entropy and an internal failure. The daemon does not call the client
module.

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
  every field of the immutable `VEC-S04-007-OPAQUE` vector through the
  public profile and client calls: every byte field and the output digest,
  drawn from the seeds `rng_seeds` lists, `lengths_decimal` against the
  public length constants, and both rejection outcomes, including the dummy
  state's refusal of the real KE3 (`dummy_finish_rejected`). The server half
  calls the pinned library with the public suite. The export keys, which
  the vector does not record, equal the pinned library's own for the same
  seeds and agree between registration and login.
- `client_calls_interoperate_with_the_coordinator_profile` registers and
  authenticates against `OpaqueProfile` and `finish_authentication`; the
  login's export key equals the registration's and differs from the session
  key. A wrong password, an unknown login (the fixed fake record) and a
  client bound to another Network ID end in the invalid login.
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
- `the_adapter_stays_latched_after_its_source_recovers` shows that once a
  draw has failed, the adapter keeps writing the sentinel and reporting the
  failure after its source works again, and that a call cannot proceed on
  it.
- The export-key and latch checks have mutation evidence: with the login's
  export key replaced by its session key, or one bit flipped in either
  export key, the vector and interoperation tests fail; with the latch
  removed from the adapter, the latch test fails. Each of these mutants
  passed the suite before the checks were added.
- `cargo nextest run -p agenc-relay-auth --all-features --locked` passes 84
  tests with the generator skipped. At the topic tip,
  `cargo clippy --workspace --all-targets --all-features --locked -- -D
  warnings` is clean and `cargo nextest run --workspace --all-features
  --locked` passes all 4,531 tests it runs, the migrated daemon suites
  included (24 skipped). The fuzz workspace's format, deny and check
  commands and the auth doctests pass. The storage disk-profile workload,
  which needs a filesystem no other process writes to, is left to the full
  gate's exclusive lane; this topic does not change the storage crate.

## Limits

- This is an extraction, not a repair: no earlier behaviour was wrong, so no
  regression test fails at the base revision other than by not compiling.
- The server crate's `argon2` and `opaque-sha2` test dependencies are no
  longer named by its tests. They stay, because the workspace checker pins
  the binary's test dependency set and removing them changes `Cargo.lock`.
- The client module is only as careful with secrets as the `opaque-ke`
  source it is linked with. In this workspace and the fuzz workspace that is
  the reviewed local copy, whose patch keeps the password-derived OPRF and
  KSF outputs in zeroizing wrappers inside `get_password_derived_key`, which
  both client finishes call. A consumer with its own workspace root, such as
  the SDK, resolves the unpatched crates.io release unless it repeats the
  root `[patch]`, because the explicit edge of X-09 is not applied (see
  [the OPAQUE fuzz source record](stage-10-opaque-fuzz-source.md)).
- The SDK keeps its own OPAQUE module and comparison tests until the owner
  accepts this extraction.

No Stage 04 or Stage 10 task changes state.
