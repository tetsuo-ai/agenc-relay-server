# Stage 04 Evidence

Status: implementation complete; schema version 2 checkpoint refresh pending.
The [historical
manifest](evidence/stage-04-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json)
binds every required record for source commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb` to one clean gate run and its checked-in
[artifact](evidence/artifacts/stage-four-implementation-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json).

Stage 04 implements the cryptographic adapters and account-authentication
state machines. The adapters compose maintained libraries; they do not
implement cryptographic primitives.

## Secret, entropy, and primitive adapters

`EVID-S04-001-SECRETS` covers move-only secret buffers, narrow byte-exposure
methods, no formatting traits, and zeroization on drop. Compile-fail examples
reject `Clone` and `Debug` on keys, keyed indexes, and secret types. Decrypted
HPKE buffers, padded account-service plaintexts, OPAQUE setup material, fake
records, login state, and session keys remain in zeroizing storage. Canary tests
check that worker errors and public error text do not contain submitted job data.

`EVID-S04-002-ENTROPY` covers complete OS-CSPRNG fills, explicit failure, and
erasure of partially written output. Production has no deterministic entropy
mode or fallback generator.

`EVID-S04-003-DOMAIN-KDFS` covers the registered SHA-256 and SHA-512 domains,
login and fake-credential HMACs, storage HKDF labels, exact output widths, and
cross-domain negative tests. `test-data/vectors/stage-four-crypto-v1.vectors`
supplies fixed expected hash, HMAC, and derived-key bytes. The production tests
consume that file without calling the generator.

`EVID-S04-004-STORAGE-AEAD` covers XChaCha20-Poly1305 with 32-byte keys,
24-byte externally reserved nonces, full tags, typed table and database AAD,
bounded ciphertext, and wrong-key, nonce, AAD, truncation, and tamper tests.
The same fixed crypto file binds the derived keys, storage index, nonce, AAD,
plaintext, and ciphertext. Nonce reservation remains a Stage 05 storage
responsibility.

`EVID-S04-005-SIGNATURES` covers typed Ed25519 signing domains, canonical
message construction, `verify_strict`, wrong-domain rejection, and the absence
of batch, hazmat, legacy, and Serde surfaces. The fixed signature input, public
key, and signature come from the reviewed primitive-level generator.

## Private account service

`EVID-S04-006-HPKE` covers RFC 9180 Base mode with
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, and ChaCha20-Poly1305. Tests enforce
the 4,726-byte request and 4,342-byte response envelopes, recovery epoch,
network, key, request ID, operation kind, zero padding, exporter salt, response
counter, and one-use request/response contexts. The fixed vector includes the
request encapsulation and ciphertext, response exporter key and nonce,
response ciphertext, exact outer wrappers, valid padding boundaries, and an
authenticated nonzero-padding request. Tests mutate network, epoch, key ID,
request ID, request and response kinds, salt, encapsulation, and ciphertext.

`EVID-S04-007-OPAQUE` covers the exact `opaque-ke` 4.0.1 profile, fixed
Argon2id KSF, network and credential identities, canonical serialized lengths,
stable fake records, unknown-login parity, dummy KE3 work, and corruption
rejection. The fake record uses an independently sampled valid client public
key (`ServerSetup::dummy_pk`), an independently sampled 64-byte masking key,
and an all-zero envelope; restore rejects a mismatched key or nonzero fake
envelope. KE2 is the RFC-9807-compatible
320-byte value produced by the pinned suite.
`test-data/vectors/stage-four-opaque-v1.vectors` fixes setup, fake record,
registration request/response/upload/record, KE1/KE2/KE3, real, fake, and
dummy server state, session key, identities, context, KSF parameters, and all
lengths.

`EVID-S04-008-CREATION` covers open, invitation-only, and closed admission, signature
and time checks, login and credential binding, duplicate-login refusal,
one-use registration state, expiry, disconnect, and successful record intent.
It does not create an E2EE identity.

`EVID-S04-009-AUTHENTICATION` covers known and unknown login arms, KE1/KE2/KE3,
connection and origin binding, fake-record and dummy-finish work, one-use
transactions, public result shape, and account-session generation fences.

`EVID-S04-010-COMPLETIONS` covers exporter-authenticated completion receipts,
fresh response salts, exact request and response kind binding, counter
overflow, bare-success refusal, header substitution, tamper, and idempotent
byte replay boundaries.

`EVID-S04-011-DESTRUCTIVE-AUTH` covers fresh same-account proof, credential
identity reuse, revision-bound replacement and deletion intents, one-use
deletion tokens, late precondition checks, atomic domain plans, and removal of
all sessions from the old account generation. There is no server-assisted
password recovery path.

## Workers, dependencies, and verification

`EVID-S04-012-WORKERS` covers separate queued-plus-running limits for channel
and OPAQUE jobs, a physical ingress queue with exactly two slots per worker,
a fixed OS-thread pool, queue-full recovery of unadmitted jobs,
pre-start cancellation, worker panic poisoning, shutdown, joined thread
destruction, and secret-free public errors. Blocking cryptographic work does
not run on Tokio workers.

`EVID-S04-013-DEPENDENCIES` is
`conformance/stage-four-crypto-profile.toml`. It records every direct
cryptographic version, feature set, crates.io checksum, fixed primitive
profile, worker limit, and fuzz bound. It retains the published OPAQUE checksum
and records the complete local patched-tree digest. `scripts/check-stage-four.py`
compares that record with the two crate manifests, root source override,
patched tree, and `Cargo.lock`, rejects Git sources, and permits only the
reviewed OPAQUE/direct-stack duplicate generations.

`EVID-S04-014-VERIFICATION` is the auth, crypto, and domain public-boundary
test matrix plus the `account_service_envelope` and `crypto_wrappers` fuzz
targets. The targets cover outer envelopes, decrypted request and response
parsers, OPAQUE messages and state, invitations, signatures, HPKE keys, and
sealed storage records. The test matrix covers vectors, round trips, malformed
lengths and padding, substitutions, replay, expiry, unknown-login work, worker
bounds, credential replacement, account deletion, and the protocol's critical
branches. `crates/agenc-ircd-auth/tests/stage_four_security.rs` enumerates all
public auth, crypto, and worker error formatting with a secret canary, then
checks queued cancellation and panic capture without formatting the job. Its
known/unknown OPAQUE timing test uses a fixed shuffled schedule, separate
medians, and a pooled median absolute deviation. Measurement is supplemental;
the source-hash-bound path review in
`conformance/stage-four-constant-time-review.toml` is the primary evidence.
That review also records the remaining Stage 05 fixed-lookup dependency.
`conformance/stage-four-fuzz-smoke.toml` records the deterministic smoke runs.
The 24 CPU-hour release campaign for each target remains Stage 10 evidence.

## Gate state

`bash scripts/check-stage-four.sh` inherits every Stage 00 through Stage 03
check and adds the Stage 04 profile, tests, and fuzz target. The [historical
manifest](evidence/stage-04-8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb.json)
binds the full passed gate and its checked-in artifact to exact source commit
`8e7236e82ea15e9d3ae6b2a8f01466e32e48feeb`. The baseline at that commit
contains the corrected normative OPAQUE length. The record is retained as
archive evidence, and a fresh schema version 2 run is required to close
`S04-900` for the current source.
