# Golden Vectors

Production tests treat this directory as immutable input. They do not calculate
their expected bytes with the adapter under test.

Each pipe-delimited record starts with its vector ID, kind, and source. Binary
fields use lowercase hexadecimal. `output_sha256` covers the ordered expected
outputs named by `scripts/check-stage-four.py`. The checker also binds each
complete file and its generator source to SHA-256.

## Stage 04 files

`stage-four-crypto-v1.vectors` contains the project SHA-256, HMAC, HKDF,
XChaCha20-Poly1305, strict Ed25519, HPKE request, HPKE response-exporter, and
padding vectors. Its SHA-256 is
`a3c88fc13fdf701d4ca5b2798b2a8db43269e2b1e3debd9ade81ea256b740ede`.

`stage-four-opaque-v1.vectors` contains the exact OPAQUE setup, fixed fake
record, registration messages and password file, real and fake login messages,
server states, session key, dummy-finish input, fixed Argon2id parameters, and
all serialized lengths. Its client public key is the setup's separately
sampled `dummy_pk`; its masking key is sampled independently and its envelope
is all zero. The file's SHA-256 is
`a0134c2b46c08def5d5081a58d2a6212b3d90fe4ef55f9242f563452440abf3f`.

The ignored Rust targets are manual reference generators:

- `crates/agenc-ircd-crypto/tests/generate_stage_four_vectors.rs`, SHA-256
  `12c23093367bc95fde8381accef1340ee977974c279948772c49d270ecdaa37a`
- `crates/agenc-ircd-auth/tests/generate_stage_four_vectors.rs`, SHA-256
  `3f1afff29e1f54e6d1eda0fd24b58f69742f0c5bc2dffb20f7c70f707d378270`

They call the pinned primitive crates directly and never call the production
crypto or auth adapters. The deterministic RNG in the OPAQUE generator is a
SHA-512 counter stream for vector generation only. It is not reachable from
production code.

Generate candidate output for review with:

```sh
cargo test -q -p agenc-ircd-crypto \
  --test generate_stage_four_vectors --locked -- --ignored --nocapture
cargo test -q -p agenc-ircd-auth \
  --test generate_stage_four_vectors --locked -- --ignored --nocapture
```

The checked-in OPAQUE bytes use only the pinned `opaque-ke` 4.0.1 primitive
APIs. The local patch changes secret lifetime but not protocol bytes.

Changing a generator does not update a vector automatically. Review the
procedure and candidate bytes, replace the input deliberately, update the
record and file digests, and rerun the independent consumers and Stage 04
checker.
