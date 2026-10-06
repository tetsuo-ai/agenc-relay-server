# Golden Vectors

Production tests treat this directory as immutable input. They do not calculate
their expected bytes with the adapter under test.

Each pipe-delimited record starts with its vector ID, kind, and source. Binary
fields use lowercase hexadecimal. `output_sha256` covers the ordered expected
outputs named by `scripts/check-stage-four.py`. The checker also binds each
complete file and its generator source to SHA-256.

## E2EE companion vectors

`e2ee/identity`, `e2ee/recovery` and `e2ee/reinit` are written by
`scripts/generate-e2ee-vectors.py`, an independent Python TLS encoder and
Ed25519 signer that never calls the Rust codec; `--check` fails on any drift
in any set, including a stale or missing file. The identity set covers the
companion Section 8 objects and is read by
`crates/agenc-relay-e2ee/tests/identity_vectors.rs`.

The ReInit set covers the companion Section 13.8 target construction and is
read byte for byte by `crates/agenc-relay-e2ee/tests/reinit_vectors.rs`. For
suites `0x0001` and `0x0003` it carries the successor extension list a
`ReInit` Proposal carries, the `ArcReInitTargetTBS` that list reconstructs, its
Section 2.2 digest, and a complete sequencer log of the old conversation from
its pinned genesis binding through the ReInit finalization, the attempt
receipt and the activation, with the attempt object, which carries the
target byte for byte, a successor initial Commit whose `ArcCommitAad` names
the old finalization, and the ReInit binding-chain and policy-chain entries a
later joiner of that successor checks against the target the activation's
attempt carries, after the old genesis entry. A suite-`0x0001` log also
advances the accepted state, aborts one ReInit candidate and retries one
attempt, and still carries one target. Rejection files duplicate the context
extension, omit `required_capabilities`, carry a later joiner's context with
its own pending join, change the context core, keep the pinned-revision
target layout that named the finalization ID, name the activation in the
initial Commit, name another target's digest (and carry that target) in an
otherwise valid attempt and receipt, and name the authorized digest while
carrying another target.

The ReInit set also covers the successor rosters. Account `d` rotates its root
continuously (`root-d-1.bin`, whose continuity signature is by `d`'s old root,
and `roster-d-1.bin` under it), and the `rotation` successor names that root
in its roster heads, binding principals, policy and plan; its log runs from the
ReInit candidate through activation under the old council, with the attempt,
the initial Commit and a later joiner's entries. `rotation-0003` is the same
rotation with a suite change from `0x0001` to `0x0003`, reconstructed only.
The rejection files for the rosters are a generation-one root of `d` with the
same fingerprint and a continuity signature by another key, another valid
generation-one root of `d` (`root-d-1-sibling.bin`) from which the rotation
does not descend, a successor naming
a generation-zero root of `d` that does not continue the old one (with its own
root and roster files), a successor whose binding keeps `d`'s old root while
its heads, policy and plan name the new one, and a successor naming a
continuously rotated root of `c` (`root-c-1.bin`, `roster-c-1.bin`), the
channel-authority root the old semantic route lock names.

Two more rejection files hold a successor binding to the shape every binding
has against the semantic route it carries: a successor whose context, binding,
policy and context core name the direct kind while its binding keeps the old
channel's semantic route, lock, channel instance and route binding, as the
Proposal's extension list (`reject-extensions-kind-changed.bin`) and as the
target a sender carrying that list builds (`reject-target-kind-changed.bin`).

The recovery set covers the ENC-01 public-evidence contract: every `.bin`
file is one complete encoded `ArcWireObject` of kind `recovery_submission`
(35), `witness_resolution` (36), `leaf_membership_proof` (37), or an existing
`sequencer_record`, `close_authorization`, or `commit_ack` element or ACK.
Its `manifest.toml` records each file's kind, encoded length, object ID,
semantic IDs, signing seeds, and expected disposition with the exact Section
11.9 reply code. Positive files walk an empty head at the activation anchor
through a candidate record to a close (`submission-01`, `element-01`,
`submission-02`, `element-02`), present two valid successors at one position
(`submission-03-fork-a/b`, `element-03-fork-a/b`), and deliver one witness
resolution (`witness-resolution-begin`, `witness-resolution-entry`).
Rejection files change exactly one submission field, use a device outside the
roster, duplicate a continuing leaf, ACK without a stored proof, or leave a
submission's element unsupplied. These are synthetic public-envelope vectors
whose close element names the head record rather than a real finalization
certificate; they do not substitute for real MLS endpoint evidence, and their
Rust consumers are owned by ENC-02 through ENC-05 under master #35.

## Server-to-client wire vectors

`server-wire-v1.vectors` holds lines a server sends, written by hand from
Architecture Sections 7.4, 9.1, 9.2, 9.4, 9.5 and 10.3 and Appendix A.2,
in the four-field `evidence-id|surface|encoding|payload` form that
`scripts/check-stage-two.py` binds to the Stage 02 evidence IDs. A surface
`accept/<name>` must decode and rebuild byte for byte from its parts;
`reject/<stage>/<error>/<name>` must fail at the framing, tags or message
stage with that error. An ascii payload is one line without its CRLF; a hex
payload is a whole stream. `crates/agenc-relay-client-wire/tests/server_vectors.rs`
reads them.

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

- `crates/agenc-relay-crypto/tests/generate_stage_four_vectors.rs`, SHA-256
  `12c23093367bc95fde8381accef1340ee977974c279948772c49d270ecdaa37a`
- `crates/agenc-relay-auth/tests/generate_stage_four_vectors.rs`, SHA-256
  `3f1afff29e1f54e6d1eda0fd24b58f69742f0c5bc2dffb20f7c70f707d378270`

They call the pinned primitive crates directly and never call the production
crypto or auth adapters. The deterministic RNG in the OPAQUE generator is a
SHA-512 counter stream for vector generation only. It is not reachable from
production code.

Generate candidate output for review with:

```sh
cargo test -q -p agenc-relay-crypto \
  --test generate_stage_four_vectors --locked -- --ignored --nocapture
cargo test -q -p agenc-relay-auth \
  --test generate_stage_four_vectors --locked -- --ignored --nocapture
```

The checked-in OPAQUE bytes use only the pinned `opaque-ke` 4.0.1 primitive
APIs. The local patch changes secret lifetime but not protocol bytes.

Changing a generator does not update a vector automatically. Review the
procedure and candidate bytes, replace the input deliberately, update the
record and file digests, and rerun the independent consumers and Stage 04
checker.
