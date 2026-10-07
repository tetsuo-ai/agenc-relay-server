# The leaf credential the credential hashes read (D-42)

This record covers decision D-42 of the SDK server program (2026-10-07,
outside master #35). Companion Section 2.2 defines

- `old_credential_hash` as
  `SHA256("ARC-MLS/1 old credential hash" || encoded_BasicCredential)`, and
- `resulting_leaf_credential_hash` as
  `SHA256("ARC-MLS/1 resulting leaf credential" || TLS-encode(resulting_leaf_index, encoded_BasicCredential))`,

and every formula of that registry "hashes the canonical TLS encoding of the
named TBS unless a different input is stated explicitly". RFC 9420 Section
5.3 encodes a leaf's credential as one `Credential` structure: a `uint16`
`credential_type` and, for the type `basic`, `opaque identity<V>`. Companion
Section 8.5 places the exact `ArcCredentialBundle` in that identity.
`encoded_BasicCredential` is therefore the canonical TLS encoding of the
leaf's RFC 9420 `Credential` whose `credential_type` is basic: the credential
type, then `identity<V>`. These are the bytes the shared outer parser records
for a KeyPackage leaf and the bytes an MLS library encodes for that leaf's
credential.

The first commit gives the shared code one helper over that input, checked
against openmls and mls-rs. The second has the independent vector generator
hash the same input and regenerates the vectors that carry these hashes. No
specification text, profile hash, registry
entry, named limit, reply code, wire object, table, key, row kind, field or
storage generation changed, and no runtime path changed: the coordinator
compares the credential hashes that ACKs, leaf-membership proofs and ReInit
attempts carry, and never computes one from a credential.

## One helper over the leaf's credential (first commit)

- `agenc_relay_e2ee::mls_outer::EncodedBasicCredential` holds one leaf's
  credential in the form both hashes read. `EncodedBasicCredential::parse`
  reads its input as exactly one basic `Credential` with the KeyPackage
  parser's own credential reader (`read_basic_credential`, which
  `parse_leaf_node` now calls for the slice it records as
  `PublicLeafNode::encoded_credential`). Another credential type is refused
  with `ProfileMismatch`; a short input, trailing bytes and a non-minimal
  length prefix are refused as the parser refuses them. The bare identity,
  which is the encoded `ArcCredentialBundle`, and `identity<V>` without its
  credential type are not a credential, and are refused.
- `EncodedBasicCredential::old_credential_hash` and
  `EncodedBasicCredential::resulting_leaf_credential_hash` hash exactly
  those bytes, through `ids::old_credential_hash` and
  `ids::resulting_leaf_credential_hash`, whose documentation now names the
  input.
- `PublicLeafNode::credential` returns a parsed leaf's credential. It reads
  the public field again, so a leaf whose field was changed after parsing is
  refused rather than hashed.

The KeyPackage parser reads, accepts and refuses exactly what it did before;
only the credential reader moved into its own function.

Tests:

- `mls_outer::tests::a_leaf_credential_hash_reads_the_leafs_whole_basic_credential`
  parses a KeyPackage and requires that its leaf's credential is the basic
  type followed by `identity<V>`, and that both hashes equal SHA-256 over the
  registry label and those bytes (with the big-endian leaf index for the
  resulting-leaf hash), computed in the test without the crate's label table.
- `mls_outer::tests::other_credential_encodings_are_not_a_leaf_credential`
  refuses the bare identity, `identity<V>` without its type, a bare identity
  that starts with the basic type value (as an encoded `ArcCredentialBundle`
  does, with its profile version), another credential type, trailing bytes,
  a short input, a non-minimal length prefix, and a leaf whose public field
  holds its identity instead of its credential.
- `mls_interop::the_parsed_leaf_credential_is_each_librarys_credential_encoding`
  (testkit) is the cross-check with two MLS libraries. For suites `0x0001`
  and `0x0003`, and identities of 21, 1,000 and 20,000 bytes (one-, two- and
  four-byte length prefixes), openmls 0.9.0 and mls-rs 0.56.0 each generate
  a KeyPackage. The daemon's parser reads it and verifies its signatures, and
  the leaf's credential slice must equal that library's own encoding of the
  `Credential` its KeyPackage holds (openmls `tls_serialize_detached`, mls-rs
  `mls_encode_to_vec`). Both hashes must equal SHA-256 over the label and
  those bytes.

Revert proofs, each run of the outer-parser unit tests and the testkit
cross-check against one edit of `mls_outer.rs`: with the file set back to
the parent the tests do not compile, because the helper is absent; and each
of six single edits fails a test (exit 100). A credential slice that starts
after the credential type fails the existing KeyPackage field test, the new
unit test and the cross-check; a hash over the bytes after the type, and a
resulting-leaf hash that ignores its index, each fail the new unit test and
the cross-check; a parse that accepts trailing bytes, one that accepts
another credential type, and a leaf whose field is not read again each fail
the refusal test, the second also the parser's existing refusal of another
credential type.

## The vectors hash the same input (second commit)

`scripts/generate-e2ee-vectors.py` gains `encoded_basic_credential`, the
basic credential type followed by `identity<V>`, which both the KeyPackage
leaf and every `old_credential_hash` of the generator now use:

- the recovery set's leaf-membership proofs and its Commit ACK hash the
  credential whose identity is the device's credential bundle, the same
  bytes the identity set's `key-package-7.bin` carries for device 7;
- the ReInit set's principals hash the credential of their old leaf, whose
  synthetic identity is the principal's root identity followed by its device
  certificate, in every Commit ACK, attempt, attempt authorization and
  ReInit ACK.

The generator writes no `resulting_leaf_credential_hash`. Its module
documentation states the rule.

The regenerated files, all through the generator (`python3
scripts/generate-e2ee-vectors.py`, then `--check`: 9 identity, 20 recovery
and 81 ReInit files):

- Identity set: no file changed; `key-package-7.bin` already carried this
  encoding of its credential.
- Recovery set, 6 files: `membership-continuing.bin`,
  `membership-removed.bin`, `reject-duplicate-continuing-leaf.bin`,
  `reject-revoked-device.bin`, `commit-ack-without-membership.bin` and
  `manifest.toml`. The other 15 files are byte-identical.
- ReInit set, 40 files: `manifest.toml` and the 39 files from the
  bootstrap finalization on, whose ACK set digest, and with it every later
  record identifier, initial Commit and attempt, follows the ACKs:
  `record-01-bootstrap-finalization.bin`; `advanced-attempt-0.bin`,
  `advanced-attempt-1.bin`, `advanced-initial-commit-0.bin`,
  `advanced-initial-commit-1.bin` and `advanced-record-02` to
  `advanced-record-11`; `rotation-attempt-0.bin`,
  `rotation-initial-commit-0.bin` and `rotation-record-02` to
  `rotation-record-05`; for each of `suite-0001` and `suite-0003`,
  `attempt-0.bin`, `initial-commit-0.bin` and `record-02` to `record-05`;
  and the rejections `reject-carried-target-attempt-0.bin`,
  `reject-carried-target-record-04-attempt-0-receipt.bin`,
  `reject-initial-commit-names-activation.bin`,
  `reject-other-digest-attempt-0.bin`,
  `reject-other-digest-record-04-attempt-0-receipt.bin` and
  `reject-target-pinned-layout.bin`. The other 42 files (the genesis,
  policies, roots, rosters, sequencer credential, bootstrap candidate,
  extension lists, targets, joiner entries and the other rejections) are
  byte-identical.

No manifest digest, fixture or checker outside the vector directories pins
the replaced bytes: none of the 82 identifiers and digests the two manifests
no longer carry occurs anywhere else in the tree, and the vector sets are
checked only by `generate-e2ee-vectors.py --check` and the e2ee crate's
vector tests, which read the manifests.

Tests:

- `membership_vectors::generator_proofs_name_the_leaf_by_its_basic_credential`
  parses `key-package-7.bin` with the outer parser, requires that its leaf's
  identity is `credential-bundle-7.bin`, and requires that the three proofs
  naming device 7's leaf carry that leaf credential's `old_credential_hash`.
- `reinit_vectors::every_old_leaf_is_named_by_its_basic_credential` builds
  the credential of each principal's old leaf from `root-c.bin` and
  `roster-c.bin` (and `d`), and requires that every attempt's creator, every
  Commit ACK of a finalization record and every ReInit ACK of an activation
  record names its leaf by that hash: 9 attempts, 6 Commit ACKs and 8 ReInit
  ACKs.

Revert proofs, each regenerating the vectors with the edit, running the
three vector test binaries and restoring the files byte for byte: with the
generator's credential hash set back to `identity<V>` without the type, both
new tests fail; with only the ReInit principals' hash set back, the ReInit
test fails; with the whole generator set back to the parent, both fail; and
with the vector files set back to the parent under the new generator,
`generate-e2ee-vectors.py --check` exits 1 and both tests fail. Every other
vector test passes in each case.

## For the next normative revision

The companion does not define `encoded_BasicCredential` in words. Adding a
definition changes the bytes of `docs/arc-mls-e2ee-extension.md` and so the
ARC-MLS profile hash (companion Section 2.3), which needs a normative
revision and its refreeze. This topic changes neither that document nor
`docs/federation-v1-profile.registry`. The next normative revision should add
this sentence to Section 2.2, as a paragraph directly after the registry
table:

> In the `old_credential_hash` and `resulting_leaf_credential_hash` rows,
> `encoded_BasicCredential` is the canonical TLS encoding of the leaf's
> RFC 9420 `Credential` whose `credential_type` is `basic`: the `uint16`
> `credential_type` followed by `opaque identity<V>`, whose `identity` is the
> exact `ArcCredentialBundle` (Section 8.5).

`TODO.md` lists it as an open item.

## Coverage

The first commit changes `mls_outer.rs` and the documentation of two
functions in `ids.rs`. `mls_outer.rs` has no reviewed region; the five
`companion-ids-*` regions of the release policy below the changed comments
move, with their spans unchanged. Both source inventories are refreshed. The
second commit changes no production source.

## Validation

First commit, Rust 1.98.0, from the worktree root, each exit 0:

- `cargo clippy --workspace --all-targets --all-features --locked -- -D
  warnings`.
- `cargo nextest run -p agenc-relay-e2ee --all-features --locked
  --no-fail-fast`: 354 of 354 pass.
- `cargo nextest run -p agenc-relay-testkit --all-features --locked
  --no-fail-fast --test mls_interop`: 2 of 2 pass.
- `python3 scripts/check-coverage.py audit` on both policies, and `git diff
  --cached --check`.
- The program's 59-command fast gate on the staged tree: 59 of 59 exit 0. It
  includes `cargo fmt --all --check`, `python3 scripts/check-source.py
  check`, `bash scripts/check-spec.sh`, `cargo audit --deny warnings` and
  `python3 scripts/generate-e2ee-vectors.py --check`.

Second commit, each exit 0: `cargo clippy --workspace --all-targets
--all-features --locked -- -D warnings`; `cargo nextest run -p
agenc-relay-e2ee --all-features --locked --no-fail-fast`, 356 of 356 pass;
`python3 scripts/generate-e2ee-vectors.py --check`; `python3
scripts/check-coverage.py audit` on both policies; `git diff --cached
--check`; and the 59-command fast gate on the staged tree, 59 of 59.

Not run here: the full stage-nine gate, which cannot finish on this host.
