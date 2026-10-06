# Encrypted recovery, rotation and ReInit with real MLS clients

This record closes ENC-10 (issue #71): the repaired encrypted paths are now
driven end to end by real openmls and mls-rs endpoints through the production
binary's client surface, rather than by synthetic MLS bodies. The gap it
closes is missing end-to-end verification, not a reproduced defect. No wire
object, opcode, reply code, limit or normative text changed; the only
production-crate change is a test-only builder in the testkit.

Three daemon scenarios join the Stage 08 suite, one per repaired path. Each
asserts what plaintext every client can and cannot derive, what the server
refuses, and that a refusal leaves the state it would have changed exactly as
it was. Every scenario runs one coordinator and two edges of the production
binary over real mutual TLS, with both clients registered, authenticated and
device-attached, and every companion object signed by keys no server holds.

## What the endpoints now sign

Before this change the daemon suite attested to one fixed synthetic leaf key
for every conversation: the leaf-membership proof named that key and every
Commit acknowledgement was signed with it, while the MLS libraries held
signature keys of their own. The two are now the same key.

`OldLeaf` names the exact signature key an endpoint's MLS library holds, that
leaf's index in the group, and `old_credential_hash` computed over the encoded
credential bundle the leaf actually carries. `OpenMlsMember::with_leaf` and
`mls_rs_client_with_leaf` build each library's signer from that key, so:

- the Section 13.7.3 leaf-membership proof names the leaf key the library
  advertises and carries that key's own possession signature;
- every `commit processed` and `reinit processed` acknowledgement is signed by
  the private key of the leaf it names;
- the coordinator identifies each acknowledgement through the stored proof of
  that leaf, which is the ENC-05 rule it was written for.

`leaf_membership` also builds removed proofs: an empty possession field and the
finalization identifier that removed the leaf, which is what "a removal proof
holds for a leaf's last epoch" means in practice.

The suites also pace themselves against the Section 16 admission bucket. The
daemon admits four E2EE command lines a second per session with a burst of
twenty; these scenarios submit far more objects than a person would, so each
client waits for its token before writing. A refusal in a scenario is
therefore never the admission bucket.

## Scenario A — recovery

`crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/recovery.rs`,
`a_recovering_member_rejoins_and_reads_only_the_history_it_is_entitled_to`.

alice runs openmls and creates the channel group; bob runs mls-rs. A signed
current-format backup is taken while the route holds no record at all, so the
restored head is the external genesis anchor and every later record must be
recovered. The live lifetime is then five certified real Commits: the bootstrap
activation, bob's Add through a published and claimed KeyPackage and a
delivered Welcome, the removal of the leaf bob lost, the Add of his
replacement leaf, and the closing transition, followed by the finalized public
close. Ten sequencer records stand in route order.

What it proves:

- **A lost leaf does not continue.** Companion 13.7 forbids continuing with the
  old leaf. bob's endpoint is discarded, his leaf is removed by a real Commit,
  he publishes a removed proof naming that removal's finalization, and he
  rejoins under a fresh leaf key through a second claimed KeyPackage and a
  second delivered Welcome.
- **It reads what it is entitled to.** The rejoined endpoint decrypts the
  padded Section 7.5 content alice sends at the epoch it joined.
- **And nothing it is not.** Replaying the retained ciphertext of the epoch
  before the loss into the rejoined endpoint yields no plaintext: mls-rs
  refuses the message, because the epoch secrets of that epoch were never
  delivered to the new leaf.
- **The repaired recovery-evidence path carries that real lineage.** The
  coordinator is restored from the backup under a new recovery epoch; the
  durable gate reads `pending` at the restored binding. The attached device
  uploads the operational policy reference and all ten real records through
  `EGROUP SUBMIT RECOVERY` and `RECOVERY-ELEMENT`, then the close element, and
  the route becomes permanently `closed` naming the original close.
- **A refusal installs nothing.** Inside the upload, a complete record that does
  not continue the chain at its position is refused
  `E2EE_BINDING_AUTH_INVALID`, and the genuine record at that same position is
  still accepted immediately afterwards. After the close, the durable gate
  reads `closed` across a coordinator stop and the restarted coordinator
  refuses every further submission with `E2EE_ROUTE_INVALID`.

## Scenario B — rotation and retirement

`crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/rotation.rs`,
`sequencer_rotation_and_leaf_retirement_hold_the_encrypted_channel`.

The advertised sequencer key set moves through three generations while the
same openmls and mls-rs conversation keeps running. Every restart rewrites the
credentials file on all three nodes and the signer paths on the coordinator,
stops every daemon, starts them again, and brings both clients back as new
sessions of the same accounts with their retained device identities.

What it proves:

- **Generation zero.** The bootstrap activation's candidate receipt names the
  credential the binding pinned, and its sequencer signature verifies under
  exactly that credential's public key.
- **The overlap set.** The file advances to set generation one with the
  generation-zero credential first and the chained successor second, the
  successor signer installed beside the active one. A finalized `SEQUENCER`
  transition is itself receipted under the old credential, exactly as
  companion 9.2.1 requires.
- **The pin moves.** The next real Commit's receipt names the successor
  credential and verifies under the successor's public key.
- **The file opens above generation zero.** The set then advances to generation
  two carrying only the generation-one credential, with the successor signer
  removed and the active signer set to it. The coordinator starts, both edges
  acknowledge the profile, both clients re-attach and the conversation keeps
  running: bob rejoins with a fresh leaf and decrypts the minutes of the epoch
  he joined, and that Commit's receipt still names the successor.
- **A retired credential can no longer be pinned.** A second channel bound
  while its package still pins the retired generation-zero credential is
  refused `E2EE_BINDING_AUTH_INVALID` with no `BOUND` line, and the same
  reservation binds once the package pins the credential the set now issues.
- **A retired leaf reads nothing past its retirement.** bob's leaf is removed by
  a real Commit and he publishes the removal proof of that leaf's last epoch.
  The edge still forwards alice's next application object to him — the carrier
  is opaque and hides nothing — and his retained endpoint derives no plaintext
  from it. A continuing proof of the same leaf at the same epoch is refused
  `E2EE_OPERATION_CONFLICT`, and the byte-identical removal still returns the
  same stored identifier, so the refusal changed nothing.

## Scenario C — ReInit

`crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/reinit.rs`,
`a_reinit_activates_only_with_every_continuing_leaf_acknowledged`.

A real RFC 9420 ReInit. alice's old group is an mls-rs group; an openmls leaf
of bob publishes a real KeyPackage, is claimed and added to it, and is removed
before the ReInit, so the old group crosses both libraries. The two endpoints
that continue into the successor are both mls-rs, because openmls 0.9 exposes
no API that creates a ReInit proposal or a resumption successor. The old group
reaches its ReInit through four certified real Commits, then a fifth whose
inline proposal is a genuine `ReInitProposal` and whose authorization carries
`action_bits::REINIT` and the Section 2.2 target digest of the immutable
`ArcReInitTargetTBS`.

What it proves:

- **Which members continue and which must rejoin.** bob's openmls leaf joins
  and is removed in its own finalized epoch, with a removal proof naming that
  finalization. It is therefore not in the expected continuing set, is not
  carried by the key-package plan, and is not required to acknowledge the
  attempt. bob's replacement mls-rs leaf and alice's creator leaf are the
  continuing set, and both appear in the plan.
- **The attempt is real.** Both endpoints resume through
  `Group::get_reinit_client`; bob generates the reserved KeyPackage of the
  successor suite, alice builds the resumption successor with it, and bob
  consumes the one-use Welcome and reaches new epoch one. The attempt object
  carries that plan, the successor's initial state bytes, the exporter
  authenticator the companion fixes (`ARC-MLS/1 reinit activation` over the old
  ReInit state), and the old-policy controller authorization whose every field
  the attempt repeats. `EGROUP SUBMIT REINIT ATTEMPT` stages it and the
  coordinator's `reinit_attempt` receipt names it.
- **One acknowledgement per continuing leaf.** The creator submits a
  `creator_state` acknowledgement with an empty reserved reference from its own
  attached device; the continuing joiner submits a `welcome_join`
  acknowledgement naming its own plan entry from its own device. Each is signed
  by the private key of the old leaf it names.
- **The bounded expected-continuing-set behaviour.** An activation carrying only
  the creator's acknowledgement is refused `E2EE_BINDING_AUTH_INVALID` with no
  `REINIT-ACTIVATED` line. The attempt and its receipt are unchanged: the same
  attempt and the same receipt then activate once both acknowledgements are
  present, under the two-of-two council quorum the operational policy derives.
- **What each endpoint can derive.** The activated successor's padded content
  decrypts in the continuing joiner's successor state, and the openmls state of
  the leaf removed before the ReInit derives nothing from it.
- **One target, checked through the shared history** (PC-001 revision,
  2026-10-04). The target is built once, before the ReInit Commit, and names
  no state of the old group, so the digest the controller authorization
  commits is the digest every attempt names, and every attempt carries that
  target byte for byte in `ArcReInitAttempt.target`; the attempt-abort
  scenario stages its attempt the same way. After the activation the scenario
  fetches the daemon's retained records and replays them through
  `HistoricalChain`, resumed at the accepted state before the ReInit
  candidate: the finalization commits the target's digest, `AuthorizedReinit`
  recomputes the finalization identifier and accepts the carried target, a
  target with one field replaced neither matches the authorization nor binds
  to the chain, the bound target admits the attempt receipt whose carried
  target it equals, no target binds while that attempt is open, and the
  activation ends the old lineage naming the successor conversation. The
  replayed attempt does not satisfy the companion's successor initial-Commit
  rule: its `initial_commit_bytes` are the mls-rs `GroupInfo` message (see
  Limitations), which `AuthorizedReinit::check_initial_commit` refuses as
  another message kind. `HistoricalChain` does not apply that rule, so this
  scenario proves the one target, not the initial Commit.

## Fixtures

- The three scenarios share `encrypted_clients.rs`: the channel bind, the live
  conversation, the real-leaf evidence, and the daemon lifecycle wrapper.
- Every scenario runs on the admin-enabled capacity plan, because the restore
  and rotation steps stop daemons through the local admin socket and wait on
  the account authority it reports.
- Rosters and leaves are valid around the wall-clock second the fixture starts,
  and scenario A drives its canonical validation times from that same second,
  because the ENC-02 historical chain re-verifies every root and roster at the
  record's own validation time.

## Limitations

- mls-rs produces a Welcome and a `GroupInfo` for a resumption successor, not a
  separate initial-Commit message, and offers no way to set that Commit's
  authenticated data. The attempt therefore carries the successor's
  `GroupInfo` message as `initial_commit_bytes`. The coordinator binds only its
  digest and never parses it; parsing the successor's Add set, KeyPackageRefs
  and resumption PSK usage is the endpoint check the companion assigns to
  endpoints, and it is not claimed here. The initial Commit's `ArcCommitAad`
  naming the old finalization (companion 13.8, PC-001 revision) is checked by
  `AuthorizedReinit::check_initial_commit` against the independent vectors in
  `test-data/vectors/e2ee/reinit`, not against an mls-rs Commit.
- For the same reason the scenario's ReInit proposal carries an empty
  extension list: these endpoints advertise no ARC extension capability, and
  the target the scenario builds carries a one-byte placeholder list. The
  target's reconstruction from a real extension list, and the structural
  checks of the list an attempt carries, are exercised by the ReInit vectors
  for suites `0x0001` and `0x0003`, not by this scenario.
- Three of the four successor result digests
  (`new_group_info_digest`, `new_group_context_digest`,
  `new_ratchet_tree_digest`) are object-identifier hashes of successor
  material, not the Section 2.2 formulas the companion registers for them.
  The fourth, the exporter authenticator, uses the label and context the
  companion fixes.
- The successor route of the ReInit is not bound, so successor traffic is
  exchanged between the two endpoints rather than carried by the daemon. The
  `ArcStagedReInit` mailbox carrier is not exercised; the normal Welcome mailbox
  carrier is, in scenarios A and B.
- The two endpoints that continue through the ReInit are both mls-rs, for the
  library reason above; openmls participates in scenario C only as the leaf
  removed before it.
- Scenario B proves the retirement of a sequencer credential that no live route
  still pins. The blocked-route path of a retirement before the overlap
  deadline stays with the ENC-07 in-process suites.
- These are development-host runs of the Stage 08 fixture. Native release
  qualification, the seven-day soak and the long fuzz campaigns remain with the
  root release issues.

## Evidence

Sources:

- `crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients.rs`
- `crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/recovery.rs`
- `crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/rotation.rs`
- `crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/reinit.rs`
- `crates/agenc-relay-server/tests/stage_eight_e2ee.rs` (real-leaf evidence, the
  paced client, the shared certification helpers)
- `crates/agenc-relay-server/tests/stage_eight_e2ee/close_authority.rs`
- `crates/agenc-relay-testkit/src/e2ee_client.rs`
  (`sequencer_retirement_document`)
- `conformance/e2ee-interop-matrix.toml`

Commands and results at this branch (Rust 1.98.0, from the repository root):

```sh
cargo test -p agenc-relay-server --test stage_eight_e2ee --all-features
# 34 passed; 0 failed; 16 ignored (the Stage 10 drills); 72.26s
cargo test -p agenc-relay-server --test stage_eight_e2ee --all-features -- encrypted_clients
# 4 passed; 0 failed; 46 filtered out; 45.55s
cargo test -p agenc-relay-e2ee --all-features
# 210 passed; 0 failed across eleven result groups
cargo test -p agenc-relay-testkit --all-features
# 0 failed across twenty-two result groups
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean
cargo fmt --all --check
python3 scripts/check-source.py check
# source policy: ok (984 Rust files)
python3 scripts/requirements.py check
# requirement ledger: ok (251 records)
```

The interoperability matrix records nine new lifecycle rules, three per
scenario, and its final close claim is repaired: the conversation closes under
a separately finalized public closing intent, not under the finalization that
added the joiner. Each real-client suite requires its own rules to read
`agree` and requires the matrix to record no lifecycle rule that no suite
claims, so a deviation is visible rather than hidden.

The coverage source inventory in `conformance/critical-coverage.toml` and
`conformance/release-critical-coverage.toml` is reanchored for the one
production source this change touches. No critical region moved, so no region
digest changed.
