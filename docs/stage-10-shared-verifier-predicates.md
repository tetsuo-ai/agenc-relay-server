# Shared verifier predicates

This record covers X-10 of the SDK program's server work (2026-10-01, outside
master #35): predicates of the shared public verifiers in `agenc-relay-e2ee`
that the SDK readiness audit of 2026-09-28 found admitting correctly signed
objects the companion refuses. These verifiers are what a client runs on the
public objects it imports. A client has no private signer installation and no
durable directory behind them, so each companion rule has to hold in the
shared predicate itself, not only in a later daemon step.

No specification, profile hash, registry, wire format, storage generation or
dependency changes. No Stage 10 task is closed by this record.

## Distinct sequencer-successor key

### Finding

Companion 9.2.1 says "a successor **MUST NOT** reuse the active credential's
public key". `verify_sequencer_credential` checked a successor's generation,
predecessor identifier, interval and continuity signature, but not its key.
A successor carrying its predecessor's public key, whose continuity that same
key signs, therefore verified, and so did every path that chains a successor
through it: `SequencerKeySet::verify`, the credentials-file
`SequencerKeySet::verify_opened`, `verify_context` with a previous sequencer,
and the historical chain's `SEQUENCER` transition. The daemon refused such a
set only later, when installation found two signer roles with one public key;
a client importing a public credentials file has no such step.

### Change

- `crates/agenc-relay-e2ee/src/sequencer.rs`: the predecessor arm of
  `verify_sequencer_credential` refuses a successor whose
  `sequencer_public_key` equals its predecessor's (`InvalidValue`, beside the
  arm's other lineage failures). A credentials file that opens above
  generation zero still has no predecessor at hand; its opened credential is
  checked structurally as before, and the coordinator's durable credential
  history remains the check of that succession.
- Three runtime regressions built a same-key set through the shared verifier
  to exercise the daemon's own checks. They now assert that the verifier
  refuses the set, and assemble it without the verifier
  (`sequencer_eligibility::unverified_set`, which checks each credential only
  structurally) so those daemon checks stay covered: installation refuses two
  roles sharing one key, installation selects a credential by identity rather
  than by key, and a terminal follows its receipt's credential identity.

### Tests

| Test | What it pins |
| --- | --- |
| `tests/shared_predicate_counterexamples.rs::a_same_key_sequencer_successor_is_refused` | Audit counterexample: the anchored successor with its predecessor's key. |
| `tests/shared_predicate_counterexamples.rs::a_key_set_whose_successor_reuses_the_current_key_is_refused` | Audit counterexample: the overlap set, through both `verify` and `verify_opened`. |
| `tests/shared_predicate_counterexamples.rs::control_distinct_key_successor_is_accepted` | Control: a fresh successor key still verifies, alone and in a set. |
| `src/tests/sequencer.rs::a_successor_reusing_its_predecessors_key_is_refused_on_every_chained_path` | The anchored successor, the overlap set, a set opening at the successor with its predecessor at hand, and credentials files opening at and above generation zero; the same chains with a fresh key verify. |
| runtime `sequencer_eligibility::rotation::signer_installation_refuses_keys_outside_their_role` | The verifier refuses the shared-key set; installation still refuses it when assembled without the verifier. |
| runtime `sequencer_eligibility::installation::shared_public_key_does_not_select_another_credential` | The verifier refuses the set; installation selects by credential identity. |
| runtime `sequencer_eligibility::terminal::*` (four tests) | Unchanged assertions; their key-reuse cases now assemble the set without the verifier. |

At `70c832c` the two counterexamples fail and the control passes. With the new
condition removed from this commit's tree, the three e2ee tests above that
expect a refusal and the first two runtime tests fail; with it, all pass. The
terminal tests pass either way: they exercise the daemon, not the predicate.

## Signed network on capability and leaf statements

### Finding

A capability statement and a leaf authorization each sign their own
`network_id`. `verify_capabilities_lineage` and `verify_leaf_authorization`
compared the statement's account, root, roster and device with the trusted
roster but never its network, because `VerifiedRoster` did not carry one. A
statement correctly signed for network B that repeats network A's exact
account, root and roster references therefore verified under the network A
roster, on the checked path and on `restore_capabilities`, and the credential
bundle and KeyPackage checks inherited the omission through the leaf.

### Change

- `crates/agenc-relay-e2ee/src/identity.rs`: `VerifiedRoster` gains a public
  `network_id`, set from the verified root that signed the roster (the roster
  verifiers already require the roster's own `network_id` to equal it). The
  capability verifier (both its checked and restored paths) and
  `verify_leaf_authorization` refuse a statement whose signed network differs
  (`ProfileMismatch`, the variant the crate documents for a network mismatch
  and the one the root and sequencer verifiers use). The signed field is
  compared, never rewritten.
- `VerifiedRoster` is constructed only inside the crate, so the new field is
  an additive change for callers that read it.

### Tests

| Test | What it pins |
| --- | --- |
| `tests/shared_predicate_counterexamples.rs::a_capability_statement_signed_for_another_network_is_refused` | Audit counterexample on `verify_capabilities` and `restore_capabilities`. |
| `tests/shared_predicate_counterexamples.rs::a_leaf_authorization_signed_for_another_network_is_refused` | Audit counterexample on `verify_leaf_authorization`. |
| `tests/shared_predicate_counterexamples.rs::control_valid_same_network_capability_and_leaf_are_accepted` | Control: the same statements for the roster's network verify, the capability statement on both paths. |
| `src/tests/identity.rs::statements_signed_for_another_network_are_refused_under_this_roster` | Re-signed foreign statements refused on the checked and restored capability paths, the leaf path and through a credential bundle; the same statements re-signed for the roster's network verify; the verified roster names its root's network. |

The audit executed only the checked half of the capability case; the restore
half was a reading. At `70c832c`, a probe (not committed) ran
`restore_capabilities` on the network B statement under the network A roster
and it returned `Ok`, so both halves are executed. With the two new
comparisons removed from this commit's tree, the two counterexamples and the
unit test fail; with them, all pass.

## Compatibility

- Wire: unchanged. The runtime answers every refusal on these paths as before.
- Persistence: unchanged format (storage generation 5). A coordinator could
  never install a same-key set (installation refused it), so no accepted
  durable credential history holds one. A capability statement that names
  another network could have been accepted by an earlier binary; startup
  reconstruction re-verifies every stored statement with
  `restore_capabilities`, so such a row is now skipped at startup, as is
  any stored row that does not re-verify.
- API: `VerifiedRoster` has one more public field.
- Privacy and dependencies: unchanged.

## Limitations

- The rule compares a successor with its immediate predecessor only, as the
  companion states it; a key reused from an older, retired credential is not
  a shared-predicate check.
- The opened credential of a credentials file above generation zero is not
  compared with a predecessor it does not carry.
- The changed predicates are not release-critical coverage regions; the
  inventory is unchanged apart from the two moved `sequencer.rs` spans.
- The implementation gate (`scripts/check-stage-nine.sh`) was not run on this
  branch.

## Evidence

Commands at this branch, from the repository root:

```sh
cargo fmt --all --check
cargo clippy -p agenc-relay-e2ee -p agenc-relay-runtime --all-targets --all-features --locked -- -D warnings
cargo nextest run -p agenc-relay-e2ee --all-features --locked
cargo nextest run -p agenc-relay-runtime --all-features --locked
python3 scripts/check-source.py check
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
```
