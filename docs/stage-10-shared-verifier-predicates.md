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

## Enrollment issuance and first contact

### Finding

Companion 8.3 makes an enrollment "a short-lived issuance authorization":
the target roster's `not_before` must lie in the enrollment interval, every
later new-device enrollment targets exactly the next roster generation, and
the certificate then continues unchanged in later rosters, where (8.4)
absence means revoked. `verify_roster_lineage` checked the enrollment
interval only when a certificate's target generation equalled the roster's.
A root-signed roster could therefore carry a certificate enrolled for a
later generation, which skipped the check (the audit's counterexample is a
generation-zero roster holding a certificate enrolled for generation five),
or a certificate claiming an earlier generation that no earlier roster had
issued, or that the predecessor had revoked by leaving it out; every path
admitted both. There was also no shared way to admit a roster on first
contact above generation zero: a caller had the checked path, which needs
the predecessor, or `restore_roster`, which exists for a roster the caller
itself accepted before.

### Change

`crates/agenc-relay-e2ee/src/identity.rs`, by admission path:

| Path | Lineage step | Certificate enrolled for a later generation | Certificate enrolled for an earlier generation |
| --- | --- | --- | --- |
| `verify_roster` (checked) | generation zero without a predecessor, else exactly the next one | refused | active, unchanged, in the predecessor |
| `verify_first_contact_roster` (new) | none; only the shape: generation zero, and only it, names the all-zero predecessor | refused | active, unchanged, in the supplied verified roster of the same root at exactly its target generation |
| `restore_roster` | none | refused | admitted: shown when this node accepted the roster |

A certificate enrolled for the roster's own generation keeps the existing
interval rule on every path. Every refusal is `InvalidValue`.
`verify_first_contact_roster` takes the issuance evidence as earlier
verified rosters (`&[VerifiedRoster]`), such as a Welcome's roster chain or
imported roster proofs; missing evidence refuses the roster, and the result
makes no claim that no newer roster exists. `restore_roster`'s documentation
now says it never admits a roster received from another party. Neither
existing signature changed, so no runtime call site changed.

`initial_authority` keeps admitting each principal's roster with
`restore_roster` under the independently pinned binding, which already
stands in for that roster's omitted history (see Limitations).

One runtime fixture modelled what this refuses:
`leaf_membership::named_roster::successor` built a generation that drops
device 8 and a later one that lists its original certificate again. The
helper now keeps a certificate the predecessor lists and gives a device the
predecessor dropped a fresh enrollment for the new generation, so the two
tests using it still exercise a device active in generation zero, absent
from generation one and active now; their assertions are unchanged.

### Tests

| Test | What it pins |
| --- | --- |
| `tests/shared_predicate_counterexamples.rs::an_initial_roster_holding_a_future_target_certificate_is_refused` | Audit counterexample: generation zero holding a certificate enrolled for generation five. |
| `tests/shared_predicate_counterexamples.rs::control_current_target_certificate_outside_enrollment_window_is_refused` | Control: the existing current-target interval rule. |
| `src/tests/identity.rs::a_certificate_enrolled_for_a_later_generation_is_refused_on_every_path` | A later target at generation zero and at generation one, on the checked, first-contact and restore paths. |
| `src/tests/identity.rs::a_continuing_certificate_must_be_active_unchanged_in_the_predecessor` | Continuing certificates verify after their enrollment interval closed and restore without the predecessor; a new device claiming an earlier target, a replacement certificate under an active Device ID, and a dropped certificate returning are refused. |
| `src/tests/identity.rs::first_contact_requires_the_issuance_of_every_continuing_certificate` | First contact at generation zero equals the initial check; above it, continuing certificates need their exact target roster (either order), and the wrong generation, another root, a late current enrollment, a generation-one roster naming no predecessor and a generation-zero roster naming one are refused; with the evidence the result equals the checked one. |
| runtime `leaf_membership::named_roster::*` (nine tests) | Unchanged assertions over the corrected fixture. |

At `70c832c` the counterexample fails and the control passes. With the
later-target refusal removed from this commit's tree, the counterexample and
the later-target unit test fail; with the earlier-target requirement
removed, the continuing-certificate and first-contact unit tests fail; with
both restored, all pass. The named-roster tests pass either way.

## Compatibility

- Wire: unchanged. The runtime answers every refusal on these paths as before.
- Persistence: unchanged format (storage generation 5). A coordinator could
  never install a same-key set (installation refused it), so no accepted
  durable credential history holds one. A capability statement that names
  another network could have been accepted by an earlier binary; startup
  reconstruction re-verifies every stored statement with
  `restore_capabilities`, so such a row is now skipped at startup, as is
  any stored row that does not re-verify. The same holds for a stored
  roster holding a certificate enrolled for a later generation. `EKEY
  PUBLISH ROSTER` refuses a roster breaking the issuance rules with the same
  reply as any refused roster, and a historical chain refuses the record
  whose roster transition installs one.
- API: `VerifiedRoster` has one more public field, and
  `verify_first_contact_roster` is new; existing signatures are unchanged.
- Privacy and dependencies: unchanged.

## Limitations

- The rule compares a successor with its immediate predecessor only, as the
  companion states it; a key reused from an older, retired credential is not
  a shared-predicate check.
- The opened credential of a credentials file above generation zero is not
  compared with a predecessor it does not carry.
- `authenticate_initial_authority` still admits each principal's roster
  with `restore_roster` under the independently pinned binding, so a pinned
  roster above generation zero keeps its continuing certificates without
  issuance evidence (it now refuses a later target). Requiring that evidence
  there would need a new evidence input; the SDK's verification design asks
  for it at first contact, and it is left to that decision.
- There is no capability first-contact function; a capability head above
  generation zero is still admitted only by succession or restore.
- On first contact the issuance evidence is the roster at exactly the
  certificate's target generation; a later roster that lists the certificate
  is not accepted in its place.
- Restore cannot see a certificate that was dropped and listed again within
  history it does not hold; that stays the checked path's job when the
  roster is first accepted.
- The client consumption rules of 8.3 (a challenge, Device ID, serial or
  target generation already used under a root) remain endpoint checks.
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
cargo nextest run -p agenc-relay-testkit -p agenc-relay-storage -p agenc-relay-server --all-features --locked
python3 scripts/check-source.py check
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
```
