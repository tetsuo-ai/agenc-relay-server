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
- Three places in the runtime regressions (two tests and the set helper of
  four terminal tests) built a same-key set through the shared verifier to
  exercise the daemon's own checks. They now assert that the verifier
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
| `src/tests/context.rs::a_context_sequencer_successor_needs_a_fresh_key` | `verify_context` with a previous sequencer refuses a context whose sequencer reuses the predecessor's key and verifies one with a fresh key. |
| `tests/history.rs::a_sequencer_rotation_changes_the_committed_credential_for_later_positions` | The historical chain's `SEQUENCER` transition refuses a successor credential that reuses the current key (the chain is unchanged) and installs the fresh-key successor. |
| runtime `sequencer_eligibility::rotation::signer_installation_refuses_keys_outside_their_role` | The verifier refuses the shared-key set; installation still refuses it when assembled without the verifier. |
| runtime `sequencer_eligibility::installation::shared_public_key_does_not_select_another_credential` | The verifier refuses the set; installation selects by credential identity. |
| runtime `sequencer_eligibility::terminal::*` (four tests) | Unchanged assertions; their key-reuse cases now assemble the set without the verifier. |

At `70c832c` the two counterexamples fail and the control passes. With the new
condition removed from this commit's tree, the three e2ee tests above that
expect a refusal and the first two runtime tests fail; with it, all pass. The
terminal tests pass either way: they exercise the daemon, not the predicate.
The context and historical-chain cases were added after the independent
review of the branch noted that no test exercised those two paths with a
same-key successor; with the condition removed, both fail, beside the three
e2ee tests above.

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
| `verify_first_contact_roster` (new) | the predecessor the roster names, when the supplied rosters hold its root's previous generation; otherwise only the shape: generation zero, and only it, names the all-zero predecessor | refused | active, unchanged, in the supplied roster of its root at exactly its target generation, and in every supplied roster of its root after that one |
| `restore_roster` | none | refused | admitted: shown when this node accepted the roster |

A certificate enrolled for the roster's own generation keeps the existing
interval rule on every path. Every refusal is `InvalidValue`.
`verify_first_contact_roster` takes the issuance evidence as earlier
verified rosters (`&[VerifiedRoster]`), such as a Welcome's roster chain or
imported roster proofs. Those of the roster's root below its generation are
history the roster must continue, as succession holds a roster to its
predecessor: besides the two columns above, every revocation a supplied
roster of the root lists must still be listed. A missing target-generation
roster refuses the roster; a roster that is not supplied is not inferred,
and supplied rosters of other roots, or at or above the roster's
generation, are not consulted. When the supplied rosters are the complete
chain from generation zero under the root, first contact decides exactly as
the checked path does from the predecessor; the result makes no claim that
no newer roster exists. `restore_roster`'s documentation now names its two
uses, a roster this node accepted before and a principal roster an
independently pinned binding names (initial authority), and says it never
admits a roster on another party's say-so. Neither existing signature
changed, so no runtime call site changed.

`initial_authority` keeps admitting each principal's roster with
`restore_roster` under the independently pinned binding, which already
stands in for that roster's omitted history (see Limitations).

One runtime fixture modelled what this refuses:
`leaf_membership::named_roster::successor` built a generation that drops
device 8 and a later one that lists its original certificate again. Under
one root no conforming roster does that: the dropped certificate was
revoked (8.4), and a root uses a Device ID, enrollment challenge and serial
once (8.3). The first version of this change re-enrolled the returning
device under the same root with its old Device ID, key and challenge, which
8.3 has clients reject, and so changed the tests' scenario while saying it
kept it; the independent review of the branch found both. The fixture now
returns the device the conforming way: a continuous root rotation (8.2),
whose first roster issues every kept device a fresh certificate under the
new root, makes it roster-active again (13.7.3).
`AccountRoot::successor` keeps every certificate under the same root and
refuses to return a dropped device there. The two tests using it still
exercise a device active in generation zero, absent from generation one and
roster-active now by Device ID, which is the daemon's rule; their scenario
now includes the rotation, and their assertions are unchanged.

### Tests

| Test | What it pins |
| --- | --- |
| `tests/shared_predicate_counterexamples.rs::an_initial_roster_holding_a_future_target_certificate_is_refused` | Audit counterexample: generation zero holding a certificate enrolled for generation five. |
| `tests/shared_predicate_counterexamples.rs::control_current_target_certificate_outside_enrollment_window_is_refused` | Control: the existing current-target interval rule. |
| `src/tests/identity.rs::a_certificate_enrolled_for_a_later_generation_is_refused_on_every_path` | A later target at generation zero and at generation one, on the checked, first-contact and restore paths. |
| `src/tests/identity.rs::the_current_target_enrollment_interval_includes_both_ends` | A certificate enrolled for the roster's own generation is admitted with `issued_at` or `expires_at` equal to the roster's `not_before`, and refused one second outside either end, on the checked, first-contact and restore paths. With either comparison made strict, it fails. |
| `src/tests/identity.rs::a_continuing_certificate_must_be_active_unchanged_in_the_predecessor` | Continuing certificates verify after their enrollment interval closed and restore without the predecessor; a new device claiming an earlier target, a replacement certificate under an active Device ID, and a dropped certificate returning are refused. |
| `src/tests/identity.rs::first_contact_requires_the_issuance_of_every_continuing_certificate` | First contact at generation zero equals the initial check; above it, continuing certificates need their exact target roster (either order), and the wrong generation, another root, a target-generation roster without the device or holding another certificate for its Device ID, a late current enrollment, a generation-one roster naming no predecessor and a generation-zero roster naming one are refused; with the evidence the result equals the checked one. |
| `src/tests/identity.rs::first_contact_holds_a_roster_to_every_supplied_roster_of_its_root` | Given the complete chain from generation zero, first contact decides as the checked path does for a certificate dropped by a supplied roster between its target and the roster (with and without a revocation entry), a revocation dropped, a supplied previous generation that is not the named predecessor, and the conforming continuations; without the roster that dropped a certificate nothing shows the drop; supplied rosters of another root or of the roster's own generation are not consulted. |
| runtime `leaf_membership::named_roster::*` (nine tests) | Unchanged assertions; in the two tests whose device returns, it returns through a continuous root rotation. With a device absent from the named roster classified as invalid rather than inactive, exactly those two fail. |

At `70c832c` the counterexample fails and the control passes. With the
later-target refusal removed from this commit's tree, the counterexample and
the later-target unit test fail; with the earlier-target requirement
removed, the continuing-certificate and first-contact unit tests fail; with
both restored, all pass. The named-roster tests pass either way.

The independent review of the branch found that the first version of
`verify_first_contact_roster` consulted only the supplied roster at a
certificate's target generation, so it admitted a certificate that a
supplied later roster showed dropped, which the checked path refuses, and
that no test pinned the exact-certificate condition. The rules above are
the correction: written first, the second first-contact test fails against
the first version (first contact admits what succession refuses) and passes
with the correction. Each of these mutations of the correction fails at
least one of the two first-contact tests: requiring no supplied roster to
hold the certificate, comparing Device IDs instead of certificates,
dropping the target-generation requirement, the predecessor rule or the
revocation rule, consulting supplied rosters of other roots or at the
roster's own generation, and counting history from generation zero rather
than from the target.

## A certificate listed both active and revoked

### Finding

Companion 8.4 makes `(Device ID, certificate_serial)` unique and reads
absence from the active set as revocation. `verify_roster_lineage` checked
that each of a roster's two vectors is canonical but never compared the
active set with the roster's own `revocations`, so a root-signed roster that
lists one certificate both active and revoked verified on every path, and on
succession the predecessor's revocation was carried while the certificate
stayed active. The independent review of this branch found it; it predates
the branch (`70c832c` admits the same roster).

### Change

- `crates/agenc-relay-e2ee/src/identity.rs`: `verify_roster_lineage` refuses
  a roster in which an active certificate's `(device_id,
  certificate_serial)` also appears in its `revocations` (`InvalidValue`),
  on the checked, first-contact and restore paths alike.

### Tests

| Test | What it pins |
| --- | --- |
| `src/tests/identity.rs::a_certificate_listed_active_and_revoked_is_refused_on_every_path` | A generation-zero roster, and a successor that carries the predecessor's revocation while listing the certificate, are refused on the checked, first-contact and restore paths; a successor that drops the certificate and revokes it verifies on all three. |

Written before the change, the test fails (the generation-zero roster
verifies); with the change it passes.

## First contact for capability statements

### Finding

The SDK's shared-verifier design asks the shared API for an explicit
first-contact admission of a nonzero roster or capability head, so that a
client with no pinned head never calls a `restore_*` helper on received
bytes. The roster gained `verify_first_contact_roster` above, but a
capability statement above generation zero with no pinned head was
refused by `verify_capabilities` (no predecessor means generation zero)
and admitted only by `restore_capabilities`, which exists for a statement
the caller accepted before. A client importing a peer device's rotated
capabilities therefore had no sanctioned shared path. The independent
review of this branch raised it.

### Change

- `crates/agenc-relay-e2ee/src/identity.rs`: the new
  `verify_first_contact_capabilities(roster, statement)` applies every rule
  of `verify_capabilities` (active device, exact roster references, signed
  network, bounded interval, canonical vectors, device signature) except
  the predecessor step, which the lineage shape replaces: generation zero,
  and only it, names the all-zero predecessor (`InvalidValue`). The public
  `Lineage` mode gains a `FirstContact` variant for it; no public function
  takes a `Lineage`, and no code in this workspace or the SDK matches on
  it. `restore_capabilities`'s documentation now says it never admits a
  statement received from another party.

### Tests

| Test | What it pins |
| --- | --- |
| `src/tests/identity.rs::first_contact_admits_a_capability_head_at_any_generation` | First contact admits generations zero, one and five with no predecessor, and equals the checked result where succession applies; a generation-one statement naming the all-zero predecessor, a generation-zero one naming another, a device the roster does not list, a statement signed for another network and a forged signature are refused. |

Before the change the test does not compile (the function does not
exist). With the shape check removed, or replaced by the checked rule
without a predecessor, the test fails; with the change it passes.

## Compatibility

- Wire: unchanged. The runtime answers every refusal on these paths as before.
- Persistence: unchanged format (storage generation 5). A coordinator could
  never install a same-key set (installation refused it), so no accepted
  durable credential history holds one. A capability statement that names
  another network could have been accepted by an earlier binary; startup
  reconstruction re-verifies every stored statement with
  `restore_capabilities`, so such a row is now skipped at startup, as is
  any stored row that does not re-verify. The same holds for a stored
  roster holding a certificate enrolled for a later generation, or one
  listing a certificate both active and revoked. `EKEY PUBLISH ROSTER`
  refuses a roster breaking the issuance rules, or listing a certificate
  both active and revoked, with the same reply as any refused roster, and a
  historical chain refuses the record whose roster transition installs one.
- API: `VerifiedRoster` has one more public field,
  `verify_first_contact_roster` and `verify_first_contact_capabilities`
  are new, and `Lineage` has one more variant; existing signatures are
  unchanged.
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
- On first contact the issuance evidence is the roster at exactly the
  certificate's target generation; a later roster that lists the certificate
  is not accepted in its place.
- First contact cannot see a drop, a revocation or a fork in a roster it is
  not given, and it does not consult supplied rosters of another root, so
  the step from a previous root's last roster after a root rotation is the
  checked path's. Contiguous history at hand is verified step by step with
  `verify_roster`.
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
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo nextest run -p agenc-relay-e2ee --all-features --locked
cargo nextest run -p agenc-relay-runtime --all-features --locked
cargo nextest run -p agenc-relay-testkit -p agenc-relay-storage -p agenc-relay-server --all-features --locked
cargo nextest run --workspace --all-features --locked
python3 scripts/check-source.py check
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
```

Each passes at the branch tip. The per-commit results and the runs with
each correction removed are in the commit messages. The storage `disk`
profile was not run: the host was not quiet.
