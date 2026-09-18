# Leaf-membership proofs are verified against the roster they name

This record closes ENC-18 (issue #164), the remediation of finding `ENC11-1`
from the 2026-09-18 internal review of the encrypted-messaging profile. That
review was internal: it was performed by a reviewer that had no context from
the implementation and no stake in it, and it is **not** a third-party audit.
It does not close the external review task `S08-039`.

## Finding

Companion 13.7.3 says a leaf-membership proof's account, device, root, roster
and credential generation fields "equal the leaf authorization of that
credential", and that "the proof's device must be active in the retained
roster named by `roster_id` at the record's validation time". A continuing
leaf keeps its credential across in-group updates (companion 8.5), and every
Add or revocation Commit carries a roster proposal (companion 9.3), so the
roster a proof names stops being the account's current roster at the first
rotation.

`ops/membership.rs::verify` took the root and roster from
`state.principals`, the account's **current** heads, and
`verify_leaf_membership_proof` requires the proof to name exactly the root and
roster it is given. Startup reconstruction (`membership_restore::restore`)
did the opposite and correct thing: it finds the retained snapshot the proof
names by `(root fingerprint, root generation, roster_id)`. The two paths
therefore decided differently on the same bytes: a proof naming a retained
predecessor roster was refused live with `E2EE_BINDING_AUTH_INVALID` and
accepted on a reload. A client following 13.7.3 literally could not publish a
proof after a routine rotation, and because ACK signers are identified only
through stored proofs, its ACKs could not be identified either. The live path
was stricter, never more permissive, so this was a specification divergence
with an availability edge, not an authority break.

## Change

- `crates/agenc-ircd-runtime/src/e2ee/coordinator/roster_snapshots.rs` (new)
  keeps `CompanionState::roster_snapshots`, an index from roster identifier
  to the retained `device_roster` object, and `resolve`, which returns the
  root and roster a statement names for one account. A statement naming the
  account's current heads resolves to them with no extra work. Otherwise the
  root is the current root or, for an earlier root generation, the matching
  root of the account's re-verified chain (`startup::principal_roots`, the
  function reconstruction uses), and the roster is the indexed object
  re-verified with `restore_roster` under that root, exactly as
  reconstruction verifies its snapshots. A roster that was never retained,
  that another account's root signed, or that does not re-verify resolves
  nothing.
- The index is written with the commit of `EKEY PUBLISH ROSTER`
  (`ops/directory.rs::publish_roster`) and rebuilt at startup from the
  resident objects at the end of `restore_directory`.
- `ops/membership.rs::verify` resolves the named snapshot under a transient
  backing reservation and verifies the proof against it. An unresolvable
  name is the 13.7.3 "roster or root mismatch" row,
  `E2EE_BINDING_AUTH_INVALID`; a device that was not active in the named
  roster stays `E2EE_DEVICE_REQUIRED`. `verify_leaf_membership_proof` is
  unchanged.
- Current roster activity is the separate check the finding asked for, and it
  was already present: `submit_membership` begins with
  `Exec::attached_device`, which requires the attached device to be active in
  the directory's current roster, and `verify` requires the proof's device to
  be that attached device. That is the same directory predicate
  `ops/ack_context.rs::device_active` applies when an ACK is identified. A
  second explicit call in `verify` would be unreachable, so none was added;
  the doc comment states where the check lives.

## The `removed` proof

13.7.3 can be read two ways for a `removed` proof. One reading lets a revoked
device, or someone on its behalf, state `removed` for the leaf the revocation
Commit took away. The other applies the same two device rules to both
dispositions. This change takes the **second** reading:

- 13.7.3 states the fields and the device signature "in both dispositions",
  and states the roster rule for "a proof" without distinguishing them.
- Its failure table answers an "unattached or revoked device" with
  `E2EE_DEVICE_REQUIRED`, and companion 11.6 requires every companion
  mutation to come from an attached device that is active in the highest
  accepted roster. A revoked device can therefore submit nothing.
- Nothing is lost: the same section says a stored proof whose device is no
  longer roster-active "states no expectation" and "leaves the expected
  continuing set when the device is revoked". Revocation already does what a
  `removed` proof from that device would do.

So a `removed` proof is for a device that is still roster-active and whose
leaf is gone: a PART or KICK, a remove-and-re-add that rotates the leaf key,
or a rejoin after state loss. That device's credential usually predates the
current roster, which is exactly the case the old code refused. It is now
admitted under the predecessor roster it names, and a revoked device's
`removed` proof is refused with `E2EE_DEVICE_REQUIRED` while its claim is
already outside the expected set. The review's side remark that a removed
device "can never" state `removed` described the revoked case, which is the
specified behaviour, and missed the roster-active case, which was the defect.

## Tests

`crates/agenc-ircd-runtime/src/e2ee/coordinator/tests/sequence/leaf_membership/named_roster.rs`:

| Test | What it pins |
| --- | --- |
| `a_conforming_proof_naming_a_predecessor_roster_is_admitted` | After a rotation that keeps the device, its first proof naming roster generation zero is stored. |
| `a_proof_naming_a_predecessor_root_is_admitted_and_survives_a_reload` | After a continuous root rotation the proof names the generation-zero root and roster, is stored, and reloads identically; a root the account never held resolves nothing. |
| `a_proof_naming_a_roster_that_was_never_retained_is_refused` | A root-signed but unpublished roster is `E2EE_BINDING_AUTH_INVALID` with no state change; once published, the same bytes are admitted. |
| `a_proof_naming_another_accounts_retained_roster_is_refused` | A retained, indexed roster of another account does not re-verify under this account's root. |
| `a_proof_naming_a_retained_roster_without_its_device_is_refused` | A device active now and in generation zero, but not in the retained generation one it names, is `E2EE_DEVICE_REQUIRED`. |
| `a_roster_active_device_states_removed_under_its_predecessor_roster` | The `removed` decision, positive half: admitted, and the device leaves the expected set. |
| `a_revoked_device_states_no_removed_proof_and_is_not_expected` | The `removed` decision, negative half: `E2EE_DEVICE_REQUIRED`, no state change, and the claim is already outside the expected set. |
| `live_admission_and_reconstruction_agree_on_the_named_roster` | The stored set reloads identically; rows injected for the two proofs live admission refused restore nothing; a reloaded coordinator refuses and admits the same inputs. |

With `verify` reverted to the merged source, four of these fail
(`BindingAuthInvalid` where the proof must be stored or where
`DeviceRequired` is specified) and the rest pass; with the change all eight
pass.

The review's demonstrating test was corrected before it was kept. As
committed by the review it submitted a second continuing leaf for a device
that already held one at the same epoch, which 13.7.3 refuses as a duplicate
continuing leaf whatever roster is named; on the unfixed tree the roster
refusal came first and hid that. The kept test has the second device publish
its own first proof, fails on the unfixed `verify` for the reason the finding
states, and passes now. `inject`, `memberships_of` and `conversation_of` in
the sibling `restart` test module became `pub(super)` so the agreement test
reuses them.

## Policy bindings

The release region `coordinator-membership-submission` names
`submit_membership` and its reviewed text included `verify`, which this
change rewrote, so `reanchor.py` could not relocate it and it was set by hand
onto the same items; its reason now states the named-snapshot rule and the
span was re-reviewed: no conditional was added to it. A new release region,
`coordinator-roster-snapshot-resolution`, covers `roster_snapshots::resolve`
with the branch metric; the tests above take both outcomes of its two
conditionals. `conformance/review/findings.md` carries the finding and this
disposition.

## Limitations

- A roster object that becomes resident by any path other than
  `EKEY PUBLISH ROSTER` joins the index at the next startup. Until then a
  proof naming it is refused as never retained, which is the conservative
  direction; the only such path today is a recovery reference element, on a
  route whose `pending` gate refuses `SUBMIT MEMBERSHIP` anyway.
- A predecessor name costs one roster re-verification (one root signature
  and three per active device, at most 193) and, for an earlier root
  generation, the account's root chain. The work runs under a fixed transient
  reservation and the existing per-origin admission; verified predecessors
  are not cached.
- The server still cannot tell whether the roster a proof names is the one
  the leaf was really authorized under; that needs the leaf authorization
  and stays an endpoint check, as 13.7.2 assigns it.
- Fixtures use synthetic MLS bodies with real proof, roster and root
  signatures. The implementation gate was not run on this branch.

## Evidence

Commands at this branch (from the repository root):

```sh
cargo test -p agenc-ircd-runtime --all-features --locked
cargo test -p agenc-ircd-e2ee --all-features --locked
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo fmt --all
python3 scripts/check-source.py check
python3 /mnt/data/agenc-dev/tools/reanchor.py /mnt/data/agenc-dev/wt/wt60 origin/main
python3 /mnt/data/agenc-dev/tools/verify-regions.py /mnt/data/agenc-dev/wt/wt60
bash /mnt/data/agenc-dev/tools/static-checks.sh /mnt/data/agenc-dev/wt/wt60
```
