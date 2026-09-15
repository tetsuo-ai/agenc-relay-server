# Leaf-membership admission

This record closes ENC-05 (issue #52): Commit and ReInit admission and every
ACK are bound to authenticated old and continuing MLS leaves through the
companion 13.7.3 leaf-membership proof. It adds the registered
`leaf_membership_proof` wire kind (37), the `EGROUP SUBMIT MEMBERSHIP`
command (`submit_membership`, federation opcode 44, `store_membership` 11),
the `IRC-MLS/1 leaf membership` and `IRC-MLS/1 leaf membership possession`
signature labels, the `leaf_membership_id` semantic hash, and one sequencer
storage row (`membership/v1/`). All of these were already fixed by the
companion; no profile hash, registry, or specification text changes. Earlier
development storage images without the row simply restore no proofs.

## Proof admission

`agenc_ircd_e2ee::membership::verify_leaf_membership_proof` checks a proof
against the root and the exact roster it names: profile, network,
conversation, account, root generation and fingerprint, roster generation and
ID, credential generation zero, the Ed25519 leaf scheme, and a leaf index
below `MAX_GROUP_LEAVES`. The device signature must verify under the device
certificate in that roster (a device absent from the roster is
`E2EE_DEVICE_REQUIRED`); a `continuing` proof needs the old leaf's possession
signature and an all-zero removal ID, and a `removed` proof needs an empty
possession field and a nonzero removal ID.

The coordinator's `submit_membership` admits a proof only from the attached,
roster-active device the proof names, on an account that is a principal of
the conversation's binding, verified against that account's current retained
root and roster. It then applies the conversation rules:

- a `removed` proof must name a retained finalization (a terminal whose
  retained request is a `finalization_request`);
- a proof naming an epoch the conversation has not reached is
  `E2EE_EPOCH_STALE`;
- `LeafMembershipSet::admit` returns the same `STORED MEMBERSHIP` reply
  without any write for a byte-identical resubmission, refuses a proof for a
  retained leaf from another device, a differing proof at the same or an
  earlier epoch, and a second `continuing` leaf of one device at one epoch
  with `E2EE_OPERATION_CONFLICT`, and replaces a leaf's proof only by the
  same device at a higher epoch;
- a conversation retains at most `MAX_RETAINED_LEAF_MEMBERSHIPS` (two per
  possible leaf) proofs; a new leaf beyond that is `E2EE_RATE_LIMITED`.

The object and its row are staged in the same batch before the proof is
used; the retained set changes only on commit. `EGROUP FETCH OBJECT` returns
a proof only under the conversation it names and only to an account that is
a principal of that binding.

## ACK signer identification

`LeafMembershipSet::identify` finds the stored `continuing` proof whose leaf
index and old credential hash equal the ACK's and whose epoch is not later
than the ACK's prior epoch (the old group's accepted epoch for a ReInit ACK),
and verifies `old_leaf_signature` under that proof's public key with the
registered `IRC-MLS/1 commit processed` or `IRC-MLS/1 reinit processed`
label. The coordinator additionally requires the proof's device to be
roster-active now. An unidentified, revoked, or wrongly signed ACK is
`E2EE_BINDING_AUTH_INVALID` and consumes no state.

- A standalone Commit or ReInit ACK is admitted only from the attached device
  its proof names. A byte-identical resubmission repeats the same result; a
  different ACK for an acknowledged leaf, or a second leaf's ACK by the same
  device for one candidate or attempt, is `E2EE_OPERATION_CONFLICT`.
- Every ACK a finalization request embeds is identified the same way, and no
  device may sign two of them.
- A ReInit ACK's role must name its signer's own KeyPackage plan entry: the
  creator entry for `creator_state`, the entry holding the reserved ref for
  `welcome_join`.

The context checks that CAP-99 added still run first, so their reply codes
are unchanged.

## ReInit submitter roles and coverage

- An attempt or attempt abort comes only from an old-group device: the
  attached device holds a proof in the expected continuing set.
- An activation comes only from a continuing old-group device: such a device
  that the attempt's KeyPackage plan carries into the successor.
- An activation's embedded ACKs must cover the attempt exactly: every ACK is
  identified by a distinct device, names that device's own plan entry,
  exactly one ACK exists per plan entry, and every stored continuing proof in
  the expected set has a proof-backed ACK (otherwise the missing continuing
  leaf is `E2EE_BINDING_AUTH_INVALID`).

The expected continuing set is every stored `continuing` proof whose device
is still roster-active. A leaf is removed from it by the same device's
`removed` proof at a higher epoch, which replaces the continuing proof; a
revoked device's proof no longer counts, following "a proof ... from a
revoked device is refused". All role checks run before any sequencer signer
access. The exact continuing set, copath coverage, and removal outcomes remain
endpoint MLS checks; the server check is a filter.

## Reconstruction

Startup restores each `membership/v1/` row by re-verifying its retained
object against the retained root and the exact roster snapshot it names, so
a later roster or root rotation keeps an accepted proof. A row whose object
is missing, whose facts disagree with its key, or whose removal no longer
names a retained finalization restores nothing. ACK signers are rebuilt from
the retained ACK objects through the restored proofs, so duplicate-leaf and
duplicate-signer refusals survive a restart. Device activity is checked again
at every use.

## Historical verification

`RecordReferences::memberships` passes the same validated
`LeafMembershipSet` into `HistoricalChain::advance`. When present, every ACK a
finalization embeds is identified at its prior epoch, every ReInit ACK of an
activation at the old group's accepted epoch, no device signs twice, and each
ReInit ACK names its signer's plan entry. When absent, ACK signatures remain
the endpoint's check as before. No MLS processing is introduced.

## Open specification questions

Issue #111 records four normative gaps this implementation had to take a
position on: a leaf removed in the epoch its proof names cannot be marked
removed under the replacement rule; any principal device can publish an
unverifiable continuing proof that blocks ReInit activation until revoked;
future-epoch proofs are refused with `E2EE_EPOCH_STALE`, which the failure
table does not list; and revoked devices are excluded from the expected set.

## Evidence

- `crates/agenc-ircd-e2ee/src/tests/membership.rs`: replacement, duplicate
  and conflicting leaves, the quota at exactly 1,024 retained proofs, signer
  lookup by leaf, credential, disposition, and epoch, the expected set, every
  verifier refusal (foreign roster, leaf beyond the group, short account or
  leaf key, invalid leaf point, disposition shape, inactive device, device and
  possession signatures), and one signing device per ACK set.
- `crates/agenc-ircd-e2ee/tests/membership_vectors.rs`: the proofs
  `scripts/generate-e2ee-vectors.py` encodes independently decode, verify
  under the generator's root and roster, and recompute their object and
  leaf-membership IDs; the revoked-device, duplicate-leaf, and
  ACK-without-membership vectors are refused for their stated reasons.
- `crates/agenc-ircd-e2ee/tests/history/membership.rs`: supplied facts refuse
  a finalization with no proof, another leaf key, or another credential, and
  an activation with an omitted joiner proof or a joiner leaf held by another
  device, then accept the exact facts.
- `crates/agenc-ircd-runtime/src/e2ee/coordinator/tests/sequence/leaf_membership.rs`
  and its `finalization` and `restart` modules: proof replacement, conflicts,
  and every refusal of a foreign device, signature, roster, root, conversation,
  scheme, removal, or kind; the standalone Commit ACK matrix (unsigned,
  incorrect label, another leaf's valid signature, wrong index, wrong
  credential, another device's leaf) with the absent-signer control;
  duplicate leaf and duplicate signer; embedded ACKs in finalizations,
  including a removal Commit processed by the continuing leaf alone; a
  revoked device, including its ACK submitted from another attached device;
  fetch scope (a proof reads only under its own conversation and only for a
  binding principal); another account's proof on this device; and proofs and
  ACK signers after a logical reload, a roster rotation, a removed proof, rows
  that disagree with their proof or name a non-proof object, a row admission
  would have refused, a proof that no longer verifies, a removal naming no
  retained finalization, a missing proof or ACK object, and a real storage
  shutdown and reopen.
- `crates/agenc-ircd-runtime/src/e2ee/coordinator/tests/sequence/reinit/leaf_membership.rs`
  and its `maximum` module: a nonmember device of an approved account cannot
  attempt, activate, or abort with the signer present or absent while the
  proven device succeeds; activation by the creator and by a continuing
  joiner; an excluded leaf and an omitted continuing leaf; a plan entry
  without its ACK; an ACK naming another member's plan entry; the standalone and embedded ReInit ACK matrix (unsigned,
  incorrect label, another leaf, wrong index, creator disposition from a
  joiner, a joined disposition naming the creator's ref, duplicate leaf,
  omitted continuing leaf); same-device different-leaf and duplicate signer;
  a removed leaf shrinking the set; a revoked joiner; and the maximum shape of
  one account with all 64 active devices continuing, where one missing ACK is
  refused and the exact 64-ACK set activates under a 33-of-64 quorum.
- `crates/agenc-ircd/tests/stage_eight_e2ee.rs`: through the real daemon, an
  unproven Commit ACK is `E2EE_BINDING_AUTH_INVALID`, `EGROUP SUBMIT
  MEMBERSHIP` answers `STORED MEMBERSHIP` with the recomputed IDs, and the
  bootstrap and later finalizations embed ACKs signed by the proven leaf.

Eight release critical regions cover the verifier, the retained set and
planned-device rule, the coordinator's submission, read scope, and signer
identification, reconstruction, and historical ACK authentication; each
measures branches, and a branch-instrumented coverage run over the owning
crates reaches every branch outcome in all eight.

The runtime fixtures use synthetic MLS bodies and public-envelope ACKs; the
proof, ACK, and council signatures are real. Real MLS endpoint evidence for
the continuing set remains outside the server's claim.
