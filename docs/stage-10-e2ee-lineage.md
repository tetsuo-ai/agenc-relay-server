# Roster liveness and root-scoped directory lineage (B-15, B-16)

This record covers the server topic `sdk/b-e2ee-lineage` of the SDK server
program (items B-15 and B-16, 2026-10-09, outside master #35). The first
commit checks the roots and rosters a historical finalization uses against
the Commit's canonical validation time, with the narrow roster recovery of
companion Section 8.4. The second starts an account's roster and capability
lineages at generation zero under each root, keeps the account's roster
while a new root awaits its first roster, live and after a restart alike,
and keeps attachment counters in their account and device scope. The third
restores each capability head against the roster it names, so its lineage
survives a restart after a roster renewal, keeps that roster retained while
a head names it, and lists only statements naming the current roster as
current. The fourth restores stores written before these rules (G-08). No
specification, profile hash, registry entry, named limit, reply code, wire
object, table, key, row kind, field or storage generation changed.

## A finalization's roots and rosters are checked per use (first commit)

The companion text this rule implements:

- Section 8.2: "a root used for a candidate must cover its canonical
  validation time".
- Section 8.3: "Every later use checks the certificate and roster intervals
  against the candidate's canonical validation time."
- Section 8.4: "An expired roster cannot authorize an Add, policy approval,
  binding, or new ordinary Commit ACK. There is one narrow recovery
  exception: an old leaf whose certificate is named in the expired roster
  may authenticate a `roster_recovery` candidate only when that candidate (a)
  installs a continuous unexpired successor roster in the committed context,
  (b) changes no policy, binding, suite, sequencer, or membership except
  removing devices absent from that successor, (c) performs no Add, and (d)
  includes a populated UpdatePath. The old leaf is checked against both the
  expired predecessor and the resulting successor; a removed target may
  authenticate only the public removal path. Every other authorization check
  uses the resulting unexpired roster." Within that candidate "the unchanged
  old leaf may produce a processing ACK and the old policy's unchanged
  finality device may produce a disposition vote".
- Section 9.3: "`roster_recovery` has a roster proposal and only the Removes
  required by that successor", and "A `roster_recovery` uses the narrow
  root-signed successor rule in Section 8.4 and the finality quorum; expired
  controller credentials do not gain general approval authority." A Commit
  with Adds for an account "carries that exact full roster once", and
  "Every roster reaffirmation or update is accompanied by an inline
  GroupContextExtensions proposal whose resulting `ArcMlsContext.roster_heads`
  names the exact roster generation and ID".
- Section 12.4: "The quorum `q` is still derived from the complete old
  council. [...] The expired-roster recovery path obeys the same rule."
- Section 13.7.2: a policy transition is authorized by "the retained
  finalized policy chain head and the roster heads at the record's
  validation time", and a root continuity transition is proved by "the
  successor `root_identity` in the account root chain and the finalized
  record" and authorized by "the previous root's continuity signature over
  the successor".

The rule, in `crates/agenc-relay-e2ee/src/history/liveness.rs`, which
`HistoricalChain::adopt_finalization` applies once the record's transitions
are installed, and in the transitions themselves
(`crates/agenc-relay-e2ee/src/history/finalization.rs`):

- The sequencer credential committed for the position covers the time, as
  before, and is checked first.
- A record installs at most one root continuation and one roster per
  account (`repeats_installed`): the roster it installs is the exact
  successor its context head names, so a second, different root or roster
  of an account is refused, even when it continues the first, and an exact
  repeat of one, as when two submitters supply the same reference element,
  is installed once. The rule is per account: one record may carry a root
  continuation and a roster for each of several accounts.
- Every root and roster the record installs, or carries as a reaffirmation,
  covers the time: a transition never installs an expired root or roster,
  and never reaches a live roster through an expired one.
- A finalization uses the principals whose devices approve its
  authorization, vote on it, or sign an ACK that the caller's
  leaf-membership facts identify (`history::membership` returns those
  signers), and every principal when it changes the policy or the binding.
  Each principal it uses held, before the record, a root and roster that
  cover the time. A principal that signs nothing in the record is not used
  by it, so its expired roster does not block the record, as for a group
  that removes or renews a stale account.
- A principal whose roster expired is admitted only within the recovery
  exception: the record is labelled `roster_recovery`, which the
  authorization's shape check holds to the roster bit and the Removes its
  successor requires, and continues no root; the principal approves
  nothing; it now holds a roster that covers the time under a root that
  does, which only a roster this record installed can be, and which the
  transition holds to the next generation naming the expired one; and every
  device of it that voted or acknowledged is unchanged in that roster, so a
  device the successor drops cannot vote for its own removal.
- The quorum is counted from the complete old council, as before; an
  expired principal's vote counts only inside the exception.

Endpoint-only, as before: which leaf committed the candidate, and the
Removes and UpdatePath inside the encrypted Commit.

A coordinator restored as `pending` adopts records through this chain
(companion 13.7.4), so it adopts such a recovery as the live coordinator,
which checks no roster time when it finalizes, accepted it. A device whose
account is no binding principal, such as a channel member outside the
controller and authority roots, holds no roster in the chain; when the
caller's facts identify it as an ACK signer, its roster's time is the
caller's check, as is its device activity (companion 13.7.3).

A coordinator restored as `pending` takes, for a record, every reference
element retained at the record's position (companion 13.7.4). With one
roster per account, a second, different roster of an account that an
authorized submitter supplies there makes the record unadoptable, where it
would have moved the restored chain past the roster the record committed;
keying reference elements by account at submission is left to a later
recovery-submission change.

### Readings recorded for the owner

- The approval vector of a `roster_recovery`. Section 9.3 gives a
  `roster_recovery` "the narrow root-signed successor rule in Section 8.4
  and the finality quorum" beside the rules that "use the old policy's
  controller threshold", and says that "expired controller credentials do
  not gain general approval authority"; it also says that an
  authorization's "approval vector may be empty only for
  `routine_self_update`, `open_visible_add`, and `join_confirmation`", and
  that an `open_visible` policy uses its threshold for "recovery
  decisions". `needs_controller_approval` keeps a `roster_recovery` free of
  the controller threshold, as at the start commit, so the recovery of a
  lapsed principal finalizes with an empty approval vector; approvals it
  does carry are verified, and a principal that approves must hold a root
  and roster that cover the time. Requiring the old policy's threshold
  from such controllers would leave the Section 8.4 recovery unreachable
  wherever that threshold needs the lapsed account, as in a conversation of
  one account or a `fixed_direct` pair, and would refuse every
  `roster_recovery` without approvals, which the start commit already
  accepted from a live predecessor; the live coordinator verifies no
  authorization approvals when it finalizes, so only historical-chain
  consumers would see the change. This topic keeps the start commit's
  reading, and the owner is asked which reading holds.
- Root continuations in one record. A record continues an account's root
  at most once, as Section 13.7.2 proves a root continuity transition by
  "the successor `root_identity`", so every root it installs is the one its
  time check sees. An account that rotated its root twice since a
  conversation's last head moves that head one continuation per record,
  each with its first roster, or through the ReInit that Section 8.2 has a
  continuous root rotation use. Whether one record may instead carry a
  chain of continuations, each covering its time, is asked of the owner.

### Tests

`crates/agenc-relay-e2ee/tests/history/roster_recovery.rs`, with real
signatures, a bootstrap at time 150 and every later record at 300,000:

| Test | What it pins |
| --- | --- |
| `an_expired_predecessor_recovers_through_its_continuous_successor` | A roster ending at the record's time (still live) and one ending a second before it (expired) are both recovered by the second principal's continuous successor, its device voting under the exception. |
| `a_recovery_removes_the_devices_its_successor_drops` | The Remove variant (`ROSTER` and `REMOVE_LEAF`) finalizes with the device the successor keeps voting; a vote from the device it drops is refused. |
| `a_recovery_admits_no_other_shape` | Refused: a skipped generation, a successor that expired or is not yet valid, the expired roster reaffirmed, a successor under a continued root, a root continuation beside the recovery, another principal's successor only, an Add (as a controlled transition and labelled `roster_recovery`), the policy bit, the controlled-transition label, an approval from the expired roster, and a reduced quorum; the exact recovery finalizes. |
| `a_lapsed_principal_that_signs_nothing_does_not_block_a_finalization` | With one principal's roster expired, a routine update and a controlled removal that it does not sign finalize; its vote outside the exception is refused; a policy transition is refused while it is expired and finalizes while it is live. |
| `an_identified_acknowledgement_uses_its_signers_roster` | With the creator's roster expired and the other principal's devices reaching the quorum, the record finalizes without leaf-membership facts and is refused when the facts identify the creator's leaf as the ACK signer. |
| `a_finalization_never_installs_a_roster_that_does_not_cover_its_time` | With both principals live, a successor that expired is refused in a recovery and in a controlled transition; one opening exactly at the time is installed. |
| `an_acknowledgement_from_outside_the_binding_principals_is_the_callers_check` | Facts that name a device of a non-principal account, whose roster expired, as the ACK signer leave a routine record finalizing. |
| `a_record_installs_one_roster_per_account` | A recovery carrying two successive rosters of the lapsed principal, or an expired roster and its live successor, is refused, as is a live principal's controlled transition through an expired roster to its live successor; in either order the current roster beside a successor is refused, as is a different roster after or between repeats of one; the same roster, or the current roster, supplied twice is installed and reported once. |
| `a_record_continues_an_accounts_root_once` | A controlled transition continuing the second principal's root installs the root and its generation-zero roster; one carrying a second continuation of that root is refused, and the same root supplied twice is installed and reported once. |
| `a_record_installs_one_roster_for_each_of_two_accounts` | A controlled transition carrying the creator's same-root renewal and the second principal's successor installs both, with one head for each account, also when the creator's roster is repeated around the other's. |
| `a_record_continues_the_roots_of_two_accounts` | A controlled transition continuing both principals' roots, each with its generation-zero roster, installs one root and one roster for each account. |
| `a_finalization_never_installs_a_root_that_does_not_cover_its_time` | A continued root opening one second after the record's time is refused although its first roster covers the time; one opening exactly at the time is installed. |
| `a_recovery_refuses_a_vote_from_a_device_whose_certificate_its_successor_replaces` | A successor that reissues the voting device with a new certificate is installed by a controlled transition the lapsed principal does not sign, and the recovery in which that device votes under its replaced certificate is refused. |
| `a_recovery_admits_an_acknowledgement_only_from_a_device_its_successor_keeps` | The lapsed principal's device that the successor keeps may sign the recovery's identified ACK, and the same ACK in a routine record is refused; an identified ACK from the device the successor drops is refused, and the record finalizes without it. |

`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/recovery_submission/expired_roster.rs`
drives the coordinator: a live coordinator finalizes a `roster_recovery` at a
time after its principal's roster ended, and a coordinator restored as
`pending` from the genesis adopts its records through `SUBMIT RECOVERY`:

| Test | What it pins |
| --- | --- |
| `a_pending_route_adopts_a_roster_recovery_from_an_expired_predecessor` | With the successor roster as the record's reference element, the recovery's finalization is adopted at its route sequence, and a restart replays it. |
| `a_pending_route_refuses_a_roster_recovery_whose_successor_has_expired` | With a continuous successor that ends before the record's time, the finalization is refused with `E2EE_BINDING_AUTH_INVALID` and the head stays at the candidate. |
| `a_pending_route_refuses_a_recovery_whose_references_carry_two_rosters_of_its_principal` | With the successor and the next roster naming it, each covering the record's time, as reference elements that the chain takes in that order, the finalization is refused with `E2EE_BINDING_AUTH_INVALID` and the head stays at the candidate. |

## Roster and capability lineages start at each root (second commit)

The companion text this rule implements:

- Section 14: "All state-advancing profile generation and sequence counters
  have one exact scope and advancement rule": `roster_generation` is scoped
  to the "root fingerprint" and `capability_generation` to the "root
  fingerprint and Device ID", each starting at 0 and advancing by "exactly
  +1", while `device_session_generation` is scoped to the "Account ID and
  Device ID".
- Section 8.2: "A continuous root rotation issues a new complete roster and
  new device certificates under the new root".
- Section 8.4: "Clients persist the highest generation and ID per root. [...]
  Roster generation zero uses an all-zero predecessor; every successor
  increments by one and names the previous accepted ID", and "Revocation
  entries are append-only within a root generation".
- Section 8.5: "Generation zero has an all-zero predecessor. Every successor
  increments by one, names the previously accepted ID".
- Section 11.6: "`session_generation` is a durable nonzero uint64 counter
  scoped to the Account ID and Device ID. [...] it never wraps or reuses a
  value after restart".

The rule:

- The shared verifiers scope a lineage to its root
  (`crates/agenc-relay-e2ee/src/identity.rs`): `roster_predecessor` selects
  the predecessor a roster continues, the account's accepted roster when the
  same root signed it and none otherwise, and `capability_predecessor` the
  predecessor a capability statement continues, the device's accepted
  statement when it belongs to the root of the roster the new statement
  names. `verify_roster` and `verify_capabilities` refuse a predecessor of
  another root, and `VerifiedCapabilities` carries the root fingerprint of
  its lineage. The historical chain's roster transition selects its
  predecessor through `roster_predecessor`.
- The directory (`Directory::publish_roster` in the domain crate) admits a
  root's first roster at generation zero and each later roster of that root
  at its head plus one, under the newest root only. A root's first roster
  keeps no capability head of an earlier root; a later roster keeps the
  heads of the devices it keeps. Attachment counters outlive every roster.
- `EKEY PUBLISH IDENTITY` continues the account's newest root, the one that
  awaits its first roster or else the root of its current roster
  (`newest_root`), and leaves the new root awaiting its first roster.
  `EKEY PUBLISH ROSTER` verifies a roster under the newest root against the
  head of that root only, and its batch deletes the capability row of every
  head the directory drops, of a device that left the roster or of an
  earlier root, so storage holds exactly the heads the directory keeps.
  `EKEY PUBLISH CAPABILITIES` continues only the head of the root of the
  roster the statement names.
- Startup re-verifies the account's root chain and keeps every root of it,
  restores the current roster under the root of the chain that signed it,
  and leaves a newer root awaiting its first roster
  (`restore_identity`, `restore_roster_row`, `pend_newest_root`).

Between a root's publication and its first roster, the specification does
not say which roster governs. The account keeps its current roster, root,
devices, attachments and capability heads: that roster is still the
highest accepted roster in which its devices are active (Sections 8.4 and
11.6), its certificates keep their intervals under a root whose interval
the new root's `not_before` lies in (Section 8.2), and only a roster under
the new root can follow it, at generation zero. The alternative, no
active device until the new roster, would stop every encrypted operation
of the account between two publications that the root holder makes in
sequence. A restart rebuilds the same state from the identity and roster
rows, so live publication and a restart admit and refuse alike, and a
crash between the root's and the roster's publication, or between the
roster's and the capabilities', leaves a state from which the next
publication proceeds.

### Tests

`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/root_lineage.rs`
publishes through the directory handlers into the harness's store; a
restart rebuilds the coordinator from every stored row and must hold the
live state and answer `FETCH IDENTITY`, `ROOT-CHAIN`, `ROSTER` and
`CAPABILITIES` alike:

| Test | What it pins |
| --- | --- |
| `a_rotated_root_starts_its_roster_and_capability_lineages_at_zero` | Under a continued root, a roster continuing the old root's counter and a roster under the old root are refused; the new root's generation-zero roster is stored and its batch deletes the old root's capability head from memory and storage; the device's capability counter continued under the new root is refused and its generation-zero statement stored; the next roster and statement of the new root advance by one; a restart holds the same state. |
| `a_restart_at_each_step_of_a_rotation_rebuilds_the_live_state` | After the root, the first roster, the first capability statement and the next statement, a restart holds the live state, refuses the old root's counters continued under the new root as the live coordinator does, and stores the next step. |
| `while_the_new_root_awaits_its_roster_the_account_keeps_its_devices` | Between a root and its first roster the account keeps its roster and capability heads, with the new root pending; live and after a restart, the device continues its statement under that roster and attaches again. |
| `a_same_root_successor_advances_by_exactly_one` | Live and after a restart, a roster reset, a skipped roster generation and a capability reset, gap and fork are refused, and the exact successors are stored. |
| `a_device_leaving_the_roster_leaves_no_capability_head` | A same-root roster that revokes a device deletes that device's capability row in its batch and keeps the remaining device's head. |
| `attachment_counters_outlive_a_rotation` | A device the new root's first roster leaves out keeps its attachment counter, so its enrollment under the new root continues it, live and after a restart. |
| `a_root_continues_the_root_that_awaits_its_first_roster` | Before any roster, the next root continues the pending root and a second successor of the first root is refused, live and after a restart. |
| `a_root_recovery_rotates_again_from_the_root_that_awaits_its_roster` | With a continued root still awaiting its roster after a restart, a further continuous rotation is stored, a roster of the abandoned root is refused, and the recovered root's lineages start at zero, live and after the restart alike. |

Also: `startup::directory_tests::a_roster_restores_under_the_root_that_signed_it_beside_a_newer_pending_root`
(the rows of an account whose newest root awaits its roster restore the
roster under the earlier root and leave the newest pending);
`tests::identity::roster_and_capability_lineages_are_scoped_to_their_root`
in the e2ee crate (both selection helpers, and both verifiers refusing a
counter continued across roots even with the old head offered as
predecessor); and, in the domain crate,
`a_rotated_root_starts_its_roster_and_capability_lineages` (generation zero
under the new root, no earlier head, attachment counters kept),
`a_roster_burns_only_its_own_accounts_packages`, and
`heads_advance_by_one_and_bind_to_each_other`, which now pins the active
device limit under a new root at generation zero.

Five coordinator tests that rotate the account's root now issue the new
root's first roster at generation zero with an all-zero predecessor and
certificates enrolled for it: `reload_preserves_published_policies_after_root_rotation`,
`named_roster::a_proof_naming_a_predecessor_root_is_admitted_and_survives_a_reload`,
`named_roster::a_proof_naming_a_retained_roster_without_its_device_is_refused`,
`named_roster::live_admission_and_reconstruction_agree_on_the_named_roster`
and `reinit::successor::expiry::an_installed_successor_restarts_after_its_principal_rotates_the_account_root`.

## A capability head keeps its lineage across a roster renewal (third commit)

The companion text this rule implements:

- Section 8.5: "A capability object is valid only for the same highest
  roster in which the signing device is active. [...] Generation zero has
  an all-zero predecessor. Every successor increments by one, names the
  previously accepted ID, [...]. Clients durably pin the highest generation
  and ID per device; rollback, a gap, or two IDs at one generation is a
  security error."
- Section 14: `capability_generation` is scoped to the root fingerprint and
  Device ID, so a renewal of the roster under the same root continues it.
- Section 11.6: "`FETCH CAPABILITIES` pages the exact current-roster device
  set in canonical Device-ID order under one immutable snapshot. Every
  active device appears exactly once, no inactive device appears, and each
  returned capability object is the highest accepted generation for that
  device and named roster", and "The client still authenticates every
  returned object cryptographically."

The rule:

- Startup restores each capability head against the roster it names
  (`restore_capability_row`, `named_roster` in `startup.rs`): the current
  roster, or an earlier roster of the current root that the store retains,
  re-verified under that root, and only for a device the current roster
  keeps active, as live publication holds heads. The head keeps its
  generation and identifier whether or not it names the current roster, so
  the device's next statement continues it after a restart as it does
  live, and a reset, a gap and a fork are refused alike. The roster index
  is rebuilt before the capability rows are restored.
- A current capability page (`Directory::capability_page`, answered by
  `EKEY FETCH CAPABILITIES`) lists the highest statement of each active
  device only when it names the current roster: an object naming an
  earlier roster is not valid for the highest roster (Section 8.5), so a
  device whose head names one is left out until it publishes for the
  current roster, while its head is kept. The page therefore lists every
  active device that has a statement valid for the current roster,
  exactly once; a client still compares the page with the roster.
- A device's capability row holds the roster its head names
  (`owners::hold_capability_rosters`), as a holder not charged to any
  conversation, so the roster a restart re-verifies the head against stays
  resident. An account's roster row owns only its current roster, and a
  replaced roster that nothing else holds is collected once the
  security-proof window (`SEQUENCER_RECORD_RETENTION`, 30 days) has passed
  since the account replaced it ([the binding retention
  record](stage-10-binding-retention.md)); with this rule a replaced roster
  stays held exactly while a head names it. The device's next statement,
  which names the current roster, or the deletion of its row when it
  leaves the roster or its root is replaced, releases the replaced roster
  to object expiry. Startup derives the same holding from each restored
  head (`restored_capability_holders`), so a restart of a store this
  coordinator wrote reconstructs the ownership accounts clean. A roster
  that already lists as many owners as one owner row can reference
  (`MAX_RECORD_REFERENCES`) takes no capability-row holder and the
  publication is admitted, as for route rows: the rows that hold it retain
  it.

This extends the owner matrix of [the object ownership
record](stage-10-object-owners.md), which is left as written: a capability
row owns its statement object and holds the roster its head names. The
module documentation of `roster_snapshots.rs` and `roster_holds.rs` names
the capability row beside the route row as a holder of a replaced roster.

### Tests

| Test | What it pins |
| --- | --- |
| `root_lineage::a_restart_keeps_a_head_that_names_a_superseded_roster` | After a same-root renewal, the head naming the replaced roster is no current statement; a restart holds it, and live and restarted alike refuse a reset and a gap, store the device's next statement, refuse a fork, and list only the new statement. |
| `root_lineage::a_capability_page_lists_only_statements_naming_the_current_roster` | With two devices after a renewal, only the device that published for the current roster is listed, live and after a restart; the other's next statement continues its head and is then listed. |
| `root_lineage::a_device_leaving_the_roster_leaves_no_capability_head` | Now also requires a restart to hold the live state after the revocation. |
| `retention::capabilities::a_capability_head_holds_the_roster_it_names_until_its_device_moves_on` | The roster row and the capability row hold the current roster; after a renewal the capability row alone holds the replaced roster, which object expiry past every window keeps; a restart reconstructs clean and restores the head against it; the device's next statement retires the replaced roster, expiry collects it, and the next restart restores the new head held by both rows. |
| `retention::capabilities::a_device_leaving_the_roster_releases_the_roster_its_head_named` | A renewal that drops a device deletes its row; once the remaining device moves on, the replaced roster is collected and a restart restores only the remaining head. |
| `retention::capabilities::a_capability_row_adds_no_holder_to_a_roster_at_the_reference_ceiling` | A statement naming a roster that as many rows hold as one owner row can reference is admitted, and the roster's owners are unchanged. |
| `startup::directory_tests::a_capability_head_restores_against_the_earlier_roster_it_names` | A head naming the retained earlier roster restores with its generation and identifier and is not on the current page. |
| `startup::directory_tests::a_capability_head_restores_nothing_without_its_named_roster_root_or_device` | A head whose named roster the store no longer holds, of a device the current roster dropped, or of an earlier root restores nothing. |
| `startup::directory_tests::restore_capability_row_refuses_a_row_of_another_directory_kind` | The restore of a capability row given a row of another kind restores nothing. |

The domain test `capabilities_follow_the_roster_and_page_in_device_order`
now requires a renewed roster's page to leave out the device whose head
names the replaced roster, while the head stays for its next statement,
and `a_current_page_lists_no_inactive_device` requires the page of an
entry restored with a head of a device its roster does not keep to leave
that device out.

## Stores written before these rules (G-08, fourth commit)

The decision is additive within storage generation 5 (decision D-06). No
table, key, row kind, field or object layout changes, and startup writes
nothing. What changes is what a restart restores and which holders it
derives: a capability row whose head names a roster the account replaced
under the same root restores against that roster while the store holds it,
an identity row whose newest root awaits its first roster restores that
root pending beside the roster row it follows, and a capability row holds
the roster its head names. Owner rows already reference table-23 rows, and
a capability row is one.

`test-data/stage-ten/e2ee-lineage/` holds four stores that the test harness
of the start commit (`eb2b025`) wrote, with the generator and command in
its README; separate runs wrote identical files. In
`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/retention/earlier_lineage.rs`:

| Test | What it pins |
| --- | --- |
| `every_earlier_lineage_store_restores_from_sealed_storage` | The four stores restore through the storage reads a restart uses. |
| `an_earlier_head_naming_the_replaced_roster_restores_and_holds_it` | After a same-root renewal, the head naming the replaced roster restores with its generation and identifier, and the restart derives that its capability row holds that roster, which object expiry past every window keeps; until a batch next writes the roster's owner row each restart derives the holding again and counts the account as rebuilt. The device's next statement continues the head and a reset is refused; the replaced roster then retires, expiry collects it, and the next restart reconstructs clean. |
| `an_earlier_pending_root_restores_beside_the_roster_it_follows` | The account keeps its roster and the device's head while the continued root awaits its first roster; that root's roster at generation zero is admitted and one continuing the earlier root's counter is refused, and the new roster keeps no head of the earlier root. |
| `an_earlier_rotation_keeps_the_counters_it_was_admitted_with` | A completed rotation whose roster and statement continued the earlier root's counters, as the writing coordinator required, restores under the new root with those heads; the next roster and statement advance by one from them, and a roster reset to generation zero is refused. |
| `an_earlier_head_whose_named_roster_was_collected_restores_nothing` | Once object expiry collected the replaced roster, the head naming it restores nothing, the current page lists no statement, and the device's next statement is admitted at generation zero. |

A rotation that an earlier coordinator admitted with continued counters
keeps them: its roster and statements were verified when they were stored,
their signatures commit to their generations and predecessors, and the
lineage continues from the stored heads by exactly one (Section 14).
Rewriting them, or refusing the account, would leave the account no
admissible next roster.

A head whose named roster an earlier store no longer holds cannot be
re-verified and restores nothing, as at the start commit (see Limitations).

Downgrade: the start commit reads a store these rules wrote, since no
format changed, and applies its own rules from its restart. Run from an
export of the start commit with one test-only module added, on three
stores that this topic's coordinator wrote (a head naming a replaced
roster, a root awaiting its first roster, and a completed rotation), it
restored each through sealed storage and through its harness reload. It
restored no head naming a replaced roster, so the device's continued
statement was refused and a reset admitted, as on its own stores; it
restored a root awaiting its first roster without the account's roster, as
on its own stores; and it continued the rotation's roster and statement
from the stored heads by one. It rebuilt each roster's owner account from
its own derivation and counted it as mismatched, and kept a replaced
roster that only a capability row held as unowned, so nothing collected
it. The operator guide already says not to start release candidate 3 on a
database this release has run on.

## Limitations

- A capability head written before these rules whose named roster object
  expiry already collected restores nothing. The device's next statement
  must then be a generation-zero statement for the current roster, which a
  client that pinned the earlier head refuses as a second identifier at
  one generation (Section 8.5), until the account's next root rotation
  starts new lineages. A head this topic's coordinator writes keeps its
  named roster resident, so the case arises only in a store written before
  these rules in which a device did not republish within the
  security-proof window after a roster renewal. Restoring such a head's
  generation and identifier from its row without re-verifying the
  statement, or re-verifying it under the device's continuing certificate
  in the current roster, would keep the counter; neither is done, since
  every restored head is re-verified, and the choice is recorded for the
  owner.
- A store written before these rules can hold the capability row of a
  device its current roster does not keep, or of an earlier root's
  lineage. Startup restores no head from such a row and writes nothing, so
  the row and the statement object it owns stay until the device's next
  statement under the account's current root replaces the row.
- Between a root's publication and its first roster the account keeps its
  current roster, devices, attachments and capability heads; the
  specification leaves that state open, and the reasons for this choice
  are in the second commit's section.
- The historical chain checks the roots and rosters of the binding
  principals a finalization uses. An identified ACK signer outside the
  binding principals holds no roster in the chain, and its roster's time
  stays the caller's check.
- A coordinator restored as `pending` takes every reference element
  retained at a record's position (companion 13.7.4), so a second,
  different roster of one account that an authorized submitter supplies
  there makes that record unadoptable; keying reference elements by
  account at submission is left to a later recovery-submission change.
- A `roster_recovery` keeps the start commit's empty approval vector, and
  a record continues an account's root at most once; both readings are in
  the first commit's section for the owner.

## Coverage

Release policy (`conformance/release-critical-coverage.toml`):

- First commit: four new regions in `history/liveness.rs`,
  `history-liveness-check` (`check_liveness`), `history-liveness-uses`
  (`uses`), `history-liveness-recovery-candidate` (`recovery_candidate`) and
  `history-liveness-recovers` (`recovers`), score 8 of 8, 4 of 4, 2 of 2 and
  4 of 4 branches, and `history-finalization-one-per-account`
  (`repeats_installed` in `history/finalization.rs`) scores 2 of 2, in a
  branch report of the e2ee crate. `history-membership-ack-authentication`
  is re-spanned from its reviewed first and last lines over the returned
  signers and scores 2 of 2; `history-finalization-transitions` is
  re-spanned the same way over the transition comment that states the rule
  and scores 186 of 195 regions (185 of 195 at the start commit);
  `history-finalization-quorum`, `history-chain-record-adoption` and
  `e2ee-history-resume` only moved and keep the scores they have at the
  start commit (71 of 77 and 67 of 69 regions, and 12 of 12 branches).

- Second commit: ten new regions, `identity-roster-predecessor`
  (`roster_predecessor`) and `identity-capability-predecessor`
  (`capability_predecessor`), 6 of 6 regions each, and
  `identity-roster-lineage` (`check_roster_lineage`) and
  `identity-capability-lineage` (`check_capability_lineage`), 10 of 10 and
  12 of 12 branches, in the e2ee crate; `directory-roster-root-scope`
  (`Directory::publish_roster`), 10 of 10 branches, in the domain crate; and
  `directory-newest-root` (`newest_root`), 12 of 12 regions,
  `directory-roster-publication` (`publish_roster`), 2 of 2 branches,
  `startup-directory-identity` (`restore_identity`),
  `startup-directory-roster` (`restore_roster_row`) and
  `startup-directory-pending-root` (`pend_newest_root`), 4 of 4, 4 of 4 and
  2 of 2 branches, in a branch report of the runtime library. The three
  finalization regions and the startup regions below `restore_directory`
  only moved; `cap76-startup-rebuild` and
  `coordinator-roster-snapshot-resolution` keep 91 of 91 regions and 4 of 4
  branches.

- Third commit: six new regions, `retention-owner-capability-rosters`
  (`hold_capability_rosters`), 2 of 2 branches,
  `retention-owner-capability-rows` (`capability_holders_in`), 6 of 6,
  `retention-owner-startup-capability-rosters`
  (`restored_capability_holders`), 33 of 33 regions,
  `startup-directory-capability` (`restore_capability_row`) and
  `startup-directory-named-roster` (`named_roster`), 6 of 6 and 2 of 2
  branches, in the runtime library, and `directory-current-capability-page`
  (`Directory::capability_page`), 2 of 2 branches, in the domain crate.
  `e2ee-owner-reconstruction` and `retention-owner-startup-holdings` are
  re-spanned from their reviewed first and last lines over the capability
  holding, with their reasons extended by it; the first scores 36 of 36
  branches and the second has no branch, as before. `hold_named_rosters`
  is unchanged and `retention-owner-named-rosters` keeps 4 of 4;
  `e2ee-owner-batch-derivation` and `e2ee-owner-stage-rows` keep 20 of 24
  and 10 of 14 on lines this topic does not touch.
  `coordinator-roster-snapshot-resolution` and the eight
  `retention-roster-holds-*` regions only moved under the module
  documentation of `roster_snapshots.rs` and `roster_holds.rs`, which now
  names the capability row as a holder of a replaced roster.

- Fourth commit: no production line changed, and no region moved.

Both policies' source inventories are refreshed at each commit.

## Revert proofs

- First commit: with `history.rs`, `history/finalization.rs` and
  `history/membership.rs` set back to the start commit and
  `history/liveness.rs` removed, twelve of the fourteen history tests fail;
  the other two, which pin what the chain leaves to the caller and two
  accounts' root continuations in one record, which the start commit
  already installed, pass; in the coordinator suite the adoption test
  fails and the two refusals pass. With only `history/finalization.rs` and
  `history.rs` set back to the first commit before the one-root-and-roster
  rule, the three history tests whose records carry a second root or
  roster of one account, different or repeated, and the coordinator's
  two-roster refusal fail. Twenty-two single-edit mutations each fail at
  least one test: not checking installed rosters, no exception, any rule
  label, a root continuation allowed, an approver or a changed device
  admitted, an unrenewed principal admitted, a policy transition using
  only its signers, votes or approvals or identified ACK signers not
  counted, the signers checked against the rosters after the record, an
  identified signer outside the principals checked, a device the successor
  reissues admitted as present, a root's interval left unchecked, a second
  different root or roster skipped as a repeat, an exact repeat refused,
  the rule left out of the root or of the roster transition (the last also
  failing the coordinator's two-roster refusal), and the rule keyed by the
  record rather than by the account, in both transitions, in the root
  transition only or in the roster transition only (each failing a history
  test of two accounts).
- Second commit: with `identity.rs`, `history/finalization.rs`, the
  domain's `directory.rs` and the runtime's `ops/directory.rs` and
  `startup.rs` set back to the first commit, thirteen tests fail: seven of
  the eight in `root_lineage.rs`, the startup restore test and the five
  updated rotation tests. The eighth, `a_same_root_successor_advances_by_exactly_one`,
  pins same-root rules the first commit already had and passes there. With
  only the domain's `directory.rs` set back, its rotation test fails.
  Sixteen single-edit mutations each fail at least one test: either
  selection helper or either lineage check admitting another root, the
  domain's next generation ignoring the root, its capability heads kept
  across roots, its attachment counters dropped with a roster, its package
  burn reaching another account, the new root merged into the principal
  beside the old roster, the newest root ignoring a pending root, the
  dropped heads' rows kept or their heads kept in memory, the restored
  roster looked up under the newest root only, a pending root left only
  without a roster, the historical chain's roster transition continuing
  across roots, and the roster handler not selecting through
  `roster_predecessor`.
- Third commit: with the domain's `directory.rs` and the runtime's
  `startup.rs` and `owners.rs` set back to the second commit, six tests
  fail: the restart and current-page tests, the revoked device's restart,
  both retention tests that hold a replaced roster, and the startup
  restore against an earlier roster; with only the domain's `directory.rs`
  set back, its page test fails. The ceiling test, the refusals of the
  startup restore and the restore of a row of another kind pin conditions
  the second commit already met. Eight single-edit mutations each fail at
  least one test: the page listing any roster's statement (failing in the
  domain and the runtime runs), the restore against the current roster
  only, the restore for a device the roster dropped, the roster index
  rebuilt after the capability rows, no capability holding in live
  batches, none derived at startup, a capability row keeping a roster on
  rewrite, and a capability holder added past the reference ceiling.
- Fourth commit: with the topic's production files set back to the start
  commit, two of the five restore tests fail: the head naming the replaced
  roster and the pending root. The other three pin what the start commit
  already did: the sealed-storage restore, the counters a rotation was
  admitted with, and a head whose named roster was collected.

## Validation

Each commit, Rust 1.98.0, from the worktree root: `cargo fmt --all
--check`, `cargo clippy --workspace --all-targets --all-features --locked
-- -D warnings`, `python3 scripts/check-source.py check`, `python3
scripts/check-coverage.py audit` on both policies, `git diff --cached
--check` and the program's 59-command fast gate on the staged tree: exit 0.
The runtime library run is `cargo nextest run -p agenc-relay-runtime --lib
--all-features --locked --no-fail-fast -E 'not test(/offline::tests::/)'`;
it leaves out the 36 `offline::tests`, ten of which fail on this host's
root file system, below its storage reserve, at every revision, and skips
one ignored capacity test.

First commit: `cargo nextest run -p agenc-relay-e2ee --all-features
--locked --no-fail-fast` passes 374 of 374, the domain crate 261 of 261 and
the runtime library 2,823 of 2,823. The revert proofs and the single
edits ran the e2ee crate's `history` tests filtered to `roster_recovery::`;
the edits of the device check and the root interval also ran every
`history` test, and the rule keyed by the record every `history` test and
the whole e2ee crate. The revert proofs and the rule left out of the
roster transition also ran the runtime library's `recovery_submission::`
tests, where they fail; none fails to compile. With the root interval left
unchecked, the runtime library's `recovery_submission` and `named_roster`
tests still pass, since no coordinator test continues a root inside a
finalization, and with the rule keyed by the record the whole runtime
library passes, since no coordinator test carries two accounts' rosters
in one record; the history tests fail.
`RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest --branch -p agenc-relay-e2ee
--all-features --locked --no-fail-fast`, after `cargo llvm-cov clean
--workspace`, passes 374 of 374 and gives the scores above; the same
report of `eb2b025`, exported with `git archive`, gives the start commit's
scores.

Second commit: the e2ee crate passes 375 of 375, the domain crate 263 of
263 and the runtime library 2,832 of 2,832. The revert proofs and the
sixteen single edits ran the runtime library's tests of the rotation, the
startup directory and the updated rotation tests, the domain's directory
tests, and the e2ee crate's identity and history tests, each as named
above; none fails to compile. Branch reports of the three crates
(`RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest --branch` after `cargo llvm-cov
clean --workspace`, the runtime library with the same filter) pass 375,
263 and 2,832 tests and give the scores above.

Third commit: the e2ee crate passes 375 of 375, the domain crate 264 of
264 and the runtime library 2,840 of 2,840. The revert proofs and the
eight single edits ran the runtime library's rotation, retention and
startup directory tests and the domain's directory tests; none fails to
compile. Branch reports of the domain crate (264 of 264) and the runtime
library (2,840 of 2,840), after `cargo llvm-cov clean --workspace`, give
the scores above.

Fourth commit: the e2ee crate passes 375 of 375, the domain crate 264 of
264 and the runtime library 2,845 of 2,845. The revert proof ran the
runtime library's `earlier_lineage::` tests; none fails to compile. The
fixture generator ran twice in an export of the start commit and wrote
identical files. The downgrade check ran a test-only module in an export
of the start commit over three stores that the same kind of generator
wrote in an export of the third commit, whose production code the later
commits leave unchanged; its four tests passed.

Not run here: the full stage-nine gate, which cannot finish on this host.
