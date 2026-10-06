# The coordinator's ReInit enforcement and successor installation (AUD-14, SC-014, P-04)

This record covers plan item P-04 of the SDK server program (2026-10-05,
outside master #35) with the Stage 08 evidence maintenance (G-07) and the
persistent-format decision (G-08) that come with it: the coordinator now
applies the companion Section 13.8 rules that the program's normative
revision ([the ReInit target revision record](stage-10-reinit-target-revision.md),
P-01) assigned to the sequencer and the coordinator, with the shared helper
of [the ReInit target helper record](stage-10-reinit-target-helper.md)
(P-02). The work lands in small commits: the first enters the ReInit phase
at the ReInit finalization and checks attempts against it, the second
installs the successor in the activation's own transaction, the third
restores the ReInit state a coordinator stored under the previous profile
(G-08), and the fourth ties every restored route's head to its last
retained record. No specification, profile hash, registry entry, named limit, reply
code, wire object or storage generation changed.

## The ReInit phase begins at the ReInit finalization

Companion 13.8 step 2: "After finalization, the old group is permanently
closed to application and handshake messages; it can never be reactivated."
Step 4: "The sequencer checks the attempt and the target it carries against
the finalized old ReInit Commit".

- `SequencerLog::finalize_reinit` (domain) finalizes the active candidate
  exactly as `finalize` does and enters `Phase::Reinit` at that finalization
  in the same step. It is the only transition into the phase:
  `enter_reinit`, which let the first attempt enter it, is removed. In the
  phase the log takes no ordinary candidate, no application object and no
  close, and its first attempt names the finalization as predecessor at the
  next route sequence, as before.
- `submit_finalization` (runtime) finalizes through `finalize_reinit` when the
  finalized authorization carries the ReInit bit (`reinit_entry`), whatever
  else it carries, and records in the conversation's state the
  `AuthorizedReinit` that `AuthorizedReinit::from_proof` builds from the
  finalization proof: the finalization ID and the authorized
  `transition_target_digest` every attempt is checked against. A proof that
  `from_proof` refuses, such as the ReInit bit beside another bit, still
  closes the group, and records no authority, so no attempt can follow it
  (companion 9.3 makes such an authorization invalid for every endpoint).
  An activation ends the phase and drops the authority; an attempt abort
  keeps both.
- Ordinary candidates and application objects of the old group are refused
  from the finalization on with `E2EE_ROUTE_INVALID`, the reply the closed
  phase already gave, and also after a restart.

The authority lives in `ConversationState::reinit`, not in a durable row: it
is a property of the finalization proof the coordinator already retains as
the finalization record. A restart derives both from retained records:

- a route whose durable head is the finalization of a ReInit Commit restores
  the ReInit phase at that finalization (`finalization_head_phase`), under
  the identity checks a ReInit receipt head already had: the record kind,
  this conversation, the row's predecessor, the finalization ID as both the
  accepted state and the head, and the route sequence; any other
  finalization head leaves the group open;
- the phase's authority is rebuilt from the retained finalization record of
  its accepted state (`restored_authority`), also when the head is a later
  attempt receipt or attempt abort; a missing, undecodable or other record,
  or a proof that `from_proof` refuses, restores no authority.

## The sequencer's attempt checks

`submit_reinit_attempt` now applies the companion 13.8 attempt rules in the
order decision D-11a fixes, each refusal retaining nothing:

1. the requester checks it already had: an attached device, a binding
   principal of the old conversation, a device that holds an old leaf, and
   the recovery gate;
2. `E2EE_FINALITY_REQUIRED` unless the old group is in its ReInit phase and
   the recorded authority is that of the finalization that is the accepted
   state (`reinit_authority::authorized`);
3. the attempt decodes, and names this conversation and network
   (`E2EE_ROUTE_INVALID`, an addressing check);
4. `E2EE_BINDING_AUTH_INVALID` on any error of `AuthorizedReinit::check_attempt`
   (`reinit_authority::check_attempt`): the attempt names that finalization;
   the carried target hashes to its `target_context_digest`, which is the
   authorized digest; its group, version, suite, successor conversation,
   binding and plan are the carried target's; its KeyPackage plan forms the
   target's member plan; and the carried extension list describes the
   successor of the old conversation's current binding and yields the
   target's derived IDs. That binding is the retained binding package
   re-verified under the rosters its principals name, each resolved from the
   principal's re-verified root chain and the retained roster snapshot the
   binding names, as leaf-membership proofs resolve theirs; a binding that
   does not re-verify refuses the attempt the same way;
5. the successor conversation is vacant in every representation
   (`E2EE_ROUTE_INVALID`), checked here instead of in the recovery
   admission, so it follows the checks above;
6. the attempt slot and sequence, the old-policy authorization and the
   blocked pin, as before.

Steps 4 to 6 run under one bounded work reservation
(`reinit_authority::reserve_work`): a conversation with more principals than
a binding admits is `E2EE_BINDING_AUTH_INVALID` before any work, and an
exhausted backing budget `E2EE_RATE_LIMITED`; the old-policy check reserved
its own before, and the per-principal bound now includes the roster snapshot
each principal's binding entry names. The questions file of this lane
records why the requester checks stay first, why the vacancy check moved and
how the work is bounded (Q-RD-4, Q-RD-5, Q-RD-9). The old-policy
authorization no longer compares the attempt's `old_reinit_state_id` with
the accepted state itself: step 4 does.

## The activation installs the successor (second commit)

Companion 13.8: "The coordinator MUST install the successor from the target
the activated attempt carries in the same durable transaction that stores the
activation certificate, and before it sends any reply or event for that
activation", so that "no `EGROUP RESERVE` or `EGROUP BIND` precedes successor
traffic" (step 6).

`submit_reinit_terminal` prepares the installation once the activation's
quorum is reached and before it signs or stages anything
(`reinit_install::prepare`), and every refusal retains nothing:

- the old group must still hold the authority its ReInit finalization
  recorded (`E2EE_FINALITY_REQUIRED` otherwise), and, under the same bounded
  work reservation the attempt used, the activated attempt and its carried
  target are checked again with `AuthorizedReinit::check_attempt` against
  the old binding re-verified under the rosters it names;
- the successor's binding package is the target context's `current_binding`
  with the `ArcInitialMemberPlan` the attempt's KeyPackage plan forms and no
  root binding lock (`reinit_install::package`); it and the context's policy
  verify under the rosters the successor binding names, and its pin, the
  context's `sequencer`, must be a credential this coordinator issues
  receipts under (Q-RD-12); any of these refused is
  `E2EE_BINDING_AUTH_INVALID`;
- the route table replaces the predecessor's route by the successor
  (`RouteTable::install_successor`) only as the exact next binding of its
  lineage on the same concrete route, lock and incarnation, from a
  predecessor that owns the route and accepts traffic; the predecessor keeps
  its entry without the route's indexes.

The activation's batch then carries, beside the activation certificate and
the old route's refreshed row, the successor's binding object, its policy
object and policy row, its route state object and its route row, whose
accepted state and record-head anchor are `reinit_activation_id` at route
sequence zero. When the batch commits, the successor's log is anchored at the
activation (`SequencerLog::from_activation`), its lifecycle has no bootstrap,
its retained facts hold the binding, the published policy and the pin, the
old route's delivery entitlements move to it, and the same route events a
binding sent go out: the old route hidden from every edge entitled to it and
the successor's route state to every edge holding the channel
(Q-RD-13). The successor's context digest is the Section 2.2 `context_digest`
of the `ArcMlsContext` the target carries (`ContextHash`), never the
attempt's `target_context_digest` (`ReinitTarget`). The replies and events of
the activation leave only with its committed batch, as every coordinator
operation's do.

The successor `RESERVE` and `BIND` path is removed: `EGROUP RESERVE` of an
existing route is `E2EE_GROUP_CONFLICT` as a bound or tombstoned target
already was, a direct reservation always takes a fresh nonce, and
`EGROUP BIND` binds generation zero only (Q-RD-14). `RouteTable` loses
`reserve_successor`, `bind_successor` and its successor reservations;
`route_successor` keeps the binding lookup, the requester's principal check
and the activation lookup. `BIND` and the installation share the binding
summary and the starting facts of a bound conversation
(`route::binding_summary`, `route::bound_state`).

## A restart restores the installed successor (second commit)

The successor restores from its own rows like every route; the substitution
of its context digest at startup is removed. Once every route has loaded,
`restore_successors` checks each migrated predecessor's successor
(`restore_successor`): its binding package must be the one the activated
target installs, and its log must be anchored at the activation (accepted
state, record head and epoch one) or continue from it; its route is then
selected over the predecessor's whatever the read order, its lifecycle keeps
no bootstrap, and its context digest is recomputed from the target's
context. A migrated predecessor without its installed successor, two
predecessors naming one successor, or a successor that does not match its
activation refuse startup (Q-RD-15). The recovery lineage stays consistent:
a predecessor whose head is a ReInit record resumes nothing, and a successor
restored pending resumes at its activation anchor.

## ReInit state of the previous profile (G-08, third commit)

Decision: **additive within generation 5**. No table, key, row kind, field
or object layout changes, and the storage generation stays 5 (decision
D-06). What changes is how stored state is read: the first commit reads a
ReInit finalization head as the closed ReInit phase, the second writes the
successor's rows at activation instead of at `BIND`, and this commit reads
the ReInit state that a coordinator of release candidate 3 (`70c832c`)
stored under the previous profile hash, of which companion 2.3 says: "A
ReInit object stored under the previous hash is never parsed or
reinterpreted under this one."

What such a coordinator can have stored, and what the parent commit made of
it when the store was sealed into a storage fixture and reconstructed:

- an attempt admitted with no ReInit Commit before it, at the genesis anchor
  or after an ordinary finalization, left open: restored in the ReInit phase
  with the attempt open and no authority;
- that attempt aborted or activated: the abort or activation record embeds
  an attempt of the previous layout, which no longer decodes, and the
  coordinator refused to start (storage fault), with or without a successor
  bound for the activation;
- a finalized ReInit Commit, whose phase that coordinator entered only at
  the first attempt: restored in the ReInit phase at it (first commit);
- such a finalization followed by ordinary records: restored open, so the
  group took ordinary candidates and application objects again, and an
  ordinary candidate left open stayed open.

This commit keeps the coordinator startable and every such group closed:

- `Phase::Retired` (domain) is a phase only a restore enters. The log keeps
  its head, accepted state and epoch and takes no candidate, terminal,
  application object, attempt or close: `restore_epoch` keeps no candidate
  in it, the route is a tombstone for plaintext purposes
  (`Lifecycle::is_tombstone`), and its recovery lineage resumes nothing
  (`recovery_lineage::resume`, `E2EE_ROUTE_INVALID`).
- A route whose head is a ReInit activation or abort of the previous profile
  is retired (`head_log_phase`, `previous_profile_terminal`). Its record is
  not parsed: after the restore's decode of the head record fails, the record
  is recognized from its rows alone. The head's record row must be an
  activation or abort terminal whose identifier is the route row's head and
  whose predecessor is the attempt receipt row before it, and its retained
  object's envelope must be a sequencer record; any disagreement refuses
  startup, as any other undecodable head does (Q-RD-19).
- The successor that such an activation's group bound with `EGROUP RESERVE`
  and `EGROUP BIND` cannot be checked against its activation and is retired
  with its predecessor (`discard_unanchored_successors`, `retire_route`), in
  binding-generation order, so a chain of them is retired.
- A group that its head leaves open, but whose log holds a finalized ReInit
  Commit followed by any record other than an attempt receipt, is retired
  (`restore_log_phase`, `ordinary_after_reinit`) once the head's own checks
  have passed.
- Unchanged: an attempt left open restores open in the ReInit phase and can
  neither complete nor be aborted, because its object has the previous
  layout; no other attempt follows it, refused with
  `E2EE_FINALITY_REQUIRED` without an authority and with
  `E2EE_BINDING_AUTH_INVALID` under the authority of a ReInit Commit of the
  previous profile, whose authorized target no attempt of this profile
  carries. A group closed by an authorized close stays closed.

A retired route stays bound, so plaintext stays refused on it and a new
reservation of its channel is `E2EE_GROUP_CONFLICT`. Startup writes nothing:
the retirement is derived again from the same rows at every restart.

The restore evidence is `test-data/stage-ten/previous-profile-reinit/`: ten
stores that the `70c832c` coordinator wrote through its own test harness,
those of the states above, among them an open ordinary candidate with the
finalization request that would have completed it, and a finalized ReInit
Commit followed by an attempt (the previous profile's own flow) or by a
closing intent and its close. Its README reproduces the generator, the three
test-only edits of the exported tree and the command; separate runs wrote
byte-identical files (Q-RD-17). The tests are listed below.

Staying in generation 5 has a cost: nothing refuses a database this branch
has written when release candidate 3 opens it, and release candidate 3 does
not read this branch's ReInit state as this branch does, so downgrading a
node is unsafe. The operator guide's upgrade note says so and that going
back means restoring a backup taken before the upgrade. The source ledger's
Section 9 still says only that the persistent format is unchanged; the
ledger is a pinned normative artifact, so its downgrade sentence is left for
the next normative revision (Q-RD-20).

## A restored head is the route's last record (fourth commit)

Companion 13.8 step 2 closes the old group for good, so the phase a restart
restores must be the phase of the route's actual last record.
`restore_log_phase` now first requires `head_is_last_record`: the head the
route row names is its last retained record, at that record's route
sequence and under its identifier. A closed route's head is its close,
which is not a retained record, and a route without a retained record (a
genesis anchor, or a successor anchored at its activation) has no recorded
head. A route row that names an earlier record, a position after the last
one or another identifier at that position restores nothing, so startup
refuses the store, as it does for the other identity disagreements. Stores
this coordinator writes, including those of the previous profile, always
name their last record: the route row and the record are written in one
batch.

## The Stage 08 scenarios

`crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/reinit.rs`
built its target with a one-byte placeholder extension list, which the
sequencer's step 4 refuses since the first commit. Its target now carries the successor context
companion 13.8 describes (the replacement of the bound `#room` binding on the
same route, the successor's generation-zero policy of both principals, a
sequencer credential and both principals' roster heads) with an empty
`required_capabilities` extension, and the attempt's KeyPackage plan is in the
canonical order of the semantic plan's device tuples. Both ReInit scenarios
(activation and attempt abort) pass through the daemon with that target. The
mls-rs endpoints still advertise no ARC extension, so their own ReInit
Proposal carries no extension list and they never rebuild the target from it.

Since the second commit the activation scenario continues through the
daemons with no further reservation or binding: alice's application message
on the remapped `#room` route, encrypted by her successor group, reaches
bob's edge and bob's successor group reads it, while the leaf removed before
the ReInit derives nothing; alice's first successor Commit is sequenced at
the successor's route sequence zero after the activation; and after the
whole network restarts, as the rotation scenario restarts it (Q-RD-16), the
successor takes another application message that bob reads.

## Stage 08 model and transcripts (G-07)

`crates/agenc-relay-testkit/src/e2ee_model.rs` gains one action,
`ReinitFinalize(c)`, which finalizes the active candidate as a ReInit Commit
through `finalize_reinit`, and checks after every transition that no
ordinary candidate, application object or close is accepted after it
(`Violation::ReinitClosedGroup`). At the recorded bounds (two conversations,
accounts and devices, depth 6) `conformance/stage-eight-model.toml` changes:

| Count | Before | After | Why |
| --- | ---: | ---: | --- |
| actions | 28 | 30 | `ReinitFinalize` for each of the two conversations |
| states | 50 | 57 | the seven states in which a ReInit finalization closed one conversation's group, first reached at depths 4 (one), 5 (two) and 6 (four) |
| transitions | 124 | 144 | 14 accepted `ReinitFinalize` actions, one from each reached state below the depth bound whose conversation has an active candidate, and 6 accepted actions in the three ReInit states below the bound, each reserving, binding or sending plaintext for the other conversation |
| paths | 22 | 26 | the four new states at the depth bound; no new dead end |
| refusals | 660 | 786 | 42 refused `ReinitFinalize` actions (56 attempts from the 28 earlier states below the bound, 14 accepted) and 84 refused actions in the three ReInit states below the bound (28 of the 30 actions in each, every action on the closed conversation among them) |

`violations` stays 0 and the invariants list is unchanged. Attempt, ACK and
terminal actions are not added: they are not phase entries, and the domain and
coordinator tests cover them (Q-RD-7). `bash scripts/run-stage-eight-model.sh`
and `bash scripts/run-stage-eight-transcripts.sh` pass, and the pinned test
names of `conformance/stage-eight-transcripts.toml` are kept.

The Stage 08 evidence that changed, for the TODO note and the push report:

| Evidence | Transcript row, Section 21 gate | Stage 08 task |
| --- | --- | --- |
| `reinit_attempts_activate_or_abort_and_migrate_the_log` (domain, rewritten for `finalize_reinit`) and the three domain restore tests | `domain-reinit-log`, gate 14 | S08-012, S08-030 |
| the model's new action and check, and its counts | `model-exhaustive` (gates 7, 22), `model-adversarial` (gate 7) | S08-008, S08-024, S08-030 |
| `a_reinit_attempt_is_staged_acknowledged_aborted_and_finally_activated` and every coordinator test that stages an attempt, now after a finalized ReInit Commit | `coordinator-reinit`, gate 14 | S08-012, S08-030 |
| the Stage 08 ReInit scenarios with a target the sequencer checks | (daemon scenarios of ENC-10) | S08-012, S08-030 |
| second commit: the activation's route events in `a_reinit_attempt_is_staged_acknowledged_aborted_and_finally_activated` | `coordinator-reinit`, gate 14 | S08-012, S08-030 |
| second commit: the Stage 08 activation scenario's successor traffic with no binding, also after a restart | (daemon scenario of ENC-10) | S08-012, S08-030 |
| second commit: `RouteTable::install_successor` replacing the successor reservation (`route_table_successor.rs`, no transcript row) | none | S08-012 |
| third commit: the retired phase's domain tests, beside the unchanged pinned tests of `restore_epoch` and `is_tombstone` | none (`domain-close-restore` and `domain-lifecycle-gate`, gate 8, unchanged) | S08-011, S08-012 |
| third commit: the restore of the previous profile's ReInit state (`previous_profile.rs`) | none | S08-012, S08-013, S08-015 |

The gate numbers are the transcript catalog's; its gate 14 is the companion's
ReInit race item, whose text since P-01 names the successor that takes
traffic after activation and after a coordinator restart with no
`EGROUP BIND`, and a crash on either side of the activation transaction. The
second commit changes no model count: the model's route actions reserve,
bind, close and reopen, and none of them is a ReInit successor. The third
commit adds `Phase::Retired`, which only a restore enters; the model never
restores a log, so its counts do not change either, and its state key gives
the new phase its own tag. The domain functions it touches, `restore_epoch`
and `Lifecycle::is_tombstone`, changed only for that phase, and the pinned
tests that run them (`domain-close-restore` and `domain-lifecycle-gate`,
gate 8) pass unchanged. No box changes.

## Tests

- `crates/agenc-relay-domain/src/e2ee/tests/sequencer_log.rs`: the ReInit
  finalization closes the group in one step, a refused one changes nothing,
  and restore keeps the active and exhausted attempt slots after it.
- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/reinit/enforcement.rs`:
  an attempt at the genesis anchor or after an ordinary finalization is
  `E2EE_FINALITY_REQUIRED`, also when it carries an unauthorized target or
  names an existing conversation as successor; a ReInit bit beside another
  bit closes the group, admits no attempt and stays so after a restart;
  ten attempts that differ from the authorized target (another old ReInit
  state, digest, carried target, consistently renamed target, successor,
  existing conversation as successor, binding, member plan, suite, KeyPackage
  plan) are `E2EE_BINDING_AUTH_INVALID` and the unchanged attempt is then
  admitted; an authorized target whose list fails the structural rules is
  refused; the old group refuses an ordinary candidate and an application
  object after the ReInit finality, before and after a restart; a restart
  restores the phase and its authority, refuses a wrong digest and admits
  the authorized attempt; an authority of another finalization admits
  nothing; the binding is checked under the rosters it names after the
  principal's roster moved on, and a missing roster snapshot or binding, a
  root chain that does not re-verify, a binding naming another root or an
  account identifier of another length, or more principals than a binding
  admits, refuses the attempt.
- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/startup_heads.rs`:
  a ReInit finalization head restores the phase, an ordinary one leaves the
  group open, and each identity disagreement leaves the phase unrestorable;
  the authority comes only from the retained finalization record of the
  phase's state.
- `tests/sequence/reinit/successor.rs`: an activation ends the phase and its
  authority, live and after a restart, and the migrated group refuses an
  attempt with `E2EE_FINALITY_REQUIRED` even with the authority put back.
- Every coordinator test that stages an attempt now finalizes a ReInit Commit
  that authorizes its target first (`Harness::bind_channel_for_reinit`,
  `finalize_reinit`, `finalize_reinit_to`).

Second commit:

- `crates/agenc-relay-domain/src/e2ee/tests/route_table_successor.rs`: an
  installed successor takes the channel or direct route, plaintext stays
  refused and the predecessor keeps its entry without the indexes; a second
  install from the predecessor, a predecessor closing, pending, without the
  route's indexes or missing, a successor that already has a route, and each
  lineage field (instance, nonce, lock, incarnation, generation, previous
  binding, conversation) are refused with the table unchanged.
- `tests/sequence/reinit/successor.rs`: the activation's batch carries the
  successor's route row, binding and policy objects and policy row, and its
  route events; the successor holds the target's binding, policy, pin and
  context digest (`ContextHash`, not the target's digest), live and after a
  restart that reproduces it; it takes an application object and a Commit
  candidate with no binding, and the candidate survives a restart. An
  activation evaluated but not committed leaves, after a restart, the old
  route closed with its attempt pending and no part of the successor, and the
  same activation then installs it. The route is neither reserved nor bound
  again. An activation without its authority, with a foreign authority, under
  an exhausted work budget, with a successor policy that does not verify,
  with a pin this coordinator does not issue under, or when the old binding
  cannot be checked again retains nothing, and the bindings are checked
  under the rosters they name after the roster moved on. A restored
  successor keeps no bootstrap whatever the read order.
- `successor/row_mismatch.rs`, `successor/target_mismatch.rs`,
  `successor/declared_recovery.rs` and `successor/reconstruction.rs` keep
  their restore checks on installed successors; new cases refuse a successor
  row naming another binding or leaving its activation anchor (accepted
  state, head, no epoch, a later epoch), the sealed reconstruction refuses an
  independent route at the activation target and preserves an installed
  successor's later head, and a pending successor's recovery lineage resumes
  at its anchor while its predecessor's resumes nothing.
- `tests/startup_routes.rs`: an activation without its installed successor
  refuses startup and anchors nothing.

Third commit:

- `crates/agenc-relay-domain/src/e2ee/tests/sequencer_log.rs` and
  `tests/lifecycle.rs`: a retired log keeps its head, keeps no candidate its
  head names, and refuses a candidate, a finalization or abort, a ReInit
  finalization, an attempt, a ReInit restore and a close, unchanged; a
  retired route is a tombstone that refuses application traffic and
  candidates.
- `tests/sequence/reinit/successor/previous_profile.rs`, over the ten
  `70c832c` stores: every store reconstructs through the sealed storage
  fixture; a route whose head is the previous profile's ReInit abort or
  activation is retired, and so is the successor bound for the activation;
  an attempt admitted before this enforcement, also after a ReInit Commit,
  stays open in the ReInit phase; a ReInit Commit finalized under the
  previous profile keeps the group in that phase, and ordinary records after
  it retire the group; an ordinary candidate left open after it is not
  restored, and its stored finalization request is
  `E2EE_FINALITY_REQUIRED`; a group closed after it stays closed. On every
  such route a candidate and an application object are
  `E2EE_ROUTE_INVALID`, an attempt is `E2EE_FINALITY_REQUIRED` or, under a
  previous-profile authority, `E2EE_BINDING_AUTH_INVALID`, a reservation of
  the channel is `E2EE_GROUP_CONFLICT` and plaintext stays refused, and no
  retired or ReInit-phase route resumes a recovery lineage. Eight row
  disagreements around a retired head (the route row's
  head, the record row's identifier, kind, terminal flag and predecessor,
  the kind of the record before it, an object of another kind and a missing
  object) each refuse startup, while the unedited rows restore, and a head
  record row that names another kind than its record refuses startup.
- `successor/row_mismatch.rs`: an attempt aborted under this profile
  restores in the ReInit phase, and a route row that names another accepted
  state or another head than its abort record refuses startup.

Fourth commit:

- `tests/startup_heads.rs`: a route row whose head is its last record
  restores, and one that names a later position, an earlier record or
  another identifier restores nothing; a closed route and a route without
  records restore.
- `successor/row_mismatch.rs`: a route row of an aborted attempt that names
  a later route sequence, and a route row rolled back from the ReInit
  finalization to the bootstrap activation before it, refuse startup.

## Requirements

No binding changes (Q-PR-1 of the P-02 lane): a clause's status follows its
closure task, so the seven `S10-004` clauses stay `unimplemented` until
`S10-004` closes. The first commit implements six of them in the
coordinator, the second the seventh:

| Requirement | Clause | Implemented by |
| --- | --- | --- |
| `E2EE-REQ-91603206702A296AE34F` | `E2EE_FINALITY_REQUIRED` unless the accepted state is a ReInit finalization | `finalize_reinit`, `reinit_entry`, `reinit_authority::authorized`, restore |
| `E2EE-REQ-667141DBC7473B7A0F9D` | the attempt names that finalization | `reinit_authority::check_attempt` (`AuthorizedReinit::check_attempt`) |
| `E2EE-REQ-CCA2E69085E483C5155F` | carried target digest and the authorized digest | the same |
| `E2EE-REQ-39DFA440E75F7F7495F2` | attempt fields against the carried target | the same |
| `E2EE-REQ-B4977D179E4C66AAD737` | the KeyPackage plan forms the member plan | the same |
| `E2EE-REQ-4A3F05D133A72461A8DC` | the carried list's structure and derived IDs | the same, against the binding re-verified under its named rosters |
| `E2EE-REQ-65D600D44A7F4FDA9EE6` | the atomic successor installation (second commit) | `reinit_install::prepare` and `package`, `RouteTable::install_successor`, the activation's batch and effect, `restore_successor` |

No clause of the revision is left without an implementation in the
coordinator or the shared code.

## Coverage

Both coverage policies take the new production source inventory (1,019
files). The release policy gains eight regions, all at 100 percent in a
runtime branch report: `p04-reinit-entry`,
`p04-reinit-authority-{authorized,check-attempt,reserve-work,current-binding,named-rosters}`
and `p04-startup-{finalization-head-phase,restored-authority}`. Five reviewed
spans changed text and were re-reviewed and respanned:
`cap73-recovery-reinit`, `cap76-recovery-vacant-successor`,
`cap100-reinit-authority-004-verify`, `cap100-reinit-authority-005-work-capacity`
and `cap100-reinit-authority-006-submit-reinit-attempt`; the others whose
lines moved were re-anchored. The policy holds 1,192 reviewed spans.

The second commit adds five regions (`p04-reinit-install-{prepare,package}`,
`p04-sequence-{install-successor,successor-route-events}` and the domain's
`p04-route-table-install-successor`), re-reviews and respans
`cap73-recovery-bind`, `cap76-startup-rebuild`,
`cap76-startup-restore-successors` and three `p04-reinit-authority-*`
regions, and moves `cap76-startup-restore-successor-binding` to the renamed
`restore_successor`. The policy holds 1,197 reviewed spans and both
inventories 1,020 files.

The third commit adds six regions,
`p04-startup-{restore-log-phase,head-log-phase,previous-profile-terminal,ordinary-after-reinit,discard-unanchored-successors,retire-route}`,
and re-reviews and respans `runtime-recovery-lineage-resume`, whose refusal
now names the retired phase. The policy holds 1,203 reviewed spans and both
inventories 1,021 files.

The fourth commit adds `p04-startup-head-is-last-record` and re-reviews and
respans `p04-startup-restore-log-phase`; the policy holds 1,204 reviewed
spans.

## Persistence

No row, field, table or object layout changed, and the storage generation
stays 5. The first commit derives the phase and its authority from the
retained finalization record; a stored route whose head is the finalization
of a ReInit Commit now restores closed in the ReInit phase instead of open.
The second commit writes the successor's existing kinds of rows (route row,
binding, policy and route state objects, policy row) in the activation's
transaction instead of at a later `BIND`, and restores them like any route.
The third commit writes nothing: it reads the ReInit state stored under the
previous profile, including attempts admitted before this enforcement, as
the G-08 section describes, and the decision is additive within generation
5.

## Revert proofs and mutations

The parent commit cannot run the new tests: its domain had no ReInit
finalization and its attempt handler entered the phase itself, so the tests
do not compile against it. Each rule was instead reverted in place on this
tree by the lane's mutation tool, which disables one rule or one condition,
rebuilds, runs the runtime's 800 E2EE tests (the domain's sequencer log
tests and the Stage 08 model for the two domain mutations) and restores the
sources by hash:

| Reverted rule | Failing tests |
| --- | --- |
| a ReInit finalization enters no phase and records no authority | 110, among them every test that stages an attempt and the closed-group test |
| the finality check removed | 2: the other-finalization and the migrated-group tests |
| the attempt not checked against the authorized target | 6: the mismatched attempts, the structural refusal, both binding re-checks, the restart test's wrong digest and a later attempt's old state |
| neither phase nor authority restored from a ReInit finalization head | 9: the head tests, the restart tests, the pending-recovery refusal and the staged-then-activated transcript |

The 24 single-condition mutations (phase entry on the ReInit bit, entry on
every finalization, no recorded authority, no phase, authority kept at
activation, the phase and accepted-state conditions of the finality check,
the attempt checks, which is the third revert's edit, the binding verified
under the current heads, the root taken by fingerprint, the successor
vacancy in the handler and in the admission, the six identity conditions of
a restored finalization head, the restored authority, the authority of
another record, and the domain's phase entry and its precondition) kill 23,
so the campaign kills 27 of its 28 entries. The survivor takes the principal's
newest root instead of the root the binding names: only a root rotation
makes them differ, and after one the old-policy authorization, which this
change does not alter, refuses the attempt whichever root the binding check
took (see the limitations).

The second commit's campaign, run the same way (the domain's route table
tests for the route table mutations), reverts three rules and 26 single
conditions:

| Reverted rule | Failing tests |
| --- | --- |
| the activation installs nothing | 14: the installation, crash, restart, recovery-gate, reconstruction and row tests and the staged-then-activated transcript |
| a restart does not check the installed successor against its activation | 3: the successor rows that leave the activation anchor, name another binding of the lineage, or lose the epoch after a later head |
| the successor's context digest is the target's digest | 2: the installation test and the sealed reconstruction |

Of the 26 single-condition mutations (the attempt's links not checked again,
the successor bindings under the current heads, a pin that need not issue,
the policy verified for the old conversation, the old route not hidden, the
successor's route not sent, the old entitlement kept, the successor channel
not entitled, a bootstrap left on the successor, a successor log anchored
elsewhere, the restore's binding comparison, its four anchor conditions, its
lifecycle, its route selection and its missing-successor fault, and the
route table's eight install conditions), 25 are killed, so the campaign
kills 28 of its 29 entries. The survivor skips the route selection after the
restore's checks: `restore_entry` already gives the route to the higher
binding generation of one lock and incarnation whatever the read order, and
the lineage the selection checks follows from the binding comparison before
it, so no reachable store distinguishes it; the selection is kept as it was
before this change.

The third commit's campaign, run the same way (the domain and testkit
suites for the two domain mutations, the runtime's E2EE tests otherwise),
reverts four rules (the last against both crates' tests) and 18 single
conditions:

| Reverted rule | Failing tests |
| --- | --- |
| a previous-profile ReInit activation or abort at the head refuses startup again | 4: the restore of every store, the terminal retirement, the bound successor and the row disagreements |
| ordinary records after a finalized ReInit Commit no longer retire the group | 2: the finalized ReInit Commit test (its store with ordinary records after it) and the open candidate test |
| a successor bound under the previous profile is discarded again | 2: the bound successor test and the restore of every store |
| a retired log keeps the candidate its head names | 1 domain test, and 1 runtime test: the open candidate's stored finalization request is accepted |

The 18 single-condition mutations (a closed group retired, the retirement
before the head's own checks, every finalization or every ReInit
finalization retiring, an attempt receipt counted as an ordinary record, a
previous-profile terminal left in the row's phase, every undecodable head
retired, the seven row conditions of a previous-profile terminal, a retired
predecessor's successor kept in its phase or `retire_route` doing nothing, a
retired lineage resumed, and a retired route that is no tombstone) are all
killed, so the campaign kills 23 of its 23 entries.

The fourth commit's campaign reverts its rule, which fails 3 tests (the
unit test of the head position, the aborted attempt's later route sequence
and the rolled-back route row), and kills its four single-condition
mutations (the route sequence or the identifier not compared, a closed
route held to the rule, a route without records refused), 5 of 5 entries.

## Limitations

- The Stage 08 scenarios' successor context is built by the test from the
  bound route; the mls-rs endpoints do not rebuild it from their Proposal.
- An attempt's old-policy authorization is verified under the principals'
  current root and roster heads, as before this change; after a principal
  rotates its root, which companion 8.2 follows with a ReInit, the old
  policy's controllers name the previous root and no attempt of that
  conversation is authorized. The binding check of this change resolves the
  root and roster the binding names and is not what refuses it.
- A successor of a direct conversation is installed by the same code, but no
  coordinator test binds a direct conversation through the harness, so its
  entitlement branch is covered by no test; the route table's direct install
  is.
- The daemon-level restart in the Stage 08 scenario restarts the whole
  network; a coordinator-only restart with live sessions is not used there
  (Q-RD-16).
- A retired channel takes no encrypted traffic again in this release: it
  cannot be closed, reserved or bound anew. How such a channel gets a new
  group is for plan item B-14 (recreated routes) to define.
- Startup writes nothing for a retired route, so its edges keep the route
  state they last received, an active route; the coordinator refuses every
  request on it.
- The restore still decodes each head record under this profile before it
  recognizes a previous-profile terminal from its rows, and it still reads
  the receipt of an attempt left open under the previous profile, whose
  layout the revision did not change, to restore that attempt's slot
  (Q-RD-19).
- The restore fixtures come from the `70c832c` coordinator's test harness,
  not from a running `arcd` of that release, and cover one channel route.

## Validation

On the tree of this commit, before it was committed, with Rust 1.98.0:

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  and `python3 scripts/check-source.py check`: clean.
- `cargo nextest run -p agenc-relay-runtime --lib --all-features --locked`:
  2,705 passed, 1 skipped (800 of them E2EE tests).
- `cargo nextest run -p agenc-relay-domain -p agenc-relay-testkit --all-features --locked`:
  391 passed.
- `cargo nextest run -p agenc-relay-server --test stage_eight_e2ee --all-features --locked`:
  47 passed, both ReInit scenarios among them; the 17 Stage 10 drills were
  skipped.
- `bash scripts/run-stage-eight-model.sh` and
  `bash scripts/run-stage-eight-transcripts.sh`: passed, with the counts
  above.
- The mutation campaign above: 27 of 28 killed.
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime --all-features --branch --locked --json`:
  the eight new regions at 100 percent (7, 16, 25, 17, 19, 41, 15 and 23
  regions); the respanned `cap76-recovery-vacant-successor` at 17 of 17, and
  `cap73-recovery-reinit` 21 of 26, `cap100-reinit-authority-004-verify` 30
  of 33, `cap100-reinit-authority-005-work-capacity` 10 of 13 and
  `cap100-reinit-authority-006-submit-reinit-attempt` 192 of 214 in this
  runtime-only report, whose uncovered parts are refusals of internal
  failures no test reaches (payload, decode, lookup and write failures and
  checked arithmetic on constants).
- `python3 scripts/check-coverage.py audit` and `self-test` on both
  policies: passed (21 and 1,192 reviewed spans).
- The program's fast static gate (59 commands): all passed.

On the tree of the second commit, before it was committed:

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  and `python3 scripts/check-source.py check`: clean.
- `cargo nextest run -p agenc-relay-runtime --lib --all-features --locked`:
  2,709 passed, 1 skipped (804 of them E2EE tests).
- `cargo nextest run -p agenc-relay-domain -p agenc-relay-testkit --all-features --locked`:
  389 passed (the four successor reservation tests replaced by two install
  tests).
- `cargo nextest run -p agenc-relay-server --test stage_eight_e2ee --all-features --locked`:
  47 passed, 17 skipped; the activation scenario with its successor traffic
  and network restart among them.
- `bash scripts/run-stage-eight-model.sh` and
  `bash scripts/run-stage-eight-transcripts.sh`: passed, the model's counts
  unchanged.
- The mutation campaign above: 28 of 29 killed.
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime -p agenc-relay-domain --all-features --branch --locked --json`:
  `p04-sequence-successor-route-events` (30 of 30 regions) and
  `p04-route-table-install-successor` (20 of 20 branches) complete;
  `p04-reinit-install-prepare` 203 of 230, `p04-reinit-install-package` 19 of
  21 and `p04-sequence-install-successor` 27 of 31 regions, short by internal
  failures no test reaches (encoding and lookup failures, a bounded plan
  that cannot overflow) and by the direct-conversation branch (see the
  limitations); the respanned `cap76-startup-rebuild` (89 of 89) and
  `cap76-startup-restore-successors` (51 of 51) complete, and
  `cap76-startup-restore-successor-binding` 80 of 91 and `cap73-recovery-bind`
  21 of 26, short by internal failures; the first commit's new regions,
  three of them respanned, stay complete.
- `python3 scripts/check-coverage.py audit` and `self-test` on both
  policies: passed (21 and 1,197 reviewed spans).
- The program's fast static gate (59 commands): all passed.

On the tree of the third commit, before it was committed:

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  and `python3 scripts/check-source.py check`: clean.
- `cargo nextest run -p agenc-relay-runtime --lib --all-features --locked`:
  2,719 passed, 1 skipped (814 of them E2EE tests).
- `cargo nextest run -p agenc-relay-domain -p agenc-relay-testkit --all-features --locked`:
  391 passed.
- `cargo nextest run -p agenc-relay-server --test stage_eight_e2ee --all-features --locked`:
  47 passed, 17 skipped.
- `bash scripts/run-stage-eight-model.sh` and
  `bash scripts/run-stage-eight-transcripts.sh`: passed, the model's counts
  unchanged.
- `cargo nextest run -p agenc-relay-storage --all-features --locked`: 443
  passed, 1 skipped (no storage source changed). With `--profile disk`: the
  one test of that profile,
  `qualification_workload::production_workload_measures_every_required_case_and_phase`,
  failed with `StaleState` and its five `reserve-minus-one` rows refused,
  the known failure of issue #55 on this host's XFS volume.
- The mutation campaign above: 23 of 23 killed.
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime -p agenc-relay-domain --all-features --branch --locked --json`:
  `p04-startup-restore-log-phase` (16 of 16 regions),
  `p04-startup-previous-profile-terminal` (29 of 29) and
  `p04-startup-ordinary-after-reinit` (25 of 25) complete, and the respanned
  `runtime-recovery-lineage-resume` (10 of 10 branches);
  `p04-startup-head-log-phase` 85 of 86, short by an attempt sequence at its
  maximum, which the bounded attempt count never reaches;
  `p04-startup-discard-unanchored-successors` 64 of 65, short by a restored
  conversation whose binding is not indexed, and `p04-startup-retire-route`
  11 of 12, short by a retired conversation without a log, which no restore
  produces. A first run of the same command failed in the unrelated
  `state_core::tests::a_guest_session_registers_and_commands_flow_through_the_router`,
  whose scripted session can race its own stop under host load; the second
  run passed all 3,084 tests.
- `python3 scripts/check-coverage.py audit` and `self-test` on both
  policies: passed (21 and 1,203 reviewed spans).
- The program's fast static gate (59 commands): all passed.

On the tree of the fourth commit, before it was committed:

- `cargo fmt --all --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`
  and `python3 scripts/check-source.py check`: clean.
- `cargo nextest run -p agenc-relay-runtime --lib --all-features --locked`:
  2,721 passed, 1 skipped (816 of them E2EE tests, the ten restore tests
  over the `70c832c` stores among them).
- `cargo nextest run -p agenc-relay-domain -p agenc-relay-testkit --all-features --locked`:
  391 passed.
- `cargo nextest run -p agenc-relay-server --test stage_eight_e2ee --all-features --locked`:
  47 passed, 17 skipped.
- `bash scripts/run-stage-eight-model.sh` and
  `bash scripts/run-stage-eight-transcripts.sh`: passed.
- The mutation campaign above: 5 of 5 killed.
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime -p agenc-relay-domain --all-features --branch --locked --json`:
  `p04-startup-head-is-last-record` (11 of 11 regions) and the respanned
  `p04-startup-restore-log-phase` (20 of 20) complete.
- `python3 scripts/check-coverage.py audit` and `self-test` on both
  policies: passed (21 and 1,204 reviewed spans).
- The program's fast static gate (59 commands): all passed.

The workspace test run and the full `bash scripts/check-stage-nine.sh` run at
the tip of the branch; their results are in the program's lane report.
