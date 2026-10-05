# The coordinator's ReInit enforcement (AUD-14, SC-014, P-04)

This record covers plan item P-04 of the SDK server program (2026-10-05,
outside master #35) with the Stage 08 evidence maintenance (G-07) and the
persistent-format decision (G-08) that come with it: the coordinator now
applies the companion Section 13.8 rules that the program's normative
revision ([the ReInit target revision record](stage-10-reinit-target-revision.md),
P-01) assigned to the sequencer and the coordinator, with the shared helper
of [the ReInit target helper record](stage-10-reinit-target-helper.md)
(P-02). The work lands in small commits; each section below names the
commit that made it. No specification, profile hash, registry entry, named
limit, reply code, wire object or storage generation changed.

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

## The Stage 08 fixture builds a successor the sequencer accepts

`crates/agenc-relay-server/tests/stage_eight_e2ee/encrypted_clients/reinit.rs`
built its target with a one-byte placeholder extension list, which the
sequencer's step 4 now refuses. Its target now carries the successor context
companion 13.8 describes (the replacement of the bound `#room` binding on the
same route, the successor's generation-zero policy of both principals, a
sequencer credential and both principals' roster heads) with an empty
`required_capabilities` extension, and the attempt's KeyPackage plan is in the
canonical order of the semantic plan's device tuples. Both ReInit scenarios
(activation and attempt abort) pass through the daemon with that target. The
mls-rs endpoints still advertise no ARC extension, so their own ReInit
Proposal carries no extension list and they never rebuild the target from it.

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

The gate numbers are the transcript catalog's; its gate 14 is the companion's
ReInit race item. No box changes.

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

## Requirements

No binding changes (Q-PR-1 of the P-02 lane): a clause's status follows its
closure task, so the seven `S10-004` clauses stay `unimplemented` until
`S10-004` closes. This commit implements six of them in the coordinator:

| Requirement | Clause | Implemented by |
| --- | --- | --- |
| `E2EE-REQ-91603206702A296AE34F` | `E2EE_FINALITY_REQUIRED` unless the accepted state is a ReInit finalization | `finalize_reinit`, `reinit_entry`, `reinit_authority::authorized`, restore |
| `E2EE-REQ-667141DBC7473B7A0F9D` | the attempt names that finalization | `reinit_authority::check_attempt` (`AuthorizedReinit::check_attempt`) |
| `E2EE-REQ-CCA2E69085E483C5155F` | carried target digest and the authorized digest | the same |
| `E2EE-REQ-39DFA440E75F7F7495F2` | attempt fields against the carried target | the same |
| `E2EE-REQ-B4977D179E4C66AAD737` | the KeyPackage plan forms the member plan | the same |
| `E2EE-REQ-4A3F05D133A72461A8DC` | the carried list's structure and derived IDs | the same, against the binding re-verified under its named rosters |

`E2EE-REQ-65D600D44A7F4FDA9EE6`, the atomic successor installation, is still
open in this commit.

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

## Persistence

No row, field, table or object layout changed, and the storage generation
stays 5: the phase and its authority are derived from the retained
finalization record. A stored route whose head is the finalization of a
ReInit Commit now restores closed in the ReInit phase instead of open. How
routes written before this change restore, including attempts admitted
before this enforcement and ReInit state of the previous profile, is decided
with its restore test in the G-08 section.

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

## Limitations

- The successor is still installed by `EGROUP RESERVE` and `EGROUP BIND`
  after the activation in this commit.
- The Stage 08 scenarios' successor context is built by the test from the
  bound route; the mls-rs endpoints do not rebuild it from their Proposal.
- An attempt's old-policy authorization is verified under the principals'
  current root and roster heads, as before this change; after a principal
  rotates its root, which companion 8.2 follows with a ReInit, the old
  policy's controllers name the previous root and no attempt of that
  conversation is authorized. The binding check of this change resolves the
  root and roster the binding names and is not what refuses it.

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
  policies: passed (21 and 1,191 reviewed spans).
- The program's fast static gate (59 commands): all passed.

The workspace test run and the full `bash scripts/check-stage-nine.sh` run at
the tip of the branch; their results are in the program's lane report.
