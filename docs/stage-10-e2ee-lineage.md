# Roster liveness and root-scoped directory lineage (B-15, B-16)

This record covers the server topic `sdk/b-e2ee-lineage` of the SDK server
program (items B-15 and B-16, 2026-10-09, outside master #35). The first
commit checks the roots and rosters a historical finalization uses against
the Commit's canonical validation time, with the narrow roster recovery of
companion Section 8.4. No specification, profile hash, registry entry, named
limit, reply code, wire object, table, key, row kind, field or storage
generation changed.

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

Both policies' source inventories are refreshed.

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

Not run here: the full stage-nine gate, which cannot finish on this host.
