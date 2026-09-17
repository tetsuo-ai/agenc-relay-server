# Secondary 2026-09-01 audit findings: ZDH-C3, C4, C5 and A1

This record disposes the four secondary findings grouped in issue #13, each
re-verified against the current tree at `fb618ab22aedb914ad983fd5143bb9c81acd9ddd`.
The audit read commit `99dd9074f75f39bfd2fac57fef4b594d9f1add76` (2026-08-29);
the tree has moved a long way since, so every finding was re-read against the
code that exists now before any change was considered. All four no longer
apply. No production source is changed by this record; it adds two regressions
that pin the exact behaviour each finding alleged was missing, and states for
every finding which commit resolved it and which code now carries the
decision.

Only defect classes are described here. No document in this repository
carries a reproduction procedure against a running daemon.

## Method

Each finding was disposed in three steps.

1. Read the code the finding named, and the code that replaced it, at HEAD.
2. Find the commit that changed the behaviour, and confirm it is an ancestor
   of `main`.
3. Confirm that a regression actually discriminates the defect: run it against
   a temporary, local source mutation that restores the audited behaviour,
   confirm it fails with the audited symptom, then restore the source and
   confirm it passes. The mutations were never committed; `git status` was
   clean of production sources before the commit that carries this record.

## ZDH-C3 — ban and exception entries attributed to the channel creator

**Status: no longer applies.** Repaired by `cc57214ac898ae5a80f2f141582ea94adde7f3e2`
("Record the acting operator as the mask-list entry setter", 2026-09-02),
merged in PR #17 (`d6b883a`), one day after the audit.

The finding was that `apply_mode_change` built every `+b`, `+e` and `+I`
`ListEntry` with `setter: channel.creator`, so the moderation trail attributed
a half-operator's ban to the founder, and that the entry timestamp fell back to
the channel's creation time whenever the trusted UTC read was absent.

Code inspected at HEAD:

- `crates/agenc-ircd-domain/src/decision.rs:1223` — `ModeBatch` carries a
  `setter: Principal` field beside the changes, entry identifiers, key
  verifiers and `created_at`.
- `crates/agenc-ircd-domain/src/decision.rs:3115` — `plan_modes` populates
  `Mutation::ApplyModes` with `setter: principal`, the acting principal
  resolved from the authorized command, and `created_at: inputs.utc_now`.
- `crates/agenc-ircd-domain/src/decision.rs:4224` and `:4247` — `apply_modes`
  destructures the batch and `apply_mode_change`'s `AddMask` arm constructs
  `ListEntry::new(entry_id, mask, setter, created_at.unwrap_or(channel.created_at))`.
  The setter is the acting operator. `Mutation::ApplyModes` is private to
  `decision.rs` and has no cross-crate or replication constructor, so
  `plan_modes` is its only producer.

The creation-time fallback that the finding also named is unreachable rather
than merely unused. `mode_requests`
(`crates/agenc-ircd-domain/src/decision.rs:4505`) pushes a `UtcNow` request
whenever the vector contains an `AddMask`, and `validate_requested_clocks`
(`:4586`) refuses the plan with `ExternalInputMismatch` unless the supplied
inputs match the requested clocks exactly. A mask cannot be added without a
trusted UTC read, so `unwrap_or` never selects the channel's creation time on
any reachable path. `external_input_validation_covers_every_shape_and_clock_combination`
in the same file covers the clock and entropy mismatch matrix.

**What changed here:** nothing. The finding is recorded as resolved.

**Test that proves it:** `mask_list_entries_record_the_operator_that_added_them`
(`crates/agenc-ircd-domain/src/decision.rs:10868`) drives a real MODE by a
member promoted to operator through `authorize`, `plan_authorized`,
`prepare_mutation` and `apply_prepared`, then asserts the stored entry's
setter equals the acting member's account, differs from the owner's account,
and carries the supplied UTC second rather than the channel's creation second.
Restoring the audited construction (`channel.creator` and `channel.created_at`)
as a temporary local mutation makes that test fail on the setter assertion;
the unmodified source passes.

## ZDH-C4 — secret versus nonexistent JOIN outcome divergence

**Status: no longer applies.** Disposed normatively by
`2eb0ae37127d9c66c4ec267dd0d0c60108e2f548` (PR #101, `20a1c90`) and repaired in
code by `539bf24a31f9b05a55c7124240157ce7269f73b0`
("Check the member ceiling only after hidden-channel authorization", PR #107,
`ecae28c`), both 2026-09-15, under RUN-01 (issue #44, closed).

The finding raised two distinct divergences: that an authenticated JOIN of a
secret `+i` channel answered with a refusal that differs from the unavailable
result, and that creating a free name is distinguishable from the refusal of a
held secret name.

Architecture Section 14.2 now carries one executable JOIN outcome matrix
(`docs/ircd-architecture-and-implementation-spec.md:2029`) that reconciles the
Section 13.1 creation rule with the Section 13.5 discovery rule. It requires
`SECRET_UNAVAILABLE` for every existing hidden channel the requester is not
authorized to enter, "whether the channel is banned, `+i`, or full", and
records absent-name creation as a documented outcome bounded only by the
requester's own session quota and the scope ceiling. That text explicitly
disposes ZDH-C4.

Code inspected at HEAD, `crates/agenc-ircd-domain/src/decision.rs`:

- `check_join_existing` (`:2919`) runs, in order: existing membership,
  `validate_guest_join` (`:4672`), invite resolution,
  `validate_hidden_channel_join` (`:4701`), the ban mask, then
  `validate_join_admission` (`:4720`). The `+i`, key, member-ceiling,
  `+l` and E2EE outcomes are all inside the last call, so none of them can be
  reached by a requester the hidden-channel decision has not already admitted.
  The ordering carries an explicit comment naming PRV-01 and Section 14.2.
- `channel_is_full` (`:4749`) applies both the channel's own `+l` and the
  configured `members_per_channel`, and is documented as reachable only after
  that admission.
- `plan_join_target` (`:2798`) applies the requester's own session channel
  ceiling before any target-specific work and the scope ceiling before
  creation, both identically for absent and existing names.

The error renderings match the matrix:
`crates/agenc-ircd-runtime/src/client_render.rs:150` maps `LimitExceeded` to
`SERVER_BUSY`, the ban and `+i` refusals to `482`, and `SecretUnavailable` to
the single channel-unavailable failure.

**What changed here:** nothing in production code.

**Test that proves it:** a new regression,
`hidden_invite_only_and_banned_joins_report_only_unavailability` in
`crates/agenc-ircd-testkit/tests/domain_secret_admission.rs`. The existing
RUN-01 regressions cover the *full* hidden channel and the guest and
unauthorized-account cases; the `+i` and ban rows of the matrix, which are the
two the finding named by error code, had no test of their own. The new one
builds a secret `+i` channel, an unlisted channel carrying a ban that matches
the visitor, and a listed `+i` control, then asserts that

- a guest and an authenticated non-member receive `SecretUnavailable` from
  both hidden channels and change no membership,
- the listed `+i` channel still reports its real refusal, so the identical
  pair above is a privacy decision and not a blanket error, and
- a requester the invite rules already admit (a `+I` match on the secret
  channel, an invitation on the banning one) joins the first and receives the
  real ban refusal from the second.

Restoring the audited ordering as a temporary local mutation — evaluating the
ban and admission checks before `validate_hidden_channel_join` — makes it fail
with `expected SecretUnavailable, got [Forbidden]`, the exact symptom the
finding described, and makes the existing
`full_hidden_channel_stays_unavailable_and_listed_capacity_is_reported` fail
with `got [LimitExceeded]`. The unmodified source passes both. The daemon-level
equivalent through the real binary is
`full_hidden_channel_join_is_unavailable_and_absent_name_is_created` in
`crates/agenc-ircd/tests/stage_six_daemon/runtime_regressions.rs`.

**Residual:** the Section 13.5 response floor is a separate, still-open item.
`privacy.secret_lookup_floor_milliseconds` is accepted by the configuration
(`crates/agenc-ircd-config/src/privacy.rs:60`) and
`SECRET_CHANNEL_FLOOR_MILLIS` and `TimerKind::SecretChannelFloor` exist
(`crates/agenc-ircd-runtime/src/state_core/timers.rs:26,65`), but nothing in
the runtime reads them. That is a timing property, not the outcome divergence
ZDH-C4 alleged; it is owned by RUN-06 (issue #60, open) and is untouched here.

## ZDH-C5 — named-LIST queries carry no privacy gate

**Status: no longer applies.** The name-resolving LIST path was introduced with
its privacy gate already in place by
`c93ccf30ba76719687a57029976b024289fcc521` ("Select LIST names before the
result ceiling and charge scan tokens before the scan", PR #110, `b9b373c`,
2026-09-15) under RUN-02 (issue #54, closed).

The finding was that `authorize_command` had no arm for
`CanonicalCommandData::List` and `project_channel_list` could not filter by the
command's name vector, so the privacy decision for a named LIST existed
nowhere and a daemon that later resolved names directly would confirm
secret-channel existence.

The second half was correct and is repaired. The first half is still literally
true and is correct by design: LIST answers a hidden name by omitting it, not
by refusing the command. An authorization arm would have to distinguish
absent from hidden in order to refuse, which is precisely the distinction
PRV-01 forbids, so the decision belongs in the projection.

Code inspected at HEAD, `crates/agenc-ircd-domain/src/projection.rs`:

- `select_channel_list(selected)` (`:407`) is the single selection API. With
  an empty selector it scans the bounded table prefix; with an explicit vector
  it resolves each name through `channel_names` and admits a row only when the
  channel exists *and* is `Visibility::Listed`. An absent name, a secret name
  and an unlisted name all fall through the same `continue`, producing no row,
  no count and no distinct shape.
- `list_scan_bound` (`:381`) and `list_query_tokens` (`:392`) derive the
  charge from the number of names requested, never from how many resolve, so
  the rate cost of a named LIST does not depend on whether the names exist.
- `project_channel_list` (`:372`) is now `select_channel_list(&[])`, the
  unselected page only.

Both renderers consume that one API:
`render_list_snapshot` (`crates/agenc-ircd-runtime/src/query_render.rs:118`)
sizes its snapshot from `list_scan_bound` and renders `scan.rows()`, and the
federated `list_frames` (`:1598`) does the same. The Listed-only gate is not
new — `project_channel_list` was already Listed-only at the audited commit
`99dd907` — so no hidden channel was ever in a rendered page; what RUN-02
added was the named selector, and it was written with the gate inside it.

**What changed here:** nothing in production code.

**Test that proves it:** a new daemon regression,
`named_list_answers_a_secret_name_exactly_like_an_absent_name` in
`crates/agenc-ircd/tests/stage_six_daemon/runtime_regressions.rs`. The domain
already pins the selection semantics
(`list_selection_hides_secret_unlisted_and_absent_names_identically` in
`crates/agenc-ircd-domain/src/decision.rs`), but the finding's claim was
specifically about a daemon resolving names directly, and no test covered a
named LIST through the real binary. The new one drives the production daemon
over TLS: an account owner creates a secret channel and a listed one, an
unrelated authenticated account then issues a named LIST for the secret name
and a named LIST for a name that does not exist, and the two frame sequences
must be equal. It also asserts that the same query shape returns the row of
the listed channel, so the equality is a privacy decision rather than a dead
selector, and that the unselected page omits the secret channel.

Removing the `Visibility::Listed` condition from the named branch of
`select_channel_list` as a temporary local mutation makes it fail with the
secret channel's `322` row present on one side and absent on the other. The
unmodified source passes.

**Note:** RUN-02 also reproduced and fixed separate named-LIST truncation and
scan-charging defects. Those were never part of ZDH-C5 and are recorded in
[the LIST selection repair](stage-10-list-selection-repair.md).

## ZDH-A1 — invitation validity frozen at START

**Status: no longer applies.** Repaired under ENC-12 (issue #38, closed) by
`6b07e2e758ff55fdd6555030d1ac3335a24b3526` and
`d5d5f06258f731d62e9c41c5af764042f7b89e74`, merged in PR #93 (`8c09bc3`,
2026-09-15).

The finding was that `evaluate_creation_invitation` ran only inside
`begin_account_creation`, so a creation transaction straddling `expires_at` or
`not_before` could commit an account under an invitation that was invalid at
commit time.

Code inspected at HEAD:

- `crates/agenc-ircd-auth/src/invitation.rs:34` — `invitation_interval_admits`
  is the single exported predicate for the Section 11.3 rule
  `not_before <= now < expires_at`. START verification, the FINISH recheck and
  the runtime's durable admission all call it.
- `crates/agenc-ircd-auth/src/service.rs:603` — `evaluate_creation_invitation`
  now records `not_before` beside `expires_at` in `ValidatedInvitation`, so
  the interval survives into the transaction rather than only its identifier
  and expiry.
- `crates/agenc-ircd-auth/src/service.rs:650` —
  `finish_account_creation_with_entropy` rechecks the interval against
  `context.now_utc`, the trusted UTC read taken when FINISH is opened, after
  the frozen START disposition and before an account identifier is drawn. A
  refusal returns the same fixed-size rejected completion as every other
  semantic rejection; the transaction is already consumed, so the one-use
  FINISH is spent and no `CreateAccountIntent` exists.
- `crates/agenc-ircd-runtime/src/account_service.rs:4371` — the same predicate
  is re-evaluated with a fresh trusted UTC read immediately before the finish
  durable set is staged, so latency between the worker's check and staging
  cannot carry an expired invitation into a commit. A reading outside the
  interval, or an unavailable trusted clock, fails closed.

**What changed here:** nothing. The full repair is recorded in
[the invitation FINISH repair](stage-10-invitation-finish-repair.md).

**Test that proves it:**
`invited_finish_at_or_after_expiry_is_rejected_inside_the_transaction_ttl` and
`invited_finish_boundaries_follow_the_exact_interval_and_spare_unrelated_creations`
in `crates/agenc-ircd-auth/tests/stage_four.rs`, with restart coverage in
`restored_invited_creation_rechecks_the_invitation_interval_at_finish`
(`crates/agenc-ircd-auth/tests/stage_four_restart_records.rs`) and durable
admission coverage in
`crates/agenc-ircd-runtime/src/account_service/tests/invitation_window.rs`.
Disabling the FINISH predicate as a temporary local mutation makes both
`stage_four` tests fail with
`assertion left == right failed: FINISH at UTC 20 must reject the expired
invitation; left: None, right: Some(InvitationRejected)`. The unmodified
source passes.

## Disposition

| Finding | Status at `fb618ab` | Resolved by |
| --- | --- | --- |
| ZDH-C3 | No longer applies | `cc57214` (PR #17) |
| ZDH-C4 | No longer applies | `2eb0ae3` (PR #101) and `539bf24` (PR #107) |
| ZDH-C5 | No longer applies | `c93ccf3` (PR #110) |
| ZDH-A1 | No longer applies | `6b07e2e` and `d5d5f06` (PR #93) |

Issue #13 also records the Section 13.5 response floor as a remaining
constraint on the C4 disposition. That work is RUN-06 (issue #60) and is not
started; it is a best-effort timing floor, not an outcome guarantee, and no
finding in this record depends on it.

## Validation

```sh
cargo fmt --all
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python3 scripts/check-source.py check
cargo test -p agenc-ircd-testkit --locked
cargo test -p agenc-ircd --locked
cargo test -p agenc-ircd-domain --locked
cargo test -p agenc-ircd-auth --locked
```

Formatting is clean, all-target Clippy with warnings denied passes across the
workspace, and the source policy passes over 965 Rust files. The two crates
carrying the new regressions pass in full: `agenc-ircd-testkit` passes 121
tests with no failures and none ignored, and `agenc-ircd` passes 54 tests with
no failures and 18 default-ignored qualification scenarios, including the
61-second `stage_six_daemon` suite that carries the new named-LIST regression.
The two crates whose sources the falsification experiments touched were
restored and re-run: `agenc-ircd-domain` passes 171 tests and `agenc-ircd-auth`
80 tests with one ignored vector generator, both with no failures.

No production source, wire format, numeric, reply code, registry, configured
limit, rate table, dependency pin or storage growth limit is changed by this
work, so no coverage region digest, requirement binding or specification pin
moves. The full implementation gate was not run for this record.
