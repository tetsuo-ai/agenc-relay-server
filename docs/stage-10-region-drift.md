# Stage 10 release-critical region drift

This record covers COV-07 (issue #145). It is the second half of the defect
COV-06 (#142) opened. A release-critical region names a file and a line span,
and that span is what the release claims was reviewed. When the file grows
above the span, the row keeps pointing at line numbers that now hold other
code. COV-06 moved the ten rows whose drift landed on non-executable text,
because those produce a visible refusal. The rows here drifted onto executable
code, so nothing refuses: each one scores, and the number it reports describes
an item its row never declared.

Nothing here changes a production handler, adds a test, lowers a floor or
deletes a reviewed row. Every change is to
`conformance/release-critical-coverage.toml`,
`conformance/critical-coverage.toml` and `scripts/check-coverage.py`, and every
score below is bound to one measurement.

## How the report was produced

One report, on the pinned nightly that carries `-C instrument-coverage` branch
support, with `cargo-llvm-cov 0.9.0`. It is a whole-workspace all-target
report, which is the only report `check-coverage.py check` can run to
completion: a `--lib` report omits `crates/agenc-relay-server/src/main.rs` entirely and
refuses before scoring anything.

```sh
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  --workspace --all-features --branch --json \
  --output-path wt64-cov-all.json -- --skip qualification_workload
```

Every "Was" figure below is that report read at the row's old span and every
"Now" figure is that same report read at the row's new span. No source changed
between the two readings, so the two columns are the same measurement of the
same build seen through two different spans. That report reads 76.1827 percent
branches, 91.7469 percent lines and 86.2036 percent regions over the workspace.

## The defect, and how it survived the staleness check

`verify-regions.py` compared each row's `source_sha256` against its file and
checked that `end_line` exists. Both pass after a routine re-anchor that
refreshes the hash without moving the lines, which is exactly what the tooling
did. Commit `4bcf230` is the worked example: it inserted thirty-six lines into
`crates/agenc-relay-runtime/src/e2ee/edge/witness_failure.rs` and refreshed
every affected row's `source_sha256` to the new file while leaving every
`start_line` and `end_line` where they were. At the parent commit `52808b9`,
`cap74-witness-failure-witness-pending` read exactly `witness_pending` at
47-53. Today `witness_pending` is at 83-89, and 47-53 is a blank line, a doc
comment and the opening of `forget_durable`.

So the file hash proves the file is the one that was reviewed. It does not
prove the span still covers the item that was reviewed, and until this change
nothing else did either. The same insertion shifts every row below it by the
same amount, which is why the drift arrives in whole files at once: all ten
rows in `federation/coordinator/companion.rs` are displaced by exactly
thirty-four lines, and all nine in `witness_failure.rs` by exactly thirty-six.

## What the audit found

The audit is independent of the coverage report. It reads only the policy and
the sources, and asks whether the item a row names is still inside the row's
span, or whether the span lies inside that item. The version COV-06 ran derived
the item from the row's `id`, which is a guess, and its count was reported as
sixty-seven. Re-running it here with the item's full extent rather than only
its declaration line flags **sixty-eight** rows. Each of the sixty-eight was
then decided against the history of `conformance/release-critical-coverage.toml`
itself: the commit that introduced the row is read, and the source at that
commit is read at the row's span, which says without guessing what the row was
anchored to when it was written.

That history gives three answers.

- **Fifty-nine rows have genuinely drifted.** Each was written on the
  declaration line of a named item, the file grew above it, and the span now
  holds other code. These are re-anchored below.
- **Eight rows never named the item the `id` suffix suggests.** Their spans have
  covered the same item since the commit that introduced them; the audit's
  `id`-derived guess matched an unrelated helper whose name happens to be the
  `id`'s last word. They are listed below unchanged, and each now declares the
  item it has always held, which is what removes them from the audit for good.
- **One row's item was renamed underneath it.** `storage-execute-restore-command`
  was written on `pub fn execute_restore_command` at 129-183. That body was
  later renamed `execute_restore_admitted` behind an identically-signed
  `execute_restore_command` entry point that delegates to it unconditionally,
  and the re-anchor tooling followed the body. Its span is unchanged and now
  declares `execute_restore_admitted`, the body the row reviews. Moving it onto
  the six-line delegator was measured and rejected: that span matches no
  executable coverage data at all, so the row would refuse rather than score,
  and the reviewed claim — "restore composes trust keys, fencing, and the
  construction ledger" — is false of a delegator.

So sixty-seven was an overcount by nine and an undercount by one. The one the
`id`-derived audit missed is `cap101-sequencer-eligibility-001-selected-credential`,
which COV-06 filed as one of COV-05's deliberate narrowings. It is not one:
COV-05 narrowed four rows and that is not among them. Its span is 15-41 and
`selected_credential` is 13-39, so the span excludes the function's first two
lines and runs two lines past its closing brace onto a blank line and a doc
comment.

## The fifty-nine rows re-anchored here

Each row below was re-anchored onto the item its `id`, `category` and `reason`
name, that item was read, and the row's claim was confirmed to hold over the
span it now covers. Each row's `reason` records the move and the re-review, and
names the score where the row does not reach 100 percent. No span was widened.

#### `crates/agenc-relay-runtime/src/federation/coordinator/companion.rs` (10)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap79-fresh-object-018-run` | 447-455 | 481-489 | `run` | `regions` | 1/1 | 9/9 |
| `s10-cap70-receipt-committed-ack` | 658-685 | 692-719 | `committed_ack` | `branches` | 6/10 | 3/4 |
| `cap79-fresh-object-020-request-committed` | 689-720 | 723-754 | `request_committed` | `regions` | 32/38 | 24/31 |
| `cap79-fresh-object-021-send-response` | 722-744 | 756-778 | `send_response` | `regions` | 16/23 | 25/33 |
| `cap78-companion-schedule-mailbox-expiry` | 746-772 | 780-806 | `schedule_mailbox_expiry` | `regions` | 27/27 | 18/25 |
| `cap78-companion-mailbox-timer-fired` | 774-787 | 808-821 | `mailbox_timer_fired` | `regions` | 9/17 | 0/13 |
| `companion-companion-snapshot-timer-fired` | 822-848 | 856-882 | `snapshot_timer_fired` | `regions` | 18/32 | 0/33 |
| `companion-companion-continue-snapshot` | 878-908 | 912-942 | `continue_snapshot` | `regions` | 23/33 | 45/53 |
| `companion-companion-send-page` | 911-936 | 945-970 | `send_page` | `regions` | 40/42 | 23/32 |
| `companion-companion-continue-fetch` | 938-971 | 972-1005 | `continue_fetch` | `regions` | 27/42 | 0/55 |

#### `crates/agenc-relay-runtime/src/e2ee/edge/witness_failure.rs` (9)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap74-witness-failure-witness-pending` | 47-53 | 83-89 | `E2eeEdge::witness_pending` | `regions` | 4/4 | 8/8 |
| `cap74-witness-failure-prepare-witness-retry` | 55-70 | 91-106 | `E2eeEdge::prepare_witness_retry` | `regions` | 12/14 | 16/16 |
| `cap74-witness-failure-arm-witness-retry` | 72-90 | 108-126 | `E2eeEdge::arm_witness_retry` | `regions` | 9/9 | 25/26 |
| `cap74-witness-failure-record-witness` | 92-112 | 128-153 | `E2eeEdge::record_witness` | `regions` | 21/21 | 20/20 |
| `cap74-witness-failure-try-witness-stage` | 114-150 | 155-191 | `E2eeEdge::try_witness_stage` | `regions` | 33/34 | 47/52 |
| `cap74-witness-failure-witness-timer-fired` | 152-177 | 193-222 | `E2eeEdge::witness_timer_fired` | `regions` | 38/41 | 32/34 |
| `cap74-witness-failure-witness-batch-applied` | 179-214 | 224-261 | `E2eeEdge::witness_batch_applied` | `regions` | 34/36 | 41/44 |
| `cap74-witness-failure-witness-rejection` | 218-225 | 265-272 | `E2eeEdge::witness_rejection` | `regions` | 7/8 | 11/14 |
| `cap74-witness-failure-witness-batch-rejected` | 227-240 | 274-287 | `E2eeEdge::witness_batch_rejected` | `regions` | 12/12 | 12/14 |

#### `crates/agenc-relay-runtime/src/e2ee/edge/witness_recovery.rs` (8)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap74-witness-recovery-pending` | 23-25 | 25-27 | `WitnessRecovery::pending` | `regions` | 1/1 | 5/5 |
| `cap74-witness-recovery-install-backing` | 27-36 | 71-80 | `WitnessRecovery::install_backing` | `regions` | 7/7 | 9/10 |
| `cap74-witness-recovery-restore` | 38-50 | 82-94 | `WitnessRecovery::restore` | `regions` | 15/15 | 17/17 |
| `cap74-witness-recovery-reserve-one` | 52-72 | 96-116 | `WitnessRecovery::reserve_one` | `regions` | 8/19 | 28/31 |
| `cap74-witness-recovery-grow` | 74-89 | 118-133 | `WitnessRecovery::grow` | `regions` | 12/13 | 31/35 |
| `cap74-witness-recovery-insert-reserved` | 91-114 | 135-158 | `WitnessRecovery::insert_reserved` | `regions` | 31/34 | 14/22 |
| `cap74-witness-recovery-restore-witness-backing` | 118-123 | 162-167 | `super::restore_witness_backing` | `regions` | 14/15 | 5/5 |
| `cap74-witness-recovery-restore-chain-witness` | 125-132 | 169-176 | `super::restore_chain_witness` | `regions` | 13/16 | 9/10 |

#### `crates/agenc-relay-runtime/src/e2ee/coordinator/sync.rs` (5)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `companion-sync-companioncoordinator-state-fetch` | 821-838 | 843-860 | `CompanionCoordinator::state_fetch` | `regions` | 0/32 | 13/14 |
| `companion-sync-companioncoordinator-snapshot-expired` | 957-969 | 979-991 | `CompanionCoordinator::snapshot_expired` | `regions` | 31/35 | 14/15 |
| `companion-sync-companioncoordinator-accepting-requests` | 1018-1022 | 1040-1044 | `CompanionCoordinator::accepting_requests` | `regions` | 4/4 | 8/8 |
| `companion-sync-companioncoordinator-link-lost` | 1032-1045 | 1054-1070 | `CompanionCoordinator::link_lost` | `regions` | 14/14 | 21/22 |
| `companion-sync-require-cut-scope` | 1176-1188 | 1201-1213 | `require_cut_scope` | `regions` | 19/20 | 10/10 |

#### `crates/agenc-relay-runtime/src/federation/coordinator/mod.rs` (5)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap79-mailbox-expiry-027-batch-applied` | 1401-1408 | 1416-1423 | `FederationCoordinator::batch_applied` | `regions` | 6/6 | 20/21 |
| `s10-cap70-base-ack-delivery-ack-receipt` | 1493-1508 | 1509-1524 | `FederationCoordinator::delivery_ack_receipt` | `branches` | 0/2 | 3/4 |
| `cap79-maintenance-055-replay-io-busy` | 1589-1594 | 1608-1613 | `FederationCoordinator::replay_io_busy` | `regions` | 8/8 | 10/10 |
| `cap81-mod-federationcoordinator-batch-rejected-with-error` | 1619-1629 | 1638-1648 | `FederationCoordinator::batch_rejected_with_error` | `regions` | 13/14 | 16/16 |
| `cap79-maintenance-057-reject-origin-acknowledgement` | 1721-1730 | 1750-1759 | `FederationCoordinator::reject_origin_acknowledgement` | `regions` | 10/10 | 11/12 |

#### `crates/agenc-relay-runtime/src/federation/coordinator/startup/retirement.rs` (4)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `companion-retirement-committed` | 133-166 | 196-235 | `committed` | `regions` | 38/49 | 42/51 |
| `companion-retirement-rejected` | 168-187 | 237-256 | `rejected` | `regions` | 18/21 | 0/23 |
| `companion-retirement-retryable` | 189-198 | 258-267 | `retryable` | `regions` | 5/6 | 0/4 |
| `companion-retirement-retry` | 200-206 | 269-275 | `retry` | `regions` | 8/8 | 0/9 |

#### `crates/agenc-relay-runtime/src/e2ee/coordinator/ops/sequence.rs` (3)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `coordinator-bootstrap-dual-council` | 228-253 | 253-267 | `resulting_council` | `branches` | 2/2 | 2/2 |
| `cap99-ack-context-010-submit-reinit-ack` | 1110-1192 | 1203-1285 | `submit_reinit_ack` | `regions` | 110/126 | 125/140 |
| `cap79-fresh-object-012-fetch-object` | 1490-1526 | 1583-1619 | `fetch_object` | `regions` | 49/57 | 56/65 |

#### `crates/agenc-relay-runtime/src/e2ee/coordinator/sequencer_signing.rs` (3)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap101-sequencer-eligibility-001-selected-credential` | 15-41 | 13-39 | `selected_credential` | `regions` | 28/29 | 29/30 |
| `cap101-sequencer-eligibility-002-at-time` | 44-48 | 109-117 | `at_time` | `regions` | 1/1 | 18/21 |
| `cap101-terminal-key-001-for-receipt` | 51-58 | 121-126 | `for_receipt` | `regions` | 15/15 | 7/7 |

#### `crates/agenc-relay-runtime/src/e2ee/coordinator/recovery_gates.rs` (2)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap73-declared-head-predicate-001-matches-restored-heads` | 167-171 | 175-179 | `matches_restored_heads` | `regions` | 3/3 | 5/5 |
| `cap73-declared-gates-007-states` | 173-180 | 181-188 | `states` | `regions` | 6/6 | 7/7 |

#### `crates/agenc-relay-runtime/src/state_core/mod.rs` (2)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `companion-mod-statecorecontext-backing-reservations` | 838-840 | 860-862 | `StateCoreContext::backing_reservations` | `regions` | 0/9 | 5/5 |
| `cap13-mod-complete-index-refresh` | 3835-3877 | 3916-3958 | `StateCore::complete_index_refresh` | `regions` | 53/60 | 35/45 |

#### `crates/agenc-relay-e2ee/src/record_authentication.rs` (1)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap73-record-authentication-001-authenticate-record` | 67-96 | 111-127 | `authenticate_record` | `regions` | 26/29 | 23/23 |

#### `crates/agenc-relay-runtime/src/daemon.rs` (1)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `companion-daemon-attach-coordinator-role` | 1294-1334 | 1383-1423 | `attach_coordinator_role` | `regions` | 52/55 | 54/59 |

#### `crates/agenc-relay-runtime/src/e2ee/edge/mod.rs` (1)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap74-mod-is-active` | 278-280 | 320-322 | `E2eeEdge::is_active` | `regions` | 3/3 | 5/5 |

#### `crates/agenc-relay-runtime/src/e2ee/edge/sync.rs` (1)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap74-sync-fail-frame` | 209-217 | 235-243 | `E2eeEdge::fail_frame` | `regions` | 16/16 | 16/16 |

#### `crates/agenc-relay-runtime/src/federation/coordinator/mailbox_expiry.rs` (1)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap79-mailbox-expiry-023-rejected` | 172-178 | 181-187 | `rejected` | `regions` | 12/12 | 5/5 |

#### `crates/agenc-relay-runtime/src/federation/coordinator/replay_maintenance/receipt.rs` (1)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap79-maintenance-045-rejected` | 97-103 | 114-120 | `rejected` | `regions` | 11/12 | 5/5 |

#### `crates/agenc-relay-runtime/src/federation/coordinator/request_expiry.rs` (1)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap79-request-expiry-015-rejected` | 172-178 | 181-187 | `rejected` | `regions` | 12/12 | 5/5 |

#### `crates/agenc-relay-runtime/src/registration.rs` (1)

| Region | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- |
| `cap13-registration-index-refreshed` | 3142-3147 | 3186-3191 | `RegistrationRouter::index_refreshed` | `regions` | 7/8 | 12/12 |

## The nine rows whose span was already right

These are the audit's own false positives, kept here because the audit is the
instrument and its error rate is part of the record. Eight are rows whose `id`
ends in a word that is also the name of an unrelated helper somewhere in the
same file; the ninth is the renamed body. Every one of the nine has held the
same item since the commit that introduced it, so no span moves and no
re-review of a moved span is claimed. Each now declares that item, which is
what takes it out of the audit permanently.

| Region | File | Span | The item the span holds | The word the `id` ends in | Score |
| --- | --- | --- | --- | --- | --- |
| `account-suspension-revision` | `model.rs` | 1793-1807 | `DomainState::admin_suspend_account` | `revision` | 17/17 |
| `account-restoration-revision` | `model.rs` | 1810-1822 | `DomainState::admin_restore_account` | `revision` | 2/2 |
| `sequencer-opened-credential` | `sequencer.rs` | 84-99 | `verify_opened_credential` | `credential` | 10/10 |
| `sequencer-opened-key-set` | `sequencer.rs` | 149-191 | `SequencerKeySet::verify_opened` | `set` | 4/4 |
| `runtime-opaque-record-account-binding` | `account_service.rs` | 6941-6955 | `opaque_record_matches_account` | `binding` | 9/10 |
| `runtime-opaque-record-account-generation` | `account_service.rs` | 6957-6965 | `opaque_version_precedes_account` | `generation` | 6/6 |
| `remote-account-registered-carrier` | `remote_accounts.rs` | 332-366 | `bind_registered_carrier` | `carrier` | 7/10 |
| `credential-replayed-terminal-outcome` | `remote_accounts.rs` | 496-504 | `credential_changed` | `outcome` | 2/2 |
| `storage-execute-restore-command` | `restore_command.rs` | 138-193 | `execute_restore_admitted` | `command` | 3/4 |

`sequencer-opened-key-set` is the one of the nine whose covered code was split
rather than renamed: it was written on `pub fn verify_opened` at 149-191, and
that function is now `verify_opened` at 149-161 followed by `chain` at 164-191.
The span still covers both halves, which is exactly the claim the row states —
an opened set verifies its first credential and chains at most one successor
from it — so the span stands and the row declares `verify_opened`.

## What the correction cost

Of the fifty-nine rows moved, fifty-seven read a different number at their
correct span than at the lines they had drifted onto. **Nine read 100 percent
at lines they do not describe and read below 100 percent at the lines they do.**

| Region | At the drifted span | At its own item |
| --- | --- | --- |
| `cap78-companion-schedule-mailbox-expiry` | 27/27 | 18/25 |
| `companion-retirement-retry` | 8/8 | 0/9 |
| `cap101-sequencer-eligibility-002-at-time` | 1/1 | 18/21 |
| `cap79-mailbox-expiry-027-batch-applied` | 6/6 | 20/21 |
| `cap74-witness-failure-arm-witness-retry` | 9/9 | 25/26 |
| `cap74-witness-failure-witness-batch-rejected` | 12/12 | 12/14 |
| `cap74-witness-recovery-install-backing` | 7/7 | 9/10 |
| `cap79-maintenance-057-reject-origin-acknowledgement` | 10/10 | 11/12 |
| `companion-sync-companioncoordinator-link-lost` | 14/14 | 21/22 |

Eight rows move the other way and reach 100 percent only once correctly
anchored: `cap13-registration-index-refreshed`,
`cap73-record-authentication-001-authenticate-record`,
`cap74-witness-failure-prepare-witness-retry`,
`cap74-witness-recovery-restore-witness-backing`,
`cap79-maintenance-045-rejected`,
`cap81-mod-federationcoordinator-batch-rejected-with-error`,
`companion-mod-statecorecontext-backing-reservations` and
`companion-sync-require-cut-scope`.

Six rows measure **zero** at their own item. Each had been reporting a partial
or full score for code belonging to some other function, and none of the six
functions is reached by any test in the report at all:
`cap78-companion-mailbox-timer-fired` 0/13,
`companion-companion-snapshot-timer-fired` 0/33,
`companion-companion-continue-fetch` 0/55,
`companion-retirement-rejected` 0/23, `companion-retirement-retryable` 0/4 and
`companion-retirement-retry` 0/9. That is the sharpest illustration of the
defect: the mailbox expiry timer, the companion snapshot expiry timer, the
companion fetch continuation and three quarters of the startup retirement
protocol are release-critical and untested, and the policy has been reporting
otherwise.

Over the whole policy, `check-coverage.py check` on the one report moves from
**635 failure items to 636**: one floor (branch coverage 76.18 percent against
the 90 percent release floor) and 634 rows below 100 percent before, the same
floor and 635 rows below 100 percent after. Nine rows newly fail and eight
newly pass. No row matches no executable data and no declaration is unscoreable
in either reading.

## What is still failing

Thirty-six of the fifty-nine stay below 100 percent at their correct span. They
are decided under the rule COV-05 established and COV-06 kept: narrow only when
every uncovered entry is provably unreachable and sits at the boundary of the
span, otherwise leave the row failing with its score named in its own `reason`.
No row here satisfies that test, so no span is narrowed. The owed entries fall
into five groups.

- **Six functions no test reaches at all**, listed above. Their owed entry is
  the whole function, and the remedy is a test, not a span.
- **Link-failure and send-failure arms** that are reachable and are ordinary
  test work: `cap79-fresh-object-020-request-committed` 24/31 and
  `cap79-fresh-object-021-send-response` 25/33 (the `fail_link` and
  `send_failed` paths), `companion-companion-send-page` 23/32 and
  `companion-companion-continue-snapshot` 45/53 (the same two),
  `companion-retirement-committed` 42/51 (two `fail_restore` refusals and the
  signers discriminant), `cap78-companion-schedule-mailbox-expiry` 18/25 (the
  absent-executor return, the empty next-expiry and the timer reservation
  failure).
- **Arithmetic and allocation ceilings**: `cap74-witness-recovery-reserve-one`
  28/31 and `cap74-witness-recovery-grow` 31/35 (`checked_add` overflow,
  `LimitExceeded` and `MemoryExhausted`),
  `cap74-witness-failure-arm-witness-retry` 25/26 (one `Overflow`),
  `cap74-witness-recovery-insert-reserved` 14/22 (the occupied-slot arm and its
  `InvalidValue` refusals), `cap74-witness-recovery-install-backing` 9/10 (the
  second install refusal), `cap13-mod-complete-index-refresh` 35/45 (four
  `IndexRefreshFailed` corruptions and the durable-failure arm).
- **`?` propagations inside a decode or encode** that the row is reviewed for
  and that no narrower span excludes: `cap99-ack-context-010-submit-reinit-ack`
  125/140, `cap79-fresh-object-012-fetch-object` 56/65,
  `cap101-sequencer-eligibility-002-at-time` 18/21,
  `cap101-sequencer-eligibility-001-selected-credential` 29/30,
  `cap74-witness-recovery-restore-chain-witness` 9/10,
  `companion-daemon-attach-coordinator-role` 54/59 and
  `cap74-witness-failure-try-witness-stage` 47/52.
- **Single reachable refusals** that are one test each:
  `cap74-witness-failure-witness-timer-fired` 32/34,
  `cap74-witness-failure-witness-batch-applied` 41/44,
  `cap74-witness-failure-witness-rejection` 11/14,
  `cap74-witness-failure-witness-batch-rejected` 12/14,
  `companion-sync-companioncoordinator-state-fetch` 13/14,
  `companion-sync-companioncoordinator-snapshot-expired` 14/15,
  `companion-sync-companioncoordinator-link-lost` 21/22,
  `cap79-mailbox-expiry-027-batch-applied` 20/21,
  `cap79-maintenance-057-reject-origin-acknowledgement` 11/12,
  `s10-cap70-receipt-committed-ack` 3/4 (the barrier apply failure) and
  `s10-cap70-base-ack-delivery-ack-receipt` 3/4 (the non-matching pending
  commit).

## The mechanism that closes the hole

A row is now bound to its item rather than to a line range. Every region in
both policies carries two new fields:

```toml
item = "witness_pending"
span_sha256 = "41bd098656a7d1cc3cf3e8dbf518f20b46a9f340868a2f1b541f0af41a557898"
```

- `span_sha256` is the SHA-256 of the span's own bytes, lines `start_line`
  through `end_line` inclusive. It is invariant under every edit that does not
  touch the reviewed lines: text inserted above the span moves the span, and
  re-anchoring it back onto the same text leaves the hash unchanged. It changes
  only when the reviewed text itself changes, which is exactly when a
  re-review is owed. This is what makes the failure of `4bcf230` impossible:
  refreshing the file hash while leaving the line range now leaves lines 47-53
  hashing to a blank line, a doc comment and the opening of `forget_durable`
  rather than to `witness_pending`, and the policy is refused.
- `item` is the name of the Rust item the span is anchored to. The span must
  declare that item or lie inside it. This is the semantic half: it survives a
  reformat that changes the span's bytes, it states in the policy what the
  `id` could only imply, and it is what the audit reads instead of guessing.

Both are checked by `validate_policy_data` in `scripts/check-coverage.py`, so
both run on every `check` and every `self-test` invocation, which is how the
gate already calls it. `check-coverage.py` gained a Rust item locator for this:
`source_items` finds every `fn`, `struct`, `enum`, `union`, `trait`, `type`,
`const` and `static` with its first and last line, scanning braces over a copy
of the source with comments and literals blanked in place. `impl` and `mod`
blocks are deliberately excluded, because they enclose most of a file and a
span inside one would bind to it however far it had drifted.

The refusals are:

```
coverage region <id> has a stale span hash, so lines <start>-<end> of <file>
are no longer the reviewed text; the span was displaced by an edit above it and
must be re-anchored onto the item it names and re-reviewed

coverage region <id> names the item <item> but its span <file>:<start>-<end>
neither declares it nor lies inside it, so the row scores against code it never
declared and must be re-anchored onto that item and re-reviewed
```

The self-test grew from 26 to 28 rejection cases: one seeds a span hash that
does not match its lines, and one moves a row's `item` to an item defined
outside the span, which is the same displacement seen from the item's side.

`check-coverage.py` also gained an `audit` subcommand, so the audit is runnable
on its own without any coverage report:

```sh
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
# region anchors: ok (1144 reviewed spans hold the item they name)
```

The out-of-tree tooling moved with it. `verify-regions.py` checks the span hash
and the item bind as well as the file hash. `reanchor.py` may now move a span
only by finding the exact reviewed text again, verifies that the relocated span
still hashes to the reviewed span hash and still holds the named item, and
exits nonzero when any region needs manual re-anchoring — so it can no longer
refresh a file hash while leaving a stale line range, which is the specific
operation that produced all of this.

## The audit at the end

```
python3 scripts/check-coverage.py audit conformance/critical-coverage.toml
# region anchors: ok (21 reviewed spans hold the item they name)
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
# region anchors: ok (1144 reviewed spans hold the item they name)
```

Zero drifted rows in either policy, over all 1165 rows.

## Limitations

- A row is re-reviewed here only against the item its `id`, `category` and
  `reason` name. Where one `reason` is shared by a family of rows, the
  re-review confirms that the row's own item carries the part of that sentence
  the `id` names, not that the sentence is the best description of the family.
- Thirty-six rows stay below 100 percent at their correct span, six of them at
  zero. Nothing here tests them; each names its score in its own `reason` and
  the owed entries are grouped above.
- The item bind accepts a span that covers its item's declaration without
  covering the whole item, which is what lets a row narrow deliberately to a
  block inside a function, as COV-05's four narrowings do. A stricter reading,
  requiring every span to be a whole number of complete items, flags a further
  eighty-eight rows across twenty-nine files whose spans are offset from their
  item by a line or two while still covering its declaration, none of them a
  row this change touched. Those are not
  moved here: they are not this issue's class, they score against the item they
  name, and `span_sha256` now stops any new one from appearing silently.
- The `id`-derived form of the audit is a lower bound and was shown here to be
  imprecise in both directions. It is retained only as the historical
  instrument; the audit that runs in the gate reads the declared `item`.
- No overall floor is claimed. Branch coverage is 76.18 percent against a 90
  percent floor and the integrated verdict remains COV-04's (#73).

## Evidence

```sh
python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
# coverage self-test: ok (28 rejection cases)

python3 scripts/check-coverage.py audit conformance/critical-coverage.toml
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
# region anchors: ok (1144 reviewed spans hold the item they name)

RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  --workspace --all-features --branch --json \
  --output-path wt64-cov-all.json -- --skip qualification_workload

python3 scripts/check-coverage.py check wt64-cov-all.json \
  conformance/release-critical-coverage.toml
# coverage check failed, with 636 items:
#   1 floor: branch coverage 76.18% is below 90.00% (the line floor passes)
#   0 matched-no-executable rows, 0 anchored-on-non-executable-text rows
#   0 unscoreable-as-declared rows
#   635 rows below 100.00%
# Before this change the same report and the same build gave 635 items, with
# fifty-nine of them scored against an item their row never declared.

python3 scripts/check-source.py check
# source policy: ok (1003 Rust files)
```
