# Stage 10 release-critical region anchors

This record covers COV-06 (issue #142). A release-critical region names a file
and a line span, and that span is what the release claims was reviewed. COV-01
(#66), COV-02 (#72) and COV-05 (#135) each found rows whose span is not the
item the row's `reason` describes, and each deliberately recorded them rather
than moving them, because moving a reviewed span asserts a review over lines
nobody looked at. This record moves them, says which item each span now
covers, and states that the span it now covers was re-reviewed as part of this
change.

Nothing here changes a production handler, adds a test, lowers a floor or
deletes a reviewed row. Every change is to
`conformance/release-critical-coverage.toml` and to
`scripts/check-coverage.py`, and every score below is bound to one
measurement.

## How the report was produced

One report, on the pinned nightly that carries `-C instrument-coverage` branch
support, with `cargo-llvm-cov 0.9.0`. It is a whole-workspace all-target
report, which is the only report `check-coverage.py check` can run to
completion: a `--lib` report omits `crates/agenc-ircd/src/main.rs` entirely and
refuses before scoring anything.

```sh
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  --workspace --all-features --branch --json \
  --output-path wt62-cov-all.json -- --skip qualification_workload
```

Every "Was" figure below is that same report read at the row's old span, and
every "Now" figure is that same report read at the row's new span. No source
changed between the two readings, so the two columns are the same measurement
of the same build seen through two different spans.

## The defect, and how the spans drifted

The nine rows COV-05 tabulated were anchored on a doc comment, on rows of a
`static` prefix table, on a `struct` or `enum` declaration, or on struct
fields. `edge-origin-settled-gate` was anchored on two argument lines inside
the `SubmitKind::Membership` decode arm of `submitted_identifier`, while its
reason describes `settled()` seventeen lines later. None of them is a metric
defect: correcting the metric changes nothing, because the span holds no
executable item to score.

The cause is not authoring error. Every one of these spans was correct when it
was written, and the file then grew above it. Commit `4bcf230` ("Resolve
durable edge witnesses with authenticated record ancestry") is the clearest
case: it inserted thirty-six lines into
`crates/agenc-ircd-runtime/src/e2ee/edge/witness_failure.rs` and refreshed
every affected row's `source_sha256` to the new file, but left every
`start_line` and `end_line` where they were. At the parent commit `52808b9`,
`cap74-witness-failure-witness-pending` reads exactly `witness_pending` at
47-53; today lines 47-53 are a blank line, a doc comment and the opening of
`forget_durable`, and `witness_pending` is at 83-89.

Refreshing the hash without moving the span defeats the only staleness check
the repository has. `verify-regions.py` compares each row's `source_sha256`
against its file and checks that `end_line` exists; both pass after such a
refresh, so the row looks current while pointing at whatever now occupies
those line numbers. A row that lands on other executable code is worse than
one that lands on a doc comment, because it scores, and the number it produces
describes an item nobody declared.

## The thirty-five rows re-anchored here

Each row below was re-anchored onto the item its `id`, `category` and `reason`
name, that item was read, and the row's claim was confirmed to hold over the
span it now covers. Each row's `reason` records the move and the re-review.

### The ten rows issue #142 names (10)

| Region | File | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cap73-declared-gates-011-admit-restored-with-backing` | `mod.rs` | 478-492 | 555-569 | `CompanionCoordinator::admit_restored_with_backing` | `regions` | no data | 12/12 |
| `cap79-result-memory-005-set-backing` | `startup.rs` | 127-130 | 132-135 | `Restore::set_backing` | `regions` | no data | 8/8 |
| `edge-origin-settled-gate` | `router.rs` | 609-611 | 626-628 | `settled` | `branches` | no data | 4/4 |
| `cap78-session-sessiontable-queue-snapshot` | `session.rs` | 506-510 | 525-529 | `SessionTable::queue_snapshot` | `regions` | no data | 12/12 |
| `companion-e2ee-records-record-kind-for-key` | `e2ee_records.rs` | 212-220 | 252-260 | `record_kind_for_key` | `regions` | no data | 17/17 |
| `companion-e2ee-records-check-state-key` | `e2ee_records.rs` | 223-228 | 263-268 | `check_state_key` | `regions` | no data | 9/9 |
| `edge-delivery-checkpoint-cursor-key` | `e2ee_records.rs` | 2347-2349 | 2383-2385 | `DeliveryRow::cursor_key` | `regions` | no data | 4/4 |
| `edge-delivery-checkpoint-decode` | `e2ee_records.rs` | 2358-2374 | 2407-2423 | `DeliveryRow::decode` | `regions` | no data | 30/38 |
| `cap74-e2ee-records-key` | `e2ee_records.rs` | 2787-2789 | 2836-2838 | `WitnessRow::key` | `regions` | no data | 4/4 |
| `cap74-e2ee-records-decode` | `e2ee_records.rs` | 2498-2512 | 2859-2874 | `WitnessRow::decode` | `regions` | no data | 31/41 |

Eight of the ten now reach 100 percent. `edge-origin-settled-gate` keeps the
`branches` metric it declared and reaches 4/4 on it, so the metric was never
the problem for that row: the span of `settled()` carries four branch outcomes
and every one of them is driven. The two `e2ee_records.rs` decoders do not
reach 100 percent, and their owed entries are named below.

### Further rows the audit found in the same five files (25)

| Region | File | Old span | New span | Item it now covers | Metric | Was | Now |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `cap79-result-memory-009-finish-restore-with-backing` | `mod.rs` | 501-507 | 578-584 | `CompanionCoordinator::finish_restore_with_backing` | `regions` | 0/14 | 7/7 |
| `cap101-sequencer-eligibility-003-install-sequencer` | `mod.rs` | 553-565 | 654-661 | `CompanionCoordinator::install_sequencer` | `regions` | 7/7 | 9/9 |
| `cap97-recent-001-replay-recent` | `mod.rs` | 719-761 | 883-925 | `CompanionCoordinator::replay_recent` | `regions` | 32/32 | 49/51 |
| `companion-mod-companioncoordinator-set-pending` | `mod.rs` | 866-868 | 1030-1032 | `CompanionCoordinator::set_pending` | `regions` | 3/3 | 4/4 |
| `companion-mod-companioncoordinator-batch-applied` | `mod.rs` | 872-899 | 1076-1106 | `CompanionCoordinator::batch_applied` | `regions` | 16/16 | 39/40 |
| `companion-mod-companioncoordinator-batch-rejected` | `mod.rs` | 902-904 | 1109-1112 | `CompanionCoordinator::batch_rejected` | `regions` | 6/6 | 6/6 |
| `cap79-selective-013-select-restored-objects` | `mod.rs` | 985-990 | 1193-1198 | `CompanionCoordinator::select_restored_objects` | `regions` | 7/8 | 5/5 |
| `cap73-declared-gates-008-admit-gate` | `startup.rs` | 192-201 | 235-244 | `Restore::admit_gate` | `regions` | 10/10 | 10/10 |
| `cap76-startup-rebuild` | `startup.rs` | 469-502 | 534-580 | `rebuild` | `regions` | 24/27 | 88/88 |
| `cap76-startup-restore-successors` | `startup.rs` | 506-557 | 650-701 | `restore_successors` | `regions` | 66/68 | 71/72 |
| `cap76-startup-restore-successor-binding` | `startup.rs` | 605-642 | 749-786 | `restore_successor_binding` | `regions` | 51/57 | 55/62 |
| `cap80-startup-mailboxrows-admit-item` | `startup.rs` | 983-1015 | 1127-1159 | `MailboxRows::admit_item` | `regions` | 26/31 | 27/29 |
| `cap80-startup-mailboxrows-admit-token` | `startup.rs` | 1017-1046 | 1161-1190 | `MailboxRows::admit_token` | `regions` | 13/26 | 22/24 |
| `cap80-startup-restore-mailboxes` | `startup.rs` | 1068-1087 | 1212-1231 | `restore_mailboxes` | `regions` | 18/20 | 36/36 |
| `cap80-startup-validate-mailbox-grants` | `startup.rs` | 1089-1117 | 1233-1261 | `validate_mailbox_grants` | `regions` | 10/12 | 42/42 |
| `cap79-result-memory-006-restore-replays` | `startup.rs` | 1135-1165 | 1279-1309 | `restore_replays` | `regions` | 24/26 | 42/46 |
| `cap79-selective-012-select-objects` | `startup.rs` | 1961-1966 | 2109-2114 | `Restore::select_objects` | `regions` | 1/4 | 7/7 |
| `cap78-session-sessiontable-query-snapshot-for` | `session.rs` | 572-586 | 591-605 | `SessionTable::query_snapshot_for` | `regions` | 21/21 | 18/19 |
| `edge-delivery-checkpoint-parse-cursor-key` | `e2ee_records.rs` | 2329-2331 | 2378-2380 | `DeliveryRow::parse_cursor_key` | `regions` | 6/9 | 7/7 |
| `edge-delivery-checkpoint-encode` | `e2ee_records.rs` | 2339-2355 | 2388-2403 | `DeliveryRow::encode` | `regions` | 1/1 | 29/36 |
| `edge-delivery-checkpoint-check` | `e2ee_records.rs` | 2376-2393 | 2425-2442 | `DeliveryRow::check` | `regions` | 17/18 | 14/14 |
| `edge-delivery-checkpoint-matches-key` | `e2ee_records.rs` | 2429-2431 | 2446-2448 | `DeliveryRow::matches_key` | `regions` | 2/2 | 4/4 |
| `cap74-e2ee-records-parse-key` | `e2ee_records.rs` | 2486-2488 | 2841-2843 | `WitnessRow::parse_key` | `regions` | 6/8 | 6/7 |
| `cap74-e2ee-records-encode` | `e2ee_records.rs` | 2486-2495 | 2846-2856 | `WitnessRow::encode` | `regions` | 15/21 | 30/38 |
| `companion-e2ee-records-validate-state-body` | `e2ee_records.rs` | 2520-2540 | 2882-2909 | `validate_state_body` | `regions` | 10/16 | 69/69 |

Four of these twenty-five read 100 percent at lines they do not describe and
read below 100 percent at the lines they do: `cap97-recent-001-replay-recent`
32/32 to 49/51, `companion-mod-companioncoordinator-batch-applied` 16/16 to
39/40, `cap78-session-sessiontable-query-snapshot-for` 21/21 to 18/19 and
`edge-delivery-checkpoint-encode` 1/1 to 29/36. Those four numbers are the
honest cost of the correction and are not narrowed away: a span was not
widened to keep a passing figure, and a passing figure over the wrong lines
was worth nothing.

The scope of this change is every mis-anchored row in the five files the ten
rows already touch. Those five files are re-reviewed here end to end for the
items these rows name, which is what lets the re-review claim above be made
row by row.

## What is still failing

Thirteen of the thirty-five stay below 100 percent at their correct span, and
each names its owed entries in its own `reason`. They are decided under the
same rule COV-05 established: narrow only when every uncovered entry is
provably unreachable and sits at the boundary of the span, otherwise leave the
row failing with the owed entry named. No row here satisfies that test, so no
span is narrowed.

- Reachable refusals that are ordinary test work:
  `cap80-startup-mailboxrows-admit-item` 27/29 and
  `cap80-startup-mailboxrows-admit-token` 22/24 (the early returns for a row
  of another kind and for an unparsable key),
  `cap78-session-sessiontable-query-snapshot-for` 18/19 (a generation whose
  sink is gone), `cap76-startup-restore-successors` 71/72 (a target that
  already owns a log, lifecycle or route),
  `companion-mod-companioncoordinator-batch-applied` 39/40 (the
  acknowledgement apply failure), `cap74-e2ee-records-parse-key` 6/7 (a key
  without the witness prefix), `cap97-recent-001-replay-recent` 49/51 (the
  absent stored result and the render failure), and
  `cap79-result-memory-006-restore-replays` 42/46 (two unparsable-key skips
  and the `Ceiling` refusal when no backing was supplied).
- `cap76-startup-restore-successor-binding` 55/62 holds seven reachable
  refusals — activation, binding, verification, log, head, route selection and
  lifecycle — interleaved with the accepted path, so no narrower span excludes
  them.
- `cap74-e2ee-records-decode` 31/41 and `edge-delivery-checkpoint-decode`
  30/38 hold decoder propagations whose truncation and trailing-input refusals
  are reachable, and both rows are reviewed for exactly that ("malformed
  bodies cannot become recovery authority", "incomplete bodies are rejected"),
  so those entries are the row's own subject and may not be narrowed away.
- `cap74-e2ee-records-encode` 30/38 and `edge-delivery-checkpoint-encode`
  29/36 hold encoder propagations that cannot fail for a fixed-width row, but
  they are interleaved with the field writes the rows are reviewed for. These
  are the same class as COV-05's `cap5-tbs-maintenanceauditeventtbs-encode`
  and need either the propagation restructured out of the span or a policy
  format that can name an exempt entry.

## The audit of the rest of the inventory

The inventory was audited a second way, independent of the coverage report: a
row whose `id` names an item is mis-anchored if that item's definition is not
inside the row's span. Over all 1144 release rows that test flags 101, of
which four are COV-05's deliberate narrowings inside the right function and
the rest are genuine. Thirty-four of them are the rows re-anchored above.

The remaining sixty-seven are in twenty-three other files and are **not**
changed here, for the reason the issue itself gives: each needs its owner to
confirm which item its reason meant and to re-review the span it would then
cover, and this change only re-reviewed the five files above. They are
recorded here so that work is mechanical for whoever takes it.

| File | Rows | The items their ids name, in file order |
| --- | --- | --- |
| `crates/agenc-ircd-runtime/src/federation/coordinator/companion.rs` | 10 | `run`, `committed_ack`, `request_committed`, `send_response`, `schedule_mailbox_expiry`, `mailbox_timer_fired`, `snapshot_timer_fired`, `continue_snapshot`, `send_page`, `continue_fetch` |
| `crates/agenc-ircd-runtime/src/e2ee/edge/witness_failure.rs` | 9 | `witness_pending`, `prepare_witness_retry`, `arm_witness_retry`, `record_witness`, `try_witness_stage`, `witness_timer_fired`, `witness_batch_applied`, `witness_rejection`, `witness_batch_rejected` |
| `crates/agenc-ircd-runtime/src/e2ee/edge/witness_recovery.rs` | 8 | `witness_recovery_pending`, `install_backing`, `restore`, `reserve_one`, `grow`, `insert_reserved`, `restore_witness_backing`, `restore_chain_witness` |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/sync.rs` | 5 | `state_fetch`, `snapshot_expired`, `accepting_requests`, `link_lost`, `require_cut_scope` |
| `crates/agenc-ircd-runtime/src/federation/coordinator/mod.rs` | 5 | `batch_applied`, `delivery_ack_receipt`, `replay_io_busy`, `batch_rejected_with_error`, `reject_origin_acknowledgement` |
| `crates/agenc-ircd-runtime/src/federation/coordinator/startup/retirement.rs` | 4 | `committed`, `rejected`, `retryable`, `retry` |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/ops/sequence.rs` | 3 | `council`, `submit_reinit_ack`, `fetch_object` |
| `crates/agenc-ircd-domain/src/model.rs` | 2 | `revision`, `revision` |
| `crates/agenc-ircd-e2ee/src/sequencer.rs` | 2 | `credential`, `key_set` |
| `crates/agenc-ircd-runtime/src/account_service.rs` | 2 | `binding`, `generation` |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/recovery_gates.rs` | 2 | `matches_restored_heads`, `states` |
| `crates/agenc-ircd-runtime/src/e2ee/coordinator/sequencer_signing.rs` | 2 | `at_time`, `for_receipt` |
| `crates/agenc-ircd-runtime/src/remote_accounts.rs` | 2 | `carrier`, `outcome` |
| `crates/agenc-ircd-runtime/src/state_core/mod.rs` | 2 | `backing_reservations`, `complete_index_refresh` |
| `crates/agenc-ircd-e2ee/src/record_authentication.rs` | 1 | `authenticate_record` |
| `crates/agenc-ircd-runtime/src/daemon.rs` | 1 | `attach_coordinator_role` |
| `crates/agenc-ircd-runtime/src/e2ee/edge/mod.rs` | 1 | `is_active` |
| `crates/agenc-ircd-runtime/src/e2ee/edge/sync.rs` | 1 | `fail_frame` |
| `crates/agenc-ircd-runtime/src/federation/coordinator/mailbox_expiry.rs` | 1 | `rejected` |
| `crates/agenc-ircd-runtime/src/federation/coordinator/replay_maintenance/receipt.rs` | 1 | `rejected` |
| `crates/agenc-ircd-runtime/src/federation/coordinator/request_expiry.rs` | 1 | `rejected` |
| `crates/agenc-ircd-runtime/src/registration.rs` | 1 | `index_refreshed` |
| `crates/agenc-ircd-storage/src/restore_command.rs` | 1 | `execute_restore_command` |

Every one of these sixty-seven matches executable coverage data, so none is
visible to `check-coverage.py` at all: each scores, silently, against an item
its row never declared. That is the more dangerous half of this defect, and it
is why the count kept rising across three partial audits. The interim policy
`conformance/critical-coverage.toml` has none: all twenty-one of its rows
contain the item their id names.

## The refusal now names the third case

COV-05 split `matched no executable coverage data` in two, separating a
`branches` declaration over a branch-free span — unscoreable as declared — from
a span that matched nothing at all. This change splits the second half again,
keeping COV-05's message untouched and keeping `matched no executable coverage
data` as the stem of both new messages, so that neither reads as "untested":

```
critical region <id> (<file>:<start>-<end>) matched no executable coverage
data although the file reports <n> executable regions elsewhere, so the span
is anchored on non-executable text rather than on the item the row names and
must be re-anchored onto that item

critical region <id> (<file>:<start>-<end>) matched no executable coverage
data, and neither does any other line of the file, so the report does not
exercise this file at all and cannot decide the row
```

The first is the defect this record fixes; the second is a partial report,
which is a different failure with a different remedy and used to be
indistinguishable from it. The self-test grew from 25 to 26 rejection cases:
the existing empty-span case now asserts the sharper wording, and a new case
empties one file's `segments` and `branches` and asserts the report-side
message.

## Limitations

- A row is re-reviewed here only against the item its `id`, `category` and
  `reason` name. Where a reason covers a family of rows — the six
  `edge-delivery-checkpoint` rows share one sentence, as do the four
  `cap74-e2ee-records` rows — the re-review confirms that the row's own item
  carries the part of that sentence the `id` names, not that the sentence is
  the best description of the family.
- Sixty-seven mis-anchored rows are recorded and not moved. Until they are,
  sixty-seven release-critical scores describe items their rows do not
  declare, and no claim is made here about any of them.
- No overall floor is claimed. Branch coverage is 76.19 percent against a 90
  percent floor and the integrated verdict remains COV-04's (#73).
- The `id`-names-the-item audit is a lower bound. It can only flag a row whose
  `id` ends in the name of a function; a row named for a concept rather than
  an item cannot be checked this way, and neither can a span that should cover
  a `match` arm or a block inside a function.
- Nothing here prevents the next drift. `verify-regions.py` still passes for a
  row whose hash was refreshed without moving its span, which is exactly how
  these arose.

## Evidence

```sh
python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
# coverage self-test: ok (26 rejection cases)

RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  --workspace --all-features --branch --json \
  --output-path wt62-cov-all.json -- --skip qualification_workload

python3 scripts/check-coverage.py check wt62-cov-all.json \
  conformance/release-critical-coverage.toml
# coverage check failed, with 635 items:
#   1 floor: branch coverage 76.19% is below 90.00% (the line floor passes)
#   0 matched-no-executable rows, 0 anchored-on-non-executable-text rows
#   0 unscoreable-as-declared rows
#   634 rows below 100.00%
# Before this change the same report and the same build gave 648 items,
# including nine matched-no-executable rows and one unscoreable declaration.

python3 scripts/check-source.py check
# source policy: ok (1003 Rust files)
```
