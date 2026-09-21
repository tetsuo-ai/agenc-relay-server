# Invitation FINISH revalidation repair

This repair closes audit subfinding ZDH-A1 (issue #13, tracked as issue #38,
plan key ENC-12) on top of `8429902ab10a0b9fc4920821c41d0effd9947b24`. It
changes the account-creation transaction record format and the runtime's
durable admission of a creation FINISH. It changes no protocol registry, wire
format, dependency pin or storage growth limit. Earlier development storage
formats remain unsupported.

## Finding

A client could START account creation with an invitation shortly before its
exclusive `expires_at` and FINISH after that boundary while the separate
monotonic account transaction was still valid. START stored only the invite
identifier and expiry; FINISH checked the transaction, the route context and
the frozen START disposition but never the invitation's UTC interval. The
runtime used `expires_at` only to size the redemption tombstone.

## Repair

The auth crate carries the authenticated invitation interval through the
transaction and rechecks it at FINISH:

- `AccountCreationInvite::not_before` and one exported predicate,
  `invitation_interval_admits`, implement exactly the architecture §11.3 rule
  `not_before <= now < expires_at`. START verification, the worker FINISH
  recheck and the runtime's durable admission evaluate this one function.
- `ValidatedInvitation` and `CreateAccountIntent::invitation_interval` carry
  `not_before` beside `expires_at`.
- `finish_account_creation` rechecks the interval against
  `AccountOperationContext::now_utc`, the coordinator's trusted UTC read taken
  when FINISH was opened, after the frozen START disposition and before an
  account identifier is drawn. A refusal returns the same fixed-size rejected
  completion as every other semantic rejection. The transaction is already
  consumed, so the one-use FINISH is spent and no `CreateAccountIntent`
  exists.
- The creation transaction record's invitation tail is
  `tag(1) + invite_id(16) + not_before(8) + expires_at(8)`, so
  `CREATION_TRANSACTION_RECORD_BYTES` is 361 (was 353). `parse` rejects a
  353-byte body outright; `restore` and the restart-cleanup decoder reject a
  present invitation whose `not_before` is not below `expires_at` or whose
  lifetime exceeds 2,592,000 seconds, and an absent invitation whose interval
  slots are not all zero. No migration is added.

The runtime defines the publication point precisely:

- The worker-side publication point is the trusted UTC read captured when
  FINISH is opened (`operation_context`). A `ClockError` there fails closed:
  the live transaction is taken from the connection, the creation cleanup is
  queued and the carrier completes as an error. No fallback epoch is
  substituted anywhere on the FINISH path.
- Crypto and queue latency can cross `expires_at` after the worker's check,
  so `stage_creation_finish` re-evaluates the same predicate with a fresh
  trusted UTC read immediately before the finish durable set is staged. A
  reading outside the interval, or an unavailable trusted clock, returns
  `RuntimeError::InvalidValue` before any plan or write is prepared.
  `stage_ready` then queues `TransactionCleanup::creation`, which deletes the
  `AuthTransaction` row, the `LoginIndex` reservation and the
  `RegistrationInvite` reservation, and completes the carrier as closed. No
  `Account`, `OpaqueRecord`, live login value, tombstone or success completion
  is published.
- Storage latency after staging is accepted: an outcome staged inside the
  interval commits even if the clock passes `expires_at` before the receipt.
  A refused receipt releases the pending authority and queues the same
  creation cleanup. An indeterminate receipt stops the state core; on restart
  the reconstruction either finds the committed rows or schedules the creation
  cleanup for the retained START rows.
- The monotonic transaction TTL bounds only how long the one-use transaction
  may be finished. It is never invitation validity.

Generic refusal and privacy behavior are unchanged: an expired invitation,
an unavailable clock, a conflict and a refused batch are not distinguishable
to the client, the fixed-size rejected completion and `FAIL ACCTCREATE
UNAVAILABLE` frames are unchanged, and a committed success replays its exact
stored result.

## Evidence

Phase 1 (auth crate, record format, restart decoders) is commit `6b07e2e`.
Phase 2 (runtime durable admission and its tests) is commit `d5d5f06`.

Failing-before, fixed-after:

1. `invited_finish_at_or_after_expiry_is_rejected_inside_the_transaction_ttl`
   in `crates/agenc-relay-auth/tests/stage_four.rs` uses only APIs that exist
   on the base commit. Appended unchanged to the base commit's `stage_four.rs`
   and run with `cargo test -p agenc-relay-auth --test stage_four --locked`
   at `8429902`, it fails with
   `assertion left == right failed: FINISH at UTC 20 must reject the expired
   invitation; left: None, right: Some(InvitationRejected)`. On the phase-1
   source it passes.
2. `durable_admission_refuses_a_valid_worker_finish_whose_wall_clock_passed_expiry`
   and `durable_admission_refuses_a_wall_clock_before_not_before_or_no_trusted_clock`
   in `crates/agenc-relay-runtime/src/account_service/tests/invitation_window.rs`
   were run against the phase-2 source with the durable-admission predicate
   disabled (`if false && !invitation_interval_admits(...)`), the only
   textual difference. Both fail with
   `Error: "durable admission must refuse the finish"` while the other five
   module tests pass. With the predicate enabled all seven pass.

The coordinator module drives real auth-crate START and FINISH transactions,
sealed with the fixture's HPKE key and the fixed Stage 04 OPAQUE registration
vectors, through `stage_creation_start`, `stage_creation_finish`, the
fixture's actual sealed storage and `batch_applied`, with deterministic
clocks:

- START at UTC 19, worker FINISH at UTC 19, staging at UTC 21 (not_before 10,
  expires_at 20): refused, the queued cleanup carries exactly three deletes,
  its commit removes the transaction row, login reservation and invitation
  reservation, no `OpaqueRecord` row or live login key exists, and no frame
  reaches the client. A distinct unexpired invitation and an open-policy
  creation still commit afterwards.
- Staging at UTC 9 (before `not_before`) and with no trusted wall clock:
  refused the same way, without panic.
- START, worker FINISH and staging exactly at `not_before` and at
  `expires_at - 1`: committed; the live login key, `OpaqueRecord` row and
  `RegistrationInvite` tombstone exist, the transaction row is gone, the
  client receives the account-created note, and a storage restart
  reconstructs the rows with no stale creation cleanup.
- Worker FINISH at UTC 20 and 21 inside the monotonic TTL: the auth crate's
  rejected outcome stages as `RequestTerminal::Rejected`, both reservations
  are deleted, no credential row exists and the client sees only the generic
  failure frame.
- A refused batch after a valid FINISH: the carrier closes, no success is
  published, the live login key is not installed, and the creation cleanup
  commits.
- A committed success replayed at UTC 50 on a fresh carrier: `replay_read`
  reproduces the stored accepted result and account-created note without
  staging, without a second account and without touching the invitation.
- Opening FINISH with no trusted clock: the live transaction is consumed, the
  creation cleanup is queued and no crypto job is submitted.

Restart of a sealed invitation-admitted START is covered by
`restored_invited_creation_rechecks_the_invitation_interval_at_finish` in
`crates/agenc-relay-auth/tests/stage_four_restart_records.rs`: the 361-byte
record restores with its exact interval, a restored FINISH commits inside the
interval and rejects at or after `expires_at` and before `not_before`, and
interval corruption fails restore and restart-cleanup decoding. The runtime's
existing stale-START and reconstruction tests decode the widened record.

Fixture limitations: the coordinator tests use synthetic public envelopes,
the fixed OPAQUE registration vectors and deterministic clocks rather than an
OPAQUE client or a real MLS endpoint. Refused receipts are driven through the
state core's rejection path; an indeterminate receipt is not fault-injected
here and relies on the state core's existing indeterminate exit and the
startup cleanup qualified for stale START rows. Synthetic envelope tests do
not substitute for real endpoint evidence.

## Policy bindings

Both reviewed coverage inventories bind 783 production sources (782 plus
`invitation_window.rs`). The release region `startup-audit-before-images`
carries the new `reconstruct.rs` digest with unchanged lines. The four
release regions on `account_service.rs` and the two on `state_core/mod.rs`
carry the new digests; `runtime-opaque-record-account-binding` and
`runtime-opaque-record-account-generation` move by the nineteen inserted
lines, the others keep their lines. The Stage 04 constant-time review records
that `begin_authentication` is byte-for-byte unchanged by the auth changes.

## Validation

```sh
cargo test -p agenc-relay-auth --locked
cargo test -p agenc-relay-runtime --lib account_service --locked
cargo test -p agenc-relay-runtime --lib --locked -- account_service state_core::reconstruct daemon::login_index
cargo test -p agenc-relay-server --test stage_eight_e2ee --locked
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
python3 scripts/check-stage-four.py check
python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
python3 scripts/requirements.py check
python3 scripts/check-source.py check
python3 scripts/check-workspace.py check
bash scripts/check-stage-nine.sh
```

At `d5d5f06` the auth crate passes 80 tests (33 unit, 19 stage-four, 10
restart-record, 13 vector and 5 further integration tests; one ignored vector
generator), the focused runtime selection passes 97 tests including the seven
invitation-window tests, and `stage_eight_e2ee` passes 17 tests with 16
ignored qualification scenarios. Formatting, all-target Clippy with warnings
denied, the Stage 04 review check, both coverage-policy self-tests, the
requirement ledger (244 records), the source policy (927 Rust files) and the
workspace policy pass. The full implementation gate `bash scripts/check-stage-nine.sh` passes at
`d5d5f06` (104 gate commands, exit 0).

Issue #13 subfinding A1 is evidenced by this work only. C3, C4 and C5 remain
under their separate runtime dispositions. No security, memory, disk or
release threshold was weakened.
