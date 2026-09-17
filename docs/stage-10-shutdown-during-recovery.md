# Stage 10 shutdown during active federation recovery

This record covers RUN-05 (issue #64). The gap it closes is missing focused
evidence, not a reproduced defect: the production-capacity harness calls
`wait_for_federation_drain` before every stop
(`crates/agenc-ircd/tests/stage_eight_e2ee/stage_ten_capacity.rs`), so until
now no test stopped a daemon while federation recovery was live and
acknowledgement work was still outstanding. CAP-14's original failure is not
reproducible on the current source and is not claimed here.

The three regressions below stop a coordinator and an edge through the real
four-phase driver, `run_shutdown`, while the network is deliberately not
drained. Every one of them runs the production actor loop against real redb
storage in a temporary directory.

## What is now proven

### The coordinator stops inside its budgets with recovery outstanding

`a_four_phase_stop_completes_inside_its_budgets_while_recovery_is_outstanding`
builds one coordinator serving two scripted edges. Edge *away* registers,
joins `#recovery` and then loses its link; edge *live* joins the same channel
and speaks twice, so three deliveries are reserved for the absent edge and
never acknowledged. Edge *live* also starts an OPAQUE exchange and never
finishes it, which leaves a live virtual account carrier and its durable
authentication transaction. Edge *away* then reconnects and gets FRESUME OK
but never completes its origin replay, so the peer is inside its recovery
transition when the stop arrives.

The test reads the coordinator's own `edge_outbox` table before the stop and
requires at least three retained deliveries, so the stop demonstrably happens
with outstanding acknowledgement work. It then runs `run_shutdown` with a
plan of 2 s quiesce, 5 s drain, 5 s flush and 2 s stop — every phase a
fraction of the spec defaults of 5, 20, 10 and 5 — and requires:

- `PhaseOutcome::Completed` for all four phases and `first_problem() == None`;
- `stop_deadline_expired` never called;
- the elapsed run inside the plan's total;
- `StateCoreExit::Stopped`;
- zero remaining sessions, so no virtual account carrier is stranded;
- `account_service_response_count == 1`, so the stop invented no
  account-service response for the exchange it cancelled.

The database is then sealed and reopened from the same directory. Every
delivery the stop observed reappears byte for byte under the same key, the
reopened `edge_outbox` keys stay strictly ordered by target, projection
generation and delivery sequence, so no sequence was reused, and no
`auth_transaction` row survives, so the abandoned carrier's durable cleanup
completed before the flush acknowledgement.

### Drain does not acknowledge ahead of a durable receipt

`drain_waits_for_a_committed_outcome_that_still_owes_its_readback` interposes
a relay on the storage completion channel that buffers commit receipts on
demand. With a receipt withheld, the committed outcome is present in storage
but has not reached the state owner, so its index readback and publication
are outstanding. The test requires that:

- the coordinator sends the edge nothing at all while the receipt is held, so
  no result is emitted ahead of its matching durable receipt;
- `LifecyclePhase::Drain` does not acknowledge while the receipt is held;
- drain completes once the receipt is released, and only then does the edge
  receive the committed `session_registered` result;
- flush and stop then complete inside the same tightened budgets.

### The edge stops inside its budgets with an unanswered request

`an_edge_stops_inside_its_budgets_with_an_unanswered_federated_request` runs
an edge against a scripted coordinator. A client registers, then issues
`JOIN #recovery`; the coordinator reads the request, never answers it, and
the link is lost, so the edge holds a retained request, its origin ownership
and an armed journal recovery when the stop arrives. The test requires that
the client never received a `JOIN` reply, then runs `run_shutdown` under the
same tightened plan with the connection's physical close reported from the
drain phase exactly as the connection task reports it. It requires all four
phases `Completed`, no stop-deadline expiry, `StateCoreExit::Stopped`, no
stranded physical session, and that every retained `federation_origin` and
`request_result` row reappears byte for byte after the database is sealed and
reopened.

## Fixtures

All three use in-crate fixtures over real storage:

- `StateCoreFixture::with_federation_coordinator` for the coordinator cases,
  with the scripted `Edge` and `Origin` peers of
  `crates/agenc-ircd-runtime/src/federation/coordinator/tests/harness.rs`;
- `StateCoreFixture::with_edge` for the edge case, with the scripted `Hub`
  and `Client` of
  `crates/agenc-ircd-runtime/src/federation/edge/tests/harness.rs`;
- `StateCoreFixture::restart_registration_storage` for the reopen, which
  stops the storage owner and opens the same directory again through the
  ordinary rollback-guard path.

No test calls `wait_for_federation_drain`, and none changes the production
capacity driver's workload.

## Limitations

- **The native storage deadline stays blocked on STO-03 (#61).** The bounded
  physical allocation allowance is implemented upstream only
  (`docs/upstream/redb-bounded-transaction/`); its application integration is
  STO-03 and depends on an upstream release. These memory-backed component
  tests prove *ordering* — which phase may acknowledge, and what survives a
  reopen — not the native ext4 shutdown deadline. The final physical-allowance
  guarantee, and the native timing qualification of the stop, are not claimed
  here and remain bound to STO-03 and to REL-10 (#84)'s frozen drill.
- The budgets are exercised through `run_shutdown` with a tightened plan
  rather than the configured 5/20/10/5 defaults. A run that completes inside
  2/5/5/2 also completes inside the defaults, but the tests do not measure
  the defaults themselves.
- Case (b) of the acceptance list, a gathering checkpoint that is staged but
  not yet submitted, is covered only indirectly: the gather window is one
  millisecond and the actor loop closes it at its own deadline, so the
  regressions here hold a *submitted* batch whose receipt is withheld. The
  existing step-mode coverage in
  `crates/agenc-ircd-runtime/src/federation/coordinator/tests/combined_barriers.rs`
  and `.../tests/account_shutdown.rs` keeps the unsubmitted-batch boundary.
- Combined cross-profile barriers are held pending only in the existing
  `combined_barriers` suite; the new stops do not carry a companion profile.
- The two coordinator cases and the edge case stop one state owner each. A
  simultaneous three-daemon stop remains the separate native campaign.

## Evidence

Sources:

- `crates/agenc-ircd-runtime/src/federation/coordinator/tests/shutdown_recovery.rs`
- `crates/agenc-ircd-runtime/src/federation/edge/tests/shutdown_recovery.rs`

Both files are test-only modules under a `tests` path component; the two
harnesses gain one `mod` line each. No production handler changed, so this
work adds no wire or storage format, no dependency pin and no limit.

Commands and results at this branch:

```sh
cargo test -p agenc-ircd-runtime --all-features --locked --lib shutdown_recovery
# 3 passed; 0 failed; 1498 filtered out

cargo test -p agenc-ircd-runtime --all-features --locked --test shutdown
# 11 passed; 0 failed

cargo test -p agenc-ircd-runtime --all-features --locked --lib account_shutdown
# 6 passed; 0 failed

cargo test -p agenc-ircd-runtime --all-features --locked --lib ordinary_batch
# 24 passed; 0 failed

cargo test -p agenc-ircd-runtime --all-features --locked --lib combined_barriers
# 32 passed; 0 failed

cargo test -p agenc-ircd-runtime --all-features --locked
# 1,500 unit tests pass with one ignored, and every integration target passes:
# bridge_crypto 8, bridge_storage 6, e2ee_load 1, federation_link 16,
# idle_connection_memory 2, listener_accept 22, loom_models 6, shutdown 11,
# stage_six_soak 2, tls_endpoint 15, tls_federation_policy 1,
# tls_fixture_spike 4, tor_client 7. No failures.

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean

cargo fmt --all --check
python3 scripts/check-source.py check
# source policy: ok (969 Rust files)
```

The coverage source inventory in `conformance/critical-coverage.toml` and
`conformance/release-critical-coverage.toml` is reanchored to the 814 current
production sources. No critical region moved, so no region digest changed.
