# Stage 10 companion coordinator and startup retirement coverage

This record covers COV-08 (issue #150). COV-07 (#145) re-anchored every
reviewed release-critical region onto the item its row names, and six rows
that had been reporting partial or full coverage against neighbouring
functions measured zero at their own spans: the companion coordinator's
mailbox expiry timer, its ESTATE snapshot expiry timer, its fetch
continuation, and three quarters of the startup owner-retirement protocol.
That is 137 executable regions, all declared release-critical, reached by no
test at all. This closes five of the six and takes the sixth to the maximum
its span can reach.

Nothing here changes a production handler. Every source change is a test
module under a `tests` path component plus the one `mod` line that admits it,
and each `mod` line sits at the end of its file so no reviewed span above it
moves. No span was narrowed, widened or re-scored, and no `reason` changed.

## How the report was produced

One whole-workspace all-target report per measurement, on the pinned nightly
that carries `-C instrument-coverage` branch support, with `cargo-llvm-cov
0.9.0`. A `--lib` report cannot be used here: it omits
`crates/agenc-ircd/src/main.rs` entirely and `check-coverage.py check` refuses
before scoring anything.

```sh
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  --workspace --all-features --branch --json \
  --output-path before.json -- --skip qualification_workload
python3 scripts/check-coverage.py check before.json \
  conformance/release-critical-coverage.toml
```

and the identical pair at this branch into `after.json`. Regions were scored
with `scripts/check-coverage.py`'s own `region_counts`, which is what the gate
reads; the per-entry listings quoted below come from the same `segments`
records in the same two reports.

Selection: `--all-features`, host `x86_64-unknown-linux-gnu`, toolchain
`nightly-2026-08-24` for instrumentation and the pinned stable for the gate
commands. `Cargo.lock` is unchanged. Baseline tree: `6752da0`
(`origin/main`).

## Before and after

The six rows, at their own spans, under their declared `regions` metric:

| Region | Item | File | Before | After |
| --- | --- | --- | ---: | ---: |
| `cap78-companion-mailbox-timer-fired` | `mailbox_timer_fired` | `federation/coordinator/companion.rs` | 0/13 | 13/13 |
| `companion-companion-snapshot-timer-fired` | `snapshot_timer_fired` | `federation/coordinator/companion.rs` | 0/33 | 33/33 |
| `companion-companion-continue-fetch` | `continue_fetch` | `federation/coordinator/companion.rs` | 0/55 | 54/55 |
| `companion-retirement-rejected` | `rejected` | `federation/coordinator/startup/retirement.rs` | 0/23 | 23/23 |
| `companion-retirement-retryable` | `retryable` | `federation/coordinator/startup/retirement.rs` | 0/4 | 4/4 |
| `companion-retirement-retry` | `retry` | `federation/coordinator/startup/retirement.rs` | 0/9 | 9/9 |

Five reach 100 percent. `companion-companion-continue-fetch` reaches
54/55 (98.18 percent); the one entry it cannot reach is recorded under "Not closed"
below, with the proof that no test can reach it at that span.

Overall workspace totals, same command, same selection:

| Tree | Branches | Lines | Regions |
| --- | --- | --- | --- |
| `6752da0` (before) | 76.2024% (19,235/25,242) | 91.7454% (185,168/201,828) | 86.2039% (268,583/311,567) |
| this branch (after) | 76.3846% (19,281/25,242) | 91.8118% (185,302/201,828) | 86.2691% (268,786/311,567) |

`check-coverage.py check` over the same two reports moves from 636 failure
items to 629 — one floor (branch coverage below 90 percent) and 628 rows below
100 percent. Seven rows newly pass and none newly fails. Five are the rows
above; the other two are reached on the way and are recorded as a fact of the
same measurement rather than claimed as this issue's work:

| Region | File | Before | After |
| --- | --- | ---: | ---: |
| `companion-companion-send-page` | `federation/coordinator/companion.rs:945-970` | 23/32 | 32/32 |
| `companion-sync-companioncoordinator-snapshot-expired` | `e2ee/coordinator/sync.rs:979-991` | 14/15 | 15/15 |

`send_page` is the adapter the fetch continuation publishes through, and
`snapshot_expired` is the predicate the ESTATE expiry timer reads, so both are
exercised by the same cases.

## What the new regressions prove

### The two expiry timers, off the owner's own heap

`crates/agenc-ircd-runtime/src/federation/coordinator/companion/tests/timers.rs`

Every case arms a real heap entry, pops it with `TimerHeap::pop_due` the way
`StateCore::step_wake` does, and hands it to
`FederationCoordinator::timer_fired`. What is proved is that the path is
reachable in the composed owner, through the whole `||` chain of eight
handlers, and not merely that the handler computes.

- A due `MailboxSnapshotExpiry` wake releases the owner's reservation: the
  executor's `mailbox_expiry_armed` returns to `None` and, with no cut left to
  release, the heap entry is cancelled rather than rearmed. The entry the test
  fires is the one `reserve_expiry` armed, not a synthesized one.
- The same wake on a node with no companion executor is still owned: it is
  accepted, it retires, and it touches no other owner's state.
- Neither handler claims an entry it does not own. A `MailboxSnapshotExpiry`
  addressed to a peer and a `CompanionSnapshotExpiry` addressed to the global
  identity are both declined by the whole federation chain, so the owner keeps
  looking instead of swallowing another subsystem's wake.
- An expired ESTATE token is fatal for the link that holds it. The cut is
  published through `admitted` over a real `ERESUME`, its expiry is armed by
  the coordinator's own `ScheduleExpiry`, and when that entry comes due the
  transfer is released, the live link is retired, the writer is closed and the
  violation counter advances by exactly one.
- The same due entry with no live link releases the cut, reports the timer
  handled, and invents no link to retire.
- A due entry for a peer holding no cut expires nothing and retires nothing,
  so a stale wake cannot take a healthy transfer down.

### The fetch continuation, through the owner's commit receipt

`crates/agenc-ircd-runtime/src/federation/coordinator/companion/tests/fetch.rs`

Each case opens a real multi-page cut over `ERESUME`, sends `ESTATE FETCH`
quoting the cursor the previous page ended on, and settles the staged
boundary through `commit_staged_batch` and `FederationCoordinator::
batch_applied`, which is the only path that reaches `continue_fetch`.

- A continuation the receipt accepts publishes exactly the next page to the
  link the fetch named, and the cut runs on to its final page that way.
- A continuation that overruns the link queue stops at the byte boundary: the
  queue never exceeds its own ceiling, the link is retired rather than
  carrying a partial page on, and the violation counter advances by one.
- A continuation interrupted by a reconnection publishes nothing to the link
  that is gone, and the page its receipt committed is not lost: the edge
  fetches the same page again over its new link and receives it, without
  staging a second durable boundary.
- A continuation whose delivery owner moved under it retires the exact live
  link it was staged for — the private publication is applied only when it
  still matches its own owner.
- The same refusal on a link that is already gone retires nothing, so a
  reconnection that arrived first is not taken down by a stale receipt.
- A node with no companion executor holds no publication authority: the
  continuation is discarded without a line, a link retirement or a counter.

### The startup retirement refusal side

`crates/agenc-ircd-runtime/src/federation/coordinator/startup/retirement/tests/refusal.rs`
and its `boundaries.rs` and `pacing.rs`

The fixture runs the real reload — `FederationCoordinator::startup` driven by
real storage reads — until it parks on one accepted startup write, then
settles the exact storage refusal through the owner's public
`batch_rejected_with_error`. A `Receipt` cannot be built by hand, so every
case is the receipt the reload itself produced.

- A receipt taken at a moved durable head fails closed although the refusal is
  retryable. The batch had actually reached the log while the owner was told it
  had not; returning the candidate there would stage the same row twice.
- A receipt whose pinned commit no longer matches fails closed for the same
  reason: the pinned commit is the revision every startup pass must observe.
- A loader already holding a candidate refuses a second receipt and keeps the
  candidate it held, rather than replacing it with a stale one.
- A receipt that cannot be confirmed against live state — the indeterminate
  boundary — fails closed.
- Each refusal leaves the durable head where it was, leaves `retry_at` at
  zero, advances the violation counter by exactly one, and leaves the reload
  incomplete and failed, which is what "fails closed" means here: the loader
  is wedged rather than guessing.
- A retryable refusal returns the candidate and reserves exactly one fixed
  100-millisecond interval; `advance` stages nothing before that interval
  elapses and stages the same write again once it has.
- `retryable` is pinned to exactly five bounded refusals —
  `AllocationFailed`, `QueueFull`, `LimitExceeded`, `DatabaseRejected` and
  `FilesystemRejected` for every one of its seven causes — against the eight
  determinate and indeterminate outcomes that must fail the reload closed.
  This matters because the sibling `resume_reconciliation::retryable_storage`
  deliberately admits a smaller set.
- A monotonic reading within one retry interval of the `u64` ceiling cannot
  carry a paced deadline, so the owner fails closed rather than retrying
  without pacing, and still holds the candidate it took back.

## Not closed

### `companion-companion-continue-fetch` is 54/55 (98.18 percent), and 55/55 is unreachable

The one entry left uncovered is the `?` unwind at `companion.rs:996:64`:

```rust
        .and_then(|actions| {
            for action in actions {
                apply(coordinator, context, link, peer, action)?;
            }
            Ok(())
        });
```

`continue_fetch` has exactly one caller, `companion::committed`, and the
`actions` it iterates come from exactly one place,
`delivery_owner::fetch::Prepared::committed`, which returns either
`Ok(Vec::new())` or `Ok(vec![Action::SendPage(output)])` and nothing else.
`apply`'s `Action::SendPage` arm is

```rust
        Action::SendPage(output) => {
            send_page(coordinator, context, link, peer, output);
            Ok(())
        }
```

which cannot return `Err`. So no input reaches that `?`, and no test can
cover it without changing a production handler. The same entry is uncovered
in the neighbouring `continue_snapshot` span (`companion.rs:935:60`) in both
the before and the after report, where it *is* reachable, because that
publication can also emit `Action::Stage` and `Action::ReadSnapshotPage`.

This is reported rather than acted on. COV-05's (#135) rule narrows a span
only when every uncovered entry is provably unreachable and sits at the
boundary; here one entry qualifies and the span is otherwise fully reached,
which is a policy decision — narrow the span by one line, accept 54/55 as the
row's ceiling, or change `apply` so the arm can fail — and not a test. Issues
#135 and #145 settled the anchoring and the metric for this row, so nothing
here moves either.

### No overall floor is claimed

The release floors of 90 percent branches and 90 percent lines remain COV-04's
(#73) integrated verdict. This record makes no claim about the other rows
below 100 percent.

## Limitations

- The `no executor` guard in `continue_fetch` cannot be reached through the
  owner's receipt path, because `companion::committed` returns before it when
  `companion_exec` is `None`. The case that covers it commits the staged
  batch, takes the receipt's own publication out of
  `CompanionCoordinator::batch_applied`, removes the executor and calls
  `continue_fetch` with it. It is a defensive guard with no other reachable
  caller. Two other cases also reach past the public entry points: the pacing
  case calls `retirement::advance` directly, because that is the function the
  loader itself calls and the only way to observe that nothing is staged
  before the interval elapses, and the `retryable` truth table calls that
  pure predicate directly. Every other case runs through `admitted`,
  `startup`, `storage_read_completed`, `timer_fired`, `batch_applied` or
  `batch_rejected_with_error`.
- The retirement fixture's candidate is the startup signer reconciliation, not
  a delivery-owner retirement, because a restored retirement candidate needs a
  `sync::Snapshot` whose fields are private to `crate::e2ee::coordinator` and
  a full pending-cut restart. Both candidates are the same `RestoredWrite`
  through `rejected`, `retryable` and `retry` — the three rows this closes —
  and the retirement variant's own validation already has coverage in
  `e2ee/coordinator/tests/sync/delivery_restart/pending_recovery.rs`.
- The timer cases drop due wakes of other kinds rather than firing them, so
  each case observes only its own handler. No case asserts anything about the
  maintenance wakes the same heap carries.
- The retirement fixture composes the registration router, which
  `compose_test_state` gives the real monotonic clock rather than the
  deterministic one. The reload's last reading is pinned with
  `set_monotonic_for_test` before any case runs, so the paced deadline is an
  exact value instead of one that can cross a millisecond between the value a
  case reads and the value `retry` reserves. That is a fixture property, not a
  production one; `retry` reads the clock exactly once.
- The cut this branch publishes carries route-state entries at state
  generation zero, which is what a freshly composed fixture's domain revision
  admits; nothing here exercises a cut refused for a stale state generation.

## Evidence

New test sources, all under a `tests` path component:

- `crates/agenc-ircd-runtime/src/federation/coordinator/companion/tests/transfer.rs`
- `crates/agenc-ircd-runtime/src/federation/coordinator/companion/tests/timers.rs`
- `crates/agenc-ircd-runtime/src/federation/coordinator/companion/tests/fetch.rs`
- `crates/agenc-ircd-runtime/src/federation/coordinator/startup/retirement/tests/refusal.rs`
- `crates/agenc-ircd-runtime/src/federation/coordinator/startup/retirement/tests/boundaries.rs`
- `crates/agenc-ircd-runtime/src/federation/coordinator/startup/retirement/tests/pacing.rs`

plus the two `mod` lines that admit them, each appended at the end of its file
so no reviewed span moves. No production handler changed, so this work adds no
wire or storage format, no dependency pin and no limit.

Commands and results at this branch:

```sh
cargo test -p agenc-ircd-runtime --all-features
# 1,579 unit tests pass with one ignored, and every integration target passes:
# bridge_crypto 8, bridge_storage 6, e2ee_load 1, federation_link 16,
# idle_connection_memory 2 with one ignored, listener_accept 22,
# loom_models 6, shutdown 11, stage_six_soak 2, tls_endpoint 15,
# tls_federation_policy 1, tls_fixture_spike 4, tor_client 7. No failures.

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean

cargo fmt --all
python3 scripts/check-source.py check
# source policy: ok (1,012 Rust files)

python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
# coverage self-test: ok (28 rejection cases)

python3 scripts/check-coverage.py audit conformance/critical-coverage.toml
python3 scripts/check-coverage.py audit conformance/release-critical-coverage.toml
# zero drifted rows
```

The coverage source inventory in `conformance/critical-coverage.toml` and
`conformance/release-critical-coverage.toml` is re-anchored to the current
production sources. Every reviewed span keeps its lines, its `item` and its
`span_sha256`; the six new test files and the two `mod` lines change only the
inventory hash and the two files' `source_sha256`.
