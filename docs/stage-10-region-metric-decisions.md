# Stage 10 release-critical region metric decisions

This record covers COV-05 (issue #135). COV-01 (#66, PR #133) found that a
group of release-critical regions declares `metric = "branches"` over spans
that LLVM's branch instrumentation does not describe at all, re-scored
twenty-four of them to `metric = "regions"`, and left sixteen that reach 100
percent under neither metric for review. This record takes those sixteen row
by row, audits the rest of the release inventory for the same declaration
defect, and gives `check-coverage.py` a distinct refusal for the case.

Nothing here changes a production handler, adds a test, lowers a floor,
deletes a reviewed row or narrows away a reachable entry. Every change is to
`conformance/release-critical-coverage.toml` and to
`scripts/check-coverage.py`, and every decision below is bound to a
measurement.

## How the reports were produced

Three reports, on the pinned nightly that carries `-C instrument-coverage`
branch support, with `cargo-llvm-cov 0.9.0`. The whole-workspace all-target
report is the authoritative one: every score quoted below is taken from it,
and it is the only report `check-coverage.py check` can run to completion,
because a `--lib` report omits `crates/agenc-ircd/src/main.rs` entirely.

```sh
# the workspace report every decision below is taken from
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  --workspace --all-features --branch --lib --json \
  --output-path wt60-cov.json

# the storage crate's own regression suites, which live in crates/*/tests/
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  -p agenc-ircd-storage --all-features --branch --json \
  --output-path wt60-cov-storage.json -- --skip qualification_workload

# every target in the workspace, for the one check run below
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  --workspace --all-features --branch --json \
  --output-path wt60-cov-all.json -- --skip qualification_workload
```

`qualification_workload` is skipped because it fallocates a ballast file sized
to the host filesystem; it exercises no reviewed region.

The `--lib` report was used for the entry-by-entry reachability analysis and
agrees with the all-target report on every entry quoted below. It understates
three rows whose only callers are in `crates/*/tests/` targets, and those rows
are scored from the all-target report: `cap5-login-index-execute` reads 0/63
under `--lib` and 56/63 with every target built, `cap5-login-index-load-secrets`
reads 0/16 and 16/16, and `storage-declared-recovery-selection` reads 20/24 and
23/24.

Selection: `--all-features`, host `x86_64-unknown-linux-gnu`, instrumentation
toolchain `rustc 1.100.0-nightly (fb6531d55 2026-08-23)`
(`nightly-2026-08-24`), gate toolchain `1.98.0`. `Cargo.lock` SHA-256
`eb963d43bb6d08c6833ab51cbcdbccbaef0815b6b5437f1a5b523402454e714d`
(unchanged). Baseline tree `ce98ea0` (`origin/main`). Totals at that tree:
`--lib` branches 65.8418 percent (16,284/24,732) and lines 82.0210 percent
(164,594/200,673); all-target branches 76.04 percent and lines above the 90
percent floor.

Regions were scored with `check-coverage.py`'s own `branch_counts` and
`region_counts`, merged across reports by coordinate, so the figures below are
the ones the gate itself would compute.

## What the two metrics can express

`branch_counts` scores the `branches` array, which LLVM emits only for
conditional jumps it instruments as decisions. A body built from `match` arms,
slice patterns and `?` propagation emits **no** branch record at all, so a
`branches` declaration over such a span matches zero outcomes and can never be
satisfied.

`region_counts` scores the `segments` array, counting every executable entry
region. That includes one entry per `?` unwind. A span holding a `?` whose
error arm cannot be produced therefore holds an entry no test can reach, and
**cannot reach 100 percent either**.

Those two facts together are the whole of this issue: a reviewed span is
scoreable at 100 percent only when it either carries real branch records, or
carries no unreachable propagation. Sixteen rows satisfy neither.

## The decision rule

Applied to every row below, in this order:

1. **Narrow.** If the uncovered entries are all provably unreachable *and*
   they sit at the boundary of the span, so that a shorter span exists which
   is free of them and still states the reviewed claim, narrow the span to it,
   re-score to `regions`, and record in `reason` what the row now claims and
   what was excluded.
2. **Metric only.** If any uncovered entry is *reachable* — a decision a test
   could drive but none does — the row is a genuine coverage gap. Correct the
   metric, because `regions` is the true description of the span, and leave
   the row failing with the owed entry named in `reason`.
3. **Leave.** If every uncovered entry is unreachable but they are interleaved
   with the claim, so that no narrower span excludes them without dropping a
   covered decision, correct the metric and leave the row failing, with the
   reason recording why it cannot be repaired without restructuring the code.

No exemption mechanism was added. `REGION_FIELDS` in `check-coverage.py` is a
closed set and `set(raw_region) != REGION_FIELDS` is one of the checks that
keeps the release inventory honest; opening it so a region can be scored over
fewer entries than its own span contains is a permanent weakening of the
policy, it is not needed by any row that rule 1 covers, and it would be a
worse outcome than a row that is visibly failing. Three rows are left failing
that such a mechanism would have passed; each names its remedy below.

## The nine rows decided here

The other seven of COV-01's sixteen are the `login_index` family and are
treated in the next section. "Before" is the score under the declared
`branches` metric; every one of them was `0/0`, which is what
`matched no executable coverage data` was reporting.

| Row | Measured (regions) | Decision | Why |
| --- | --- | --- | --- |
| `cap5-mod-maintenanceauditevent-sign` | 19/21 → **7/7** | narrow 34-51 → 34-38 | The two uncovered entries are `tbs.hash()?` and the `sign_canonical` error map, at the tail of the span. `hash` refuses only a length other than 358 and `encode` is ceiling-bound to exactly 358; every constructor of the TBS validates, so neither can fail. The retained span is the `require_key` selector fence, reached 56 times and refused once. |
| `runtime-join-echo-result-channels` | 35/37 → **16/16** | narrow 361-380 → 373-380 | The two uncovered entries lead the span: a `try_reserve_exact(MAX_JOIN_ECHOES)` ceiling map, and `frame_channel(&echo.frame, 0)?` on the edge's own rendered echo frame, whose first parameter the edge wrote from a validated `ChannelNameValue`. The retained span is exactly the reviewed claim — each held echo matches one accepted target and consumes it — including the `Violation::Consistency` refusal, reached twice. |
| `cap5-maintenance-preparedmaintenanceaudit-audit-mutation` | 28/34 → **8/8** | narrow 40-61 → 43-51 | One uncovered entry leads the span (`audit_sequence.checked_add(1)`, which needs `u64::MAX` audit events) and five trail it (the event encoding, `PersistentRecordValue::new`, `StoredKey::new` over eight bytes, `value.encode()` and `RecordMutation::put`), none of which can fail for a prepared event. The retained span is the kind-2 audit row itself: table, kind, revision `sequence + 1`, generation zero, no expiry, no references. |
| `s10-cap70-projection-delete` | 8/9 → **3/3** | narrow 87-90 → 87-88 | The single uncovered entry is `row.key()?` on the last executable line. `barrier_key` concatenates a constant prefix with a sixteen-byte target identity, far under `MAX_STORED_KEY_BYTES`, so it cannot fail. The retained span is the barrier row the deletion addresses. |
| `s10-cap70-projection-write` | 18/22 | metric only, **still failing** | Three of the four uncovered entries are unreachable encodings, but the fourth is not: `PersistentRecordValue::new` refuses `revision == 0` for this non-tombstone row, `write` is `pub(crate)` and already called directly from `federation/coordinator/tests/combined_barriers.rs`, and no test passes zero. A reachable entry may not be narrowed away. One regression closes it to 21/22. |
| `reload-audit-submission-outcome` | 23/26 | metric only, **still failing** | The refusal before submission is proved on both a full and a closed queue, but the three uncovered entries are reachable: the `token.cancelled()` arm of the `select!` and the `Ok(Err(rejection))` arm that carries a determinate core rejection. COV-01 classified this row with the unreachable-unwind group; that classification is withdrawn here. |
| `cap5-tbs-maintenanceauditeventtbs-encode` | 47/62 | metric only, **still failing** | All fifteen uncovered entries are unreachable — `validate()` cannot fail because every constructor validates, and the writer ceiling equals the exact encoded size — but they are interleaved with the fourteen field writes. The only branch-free run inside the span is `Ok(writer.finish())`, which states nothing. The layout refusals are already carried by `cap5-tbs-maintenanceauditeventtbs-decode-exact` (branches 2/2). |
| `cap5-export-export-render-0` | 15/17 | metric only, **still failing** | Both render arms and both audit labels are reached, 11 times and 5 times. The only uncovered entries are the two `event.encode()?` propagations, one inside each arm, which cannot fail for an event that decoded. Every narrower span drops one of the two arms, which is the decision. Repair needs the encoding hoisted before the `match`, which is a production change and out of scope here. |
| `credential-replayed-completion-checkpoint` | 45/47 | metric only, **still failing** | The replayed `Committed` gate, its account-service checkpoint plan and the staged durable result are all reached. The two uncovered entries are the `Violation::Ceiling` maps on that plan and on an empty `FanoutRequest`, both inside the gate, so no narrower span excludes them and still holds the gate. |

Four rows now reach 100 percent. Five are left failing with a named remedy;
two of those five (`s10-cap70-projection-write` and
`reload-audit-submission-outcome`) are ordinary test work rather than policy
work, and the issue's premise that all sixteen are blocked by unreachable
unwinds does not hold for them.

## The `login_index` family

COV-01's prose says six `login_index` rotation rows; there are seven, all
under `crates/agenc-ircd-runtime/src/daemon/login_index`. They belong to
COV-03 (#70). Each declares `branches` over a span with no branch records, so
each takes the **metric correction only** — `branches` → `regions`, with
category, span and reason untouched. That is purely a description fix: it
changes no claim and leaves every row failing for COV-03 to close with tests.

| Row | Measured (regions) |
| --- | --- |
| `cap5-login-index-load-secrets` | **16/16** |
| `cap5-transaction-commit-rotation` | 61/69 |
| `cap5-login-index-execute` | 56/63 |
| `cap5-transaction-rotation-batch` | 42/49 |
| `cap5-cleanup-cleanup-transactions` | 25/32 |
| `cap5-transaction-submit` | 13/15 |
| `cap5-scan-visit-opened` | 13/15 |

The metric correction alone brings `cap5-login-index-load-secrets` to 100
percent, so one of COV-03's rows closes here. The family is reached only from
`crates/agenc-ircd/tests/stage_eight_e2ee/stage_ten_login_index`, which drives
the offline entry point as a spawned `agenc-ircd` subprocess; under `--lib`
the two `login_index.rs` rows read 0/63 and 0/16, and with every workspace
target built they read 56/63 and 16/16. That is the `--lib` limitation, not a
coverage gap, and it is why the all-target report is the authoritative one
here.

## The audit outside COV-01's slice

Every one of the 1,144 release regions and all 21 interim regions were scored.
The interim policy `conformance/critical-coverage.toml` holds **no** row with
this defect. The release policy held twenty-five, of which COV-01 had named
sixteen. The nine further rows are:

| Row | File | Measured (regions) | Status |
| --- | --- | --- | --- |
| `storage-initial-guard-absence` | `agenc-ircd-storage/src/platform.rs` | 4/6 | re-scored to `regions`; still failing — the uncovered entry is the reachable `Err(error)` arm for a `statat` failure other than `ENOENT` |
| `storage-declared-recovery-selection` | `agenc-ircd-storage/src/construction_runtime/recovery.rs` | 23/24 | re-scored to `regions`; still failing — the reachable `?` unwind on `validate_at`, which no malformed body reaches |
| `storage-declared-recovery-delivery-key` | `agenc-ircd-storage/src/construction_runtime/recovery.rs` | 5/6 | re-scored to `regions`; still failing — `DeliveryRow::decode` is never given a malformed body |
| `cap5-signature-signaturedomain-label` | `agenc-ircd-crypto/src/signature.rs` | 44/45 | **not touched** — reserved slice |
| `cap5-signature-signaturedomain-encoding` | `agenc-ircd-crypto/src/signature.rs` | 4/4 | **not touched** — reserved slice; a metric correction alone would bring it to 100 percent |
| `leaf-membership-planned-device` | `agenc-ircd-e2ee/src/membership.rs` | 10/10 | **not touched** — reserved slice; a metric correction alone would bring it to 100 percent |
| `e2ee-owner-ledger-index` | `agenc-ircd-runtime/src/e2ee/coordinator/owners.rs` | 51/51 | **not touched** — reserved slice; a metric correction alone would bring it to 100 percent |
| `s10-cap70-companion-restore-install` | `agenc-ircd-runtime/src/e2ee/coordinator/delivery_owner/restore/barriers.rs` | 21/23 | **not touched** — reserved slice |
| `edge-origin-settled-gate` | `agenc-ircd-runtime/src/e2ee/edge/router.rs` | 0/2 | **not touched** — reserved slice |

The six reserved rows are inside the encrypted, authentication and crypto
slice that COV-02 (#72) owns; three of them need nothing but the same metric
correction to reach 100 percent and are handed over rather than edited.

`cli-account-invite-expiry` is not a defect. It looked like one only because
`crates/agenc-ircd/src/main.rs` is a binary crate source that a `--lib` report
omits entirely; under `cargo llvm-cov -p agenc-ircd --all-features --branch`
it scores branches 10/10 as declared.

## The refusal now names the case

`scripts/check-coverage.py` reported both "this span holds no executable code"
and "this span is described by the wrong metric" as
`matched no executable coverage data`, which reads as *untested* and is what
hid this defect. A `branches` declaration whose span matches no branch record
but does match executable regions now refuses separately:

```
critical region cap5-signature-signaturedomain-encoding
(crates/agenc-ircd-crypto/src/signature.rs:159-204) declares the branches
metric over a span that emits 4 executable regions and no branch records, so
it is unscoreable as declared rather than untested; re-score it to the regions
metric or narrow the reviewed span
```

`matched no executable coverage data` now means only what it says: the span
matched neither branch records nor region entries. Both cases are covered by
the script's own self-test, which the gate runs as
`python3 scripts/check-coverage.py self-test <policy>`; it grew from 24 to 25
rejection cases, and the new case also asserts that the same report and span
are accepted once the metric is corrected.

Running the check over the whole-workspace all-target report shows what the
split buys. Fifteen rows used to share the one message; they are now six
declaration defects, each named with its region count, and nine rows that
really do match nothing:

| Row | Span holds |
| --- | --- |
| `cap78-session-sessiontable-queue-snapshot` | a doc comment only |
| `cap74-e2ee-records-key` | a doc comment only |
| `companion-e2ee-records-record-kind-for-key` | rows of a `static` prefix table |
| `companion-e2ee-records-check-state-key` | rows of a `static` prefix table |
| `cap79-result-memory-005-set-backing` | struct fields |
| `edge-delivery-checkpoint-cursor-key` | a `struct` declaration |
| `edge-delivery-checkpoint-decode` | an `enum` declaration |
| `cap74-e2ee-records-decode` | a closing brace, attributes and a declaration |
| `cap73-declared-gates-011-admit-restored-with-backing` | struct fields |

None of those nine is this issue's declaration defect: each is a span anchored
on text that compiles to no code at all, so no metric can score it and
narrowing cannot help. Eight are in the encrypted and storage slices and one
(`cap78-session-sessiontable-queue-snapshot`) is in the base runtime slice.
They need their spans re-anchored onto the item they name, which is span work
for the row's owner, and they are recorded here rather than changed.

## What is still failing

Fourteen rows stay below 100 percent on purpose - eleven of COV-01's sixteen
and three of the nine this audit found - and this record claims nothing about
them:

- `cap5-tbs-maintenanceauditeventtbs-encode` 47/62,
  `cap5-export-export-render-0` 15/17 and
  `credential-replayed-completion-checkpoint` 45/47 hold unreachable `?`
  unwinds interleaved with the decision they are reviewed for. These three are
  the whole case for an exemption mechanism, and they need either the
  propagation restructured out of the span, which is a production change, or
  a policy format that can name an exempt entry. Both belong to a separate
  reviewed change.
- `s10-cap70-projection-write` 18/22 and `reload-audit-submission-outcome`
  23/26 hold reachable entries that simply have no regression. They are test
  work, not policy work.
- `storage-initial-guard-absence` 4/6, `storage-declared-recovery-selection`
  23/24 and `storage-declared-recovery-delivery-key` 5/6 are the same, in
  COV-03's slice.
- Six of the seven `login_index` rows stay with COV-03, at the scores
  tabulated above; the seventh, `cap5-login-index-load-secrets`, reaches 100
  percent on the metric correction alone.

`admin-session-check-repeat` and `remote-account-carrier-admission` are
unchanged. Both were already declared under a metric their span supports, and
both are recorded in the issue as reachable-but-not-from-a-unit-test rather
than as declaration defects.

## Limitations

- Scores are taken from the whole-workspace all-target report; the `--lib`
  report is used only for the entry-by-entry analysis, where the two agree on
  every entry quoted. The three rows a `--lib` report understates are named
  above with both figures.
- A per-crate report counts each crate's own `rlib` copy of every function,
  which no test in that report executes, so a `regions` score taken from one
  understates a `pub(crate)` or `pub(super)` item. Every decision above was
  taken from a workspace report for that reason.
- "Unreachable" in this record means *unreachable from any caller in the
  release build*, established by reading the callee's refusal conditions and by the
  measurement that the entry has zero executions across the whole workspace
  suite. It is not a proof of dead code, and any edit to one of those files
  re-binds the region's `source_sha256` and forces the judgement to be made
  again.
- No overall floor is claimed. The release floors of 90 percent branches and
  90 percent lines and the integrated verdict remain COV-04's (#73).

## Evidence

No production source changed, so no wire or storage format, dependency pin or
limit moved, and the coverage source inventory is unchanged from `ce98ea0`.

Commands and results at this branch:

```sh
python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
# coverage self-test: ok (25 rejection cases)

python3 scripts/check-coverage.py check wt60-cov-all.json \
  conformance/release-critical-coverage.toml
# coverage check failed, with 665 items:
#   1 floor: branch coverage 76.04% is below 90.00% (the line floor passes)
#   6 unscoreable-as-declared rows, every one in the reserved COV-02 (#72) slice
#   9 matched-no-executable rows, the mis-anchored spans tabulated above
#   649 rows below 100.00%
# Every item classifies; none is the ambiguous message this issue removed.

python3 scripts/check-source.py check
# source policy: ok (994 Rust files)

bash scripts/check-spec.sh && python3 scripts/check-evidence.py check
cargo fmt --all --check
# clean; no Rust source changed, so clippy has nothing new to act on
```
