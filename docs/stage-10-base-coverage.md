# Stage 10 base runtime, domain and wire branch coverage

This record covers COV-01 (issue #66). It closes measured branch-coverage
deficits in the base slice — StateCore, connections, registration, account
routing, administration, reload and shutdown, federation receipts and
projections, history and WSS, domain authorization and the wire parser and
enum boundaries. Runtime E2EE and loader E2EE belong to COV-02 (#72); storage,
configuration and the offline commands belong to COV-03 (#70).

Nothing here changes a production handler. Every source change is a test
module under a `tests` path component plus the one `mod` line that admits it,
and the coverage policy changes are metric corrections whose rationale is
recorded below.

## How the report was produced

The workspace figures below come from one command per tree, run on the pinned
nightly that carries `-C instrument-coverage` branch support, with
`cargo-llvm-cov 0.9.0`:

```sh
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  --workspace --all-features --branch --lib --json \
  --output-path <report>.json
```

Per-crate reports, used where a crate's regression suite lives in
`crates/<crate>/tests/` rather than in `src/**/tests/`, come from:

```sh
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  -p <crate> --all-features --branch --json --output-path <report>.json
```

Regions were scored with `scripts/check-coverage.py`'s own `branch_counts` and
`region_counts`, merged across reports by coordinate.

Selection: `--all-features`, host `x86_64-unknown-linux-gnu`, toolchain
`rustc 1.98.0 (88d9e12ae 2026-08-18)` for the gate commands and
`nightly-2026-08-24` for instrumentation only. `Cargo.lock` SHA-256:
`eb963d43bb6d08c6833ab51cbcdbccbaef0815b6b5437f1a5b523402454e714d`
(unchanged). Baseline tree: `165570e` (`origin/main`).

### Why `--lib` alone understates two crates

`agenc-ircd-types`, `agenc-ircd-client-wire` and `agenc-ircd-federation-wire`
keep their regression suites in `crates/<crate>/tests/`, which `--lib` does not
build. Under `--lib` the twenty-nine `generated_registry.rs` decoder regions
and the twenty-one client and federation wire regions read as uncovered; under
the per-crate all-target command every one of those fifty regions is already
at 100 percent. Both figures are reported below so the difference is a
measurement fact rather than a claim.

## Before and after

Overall workspace totals, same command, same selection:

| Tree | Branches | Lines |
| --- | --- | --- |
| `165570e` (before) | 65.6883% (16,225/24,700) | 81.9556% (164,312/200,489) |
| this branch (after) | 65.8097% (16,255/24,700) | 82.0065% (164,414/200,489) |

Critical regions inside this slice, at 100 percent under their declared
metric:

| Measurement | Before | After |
| --- | --- | --- |
| workspace `--lib` report only | 160 at 100% / 312 below | 201 at 100% / 271 below |
| plus the per-crate all-target reports | 193 at 100% / 279 below | 234 at 100% / 238 below |

Both measurements agree on the delta: **41 regions in this slice reach 100
percent that did not before, and none regressed.**

The overall branch percentage moves by only 0.12 points because this issue
targets named decisions rather than volume; the aggregate 90 percent floor is
COV-04's (#73) integrated verdict and is not claimed here.

## Regions that now reach 100 percent

Forty-one regions, with their metric and their after counts.

Domain authorization and state (`agenc-ircd-domain`):

| Region | Metric | After |
| --- | --- | --- |
| `domain-command-authorization` | branches | 96/96 |
| `domain-authorize-direct-policy` | branches | 10/10 |
| `domain-authorize-sanction` | branches | 14/14 |
| `mode-mask-lookup-after-authorization` | branches | 4/4 |
| `domain-channel-validate` | branches | 14/14 |
| `account-suspension-revision` | regions | 17/17 |
| `account-restoration-revision` | branches | 2/2 |
| `replica-validate-children` | branches | 4/4 |
| `replica-validate-invites` | branches | 4/4 |
| `replica-event-durable-rows` | branches | 48/48 |

Administration (`agenc-ircd-admin` and `agenc-ircd-runtime/src/admin`):

| Region | Metric | After |
| --- | --- | --- |
| `cap5-export-command-parse` | regions | 138/138 |
| `cap5-export-command-verb` | regions | 23/23 |
| `cap5-export-command-required-permission` | regions | 13/13 |
| `cap5-export-command-is-read-only` | regions | 4/4 |
| `cap5-export-export-sequence` | regions | 9/9 |
| `cap5-export-export-from` | regions | 7/7 |
| `cap5-export-audit-render-export-batch` | regions | 9/9 |
| `cap5-export-audit-check-export-coverage` | branches | 6/6 |
| `cap5-audit-event-auditevent-decode-exact` | regions | 18/18 |
| `cap5-audit-event-auditevent-encode` | regions | 9/9 |
| `cap5-audit-event-auditevent-encoding` | regions | 5/5 |
| `cap5-audit-event-auditchaincursor-advance-event` | regions | 10/10 |
| `cap5-state-maintenanceoperation-from-u16` | regions | 6/6 |
| `cap5-state-maintenancekeystate-take` | regions | 20/20 |
| `cap5-state-maintenancetransition-take` | regions | 14/14 |
| `cap5-state-maintenancetransition-validate` | regions | 13/13 |
| `cap5-state-maintenancetransition-validate-start` | branches | 10/10 |
| `cap5-tbs-maintenanceauditeventtbs-decode-exact` | branches | 2/2 |
| `cap5-audit-auditauthority-prepare-retention` | branches | 2/2 |
| `cap5-audit-auditauthority-sign-retention` | branches | 16/16 |
| `cap5-export-audit-finish-with-observed` | branches | 4/4 |
| `cap5-export-job-run` | regions | 7/7 |
| `audit-verify-export-coverage` | branches | 10/10 |
| `cap5-mixed-permitted-kind` | regions | 4/4 |
| `cap5-maintenance-preparedmaintenanceaudit-mutation-head` | regions | 9/9 |
| `cap5-maintenance-auditauthority-commit-maintenance-event` | regions | 14/14 |
| `cap5-transaction-maintenance-state` | regions | 20/20 |

Base runtime and federation classification:

| Region | Metric | After |
| --- | --- | --- |
| `guest-control-before-name-lookup` | branches | 2/2 |
| `runtime-resume-rejection-classification` | regions | 4/4 |
| `runtime-journal-stage-refusal-classification` | regions | 4/4 |
| `runtime-journal-storage-refusal-classification` | regions | 4/4 |

## What the new regressions prove

### Domain authorization fences

`crates/agenc-ircd-domain/src/decision/tests/authority_fences.rs`

- A session whose home peer is suspended is refused execution with
  `ServerBusy` and is refused as a new direct-message target with the same
  `NotFound` an absent nickname receives. The refusal changes no revision and
  removes neither the session nor its nickname index, so grace visibility
  survives the fence; `resume_federation_peer` restores both outcomes exactly.
- A session seed whose public cloak already belongs to a live session is
  refused `BadState` although its session ID, user ID and nickname are all
  fresh; the same seed with its own cloak is admitted.
- A `Deny` direct-message policy refuses a sender the recipient's contact set
  admits under `Contacts`, leaving the contact set intact.
- A permanent channel ban is admitted for an owner and refused for an
  operator, and the permanent form never reaches the kick-only role
  comparison. Planning the refusal advances no revision.
- A `RemoveMaskValue` inside one mode vector resolves only the addition the
  same vector staged for the same list and the same value; an addition on
  another list or of another value leaves the removal unresolved and the
  channel unchanged. The accepted vector runs the whole
  authorize/plan/prepare/apply path.

### Committed administrative account transitions

`crates/agenc-ircd-domain/src/model/tests/admin_fences.rs`

- A channel key mode and its stored verifier must appear together; either
  alone is an invariant violation.
- A pending encrypted-removal entry is refused outside an E2EE-bound channel
  and refused for a non-member.
- Suspension advances the account revision and the authoritative revision to
  the same value; an unknown account and a revision that cannot advance are
  both refused with the account and both revisions unchanged.
- Restoring an account that carries no suspension is refused and does not
  clear another account's suspension; a second restore of the same account is
  refused as well.

### Edge replica reference checks

`crates/agenc-ircd-domain/src/federation/tests/replica/reference_fences.rs`

- A membership whose channel resolves but whose session does not dangles, and
  the refused snapshot leaves the standing generation and its entries in
  place.
- An invite whose channel is absent dangles even though its target is hosted.
- An `Invited` event whose standing copy names another channel is refused as
  an invalid record before the dangling-reference and duplicate checks.
- A direct message from a remote sender to a hosted recipient delivers to the
  recipient alone; when neither end is hosted the edge delivers nothing.

### Maintenance key-state decoding

`crates/agenc-ircd-admin/src/maintenance/state/tests/mod.rs`

- Five truncations, one immediately before each field of the encoded
  key-state tuple, are each refused by the real `Reader`; only the exact
  eighty-byte encoding decodes back to the value written.
- A transition body whose operation discriminator is unassigned, and one too
  short to hold a discriminator at all, are refused before either tuple is
  read.
- A rotation start whose resulting state reports no previous generation is
  refused.
- The transition checker re-validates both tuples rather than trusting its
  caller, and still refuses a rotation start that would install the key it
  claims to replace. These two values cannot be produced by any public
  constructor, so the case builds them through the module-private form; the
  point is that the checker does not depend on the constructor having run.

### Administrative command arguments and audit export

`crates/agenc-ircd-admin/src/command/tests/argument_refusals.rs`,
`crates/agenc-ircd-admin/src/audit/tests/export_records.rs`,
`crates/agenc-ircd-admin/src/maintenance/tests/mod.rs`

- Twelve lines refuse one identifier or one reason each, and seven accepted
  lines differ from them only in that argument, so each refusal rests on the
  argument alone.
- `RESTART` and `DIE` each report their own verb in FAIL and NOTE replies.
- The independently signed encoding-two maintenance body exports under
  `NOTE AUDIT MAINTENANCE` with its exact encoded bytes, and a batch whose
  first record starts after the requested range is refused whole.
- The maintenance TBS decoder accepts exactly its 358-byte length and refuses
  every shorter and every padded buffer.

### Runtime audit authority

`crates/agenc-ircd-runtime/src/admin/audit/tests/authority_fences.rs`

- An authority that has not reconciled its persisted chain refuses both
  retention steps, and refusing leaves the chain position, the retained-first
  sequence and the checkpoint position unchanged. The same checkpoint signs
  while the authority is reconciled.
- A frozen export is released only by its own `Observed` event; the other four
  phases are refused before the batch renders.
- A range beginning after the last assigned sequence must carry no records:
  an empty batch is accepted and a checkpoint for that range is refused.
- Only `(Audit, 1)`, `(Audit, 2)` and `(AuditCheckpoint, 1)` are readable back
  into the verified chain; seven other table and record-kind pairs are
  refused.

### Channel-control account fence

`crates/agenc-ircd-runtime/src/command_convert/tests/control_account_fence.rs`

Every channel-control kind is refused for a session with no account and
admitted for one with an account, and the nickname family is unaffected in
both directions — the fence runs before the target name is consulted, so an
unauthenticated client learns nothing about whether a channel exists.

## Region metric corrections

Twenty-four regions in this slice were declared with `metric = "branches"`
over spans that LLVM's branch instrumentation does not describe at all: the
span's decisions are `match` arms, slice patterns and `?` propagation, none of
which emit branch records. `scripts/check-coverage.py` fails such a region
with `matched no executable coverage data` no matter how it is tested, so
every one of them was a guaranteed policy failure rather than a coverage gap.

Each of the twenty-four was re-scored to `metric = "regions"`, which counts
the executable entry regions the span really has, and each then reaches 100
percent on the after report. The category inventory is unchanged; no span, no
reason and no file moved. The corrected regions are the twenty-four listed in
the tables above whose metric reads `regions`.

Sixteen further regions in this slice have the same declaration defect but do
**not** reach 100 percent under either metric, so their declarations were left
untouched for review; they are listed under "Not closed" below.

## Not closed

### The declaration defect that needs review

These sixteen carry `metric = "branches"` over a span with no branch records,
and their `regions` score cannot reach 100 percent either, because the
remaining entries are `?` unwinds on paths that cannot fail:

| Region | `regions` score | Why it cannot close |
| --- | --- | --- |
| `cap5-tbs-maintenanceauditeventtbs-encode` | 47/62 | `validate()?` cannot fail for a constructed TBS and the writer ceiling equals the encoded size, so all eight `?` unwinds are unreachable |
| `cap5-mod-maintenanceauditevent-sign` | 19/21 | `tbs.hash()?` and the `sign_canonical` error map cannot fail for a validated TBS and a valid key |
| `cap5-export-export-render-0` | 15/17 | `event.encode()?` cannot fail for an event that decoded |
| `runtime-join-echo-result-channels` | 35/37 | a checked add that cannot overflow and a frame accessor on an already validated frame |
| `credential-replayed-completion-checkpoint` | 45/47 | two `Violation::Ceiling` maps on checked arithmetic that cannot overflow |
| `cap5-maintenance-preparedmaintenanceaudit-audit-mutation` | 28/34 | six `?` unwinds on encoding and key construction that cannot fail |
| `s10-cap70-projection-write` | 18/22 | `?` unwinds on row accessors that cannot fail for a projected row |
| `s10-cap70-projection-delete` | 8/9 | same |
| `reload-audit-submission-outcome` | 23/26 | the cancellation and rejection arms of the reload `select!` |
| `cap5-login-index-execute` | 0/63 | the offline `login-index rotate` entry point, owned by COV-03 (#70) |
| `cap5-login-index-load-secrets` | 0/16 | same |
| `cap5-transaction-commit-rotation` | 61/69 | same |
| `cap5-transaction-rotation-batch` | 42/49 | same |
| `cap5-transaction-submit` | 13/15 | same |
| `cap5-cleanup-cleanup-transactions` | 25/32 | same |
| `cap5-scan-visit-opened` | 13/15 | same |

The six `login_index` rows are inside COV-03's slice and were deliberately not
touched here; the other ten need either a narrower reviewed span or an
accepted exemption, which is a policy decision rather than a test.

### `admin-session-check-repeat`

19/20 under its declared `regions` metric. The one uncovered entry is the
error map on `PendingConfirmation::check`, which fails only when
`issued_at + CONFIRMATION_TTL_MILLIS` overflows. Reaching it needs the full
signed administrative handshake driven at a monotonic clock within
`CONFIRMATION_TTL_MILLIS` of `u64::MAX`; the runtime admin harness does not
admit an injected clock at that value today.

### The rest of the slice

238 regions in this slice are still below 100 percent after this work,
concentrated in the federation coordinator and edge owners
(`federation/coordinator/companion.rs`, `startup/*`, `query/*`,
`edge/ordinary_batch*`, `edge/events.rs`). They are ordinary uncovered
decisions rather than declaration defects, and they remain open for the
COV-04 (#73) integrated verdict. This record makes no claim about them.

## Limitations

- The workspace figures use `--lib`, so they exclude every
  `crates/*/tests/` integration target. The per-crate all-target reports are
  supplied for the three wire crates where that difference is material; the
  runtime integration targets that are cheap to run (`bridge_crypto`,
  `bridge_storage`, `federation_link`, `listener_accept`, `shutdown`,
  `tls_endpoint`, `tls_federation_policy`, `tls_fixture_spike`, `tor_client`)
  were also measured, and the heavy targets (`e2ee_load`,
  `idle_connection_memory`, `loom_models`, `stage_six_soak`) were not.
- A per-crate report counts each crate's own `rlib` copy of every function,
  which no test in that report executes; a `regions` score taken from a
  per-crate report therefore understates a `pub(crate)` or `pub(super)` item.
  Every metric correction above was validated on the workspace report, where
  the dependent crates' tests exercise that copy.
- No overall floor is claimed. The release floors of 90 percent branches and
  90 percent lines remain COV-04's (#73) integrated verdict.

## Evidence

New test sources, all under a `tests` path component:

- `crates/agenc-ircd-domain/src/decision/tests/authority_fences.rs`
- `crates/agenc-ircd-domain/src/model/tests/admin_fences.rs`
- `crates/agenc-ircd-domain/src/federation/tests/replica/reference_fences.rs`
- `crates/agenc-ircd-admin/src/maintenance/state/tests/mod.rs`
- `crates/agenc-ircd-admin/src/command/tests/argument_refusals.rs`
- `crates/agenc-ircd-admin/src/audit/tests/export_records.rs`
- `crates/agenc-ircd-runtime/src/admin/audit/tests/authority_fences.rs`
- `crates/agenc-ircd-runtime/src/command_convert/tests/control_account_fence.rs`

plus one case appended to
`crates/agenc-ircd-admin/src/maintenance/tests/mod.rs` and the `mod` lines that
admit the new modules. No production handler changed, so this work adds no
wire or storage format, no dependency pin and no limit.

Commands and results at this branch:

```sh
cargo test -p agenc-ircd-domain --all-features --locked
# 179 + 7 passed; 0 failed

cargo test -p agenc-ircd-admin --all-features --locked
# 56 + 1 passed; 0 failed

cargo test -p agenc-ircd-client-wire --all-features --locked
cargo test -p agenc-ircd-federation-wire --all-features --locked
cargo test -p agenc-ircd-types --all-features --locked
# every target passes; no failures

cargo test -p agenc-ircd-runtime --all-features --locked
# 1,534 unit tests pass with one ignored, and every integration target passes:
# bridge_crypto 8, bridge_storage 6, e2ee_load 1, federation_link 16,
# idle_connection_memory 2 with one ignored, listener_accept 22,
# loom_models 6, shutdown 11, stage_six_soak 2, tls_endpoint 15,
# tls_federation_policy 1, tls_fixture_spike 4, tor_client 7. No failures.

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean

cargo fmt --all --check
python3 scripts/check-source.py check
# source policy: ok (988 Rust files)

python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
# coverage self-test: ok (24 rejection cases)
```

The coverage source inventory in `conformance/critical-coverage.toml` and
`conformance/release-critical-coverage.toml` is reanchored to the 832 current
production sources. Seventeen release regions and one interim region moved
with the three lines added to
`crates/agenc-ircd-admin/src/maintenance/state.rs`; no region text changed.
