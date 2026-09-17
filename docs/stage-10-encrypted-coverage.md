# Stage 10 encrypted lifecycle, authentication and crypto branch coverage

This record covers COV-02 (issue #72). It closes measured branch-coverage
deficits in the encrypted slice — runtime E2EE
(`crates/agenc-ircd-runtime/src/e2ee/**`, including the companion loader that
pages the E2EE tables at startup), `crates/agenc-ircd-e2ee`,
`crates/agenc-ircd-auth` and `crates/agenc-ircd-crypto`. The base runtime,
domain and wire slice belongs to COV-01 (#66), which merged at `ce98ea0`;
storage, configuration and the offline commands belong to COV-03 (#70).

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

`agenc-ircd-crypto`, `agenc-ircd-auth` and `agenc-ircd-e2ee` keep large parts
of their regression suites in `crates/<crate>/tests/`, which `--lib` does not
build, so each was measured a second time with every target:

```sh
RUSTFLAGS="--cap-lints=warn" cargo +nightly-2026-08-24 llvm-cov \
  -p <crate> --all-features --branch --json --output-path <report>.json
```

Regions were scored with `scripts/check-coverage.py`'s own `branch_counts` and
`region_counts`, merged across reports by coordinate: a region counts as
reached when any measured report reaches it.

Selection: `--all-features`, host `x86_64-unknown-linux-gnu`, toolchain
`rustc 1.98.0 (88d9e12ae 2026-08-18)` for the gate commands and
`nightly-2026-08-24` (`rustc 1.100.0-nightly (fb6531d55 2026-08-23)`) for
instrumentation only. `Cargo.lock` SHA-256:
`eb963d43bb6d08c6833ab51cbcdbccbaef0815b6b5437f1a5b523402454e714d`
(unchanged). Baseline tree: `ce98ea0` (`origin/main`).

### Why `--lib` alone understates the encrypted crates

Under `--lib` the eleven `initial_authority` and `record_authentication`
regions and both `history/reinit` regions read as entirely uncovered, because
every case that drives them lives in `crates/agenc-ircd-e2ee/tests/`. The
per-crate all-target report reaches all thirteen. Both figures are reported
below so the difference stays a measurement fact rather than a claim. The new
cases in this branch are all in-crate unit tests, so each one is visible in
both measurements.

## Before and after

Overall workspace totals, same command, same selection:

| Tree | Branches | Lines |
| --- | --- | --- |
| `ce98ea0` (before) | 65.8418% (16,284/24,732) | 82.0205% (164,593/200,673) |
| this branch (after) | 65.9793% (16,318/24,732) | 82.0265% (164,605/200,673) |

The overall branch percentage moves by 0.14 points because this issue targets
named decisions rather than volume; the aggregate 90 percent floor is COV-04's
(#73) integrated verdict and is not claimed here.

Critical regions inside this slice, at 100 percent under their declared
metric:

| Measurement | Before | After |
| --- | --- | --- |
| workspace `--lib` report only | 163 at 100% / 335 below | 181 at 100% / 317 below |
| plus the per-crate all-target reports | 172 at 100% / 326 below | 190 at 100% / 308 below |

Both measurements agree on the delta: **18 regions in this slice reach 100
percent that did not before, and none regressed.** The slice holds 498
reviewed regions in total, split 8 in `agenc-ircd-crypto` (all 8 now at 100
percent), 56 in `agenc-ircd-e2ee` (32 at 100 percent) and 434 under
`crates/agenc-ircd-runtime/src/e2ee/**` (150 at 100 percent).
`agenc-ircd-auth` declares none.

## Regions that now reach 100 percent

Eighteen regions, with their metric and their after counts. Five of them are
metric corrections, marked and explained under "Region metric corrections".

Cryptographic adapters (`agenc-ircd-crypto`):

| Region | Metric | After |
| --- | --- | --- |
| `cap5-signature-signaturedomain-label` | regions (corrected) | 45/45 |
| `cap5-signature-signaturedomain-encoding` | regions (corrected) | 4/4 |

Encrypted domain (`agenc-ircd-e2ee`):

| Region | Metric | After |
| --- | --- | --- |
| `e2ee-check-policy-lineage` | branches | 10/10 |
| `e2ee-check-policy-bounds` | branches | 10/10 |
| `e2ee-route-verify-semantic-route` | branches | 20/20 |
| `e2ee-route-verify-binding-package` | branches | 8/8 |
| `e2ee-verify-commit-authorization` | branches | 8/8 |
| `leaf-membership-admission` | branches | 32/32 |
| `leaf-membership-planned-device` | regions (corrected) | 10/10 |
| `cap83-finality-quorumledger-record-encoded` | regions | 41/41 |

Runtime E2EE and the companion loader (`agenc-ircd-runtime/src/e2ee`):

| Region | Metric | After |
| --- | --- | --- |
| `s10-cap70-companion-restore-validate-event` | branches | 16/16 |
| `s10-cap70-companion-restore-validate-part` | branches | 16/16 |
| `s10-cap70-companion-restore-validate-complete` | branches | 8/8 |
| `s10-cap70-companion-restore-validate-owners` | branches | 6/6 |
| `s10-cap70-companion-restore-install` | regions (corrected) | 23/23 |
| `s10-cap94-validate-barrier-resume` | branches | 10/10 |
| `s10-cap94-acknowledge-barrier-resume` | branches | 2/2 |
| `e2ee-owner-ledger-index` | regions (corrected) | 51/51 |

## What the new regressions prove

### Every registered signature domain

`crates/agenc-ircd-crypto/src/signature/tests/domains.rs`

One key and one content produce forty-four distinct signatures, one per
registered `SignatureDomain`, each verifying under its own domain and none
verifying under its successor in the registry. Every label is unique, not
empty, and carries the prefix its declared encoding requires: thirty-two
`IRC-MLS/1 ` labels under the IRC signature input, ten `agenc-chat ` labels
under the direct prefix and two `MLS 1.0 ` labels under RFC 9420
`SignWithLabel`. The list is exhaustive, so a new domain fails the count
before it can reach the wire with an unexercised label.

### Conversation policy profile, lineage and bounds

`crates/agenc-ircd-e2ee/src/tests/policy/fences.rs`

- A later profile version and a later MLS version are each refused with
  `ProfileMismatch` before any principal set is resolved, and the policy of
  one network is refused by another network. One disabled suite in the
  allowed set refuses the whole set although the mandatory suite and the
  selected suite are both present.
- Generation zero without a predecessor names no previous policy; a successor
  must name the identifier of the policy it replaces; and a generation never
  changes the conversation kind. The accepted successor differs from each
  refusal by exactly that one field.
- The device and leaf caps admit exactly `1..=MAX_ACTIVE_DEVICES_PER_ACCOUNT`
  and `1..=MAX_GROUP_LEAVES`: zero and one beyond each cap are refused with
  `LimitExceeded`, and the same two fields at the bottom of their ranges are
  admitted under a policy whose approvals cover the changed bytes, so each
  refusal rests on the bound and not on the edit.

### Semantic routes and replacement bindings

`crates/agenc-ircd-e2ee/src/tests/route/fences.rs`

- A route of a later profile is refused before its kind is read, although its
  network matches.
- A channel route names neither direct account; a direct route pins no channel
  authority root. Each refusal differs from the accepted route of its own kind
  by exactly one field.
- A replacement binding at generation one is accepted carrying no proof of its
  own, and the same binding carrying the initial binding's unanimous approvals
  is refused. Only an initial binding carries approvals.

### Commit authorization signer identity

`crates/agenc-ircd-e2ee/src/tests/authorization/fences.rs`

- One controller root states one approval however many devices it holds: an
  approval list that is already canonical by `(root, device)` but repeats a
  root through two of its own devices is refused `NonCanonical`, and the
  single approval from the same root is accepted.
- Two distinct controller roots that enrolled the same device signature key
  never count twice. No roster check can see this on its own, because each
  roster holds only its own certificate; the authorization refuses it at the
  key set.

### The retained leaf-membership claim

`crates/agenc-ircd-e2ee/src/tests/membership/fences.rs`

A device that holds a continuing proof on one leaf and states its own removal
of another leaf at the same epoch claims nothing: the removal is admitted (it
is not a duplicate continuing leaf), both proofs stay retained, the continuing
proof still identifies the ACKs of its own epoch, and the expected continuing
set drops the device while leaving every other device standing. With the
removal one epoch behind, the claim stands; raising it to the continuing epoch
retires the device.

### The council seat a policy pinned

`crates/agenc-ircd-e2ee/src/tests/finality/roster_fences.rs`

A vote is recorded only while the current roster still holds exactly the
certificate the policy pinned. A council device the root dropped from its
republished roster cannot vote although the policy still names the seat, and a
device that re-enrolled under a new certificate serial — same device
identity, same key — does not inherit it. Both refusals record no vote.

### The durable companion gate

`crates/agenc-ircd-runtime/src/e2ee/coordinator/delivery_owner/restore/barriers/tests/fences.rs`

- Each of the six gated fields of one companion part is checked on its own:
  the delivery generation, the coordinator state generation, the mutation
  identity, the part index, the part count and the acknowledgement state. The
  gate's last sequence additionally pins its event identity.
- Outside the gated range, a part of another mutation is admitted once it is
  acknowledged and refused while it is not; the gate's own mutation is refused
  beyond its range even acknowledged; a plain event carrying no part passes
  outside the range and is a hole inside it; and a malformed part tuple is
  refused before any gate is consulted.
- An open gate needs its rows contiguous from its first sequence: dropping the
  first row is refused and changes no retained row.
- Every gate needs a READY owner that still owes one profile: a peer with no
  owner, a gate both of whose profiles are acknowledged, and a retired owner
  are each refused.
- Installing a gate needs its peer stream complete first: an absent stream and
  a stream missing the first gated row are both refused and install no
  barrier; the complete stream installs the hold and the open barrier.

### Barrier resume

`crates/agenc-ircd-runtime/src/e2ee/coordinator/events/tests/barrier_resume.rs`

A resume recovers a lost ordinary prefix only through the exact gate end: the
first gated sequence, the gate end under another event identity, a stream
carrying no open gate, and a committed acknowledgement at `u64::MAX` (which
cannot name a successor) are each refused rather than wrapped. A row already
covered by a committed acknowledgement is not part of the recovered prefix. An
`acknowledge_barrier_resume` whose acknowledgement is not one commits no
coverage, acknowledges no row and leaves the gate open; the same call with a
real acknowledgement records it.

## Region metric corrections

Five regions in this slice were declared with `metric = "branches"` over spans
that LLVM's branch instrumentation does not describe at all: their decisions
are `match` arms, slice patterns and `?` propagation, none of which emit branch
records. `scripts/check-coverage.py` fails such a region with `matched no
executable coverage data` no matter how it is tested, so every one of them was
a guaranteed policy failure rather than a coverage gap. This is the same
declaration defect COV-01 (#66) recorded, and it is corrected the same way.

Each of the five was re-scored to `metric = "regions"`, which counts the
executable entry regions the span really has. The category, the file, the span
and the reason of every row are untouched, and each row reaches 100 percent on
the after report:

| Region | File and span | Before | After |
| --- | --- | --- | --- |
| `cap5-signature-signaturedomain-label` | `crates/agenc-ircd-crypto/src/signature.rs:111-157` | `branches` 0/0 | `regions` 45/45 |
| `cap5-signature-signaturedomain-encoding` | `crates/agenc-ircd-crypto/src/signature.rs:159-204` | `branches` 0/0 | `regions` 4/4 |
| `leaf-membership-planned-device` | `crates/agenc-ircd-e2ee/src/membership.rs:387-399` | `branches` 0/0 | `regions` 10/10 |
| `s10-cap70-companion-restore-install` | `crates/agenc-ircd-runtime/src/e2ee/coordinator/delivery_owner/restore/barriers.rs:128-140` | `branches` 0/0 | `regions` 23/23 |
| `e2ee-owner-ledger-index` | `crates/agenc-ircd-runtime/src/e2ee/coordinator/owners.rs:113-153` | `branches` 0/0 | `regions` 51/51 |

Two of the five needed new cases as well as the correction: the label table
needed the `ReinitAttempt` arm, which no other suite had reached, and the
companion loader's `install` needed both of its refusals. The other three were
already fully exercised and only their metric was wrong.

One further region in this slice carries the same declaration defect and does
**not** reach 100 percent under either metric, so its declaration is left
untouched for review; it is listed under "Not closed" below.

## Not closed

### Rows that cannot reach 100 percent under their declared metric

These three are left exactly as declared. They belong to the open coverage
policy issue #135, not to this branch.

| Region | Declared | After | Why it cannot close |
| --- | --- | --- | --- |
| `e2ee-verify-policy` | `branches` | 1/2 (`regions` 75/79) | unreachable guard, see below |
| `e2ee-check-policy-profile` | `branches` | 17/18 (`regions` 34/34) | unreachable guard, see below |
| `edge-origin-settled-gate` | `branches` | 0/0 (`regions` 0/2) | stale anchor, see below |

`e2ee-verify-policy` (`crates/agenc-ircd-e2ee/src/policy.rs:129-170`) guards
`policy.encode()?.len() > MAX_POLICY_BYTES`, and that condition cannot be true
for any value the type admits. `MAX_POLICY_BYTES` is 32,768, while the TLS
field bounds of `IrcPolicyTbs` cap its encoding at roughly 7.3 KiB
(`allowed_suites` at 32 bytes, `controller_root_fingerprints` at 2,048,
`finality_principals` at 5,120) and `IrcPolicy::approvals` adds at most 16,384,
so a constructible policy encodes to at most about 23.7 KiB. The guard is
correct defence in depth against a later field-bound change; it is simply not
reachable today. Its three remaining `regions` entries are `?` unwinds on
hashing and boolean decoding that cannot fail for a policy that reached them,
so the `regions` metric does not close it either.

`e2ee-check-policy-profile` (`crates/agenc-ircd-e2ee/src/policy.rs:172-195`)
now covers seventeen of eighteen outcomes; the last one needs
`tbs.allowed_suites` to be empty. `TlsVec<u16, 2, 32>` requires at least two
encoded bytes, so neither `TlsVec::new` nor the decoder can produce an empty
allowed-suite set. The region does reach 34/34 under `regions`, but re-scoring
it would be lowering a floor to pass a counter rather than correcting a
declaration defect — the span emits real branch records — so it is left as
declared.

`edge-origin-settled-gate`
(`crates/agenc-ircd-runtime/src/e2ee/edge/router.rs:609-611`) is mis-anchored.
Its reason reads "Requests leave the edge only under an acknowledged
declaration that carries the current attachment", which is `settled()` at
lines 622-628 of the same file; the declared span is instead two argument
lines inside the `SubmitKind::Membership` decode arm of
`submitted_identifier`, which emits no branch records and whose two region
entries no current test reaches. Moving a reviewed span is a policy change, so
the row is reported rather than adjusted.

### The rest of the slice

308 regions in this slice are still below 100 percent after this work: 24 in
`agenc-ircd-e2ee` and 284 under `crates/agenc-ircd-runtime/src/e2ee/**`,
concentrated in the coordinator's sync, startup, delivery-owner restore,
retention and mailbox owners. Of those, 86 have no uncovered branch outcome at
all and only `?`, `ok_or` or `map_err` unwinds left — the same class COV-01
recorded as unreachable error propagation — while 192 still hold at least one
uncovered branch outcome and are ordinary coverage gaps. They remain open for
the COV-04 (#73) integrated verdict, and this record makes no claim about
them.

## Limitations

- The workspace figures use `--lib`, so they exclude every
  `crates/*/tests/` integration target. The per-crate all-target reports are
  supplied for `agenc-ircd-crypto`, `agenc-ircd-auth` and `agenc-ircd-e2ee`,
  where that difference is material; the runtime's integration targets were
  not measured, and the heavy ones (`e2ee_load`, `idle_connection_memory`,
  `loom_models`, `stage_six_soak`) were not run.
- A per-crate report counts each crate's own `rlib` copy of every function,
  which no test in that report executes; a `regions` score taken from a
  per-crate report therefore understates a `pub(crate)` or `pub(super)` item.
  Every metric correction below was validated on the workspace report, where
  the dependent crates' tests exercise that copy.
- `agenc-ircd-auth` declares no release-critical region, so nothing in this
  slice is claimed for it; its measured branch coverage is reported only as
  part of the workspace aggregate.
- No overall floor is claimed. The release floors of 90 percent branches and
  90 percent lines remain COV-04's (#73) integrated verdict.

## Evidence

New test sources, all under a `tests` path component:

- `crates/agenc-ircd-crypto/src/signature/tests/domains.rs`
- `crates/agenc-ircd-e2ee/src/tests/policy/fences.rs`
- `crates/agenc-ircd-e2ee/src/tests/route/fences.rs`
- `crates/agenc-ircd-e2ee/src/tests/authorization/fences.rs`
- `crates/agenc-ircd-e2ee/src/tests/membership/fences.rs`
- `crates/agenc-ircd-e2ee/src/tests/finality/roster_fences.rs`
- `crates/agenc-ircd-runtime/src/e2ee/coordinator/delivery_owner/restore/barriers/tests/fences.rs`
- `crates/agenc-ircd-runtime/src/e2ee/coordinator/events/tests/barrier_resume.rs`

plus the `mod` lines that admit them. No production handler changed, so this
work adds no wire or storage format, no dependency pin and no limit.

Commands and results at this branch:

```sh
cargo test -p agenc-ircd-crypto --all-features --locked
# 35 unit tests and every integration target pass, with one ignored

cargo test -p agenc-ircd-auth --all-features --locked
# 33 unit tests and every integration target pass, with one ignored

cargo test -p agenc-ircd-e2ee --all-features --locked
# 150 unit tests and every integration target pass; no failures

cargo test -p agenc-ircd-runtime --all-features --locked
# 1,549 unit tests pass with one ignored, and every integration target passes:
# bridge_crypto 8, bridge_storage 6, e2ee_load 1, federation_link 16,
# idle_connection_memory 2 with one ignored, listener_accept 22,
# loom_models 6, shutdown 11, stage_six_soak 2, tls_endpoint 15,
# tls_federation_policy 1, tls_fixture_spike 4, tor_client 7. No failures.

cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
# clean

cargo fmt --all --check
python3 scripts/check-source.py check
# source policy: ok

python3 scripts/check-coverage.py self-test conformance/critical-coverage.toml
python3 scripts/check-coverage.py self-test conformance/release-critical-coverage.toml
# coverage self-test: ok (24 rejection cases)
```

The coverage source inventory in `conformance/critical-coverage.toml` and
`conformance/release-critical-coverage.toml` is reanchored to the current
production sources.
