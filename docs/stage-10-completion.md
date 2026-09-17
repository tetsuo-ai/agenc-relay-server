# Stage 10 completion ledger

This working ledger tracks the implementation requested on 2026-09-10. It is
not a conformance manifest. A checked implementation item does not close a
production gate or qualify another source commit.

## Baseline

The earlier Stage 10 implementation and repairs merged through
[PR 27](https://github.com/tetsuo-ai/agenc-ircd/pull/27). The credential and
runtime follow-up starts at merge commit
`fd7d39476302caae385e69bdea126d0a54164233`.

The invitation FINISH revalidation repair (audit subfinding ZDH-A1, issue
#38) is recorded in
[the invitation FINISH repair](stage-10-invitation-finish-repair.md).
The closed filesystem rejection causes (STO-09, issue #50) are recorded in
[the filesystem causes record](stage-10-filesystem-causes.md).
The silent post-TLS close follow-up (RUN-03, issue #45) is recorded in
[the admission diagnostics record](stage-10-admission-diagnostics.md).
The backup post-rename failure repair (STO-06, issue #48) is recorded in
[the backup publication repair](stage-10-backup-publication-repair.md).
The LIST selection and scan-charging repair (RUN-02, issue #54) is recorded
in [the LIST selection repair](stage-10-list-selection-repair.md).
The historical public authority chain verifier (ENC-02, issue #51) is
recorded in [the historical chain record](stage-10-historical-chain.md).
Durable object ownership, retention classes, trusted acceptance ages and the
conversation and global disk quotas (ENC-08, issue #53) are recorded in
[the object ownership record](stage-10-object-owners.md).
The recovery submission carrier that lets a restored pending route become
permanently closed or conflict (ENC-03, issue #57) is recorded in
[the recovery submission record](stage-10-recovery-submission.md).
The three sequencer signer roles, per-conversation credential pins and the
startup reconciliation across a key rotation (ENC-07, issue #58) are recorded
in [the sequencer signer record](stage-10-sequencer-signers.md).
The edge's bounded durable snapshot generations with exact READY and ACTIVE
recovery (ENC-14, issue #59) are recorded in
[the edge snapshot generations record](stage-10-edge-snapshot-generations.md).
The re-verification and disposition of the four secondary 2026-09-01 audit
findings ZDH-C3, C4, C5 and A1 (issue #13) are recorded in
[the secondary audit findings record](stage-10-audit-secondary-findings.md).
Further task isolation, generated administrator identity and federated MODE
repairs are recorded in [the runtime follow-up](stage-10-runtime-followup.md).
Independent connection scheduling and borrowed storage ciphertext are recorded
in [the client input repair](stage-10-client-input-repair.md) and
[the storage copy repair](stage-10-storage-copy-repair.md). On-demand input
and output queue backing and the default idle admission model (RUN-04, issue
#46) are recorded in [the idle connection backing record](stage-10-idle-backing.md).
The preceding operational changes are recorded in
[the operational repair report](stage-10-operational-repair.md). Earlier credential
and runtime repairs are recorded in
[the credential and runtime repair report](stage-10-credential-runtime-repair.md).
Earlier test and coverage measurements apply to their recorded sources. The
ignored qualification jobs and the external encrypted-profile review remain
separate from the default workspace tests.

The accepted constraints are current-format storage only, published upstream
redb dependencies only, unchanged physical growth limits, and all five v1
claims on both native Linux targets. Earlier development formats remain
unsupported. The current-format backup and restore contract remains required.

## Implementation work

| Item | Required result | Status |
| --- | --- | --- |
| Repository history | Push the existing committed branch and open its review | Repair branches pushed in PRs #29–#34; PRs #29–#33 merged, with the final queue repair and completed gate results in #34 |
| Conformance maintenance | Bind the accepted current-format specification and preserve historical evidence | Baseline and requirement bindings repaired |
| Storage initialization | Preserve every existing rollback guard and reject reused initialization directories | Implemented; 316 storage tests pass |
| STO-1 | Upstream bounded preparation, allocation-free publication, bounded cleanup and close; integrate a published release | Upstream mechanism implemented and tested in the isolated checkout (STO-01); upstream publication (STO-02) and application integration (STO-03) open |
| CAP-73 authority | Authenticate public state and its complete historical transitions without exposing private MLS context | Open |
| CAP-73 recovery | Ingest signed terminal evidence and atomically install Closed or Conflict | Open |
| CAP-74 | Resolve retained edge witnesses with authenticated ancestry | Open |
| CAP-86 | Bind ReInit admission and ACK signatures to the required old and continuing leaves | Open |
| CAP-101 | Select per-conversation credentials and retain exact old signers for unfinished records | Open |
| CAP-79 | Persist complete accepted-owner references, trusted ages and race-safe physical object cleanup | Open |
| Edge credentials | Forward registered credential replacement with durable coordinator authority and replay | Implemented; real daemon replacement, registered reauthentication, session revocation, restart and receipt-order tests pass |
| Runtime follow-ups | Revalidate and close the Stage 06 command, privacy, revision, queue, reload and shutdown findings | Deferred channel-key authorization, account administration revisions, reload admission, durable refusal audit, idle session-close retry and startup audit indexing repaired. Capability refusals, channel privacy, per-connection accounting, maintenance isolation and independent round-robin input scheduling repaired; other items open |
| Storage follow-ups | Revalidate and close backup slicing, publication, temporary cleanup, canonical decoding and accounting findings | Canonical decoding, temporary cleanup, borrowed ciphertext decoding/opening and reverse-manifest arithmetic repaired; checkpoint/backup capacity and publication remain open |
| Configuration follow-ups | Reconcile OCSP, disabled listeners, key sharing, service-user checks and generated admin access | Disabled material, same-class key sharing, generated administrator UID and OCSP schema/WSS admission repaired, preserving edge outbound TLS; service-user checks remain open |
| Capacity evidence | Distinguish development load from production capacity and exercise the advertised limits | Report validation repaired; idle connections hold only the base charge and the default model admits 50,000 within the pool (Section 19.3 thresholds conflict recorded in #113); full workload open |

Earlier findings remain in `TODO.md` and `stage-10-qualification.md`. A finding
is closed here only with a current regression or a recorded current-source
check showing the earlier repair. Historical checkpoint counts do not replace
fresh results.

### Storage initialization evidence

Three integration regressions fail on the baseline because initialization
reports success after overwriting a retained guard. The repair rejects a
retained valid guard, malformed or empty guard, symlink or directory before
creating `database.redb`. First-guard publication uses an exclusive rename;
a late entry is preserved and a failure after the database commit remains
Indeterminate. Later normal guard replacements retain their existing behavior.

`cargo test -p agenc-ircd-storage --locked` passes 210 unit tests and 106
integration tests, including the new five regression and control tests and
the existing crash, restore and fault-injection cases. The production changes
add no wire or storage format and change no dependency pin or limit. The
release critical inventory now includes the initialization and guard checks.

### Capacity report evidence

The report verifier now requires at least 50,000 configured and observed
connections for the production capacity job. The separate soak job requires
at least 256. A 64-client development campaign cannot close production
capacity. The driver records its actual configured and peak populations and
rejects dropped resource samples, invalid sample times, unordered latency
percentiles and non-boolean shutdown results.

The regression tests fail on the earlier verifier and pass with the repair.
`python3 scripts/test-release-qualification.py` passes all 50 tests, and
`python3 scripts/qualify-release.py check` validates the 31-job inventory.
The existing capacity driver still runs 64 clients and therefore cannot
produce passing production evidence. Implementing and running the full
workload remains open.

### Canonical storage evidence

Channel body encoding and decoding now use the domain topic parser and
require canonical typed masks in every list. Persisted reference decoding
requires strictly increasing table/key pairs. Three regression tests reproduce
the earlier acceptance failures. A fourth test preserves valid topic tabs,
Unicode, each mask subject and quiet masks. The release inventory now includes
the changed envelope and channel validation gates.

Workspace Clippy passes with warnings denied. The all-feature workspace tests
pass, including live TLS, administration, restart, WSS and both MLS clients.
The first separate storage run refused its physical reserve probe because
filesystem free space changed between samples on all five attempts. The same
probe passes in the completed workspace run. Its exact boundary requirement
and retry count are unchanged.

### Temporary cleanup evidence

Storage startup and backup creation now enumerate temporary files through
the same open directory used for deletion. The new regression replaces the
original directory path, checks that the replacement's files remain intact,
and repeats cleanup through the retained descriptor. It fails with the earlier
path-based enumeration and passes with the repair. All 10 platform tests,
the complete storage suite and workspace Clippy pass.

### Specification and evidence bindings

The specification baseline now names exact normative source commit
`15acb53621e04b1aed87fa53033eb4b1f4628bd5`. Its six artifact bytes match that
commit, including current-format admission, the audit export union and the
client numeric corrections. The base and E2EE profile hashes are unchanged.
No normative document or archived result was edited for this repair.

Three current storage requirement bindings are added to the reviewed catalog.
The replaced migration atomicity sentence remains an archive-only binding and
is rejected for new closure. The catalog validates 382 bindings and all 1,000
archived entries. Its 79 negative cases and explicit retired-closure checks
pass. These catalog records identify required evidence; they do not provide
new passing qualification artifacts.

The inherited gates exposed three additional stale catalogs. Stage 01 now
pins the same architecture and decision-ledger bytes as the baseline. Stage 04
records the review of two changed crypto files: unkeyed artifact/snapshot
hash adapters and a public database-ID accessor. The reviewed login HMAC,
OPAQUE paths and secret comparisons are unchanged. Stage 05 no longer
requires the five legacy migration modules removed by the current-format
decision. Each stage's catalog check and negative self-tests pass.

At `8daac95`, the fresh all-feature workspace run passes 2,807 tests with
zero failures and 21 ignored tests. The separate documentation run passes
41 tests. Workspace Clippy, both target compile checks, dependency policy and
the advisory check pass. Coverage is 75.0714% branches and 91.4550% lines,
with all eight interim critical regions at 100%. That inherited run exposed
stale catalogs; the final validation below includes the resumed checks.

### Reader and command-line boundaries

The reader checks the pending parsed-byte and request counts before parsing
each completed line. Refusal stops further accumulation. Forwarding now
drains each complete line before feeding another, so a maximum-sized line
retained from an earlier read can complete within the minimum arena. Two
accumulator regressions fail with the earlier behavior. All 27 connection
tests pass, including fragmented input, message ordering and the exact
30-second inbox stall under a paused clock.

Account invitation expiry now rejects noncanonical unsigned decimals before
descriptor or signing-key access. The subprocess regression reproduces the
earlier acceptance of `+1` and passes for eight invalid spellings after the
repair. Workspace Clippy and source policy pass. The source-bound release
inventory includes both reader gates and the CLI parser; its thresholds are
unchanged.

JOIN key duplication was rechecked against Appendix A.1. Its `csv(key,20)`
grammar forbids duplicate canonical values, so the existing rejection is
retained. The broader queue-ownership and command-authorization findings
remain open.

### Final local validation

At `b2aa74760330b7a1c74fa0a1638402a5a20eba2d`,
`cargo test --workspace --all-features --locked` passes 2,813 tests, including
documentation tests, with zero failures and 21 ignored tests. The ignored
set contains 19 qualification scenarios and two fixture generators. Live TLS,
administration, federation, restart, WSS and both MLS client tests pass.

Workspace Clippy with all targets and features and warnings denied, formatting,
source policy and its 31 rejection cases, workspace policy, the requirement
ledger and baseline checks pass. The 50 release-runner tests and the 31-job
qualification inventory pass. Both x86_64 and AArch64 all-target compilation
checks pass; native AArch64 execution remains outstanding.

The 103 inherited Stage 00 through 09 commands were checked through the initial
and resumed runs after the catalog and test repairs. The final Stage 07 through
09 run passes its transcripts, bounded models, encrypted load and fuzz smoke
checks. The optional-profile matrix passes four builds, nine admitted
configurations, seven refusals before storage writes and retained-history
restarts with history disabled. These are implementation checks. Full native
release campaigns remain required.

Fresh coverage is 75.09% branches and 91.46% lines. All eight interim critical
regions and the three added reader/CLI regions reach 100%. The release check
still fails its 90% branch floor and 672 of 1,061 critical regions, including
regions without executable branch data. Both inventories bind all 765 current
Rust source files; the thresholds remain unchanged.

All three workflow files pass actionlint 1.7.12 syntax and expression checks,
with its optional shellcheck and Pyflakes integrations disabled, and parse
with PyYAML. The pinned checkout and upload action commits resolve.

### Hosted CI startup incident

Every push and pull-request event since 2026-09-10 17:42 UTC produces one
run that GitHub records as `startup_failure` with zero jobs, an empty
workflow name, the display title `(Unknown event)`, and the synthetic
workflow path `BuildFailed` (workflow ID 355138507, state `deleted`), for
example run 34782832427 on `daec140e`, run 34990440748 on `567cd6de`, and
run 34992419054 on `3786108f`. Their check suites carry no check runs and no
retained log, so the provider supplies no diagnostic text. The three real
workflows (`ci.yml` ID 341694647, `stage-10-aarch64.yml` ID 355219474,
`storage-qualification.yml` ID 345200086) are `active`, repository Actions
permissions are enabled with every action allowed, the default token
permission is read, no self-hosted runner is registered, and the last
workflow-file change (`d01f638`, 2026-09-05) precedes runs that started jobs
on 2026-09-05 and 2026-09-07. Probe PR #98, which removed
`stage-10-aarch64.yml`, still ended in `startup_failure`, so workflow content
is not the cause. The same signature appears across the organization's other
private repositories from 2026-09-11 (`agenc-backend` Dependabot runs,
`agenc-os` on 2026-09-14), and the organization's billing usage shows Actions
charges beyond the included quota in August and September 2026. The cause is
therefore an organization-level Actions block that starts every run before a
workflow is selected; confirming and clearing it requires an organization
owner to review the tetsuo-ai billing settings (payment method, Actions
spending limit, and any hold) and the organization Actions policy, which the
repository token cannot read (`admin:org` scope required). No repository
change can resolve it. The `Record the source identity` step now prints the
exact revision in every job log once runs start again. Hosted CI is not
green.

The isolated [upstream bounded transaction](upstream/redb-bounded-transaction/README.md)
gives redb 4.2.0 a typed physical allocation allowance with explicit phases:
charged mutation, abortable preparation that journals and restores every
allocator change on refusal, allocation-free publication, bounded resumable
reclamation, and bounded allocator-state persistence at close. It passes the
433 upstream host tests, clippy, the `panic=abort` no-std check, a fifteen-test
phase, boundary and crash matrix, and an API-aware fuzz state machine. Its
required upstream container gates still stop because Podman is unavailable.
Upstream acceptance and a published dependency remain open under STO-02, and
application integration with the full nonce/guard/main-commit allowance under
STO-03.
The x86_64 qualification host, its immutable release and client-tools
images, the ext4 tuple, the campaign isolation runbook and the AArch64
external blocker (REL-01, issue #43) are recorded in
[the qualification hosts record](stage-10-qualification-hosts.md).

The isolated [upstream allocation probe](upstream/redb-allocation-probe/README.md)
passes 424 host tests but cannot publish a transaction. Its required upstream
container gates stop because Podman is unavailable. The normal-API fuzz smoke
does not exercise the new probe API. Full bounded commit support, upstream
acceptance and a published dependency remain open under STO-1.

## Required production evidence

- [ ] Mandatory build and analysis checks on native x86_64 and AArch64.
- [ ] Default, WSS, history and combined feature checks, including retained-data restarts.
- [ ] At least 90% branch coverage, 90% line coverage and 100% of the complete critical inventory.
- [ ] Supported native ext4 storage tests at the unchanged 128 MiB qualified growth ceiling and 256 MiB operational reserve.
- [ ] Independent IRC clients, OpenMLS and mls-rs lifecycles, federation failures and Tor privacy tests.
- [ ] Default 50,000-connection capacity within 4 GiB, advertised active workloads and recorded hardware.
- [ ] Each of the 21 fuzz targets for 24 CPU-hours per native target.
- [ ] Seven-day sustained operation and all recovery, deletion, key-lifecycle and hardening drills.
- [ ] Independent E2EE review for S08-039 with all findings resolved.
- [ ] Reproducible binaries, SBOM and complete requirement evidence for the frozen candidate.
- [ ] Signed release decision and independent verification of the exact artifact hashes.

Source, lockfile, configuration, binary or qualification-policy changes create
a new candidate. Full release qualification follows the reviewed merge and
source freeze. Production deployment is a separate release-owner action.
