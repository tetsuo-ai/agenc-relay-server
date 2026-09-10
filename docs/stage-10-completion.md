# Stage 10 completion ledger

This working ledger tracks the implementation requested on 2026-09-10. It is
not a conformance manifest. A checked implementation item does not close a
production gate or qualify another source commit.

## Baseline

The implementation starts at `365b9e0e196afb6f4ff4887054b25b001ed10c4a` on
`stage-10-production`. Its 39 previously local commits are pushed, and
[PR 27](https://github.com/tetsuo-ai/agenc-ircd/pull/27) is open as a draft.

The locked all-feature workspace run passes 2,797 tests with no failures and
21 ignored tests. Nineteen ignored tests are separate qualification scenarios;
two generate deterministic fixtures. The requirement, source and workspace
checks pass. The release-runner suite passes 48 tests. Fresh coverage measures
75.09% branches and 91.45% lines. All eight interim critical regions pass;
667 of the 1,052 release-critical regions remain below 100%.

The accepted constraints are current-format storage only, published upstream
redb dependencies only, unchanged physical growth limits, and all five v1
claims on both native Linux targets. Earlier development formats remain
unsupported. The current-format backup and restore contract remains required.

## Implementation work

| Item | Required result | Status |
| --- | --- | --- |
| Repository history | Push the existing committed branch and open its review | Complete at the baseline commit |
| Storage initialization | Preserve every existing rollback guard and reject reused initialization directories | Implemented; 316 storage tests pass |
| STO-1 | Upstream bounded preparation, allocation-free publication, bounded cleanup and close; integrate a published release | Open; upstream release required |
| CAP-73 authority | Authenticate public state and its complete historical transitions without exposing private MLS context | Open |
| CAP-73 recovery | Ingest signed terminal evidence and atomically install Closed or Conflict | Open |
| CAP-74 | Resolve retained edge witnesses with authenticated ancestry | Open |
| CAP-86 | Bind ReInit admission and ACK signatures to the required old and continuing leaves | Open |
| CAP-101 | Select per-conversation credentials and retain exact old signers for unfinished records | Open |
| CAP-79 | Persist complete accepted-owner references, trusted ages and race-safe physical object cleanup | Open |
| Edge credentials | Forward registered credential replacement with durable coordinator authority and replay | Open |
| Runtime follow-ups | Revalidate and close the Stage 06 command, privacy, revision, queue, reload and shutdown findings | Open |
| Storage follow-ups | Revalidate and close backup slicing, publication, temporary cleanup, canonical decoding and accounting findings | Open |
| Configuration follow-ups | Reconcile OCSP, disabled listeners, key sharing, service-user checks and generated admin access | Open |
| Capacity evidence | Distinguish development load from production capacity and exercise the advertised limits | Open |

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
