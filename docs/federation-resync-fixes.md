# Federation resynchronization fixes

The user approved all 21 candidates in `federation-resync-review.md`. Work is
confined to `agenc-relay-stage10`, branch
`stage-10-production`, based on `41117e54ff384eb53d90d992acdcc006b7493628`.
The qualification worktree has not been used. No capacity campaign was run.
All 21 candidates are fixed. Unit and integration checks are complete;
qualification acceptance remains pending.

## Regression evidence

Tests use the existing edge, coordinator, and origin-table harnesses. The
commands use `CARGO_BUILD_JOBS=2` and locked dependencies. Each red log below
contains behavioral assertion failures before its corresponding implementation.

| Group | Candidates | Red evidence in `/tmp` | Latest verification |
| --- | --- | --- | --- |
| 1 | R05, R07, R11, R13, R21 | `agenc-relay-resync-red-01.log`, corrected replay fixture in `agenc-relay-resync-red-r07.log` | Six focused tests passed in `agenc-relay-resync-green-01.log` |
| 2 | R01, R02, R03, R14 | `agenc-relay-resync-red-02.log` | Ten focused tests passed in `agenc-relay-resync-green-02.log` |
| 3 | R06, R15, R18, R19, part of R09 | `agenc-relay-resync-red-03.log`, `agenc-relay-resync-red-03-corrected.log` | Two domain and thirteen runtime tests passed in `agenc-relay-resync-green-03-corrected.log` |
| 4 | R04 | `agenc-relay-resync-red-04.log` | The pending close and unbound-session DEL tests passed; 104 federation tests passed in `agenc-relay-resync-federation-02.log` |
| 5 | R10 outgoing requests, results, and restart | `agenc-relay-resync-red-05.log` | Eighteen focused tests passed in `agenc-relay-resync-green-05.log` |
| 6 | R10 atomic completion coverage | `agenc-relay-resync-red-06.log`; cross-profile reconstruction failed in `agenc-relay-resync-green-06.log` before its coverage fix | 108 federation tests passed in `agenc-relay-resync-green-06-barrier.log` |
| 7 | R16 | `agenc-relay-resync-red-07.log` | Exact ACK tests and companion registration passed after the fixture acknowledged its origin |
| 8 | R17 | `agenc-relay-resync-red-08.log` | 111 federation tests passed in `agenc-relay-resync-green-08.log` |
| 9 | R11, R12 | `agenc-relay-resync-red-09.log` | Durable pending READY and ACTIVE regressions passed |
| 10 | R08, R12 | `agenc-relay-resync-red-10.log` | Lost registration completion is covered by the committed snapshot cut |
| 11 | R20 | `agenc-relay-resync-red-11.log` | 116 federation and ten domain origin tests passed after base-first harness updates |
| 12 | R12 | `agenc-relay-resync-red-12.log` | Last-page receipt survives link loss; a restored pending image must match its digest |
| 13 | R01, R07 | `agenc-relay-resync-red-13.log`, `agenc-relay-resync-red-13-invalid.log`, `agenc-relay-resync-red-13-admission.log` | 121 federation tests passed in `agenc-relay-resync-green-13-all.log` |
| 14 | R06 | `agenc-relay-resync-red-14.log` | 34 focused regressions passed; overflow suppresses later reservations and reload reconstructs pressure |
| 15 | R06 | `agenc-relay-resync-red-15.log` | Pre-append transaction fence passed in the group-16 run |
| 16 | R06 | `agenc-relay-resync-red-16.log` | 125 federation tests passed in `agenc-relay-resync-green-16.log` |
| 17 | R09 | `agenc-relay-resync-red-17-domain.log`, `agenc-relay-resync-red-17-runtime.log`, `agenc-relay-resync-red-17-cleanup.log` | The peer fence commits before a hide; fenced physical rows remain owned by cleanup |
| 18 | R09 | `agenc-relay-resync-red-18.log` | A replacement incarnation first fences its predecessor; three old fixtures need fence-before-hide expectations |
| 19 | R09 | `agenc-relay-resync-red-19.log` | Restart preserves earlier incarnation fences; 39 focused runtime regressions passed |
| 20 | R09 | `agenc-relay-resync-red-20.log` | Empty cleanup commits Clean and fenced incarnations cannot open a base link; 41 focused regressions passed |
| 21 | R09 | `agenc-relay-resync-red-21.log` | Presence, nickname, session enumeration, and channel query views exclude fenced rows; all 141 domain tests passed |
| 22 | R09 grace authority | `agenc-relay-resync-red-22-corrected.log` | 42 focused regressions and 131 federation tests passed; the six existing storage codec tests passed |
| 23 | R01, R07 admission | `agenc-relay-resync-red-23.log` | Startup backlog overflow retires the queued establishment and frames together; 43 focused regressions passed in group 24 |
| 24 | R21 | `agenc-relay-resync-red-24-queued.log` | The revised two-peer fixture fails without the queue drain; 43 focused regressions passed |
| 25 | R10, R13 | `agenc-relay-resync-red-25.log` | 134 federation tests passed; terminal requests and acknowledged DELs stay retired after restart |
| 26 | R08, R10, R12 | `agenc-relay-resync-red-26.log` | 46 focused tests passed; duplicate results are idempotent and an incomplete barrier excludes snapshot coverage |
| 27 | R05, R09 | `agenc-relay-resync-red-27.log` | 47 focused tests passed; a real storage restart resumes the committed Session-ID cleanup cursor |
| 28 | R03 | `agenc-relay-resync-red-28.log` | 138 federation tests passed; account receipts include the exact outer result and origin successor |

The final source contains 52 new `resync_` regression tests. Every one has a
behavioral FAILED result in the retained red logs. Some later tests were
proved by temporarily removing the corresponding fix, running the test, and
restoring the fix. Compilation failures and test-setup failures are excluded
from that evidence.

The separate GitNexus index is named `agenc-relay-stage10`. It was built with
`gitnexus analyze --index-only --name agenc-relay-stage10 --workers 2`, without
injecting tracked metadata. Its graph describes the original source; new
symbols require manual caller checks when impact reports UNKNOWN. HIGH and
CRITICAL results have been reported before edits.

## Final implementation and checks

CAP-20 through CAP-40 in `stage-10-qualification.md` map in order to R01
through R21. The original review remains unchanged. The implementation
retains exact unresolved work, commits cursor and cleanup progress with their
writes, fences obsolete authority before physical cleanup, and requires the
coordinator's READY before edge request admission.

The account follow-up closes both sides of R03: the callback checks receipt
ownership, and the account transaction itself contains the exact federation
response and origin successor. Closed virtual carriers still settle that
committed replay state. The edge journal writes terminal state before
retiring requests and acknowledged DELs, so a later restart does not revive
completed work.

Record compatibility is explicit. Existing version-1 peer rows and ordinary
request rows remain readable. Peer incarnation history and request completion
evidence use version-2 bodies when those fields are present. A daemon whose
storage codecs predate this change cannot read those new bodies. Downgrade
compatibility is not claimed. Terminal ordinary rows are retained
conservatively; this change does not introduce their time-based deletion or
old-generation garbage collection. Retention is never shortened to recover
capacity.

Validation used the worktree-local target directory and `CARGO_BUILD_JOBS=2`:

- `cargo test -p agenc-relay-runtime -p agenc-relay-domain -p agenc-relay-storage --all-features --locked`: 1,136 passed, none failed or ignored. Log: `/tmp/agenc-relay-resync-tests-final.log`.
- `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`: passed. Log: `/tmp/agenc-relay-resync-clippy-31.log`.
- `cargo fmt --all --check`: passed in the final check.
- `python3 scripts/check-source.py check`: passed, 575 Rust files. Log: `/tmp/agenc-relay-resync-source-final.log`.
- `git diff --check`: passed.
- Both coverage policy self-tests passed all 24 rejection cases. Logs: `/tmp/agenc-relay-resync-coverage-interim.log` and `/tmp/agenc-relay-resync-coverage-release.log`.

Coverage inventories were recomputed with
`scripts/check-coverage.py::production_source_inventory`: 451 production
source files, SHA-256
`122ce35b2a86434a4c30815356a777382939a14a70d628bd4de826e058ec88c7`.
Changed region hashes and line bounds were rebound to the same reviewed
functions. Floors and required categories remain unchanged. These policy
checks do not measure the release coverage percentage; no new coverage
campaign or qualification evidence is claimed.

The qualification worktree, frozen specification, and pinned RFCs were not
modified. No capacity campaign was performed.
