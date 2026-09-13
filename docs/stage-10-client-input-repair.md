# Stage 10 connection input queue repair

Production readers previously shared a 64-slot StateCore channel with
connection-open notices. Independent request and byte reservations bounded
each reader, but one busy connection could consume the shared input capacity.

StateCore now prepares a queue for each admitted connection and returns its
input port in the admission acknowledgement. One ready entry per connection
supports round-robin dispatch with FIFO order within each queue. Ready client
and control input alternate, and queue receives spend Tokio cooperative task
budget so continuous input cannot monopolize a worker. Open/control
notices keep their bounded channel; maintenance keeps its separate channel.

The existing reader ledger reserves configured request and wire-byte capacity
before parsing, pauses further input when full, and keeps each reservation
until dispatch completes. The 30-second stall deadline, cancellation, and
storage/reload barriers also apply to the new path. Physical-close sequencing
continues to account for every accepted line.

Ready-list storage and each queue's 128 hard-maximum slots are reserved against
the process memory budget before allocation. The queue keeps its admission
slot and backing permit until its producer and queued messages are gone.
Dropping StateCore clears pending messages and wakes blocked readers. This
adds explicit queue backing charges and may reduce admitted connection count
under memory pressure; it does not increase configured ceilings or establish
50,000-client capacity. No wire, storage-format, crypto or dependency changes
are introduced. The public Rust admission outcome gains an input-port variant
and no longer implements Copy, Clone or equality.

## Verification

Tests cover 168 simultaneously queued messages across two connections,
round-robin/FIFO order, the 128-request boundary, generation/type refusal,
slot reuse, allocation-budget refusal and release, and consumer shutdown.
Eight concurrent producers deliver 1,024 messages without lost readiness.
Paused-clock reader tests cover byte pressure, retention after dequeue,
30-second stalls and wakeup when StateCore closes. Actor tests exercise
admitted ports with a full control inbox and an ephemeral command queued
behind a durable mutation. Review also reproduced a starvation bug in the
first actor integration: a ready client queue delayed an already queued open
notice behind 512 lines. The regression now requires admission after at most
one client line. A separate single-worker test checks cooperative scheduling.

All 11 focused queue tests and strict workspace lint pass. The complete
`RUST_TEST_THREADS=1 CARGO_INCREMENTAL=0 bash scripts/check-stage-nine.sh`
passed for `a0a7508a2c3ce6a61490ba7aa9e9fc47af8bf0e0` in a temporary
memory-backed checkout. Workspace tests passed 2,883 tests with 21 existing
ignored tests, including 1,358 runtime unit tests with one ignored test.
Coverage reached 75.2806% branches and 91.6783% lines, with all 21 interim
critical regions at 100%. Feature-matrix, concurrency-model and fuzz checks
passed. Coverage floors are unchanged.

The reviewed Rust inventory is 782 files, SHA-256
`a2437e3de728cbedff5a2ad5647d31400fb45f78698b502aabdc3ee751dd1012`.
The earlier host run of the same implementation also passed workspace tests
and coverage, then refused five changing free-space samples in its later
storage pass. The exact boundary, retry count and physical ceilings were
preserved. These functional checks do not establish native ext4 production
qualification or close a stage for a new exact source revision. Subsequent
main reconciliation and report edits do not change the implementation.

Encrypted historical recovery, signing-key and encrypted-object ownership,
STO-1 physical growth, service-user offline checks, checkpoint/backup capacity
and native production qualification remain open.
