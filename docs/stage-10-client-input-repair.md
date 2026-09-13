# Stage 10 connection input queue repair

Production readers previously shared a 64-slot StateCore channel with
connection-open notices. Independent request and byte reservations bounded
each reader, but one busy connection could consume the shared input capacity.

StateCore now prepares a queue for each admitted connection and returns its
input port in the admission acknowledgement. One ready entry per connection
supports round-robin dispatch with FIFO order within each queue. Open/control
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
behind a durable mutation.

The runtime unit suite passed 1,355 tests with one ignored test during
implementation. Source checks pass; final lint and full implementation gate
results will be recorded before merge. Coverage floors are unchanged, with
an additional reviewed input-publication region.

Encrypted historical recovery, signing-key and encrypted-object ownership,
STO-1 physical growth, service-user offline checks, checkpoint/backup capacity
and native production qualification remain open.
