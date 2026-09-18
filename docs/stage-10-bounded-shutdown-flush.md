# Shutdown flush is bounded whatever the size of the audit log

This record covers RUN-12 (issue #180). The `rr` recording
`/mnt/data/agenc-dev/sweep/rr2/recovering/trace-1` (edge pid 3433368) showed
what the `phase=flush` exits waited on: `flush_admin_and_state` awaited the
admin owner's flush before it asked the state owner to flush, the admin flush
was `retention_sweep`, and its blocking scan verified the Ed25519 signature of
every retained audit event, and every checkpoint ever written, inside the
flush budget. A debug build verifies about two hundred events a second, so a
few thousand events were enough; in any build the cost grew for the life of
the node.

## What changed

**Flush runs no retention sweep.** Section 21.8 has flush "persist
cursors/audit checkpoint". A retention checkpoint and its deletion are one
immediate transaction (Section 16), so a checkpoint that exists is already
durable when the state owner's flush settles, and one that does not exist yet
is not flush's to create. `AdminOwner::lifecycle_outcome` therefore completes
`Flush` without scanning; an expired prefix left behind is taken by the next
sweep, in this process or the next.

**The state owner's flush no longer queues behind the admin flush.**
`flush_admin_and_state` runs the two together and requires both.

**The maintenance sweep is bounded and resumes from the checkpoint chain.**
`AuditRetentionJob` no longer rescans the permanent checkpoint table or
re-verifies the retained tail. `AuditAuthority` keeps the verified marks it
already had reason to trust: `reconstruct` verifies both signed tables once
before any administrative authority is accepted, and every later event and
checkpoint is signed by this authority and committed through it. The marks
are the head cursor, the first retained sequence with the hash it chains
from (`retained_previous_hash`), and the latest verified creation time. A
sweep reads forward from the first retained event, verifies exactly the
events it proposes to delete against that chain position, and stops at the
first event inside the retention window or at `MAX_AUDIT_RETENTION_EVENTS`
(4,096). Its cost is bounded by that ceiling whatever the log holds. A sweep
that fills its checkpoint is followed after one minute instead of one hour,
so a backlog drains one signed checkpoint at a time. No continuation row is
needed: the checkpoint names `next_retained_sequence` and
`deleted_last_event_hash`, which is exactly where the next sweep starts after
a restart.

## Audit integrity is unchanged where it is relied on

- Every event is still verified before it is trusted: `reconstruct` verifies
  the whole retained chain and every checkpoint at startup, and refuses
  authority on a gap, fork or bad signature.
- Every event is still verified before it is deleted: the sweep verifies the
  prefix it deletes, chained from the last checkpoint, and fails closed.
  `a_sweep_still_refuses_a_forged_event_inside_the_prefix_it_would_delete`
  covers it.
- Every event is still verified before it is exported: `AuditExportSource::freeze`
  is unchanged and still scans and verifies both tables against the
  authority's cursor.
- What is gone is the hourly re-verification of events that stay retained.
  It was never a stated guarantee, it found nothing a restart or an export
  does not find, and it was the unbounded cost.

## Regressions

`crates/agenc-ircd-runtime/src/admin/audit/tests/mixed/bounded_retention.rs`:

- `a_node_with_a_large_expired_audit_log_stops_inside_its_plan` runs the real
  `AdminOwner` with 20,000 expired audit events in sealed storage, a live
  configuration and a wall clock past the thirty-day window, and stops it
  through `run_shutdown` under the 2/5/5/2 plan with hooks that call the
  daemon's own `flush_admin_and_state`. All four phases complete, the state
  flush ran, and the state owner was asked for no administrative work. With
  the sweep put back on the flush path the same test fails with
  `first_problem: Flush, TimedOut`, which is the defect.
- `a_sweep_reads_only_what_it_deletes_and_resumes_across_ticks_and_a_restart`
  seeds two expired generations ahead of a retained tail five times their
  size. The first tick deletes 300 events and reads 301; a repeat reads one;
  the second tick continues at sequence 300 under checkpoint sequence 1 and
  reads 201; and an authority reconstructed from the reopened storage
  proposes that same second checkpoint byte for byte.

## Confirmation on the fixed binary

`/mnt/data/agenc-dev/sweep/rr3/trace-1` records the same test as the #180
trace, without CPU hogs, on a daemon built from this branch. Both edges exit
0. Replaying edge pid 3661980 from the entry of `flush_admin_and_state` to
process exit with breakpoints on `ed25519_dalek::verifying::VerifyingKey::verify_strict`
and on `AuditRetentionJob::run` (both resolved) gives zero hits: no signature
verification and no retention job runs inside flush.

## Limitations

- The 4,096-event ceiling itself is exercised only by the existing selector
  tests; a debug build needs about twenty seconds to verify that many, so the
  new regressions bound the scan by the retention window instead.
- A sweep that is already running when shutdown begins still finishes first:
  the admin owner runs it inside its loop. That wait is now bounded by the
  ceiling rather than by the log.
- A backlog larger than one checkpoint drains at one checkpoint a minute.
