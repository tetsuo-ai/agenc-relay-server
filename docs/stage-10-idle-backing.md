# Stage 10 idle connection backing

Superseded in one respect: the default `server.memory_budget_bytes` this
record measures against, and with it the live pool `P = 3,338,666,016`, moved
to 6,442,450,944 and `P = 5,217,714,208` when issue #113 funded the default
population below the Section 19.3 classes. The backing behaviour recorded
below is unchanged; see
[the overload threshold record](stage-10-overload-threshold-defaults.md).

This record closes RUN-04 (issue #46). Before it, every admitted client
charged 167,936 bytes of output queue backing at admission and every opened
input port charged 16,384 bytes of input backing, beside the 65,536-byte
client connection base charge, so 50,000 idle clients needed 12.5 GB of a
3.34 GB live pool. Both backings are now acquired on demand, exactly as
Architecture 19.2 and 21.3 describe: an idle connection holds its base
charge and nothing else.

## Output queue

`WriterQueue` no longer takes a backing permit. Its storage is a fixed ring
of 24 entries inside the connection state, one per admissible response batch
at the hard item maximum (16) plus the eight control slots, which the base
charge covers. A committed demand occupies one entry until its final frame
drains. A single-frame demand lives in the entry itself. A larger demand
brings exactly one exact-capacity allocation of frame references,
`allocation_charge(frames * 8)`: 4,096 bytes for two to 480 frames, 8,192 up
to 992, and 12,288 for a maximal 1,024-frame demand. `try_reserve` names
that charge; the fanout acquires it in the same batch as the frame buffers;
`prepare` consumes the matching permit and creates only that storage; and
`commit` moves the frames into it without allocating. The storage and its
permit leave together with the demand's final frame, with an immediate
close, or with a discarded commit. A committed multi-frame transfer that
carries no fitting storage, which only a foreign reservation can produce,
excludes the whole sink as a slow consumer rather than dropping a frame.

Control frames take ring entries within the control slots and byte reserve
and never need a charge, so the emergency fatal frame is available under
normal-output exhaustion. New reservations use the current runtime byte,
item, and response ceilings; a reload that raises them admits more demands,
each still charged, and a reload that lowers them refuses new work while
accepted reservations drain. Query snapshots, generation fences,
shutdown-after-flush, and the slow-consumer close are unchanged.

## Input queue

A connection's input queue holds its oldest waiting line inline. A second
outstanding line brings charged overflow storage: 68 slots (one 4,096-byte
quantum) first, replaced by 127 slots (8,192 bytes) when it fills, which
with the inline slot is the 128-request hard maximum. The permit is reserved
before the storage is allocated and the storage is released, with its
permit, when the overflow drains. Only the connection's reader grows its
queue, so storage prepared before publication remains sufficient under the
shared lock. When the memory budget refuses the overflow, the line is
returned and the reader stays paused, retrying with a 5 ms to 250 ms
backoff inside its existing 30-second stall budget; a starved reader closes
with `ReadStall` and publishes nothing partial. Round-robin dispatch, FIFO
order within a queue, cooperative yielding, and the separate control and
maintenance lanes are unchanged. Opening a port now holds only its count
slot; the ready list remains the one fixed owner charged at startup.

## Admission

The listener charges the fixed client base and, while they last, the TLS
and WebSocket setup increments; the queue backing charge is gone from
`ConnectionResources`. The composed default model is tested against the
same functions the listener and supervisor use.

## Measurements

- `crates/agenc-relay-runtime/src/budget/idle_model.rs`: the default pool is
  `P = 3,338,666,016` bytes; a composed idle TLS client charges exactly
  65,536 bytes; 50,000 of them with the 2,007,040-byte ready list need
  3,278,807,040 bytes, inside `P`; the removed eager backing needed more
  than three times the pool.
- `crates/agenc-relay-runtime/tests/idle_connection_memory.rs`: the real
  listener, TLS endpoint, supervisor, reader, writer, and queue serve 288
  idle TLS connections held by a child process. The budget holds exactly
  65,536 bytes per connection once the setup increments return, and this
  process's anonymous resident memory grows by 37,680 bytes per connection
  (x86_64 debug build), under the base charge. Every permit returns when
  the connections close.
- `crates/agenc-relay-server/tests/stage_six_daemon/idle_capacity.rs`: the
  production binary with the default four-GiB budget serves 208 idle
  registered clients; 192 measured clients charge 192 x 65,536 plus one
  32,768-byte step of the keyed admission-bucket table, whose doubling is
  amortized over the sessions that cause it. The projected 50,000-client
  population from the measured marginal charge fits `P`. The daemon is
  non-dumpable and this host mounts `/proc` with `hidepid`, so its resident
  growth is reported unavailable there; the runtime test carries that claim.

The AArch64 run of the same tests is the existing
`stage-10-aarch64` workflow, which cannot run until organization Actions are
enabled (issue #41); nothing in the measurement is target-specific.

## Open specification conflict

Section 28.7 requires the default configuration to admit 50,000 idle client
base charges, and it does: 3,276,800,000 bytes of the 3,338,666,016-byte
pool. Section 19.3's overload classes are taken against the same live pool,
so that population sits at 98%: new connections stop at 45,849 clients and
eviction starts at 48,396. `a_full_default_population_crosses_every_overload_threshold`
pins these numbers; issue #113 records the normative decision they need.

## Exact permit evidence

`crates/agenc-relay-runtime/src/connection/queue/backing_tests.rs` covers the
charge at every quantum boundary and the hard maximum, an empty queue's
first storage, partial drain, the default and hard-maximum response
ceilings, the configured item ceiling, cancellation before and after
`prepare`, permit mismatch, consumer drop with shared frames, a query
snapshot on charged storage, generation and close fences, a reservation
without storage, a full ring, the control reserve, and shutdown-after-flush.
`crates/agenc-relay-runtime/src/state_core/client_input/tests/mod.rs` covers
the free idle port, the first overflow quantum, growth to the request
maximum, the 128-line ceiling, release on drain, arrival order across the
inline slot and the overflow, and a reader paused by an exhausted budget
that resumes when memory returns or closes at the stall deadline.
`runtime_config.rs` covers the raised and lowered live ceilings. The
existing fanout, reader, writer, listener, Loom, and generation regressions
run unchanged.
