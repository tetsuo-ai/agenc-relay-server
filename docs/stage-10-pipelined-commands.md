# Pipelined commands and the slow-consumer close

This record closes RUN-10 (issue #174). It changes no wire format, numeric,
reply code, registry, configured limit, rate table, or specification text.

## What was observed

The nine-message case was recorded once under `rr` through the real daemon
fixture and the daemon process replayed with breakpoints on every change of
the writer queue's open-demand count (`connection/queue.rs`: the increment in
`admit_normal`, the decrement in `pop_response_frame`, the rollback, and the
refusal), on `client_render::publish_failure`, and on the insufficient-credit
return of `BucketTable::charge_all_or_nothing`.

1. The `481` on the fifth PRIVMSG is not the response-batch ceiling. The
   refusing frame is `charge_all_or_nothing` returning
   `Insufficient(GuestMessage)` with `BucketRate {1 token / 2 s, burst 4}` and
   `tokens: 0`, called from `channels::charge_command` under `admit_command`.
   That is the Section 19.1 guest-message bucket, and Section 13 names `481`
   as the legacy numeric for `SERVER_BUSY`. The reply is as specified and is
   unchanged.
2. Every demand opened one count on the destination queue, whatever its size.
   The four admitted PRIVMSGs opened counts 1 to 4 on the receiver's queue
   from `fanout::reserve_queues` under `stage_durable_inner`; the five
   one-line `481` refusals opened counts on the sender's own queue from
   `publish_failure` through `send_to` and `fanout_now`.
3. The only event that closed a count was the writer task popping the
   demand's final frame. No pop occurred between the opens: the state owner
   ran all nine lines of the one read before the writer task was scheduled.
4. The refusal at `queue.rs:607` therefore fired on the sender's queue with
   `batches=4 items=4 bytes=196` of a 1 MiB queue, on the fifth `481`, and
   `FanoutReservation::commit` closed the sender as a slow consumer.
5. `begin_slow_consumer_close` was `close(SlowConsumer, Immediate)`: it
   destroyed the queue and the writer went straight to transport shutdown.
   No production path ever called `push_control`, so the reserved control
   slot was never used and the client saw only EOF.

With the guest bucket widened the same ceiling closed the receiver instead:
the fifth delivery found four undrained deliveries on its queue.

## Cause

The writer queue kept one fixed ring entry for each committed demand and
sized that ring by the open-response ceiling, so `admit_normal` reported a
sink `Full` when more than `response_batches_per_connection` demands were
undrained, even one-line replies and deliveries. Section 15.3 makes a sink
full only at its logical byte or item ceiling. The ceiling was reached by
ordinary scheduling, not by a slow reader.

## Fix

- `connection/queue.rs`: `admit_normal` refuses only at the byte and item
  ceilings. The open-response ceiling now decides placement: within it a
  demand takes a fixed ring entry with no allocation, as before; beyond it the
  reservation carries the exact charge of one cell, `prepare` allocates the
  cell after its permit exists, and `commit` links it without allocating
  (`connection/queue/overflow.rs`). Entries carry their commit sequence and
  the writer drains ring and cells in that one order. A ring placement is
  granted only while every open demand fits the ring, so it always finds its
  entry. No deferral is needed because no demand-count ceiling remains; input
  stays bounded by the input queue and the Section 19.1 buckets.
- `state_core/close_notice.rs`: the line
  `ERROR :Closing connection: output queue exceeded` is rendered and charged
  once, shared, and armed on each sink when its connection opens.
  `begin_slow_consumer_close` still destroys the whole queue, then moves the
  armed line into the reserved control slot; the writer delivers it within
  the existing close deadline and then closes. The close allocates nothing.

The slow-consumer protection is unchanged in substance: the demand that
crosses the byte or item ceiling is refused whole and the sink is closed.

## Evidence

- `crates/agenc-ircd/tests/stage_six_daemon/pipelined_commands.rs`, through
  the real daemon: 5 and 9 pipelined PRIVMSGs from a guest and 32 from an
  account, each in one write, all delivered in order with the marker `PONG`
  and no slow-consumer close; the issue's exact default-bucket case, where
  four are delivered, five are refused with `481`, and the sender stays
  connected; eight JOINs pipelined with registration. The first four fail
  without the runtime change; the JOIN case passed before and is kept as a
  guard.
- `crates/agenc-ircd-runtime/tests/listener_accept.rs`,
  `a_full_output_queue_closes_with_the_error_line_first`: over a real TLS
  transport a queue is driven to the ceiling that refuses a whole demand,
  closed as a slow consumer, and the client receives exactly the `ERROR`
  line before EOF.
- `connection/queue/tests/backing.rs`: 32 one-frame demands, a control frame
  and a multi-frame demand drain in commit order and return every charge; a
  ring demand committed after a cell demand drains after it; the item ceiling
  still refuses; the close delivers only the armed line, once.

## Not changed

Admin kill and account suspension reused `begin_slow_consumer_close` to
destroy a queue. They are not slow-consumer closes and must not carry its
reason, so they now call `begin_forced_close`, which keeps their existing
behaviour exactly, including the close label they log. Giving those closes
their own `ERROR` reasons is separate work. Overload shedding selects
connections by queue bytes and keeps the slow-consumer close and its line.
