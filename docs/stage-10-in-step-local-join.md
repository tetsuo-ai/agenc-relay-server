# A local JOIN applied in the step that admits it

This record covers AUD-16 of the SDK's 2026-09-28 readiness audit, fixed under
the SDK program outside master #35. It changes no wire format, numeric, reply
code, registry, configured limit, persistent format or specification text,
and the `005` tokens, `CHANTYPES=#&` among them, are unchanged.

## What was observed

On a core-only node a registered guest's lone `JOIN &loc` got no reply at
all: no JOIN echo, no `366`, and with `labeled-response` not even the
label's batch. Every later registered command on that connection (`TIME`,
`WHO`, `NICK`, another `JOIN`) went unanswered too, while `PING` was still
answered and `QUIT` still closed the connection. Another connection to the
same node was unaffected. The SDK reproduced it against a daemon built from
`b477e1b`, whose `crates/*/src` are identical to this base's.

## Cause

An accepted JOIN of a client on the node's own router prepares a bounded
NAMES snapshot, a seed (`PreparedLocalJoin`), before its plan is staged, and
`settle_local_join` then retains it. A retained seed opens only once it is
marked committed, which `apply_plan` does for every retained seed whose
revision equals the revision it applies. The requester's JOIN echo, topic
reply, NAMES pages and label batch are all rendered from the opened seed,
and while a seed is retained for a connection the router defers that
connection's later registered commands, so they stay ordered behind the
JOIN's reply.

An ephemeral `&` channel is never persisted (`DurableChannel::from_state`
omits it), so a guest's JOIN of one projects no durable write, and a
core-only node projects nothing to federation either. With no batch
pending, `stage_prepared` applies such a plan inside the same step
(`StageAccepted::AppliedInStep`), and `apply_plan` ran its commit hook
before `execute_planned_command` settled the seed. The seed was retained
uncommitted, no later commit carried its revision, and it never opened: the
JOIN went unanswered and every later command waited behind it until the
connection closed. A `#` JOIN is staged, so its seed is retained before its
batch commits and opens as designed.

## Fix

`settle_local_join` (`crates/agenc-relay-runtime/src/state_core/local_join.rs`)
marks an accepted seed committed when the domain has already reached the
seed's revision. The domain reaches a plan's resulting revision only by
applying that plan: in the same step for a plan with no persisted delta,
otherwise when the storage receipt of the batch that carries it is applied,
which is always a later step. A staged seed is therefore still committed
only by its batch, and a refused JOIN still releases its snapshot.
The seed is opened by the drain that already follows every routed line
(`RegistrationRouter::route`), after `attach_local_join_request` has moved
the label context onto it, so the in-step JOIN gets exactly the reply a
staged JOIN gets.

This is the program register's decision D-22 (a). Its alternative, settling
the seed before staging and rolling it back on a refusal, was not needed.

## The edge role

An edge sends every JOIN to its coordinator as a request with a durable
request record and continues the NAMES pages itself; its router never
prepares a local seed, so this defect cannot arise there.

## The regressions

| Test | What it pins |
| --- | --- |
| `state_core::local_join::tests::an_in_step_local_join_opens_its_snapshot_as_soon_as_it_settles` | A guest's `&` JOIN plan has no durable write and is applied in step; settled after that, its seed opens at once with the JOIN echo and topic reply, then one NAMES page, and no seed is left pending. |
| `state_core::tests::local_join::an_in_step_local_join_answers_its_label_batch_and_the_next_command` | Through the live router, `@label=join JOIN &loc` then `@label=time TIME` get one label batch of JOIN, `331`, `353` and `366`, closed before the labeled `391`. |
| `state_core::tests::local_join::a_staged_global_join_answers_its_label_batch_and_the_next_command` | The same exchange for `#room`, whose JOIN is staged. |
| `stage_six_daemon::local_join::a_lone_local_join_is_answered_and_the_next_command_still_runs` | The production binary on a core-only node: `JOIN &plain` then `TIME`, and the labeled `JOIN &labeled` then `TIME`. |

The existing `local_join_snapshot_opens_after_commit_and_keeps_its_membership_preimage`
and `a_committed_local_join_opens_while_the_next_batch_is_pending` still
require that a staged seed does not open before its batch commits, and
`a_refused_local_join_releases_its_reserved_snapshot` that a refused JOIN
releases its snapshot.

With `settle_local_join` reverted to its `70c832c` body and everything else
kept, the first, second and fourth tests fail: the seed is never taken, the
router never sends the `391` its script waits for, and the daemon test reads
nothing after `JOIN &plain` until its 15-second socket timeout. The staged
`#room` test passes either way; it guards the path the fix must leave
unchanged.

## Coverage

Both production source inventories are refreshed. The reviewed release region
`runtime-local-join-snapshot-identity` (`open`) moved down eleven lines with
its reviewed span unchanged. The new release region
`runtime-local-join-settled-commit` binds `settle_local_join`, the decision
this record changes, under the branch metric. Over the runtime library tests
(`cargo llvm-cov nextest -p agenc-relay-runtime --lib --all-features
--branch`, 2,616 passed) it measures 6/6 branches and 14/14 regions: an
absent seed, a refused JOIN, a staged seed and an in-step seed. `open`
measures 4/6 branches there; the two it misses are its frame and row
ceiling guards, which this change does not touch.

## Limitations

- The daemon test runs on the development host, not the release
  qualification hosts.
