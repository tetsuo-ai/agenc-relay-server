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
answered and `QUIT` still closed the connection. The SDK reproduced it
against a daemon built from `b477e1b`, whose `crates/*/src` are identical to
this base's. A client of a federated coordinator met the same stall when it
joined a `&` channel of that coordinator; a client of an edge did not (see
the federated roles below).

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
omits it), so a guest's JOIN of one projects no durable write. It projects
nothing to federation either: a core-only node has none, and a federated
coordinator projects a channel only to the edges that host one of its
members or invitees, so a `&` channel whose members and invitees are all
the coordinator's own clients projects nothing. With no batch
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

A local JOIN can also run outside a routed line. A command deferred behind a
floored refusal (the secret-lookup response floor of Section 13.5) is
resumed by the floor's timer, and a JOIN among those commands is applied in
that step too. `resume_deferred_commands`
(`crates/agenc-relay-runtime/src/registration/join_names.rs`) now opens the
seeds after resuming, as every other point that resumes or routes commands
already did: each routed line, `resume_ready_join_commands`, the JOIN
continuation timer, `batch_applied` and a command's crypto completion.
Without it the seed, now committed, would open only at the next unrelated
line or commit. The fix relies on each of these drains, so each point where
a local JOIN can run outside a routed line has its own regression below.

This is the program register's decision D-22 (a). Its alternative, settling
the seed before staging and rolling it back on a refusal, was not needed.

## The federated roles

A federated coordinator routes its own clients' commands through the same
router as a core-only node, so a `&` JOIN by one of them is applied in the
step that admits it and stalled the same way before the fix; the same fix
opens its snapshot. A daemon test with a real coordinator and edge sends
`JOIN &plain` and then `TIME`, and the labeled `JOIN &labeled` and then
`TIME`, from a client of the coordinator.

An edge sends every JOIN to its coordinator as a request with a durable
request record and continues the NAMES pages itself; its router never
prepares a local seed, so this defect cannot arise there. The same daemon
test guards that the edge's JOIN continuation, plain or labeled, answers and
then releases the command behind it.

## The regressions

| Test | What it pins |
| --- | --- |
| `state_core::local_join::tests::an_in_step_local_join_opens_its_snapshot_as_soon_as_it_settles` | A guest's `&` JOIN plan has no durable write and is applied in step; settled after that, its seed opens at once with the JOIN echo and topic reply, then one NAMES page, and no seed is left pending. |
| `state_core::tests::local_join::an_in_step_local_join_answers_its_label_batch_and_the_next_command` | Through the live router, `@label=join JOIN &loc` then `@label=time TIME` get one label batch of JOIN, `331`, `353` and `366`, closed before the labeled `391`. |
| `state_core::tests::local_join::a_staged_global_join_answers_its_label_batch_and_the_next_command` | The same exchange for `#room`, whose JOIN is staged. |
| `registration::core_line_tests::a_local_join_released_by_a_response_floor_answers_in_the_same_step` | Through the state core with its clock frozen, `TOPIC #missing` holds its `403` until the floor and the `JOIN &loc` behind it waits; firing the floor's timer publishes the `403` and then the JOIN's `366` in that one step, and no seed is left pending. |
| `registration::core_line_tests::a_keyed_local_join_answers_in_its_crypto_completion_step` | With a key set on `&locked`, a joiner's `JOIN &locked secretkey` waits for its key verification job; stepping that job's completion, and nothing else, delivers the JOIN echo through the `366`. |
| `registration::core_line_tests::a_local_join_resumed_by_a_refused_batch_answers_in_that_step` | `JOIN #room`, then `JOIN &loc` behind it; refusing the staged batch before submission answers `&loc` in that step, and `#room` gets no NAMES. |
| `registration::core_line_tests::a_local_join_resumed_by_the_names_timer_answers_in_that_step` | `JOIN #slow` while the queue is full, then `JOIN &loc` behind its NAMES continuation; once the queue drains, the continuation's timer step delivers `#slow`'s `366` and then `&loc`'s. |
| `registration::core_line_tests::a_local_join_behind_a_staged_join_answers_in_its_commit_step` | `JOIN #room`, `JOIN &loc` and `TIME`; the step that applies the batch answers `#room`, then `&loc`, then the `391`. |
| `registration::core_line_tests::a_local_join_sent_before_the_welcome_answers_in_its_commit_step` | `JOIN &loc` and `TIME` sent before the welcome; the registration's commit step sends the welcome, then `&loc`'s `366`, then the `391`. |
| `stage_six_daemon::local_join::a_lone_local_join_is_answered_and_the_next_command_still_runs` | The production binary on a core-only node: `JOIN &plain` then `TIME`, and the labeled `JOIN &labeled` then `TIME`. |
| `stage_seven_federation::joins_on_a_coordinator_and_its_edge_answer_before_the_next_command` | A coordinator and an edge: on the coordinator, `JOIN &plain` then `TIME`, and the labeled `JOIN &labeled` then `TIME`; on the edge, `JOIN #plain` then `AWAY`, and the labeled `JOIN #labeled` then `AWAY`. |

Each `core_line_tests` regression also requires that no seed is left
pending. The existing `local_join_snapshot_opens_after_commit_and_keeps_its_membership_preimage`
and `a_committed_local_join_opens_while_the_next_batch_is_pending` still
require that a staged seed does not open before its batch commits, and
`a_refused_local_join_releases_its_reserved_snapshot` that a refused JOIN
releases its snapshot.

With `settle_local_join` reverted to its `70c832c` body and everything else
kept, every test above fails except the staged `#room` test, which passes
either way: it guards the path the fix must leave unchanged. The in-step
seed is never taken, the router never sends the `391` its script waits for,
each `core_line_tests` regression receives nothing after the step that
applies its `&` JOIN (the floor's timer, for one, publishes the `403` and
nothing after it), and both daemon tests read nothing after `JOIN &plain`
until the socket timeout. The keyed test fails earlier, at the owner's own
`JOIN &locked`, a routed line its setup needs. The edge half of the
federated test passes either way.

With the fix kept and a single drain removed, the regression of that
drain's point fails. Without the crypto completion's drain the keyed test
alone fails: the joiner receives nothing after its welcome. Without the
drain of `resume_ready_join_commands`, of the JOIN continuation timer or of
`resume_deferred_commands`, the refused-batch, NAMES-timer or
response-floor test alone fails. Without the drain of `batch_applied` the
staged-JOIN and welcome tests fail together with older tests of staged
JOINs, and without the drain after each routed line the live-router `&loc`
test and the keyed test's setup fail.

## Coverage

Both production source inventories are refreshed. The reviewed release region
`runtime-local-join-snapshot-identity` (`open`) moved down eleven lines with
its reviewed span unchanged. The new release region
`runtime-local-join-settled-commit` binds `settle_local_join`, the decision
this record changes, under the branch metric. Over the runtime library tests
at `f3b4fda`, which added the last of the runtime regressions above
(`cargo llvm-cov nextest -p agenc-relay-runtime --lib --all-features
--branch`, 2,622 passed), it measures 6/6 branches and 14/14 regions: an
absent seed, a refused JOIN, a staged seed and an in-step seed. `open`
measures 4/6 branches there; the two it misses are its frame and row
ceiling guards, which this change does not touch.

## Limitations

- On the edge the daemon test exercises `#` channels and `AWAY`. On an
  edge, a JOIN of a `&` channel is refused (`481`, or `SERVER_BUSY` with
  `standard-replies`) instead of joining an edge-owned channel; that is
  outside AUD-16, the code on that path is unchanged from `70c832c`, and it
  is on the owner's list (decision D-29). The edge's information queries,
  which this record found ending the requester's connection, are answered
  since BLJ-R1's fix, recorded in
  [the edge local queries record](stage-10-edge-local-queries.md).
- The daemon tests run on the development host, not the release
  qualification hosts.
