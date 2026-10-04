# Requester replies of ReInit results and terminal events (SC-013)

This record covers SC-013 of the SDK server program (2026-10-01, outside
master #35): the labeled result a requesting connection receives for the four
ReInit submissions, and the untagged copies of an ACK or terminal event that
the requesting connection no longer receives. No wire object, registry,
profile hash, limit, persistent format or normative text changed.

## Each ReInit result keeps its own token

Companion Section 11.7 gives `EGROUP SUBMIT REINIT ATTEMPT`, `ACK`, `ACTIVATE`
and `ABORT` their own labeled replies, `REINIT-STAGED`, `REINIT-ACKED`,
`REINIT-ACTIVATED` and `REINIT-ABORTED` (the Section 11 command table and the
fixed success forms), and Section 12.5 maps each result selector one-to-one to
the corresponding Section 11.7 result. The edge decodes `commit_acked`,
`reinit_staged` and `reinit_acked` into one three-identifier tuple and
`aborted`, `reinit_activated` and `reinit_aborted` into one four-identifier
tuple, and its scalar renderer ignored the kind it had retained beside the
tuple: a staged or acknowledged ReInit was answered `ACKED`, and a successful
activation `ABORTED`. The coordinator already sends the exact result kind, and
the shared renderer in `agenc-relay-e2ee` already has all four forms, so the
defect was confined to the edge.

`scalar_line` (`crates/agenc-relay-runtime/src/e2ee/edge/result.rs`) now
takes the decoded result and chooses the line of a shared tuple by its kind
(`triple_line`, `quad_line`). A tuple under a kind that does not own it is
refused as `E2EE_INVALID_FRAGMENT` instead of being rendered as another kind;
the decoder builds each tuple from its kind, so that arm is defensive and
unreachable from the wire. The batch metadata child renders `ABORTED` only
for an `aborted` result. The completion-delayed path and the retry cache
render through the same function, so a completion that arrives after its
result and a retried submission answered from the cache carry the same token.

This adopts the SDK rehearsal's patch 0002 (rehearsal commit `6babf95c`)
unchanged; only the coverage source inventories were recomputed for this
tree.

### Regressions

`crates/agenc-relay-runtime/src/e2ee/edge/tests/result_kinds.rs` drives real
`federation_result` objects of the six kinds that share the two tuples
(`commit_acked`, `aborted` and the four ReInit kinds) through the edge's own
entry points and checks the byte-exact labeled line:

- `a_result_whose_completion_was_applied_renders_its_own_kind`: through
  `on_result_frame` with the completion event already applied;
- `a_completion_after_the_result_renders_its_own_kind`: the result first,
  then `prepare_completion` and `commit_completion`;
- `a_retried_submission_replays_its_own_kind`: a retried submission answered
  from the reply cache under a new label;
- `a_tuple_under_a_kind_that_does_not_own_it_is_refused`: mismatched kind and
  tuple pairs are refused with `InvalidFragment`;
- `only_an_aborted_tuple_names_an_aborted_batch_child`.

The three-daemon Stage 08 test
`encrypted_clients::reinit::a_reinit_activates_only_with_every_continuing_leaf_acknowledged`
asserted `" EGROUP ACKED "` for `SUBMIT REINIT ACK`; it now asserts
`REINIT-ACKED`. It also checks `REINIT-STAGED`, `REINIT-ACKED` and
`REINIT-ACTIVATED` and their identifiers on the labeled completion line
itself: its earlier `contains` checks were satisfied by the correct untagged
broadcast that arrived before the wrong labeled line.

With `result.rs` alone reverted to `70c832c`, the five unit tests fail (the
labeled token is `ACKED` where `REINIT-STAGED` is required, a mismatched tuple
renders instead of being refused, and a ReInit activation batch names an
`ABORTED` child), and the daemon test fails at its first labeled completion:
`@label=l35 :edge-a.test EGROUP ACKED …` where `REINIT-STAGED` is required.
With the fix restored, all six pass.

### An attempt abort through the daemons

The rehearsal checked `REINIT-ABORTED` at the unit level only.
`encrypted_clients::reinit::a_reinit_attempt_aborts_when_its_second_vote_arrives`
stages a real two-leaf ReInit attempt through the production coordinator and
both edges, then aborts it with the two council votes in separate requests
(companion 13.8: an abort is certified at the derived old-policy quorum,
which is two for this two-principal council):

- alice's vote alone is below the quorum and is answered
  `PENDING <conversation-id> REINIT-ABORT <request-object-id>`;
- bob's vote completes the abort and is answered
  `REINIT-ABORTED <old-conversation-id> <reinit-attempt-id> <abort-id> <certificate-object-id>`,
  whose abort ID equals the one recomputed from the abort core;
- alice then reads the untagged `REINIT-ABORTED` broadcast naming the same
  abort, as Section 11.7 gives a requester answered `PENDING`.

With only the `reinit_aborted` arm of `quad_line` rendering `ABORTED`, the
test fails at bob's completion (`@label=l6 :edge-b.test EGROUP ABORTED …`
where `REINIT-ABORTED` is required); with the whole of `result.rs` reverted
it fails earlier, at the staged attempt's `ACKED`.

### Wire effect

Only the requester's labeled completion of the four ReInit submissions changes
token: `ACKED` becomes `REINIT-STAGED` or `REINIT-ACKED`, and `ABORTED`
becomes `REINIT-ACTIVATED` or `REINIT-ABORTED`. The identifiers, the untagged
broadcasts and the ordinary `ACKED` and `ABORTED` replies are unchanged.

## The requesting connection receives only its labeled result

Companion Section 12.5 (the paragraph that begins "Labels never cross
federation") states that an ACK submission gets one labeled `ACKED`, a ReInit
ACK submission one labeled `REINIT-ACKED`, and that an immediate close,
ReInit stage, finalization, abort, ReInit activation or ReInit abort "uses
its semantic completion to send exactly one labeled scalar to the requesting
connection and the registered untagged broadcast to other eligible local
sinks; it suppresses that broadcast on the requesting connection". Section
11.7 repeats it for ACKs ("ACK submission gets only the labeled `ACKED`
scalar; the final unlabeled line merely notifies other sessions") and states
that a requesting connection receives its one labeled terminal line, or an
earlier labeled `PENDING` followed later by the untagged broadcast.

The edge rendered an event's copies for every attached connection of the
conversation, the requesting connection included, and then the request's
labeled result: the requester read the untagged `ACK`, `REINIT-ACK` notice or
terminal broadcast first and its labeled line second. `fanout`
(`crates/agenc-relay-runtime/src/e2ee/edge/events.rs`) now skips the
requesting connection for every kind except the application and candidate
events, whose copy to the requester is the request's labeled echo
(`echoes_to_requester`). The requesting connection is the one whose pending
request the event's correlation names. The coordinator correlates an event
only when it is a request's completion (the home copy of the semantic event,
or a generic `request_completed`, which renders no copy), so such an event
always completes that request, and its labeled scalar follows once the result
is present, in either arrival order. Every other attached connection, another
session of the requester's own account included, still receives the untagged
copy. A request answered `PENDING` is completed by its generic
`request_completed` event, and the edge retires it when that line renders.
The terminal that a later request completes is correlated only on the copy
the coordinator sends to that later request's home edge (`mark_completion`
in `crates/agenc-relay-runtime/src/e2ee/coordinator/execute.rs`), and it
names that request. The connection of the earlier `PENDING` request
therefore receives the terminal as the untagged broadcast, as Section 11.7
requires, unless that same connection submitted the completing request (see
Limitations). The ordinary event path and the cross-profile barrier path
both render through `fanout`.

### Regressions

`crates/agenc-relay-runtime/src/e2ee/edge/tests/requester_copies.rs` drives
the eight kinds (commit ACK, ReInit ACK, finalized, aborted, closed, ReInit
staged, ReInit activated and ReInit aborted) through the edge's own entry
points, a real `federation_event` (with its ACK object as `EDATA` for the
two ACK kinds) and a real `federation_result`, on a direct route that three
attached connections share: the requester, a second session of the
requester's account and the peer. Each connection must receive exactly the
expected line:

- `a_completed_request_reaches_its_requesting_connection_only_as_its_labeled_result`:
  the requester's request completes; the requester receives its one labeled
  scalar and both other connections the untagged copy;
- `the_untagged_copy_is_withheld_only_from_the_connection_whose_request_completes`:
  the peer's request completes, so the peer receives its one labeled scalar
  and the requester, whose own earlier request is no longer held, receives
  the untagged copy;
- `an_event_that_completes_no_local_request_reaches_every_sink`: without a
  correlation, or naming a request the edge does not hold, every connection
  receives the copy and the held request stays open (this one passes with
  and without the change, as a control);
- `a_barrier_completion_reaches_its_requesting_connection_only_as_its_labeled_result`:
  the requester's request completes through `prepare_barrier`, and the
  barrier's completions are committed as `barrier_outputs` commits them once
  the base receipt stands.

The three tests that complete a request run every kind in both arrival
orders, the result before its completion and the completion before its
result, and require the completed request to be retired.

Through the daemons, the Stage 08 ReInit scenarios now require the
requester's reply to name its result exactly once, in the labeled
completion: the staged attempt and the activation from alice, the abort
completion from bob, and, for each ReInit ACK, no `REINIT-ACK` notice of the
submitter's own ACK object. bob reads the activation, and alice the abort,
as the untagged broadcast naming the same identifiers.

The shared Stage 08 helpers apply the same check to every commit ACK,
finalization and close a daemon scenario submits: `real_clients::acknowledge`
requires the submitter's reply to carry no `ACK` notice of its own ACK
object, and `real_clients::finalize`, `activate_bootstrap_with` and
`close_conversation_at` require the labeled `FINALIZED` or `CLOSED` line to
be the only line of the reply that names that result. A line naming another
result is earlier traffic the connection had not read yet and is allowed;
the ReInit checks above follow the same rule.

`requester_copies::a_member_on_the_requesters_edge_reads_each_copy_the_requester_does_not`
(`crates/agenc-relay-server/tests/stage_eight_e2ee/requester_copies.rs`)
checks the copies on the requester's own edge. carol, an account outside the
council, attaches her device and joins the bound channel on alice's edge.
alice then finalizes the bootstrap activation, aborts a sequenced candidate
with both council votes (through the new `real_clients::abort_candidate`),
acknowledges and finalizes a close-intent Commit, and closes the
conversation. Each time alice reads only her labeled result, while carol on
her edge and bob on the other each read the untagged copy naming the same
result: `FINALIZED`, `ABORTED`, the `ACK` notice, `FINALIZED` and `CLOSED`.
carol's account is created on the coordinator's own client listener.

Each unit test reports every case that mismatches. With `events.rs` reverted
to its previous commit, the three tests that complete a request fail in all
48 of their cases, the eight kinds in both arrival orders for the
requester's request, for the peer's request and through the barrier: in
each, the connection whose request completes receives the untagged `ACK`,
`REINIT-ACK`, `FINALIZED`, `ABORTED`, `CLOSED`, `REINIT-STAGED`,
`REINIT-ACTIVATED` or `REINIT-ABORTED` copy before its labeled scalar, and
the control passes. Through the daemons, eight Stage 08 scenarios fail at
their first ACK or terminal request, each requester reading its own `ACK`
notice or `FINALIZED` broadcast before its labeled line: both ReInit
scenarios, the rotation, recovery and restored-lineage scenarios, both
pinned transcripts
(`encrypted_clients_on_two_edges_bind_a_channel_through_the_coordinator` and
`real_mls_clients_run_the_encrypted_lifecycle_through_the_daemon`) and
`requester_copies`. (Before the shared helpers carried the check, the ReInit
scenarios failed only later, at the staged attempt: "the requester received
2 REINIT-STAGED lines, not one labeled completion".)

Each single-kind mutant of the rule is caught through the daemons as well.
With the commit ACK kind added to `echoes_to_requester`, eight scenarios
fail; with the finalization kind, eight; with the close kind, five; and with
the abort kind, `requester_copies` fails at its abort ("the requester
received 2 ABORTED lines naming its result"). With the requesting test
widened to any held request (`requester.is_some()`), which withholds the
copy from every sink on the requester's edge, `requester_copies` fails when
carol waits for the activation's `FINALIZED` copy. Before these checks, all
five mutants passed every daemon test. With the change restored, all pass.

### Wire effect

A requesting connection no longer receives the untagged `ACK` or
`REINIT-ACK` notice of its own ACK submission, or the untagged `CLOSED`,
`REINIT-STAGED`, `FINALIZED`, `ABORTED`, `REINIT-ACTIVATED` or
`REINIT-ABORTED` broadcast of the request it submitted; its labeled result
is unchanged. Every other connection, and every application and candidate
echo, is unchanged.

## Limitations

- The meaning of the last identifier of `REINIT-ACTIVATED` and
  `REINIT-ABORTED` (`<certificate-object-id>`) is unchanged; the SDK
  program tracks that reading separately (its cross-check row SC-010).
- ReInit's own target-commitment correction (the SDK program's PC-001) is a
  separate change; this one only makes the edge render the result kind the
  coordinator already sends.
- Through the daemons the results are checked on the ordinary path, where the
  completion event is applied before the labeled result. A completion that
  arrives after its result and a retry answered from the reply cache are
  checked at the unit level only, and no daemon test restarts an edge between
  a ReInit result and its completion.
- Through the daemons, the requesting connection's own reply is checked for
  every ACK and terminal kind, but a second sink on the requester's own edge
  is checked only for the commit ACK, finalization, abort and close kinds.
  The ReInit scenarios read their copies on the other edge, so an edge that
  withheld a ReInit copy from every local sink would be caught by the unit
  tests only. A second session of the requester's own account and the
  barrier path are also checked at the unit level only; no daemon scenario
  runs a cross-profile barrier.
- A connection whose earlier request was answered `PENDING` and that then
  submits the request completing the same terminal itself receives that
  terminal once, as the later request's labeled completion. One device can
  do this by relaying a missing council vote after its own vote was answered
  `PENDING`, since the coordinator keeps a subject's vote ledger across
  requests. Section 11.7 promises the `PENDING` request a later untagged
  terminal, while Section 12.5 suppresses that broadcast on the requesting
  connection; the edge follows 12.5 and keeps no record of the retired
  `PENDING` request.
- The requesting connection is matched by its pending request. A client that
  disconnects before its result loses that request, as before, and a new
  connection receives the untagged copy.
- No critical-coverage region was added. The changed items render or route
  client lines and parse nothing; the file's closed decoder `decode_value`
  has no region in either policy, and neither do `scalar_line` or `fanout`.
  Whether the release inventory should gain `protocol-enum-arms` regions for
  `triple_line`, `quad_line`, `metadata_child` and `echoes_to_requester` is
  the owner's decision; the release region `edge-route-projection-writes` in
  `events.rs` was only re-anchored, its span unchanged.
