# An edge's labeled message responses and every welcome's counters

This record covers the SDK program's decision D-36 (2026-10-05, outside
master #35), two follow-ups the SDK's encrypted harness found on an edge:
an edge's response to a labeled `PRIVMSG`, `NOTICE` or `TAGMSG`, which the
SDK's wire register records as WD-16, and the welcome burst's `RPL_LUSER*`
counters, which now give the figures of the node's own `LUSERS` reply.
Neither changes a wire format, numeric, reply code, registry, configured
limit, persistent format or specification text.

## Labeled message responses

### What was observed

Architecture Section 2.1 adopts IRCv3 `labeled-response` and `echo-message`,
and Section 9.5 gives a request with a negotiated `label` that label on
exactly one logical response. A coordinator answers its own client's labeled
channel `PRIVMSG` or `NOTICE` that way: with `echo-message` the echo carries
the label (a labeled batch holds the echoes when the message named several
channels), and without it the client gets a labeled `ACK`.

An edge echoed a labeled channel `PRIVMSG` or `NOTICE` without its label,
and without `echo-message` it sent no labeled `ACK`, so the request had no
labeled response at all. `TAGMSG` and direct messages had the same gap.
Comparing every capability combination and target kind with the
coordinator showed two more differences: an edge sent a `TAGMSG` to a
recipient that had not negotiated `message-tags`, which the coordinator does
not, and it did not render a direct message to its sender as the
coordinator does.

### Cause

An edge renders the copies of a message from the coordinator's
`MessageDelivered` events: each local recipient's copy goes out when the
event is applied, the sender's own copy among them. The request's reply is
rendered later, from its completion, when both its result and its
correlated completion event are known. A committed message completed as
`EdgeCompletion::CommandCompleted`, for which the router renders nothing, so
the echo went out unlabeled with its event and no `ACK` followed.

### Fix

In `crates/agenc-relay-runtime/src/federation/edge/message_echo.rs`:

- While a connection's pending request is a message whose `label` the
  connection negotiated with `labeled-response`, the event renderer hands the
  requester's own copy of a delivered message to that request instead of the
  event's fanout (`capture`, called from `render.rs`'s
  `render_event_strict`). Every other recipient's copy, and the echo of an
  unlabeled request, goes out with its event as before.
- The held copy belongs to its request. Rendering the same event again
  replaces the copy it held, so a batch that is staged again or an event
  delivered again after a refused commit holds one copy, not two. The
  request completes only after the event that carries its completion is
  applied, which follows every event of the request in delivery order, and
  a snapshot install that skips those events resynchronizes the connection
  first. A copy is refused, which ends the link as other consistency faults
  do, when it follows the request's completion, when the request's result
  is not a commit at the copy's generation, when the request already holds a
  copy of another generation, or when it would hold more copies than the
  message names targets (`capture`, `labeled_targets`). A result that does
  not commit at a held copy's generation is refused the same way
  (`validate_result`, from `receive_result`). Each held copy is charged to the
  memory budget, twice the longest line, until it is sent.
- A committed message completes as `EdgeCompletion::MessageCommitted` with
  the copies it held, in delivery order, and any replies its result carried
  (`complete`, from `request.rs`'s `completed_request`). The router sends it
  through the path of the edge's other replies (`deliver_edge_replies`, then
  `client_render::logical_frames`), the one the coordinator's own replies take:
  one copy is labeled, several share one labeled batch, and a labeled request
  with no copy gets a labeled `ACK`. An unlabeled request with nothing held
  gets nothing, as before.

In `render.rs`'s `frames_for`, a `TAGMSG` now reaches only a recipient that
negotiated `message-tags`, its sender's echo included, as IRCv3
`message-tags` requires and the coordinator does. A direct message reaches
its target alone, and its sender only when the sender is the target and
negotiated `echo-message`. That matches the coordinator, and it is a
recorded deviation, not the rule: IRCv3 `echo-message`, which Architecture
Section 2.1 adopts and Section 30.2 pins, requires a server to send a
`PRIVMSG` or `NOTICE` back to the client that sent it, a direct message
included, and no role echoes a direct message yet. The fix for every role
is on the owner's list (Limitations).

### The regressions

| Test | What it pins |
| --- | --- |
| `federation::edge::tests::labeled_messages::an_edge_gives_a_labeled_message_the_coordinators_one_labeled_response` | A coordinator and an edge in one process over a bridged link. In four capability sets (`labeled-response` without `echo-message`, with it, with it but without `message-tags`, and `echo-message` without `labeled-response`), a client of the edge and a client of the coordinator each send twelve messages: `PRIVMSG` and `NOTICE` to a channel, to the other requester, to a client of their own node, to two channels and to a channel and the other requester, and `TAGMSG` to a channel and to the other requester. Each response is exactly one labeled line or labeled batch (none in the last set). After a topic change that the edge applies after every event of the message, the requester holds exactly its expected echoes, labeled or not, in every set. The edge's response, or in the last set its echoes, equals the coordinator's once names are written as placeholders; every other recipient's copy carries no label, on the edge and on the coordinator, and no `TAGMSG` reaches a client without `message-tags`. |
| `...::labeled_messages::a_labeled_echo_waits_for_its_request_to_complete` | Through the edge's actor loop with a scripted coordinator: the requester's copy of a labeled channel message is not sent with its event and arrives, labeled, once the request completes, whether the completion or the result arrives last; an unlabeled message's echo goes out with its event and its request ends without a reply. |
| `...::labeled_messages::a_copy_that_contradicts_its_result_ends_the_link` | The same, with the request's result committed at one coordinator state and the event that delivers its echo at another: the edge closes the link and sends no echo. |
| `...::labeled_messages::a_result_that_contradicts_a_held_copy_ends_the_link` | The same in the other order: the copy is held first and the request's result then commits at another coordinator state; the edge refuses the result, closes the link and sends no echo. |
| `federation::edge::message_echo::tests::only_the_requesters_copy_of_a_labeled_message_is_held` | No copy is held for another event, another recipient, an unlabeled request, a request with another tag and no label, a label without a value, a label without `labeled-response`, no capabilities, a request that is not a message, another connection, a connection that is gone or a request that is not a command; nothing is held without `echo-message`. |
| `...::a_held_copy_is_replaced_by_its_own_event_and_bounded_by_the_targets` | A re-rendered event replaces its copy without a second charge; a one-target message holds one copy and a two-target message two, and one more is refused; a dropped request releases its copies' backing. |
| `...::a_copy_that_contradicts_its_request_is_refused` | A copy after the completion, after the completion's coverage, under another generation than the result, for a failed request or beside a copy of another generation is refused; one at its result's generation is held. |
| `...::a_copy_without_backing_is_refused` | With the memory budget exhausted the copy is refused and nothing is held. |
| `...::a_result_must_commit_at_every_held_copys_generation` | With nothing held any result stands; with a copy held only a commit at its generation does. |
| `...::the_held_copies_become_the_response_and_keep_their_backing_until_sent` | The completion carries the held copies in order, then the result's replies, and their backing until it is dropped; with nothing held it carries no line. |
| `stage_seven_federation::an_edge_gives_a_labeled_channel_message_one_labeled_response` | The production binary, a coordinator and two edges: a client of edge A sends a labeled channel `PRIVMSG` and `NOTICE` without `echo-message` and gets one labeled `ACK` each, then with `echo-message` and gets one labeled echo each; the other members, on edge A, on edge B and on the coordinator, receive all four without a label. |

### The fix, reverted

With the production files of the fix restored to `6e84d29`
(`message_echo.rs` removed, and the new field dropped from the four test
constructors of `PendingRequest`), the four `labeled_messages` tests fail:
the scripted one sees the echo sent with its event, the bridged one gets no
response to its first labeled message, and neither contradiction ends the
link. The daemon test fails the same way: the client of edge A reads
no labeled response to its first message. Four further runs revert one part
each, with every test kept:

- The requester's copy no longer handed to `capture`: the four
  `labeled_messages` tests fail (the echo goes out unlabeled with its event,
  the completion then sends a labeled `ACK`, and nothing is held for either
  contradiction to refuse).
- The router handling `MessageCommitted` as any committed command: the
  scripted and the bridged test fail (no labeled response).
- The `message-tags` condition for `TAGMSG` removed: the bridged test fails at
  the first `TAGMSG` without `message-tags` (a labeled echo where the
  coordinator sends an `ACK`).
- The direct-message condition removed: the bridged test fails at a direct
  message with `echo-message` (an echo where the coordinator sends an
  `ACK`).

The six `message_echo` unit tests call the module directly and pass in the
four partial runs. With only the result-generation condition removed from
`capture`, `a_copy_that_contradicts_its_request_is_refused` and
`a_copy_that_contradicts_its_result_ends_the_link` fail (the link stays
open). With the result check's call in `receive_result` ignored,
`a_result_that_contradicts_a_held_copy_ends_the_link` fails (the link stays
open). With a direct message echoed to a sender without `labeled-response`,
the bridged test fails in the last capability set: the requester holds an
echo it should not.

### Coverage

Both production source inventories are refreshed (1,020 files: the new module
and two new test modules sit under `src/`). The release region
`cap13-render-render-event-strict` is respanned, since `render_event_strict`
now hands the requester's copy to `capture`, with its reason restated. Three
release regions are new: `runtime-edge-labeled-message-echo-owner` binds
`capture`, `runtime-edge-labeled-message-request` binds `labeled_targets` and
`runtime-edge-labeled-message-echo-result` binds `validate_result`. The other
regions in the changed files moved with their spans unchanged. Over the
runtime library tests (`RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p
agenc-relay-runtime --lib --all-features --branch --locked`, 2,699 passed),
scored with `check-coverage.py`'s counting:

| Item | Measure |
| --- | --- |
| `capture` (new region) | branches 20/20 |
| `labeled_targets` (new region) | branches 12/12 |
| `validate_result` (new region) | branches 2/2 |
| `render_event_strict` (respanned region) | regions 53/56; the three unreached regions are its existing failure exits (`frames_for`, a second JOIN echo, the fanout append), unreached at `6e84d29` too (43/46) |

The other release regions in the changed files that the library tests leave
short score the same at `6e84d29`, and the crate's branch and line totals
rise from 78.17% and 86.76% to 78.25% and 86.80%.

### Compatibility

- Clients of an edge: a labeled `PRIVMSG`, `NOTICE` or `TAGMSG` now gets one
  labeled response, as on the coordinator. With `echo-message` the
  requester's echo of a labeled message now arrives with the request's
  completion instead of with its event. An edge no longer sends a `TAGMSG` to a
  client without `message-tags`, and renders a direct message as the
  coordinator does: to its target, not back to its sender (a recorded
  deviation, Limitations). Unlabeled channel messages are delivered as before.
- Coordinators and core-only nodes: unchanged.
- Federation, storage, registries and the specification: unchanged. The held
  copies live in memory with their request; no persistent state changes, so
  no restore test applies.
- Mixed builds: an edge built before this change keeps the old responses,
  whatever the coordinator runs.

### Limitations

These differences between an edge and the coordinator were found while
checking and are not changed here (outside D-36):

- A message to several targets of which some fail: a coordinator client's
  response holds the failing target's failure line; an edge client's holds
  only the accepted targets' echoes, or an `ACK`, because the coordinator's
  result for a message carries no reply lines.
- A refused `NOTICE`: an edge client gets the coordinator's failure as a reply,
  while Section 15.1 says a `NOTICE` never causes an automatic error reply; a
  coordinator client gets nothing, so a refused labeled `NOTICE` gets no
  labeled response there.
- An edge's copies of a message carry no `msgid`, `time` or `account` tag
  (Section 15.1); the coordinator's carry the ones its client negotiated.
- No node yet echoes a direct message to its sender under `echo-message`,
  which IRCv3 `echo-message` requires (a MUST; Architecture Sections 2.1 and
  30.2): the domain's recipients of a direct message are its target alone.
  An edge now matches the coordinator; the fix for every role is on the
  owner's list.
- A labeled `TOPIC`, `MODE`, `NICK` or `PART` from an edge client still gets
  no labeled response; the coordinator labels each one.
- A refused direct message to a nickname that does not exist: an edge client
  gets `481`, a coordinator client `401` (`No such nick`).
- The E2EE carriers' echoes on an edge are not covered by these tests.
- The daemon test runs on the development host, not the release
  qualification hosts.

## The welcome's counters

Architecture Section 10.2 step 3 gives the welcome burst `RPL_LUSER*`
counters with privacy-safe aggregate values, and Section 14 gives `LUSERS`
privacy-safe static or aggregate output. The welcome's counters now give the
figures of the node's own `LUSERS` reply:

- an edge sends its fixed `LUSERS` form (decision D-35): `251` and `255` with
  fixed text and no count, byte-identical on every edge in every state apart
  from the server prefix and the nickname;
- a coordinator's `251` counts the network's sessions, the figure its
  `LUSERS` reply gives;
- a node without federation, whose own connections are the network's, counts
  its registered connections, as before, which is what its `LUSERS` reply
  counts.

### Fix

`crates/agenc-relay-runtime/src/registration.rs`: the welcome's
`WelcomeStep::LuserCounters` step renders `luser_counters`, which takes the
edge's fixed form from `query_render::render_static_lusers` (now
`pub(crate)`, the renderer of the edge's `LUSERS` reply), and otherwise one
`251` that counts the domain's sessions on a coordinator
(`DomainState::session_count`, which its `LUSERS` reply counts) and the
registered connections on a node without federation.

### The regressions

| Test | What it pins |
| --- | --- |
| `registration::welcome_tests::an_edge_sends_its_fixed_lusers_form` | Two clients registered on an edge each get the fixed form in their welcome, the same lines apart from the nickname. |
| `registration::welcome_tests::a_coordinator_counts_the_sessions_of_its_domain` | A coordinator's welcome counts every session of its domain, a session homed on another node among them. |
| `registration::welcome_tests::a_node_without_federation_counts_its_registered_connections` | A node without federation counts its registered connections: one, then two. |
| `registration::welcome_tests::an_edge_registration_sends_the_epoch_note_after_the_motd_group`, `registration::account_state_tests::an_authenticated_edge_burst_reads_the_logged_in_state_from_the_replica` | Updated: an edge's burst now holds `251` and `255` before the MOTD group. |
| `federation::edge::tests::welcome_counters::welcome_counters_match_each_nodes_lusers_reply` | A coordinator and an edge in one process: every client of the edge gets the fixed form in its welcome and as its `LUSERS` reply; each client of the coordinator, registered between clients of the edge, gets a welcome `251` that counts the network's sessions, three, four and then six, the count of its `LUSERS` reply. |
| `federation::edge::tests::welcome_counters::a_node_without_federation_counts_what_its_lusers_reply_counts` | A node without federation in the actor loop: each client's welcome counts what its `LUSERS` reply counts, one and two, and two again for a client that registers after another has left. |
| `stage_seven_federation::welcome_counters_match_each_nodes_lusers_reply` | The production binary, a coordinator and two edges serving different clients: the welcomes on both edges are the fixed form and the same apart from the server prefix and the nickname, as is each edge's `LUSERS` reply and a later welcome on edge A; each client of the coordinator gets a welcome that counts the network's sessions, four and then six as clients join on an edge and on the coordinator, the count of its `LUSERS` reply. |

### The fix, reverted

With the welcome's counter step and `query_render.rs` restored to `6e84d29`
and every test kept, the two updated burst tests,
`an_edge_sends_its_fixed_lusers_form` and the in-process test fail, and so
does the daemon test: an edge's welcome is not its fixed form. With only the
edge's fixed form removed, the same tests fail. With only the coordinator's
count removed, the router test of a coordinator, the in-process test and the
daemon test fail: the coordinator's welcome does not give its `LUSERS`
reply's figure. With the count of a node without federation off by one, its
router test and its actor-loop test fail.

### Coverage

The release region `runtime-edge-static-lusers` is respanned, since
`render_static_lusers` is now `pub(crate)`, with its reason restated, and
the new release region `runtime-welcome-luser-counters` binds
`luser_counters`. The other regions in the changed files moved with their
spans unchanged. Both production source inventories are refreshed (1,021
files: the new test module sits under `src/`). Over the runtime library
tests (2,704 passed), `luser_counters` scores branches 4/4 and
`render_static_lusers` regions 12/12, and every release region in the two
changed files is reached in full.

### Compatibility

- Clients of an edge: the welcome's counters are the edge's fixed form, `251`
  and `255`, as its `LUSERS` reply is.
- Clients of a coordinator: the welcome's `251` gives the count of the
  coordinator's `LUSERS` reply.
- Nodes without federation, federation, storage, registries and the
  specification: unchanged.
- Mixed builds: a node built before this change keeps its welcome counters.

## Validation

The labeled message responses (the first commit of the topic), from the
repository root before the commit:

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | clean |
| `cargo nextest run -p agenc-relay-domain -p agenc-relay-runtime -p agenc-relay-server --all-features --locked` | 3,179 passed (1 slow), 21 skipped |
| `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime --lib --all-features --branch --locked` | 2,699 passed, 1 skipped; the measures under Coverage |
| coverage policy refresh: both inventories, re-anchoring, both audits and self-tests | ok |
| the SDK program's fast gate (agenc-relay-sdk `evidence/2026-09-29-server-rehearsal-pc001/tools/fast-gates.sh`, 59 commands), on the staged tree and at the commit | every command passes |

The welcome's counters (the second commit), from the repository root before
the commit:

| Command | Result |
| --- | --- |
| `cargo fmt --all --check` | clean |
| `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings` | clean |
| `cargo nextest run -p agenc-relay-domain -p agenc-relay-runtime -p agenc-relay-server --all-features --locked` | 3,185 passed (1 slow), 21 skipped |
| `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest -p agenc-relay-runtime --lib --all-features --branch --locked` | 2,704 passed, 1 skipped; the measures under Coverage |
| coverage policy refresh: both inventories, re-anchoring, both audits and self-tests | ok |
| the SDK program's fast gate (59 commands), on the staged tree and at the commit | every command passes |

The full gate, `taskset -c 0-31 bash scripts/check-stage-nine.sh`, runs once
at the topic tip; the SDK program keeps its log (decision D-05).
