# Stage 10 Section-19.3 overload class owners

This record covers RUN-07 (issue #131). The gap it closes is missing
enforcement, not missing evidence: the runtime computed all three Section-19.3
overload classes and reported them to observers, but only part of one class
acted.

At `17da15a`, `crates/agenc-relay-runtime/src/admission/transport.rs` was the
only enforcement in the tree. It refuses an accept at
`>= OverloadClass::NoNewConnections`, so the 90-percent class stopped new
connections; because `Evict` orders above it, the 95-percent class inherited
exactly that refusal and added nothing. The 80-percent class refused nothing at
all, channel creation was never consulted, `select_evictions` had no caller
outside its own unit tests, and `StateCoreContext::overload_class()` had no
caller anywhere in the workspace.

## The ladder after this change

| Rung | Specified behaviour | Owner now |
| --- | --- | --- |
| 80% `NoGuests` | refuse guests, refuse expensive queries | `RegistrationRouter::guest_is_refused` for the guest; `channels::expensive_query_is_stopped`, consulted from `plan_session_command` and from `channels::history::history_admission`, for the query |
| 90% `NoNewConnections` | refuse new connections, refuse channel creation | `TransportAdmission::admit` (unchanged) for the accept; `channels::channel_creation_is_stopped`, consulted from `plan_session_command`, for the creation |
| 95% `Evict` | select and close whole connections until below 85% | `StateCoreContext::shed_overloaded_connections`, driven from `StateCore::step_message` and `StateCore::step_wake` |

Every owner reads the class through the new
`StateCoreContext::refresh_overload`, which reclassifies from the live budget
at the moment of the decision and reports a transition to the observer. The
accessor that had no caller, `overload_class()`, is now the read-only half of
that pair and is what `refresh_overload` reads to decide whether a transition
happened; the deciding half is never a cached value. `admit_connection` was
rewritten to use the same helper, so the reclassification on connection open
and every new decision point share one implementation and one transition
event.

## The 80-percent class

**Guests.** `commit_registration` already refused an unauthenticated
registration when `accounts.allow_guests` was false. That branch is now reached
through `guest_is_refused`, which keeps the standing-policy refusal exactly as
it was and adds the transient one: when the live class stops guests, the
connection first receives

```text
:server FAIL * REGISTRATION_REQUIRED :Registration required
```

and is then refused through the existing path. Neither refusal reaches
`session_seed`, so no session, nickname binding or durable row is created.

**Expensive queries.** The refused set is exactly
`agenc_relay_domain::is_expensive_query`, which was already the predicate that
decides which commands owe a token from the session-keyed expensive-query
bucket of Section 19.1: `NAMES`, `LIST`, `WHO`, `WHOIS`, `WHOWAS` and
`CHATHISTORY`. It was private; this change makes it public and the runtime
calls it rather than restating the set. The refusal is the bounded
`SERVER_BUSY` of Section 28.7, rendered by the existing
`client_render::render_domain_failure` from `DomainError::ServerBusy`:

```text
:server FAIL LIST SERVER_BUSY :Server is busy
```

`CHATHISTORY` does not flow through `plan_session_command`; it is admitted by
`history_admission` and then reads a snapshot. The gate is therefore applied in
both places, and in the history path it is applied before any snapshot is
selected or any storage read is submitted.

## The 90-percent class

A join is refused only when it would create a channel. The domain already
computes that: `DomainState::join_requests` asks for one
`ExternalInputRequest::Entropy { purpose: EntropyPurpose::ChannelInstance(_) }`
for each join target whose name does not exist yet, and asks for none when
every named channel already exists. `channel_creation_is_stopped` reads that
request vector, so a join of existing channels is unaffected at 90 percent
while a join that would create one is refused with the same bounded
`SERVER_BUSY`. No domain planning rule and no per-target failure class was
changed.

The refusal is taken after the command was charged, which is deliberate.
Section 19.1 requires that tokens are charged even when later validation fails,
"so a rejection cannot become an error oracle". Refusing before the charge
would make a refused expensive query strictly cheaper than a served one, which
is the wrong incentive precisely while the node is under memory pressure. The
refusal is still side-effect free in the sense Section 28.7 means: no partial
fanout, no partial durable admission, no mutation staged, no channel created.

## The 95-percent class

`shed_overloaded_connections` is the owner. It reclassifies, returns
immediately unless the class is `Evict`, and otherwise:

1. builds the candidate list from `SessionTable::eviction_candidates`, which
   lists every connection whose transport is still live together with the bytes
   its outbound queue currently holds, in ascending generation order;
2. calls the existing `select_evictions`, which sorts descending by charged
   queue bytes, breaks ties on the earlier generation, and stops as soon as the
   projected usage is below the 85-percent recovery mark;
3. for each selected connection calls `ClientSink::begin_slow_consumer_close`
   and `SessionTable::mark_sink_gone`.

`begin_slow_consumer_close` is the existing immediate close: it clears the
whole entry ring and zeroes every queue counter in one step, so the connection
loses its entire queue with the connection. No individual frame is ever
selected, and a frame shared with another connection's queue keeps its permit
until that last queue drops it, because the permit is owned by the queue entry
and not by the eviction. A connection already marked closing is filtered out of
the next candidate list, so one slow consumer is never selected twice and the
selector's projection is never charged for bytes it already reclaimed.

The projection itself is not reimplemented here. `select_evictions` owns it,
including the base charge a close returns, which is RUN-04's (#130) correction
to that function.

The sweep runs after every accepted input (`step_message`, once the message and
any batch step are complete) and after every timer wake (`step_wake`). It costs
two loads and a comparison when the node is below 95 percent. `StateCore` also
counts what it selected in the new `StateCoreCounters::connections_evicted`.

## What is now proven

Both tests are in
`crates/agenc-relay-runtime/src/state_core/tests/overload_ladder.rs` and drive
the real actor loop, the real registration router and the real command
executor. Both walk one live pool: the accept-time authority under test shares
the very `MemoryBudget` the command rungs are measured against, so the ladder
is one pool and not four fixtures.

### `the_eighty_and_ninety_percent_classes_refuse_only_their_own_work`

Below every threshold a guest registers, creates `#ladder` and the accept-time
authority admits. The pool is then pinned at the first byte that reaches 80
percent, and the test requires:

- a new guest's registration answers
  `FAIL * REGISTRATION_REQUIRED :Registration required` and never reaches
  `001`;
- `LIST`, `WHO`, `NAMES` and `WHOIS` each answer
  `FAIL <command> SERVER_BUSY :Server is busy` and produce none of the
  numerics they would have produced (`321`/`322`, `352`/`315`, `353`/`366`,
  `311`/`318`), checked only against the lines that command produced;
- `AWAY` and `TOPIC` still succeed, so ordinary traffic is untouched;
- the accept-time authority still admits.

Pinned at 90 percent, the test requires that a second registered client's join
of the existing `#ladder` still succeeds, that `JOIN #fresh` answers
`FAIL JOIN SERVER_BUSY :Server is busy` with no `JOIN #fresh` echo, and that
the accept-time authority now refuses.

Released, the test requires that the authority admits again, that a `LIST` now
succeeds and names `#ladder` but never `#fresh` — so the refused creation left
no channel behind — that `JOIN #fresh` now succeeds, and that a new guest
registers.

### `the_ninety_five_percent_class_sheds_the_largest_queues_down_to_the_recovery_mark`

Four connections are opened and one registers. Three of them hold 7, 6 and 3
percent of the pool as queued output, each backed by a real permit from that
same pool, so shedding a connection returns exactly the bytes it claimed, as
destroying a real queue does. The pool is then pinned at 95 percent and one
maintenance tick is delivered. The test requires:

- the 7-percent and 6-percent connections are both marked closing, in that
  order, which is descending charged-queue-byte order;
- the 3-percent connection is not, because 95 − 7 − 6 = 82 percent is already
  below the 85-percent recovery mark;
- the connection with an empty queue is never selected;
- a second maintenance tick selects nobody, so shedding stopped at the mark
  rather than continuing;
- at 82 percent a new guest is still refused, and once the pin is released a
  new guest registers again.

Assertions are on what the client received and on what the node still holds,
never on an internal call count; the ordering assertion reads the order in
which the sinks were told to close, which is an observable of the sink.

## Specification ambiguity resolved here

Section 19.3 names "expensive queries" without listing them. Section 19.1 has
one `expensive query` rate bucket, keyed by session, and the tree already has
one closed predicate that decides which commands owe it. This record adopts
that predicate as the definition: the narrowest reading tied to an existing
normative artifact, rather than a broader one invented for this change. If a
later decision widens the class, one predicate changes and both the rate
limiter and the overload owner follow it.

Section 19.3 also does not give a wire form for the guest refusal. Section 19.1
gives exactly one line for temporarily rejecting a new guest,
`FAIL * REGISTRATION_REQUIRED :Registration required`, in the paragraph about
the onion listener. The 80-percent class is exactly a temporary guest
rejection, so that line is reused verbatim rather than a new code being
invented; `REGISTRATION_REQUIRED` is already in the public reply registry, and
no code was added.

## Limitations

- The default `server.memory_budget_bytes` on this branch is still 4 GiB, and
  `budget::tests::idle_model` records that the Section-19.2 default population
  of 50,000 idle clients sits at 98 percent of that pool. Until RUN-04 (#130)
  raises the default to 6 GiB, a node at its own advertised population is in
  the 95-percent class and this change makes it shed. That is the conflict
  #113 decided and #130 funds; this change deliberately does not touch the
  default or the Section 19.2 and 19.3 text.
- The accept rung is still owned by `TransportAdmission` and was not changed.
  The ladder test exercises it over the same pool, but an accept refused there
  never reaches `StateCore`, so a node with no other traffic applies the
  95-percent class only on its next input or timer wake rather than on the
  refused accept itself.
- Federated and edge-mode paths are untouched. `commit_registration` hands an
  edge-mode registration to `commit_edge_registration` before the guest check,
  and a federated command is planned through `FederatedPlan` rather than
  `plan_session_command`, so an edge node applies only the accept rung and the
  eviction rung. The Section-19.3 classes are a property of one node's own
  memory pool, and the owners added here sit on the local client path.
- `select_evictions` decides from each connection's current queue occupancy. A
  connection whose charge is dominated by query-snapshot backing rather than
  queued frames is ranked by its queue bytes alone, which is what Section 19.3
  specifies ("descending charged-queue-byte order").
