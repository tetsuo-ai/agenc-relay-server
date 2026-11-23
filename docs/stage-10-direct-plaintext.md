# Plaintext between an encrypted direct pair (D-50)

This record covers the server topic `sdk/b-direct-plaintext` of the SDK
server program (decision D-50, 2026-10-09, outside master #35). The first
commit keeps a direct pair's routes ordered and indexed: an edge orders its
projections of one pair by their state generation, and removing a route
gives each index it held to the newest remaining route with that key, so a
coordinator store holding a ReInit successor that no activation anchors
leaves the successor's predecessor every index, and still does not start.
The second binds a direct reservation only to the pair it reserved. The
third refuses plaintext between the two accounts of a direct pair whose
encrypted binding is live, closing or closed, on every node, until the
pair's next incarnation binds, which refuses it in turn: the coordinator
decides every line, from its own clients and from every edge, with the route
table's one predicate, and an edge refuses earlier what its own projection
shows. The fourth drives these rules through the production daemons, on one
edge, across two edges and from the coordinator's own listener. The fifth,
written on 2026-11-23 after the topic was merged with `main` at #197, has a
removal copy only the routes it offers an index. No specification, profile
hash, registry entry, named limit, reply code, wire object, table, key, row
kind, field or storage generation changed.

## A pair's routes stay ordered and indexed (first commit)

The companion text these rules implement:

- Section 12.5: "Every change to a serialized `ArcFederationRouteState`
  field, including accepted-state or sequencer-record head, emits that
  changed object to each then-entitled edge; an authoritative route
  transition sets its `state_generation` to the event's coordinator state
  generation"; "Losing the last entitlement sends `route_state_hidden` with
  the prior object ID after every earlier event for that route; the edge
  deletes that one projection entry before EACK"; and "Edges use those
  authenticated route-state accounts for plaintext downgrade rejection".
- Section 9.4: "A later incarnation increments by one and names the
  semantic close ID of the prior incarnation", so a pair's next incarnation
  binds only after the close of the one before it.
- Section 13.8: an activation installs its successor in the transaction
  that stores the activation certificate, so a successor's route stands only
  on its predecessor's retained activation.

The rules, in `crates/agenc-relay-domain/src/e2ee/route_table.rs` and the
runtime:

- A route entry carries `state_generation`: an edge's projection takes the
  state generation of the route state it projects
  (`e2ee::edge::events::route_entry`), and the coordinator's own entries
  carry zero, since it orders its routes by incarnation and binding
  generation. The rank two entries compete by for one index is the later
  incarnation, then the later binding generation, then the later projected
  state generation, then a route that is not a tombstone. A pair's later
  incarnation binds in a later plan than the close of the one before it,
  and a closed route's state never changes again, so its projection always
  carries the later state generation: an edge indexes a pair's newest
  projection whatever the order its projections arrive or restore in, and
  two tombstones of one pair no longer tie.
- `RouteTable::remove_projection` gives each index the removed route held,
  its concrete route, its lock or its lineage, to the newest remaining
  route with that key, by the restore's rank rule (`take_indexes`, which
  now takes only the indexes it is given). An edge whose newest projection
  of a pair is hidden still indexes the pair's next newest projection.
- Coordinator startup discards a ReInit successor no verified activation
  anchors (`discard_unanchored_successors`, through `remove_projection`),
  and so re-runs that rank rule over the routes that remain: the
  predecessor regains its concrete route, lock and lineage, so its pair or
  channel instance takes no reservation and no second incarnation zero
  binds under its lock. Such a store still does not start: every route row
  has its recovery gate row (architecture Section 18.4), and installing the
  gates refuses a gate row whose route did not restore, as the discarded
  successor's did not.

| Test | What it pins |
| --- | --- |
| `e2ee::route_table::tests::projections_of_one_pair_order_by_their_state_generation` | Two tombstones of one pair, and a tombstone beside a live projection of an earlier state generation, index the later state generation in either restore order. |
| `e2ee::route_table::tests::removing_a_route_gives_its_indexes_to_the_newest_remaining_route` | Hiding an edge's newest projection of a pair indexes the next newest, and the pair keeps refusing plaintext until its last projection goes; removing a ReInit successor, of a direct pair and of a channel instance, leaves its predecessor current and its lineage indexed, the pair or instance takes no reservation, and an incarnation zero under the predecessor's lock is a fork; removing a channel route's later incarnation, on its own instance and under its own lock, gives the lineage back to the earlier one. |
| `e2ee::edge::tests::downgrade::an_edge_indexes_a_pairs_newest_projection_whatever_the_order` | Through the edge's own projection of route state objects: two tombstones of one pair, and a tombstone with the pair's next incarnation, index the newest in either order. |
| `e2ee::coordinator::startup::route_tests::a_discarded_successor_leaves_its_predecessor_every_index` | Startup's discard of an unanchored successor, restored over its predecessor, leaves the predecessor current; its pair or instance takes no reservation and an incarnation zero under its lock is a fork. |
| `e2ee::coordinator::tests::sequence::reinit::successor::unanchored::a_store_holding_an_unanchored_successor_does_not_start` | A store holding every row an activation wrote but the activation's own record, through the coordinator's full reload: the store the attempt left starts with the predecessor current, and this one does not start. |

Single edits that each fail a test: the rank without the state generation
(the domain ordering test and the edge ordering test); the edge projecting
no state generation (the edge ordering test); removal giving no index back
(the domain removal test and the startup discard test); and removal giving
back only the concrete route (the same two tests, at the lineage). The
unanchored store test pins the refusal that the recovery gates make, which
this topic keeps.

## A direct reservation binds only its pair (second commit)

The companion text this rule implements:

- Section 11.5: "Direct reservation binds the authenticated sender and
  named peer", and the reservation the sequencer signs carries the concrete
  `route_binding`.
- Section 9.4: for a direct binding "the instance is empty and the nonce is
  exactly 32 bytes. These values equal the reservation, or for a ReInit
  successor the replaced binding's, and recompute the concrete
  `route_binding` under Section 9.1", which hashes the nonce with the
  pair's two Account IDs.

The audit of how `EGROUP BIND` matches a direct reservation: the
specification requires the binding's route to be the reserved one, so the
account, the nonce and the pair must all match; the account is the
reserving owner, the smaller account of the pair, as before. The rule:
`BindingSummary::direct_pair` carries the pair a direct binding's semantic
route names (`e2ee::coordinator::ops::route::binding_summary`), and
`RouteTable::bind` admits a direct binding only when it names the reserved
pair as well as the reserved nonce, and a channel binding only when it
names no pair; any other binding takes no route and is
`E2EE_BINDING_AUTH_INVALID`, the code the handler already gave a binding
that does not fit its reservation. Every bound route is therefore indexed
under the pair its own binding names, which is the pair the plaintext
refusal below decides by.

| Test | What it pins |
| --- | --- |
| `e2ee::route_table::tests::a_direct_reservation_binds_only_the_pair_it_reserved` | A binding naming another pair, or no pair, under the reserved nonce is refused and leaves both pairs free and the reservation standing; a channel binding naming a pair takes no channel reservation; the reserved pair then binds, and a binding of a conversation that already holds a route takes the standing reservation no more. |
| `e2ee::coordinator::tests::sequence::recreated_routes::reserved_pair::a_direct_reservation_binds_no_other_pair_under_its_nonce` | Through the handlers: a binding of the creator with another account, signed by both and root-locked, on the nonce reserved for the peer, is `E2EE_BINDING_AUTH_INVALID` and indexes neither pair; the reservation then binds the peer's pair, and only that pair is encrypted. |

Single edits that each fail a test: the nonce alone matching a direct
reservation (both tests); a direct binding that names no pair admitted (the
domain test); and a channel binding naming a pair admitted (the domain
test).

## Plaintext between an encrypted direct pair is refused on every node (third commit)

The companion and architecture text these rules implement:

- Companion Section 11.4: "While a live encrypted direct binding exists for
  an Account-ID pair, the server resolves nickname targets to Account IDs
  and rejects plaintext `PRIVMSG` or `NOTICE` between that pair with
  `E2EE_REQUIRED`. Nick changes, multiple sessions, and routing through
  another edge do not bypass this rule; unrelated account pairs are
  unaffected. A closed direct binding remains an encrypted tombstone until
  an explicitly approved new semantic generation is created and never
  silently falls back to plaintext."
- Companion Section 12.5: "The coordinator remains authoritative for every
  lookup not already entitled and for every base direct-message downgrade
  check, so absence from this cache never authorizes plaintext", and a
  direct route is projected to an edge only while an event, operation or
  mailbox item of a local origin requires it.
- Companion Section 11.9: `:server FAIL <actual-command|*> <code>
  [context-token] :description`, where "The optional context is one
  already supplied by the requester" and "The command parameter is the
  actual triggering command, including `JOIN`, `PRIVMSG`, or `NOTICE`";
  `E2EE_REQUIRED` means "Plaintext is forbidden for the target".
- Architecture Section 15.2: "On an E2EE-bound channel or direct route,
  plaintext `PRIVMSG` and `NOTICE` are rejected"; Section 18.2: for an E2EE
  route, companion rules override base behavior for "allowed targets and
  commands"; Section 18.3: "Encrypted direct conversations resolve
  immutable Account IDs through the companion reservation and
  semantic-route lock."

The rules:

- One predicate decides every refusal: `RouteTable::direct_plaintext_allowed`
  refuses a pair with any route, live, closing or tombstoned, whatever its
  recovery gate, and `RouteTable::plaintext_allowed_between` applies it to
  two accounts, allowing a guest on either side and an account messaging
  itself, so unrelated pairs are unaffected. A closed pair refuses
  plaintext until its next incarnation binds, which refuses it in turn.
- The coordinator decides every line (`e2ee::downgrade::refused_direct_target`).
  Before it plans a plaintext `PRIVMSG`, `NOTICE` or client-only `TAGMSG`,
  from one of its own clients (`channels::RegisteredCommandExecutor::route_registered`)
  or from an edge's request (`federation::coordinator::request::plan_command`),
  it resolves each nickname target to its current session's account, as the
  plan resolves it, and refuses the line when the predicate keeps that
  account's pair with the sender's account encrypted. Every session of
  either account, any spelling of a nickname and any position in a target
  list meet the refusal, whichever nodes hold the sender and the target.
- The line is refused whole, before any plan: none of its targets receives
  it. A line from the coordinator's own client is charged first as its plan
  would charge it, so the refusal is no cheaper than the work it replaces
  (architecture Section 19.1: "tokens are charged even when later semantic
  validation fails"), and a line whose tokens are short is `SERVER_BUSY`,
  silent for a `NOTICE`, as every other refused command is
  (`channels::refuse_direct_line`).
- The refusal is `FAIL <command> E2EE_REQUIRED <targets> :plaintext is
  forbidden for the target`, the companion's reply with the targets as the
  requester supplied them as its context, on every capability set, for a
  `NOTICE` and a `TAGMSG` too. An edge renders the coordinator's refusal of
  its request this way (`registration::RegistrationRouter::render_edge_failure`,
  `client_render::direct_refusal_frame`), and the coordinator answers its
  own client with it under the request's label
  (`client_render::render_direct_refusal`). The base renderer's
  `E2EE_REQUIRED`, which names a channel (architecture Section 9.5), and
  every channel refusal are unchanged.
- An edge refuses earlier what its projection shows
  (`E2eeEdge::plaintext_refusal`): a line any nickname of whose target list
  names a local session of an account whose pair with the sender's account
  the predicate keeps encrypted, the nickname compared in its canonical
  form. An edge projects a direct route only while a local reason needs it,
  so the coordinator's check is the one every line meets.

Which node refuses:

| Sender | Target | Refused by |
| --- | --- | --- |
| a session on an edge | a session on the same edge, while that edge projects the pair's route | that edge, before forwarding the line |
| a session on an edge | any other session, on any node | the coordinator, before planning the edge's request |
| a session on the coordinator's own listener | any session | the coordinator, before planning |

The refusal is decided by accounts, as companion Section 11.4 states, and
consults no device attachment: the current-attachment predicate and the
per-connection rules of [the edge attachment record](stage-10-edge-attachment.md)
are unchanged.

| Test | What it pins |
| --- | --- |
| `e2ee::route_table::tests::a_direct_pair_refuses_plaintext_in_every_state_of_its_binding` | The predicate refuses the pair, either way round, while it is live, recovery-gated, closing, closed, reserved again and recreated, and allows an unrelated pair, a guest on either side and one account; a reservation alone refuses nothing. |
| `e2ee::downgrade::tests::the_coordinator_refuses_plaintext_between_an_encrypted_pair_in_every_state` | The coordinator's decision over a seeded domain: a `PRIVMSG`, `NOTICE` and `TAGMSG` to the peer, its nickname in another case, the peer second in a target list or after a channel, a second session of the sender's account, and the reverse direction are refused, naming the peer, while the pair is live, closing, closed, reserved again and recreated; an unrelated pair, a guest, the sender's own second session, a channel and an unknown nickname are not. |
| `e2ee::downgrade::tests::a_recovery_gated_pair_refuses_plaintext_and_an_application_object_is_left_to_the_plan` | A pending and a conflicting recovery gate keep refusing; an encrypted application object and a command that carries no message are left to the plan, which refuses an application object naming a user. |
| `e2ee::downgrade::tests::a_refusal_line_names_the_targets_as_supplied` | The refusal line names the command and the targets as supplied. |
| `e2ee::edge::tests::downgrade::an_edge_refuses_plaintext_to_a_local_member_of_an_encrypted_pair_in_every_state` | Through an edge's projection of route state objects and its local sessions: the same forms are refused, with the exact line, while the pair is live, closing, recovery-gated, closed and recreated; hiding the next incarnation keeps the tombstone refusing; hiding both frees the pair; unrelated pairs, guests and channels are not refused. |
| `registration::edge_completion_tests::a_coordinator_refusal_of_an_encrypted_pairs_line_is_the_companion_refusal` | An edge renders the coordinator's refusal of a direct line, a target list, a `NOTICE` and a `TAGMSG` as the companion's line with the targets as supplied, and a channel's refusal of a message or a `JOIN` as before. |
| `channels::tests::refusals::a_refused_direct_line_is_charged_as_its_plan_would_be` | The coordinator's refusal of its own client's line is charged as its plan would be: repeated refused lines are answered with the companion's line until the sender's budget is spent, then with a refusal that is not `E2EE_REQUIRED`, and a refused `NOTICE` past it is silent. |

Single edits that each fail a test: the predicate refusing only a live
route (the domain, coordinator and edge tests); one account messaging
itself refused (the domain test); a guest refused (the domain test); the
edge refusing only a live route, comparing the nickname as typed, reading
only the first target, or set back whole to the start commit (the edge
test); the coordinator reading only the first target (the coordinator
tests); the coordinator refusing a `PRIVMSG` alone (the coordinator tests);
the edge rendering the coordinator's refusal with the base renderer (the
rendering test); and the coordinator's own client's refused line left
uncharged (the charging test). The coordinator's two checks are pinned
through the daemons below.

## Through the production daemons (fourth commit)

`crates/agenc-relay-server/tests/stage_eight_e2ee/direct_plaintext.rs`
drives the Stage 08 network of production daemons, a coordinator and two
edges, through the client surface. Each refused line is followed by a line
of the sender's to a plain channel every session joined, which every target
reads up to: the coordinator orders a sender's lines and every node delivers
them in that order, so a target that reads the fence without the refused
line never received it.

| Test | What it pins |
| --- | --- |
| `an_encrypted_pair_on_one_edge_refuses_plaintext_live_closed_and_recreated` | Two accounts on edge A bind, bootstrap and use a direct conversation. While it is live, after its authorized close and before the next incarnation binds, and after incarnation one, naming that close, binds, bootstraps and carries traffic, a `PRIVMSG` and a `NOTICE` to the peer, its nickname in upper case and a list naming carol first are each `FAIL ... E2EE_REQUIRED` with the targets as sent, and neither the peer nor carol receives them; the reverse direction is refused too; carol, an account in no pair, receives the creator's plaintext; and once incarnation one is live the pair takes no other reservation. |
| `an_encrypted_pair_across_edges_and_the_coordinator_refuses_plaintext_live_closed_and_recreated` | The same, with the two accounts on edge A and edge B and carol on edge B, plus a second session of alice's account on the coordinator's own listener: its `PRIVMSG` to bob and bob's `NOTICE` to it are refused, and neither alice's sessions nor bob receives them, in all three phases. |

The tests pass in 5 of 5 runs, and in 3 of 3 confined to two processors.
Each of these fails them: the coordinator's check of an edge's request
removed (the cross-edge test); its check of its own clients removed (the
cross-edge test, at the coordinator's session); the edge rendering the
coordinator's refusal with the base renderer (the cross-edge test); and the
edge's rule set back to the start commit with both of the coordinator's
checks removed (both tests).

## A removal copies only the routes it offers an index (fifth commit)

`RouteTable::remove_projection` offered each index a removed route vacated
to every remaining route: it copied the whole table into a list and ran the
rank rule on every entry, though only a route that shares a vacated index
can take one. The rule and every index a removal leaves are unchanged; what
a removal reads and copies is not:

- A route that held none of its indexes, a projection that another outranks
  under every key, leaves none to give, and its removal returns without
  reading the table.
- Otherwise the table is read once, in its own order, and only a route that
  shares a vacated index is copied and offered it. A route that shares none
  is passed over, where before it was copied and took nothing.

One removal, in a table whose routes share no key, as the median of three
runs of a release build on the development host, beside one copy of the
whole table:

| Routes in the table | Removal before | Removal after | One copy of the table |
| --- | --- | --- | --- |
| 1,000 | 0.0083 ms | 0.0034 ms | 0.072 ms |
| 10,000 | 0.101 ms | 0.043 ms | 0.94 ms |
| 100,000 | 3.96 ms | 2.25 ms | 19 ms |
| 1,000,000 | 81.5 ms | 29.6 ms | 196 ms |

What stays open: a removal still reads the table once when the removed
route held an index. An edge already pays more than that for every event:
`E2eeEdge::begin_projection` copies the route table, with the edge's
conversations, route objects and channel names, before it applies each
ordinary companion event and each barrier (`apply_event`,
`prepare_barrier`), so the last column is the route table's part of every
event's cost, and a removal adds less than a sixth of it, at every size
measured, to an event that hides a route. A second index naming every route
under each of its keys would end the read, and every one of those copies
would then carry it; it is left until an edge no longer copies its
projection for every event.

| Test | What it pins |
| --- | --- |
| `e2ee::route_table::tests::a_removal_leaves_the_table_a_restore_of_the_remaining_routes_gives` | Over one table holding three projections of a pair, a ReInit predecessor and its successor, a route that holds its lock and lineage but not its instance beside an older incarnation that shares only that lineage, a route that holds its instance and lineage but not its lock, and two routes that share no key, removing each route in turn leaves exactly the table a restore of the others gives, in either order. |

Single edits that each fail a test: the removal returning unless the index
of the concrete route was vacated (the new test); a set of indexes counted
as empty when it names only the lineage (the new test and the removal test
of the first commit); only a route that shares the concrete route offered an
index (the same two); and the routes that share an index passed over in
place of the others (the same two). The release coverage policy re-spans
`d50-route-table-remove-projection` over the function as it now stands (10
of 10 branches, where it had 8); the other seven regions of the file keep
their spans.

## Stage 08 evidence (G-07)

The first three commits and the fifth change
`crates/agenc-relay-domain/src/e2ee/route_table.rs`.
The bounded model (`crates/agenc-relay-testkit/src/e2ee_model.rs`) binds
channel routes only and now names no pair in its binding summary; it
gains no action, since no new phase is reachable only through one, and
every count of `conformance/stage-eight-model.toml` is unchanged: actions
32, states 58, transitions 145, paths 27 and refusals 847. The pinned
`lock_slots_refuse_forks_and_admit_only_the_next_incarnation` (gate 21) and
`destroying_an_instance_removes_only_its_tombstone` (gate 4) keep their
names and bodies. The model and the transcript catalog
(`scripts/run-stage-eight-model.sh`, `scripts/run-stage-eight-transcripts.sh`)
were run at each of the first four commits, and the model, the Stage 08
check and every test of the workspace at the fifth. The evidence that
changed is new domain, coordinator, edge and daemon tests of companion
Sections 9.4, 11.4, 11.5 and 12.5, with no transcript row; no box changes.

## Storage (G-08)

The decision is unchanged storage: no table, key, row kind, field, object
layout or storage generation changed, and startup writes nothing it did not
write. Two restores read the same rows to a different index: an edge's
restore of its route rows orders a pair's projections by the state
generation every stored route state already carries, and coordinator
startup gives a discarded unanchored successor's indexes back to its
predecessor before the recovery gates refuse that store, as they refused it
before. A store the start commit wrote holds rows of the same form, so it
restores under these rules, and nothing this topic stores differs for the
start commit to restore.

## Decisions

- The coordinator decides every plaintext line, its own clients' and every
  edge's, before planning (companion Section 12.5); an edge's refusal is a
  cache of the same rule.
- A line naming a member of an encrypted pair among other targets is
  refused whole, before any plan, rather than delivered to its other
  targets: architecture Section 18.2 gives the companion's rules precedence
  over the per-target rule of Section 14.1 for an encrypted route's
  targets, and the client can send its other targets separately.
- A `NOTICE` is answered with the refusal, as companion Sections 11.4 and
  11.9 name it and an edge already answered it, rather than with the base
  profile's silence (architecture Section 15.1).
- A client-only `TAGMSG` to a member of an encrypted pair is refused at the
  coordinator as an edge already refused it, so no node delivers a
  plaintext tag between the pair.
- The refusal names the targets as the requester supplied them, on every
  capability set, as an edge's refusal did.
- A store holding an unanchored ReInit successor keeps its refusal at
  startup; the discard now leaves the predecessor every index before it.
- A removal keeps its one read of the route table. A second index would
  end it and be carried by every copy an edge makes of the table, which it
  makes for every event, so the index waits for that copy to go.
- `EGROUP BIND` refuses a direct binding that names another pair than its
  reservation with `E2EE_BINDING_AUTH_INVALID`, the code it gives every
  other binding that does not fit its reservation.
