# Plaintext between an encrypted direct pair (D-50)

This record covers the server topic `sdk/b-direct-plaintext` of the SDK
server program (decision D-50, 2026-10-09, outside master #35). The first
commit keeps a direct pair's routes ordered and indexed: an edge orders its
projections of one pair by their state generation, and removing a route
gives each index it held to the newest remaining route with that key, so a
coordinator store holding a ReInit successor that no activation anchors
leaves the successor's predecessor every index, and still does not start. No
specification, profile hash, registry entry, named limit, reply code, wire
object, table, key, row kind, field or storage generation changed.

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

## Stage 08 evidence (G-07)

The first commit changes `crates/agenc-relay-domain/src/e2ee/route_table.rs`.
The bounded model (`crates/agenc-relay-testkit/src/e2ee_model.rs`) binds
channel routes only and is unchanged; it
gains no action, since no new phase is reachable only through one, and
every count of `conformance/stage-eight-model.toml` is unchanged: actions
32, states 58, transitions 145, paths 27 and refusals 847. The pinned
`lock_slots_refuse_forks_and_admit_only_the_next_incarnation` (gate 21) and
`destroying_an_instance_removes_only_its_tombstone` (gate 4) keep their
names and bodies. The model and the transcript catalog
(`scripts/run-stage-eight-model.sh`, `scripts/run-stage-eight-transcripts.sh`)
were run at this commit. The evidence that changed is new
domain, coordinator and edge tests of companion Sections 9.4, 12.5 and
13.8, with no transcript row; no box changes.

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

- A store holding an unanchored ReInit successor keeps its refusal at
  startup; the discard now leaves the predecessor every index before it.
