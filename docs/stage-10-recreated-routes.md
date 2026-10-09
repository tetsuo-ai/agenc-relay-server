# Recreated routes at a later semantic incarnation (B-14)

This record covers the server topic `sdk/b-routes` of the SDK server
program (item B-14, 2026-10-09, outside master #35). The first commit lets
the shared verifiers accept the generation-zero binding of an ordinary group
at a later semantic incarnation, anchored at the verified close of the
incarnation before it. The second lets the coordinator host that
incarnation: its route table keys each incarnation's lock slot by its own
semantic lock and a semantic route's lineage by the lock of its incarnation
zero, admits the next incarnation after an authorized close, reserves a
closed direct pair again, and restores every route's incarnation from its
retained binding, live and after a restart alike. No specification, profile
hash, registry entry, named limit, reply code, wire object, table, key, row
kind, field or storage generation changed.

## A recreated route's genesis follows the close before it (first commit)

The companion text this rule implements:

- Section 9.4: "For either kind, semantic incarnation zero has an all-zero
  predecessor close ID. A later incarnation increments by one and names the
  semantic close ID of the prior incarnation." An initial binding "has
  generation zero and an all-zero predecessor. It has the unanimous
  approvals and root locks described below", and "An ordinary new group has
  `initial_bootstrap_pending=1`; a ReInit successor has zero. Any other
  value or a mismatch with the initial committed context is invalid."
- Section 9.3: when proof material no longer fits a Welcome, "the safe
  recovery is an explicitly closed, next semantic incarnation with new
  generation-zero root locks and renewed verification".
- Section 9.5: "`bootstrap_pending` is 1 only while constructing a
  generation-zero group and 0 afterward."
- Section 11.5: "Close approvals sign with label `ARC-MLS/1 close
  authorization`, satisfy the last finalized policy's controller rule, and
  reference the finalization ID of the exact in-group active-to-closing
  transition. The close intent and its ID must equal the resulting
  committed lifecycle value. The semantic close ID is `SHA256("ARC-MLS/1
  close authorization id" || encoded_ArcCloseAuthorizationTBS)`; approval
  subsets do not alter it."

The rule, in the shared crate:

- The context core of a binding is bootstrap-pending exactly when the
  binding has generation zero, at every semantic incarnation
  (`context::verify_context_core`); a binding of generation one or later, a
  ReInit successor, is never bootstrap-pending.
- `initial_authority::PriorTerminal` is the terminal of one closed
  incarnation: the close that ended it, the binding and conversation it
  closed, and that binding's semantic route. Only
  `HistoricalChain::prior_terminal` produces one, from a validated chain
  whose lineage a close ended; a chain that is open, closing, or ended by a
  ReInit activation has none. A chain adopts a close only through
  `HistoricalChain::close`, which requires the close to name the chain's
  network, conversation and binding, to reference the finalization of the
  exact active-to-closing transition at the chain's head, to carry the
  committed close intent, and to carry approvals that satisfy the last
  finalized policy's controller rule. A holder of retained state resumes
  the chain at its closing state (`HistoricalChain::resume`, which trusts
  that state as it trusts every resumed anchor) and adopts the exact
  retained close the same way. There is no other constructor: a close
  that no chain adopted, however well formed, yields no terminal.
- `authenticate_initial_authority` keeps accepting only incarnation zero.
  `authenticate_recreated_authority` takes the generation-zero binding of a
  later incarnation with a `PriorTerminal`, and admits it only when the
  binding's semantic route has the terminal's route key, the incarnation
  after the terminal's, and the terminal's close ID, on the same network, in
  another conversation (`PriorTerminal::precedes`). Every other check of a
  genesis binding applies unchanged: unanimous approvals, root locks, the
  pinned roots and rosters, the context core, the bootstrap policy and the
  sequencer credential. The returned authority carries the terminal.
- `HistoricalChain::open` opens a binding at incarnation zero without a
  terminal, and a binding at a later incarnation only when its authority
  carries the terminal of the incarnation before it on this network. The
  recreated chain starts bootstrap-pending at its genesis anchor, like any
  genesis.

So no next incarnation opens while the one before it is live or closing,
or after a close its controllers never approved: the recreated route's
own binding, signed by every binding-authorized device of its principals
and root-locked, pins the close ID, and the terminal it is checked against
comes only from a chain that verified that close.

### Tests

`crates/agenc-relay-e2ee/tests/history/recreation.rs`, with real
signatures, closing a channel lineage after its bootstrap:

| Test | What it pins |
| --- | --- |
| `a_closed_route_reopens_at_its_next_incarnation_and_operates` | The closed chain's terminal and the one a chain resumed at the retained closing state yields after adopting the exact retained close agree; the next incarnation's authority carries it; the chain opens bootstrap-pending at its genesis anchor, under this network only, activates its bootstrap, finalizes a routine Commit, closes in turn, and its terminal opens incarnation two. |
| `a_recreated_route_needs_the_exact_close_of_the_incarnation_before_it` | Refused: a later incarnation without a terminal, with the close of another lineage of the same route key, a skipped incarnation, a repeated incarnation zero naming the close, a terminal given for an incarnation-zero genesis, and the closed conversation as its own next incarnation. |
| `only_a_closed_lineage_yields_a_prior_terminal` | A chain at its genesis anchor, one after its bootstrap activation and one after its closing transition have no terminal; a closed one has. |
| `an_unapproved_close_yields_no_terminal_for_a_next_incarnation` | A close that names no closing finalization and that no controller approved is refused by the live chain. It, the same close naming the head finalization, the controller's approval without its signature, and a close naming another binding are refused by the closing chain and by the chain resumed at its retained closing state, neither of which then yields a terminal; the exact close then yields the terminal that opens incarnation one. |

Also `tests::context::an_ordinary_group_bootstraps_at_every_incarnation_and_a_successor_does_not`:
at incarnation one, a generation-zero binding's core verifies only
bootstrap-pending and a generation-one binding's only not pending.

Revert proofs, each run over the whole e2ee crate (380 tests):

- the three start-commit gates restored together (the context core's
  incarnation-zero predicate, the genesis anchor's and `open`'s): 4 tests
  fail;
- each gate alone: 4, 3 and 1 tests fail;
- single edits: the anchor accepting any terminal (1), accepting a later
  incarnation without one (1), `open` accepting any terminal (1),
  `precedes` accepting the closed conversation (1), any network (1) or any
  later incarnation of the key (1), `prior_terminal` answering an unclosed
  lineage (2) or a closing one (2), and `HistoricalChain::close` adopting
  a close without checking its approvals (2).
- `open` accepting a later incarnation without a terminal passes: an
  authority without a terminal is refused at a later incarnation by its
  anchor check before `open` sees it, so that check of `open` is defence in
  depth, as its generation check is.

## The coordinator hosts the next incarnation (second commit)

The companion and architecture text this rule implements:

- Companion Section 9.4: `semantic_route_lock_id` is the hash of the
  complete `ArcSemanticRouteTBS`, which carries `semantic_incarnation` and
  `predecessor_close_id`; "A later incarnation increments by one and names
  the semantic close ID of the prior incarnation. Version 1 therefore
  permits only one live semantic direct conversation per account pair, and
  the fresh conversation nonce cannot manufacture a parallel lock slot."
- Companion Section 11.4: "A closed direct binding remains an encrypted
  tombstone until an explicitly approved new semantic generation is created
  and never silently falls back to plaintext."
- Companion Section 11.3: "Authorized `CLOSE` leaves an encrypted-only
  tombstone until that exact channel instance is destroyed", and Section
  11.5: "only one binding may win for the same channel instance or
  direct-conversation generation".
- Companion Sections 13.7.1 and 13.7.5: a route a restore closes "never
  returns to `normal`", and `closed` and `conflict` "never transition
  again".
- Architecture Section 18.1: "Binding is one-way for an existing
  `ChannelInstanceId`."

The rule:

- Each incarnation of a semantic route has its own semantic lock, because
  the lock hashes the incarnation and the close it names; the incarnations
  of one route share the lock of its incarnation zero
  (`SemanticRoute::lineage_lock_id` in the shared crate). The route table
  (`crates/agenc-relay-domain/src/e2ee/route_table.rs`) records it as each
  entry's and each binding summary's `lineage`, keeps each incarnation's lock
  slot by its own lock, and indexes each lineage's newest incarnation.
- `RouteTable::bind` admits a generation-zero binding by the newest
  incarnation of its lineage (`check_lock_slot`): with none, only
  incarnation zero opens the route, under the lock that is its lineage; a
  live, closing or recovery-gated newest incarnation keeps the route, so a
  second binding is a fork (`E2EE_GROUP_CONFLICT`); after its authorized
  close only the next incarnation, naming that close, follows it, and a
  wrong close, a skipped incarnation or a replay of the closed incarnation
  is no successor (`E2EE_BINDING_AUTH_INVALID`). A second binding under a
  held lock is one of those cases, and a binding its lineage would admit
  is still a fork while another binding holds its lock slot, whatever the
  lineage index names: a fresh conversation nonce or channel instance
  never manufactures a parallel lock slot.
- `RouteTable::reserve_direct` reserves a pair again when the pair's newest
  route is a tombstone of an authorized close (`RouteEntry::authorized_close`),
  still only for the smaller account and one reservation at a time; a live,
  closing or recovery-gated route keeps the pair. A tombstoned channel
  instance stays bound to its lineage and takes no reservation: the next
  incarnation of a channel route binds a fresh instance of that route.
- A tombstone that a recovery gate installed (`closed`) frees nothing, and
  the recovery admission keeps refusing a reservation of a pair whose route
  is not `normal`.
- `RouteTable::destroy_channel_instance` frees the destroyed instance but
  keeps its closed route as the terminal of the lineage, so a fresh instance
  of the route binds only the next incarnation and never incarnation zero
  again.
- `EGROUP BIND` passes the lineage the shared crate computes
  (`ops::route::binding_summary`), and a ReInit successor takes its
  predecessor's lineage with its lock and incarnation
  (`RouteTable::install_successor`).
- `EGROUP CLOSE` now writes the close an incarnation follows into its
  tombstone row, as every other route row does.
- Startup takes each route's incarnation, the close it follows and its
  lineage from its retained binding's semantic route, as `BIND` took them,
  and a route row naming another lock or another close restores nothing, so
  startup refuses the store (`startup::restored_semantics`).
  `RouteTable::restore_entry` gives each of its target, lock and lineage
  indexes to the newest route, whatever the order of the restore: a later
  incarnation, then a later binding generation, then a route that is not a
  tombstone. `RouteTable::select_restored_successor`, which startup runs
  once every route has loaded to reselect each ReInit successor over its
  predecessor, takes indexes by the same rule (`take_indexes`), so a
  successor that a close later ended stays behind the route's next
  incarnation. A restart therefore indexes what the live path did.
- An edge projects routes and binds none: its copy keys each projected lock
  as its own lineage, and its pair index prefers a route that is not a
  tombstone, so its plaintext refusal for a live direct binding
  (`E2eeEdge::direct_pair_bound`) follows the live incarnation.

### Readings recorded for the owner

- A channel route's next incarnation binds a fresh channel instance
  (companion 11.3 and 11.5, architecture 18.1). The daemon's base profile
  keeps an encrypted channel registered and refuses `CHANCTL UNREGISTER` of
  a bound channel, so in this release a closed encrypted channel's name is
  never freed for a fresh instance: a channel route's next incarnation is
  reachable at the coordinator, as its tests drive it, but not through the
  daemon's channel lifecycle. Whether a tombstoned instance may instead bind
  the next incarnation in place is the owner's decision.
- A route that a restore closed (`closed`) keeps its pair or route
  reserved: Sections 13.7.1 and 13.7.5 make that state final, and the next
  incarnation needs the companion-valid close a restore installed. Whether
  such a close frees the route for the next incarnation is asked of the
  owner; this topic keeps the start commit's refusal.
- A route the previous profile's ReInit retired has no close, so no next
  incarnation can name one (the ReInit enforcement record left this to this
  item); it stays retired.

### Tests

`crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/recreated_routes.rs`
drives the coordinator's handlers, with restarts that rebuild the
coordinator from every stored row:

| Test | What it pins |
| --- | --- |
| `a_closed_channel_route_binds_its_next_incarnation_on_a_fresh_instance` | After a close and a restart, the closed instance takes no reservation; incarnation one binds on a fresh instance under its own lock in the lineage of incarnation zero, its row naming the close; its application waits for the bootstrap activation, then flows, and a routine Commit finalizes, live and after a restart; it closes in turn and, after a restart, incarnation two binds naming the later close but not the earlier one, and restores at incarnation two. |
| `a_recreated_channel_route_keeps_every_refusal` | While incarnation zero is live, incarnation one is a fork (`E2EE_GROUP_CONFLICT`); a replayed close is `E2EE_ROUTE_INVALID`; a wrong close, a skipped incarnation, incarnation zero again and a later incarnation naming no close are `E2EE_BINDING_AUTH_INVALID`; once incarnation one is bound, another group naming the same close is a fork. |
| `a_closed_direct_pair_is_reserved_and_bound_again` | A live direct pair takes no other reservation; after its close and a restart the smaller account reserves it again and binds incarnation one, refused under a wrong close and as incarnation zero again; `EGROUP QUERY DIRECT` answers the new incarnation, which operates and keeps the pair; a restart restores both incarnations and indexes the live one, which carries traffic while the closed one refuses it. |
| `a_recreated_direct_pair_restarts_through_the_sealed_store` | The same pair, its rows sealed into a storage fixture and read back as a restart reads them, restores both incarnations, indexes the live one, carries a Commit and keeps the pair. |
| `row_mismatch::a_route_row_naming_another_lock_or_close_than_its_binding_refuses_startup` | A restart refuses the store when incarnation one's route row names another lock, another close or no close, or when the closed incarnation zero's row names another lock or a close: startup takes a route's semantics from its binding. |

And `tests/sequence/reinit/successor/recreated.rs`:
`a_closed_successors_next_incarnation_stays_current_across_a_restart`
migrates a channel route by ReInit, closes the successor by `EGROUP CLOSE`
and binds incarnation one on a fresh instance naming that close; a restart
restores the route table exactly as the live path left it, every index
included, and a second incarnation one naming the same close is
`E2EE_GROUP_CONFLICT` before and after the restart.

In the domain crate's route table tests:
`lock_slots_refuse_forks_and_admit_only_the_next_incarnation` (pinned,
`domain-lock-slots`) now gives each incarnation its own lock, as the
semantic lock hashes the incarnation and the close; it adds the next
incarnation refused as a fork while the first is live, a skipped
incarnation, the next incarnation bound once and holding the route, and
incarnation zero refused outside its own lineage.
`destroying_an_instance_removes_only_its_tombstone` (pinned,
`domain-tombstones`) now also pins the closed route kept as the lineage's
terminal after its instance is destroyed. New:
`a_closed_direct_pair_is_reserved_again_for_its_next_incarnation`,
`a_tombstone_a_recovery_gate_installed_frees_no_route`,
`a_restore_in_any_order_indexes_the_newest_route`,
`a_held_lock_slot_admits_no_second_binding_whatever_the_lineage_index`
and, in the successor tests,
`a_restored_successor_leaves_a_later_incarnation_its_indexes`: a route
migrated by ReInit, its successor closed and its next incarnation bound,
restored in every order and reselected, equals the live table and
refuses the same fork and reservation; and
`removing_a_projection_releases_only_its_own_target_and_lock_indexes`
now also requires the lineage index released.

Revert proofs: with the start commit's keying restored (a pair kept by any
route, and the lineage looked up by the binding's own lock), the six
coordinator tests and five domain tests fail. Twenty-one single edits each
fail a test: a pair kept by its closed route; a recovery-installed close
freeing the route; the next incarnation admitted under any close or any
later incarnation; a live newest incarnation not a fork; incarnation zero
opening outside its own lineage; a binding not indexing its lineage; a
binding admitted into a lock slot another binding holds; the restore
ranking without the incarnation or without liveness, or letting the last
entry restored win; a restored ReInit successor's reselection taking
every index again; a destroyed instance's route forgotten; `EGROUP BIND`
passing the binding's own lock as its lineage; the tombstone row forgetting
the close it follows; startup taking the incarnation from the row, the
lock as the lineage, any row, or a row naming another lock; and the model
without `Recreate` or with the recreated binding's own lock as its
lineage. Through the handlers, the reselection edit is masked by the
recovery gates' re-restore of every route at startup, which ranks entries
too: with that re-restore limited to gated routes, the ReInit test fails
under the reselection edit and passes under this commit's rules, so a
restart no longer depends on that re-restore.

### Stage 08 evidence (G-07)

The second commit touches `crates/agenc-relay-domain/src/e2ee/route_table.rs`
and two pinned Stage 08 tests, whose names are kept. A recreated route is a
new phase that only an action recreating a closed route reaches, so the
bounded model (`crates/agenc-relay-testkit/src/e2ee_model.rs`) gains
`Recreate`: it reserves a fresh channel instance and binds the closed
conversation's next incarnation there, under that incarnation's lock in
the lineage of incarnation zero, naming the close. Each conversation slot
then holds its newest incarnation, whose identifiers equal the earlier
ones at incarnation zero. The adversarial `Reopen`, a second binding under
the closed lock, stays refused everywhere. The counts of
`conformance/stage-eight-model.toml`:

| Count | Before | After | Why |
| --- | ---: | ---: | --- |
| actions | 30 | 32 | one `Recreate` per conversation |
| states | 57 | 58 | the one recreated state within the depth: `Reserve(0)`, `Bind(0, 0)`, `Candidate(0)`, `Finalize(0)`, `Close(0)`, `Recreate(0)`; conversation 1 closes only at the depth bound, because the explorer's state key counts reservations rather than naming them, so its lifecycle starts after `Reserve(0)` |
| transitions | 144 | 145 | that `Recreate` |
| paths | 26 | 27 | the new state, a leaf at the depth bound |
| refusals | 786 | 847 | the two `Recreate` actions are offered in each of the 31 states below the bound and refused in all but one (62 offers, 1 accepted) |

The model also gains `replay_e2ee`, which replays one action sequence from
the empty world past the explorer's depth, checking every invariant after
each action as the explorer does, and the model test
`a_recreated_route_operates_closes_and_recreates_past_the_explored_depth`
replays a recreated route through its bootstrap, application traffic, a
routine Commit and an abort, with the duplicate, conflicting, reordered
and stale records and plaintext refused, then its close and a second
recreation; `Recreate` is refused while the route is live and `Reopen`
throughout. No count changes.

The evidence that changed, by the transcript catalog's gates (those of the
TODO catalog):

| Evidence | Transcript row and gate | Stage 08 tasks |
| --- | --- | --- |
| `lock_slots_refuse_forks_and_admit_only_the_next_incarnation`, rewritten with a lock per incarnation | `domain-lock-slots`, gate 21 | S08-004, S08-037 |
| `destroying_an_instance_removes_only_its_tombstone`, the closed route kept as its lineage's terminal | `domain-tombstones`, gate 4 | S08-004, S08-021 |
| the model's `Recreate` action, its counts and the replay of a recreated route past the explored depth | `model-exhaustive` (gates 7, 22), `model-adversarial` (gate 7) | S08-024, S08-038 |
| the coordinator tests above (no transcript row) | none | S08-004, S08-037 |

No box changes.
