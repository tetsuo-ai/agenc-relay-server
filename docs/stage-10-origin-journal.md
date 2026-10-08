# A deleted origin's journal row names what its deletion named (D-41)

This record covers the origin journal topic of decision D-41 of the SDK
server program (2026-10-07, outside master #35): a deleted origin's journal
row names the generation and next sequence its deletion named, so an edge
that restarts before the deletion's acknowledgement is durable replays the
deletion its live link sent. The first commit makes the edge's journal row
of a deleted origin hold exactly what its `FORIGIN DEL` names, and removes
the row of an update no link carried in the batch that writes it.
The second decides how rows written before this rule restore (G-08):
additive within storage generation 5, with the coordinator taking a
deletion of an origin it already deleted that names the next generation at
sequence zero, an update it never committed, as the deletion it committed.
No specification, profile hash, registry entry, named limit, reply code,
wire object, table, key, row kind, field or storage generation changed.

The architecture text these rules implement:

- Section 20.5: a session registration or another replacement of the
  connection's security principal "increments the origin generation and
  resets its operation sequence to zero only after an acknowledged
  `FORIGIN UPDATE`".
- Section 20.7: "`UPDATE` increments by one and names the exact previous
  object", and "RESET fences all live execution from that edge until it has
  replayed each origin and receives READY. DEL is durable, permanently
  rejects later requests, and retains the stated next sequence for replay
  checking."
- Section 23, the `federation_origin` table: keyed by
  "peer/incarnation/origin/generation", it holds the "origin, next
  sequence, and edge pending-DEL/`sink_gone` state".

[The origin deletion record](stage-10-origin-deletion.md) (fourth commit)
makes the base deletion name a pending update only once a link carried it,
with the record that the update went out kept in memory
(`ConnectionOrigin::update_sent`). This topic keeps that rule and makes the
journal agree with it.

## The deleted origin's row names its deletion (first commit)

The rule, in `crates/agenc-relay-runtime/src/federation/edge/mod.rs` and
`journal.rs`:

- What a deletion names is decided in one place,
  `ConnectionOrigin::deletion_point`: the first pending update's generation
  at sequence zero once a link carried that update ahead of the deletion,
  and otherwise the held generation with its next operation sequence.
  `send_origin_del` sends it, as before.
- The journal row of a deleted origin holds that pair and the declaration at
  that generation (`journal::row_declaration`): the carried update, or the
  declaration the coordinator holds at the held generation, never an update
  no link carried. The row is stored under that generation, as every origin
  row is. A live origin's row is unchanged: its first pending update at
  sequence zero, durable before any link carries it, or else its current
  declaration with its next operation sequence.
- A connection's session and account move to a new principal before its
  update is queued, so the origin keeps, in memory, the principal of its
  held generation (`ConnectionOrigin::held_principal`): unregistered at
  generation zero, the update's own at each acknowledged update, and the
  restored row's after a restart. The declaration at the held generation is
  rebuilt from it, so the row holds the exact object the coordinator
  acknowledged.
- A restart restores an origin from its highest stored generation. When a
  deleted origin's row moves below the row the journal last made durable,
  which is the row of an update no link carried, that row is removed in the
  batch that writes the deletion's row (`journal::superseded_row`), so a
  restart restores the deletion's row.
- Whether the update was carried survives a restart without a new field:
  the deleted row names the carried update's generation at sequence zero,
  or the held generation with its next sequence, and a restored origin
  replays the deletion its row names.

`crates/agenc-relay-runtime/src/federation/edge/tests/origin_deletion/stored_rows.rs`
drives the real `EdgeFederation` over a live link queue and real storage;
the store-reload tests stop the storage owner, reopen the same directory as
a restarted process does (`StateCoreFixture::restart_registration_storage`)
and restore a fresh edge from it (`restore_edge_state`):

| Test | What it pins |
| --- | --- |
| `a_deletion_whose_update_no_link_carried_is_stored_at_the_acknowledged_generation` | An origin deleted while the update its registration queued waits for its journal write: the live deletion names generation zero at the three executed requests; the row holds the acknowledged object at that sequence, deleted with its deletion pending, and is the origin's only row, the update's row having gone with the batch that wrote it. After a store reload the restored origin holds that generation, sequence and object, rewrites the same row, and replays the same deletion. |
| `a_deletion_naming_the_carried_update_is_stored_at_its_generation` | An origin whose update the link carried before its deletion: the deletion names generation one at sequence zero, the row holds the update's object there, and after a store reload the restored origin replays the same deletion. |
| `a_deletion_after_an_acknowledged_update_is_stored_at_that_generation` | Once the first update is acknowledged, a second update no link carried is pending when the origin is deleted: the deletion and the row name generation one at sequence zero with the object the coordinator acknowledged, the second update's row is gone, and after a store reload the same deletion is replayed. |
| `a_restarted_deletion_names_what_the_first_one_did` | The coordinator's origin table commits the live deletion at generation zero; an edge restored from the journal row, under the key of the generation the row names, replays a deletion naming the same generation and sequence, which the table, ready again with the origin already deleted, accepts. |

With `journal.rs`, `mod.rs`, `request.rs` and the history test fixture set
back to the start commit `4313f32`, the first, third and fourth tests fail
and the second passes. Single edits fail tests as well:

- a deleted origin's row naming its first pending update whether or not a
  link carried it fails the first, third and fourth;
- building the held declaration from the connection's current session and
  account fails the same three and
  `origin_deletion::a_deletion_names_the_acknowledged_generation_until_the_update_is_sent`;
- keeping the superseded row fails the first and third;
- leaving the held principal unchanged when an update is acknowledged fails
  the third and
  `an_origin_closed_while_the_link_is_down_is_replayed_and_deleted_after_the_reset`;
- restoring an origin with no held principal, so that the restored origin
  rewrites its row with another object, fails the second and third;
- naming a deleted origin's pending update in its deletion and its row
  whether or not a link carried it fails the first, third and fourth and
  `a_deletion_names_the_acknowledged_generation_until_the_update_is_sent`
  and `a_deletion_after_an_acknowledged_update_names_that_generation`.

## Rows written before this rule (G-08, second commit)

The decision is additive within storage generation 5 (decision D-06). No
table, key, row kind, field or object layout changes, and startup reads
origin rows exactly as before: an origin is restored from its highest
stored generation, and a deleted row's generation and next sequence are
the deletion it replays. What changes is which generation and next sequence
a deleted origin's row holds, and that the edge removes the row of an
update no link carried.

A row written before this rule for an origin deleted while an update no
link carried was pending is a deleted row at that update's generation,
naming sequence zero, with the update's object; the row of the held
generation stays beside it, live. For an origin whose update a link carried,
the deleted row is the one this rule writes. The two cannot be told apart
from the rows, since whether the update went out was kept only in memory,
so such a row is not reinterpreted: a restored edge replays the deletion it
names, the update's generation at sequence zero. The coordinator then holds
one of three states, and accepts that deletion in each:

- The origin is not deleted, because no deletion reached it: the edge's
  RESET suspends the origin, READY waits for its replay, and the deletion
  comes during the reset, which closes the origin at the generation the
  coordinator holds after everything it executed there (unchanged).
- The origin is deleted at the update's generation at sequence zero,
  because a link carried the update and then the deletion: it is the exact
  deletion (unchanged).
- The origin is deleted at the generation it holds with its next sequence,
  because the live link's deletion named it: the coordinator is ready at the
  edge's RESET, since every origin it holds for the edge may be deleted, and
  the deletion names the next generation at sequence zero. This commit's
  rule takes it as the deletion already committed.

The rule, in `crates/agenc-relay-domain/src/federation/origin.rs`
(`OriginTable::delete`, `repeats_deletion`):

- For an origin the coordinator already deleted, on a ready link, a
  deletion naming exactly the generation and stated next sequence it holds
  is accepted, as before, and so now is one naming the next generation at
  sequence zero.
- That generation is an update the coordinator never committed: the origin
  was deleted at the generation it holds, and an update of a deleted origin
  is refused. No operation ran under it, since a generation's sequence
  begins only after its acknowledged `FORIGIN UPDATE` (Section 20.5), so
  the deletion names nothing the committed one does not: the origin ends
  after everything executed under the generation the coordinator holds.
- Nothing changes: the generation, the stated next sequence the deletion
  retains for replay checking (Section 20.7) and the origin's row stay as
  they were. The coordinator acknowledges the deletion at the generation it
  names, which the edge's deletion acknowledgement check accepts
  (`ConnectionOrigin::deletion_acknowledged_at`), so the edge retires the
  origin once the acknowledgement is durable.
- Every other deletion of an already deleted origin on a ready link is
  refused as before, a later generation, the next one at another sequence
  and the held one at another sequence alike; during a reset any deletion of
  the origin is accepted, as before. The runtime's `delete` in
  `crates/agenc-relay-runtime/src/federation/coordinator/origin.rs` is
  unchanged.

The same form also reaches the coordinator from an edge running this rule.
When the link that carried an update closes before the coordinator reads
the update, the next link replays the deletion naming that update, which
the coordinator takes during the reset at the generation it holds; a
deletion the edge replays on a later link, once the coordinator is ready
again, names the update again. And when an edge stops without deleting an
origin whose update is pending, the origin's live row is that update's, at
sequence zero, written before any link carried it; a restart restores the
origin as deleted there, and its deletion names the update whether or not a
link carried it (`a_live_row_of_a_pending_update_restores_to_an_edge_that_converges`).

Downgrade: an earlier release reads rows this rule wrote as it reads its
own, since the deleted row names what the deletion named and the removed
row is one that release would have restored in its place. Upgrade: an edge
restored from a row written before this rule needs a coordinator with this
rule, so the operator guide now says to upgrade and start the coordinator
before any edge, whether or not the edge has the encrypted profile enabled
(`Upgrade order`).

| Test | What it pins |
| --- | --- |
| `federation::edge::tests::origin_deletion::stored_rows::a_store_written_before_this_rule_restores_to_an_edge_that_converges` | The rows of `deleted-unsent-update.rows`, sealed into real storage: the restored origin replays the deletion of generation one at sequence zero, and the coordinator's origin table accepts it whether it holds the origin deleted at generation zero after the executed requests, deleted at the update, or not deleted; the acknowledgement at generation one retires the origin once it is durable, a later link replays nothing, and a later restart restores nothing. |
| `federation::edge::tests::origin_deletion::stored_rows::a_live_row_of_a_pending_update_restores_to_an_edge_that_converges` | The rows of `live-pending-update.rows`: the origin is restored as deleted at the update's generation, writes its row again as the deletion's, then replays the deletion of generation one at sequence zero, which the coordinator accepts in each of the same three states; the origin retires as above. |
| `federation::coordinator::tests::deleted_origins::a_deletion_naming_the_update_a_deleted_origin_never_committed_is_acknowledged` | Through the coordinator's actor loop and real storage: an origin deleted at generation zero after one request, the link lost before the acknowledgement and the next link ready at its RESET; a deletion naming generation one at sequence zero is acknowledged at generation one, the exact deletion is still acknowledged after it, and the link keeps serving the edge. |
| `federation::coordinator::tests::deleted_origins::any_other_deletion_of_a_deleted_origin_still_closes_the_link` | The same origin: a deletion naming generation one at sequence one, generation two at sequence zero, or generation zero at sequence two or zero closes the link. |
| `federation::origin::tests::a_deletion_naming_the_update_a_deleted_origin_never_committed_is_already_committed` (`agenc-relay-domain`) | The origin table accepts the next generation at sequence zero for a deleted origin and changes nothing, refuses every other form, keeps requiring the exact generation of an origin that is not deleted, and holds the rule again once ready after a reset; for an origin deleted at a committed update, it is the generation after that update. |

The restore tests seal the rows of `test-data/stage-ten/origin-journal/`,
which the edge journal at `4313f32` wrote: a test-only generator, added to
an export of that commit and recorded with its command in the directory's
README, ran the `bound` fixture of the origin deletion tests and wrote out
every `federation_origin` row the journal made durable; separate runs wrote
identical files. `deleted-unsent-update.rows` holds an origin deleted while
an update no link carried was pending, and `live-pending-update.rows` the
same origin with the update's row written and its connection still open.
Each holds the deleted or live row of the update, at generation one and
sequence zero, exactly as that journal wrote it, and the generation-zero
row its admission wrote, which a restore reads and then shadows with the
higher generation. The journal's row logic is the same from release
candidate 3 (`70c832c`) to `4313f32`: its `journal.rs` differs only by two
struct-field initialisers that the origin row does not read, so that
release writes the same rows.

With the domain's `origin.rs` set back to the start commit `4313f32`, both
restore tests, the coordinator acknowledgement test and the domain test
fail. Single edits fail tests as well:

- naming the generation after the next one instead of the next one fails
  those four and the coordinator's closing test;
- accepting the next generation at any sequence fails the closing test and
  the domain test;
- accepting any later generation at sequence zero fails the same two;
- keeping only the exact form fails both restore tests, the acknowledgement
  test and the domain test.

## Coverage

The first commit moves the reviewed region `edge-origin-deletion-generation`
from `send_origin_del` in the edge's `request.rs` to
`ConnectionOrigin::deletion_point` in its `mod.rs`, where the decision now
is, re-reviewed with a reason that names the journal row, and adds
`edge-origin-journal-row` (`journal::row_declaration`) and
`edge-origin-journal-superseded-row` (`journal::superseded_row`), both
persistence recovery regions scored by branches. The `cap13-mod-*` regions
of `mod.rs` and the other regions of `request.rs` move with their spans
unchanged. Both source inventories are refreshed.

The second adds `origin-table-deleted-origin-deletion`
(`repeats_deletion` in the domain's `origin.rs`), an authorization decision
scored by branches, and refreshes both source inventories.

## Validation

Each commit, Rust 1.98.0, from the worktree root: `cargo fmt --all
--check`, `cargo clippy --workspace --all-targets --all-features --locked
-- -D warnings`, `python3 scripts/check-coverage.py audit` on both policies,
`git diff --cached --check` and the program's 59-command fast gate on the
staged tree, which includes `python3 scripts/check-source.py check`: exit 0.
The runtime library run is `cargo nextest run -p agenc-relay-runtime --lib
--all-features --locked --no-fail-fast -E 'not test(/offline::tests::/)'`;
the ten excluded `offline::tests` fail on this host's root file system,
which is below its storage reserve, at every revision.

First commit: the runtime library run passes 2,815 of 2,815. The revert
proof and single edits above ran the runtime library's federation tests on
the topic's final tree, where every one fails a test and none fails to
compile.

Second commit: the runtime library run passes 2,819 of 2,819 and `cargo
nextest run -p agenc-relay-domain --all-features --locked --no-fail-fast`
passes 261 of 261. The revert proof and single edits above ran the runtime
library's federation tests and the domain's origin tests on the topic's
final tree, where every one fails a test and none fails to compile. The
generator of `test-data/stage-ten/origin-journal/` ran twice at `4313f32`
and wrote identical files.
