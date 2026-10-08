# A deleted origin's journal row names what its deletion named (D-41)

This record covers the origin journal topic of decision D-41 of the SDK
server program (2026-10-07, outside master #35): a deleted origin's journal
row names the generation and next sequence its deletion named, so an edge
that restarts before the deletion's acknowledgement is durable replays the
deletion its live link sent. The first commit makes the edge's journal row
of a deleted origin hold exactly what its `FORIGIN DEL` names, and removes
the row of an update no link carried in the batch that writes it.
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
