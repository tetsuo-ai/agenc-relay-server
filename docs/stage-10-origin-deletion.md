# Origin deletions name the generation the coordinator holds (D-37)

This record covers decision D-37 of the SDK server program (2026-10-07,
outside master #35): each origin deletion an edge sends names the generation
the coordinator holds for that origin and the edge's next unused sequence
under it, and the coordinator fences the origin at that sequence; a request
that a new link carries again is classified against the coordinator's replay
rows. The first commit makes the companion `EORIGIN DEL` name the generation
of the last declaration its link carried, has the coordinator fence a
companion origin at the next unused sequence the edge states, and releases
an ended connection's companion state whether or not a deletion is sent. The
second has the coordinator assemble and classify again, against its replay
rows, a request object that a closed link carried. No specification, profile
hash, registry entry, named limit, reply code, wire object, table, key, row
kind, field or storage generation changed.

## The companion deletion names the last declared generation (first commit)

The companion text this rule implements, Section 12.5:

- "DEL uses the same base fence and next companion operation sequence".
- "Within each ACKed Origin ID/generation, the first request operation
  sequence is zero and each new logical request increments it by one. An
  origin update resets the companion operation sequence to zero exactly as the
  base profile resets its own counter."
- "FORIGIN DEL carries the next base value and EORIGIN DEL the next companion
  value, and both fences must commit before the shared origin is fully
  retired."
- "`DEL` supplies the next unused sequence and permanently fences later
  requests."

Architecture Section 20.7 has the base DEL retain "the stated next sequence
for replay checking", and on a ready link the coordinator's base origin
table accepts a DEL at a next sequence no lower than its own
(`OriginTable::delete`).

The coordinator reads one link's frames in order, so when an `EORIGIN DEL`
arrives it holds the last declaration (`EORIGIN ADD` or `UPDATE`) the link
carried before it, whether or not that declaration's acknowledgement has
reached the edge.

The rule at the edge, in
`crates/agenc-relay-runtime/src/e2ee/edge/origins.rs`
(`E2eeEdge::delete_origin`):

- The deletion names the generation of the edge's last declaration on the live
  link (`LocalOrigin::declared`).
- Its next operation sequence is the edge's count of requests under that
  generation when the edge already sequences it (`LocalOrigin::sequenced`), as
  for a declaration replayed on a new link, and zero for a generation it does
  not sequence yet: requests wait until their generation is acknowledged
  (`router::settled`), so none travels under a declaration whose
  acknowledgement is outstanding.
- An origin whose declaration on the link is still unacknowledged is deleted
  too, so its companion fence commits beside the base one; an origin with no
  declaration on the live link sends nothing, since the link that carried its
  declaration is gone and the coordinator suspended it with that link.
- Whether or not it sends a deletion, a connection's end releases its
  companion state: its unanswered requests, its reply state and any open
  ingress assembly (`E2eeEdge::connection_closed`).

The rule at the coordinator, in
`crates/agenc-relay-runtime/src/e2ee/coordinator/sync.rs`
(`CompanionCoordinator::origin_del`):

- The deletion names the generation the coordinator holds, as before, and a
  next sequence at or above the next sequence executed there: the sequence the
  edge supplies is its next unused one, which counts every request the edge
  sent under that generation.
- The origin is fenced at the stated sequence, which a repeated deletion must
  not undercut; a lower sequence or another generation is refused.

`crates/agenc-relay-runtime/src/e2ee/edge/tests/origins.rs` drives the real
`E2eeEdge` and delivers every `EORIGIN` line it queues to the real companion
coordinator, through `e2ee::coordinator::tests::sync::edge_peer::EdgePeer`,
which answers with the coordinator's own frames or its refusal:

| Test | What it pins |
| --- | --- |
| `a_deletion_names_the_last_declared_generation` | Generation zero is declared and acknowledged; the coordinator accepts the declaration of generation one, whose acknowledgement the edge has not applied; the deletion names generation one at sequence zero, and the coordinator acknowledges it and fences the origin there. |
| `a_deletion_names_zero_under_a_generation_not_sequenced_yet` | Three requests ran under generation zero before generation one was declared; the deletion names generation one at sequence zero, where the coordinator fences the origin. |
| `a_replayed_declaration_is_deleted_at_its_counted_sequence` | Seven requests ran under generation zero; after the link is replaced the edge replays its declaration and the coordinator accepts it; before the replay's acknowledgement reaches the edge the deletion names generation zero at sequence seven, where the coordinator fences the origin. |
| `a_deletion_fences_at_the_sequence_the_edge_counted` | Seven requests executed under generation zero and the edge counted an eighth; after the replayed declaration is acknowledged the deletion names generation zero at sequence eight, where the coordinator fences the origin. |
| `an_origin_undeclared_on_the_live_link_sends_no_deletion` | A connection the companion never declared, and one whose declaration was carried by a link that is gone, send no deletion. |
| `an_ended_connection_releases_its_requests_without_a_live_declaration` | A connection with one unanswered request ends after the link that carried its declaration is gone: no deletion is sent and the request is released. |

`e2ee::coordinator::tests::sync::origin_refusals` pins the coordinator's
rule: `a_delete_must_name_the_accepted_generation_and_next_sequence` refuses
another generation and a sequence below the executed one, fences at a higher
stated sequence, and refuses a later deletion below that fence;
`a_delete_at_the_executed_sequence_fences_there` fences at the executed
sequence itself, and
`a_delete_naming_another_coordinator_or_a_stale_incarnation_is_refused`
fences nothing for a deletion addressed to another coordinator or naming an
incarnation that is not live. Two earlier coordinator tests that refused a
deletion above the executed sequence now refuse another generation, and a
sequence below the executed one, instead
(`origins_mirror_the_acked_base_declaration` and
`mailbox_query_origin_close_releases_only_after_the_exact_descriptor_passes`,
which still releases the mailbox cut only once the deletion is accepted).

With `origins.rs` set back to the parent `3294b73`, the first three edge
tests and the release test fail, and the other two pass. With the
coordinator's `sync.rs` set back to the parent,
`a_deletion_fences_at_the_sequence_the_edge_counted` and
`a_delete_must_name_the_accepted_generation_and_next_sequence` fail. Single
edits fail tests as well: naming the counted sequence under every generation
fails `a_deletion_names_zero_under_a_generation_not_sequenced_yet`; naming
zero under every generation fails
`a_replayed_declaration_is_deleted_at_its_counted_sequence` and
`a_deletion_fences_at_the_sequence_the_edge_counted`; naming the
acknowledged rather than the declared generation fails the first three edge
tests; leaving the fence at the executed sequence fails
`a_deletion_fences_at_the_sequence_the_edge_counted` and
`a_delete_must_name_the_accepted_generation_and_next_sequence`; and
accepting any sequence fails the latter.

## A request a new link carries again is classified against the replay rows (second commit)

The text this rule implements:

- Architecture Section 20.5: "an exact duplicate returns the stored result
  without re-execution".
- Companion Section 12.5: "Exact duplicates return the stored result", and
  "Link loss immediately fences execution from that link; reconnect must
  replay RESET and origin state before resuming."
- Companion Section 12.5, on a replaced link: "a partially or completely
  written frame is treated as unacknowledged and may be sent byte-for-byte
  after reconnect."
- Companion Section 16: "A byte-identical retry found in the idempotency cache
  returns the prior outcome without repeated fanout, KeyPackage consumption,
  or sequencing."

The coordinator's assembler keeps a recent-object cache (companion Section
11.8): on the link that carried a request, a byte-identical copy of its
completed object is answered from that request's replay row
(`CompanionCoordinator::replay_recent`), never run again. A request whose
object completed on a link that then closed has an outcome only if it ran
there.

The rule, in `crates/agenc-relay-runtime/src/e2ee/coordinator/mod.rs`
(`CompanionCoordinator::link_closed`) and
`crates/agenc-relay-e2ee/src/wire/assembly.rs`
(`E2eeAssembler::forget_recent`):

- When a link closes, the coordinator drops its peer's open payload waits,
  queued requests and open assemblies, as before, and now also forgets which
  of that peer's request and payload objects completed.
- A request the next link carries again, exactly as first sent, is therefore
  assembled and classified against the replay rows like any complete request
  (`request::classify`): an executed one returns its stored result without
  running again, and one that never ran runs at its sequence.
- Nothing else changes: on the link that carried it a copy before its answer
  is still a violation (`a_retransmitted_request_replays_its_stored_result`),
  and other peers' requests and the closed peer's origin declarations keep the
  cache's answer.

| Test | What it pins |
| --- | --- |
| `e2ee::coordinator::tests::sync::a_request_a_closed_link_left_unexecuted_assembles_again_on_the_next` | A request object completes on a link that closes before its payload arrives; the next link carries the request and its payload exactly as first sent, and the coordinator hands the complete request to its executor. |
| `e2ee::coordinator::tests::sync::a_closed_link_forgets_only_its_own_requests` | Another peer's request awaits the executor when the peer's link closes; that other peer's copy on its own link before an answer is still refused, and the closed peer's origin declaration keeps its cache entry. |
| `wire::assembly::tests::a_forgotten_recent_object_assembles_again` (`agenc-relay-e2ee`) | The assembler forgets only the submissions selected: a forgotten one assembles again and the others still answer as recent. |

With `link_closed` set back to the first commit, the first test fails.
Forgetting the closed peer's origin declarations too, or every peer's
requests, fails the second test; keeping the selected entries instead of
forgetting them fails the assembler test and both coordinator tests.

## Coverage

The release coverage policy gains `edge-companion-origin-deletion` (first
commit), the decision of what a companion deletion names (branches),
spanning the lines that decide it. The first commit also re-reviews and
respans `cap78-sync-origin-del`, whose reason now names the fence at the
stated sequence, and moves `edge-origin-attachment-settlement` in the edge's
`origins.rs` and the other regions of the coordinator's `sync.rs`, whose
spans are unchanged.

The second commit adds `companion-closed-link-request-classification`, what
a closed link drops and forgets (regions), and moves the regions of the
coordinator's `mod.rs` below it and the assembler's
`e2ee-assembly-error-arms`, whose spans are unchanged.

Both source inventories are refreshed in each commit.

## Validation

Each commit, Rust 1.98.0, from the worktree root: `cargo clippy --workspace
--all-targets --all-features --locked -- -D warnings`, the runtime library
run below, `python3 scripts/check-coverage.py audit` on both policies, `git
diff --cached --check` and the program's 59-command fast gate on the staged
tree, which includes `cargo fmt --all --check` and `python3
scripts/check-source.py check`: exit 0, except the fast gate's `cargo audit
--deny warnings`, which exits 1 at every revision, the parent's included, on
two advisories published after the base revision against a locked crate
outside the workspace build graph; the lockfile is unchanged. The runtime
library run is `cargo nextest run -p agenc-relay-runtime --lib
--all-features --locked --no-fail-fast -E 'not test(/offline::tests::/)'`;
the ten excluded `offline::tests` fail on this host's root file system,
which is below its storage reserve, at every revision.

First commit: the runtime library run passes 2,745 of 2,745. The revert
proofs and single-edit mutations above ran the edge and coordinator origin
tests of the runtime library.

Second commit: the runtime library run passes 2,747 of 2,747, and `cargo
nextest run -p agenc-relay-e2ee --all-features --locked --no-fail-fast`
passes 352 of 352. The revert proof and single edits above ran the
coordinator and assembler tests.

Not run here: the full stage-nine gate, which cannot finish on this host.
