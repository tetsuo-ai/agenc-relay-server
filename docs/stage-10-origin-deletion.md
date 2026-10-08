# Origin deletions name the generation the coordinator holds (D-37)

This record covers decision D-37 of the SDK server program (2026-10-07,
outside master #35): each origin deletion an edge sends names the generation
the coordinator holds for that origin and the edge's next unused sequence
under it, and the coordinator fences the origin at that sequence; a request
that a new link carries again is classified against the coordinator's replay
rows; and an origin's unanswered companion requests go out again once its
replayed declaration is acknowledged, each under the generation its origin
is acknowledged at. The first commit makes the companion `EORIGIN DEL` name
the generation of the last declaration its link carried, has the coordinator
fence a companion origin at the next unused sequence the edge states, and
releases an ended connection's companion state whether or not a deletion is
sent. The second has the coordinator assemble and classify again, against
its replay rows, a request object that a closed link carried. The third
resends an origin's unanswered requests when its replayed declaration is
acknowledged after `EORIGIN READY`, each only under the generation its
origin is acknowledged at. The fourth makes the base `FORIGIN DEL` name a
pending update only once a link carried it, also on a later link, and the
fifth adds a daemon test with a coordinator and two edges. No specification,
profile hash, registry entry, named limit, reply code, wire object, table,
key, row kind, field or storage generation changed.

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

Companion Section 11.8 has a duplicate content address use the recent-object
idempotency cache "rather than consuming a second reservation or causing
repeat fanout". Once a link closes, its peer's request entries leave that
cache, so a copy the next link carries reserves assembly once more, within
the same quotas and released on completion, and the replay rows supply the
prior outcome, so there is still no repeat fanout.

| Test | What it pins |
| --- | --- |
| `e2ee::coordinator::tests::sync::a_request_a_closed_link_left_unexecuted_assembles_again_on_the_next` | A request object completes on a link that closes before its payload arrives; the next link carries the request and its payload exactly as first sent, and the coordinator hands the complete request to its executor. |
| `e2ee::coordinator::tests::sync::a_closed_link_forgets_only_its_own_requests` | Another peer's request awaits the executor when the peer's link closes; that other peer's copy on its own link before an answer is still refused, and the closed peer's origin declaration keeps its cache entry. |
| `wire::assembly::tests::a_forgotten_recent_object_assembles_again` (`agenc-relay-e2ee`) | The assembler forgets only the submissions selected: a forgotten one assembles again and the others still answer as recent. |

With `link_closed` set back to the first commit, the first test fails, and
so do the third commit's tests of requests a closed link left unexecuted or
whose result it lost. Forgetting the closed peer's origin declarations too,
or every peer's requests, fails the second test; keeping the selected
entries instead of forgetting them fails the assembler test and both
coordinator tests.

## An origin acknowledged after READY resends its requests (third commit)

The companion text this rule implements, Section 12.5:

- "Link loss immediately fences execution from that link; reconnect must
  replay RESET and origin state before resuming."
- "EORIGIN RESET/READY never completes before the matching base origin set is
  ready."
- "Within each ACKed Origin ID/generation, the first request operation
  sequence is zero and each new logical request increments it by one."
- "Exact duplicates return the stored result".

The coordinator answers `EORIGIN RESET` with `EORIGIN READY` as soon as it
accepts the RESET while the base origin set is ready, and otherwise once
that set becomes ready (`CompanionCoordinator::origin_reset`,
`origins_ready`); it acknowledges the declarations the edge replays after
the RESET in link order. READY can therefore reach the edge before or after
the acknowledgement of a replayed declaration, and a newer declaration the
edge sends before READY reaches it is read by the coordinator before any
request the edge sends after READY.

The rule, in `crates/agenc-relay-runtime/src/e2ee/edge/origins.rs` and
`sync.rs`:

- At READY the edge resends, in operation sequence order, every unanswered
  request of each origin whose declaration on the link is acknowledged
  (`origins_ready`, `resend_order`), as before.
- An origin whose first acknowledgement on the link arrives after READY
  resends its unanswered requests with that acknowledgement, exactly as first
  sent and in operation sequence order: `acknowledge_origin` returns the
  connections one acknowledgement settles, and `origin_acked` resends only
  their requests (`unanswered_of`, `resend_pending`).
- An acknowledgement before READY resends nothing, since READY does, and a
  later acknowledgement on the same link resends nothing, since the origin's
  requests went out on that link already: `acknowledge_origin` settles a
  connection only when its declaration on the link was not yet acknowledged
  at that generation, so the same acknowledgement repeated settles nothing.
- A resume resends a request only while its origin's declaration on the link
  is acknowledged, so no newer declaration awaits its acknowledgement, and
  only under the generation its origin is acknowledged at
  (`PendingRequest::origin_generation`). A request named under an earlier
  generation is never resent: the coordinator holds the later generation and
  keeps no replay row for it, so the request gets no reply and stays pending
  until its connection ends, as the base profile holds a request whose origin
  update is pending (`origin_update_pending`).
- The coordinator answers a resent request that ran from its replay row and
  runs one that did not (second commit).

`crates/agenc-relay-runtime/src/e2ee/edge/tests/origins.rs` sends a real
`EKEY WHOAMI` through `E2eeEdge::client_line`, and for a request that
carries an object encodes it again under the same correlation with a
payload, then delivers what the edge queues to the real companion
coordinator, whose test peer (`EdgePeer::deliver`) classifies each complete
request as the executor does, commits a fresh one with its replay row and
stored result, and answers an executed one from them:

| Test | What it pins |
| --- | --- |
| `requests_resend_when_their_origin_is_acknowledged_after_ready` | The request went out under generation zero on a link that closed before the coordinator received it; on the next link the coordinator answers the RESET with READY before it acknowledges the replayed declaration. READY resends nothing, the acknowledgement resends the request as first sent, the coordinator runs it at sequence zero, and the deletion then names sequence one. |
| `requests_resend_once_when_ready_follows_the_acknowledgement` | The same request, with the base origin set not ready at the RESET: the acknowledgement resends nothing, READY resends the request once and the coordinator runs it; a later acknowledgement of generation one, one naming another origin and one naming a generation never declared resend nothing. |
| `a_request_left_unexecuted_runs_when_resent_after_ready` | A request the coordinator completed on the closed link but did not run (waiting for the executor, with or without a payload, or waiting for its payload): READY precedes the acknowledgement, which resends it as first sent, and the coordinator runs it once at sequence zero. |
| `a_request_left_unexecuted_runs_when_ready_follows_the_acknowledgement` | The same three requests when the acknowledgement precedes READY, which resends them. |
| `an_executed_request_resent_on_the_next_link_returns_its_stored_result` | A request that ran on the closed link, with and without a payload, in both orders: it is resent as first sent and the coordinator answers it once from its replay row without running it again. |
| `a_later_acknowledgement_resends_only_the_requests_of_the_origin_it_settles` | Two origins resume on one link; the first one's replayed declaration is acknowledged before READY, which resends its request, and the second one's after READY, whose acknowledgement resends only the second origin's request. |
| `a_repeated_acknowledgement_on_the_link_resends_nothing` | READY precedes the acknowledgement, which resends the request; the coordinator completes it without running it, and the same acknowledgement repeated on the link resends nothing. |
| `ready_resends_nothing_while_a_newer_declaration_awaits_its_acknowledgement` | The edge declares generation one after the replayed declaration of generation zero is acknowledged and before READY arrives: READY resends nothing, the acknowledgement of generation one resends nothing named under generation zero, and the connection's end releases the request and deletes the origin at generation one. |
| `a_superseded_generation_request_is_held_when_ready_precedes_the_acknowledgement` and `..._when_the_acknowledgement_precedes_ready` | The base generation advanced before the companion replays its origin, so the edge declares generation one on the new link: neither order resends the request named under generation zero, and the coordinator refuses nothing. |

`e2ee::edge::tests::unanswered_requests_are_resent_after_origin_ready` pins
the resend order across origins with each request named under its origin's
acknowledged generation.

Settling a connection at every acknowledgement that matches its declaration,
instead of only at the first one on the link, fails
`a_repeated_acknowledgement_on_the_link_resends_nothing`.

With the edge's `origins.rs` and `sync.rs` set back to the second commit,
`requests_resend_when_their_origin_is_acknowledged_after_ready`,
`a_request_left_unexecuted_runs_when_resent_after_ready`,
`an_executed_request_resent_on_the_next_link_returns_its_stored_result`,
`a_later_acknowledgement_resends_only_the_requests_of_the_origin_it_settles`
and
`a_superseded_generation_request_is_held_when_the_acknowledgement_precedes_ready`
fail; with the coordinator's `mod.rs` set back to the first commit, the
three tests of requests a closed link left unexecuted or whose result it
lost fail. Single edits fail tests as well: resending at an acknowledgement
before READY fails
`requests_resend_once_when_ready_follows_the_acknowledgement` and four
others; resending every connection's requests at an acknowledgement fails
`a_later_acknowledgement_resends_only_the_requests_of_the_origin_it_settles`;
dropping the requirement that the declaration on the link is acknowledged
fails
`ready_resends_nothing_while_a_newer_declaration_awaits_its_acknowledgement`;
and dropping the generation scope fails both superseded-generation tests and
two others.

## The base deletion names an update only once a link carried it (fourth commit)

The architecture text this rule implements:

- Section 20.5: a session registration or another replacement of the
  connection's security principal "increments the origin generation and resets
  its operation sequence to zero only after an acknowledged `FORIGIN UPDATE`".
- Section 20.7: "`UPDATE` increments by one and names the exact previous
  object", and "DEL is durable, permanently rejects later requests, and
  retains the stated next sequence for replay checking."
- Section 20.7: "RESET fences all live execution from that edge until it has
  replayed each origin and receives READY."

The coordinator's origin table is unchanged (`OriginTable::delete`). The
coordinator closes a session registered under an origin whose update it
never received through the committed registration (`registered_sessions`),
as before.

The rule, in `crates/agenc-relay-runtime/src/federation/edge/request.rs` and
`mod.rs`:

- A pending update goes out once its journal row is durable. The edge records
  in memory that the first pending update went out on a link
  (`ConnectionOrigin::update_sent`, set by `note_update_sent`) and clears that
  record only when the update is acknowledged and the next one becomes first.
  A link loss keeps it: a closed connection's origin replays only its
  deletion, never its update (`replay_origin`).
- `FORIGIN DEL` names that update's generation at sequence zero once a link
  carried it, and otherwise the acknowledged generation with its next
  operation sequence (`send_origin_del`), so a deletion replayed on a later
  link names what the first one did.
- The record is in memory; no journal row changes here. Since the origin
  journal topic, a deleted origin's journal row names the same generation
  and next sequence as its deletion, so a restored edge replays the
  deletion its live link sent ([the origin journal
  record](stage-10-origin-journal.md)).

`crates/agenc-relay-runtime/src/federation/edge/tests/origin_deletion.rs`
drives the real `EdgeFederation` over a live link queue and storage, and
applies the `UPDATE` and `DEL` frames it sends to the coordinator's origin
table, which holds generation zero after three requests:

| Test | What it pins |
| --- | --- |
| `a_deletion_names_the_acknowledged_generation_until_the_update_is_sent` | An origin whose pending update no link has carried declares nothing more and is deleted at the acknowledged generation zero and sequence three, which the table accepts. |
| `a_deletion_names_the_update_the_link_carried` | An origin whose pending update the link carried is deleted at that update's generation and sequence zero, which the table accepts after the update. |
| `a_deletion_after_an_acknowledged_update_names_that_generation` | Once the first update is acknowledged, a second pending update no link has carried leaves the deletion at the acknowledged generation one. |
| `a_relinked_deletion_names_the_update_the_first_link_carried` | The first link carries the update and the deletion and is lost before either acknowledgement arrives; the table turns ready again with the origin deleted, and the deletion the next link carries names the generation the first one did, which the table accepts. |

With `mod.rs`, `request.rs`, `journal.rs` and the history test fixture set
back to the third commit, the first and third tests fail; the second and
fourth pass there too. Single edits fail tests as well: naming a pending
update whether or not a link carried it fails the first and third;
forgetting the record when the link closes fails
`a_relinked_deletion_names_the_update_the_first_link_carried`; and keeping
it when the update is acknowledged fails
`a_deletion_after_an_acknowledged_update_names_that_generation`.

## A daemon test (fifth commit)

`crates/agenc-relay-server/tests/stage_eight_e2ee/origin_deletion.rs`,
`origin_deletions_name_the_generation_the_coordinator_holds`, runs the
production coordinator and two production edges of the Stage 08 network with
both profiles active. Guests, and clients authenticated as one account,
register on edge A and end their connections, which deletes their base and
companion origins; the test requires that the coordinator accepts every base
and companion origin deletion. Connections are paced under the Stage 08
new-connection rate and the logins stay within the account's OPAQUE attempt
burst; the test takes about 30 seconds. The unit tests of the first four
commits pin the rules deterministically.

With the first commit's edge rule reverted the test fails in 8 of 8 runs,
and with the fourth commit's in 8 of 8; with the whole series it passes in
16 of 16 runs, eight at a time, and in both workspace runs below.

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

The third adds `edge-origin-acknowledgement-resend`, the decision of which
acknowledgement resends which requests (branches), re-reviews and respans
`edge-origin-attachment-settlement`, whose function now returns the
connections an acknowledgement settles, and moves the three `cap74-sync-*`
regions of the edge's `sync.rs`, `cap74-mod-is-active`, the two regions of
`router.rs` and `edge-companion-origin-deletion`, whose spans are unchanged.

The fourth adds `edge-origin-deletion-generation`, the decision of what a
base deletion names (branches), and moves the seven `cap13-mod-*` regions of
the base edge's `mod.rs` and the five other regions of its `request.rs`,
whose spans are unchanged.

The sixth re-reviews and respans `edge-origin-attachment-settlement`, whose
function now settles a connection only at the first acknowledgement of its
declaration on the link, and moves `edge-companion-origin-deletion` and
`edge-origin-acknowledgement-resend`, whose spans are unchanged.

Both source inventories are refreshed in each commit.

A runtime branch report at the tip (`RUSTC_BOOTSTRAP=1 cargo llvm-cov
nextest -p agenc-relay-runtime --lib --all-features --branch --locked
--no-fail-fast -E 'not test(/offline::tests::/)'`, 2,761 of 2,761 pass)
scores every new or re-reviewed region in full:
`edge-companion-origin-deletion` 2/2 branches,
`companion-closed-link-request-classification` 23/23 regions,
`edge-origin-acknowledgement-resend` 2/2 and
`edge-origin-attachment-settlement` 10/10 branches, and
`edge-origin-deletion-generation` 2/2 branches. `cap78-sync-origin-del`
scores 39 of 40 regions, the uncovered one the unchanged `?` on rendering
the acknowledgement line, and `cap13-mod-link-closed` 33 of 34, the
uncovered one the unchanged early return for a link other than the live one.

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

Third commit: the runtime library run passes 2,756 of 2,756. The revert
proofs and single edits above ran the edge and coordinator tests of the
runtime library.

Fourth commit: the runtime library run passes 2,760 of 2,760. The revert
proof and single edits above ran the base edge tests of the runtime library.

Fifth commit: no production source changed, so the runtime library and both
coverage policies are as at the fourth commit. `cargo nextest run
--workspace --all-features --locked --no-fail-fast -E 'not
(test(/offline::tests::/) | test(/cli_provisioning/))'` passes 4,848 of
4,848 with 62 skipped, the daemon test among them in 34.1 seconds; the two
excluded Stage 08 `cli_provisioning` tests fail on the same file system at
every revision. A first run of the same command passed 4,847:
`state_core::tests::a_guest_session_registers_and_commands_flow_through_the_router`,
a load-dependent single-node test this series does not reach, failed once
there and passes alone in 5 of 5 runs. The daemon revert and repeat runs
above ran the test binary directly, eight at a time.

Sixth commit: the runtime library run passes 2,761 of 2,761, and the branch
report above scores the re-reviewed region in full. The single edit above
ran the edge tests of the runtime library.

Not run here: the full stage-nine gate, which cannot finish on this host.
