# One peer's refused or excess request never fails a federation link (D-41)

This record covers decision D-41 of the SDK server program (2026-10-07,
outside master #35): what one peer asks of the coordinator is refused for
that request, connection or origin alone, and never fails the federation
link that carries it. The first commit bounds the coordinator's
recent-object cache per peer, expires it at the companion idempotency
retention, releases an answered request's objects, keeps declarations out of
it, and answers a request that completes past its peer's ceiling with its
failed result. The second assembles an edge's coordinator deliveries outside
the recent-object cache and releases the coordinator's partial objects when
its link closes. The third refuses a base declaration naming a session or
account the coordinator removed for that origin alone. The fourth refuses a
companion declaration naming a device attachment another attachment of the
device superseded for that origin alone. No specification, profile hash,
registry entry, named limit, reply code, wire object, table, key, row kind,
field or storage generation changed.

## The coordinator's recent-object cache (first commit)

The companion text this rule implements:

- Section 11.8: a receiver reserves quota "against the connection, Account
  ID, route, federation peer, and process-global reassembly quotas", and
  "duplicate content addresses use the recent-object idempotency cache rather
  than consuming a second reservation or causing repeat fanout".
- Section 16: `RECENT_OBJECT_IDEMPOTENCY_RETENTION` is 30 minutes; "Admission
  may be refused before reservation"; "A byte-identical retry found in the
  idempotency cache returns the prior outcome without repeated fanout,
  KeyPackage consumption, or sequencing"; and "At the hard ceiling, new
  storage is refused fairly rather than evicting unexpired objects from a
  selected account."
- Section 12.5: "Every opcode permits `failed`. A failed result has
  `coordinator_state_generation=0`, an empty completion Event ID, empty
  snapshot token and next cursor, and zero response descriptors; it never
  consumes or partially commits the requested semantic mutation." The replay
  key maps each operation sequence "to one request ID and request-object
  hash", and "Exact duplicates return the stored result".
- Section 11.9: `E2EE_REASSEMBLY_LIMIT` is "Memory, object-count, or timeout
  limit reached".

The rules, in `crates/agenc-relay-e2ee/src/wire/assembly.rs` and
`crates/agenc-relay-runtime/src/e2ee/coordinator/`:

- **A ceiling per peer.** The coordinator's assembler bounds its
  recent-object cache per sender (`RecentCeiling::PerSender`), and every
  coordinator assembly's sender is the federation peer, so each peer has its
  own `MAX_RECENT_OBJECTS` completed objects, counting the slots its open
  submissions reserve. One peer's objects never take another peer's slots.
  The edge's client ingress keeps the shared ceiling
  (`RecentCeiling::Shared`, the default), which refuses a new submission
  before any reservation.
- **Expiry at the idempotency retention.** A completed object is retained
  until 30 minutes after its last fragment
  (`RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS`). The coordinator forgets
  every object whose window has ended before it ingests the next companion
  fragment, at most once a second (`CompanionCoordinator::expire_recent`,
  `E2eeAssembler::expire_recent`). Expiry leaves open assemblies to their own
  idle and absolute deadlines, which the assembler enforces at their next
  fragment.
- **A request past its peer's ceiling is refused for that request.** Past
  its peer's ceiling a request or payload object still assembles within its
  quotas, but keeps no recent tuple. The request is then answered with a
  failed result, `E2EE_REASSEMBLY_LIMIT`, which commits like every failed
  result: it consumes the request's operation sequence and commits no
  semantic mutation (`CompleteRequest::refusal`, `execute::run_with_object`).
  A later exact copy returns that stored result, and the link stays up.
- **An answered request releases its objects.** Once a request's batch
  commits, or its stored result is sent again, whether that result is held
  in memory or first read back from storage, its request and payload
  objects leave the cache (`CompanionCoordinator::request_answered`, from
  `batch_applied`, `companion::replayed` and `response_read::advance`): its
  replay row answers any later copy (12.5), which assembles again. A copy
  carried before the answer, on the link that carried the request, is still
  a violation.
- **A declaration holds no slot.** The origin table, not the cache, decides a
  repeated `EORIGIN ADD` or `UPDATE`: a declaration's completion is not kept,
  an identical declaration of the accepted state is acknowledged again, and
  any other one is checked anew (`CompanionCoordinator::origin_state`,
  `holds_declaration`, `redeclared`).
- A closed link still forgets its peer's request and payload objects
  (`CompanionCoordinator::link_closed`).

Sizing. A peer's objects stay in the cache only from completion to their
answer: requests queued behind a batch (`MAX_QUEUED_COMPANION_REQUESTS` per
peer), requests waiting for their payload, the request whose batch is in
flight, and a request whose stored result is being read back from storage,
until that result is sent. Declarations hold none. Sustained traffic at any
rate therefore holds far fewer objects than the per-peer ceiling, so the
ceiling never limits throughput: it bounds what one peer leaves unanswered,
and one peer cannot exhaust another peer's slots. An object a rarer path
leaves behind is forgotten when its window ends, or when its link closes.

| Test | What it pins |
| --- | --- |
| `wire::assembly::tests::a_per_sender_ceiling_assembles_past_it_without_a_recent_tuple` (`agenc-relay-e2ee`) | Under the per-sender ceiling an object past its sender's ceiling completes without a recent tuple or a reservation and assembles again; another sender keeps its own ceiling; the shared ceiling still refuses. |
| `wire::assembly::tests::an_open_submission_reserves_its_senders_slot` | The last slot of a sender goes to its first open object; a second open object completes without a tuple. |
| `wire::assembly::tests::expiring_recent_objects_releases_their_slots_and_keeps_open_assemblies` | Objects are forgotten exactly when their window ends, the sender's slots are released, and open assemblies are left alone. |
| `wire::assembly::tests::forgetting_one_object_releases_its_senders_slot` | `forget` and `forget_recent` release the sender's slots. |
| `e2ee::coordinator::tests::sync::recent_objects::a_request_past_its_peers_ceiling_is_refused_per_request` | With the peer's ceiling held by requests awaiting the executor, the next request, and one with a payload, complete with the `E2EE_REASSEMBLY_LIMIT` refusal, and another peer's request runs. |
| `e2ee::coordinator::tests::sync::recent_objects::completed_objects_are_forgotten_when_their_window_ends` | One second before the window ends the next request is still refused; when it ends the peer's slots are free, and the first request's copy assembles again. |
| `e2ee::coordinator::tests::sync::recent_objects::an_answered_request_releases_its_objects` | A committed request batch releases the request's request and payload objects and no other request's. |
| `e2ee::coordinator::tests::sync::recent_objects::a_declaration_holds_no_slot_and_is_acknowledged_again` | A declaration keeps no tuple and its identical repeat is acknowledged again. |
| `federation::coordinator::tests::companion_refusals::a_refused_request_commits_its_failed_result_at_its_sequence` | Through real storage: the refused request commits its failed result at its sequence, its exact copy returns that result, the next request runs at the following sequence, and the link stays up. |
| `federation::coordinator::tests::response_reads::a_cold_replay_releases_the_request_and_payload_objects` | Through real storage: a request whose stored result is read back keeps its request and payload objects while the read runs, and releases both when the result is sent. |

`e2ee::coordinator::tests::sync::a_closed_link_forgets_only_its_own_requests`
now also requires that the closed peer's declaration holds no tuple, and
`federation::coordinator::tests::response_reads::complete_and_recent_requests_replay_all_cold_bodies_in_original_order`
now assembles each copy anew after the previous replay released it.

Single edits fail tests, each run on the assembler, coordinator or response
read tests above and the closed-link test, one for each part of the rule:
dropping the per-peer ceiling fails the refusal and expiry tests; dropping
the expiry fails the expiry test; dropping the release at a committed
answer fails the release test; dropping it at a resident replay fails the
refused-request test, and at a replay read back from storage the cold
replay test; keeping declarations fails the declaration test and the
closed-link test; ignoring the refusal at execution fails the
refused-request test; never marking a refusal fails the refusal and expiry
tests; an assembler that refuses past a per-sender ceiling fails three
assembler tests; one that counts every sender's tuples against a per-sender
ceiling fails the per-sender test; and one that keeps an object through the
second its window ends fails the expiry test and three earlier assembler
tests.

The release coverage policy gains `e2ee-assembly-recent-ceiling` and
`e2ee-assembly-recent-admission` (branches) and
`e2ee-assembly-recent-retention` (regions) in the assembler, and
`companion-recent-object-expiry` (branches),
`companion-answered-request-release` and `companion-recent-object-refusal`
(regions) in the coordinator. It re-reviews and respans
`companion-mod-companioncoordinator-batch-applied`,
`cap90-current-base-origin-admission`,
`cap79-fresh-object-006-run-with-object`,
`cap79-fresh-object-019-run-with-object` and
`cap79-response-021-advance`, and moves the other regions of the changed
files, whose spans are unchanged. Both source inventories are refreshed.

## An edge's coordinator deliveries hold no recent-object slot (second commit)

The companion text this rule implements:

- Section 11.8 keys an in-progress object by its exact tuple and has
  "duplicate content addresses use the recent-object idempotency cache";
  Section 16 bounds that cache's retention.
- Section 12.5 positions every delivery: an event at its delivery generation
  and sequence ("An exact duplicate at the installed cursor is re-ACKed
  without reapplying state"), a snapshot entry at its page of one immutable
  cut ("An exact FETCH retry returns the byte-identical page", and after
  link loss a pending cut is published again from its first page), and
  Section 12.5.1 a witness resolution under its token.
- Section 12.5, on a replaced link: "a partially or completely written
  frame is treated as unacknowledged and may be sent byte-for-byte after
  reconnect".

The edge's assembler serves both its clients' submissions and the
coordinator's deliveries. The rules, in
`crates/agenc-relay-runtime/src/e2ee/edge/`:

- **A delivery holds no recent-object slot.** An event and its payload
  (`assemble_event`), a snapshot entry (`state_entry`) and a witness
  resolution object (`witness_object`) are assembled as server responses
  (`Direction::Response`): they are keyed by their position, cut or token,
  and the cache never applies to them. A delivery is never refused because
  the edge's clients filled the shared ceiling, and its exact copy on a
  later link is assembled again and checked against the delivery cursor,
  the cut or the token. The recent-object cache holds only client
  submissions, which expire as client lines arrive (`client_line`).
- **A lost link releases the coordinator's partial objects.** When the
  link closes, the edge discards every open assembly of the coordinator
  (`E2eeEdge::link_down`), as it already drops the events awaiting their
  payload; the next link carries each object again from its first fragment,
  so an assembly the closed link left half-complete never meets its copy
  after its deadline.

A prerequisite recorded for the companion resume follow-up, not changed
here: the edge re-acknowledges an exact duplicate event at its installed
cursor without reapplying state (Section 12.5) before the coordinator
retransmits from its committed acknowledgement.

| Test | What it pins |
| --- | --- |
| `e2ee::edge::tests::event_faults::an_event_assembles_whatever_the_client_cache_holds` | With the client cache at its ceiling, an event is assembled and waits for its payload. |
| `e2ee::edge::tests::snapshot::entries_assemble_whatever_the_client_cache_holds` | With the client cache at its ceiling, a cut's entries stage and its READY follows. |
| `e2ee::edge::tests::projection::witness_persistence::resolution::a_resolution_assembles_whatever_the_client_cache_holds` | With the client cache at its ceiling, an authenticated continuation resolves the witness row. |
| `e2ee::edge::tests::snapshot::a_page_published_again_on_the_next_link_stages_again` | Two entries of page zero arrive before the link closes; the next link publishes the cut again from page zero, and every entry stages. |
| `e2ee::edge::tests::event_faults::a_lost_link_releases_the_coordinators_partial_objects` | A payload's first fragment arrives before the link closes; the closed link releases it, and two minutes later the next link's copy assembles anew. |

With `events.rs`, `snapshot.rs`, `witness_resolution.rs` and `mod.rs` of
the edge set back to the first commit, all five tests fail. Single edits
fail tests as well: dropping the response direction of events, entries or
witness objects fails the matching test (both snapshot tests for entries),
and dropping the release of the coordinator's partial objects at link loss
fails the lost-link test.

The release coverage policy gains `edge-delivery-assembly`,
`edge-witness-object-assembly` and `edge-link-down-partial-objects`
(regions), re-reviews and respans `edge-snapshot-receiver`, and moves the
other regions of the changed files, whose spans are unchanged. Both source
inventories are refreshed.

## A base declaration naming a removed principal closes only its origin (third commit)

The architecture text this rule implements:

- Section 20.5: a session registration, login or other replacement of the
  connection's security principal "increments the origin generation and
  resets its operation sequence to zero only after an acknowledged `FORIGIN
  UPDATE`".
- Section 20.7: "A session registration, login, logout, account switch, or
  companion device attach/detach is represented by the next generation
  before requests under it are accepted"; "RESET fences all live execution
  from that edge until it has replayed each origin and receives READY"; and
  "DEL is durable, permanently rejects later requests, and retains the
  stated next sequence for replay checking."
- Section 11.5: a completed credential change "fences all of its
  sessions", each removed as `security_fenced`; Section 10.3: "A session is
  removed from all channels in one authoritative transition".

The rules, in `crates/agenc-relay-runtime/src/federation/coordinator/origin.rs`:

- **Structure first.** A declaration is checked against the origin table
  before the principal it names is classified (`check_structure`,
  `follows`): an ADD declares generation zero with no predecessor and no
  principal, an UPDATE repeats the held declaration exactly or declares the
  generation after it with the held object as its predecessor, and either
  keeps the binding of the origin it names. A declaration that fails these
  checks is a violation whatever session it names. The origin's status is
  left to the table and to the refusal below.
- **The declaration is refused for its origin alone.** A `FORIGIN ADD` or
  `UPDATE` whose session is no longer live here, or is no longer
  authenticated as the declared account, is refused (`principal_of`,
  `PrincipalFault::Removed`, `refuse`): nothing is acknowledged, and the
  link stays up. A declaration that names a session of another user or
  edge, or an invalid account generation, is still a violation.
- **The closure, in order.** The refusal first writes the origin's existing
  row, closed at the generation and next sequence the coordinator holds, as
  a deletion at that point would. The sessions the origin owns then close
  through the coordinator's session cleanup, one durable batch each, after
  that row commits (`close_sessions`, shared with `delete`). After a
  restart, a session whose cleanup had not committed is swept at the edge's
  next READY with every session of the edge that no live origin binds
  (`ready`).
- **The edge's deletion is acknowledged.** The edge keeps the refused
  declaration pending until its connection ends; its deletion then names
  the refused generation at sequence zero, and the coordinator acknowledges
  it without recording anything more, since the refusal closed the origin
  (`refused_declarations`, `delete`).
- **A replayed refusal is refused again.** On the next link the edge
  replays the refused declaration; it is refused again without change, and
  the closed origin does not hold the link's `FORIGIN READY` back.
- **Refusals are held in memory until the deletion.** The coordinator
  records each refusal (`refused_declarations`) and removes it when it
  acknowledges the edge's deletion. A new incarnation of the edge forgets
  the refusals of the previous one. After a restart the record starts
  empty: the edge replays the refused declaration, which is refused again
  and recorded anew, or, when the connection ended meanwhile, deletes the
  origin during the reset, which the origin table accepts for a deleted
  origin; either way the deletion is acknowledged.

| Test | What it pins |
| --- | --- |
| `federation::coordinator::tests::refused_declarations::a_declaration_naming_a_removed_session_closes_only_its_origin` | Through the actor loop: a session registers and is closed before the edge declares it; the declaration is not acknowledged, a fresh origin's declaration is, the deletion naming the refused generation is acknowledged, and another origin registers on the same link. |
| `federation::coordinator::tests::refused_declarations::a_declaration_naming_an_account_its_session_lacks_closes_that_session` | The next generation of a registered origin names an account its live session is not authenticated as; the refusal hides the session, the link keeps serving, and the deletion is acknowledged. |
| `federation::coordinator::tests::refused_declarations::a_refused_declaration_replayed_on_the_next_link_is_refused_again` | After the refusal the link is lost; the next link replays every origin and the refused declaration, READY arrives, and the deletion is acknowledged. |
| `federation::coordinator::tests::refused_declarations::a_malformed_declaration_naming_a_removed_session_is_still_a_violation` | An UPDATE that skips a generation and names a closed session is a violation, not a refusal. |
| `federation::coordinator::tests::refused_declarations::restart::a_refusal_replayed_after_a_restart_is_refused_again_and_its_deletion_acknowledged` | Through real storage, batch by batch: the refusal's origin row commits and the coordinator restarts before the session's cleanup does; the reloaded origin is deleted at the generation and next sequence it held; the replayed refused declaration is refused again and recorded anew, READY follows and sweeps the session, and the deletion after READY is acknowledged and ends the record. |
| `federation::coordinator::tests::refused_declarations::restart::a_refused_origin_deleted_during_the_reset_after_a_restart_is_acknowledged` | The same restart; the edge deletes the origin during the reset instead of replaying it, the deletion is acknowledged, READY follows, and the session is gone. |

With the coordinator's `origin.rs` and `mod.rs` set back to the second
commit, and the restart tests left out since they read the refusal record,
the first three tests fail and the other 326 coordinator tests pass, the
malformed-declaration test among them. Single edits fail tests as well, one
for each part of the rule: dropping the refusal fails the first three and
both restart tests; refusing without closing the origin fails the same
five; dropping the acknowledgement of a refused generation's deletion fails
the first three and the first restart test; closing the origin without its
sessions fails the account test; dropping the account case fails the
account test and both restart tests; refusing without writing the origin's
row fails the account test and both restart tests; keeping the refusal
after the acknowledged deletion fails the first restart test; dropping the
orphan sweep at READY fails the first restart test; and classifying the
principal before the structure fails the malformed-declaration test.

The release coverage policy gains `coordinator-declared-principal`,
`coordinator-declaration-structure`, `coordinator-declaration-succession`
and `coordinator-refused-declaration-deletion` (branches) and
`coordinator-refused-declaration` (regions). No reviewed region of the
changed files changed its span. Both source inventories are refreshed.

## A companion declaration naming a superseded attachment closes only its origin (fourth commit)

The companion text this rule implements:

- Section 11.6: `session_generation` "is a durable nonzero uint64 counter
  scoped to the Account ID and Device ID", "every successful attachment
  increments it exactly once", and "`FINISH` succeeds only by
  compare-and-swap against the durable prior value"; Section 11.9:
  `E2EE_DEVICE_REQUIRED` is "Connection lacks a current roster-active device
  attachment".
- Section 12.5: "An attached device requires an authenticated account, has
  a 16-byte Device ID and nonzero device-session generation"; device attach
  advances "the one shared base origin generation before either profile
  accepts a request under it"; "`DEL` supplies the next unused sequence and
  permanently fences later requests"; and "reconnect must replay RESET and
  origin state before resuming".

The coordinator mirrors a declared attachment only at the directory's
current generation. The rules, in
`crates/agenc-relay-runtime/src/e2ee/coordinator/sync.rs`:

- **The declaration is refused for its origin alone.** A declaration whose
  device session generation the directory has advanced past is refused
  (`mirrored_device`, `MirrorFault::Superseded`, `refuse_declaration`):
  nothing is acknowledged, and the companion origin is fenced at the
  generation and next sequence it holds, as a deletion there would. The link
  stays up. A generation the directory has not reached, or any other
  disagreement, is still a violation.
- **Every later declaration of the origin is refused alike.** The edge
  answers the connection's encrypted commands with `E2EE_SYNCING` while its
  declaration is unacknowledged, and carries the attachment into the
  declarations of later base generations; each of them, and a replay on a
  later link, is refused without change until the edge deletes the origin
  (`refused_origins`). A new incarnation of the edge forgets the previous
  one's refusals.
- **The edge's deletion is acknowledged.** It names the generation of the
  last declaration its link carried, which is the one refused last, and the
  coordinator acknowledges it; the origin stays fenced (`origin_del`).
- An attachment the coordinator accepted stays accepted: the identical
  declaration of the accepted state is acknowledged again after the device
  attaches elsewhere (first commit).

| Test | What it pins |
| --- | --- |
| `e2ee::coordinator::tests::sync::superseded_attachments::a_declaration_naming_a_superseded_attachment_closes_only_its_origin` | The directory is at generation two; the declaration naming generation one is not acknowledged and fences the origin where it stood, a later declaration (a logout still naming the device) is refused alike, and the deletion naming the generation refused last is acknowledged. |
| `e2ee::coordinator::tests::sync::superseded_attachments::an_attachment_the_directory_never_reached_is_still_a_violation` | A declaration naming a generation above the directory's is a violation, and nothing is fenced. |
| `e2ee::coordinator::tests::sync::superseded_attachments::a_refused_declaration_replayed_on_the_next_link_is_refused_again` | After the link is replaced, READY follows the RESET, the replayed declaration is refused again, and the deletion is acknowledged. |
| `e2ee::coordinator::tests::sync::superseded_attachments::an_accepted_attachment_is_acknowledged_again_after_another_supersedes_it` | A declaration accepted at the directory's generation is acknowledged again on the next link after the device attaches on another connection. |

With the coordinator's `sync.rs` and `mod.rs` set back to the third commit,
the first and third tests fail and the other 99 synchronization tests pass.
Single edits fail tests as well, one for each part of the rule: dropping
the refusal fails the first and third; not refusing a later declaration of
a refused origin fails the first; not acknowledging the deletion of the
generation refused last fails the first and third; and refusing without
fencing fails the first.

The release coverage policy gains `companion-superseded-attachment`
(branches) and `companion-refused-declaration` (regions), and re-reviews and
respans `cap78-sync-origin-reset`, `cap78-sync-origin-del` and
`cap90-current-base-origin-admission`; the other regions of the file move
with unchanged spans. Both source inventories are refreshed.

## Validation

Each commit, Rust 1.98.0, from the worktree root: `cargo clippy --workspace
--all-targets --all-features --locked -- -D warnings`, the runtime library
run below, `python3 scripts/check-coverage.py audit` on both policies, `git
diff --cached --check` and the program's 59-command fast gate on the staged
tree, which includes `cargo fmt --all --check`, `python3
scripts/check-source.py check` and `cargo audit --deny warnings`: exit 0.
The runtime library run is `cargo nextest run -p agenc-relay-runtime --lib
--all-features --locked --no-fail-fast -E 'not test(/offline::tests::/)'`;
the ten excluded `offline::tests` fail on this host's root file system,
which is below its storage reserve, at every revision.

First commit: the runtime library run passes 2,767 of 2,767, and `cargo
nextest run -p agenc-relay-e2ee --all-features --locked --no-fail-fast`
passes 356 of 356. The single edits above ran the assembler,
coordinator, refusal and response read tests.

Second commit: the runtime library run passes 2,772 of 2,772. The revert
proof and single edits above ran the edge tests of the runtime library.

Third commit: the runtime library run passes 2,778 of 2,778. The revert
proof and single edits above ran the coordinator tests of the runtime
library.

Fourth commit: the runtime library run passes 2,782 of 2,782. The revert
proof and single edits above ran the coordinator's synchronization tests.

Not run here: the full stage-nine gate, which cannot finish on this host.
