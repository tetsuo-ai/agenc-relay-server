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
its link closes. No specification, profile hash, registry entry, named
limit, reply code, wire object, table, key, row kind, field or storage
generation changed.

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

Not run here: the full stage-nine gate, which cannot finish on this host.
