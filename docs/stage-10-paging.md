# Companion listings page over immutable, requester-bound cuts (B-13)

This record covers item B-13 of the SDK server program (SC-003, 2026-10-09,
outside master #35): the companion listings `EKEY FETCH ROOT-CHAIN`, `EKEY
FETCH BINDING-LOCKS`, `EKEY FETCH CAPABILITIES` and `EGROUP FETCH
AUTHORIZATIONS`, `ACKS` and `RECEIPTS` page over one immutable cut each,
continued only by the one live cursor of that cut, and every page is packed
against all three batch limits together. The first commit holds the rules
and their unit, handler and coordinator tests. No specification, profile
hash, registry entry, named limit, reply code, wire object, table, key, row
kind, field or storage generation changed.

## The text these rules implement

Companion Section 11.6:

- "`FETCH ROOT-CHAIN` returns a contiguous, immutable-snapshot page
  beginning at the requested generation. Every page repeats the same
  snapshot token and continues with no generation gap; the final root must
  match the requested account and every continuity signature."
- "`FETCH BINDING-LOCKS` is likewise an immutable, contiguous page for the
  exact Account ID and root fingerprint. Sequence zero starts that root's
  chain; a request never merges lock sequences from two root generations."
- "`FETCH CAPABILITIES` pages the exact current-roster device set in
  canonical Device-ID order under one immutable snapshot. Every active
  device appears exactly once, no inactive device appears, and each returned
  capability object is the highest accepted generation for that device and
  named roster."

Companion Section 11.7: "`snapshot-token`, continuation cursors, and
delivery tokens are 32 random bytes in unpadded base64url. A cursor is valid
only with its original attached device or authenticated Account ID, request
kind, scope, and immutable snapshot; it expires after
`DIRECTORY_CURSOR_TIMEOUT`. One batch contains at most `MAX_BATCH_OBJECTS`,
`MAX_BATCH_FRAGMENTS`, and `MAX_BATCH_DECODED_BYTES`. The opener names the
next cursor or `*` when the snapshot is exhausted. Empty pages use the fixed
`EMPTY` response and do not open a batch." Its federation results, Section
12.5: response descriptors "obey all batch object, byte, and fragment
limits"; `fetch_receipts` answers "1..`MAX_BATCH_OBJECTS` contiguous
`sequencer_record` objects beginning at the requested route sequence" and
`fetch_root_chain` "exactly one `root_identity_chain` containing the
contiguous requested page"; and "`object_page` and `mailbox_page` have a
32-byte snapshot token and an empty or 32-byte next cursor."

Companion Section 16: `MAX_BATCH_OBJECTS` is 32, `MAX_BATCH_FRAGMENTS`
1,427, `MAX_BATCH_DECODED_BYTES` 4,194,304 bytes, `MAX_ROOT_CHAIN_OBJECT`
1,048,576 bytes and `DIRECTORY_CURSOR_TIMEOUT` 10 minutes; an object's
fragments are "the exact ceiling implied by `ceil(total /
MAX_FRAGMENT_RAW)`"; and "Admission may be refused before reservation".
Section 11.9: `E2EE_OBJECT_NOT_FOUND` is "Requested retained object or
record is unavailable" and `E2EE_RATE_LIMITED` "Operation exceeded an
authenticated quota".

## Decisions

- **One live cursor per cut, consumed by its page's commit.** A cut owns
  exactly one cursor. The commit of the page a cursor names consumes it and
  installs the next one; the last page releases the cut. This is the base
  profile's paged directory query rule (Architecture invariant `FED-13`: "one
  bounded immutable snapshot and one [...] cursor slot; successful
  continuation atomically replaces that slot, while expiry, restart, wrong
  binding, or consumption can only fail"). A batch that storage refuses consumes
  nothing, so its cursor stays usable. An exact copy of a federation request
  that already committed is answered from its replay row as before, page and
  next cursor alike.
- **The refusal is `E2EE_OBJECT_NOT_FOUND`.** The companion registry has no
  query-expiry code, and a failed result names a Section 11.9 code (Section
  12.5). An unknown, forged, consumed, expired or differently bound cursor
  names a retained cut that is unavailable, the code the daemon's mailbox
  cuts already give a refused cursor (`mailbox_snapshot`). The context is
  empty. The listing never restarts at its first position under a cursor.
- **The binding.** A cursor is valid only for the session, companion origin
  and origin generation it was issued to, the requester's authenticated
  account, for an `EGROUP` listing also its current device attachment, the
  request kind, its selector (account, root fingerprint, conversation,
  candidate or ACK selector) and its first position. A continuation repeats
  the request that opened the cut, with the cursor in place of `*`.
- **The lifetime.** A cut and its one cursor expire
  `DIRECTORY_CURSOR_TIMEOUT` after the cut was captured, however many pages
  follow, as the mailbox cuts do; a later page does not extend it.
- **A cut holds identifiers and sizes, not copies.** Every object a listing
  names is retained, content-addressed and immutable, and object expiry
  collects one only after its last owner has been retired for its class's
  window, at least a day. A cut therefore records each object's identifier
  and complete encoded size, and its pages read the retained bytes. A page
  whose object is no longer retained as captured is refused with
  `E2EE_OBJECT_NOT_FOUND` rather than spliced from another state, and so is
  a listed object not retained as a complete encoded object, wherever its
  page falls. Copying the bytes would charge a receipt run of up to
  `MAX_STORED_BYTES_PER_CONVERSATION` to the query snapshot budget.
- **A listing that fits one page keeps nothing.** It is answered from the
  committed state with a fresh snapshot token and `*`, as before, and takes
  no query snapshot.
- **The bounds.** A cut is one of its session's query snapshots, charged one
  query row for each entry and its backing bytes, and holds at most the
  configured `query_snapshot_rows` entries; every cursor index a page
  prepares, a continuation's successor index included, is charged to the
  global query bytes. A contiguous run from a first position (a root chain,
  a root's locks, receipts) longer than that ends its cut there: its last
  page names `*`, and the next request continues from the following
  position. A set (capabilities, authorizations, acknowledgements) longer
  than that is refused `E2EE_RATE_LIMITED`, since a page of it would be
  incomplete. A cut's entries, its owner and its cursor index are reserved
  from the process memory budget, and every reservation is made before any
  entropy is drawn; a page refused at a reservation, at its lifetime or at
  its entropy keeps nothing, and a refused continuation leaves its cursor
  live. Cuts share the session and global query ceilings with base directory
  queries and mailbox cuts, so one connection holds at most its session's
  share and all of them the process ceilings (Section 16, and Architecture
  19.2: "All count-scaled or peer-influenced heap storage is allocated
  through one process-wide `MemoryBudget` authority").
- **The releases.** A cut is released by its last page, by its expiry wake
  (`TimerKind::ListingSnapshotExpiry`), by its origin's deletion or a refused
  declaration of its origin, whatever generation it was bound to, by a new
  incarnation of its edge, and when its edge's federation link closes. A
  page's receipt publishes only the cuts whose origin is still declared on a
  live link, unfenced, at the generation, account and, for an `EGROUP`
  listing, current attachment the cut was bound to, and that are unexpired at
  the receipt time.
- **A root chain page.** A root-chain page is one `root_identity_chain`
  object of at most `MAX_ROOT_CHAIN_OBJECT`, holding complete roots, which a
  compile-time bound keeps within one batch's bytes and fragments. A stored
  chain holds at most 1,024 roots (`MAX_ROOT_CHAIN_LENGTH` of the identity
  row), about 283 KB, so a chain fits one page today; the cut covers any
  longer one.
- **The edge is unchanged.** It still refuses a result whose descriptors
  exceed the object count or the summed bytes, which closes its link; the
  coordinator's packing keeps every page within all three limits, so no
  page reaches that refusal.

## Storage (G-08)

Cuts and cursors are process-local and never written: no table, key, row
kind, field, object layout or storage generation changed, and startup
writes and reads nothing new. The restart rule: a restart discards every
cut; a cursor issued before it is refused with `E2EE_OBJECT_NOT_FOUND`
after it, and the client opens a new cut with `*`. A federation request
whose page committed before the restart is still answered from its replay
row, and the next cursor that page names is then refused as well. No store
of the start commit needs a restore test: none holds anything these rules
read.

## The rules (first commit)

In `crates/agenc-relay-runtime/src/e2ee/coordinator/ops/listing_snapshot.rs`
(new), `ops/cut_backing.rs` (new, the charged vectors the mailbox cuts used,
moved unchanged), `ops/directory.rs`, `ops/sequence.rs`,
`ops/mailbox_snapshot.rs`, `ops/mod.rs`, `execute.rs`, `request.rs`,
`mod.rs` and `sync.rs` of the coordinator,
`crates/agenc-relay-runtime/src/federation/coordinator/companion.rs` and
`mod.rs`, `crates/agenc-relay-runtime/src/state_core/timers.rs` and
`query_usage.rs` (`QueryReservationPort::snapshot_rows`, the row ceiling of
one snapshot), and `crates/agenc-relay-runtime/src/runtime_config.rs`:

- **The listings.** `listed` enumerates each listing from the committed
  state: the account's root chain from the first generation, a root's lock
  chain and a conversation's records as the contiguous run from the first
  sequence (`run`), the capability page of the current roster, and a
  candidate's approvals and a selector's acknowledgements in their key order.
  An unknown conversation still refuses `RECEIPTS` with `E2EE_ROUTE_INVALID`,
  and an empty listing still answers its `EMPTY` kind.
- **The packing.** `Packer::admit` admits the next complete object while the
  page holds at most `MAX_BATCH_OBJECTS` objects, `MAX_BATCH_DECODED_BYTES`
  summed bytes and `MAX_BATCH_FRAGMENTS` summed per-object fragment counts,
  each object's own `ceil(size / 2,940)`; a root-chain page admits a root
  while the chain object, `CHAIN_OVERHEAD` plus each root's body, stays at
  most `MAX_ROOT_CHAIN_OBJECT`. `page_end` ends a page before the first
  object that would cross a limit; an object no page can hold is refused.
- **The first page.** `first_page` packs the first page from the committed
  state; when the listing ends within it, the page is answered with nothing
  kept. Otherwise `capture` reserves the cut (`reserve_snapshot`, the entry
  vector, its owner), records each entry's identifier and size, packs the
  first page from the cut, reserves the replacement cursor index
  (`Store::prepare_replace`, which keeps only the cuts unexpired at the
  request's time), checks that the cut's lifetime ends within the clock, and
  only then draws the snapshot token and the cursor (`install` refuses a
  token already live).
- **A continuation.** Only a request of a base session continues a cut.
  `continue_cut` finds the one live cursor of a cut bound to exactly the
  request's scope and unexpired at the request's time (`Store::lookup`),
  packs the next page from the cut, refuses a page whose objects are not
  retained as captured, and prepares the replacement without the consumed
  cursor and, unless the page is the last, with its successor (a successor
  equal to the consumed cursor or to another live cursor is refused).
- **The receipt.** The page's outcome names the earliest expiry of the
  replacement (`Outcome::listing_expiry`); `Fresh::stage` arms the listing
  expiry wake for it before the batch is staged
  (`listing_snapshot::reserve_expiry`), and the commit's effect publishes the
  replacement (`Store::publish`). `request_committed` expires due cuts and
  keeps the wake armed for the earliest one left or cancels it
  (`schedule_listing_expiry`); the wake itself does the same
  (`listing_timer_fired`, dispatched by `FederationCoordinator::timer_fired`),
  and a wake that cannot be armed again releases every cut left. A page
  whose cut's wake cannot be armed is not staged, and its request is
  answered with its failed result.
- **The releases.** `CompanionCoordinator::link_closed` releases the cuts of
  the peer's origins (`Store::close_home`); `origin_reset` releases those of
  earlier incarnations (`fence_incarnations`); `origin_del` and
  `refuse_declaration` release every cut of the origin
  (`Store::close_origin`).
- `fetch_object` keeps its singleton answer; its page helper loses the next
  cursor it no longer takes.

| Test | What it pins |
| --- | --- |
| `e2ee::coordinator::ops::listing_snapshot::tests::a_batch_page_holds_the_object_count_ceiling_and_stops_one_over` | 32 objects are one page; a 33rd opens the next. |
| `e2ee::coordinator::ops::listing_snapshot::tests::a_batch_page_holds_the_byte_ceiling_and_stops_one_byte_over` | Objects of 713 and 714 fragments summing exactly 4,194,304 bytes are one page; one byte more opens the next. |
| `e2ee::coordinator::ops::listing_snapshot::tests::fragment_rounding_ends_a_page_of_two_objects_within_the_byte_ceiling` | Two 2,097,152-byte objects fill the byte ceiling but take 1,428 fragments: one page each, although rounding their summed bytes would give 1,427; exactly 1,427 summed fragments fit, and one more does not. |
| `e2ee::coordinator::ops::listing_snapshot::tests::a_root_chain_page_holds_its_object_ceiling_and_stops_one_byte_over` | Roots whose chain object is exactly 1,048,576 bytes are one page, one byte more opens the next, and a chain page counts no batch object ceiling. |
| `e2ee::coordinator::ops::listing_snapshot::tests::the_chain_overhead_is_the_encoded_chain_around_its_roots` | The encoded chain object is `CHAIN_OVERHEAD` plus its roots' bodies. |
| `e2ee::coordinator::ops::listing_snapshot::tests::a_page_never_begins_past_its_cut_or_holds_no_object` | A page past its cut, at its end, of an object larger than a batch, or of an object without a body, is refused. |
| `e2ee::coordinator::tests::sequence::listing_pages::directory::a_root_chain_longer_than_one_batch_is_one_complete_contiguous_page` | A 40-root chain is one chain object of all 40 roots in order, a later first generation its tail, past the head `EMPTY ROOT-CHAIN`, and no cut is kept. |
| `e2ee::coordinator::tests::sequence::listing_pages::directory::capabilities_page_every_active_device_once_over_one_immutable_cut` | 40 devices' statements page 32 and 8 under one snapshot token; the cut keeps the statement a device replaced between the pages, holds every active device once in Device-ID order, each naming the current roster, and a new cut holds the replacement. |
| `e2ee::coordinator::tests::sequence::listing_pages::directory::binding_locks_page_one_roots_chain_contiguously_over_one_immutable_cut` | A root's 40 locks, the bound channel's first among them, page 32 and 8; a lock appended between the pages stays out of the cut, a later first position includes it, and another root's chain is empty. |
| `e2ee::coordinator::tests::sequence::listing_pages::directory::a_binding_lock_run_ends_at_the_first_gap` | A run of locks ends at its first missing sequence. |
| `e2ee::coordinator::tests::sequence::listing_pages::proofs::authorizations_page_over_one_cut_that_proof_growth_never_changes` | 40 signers' approvals page 32 and 8; an approval replaced and a signer slot added between the pages stay out of the cut, a new cut holds both, and another candidate has none. |
| `e2ee::coordinator::tests::sequence::listing_pages::proofs::acknowledgements_page_over_one_cut_that_outlives_their_finalization` | 40 acknowledgements page 32 and 8; one added between the pages stays out, and the finalization that retires the candidate's acknowledgements from the live state leaves the cut's second page intact. |
| `e2ee::coordinator::tests::sequence::listing_pages::proofs::receipts_page_contiguously_over_one_cut_that_later_records_never_enter` | 40 records page 32 and 8; a record appended between the pages stays out and the next request from the following sequence returns it; a run ends at a gap, past the log is `EMPTY RECEIPTS`, and an unknown conversation is `E2EE_ROUTE_INVALID`. |
| `e2ee::coordinator::tests::sequence::listing_pages::packing::a_receipt_page_holds_exactly_the_object_count_and_one_more_continues` | Through the handler: 32 records are one page, 33 two. |
| `e2ee::coordinator::tests::sequence::listing_pages::packing::a_receipt_page_holds_exactly_the_byte_ceiling_and_one_byte_more_continues` | Two records summing exactly the byte ceiling are one page; one byte more makes two. |
| `e2ee::coordinator::tests::sequence::listing_pages::packing::fragment_rounding_ends_a_receipt_page_of_fewer_than_32_records` | Two 2 MiB records are two pages; two records of exactly 1,427 fragments one, and a third record a second. |
| `e2ee::coordinator::tests::sequence::listing_pages::packing::every_page_of_one_cut_packs_against_all_three_limits` | One cut's pages end at the fragments, the count and the bytes in turn, every page within all three limits. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::a_forged_cursor_is_refused_and_never_restarts_the_listing` | Forged cursors and live cursors with a changed first or last byte are refused `E2EE_OBJECT_NOT_FOUND` for locks and receipts, before entropy and with the cuts unchanged. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::a_cursor_is_refused_under_any_other_kind_selector_or_first_position` | A lock cursor under `CAPABILITIES`, `ROOT-CHAIN`, another root, another account or another first position, a receipt cursor under another conversation, another first sequence or `ACKS`, and a lock cursor under `RECEIPTS` are refused; both cuts still continue. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::a_cursor_is_refused_to_any_other_requester` | Another session, origin generation, origin, home or account is refused; attaching the device again ends a receipt cut; the lock cut, which binds no attachment, continues. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::a_cursor_expires_at_the_exact_directory_cursor_timeout` | A cursor is served 599,999 ms after its cut's capture and refused at 600,000. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::a_consumed_cursor_is_refused_while_its_successor_continues` | A page that never commits consumes nothing; once the page commits, its cursor is refused and the last page releases the cut. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::every_cursor_continues_once_in_a_cut_of_several_pages` | 100 records page 32, 32, 32 and 4, and every consumed cursor is refused after its page. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::a_cut_whose_object_is_gone_or_altered_is_refused_rather_than_spliced` | A continuation is refused while a page object is not retained or not retained as captured, and served once it is. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::a_cursor_drawn_equal_to_a_consumed_or_live_one_is_refused` | A successor drawn equal to the cursor it consumes or to another live cursor, and a new cut's cursor drawn equal to another live cursor, are refused `E2EE_RATE_LIMITED`. |
| `e2ee::coordinator::tests::sequence::listing_pages::cursors::a_restart_discards_every_cut_and_starts_a_new_one` | After a coordinator reload no cut remains, the earlier cursor is refused, and `*` pages the capability set anew. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_run_longer_than_the_row_ceiling_ends_its_cut_there_and_the_next_request_continues` | With a 40-row ceiling 50 receipts page 32 and 8 and then 10 from sequence 40; with a 20-row ceiling the cut is one final page of 20, and a run that fits a page needs no cut. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_binding_lock_run_longer_than_the_row_ceiling_ends_its_cut_there` | With a 40-row ceiling a root's 50 locks page 32 and 8, sequences 0 to 39, and then 10 from sequence 40. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_set_longer_than_the_row_ceiling_is_refused_before_entropy` | 41 acknowledgements are refused `E2EE_RATE_LIMITED` under a 40-row ceiling and page 32 and 9 under a 41-row one. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_cut_is_one_of_its_sessions_query_snapshots` | With one query snapshot per session a second cut is refused before entropy while a one-page listing is served and another session captures its own; the last page frees the session's snapshot. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_cut_charges_one_query_row_per_entry_against_the_global_row_ceiling` | A cut of 40 receipts is charged 40 query rows; another session's cut of 40 is refused `E2EE_RATE_LIMITED` before entropy under a global row ceiling of 79, charging nothing, and kept under one of 80. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_cut_reserves_its_memory_before_entropy_and_returns_it_when_released` | With no memory budget a cut is refused before entropy; a cut's charge returns at its last page and at its expiry. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_page_that_keeps_a_cut_names_its_expiry_and_a_single_page_names_none` | The outcome names the cut's expiry, and a one-page listing names none. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::an_origins_deletion_releases_its_cut_and_no_other` | Another origin's deletion releases nothing; the origin's own deletion releases its cut, at its generation or another. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::an_origins_deletion_releases_its_cuts_of_every_generation` | A cut bound to a generation the origin has since left is released by the origin's deletion. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_new_incarnation_of_the_edge_releases_its_cuts` | A same-incarnation reset and another edge's reset keep the cut; a new incarnation of its edge releases it. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_closed_link_releases_the_cuts_of_its_origins_alone` | Another link's closure keeps the cut; its own edge's releases it. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_prepared_page_publishes_no_cut_its_origin_or_lifetime_no_longer_holds` | A prepared first page whose origin is deleted, suspended, reattached, at another generation or another account, or whose cut expired, before its receipt publishes no cut and returns its charge. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_listed_object_larger_than_any_page_is_refused` | An object larger than a batch is refused before entropy. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::a_requester_without_a_session_takes_no_cut` | Without a base session a longer listing is refused `E2EE_OBJECT_NOT_FOUND` before entropy, as is a cursor its origin's session holds, and a one-page listing is answered. |
| `e2ee::coordinator::tests::sequence::listing_pages::bounds::the_listing_expiry_wake_keeps_the_earliest_deadline_and_refuses_exhaustion` | The wake cannot be armed in a full timer heap, keeps its earliest deadline, and is due exactly then. |
| `e2ee::coordinator::tests::sequence::listing_pages::refusals::a_listed_object_not_retained_as_an_encoded_object_is_refused` | A record that is gone, or retained empty, is refused `E2EE_OBJECT_NOT_FOUND` before entropy at the first page and at the capture of the cut beyond it, keeping nothing, and at the later page that holds it, which keeps its cursor. |
| `e2ee::coordinator::tests::sequence::listing_pages::refusals::a_page_without_entropy_for_its_tokens_is_refused_and_keeps_nothing` | A one-page listing without its snapshot token, and a cut without its snapshot token or its cursor, are refused `E2EE_RATE_LIMITED` with nothing kept; a continuation without its successor keeps its cursor, which then continues. |
| `e2ee::coordinator::tests::sequence::listing_pages::refusals::a_cut_refused_at_any_memory_reservation_keeps_nothing_charged` | Memory budgets short of a cut's entries, its owner or its cursor index, or of a continuation's successor index, refuse the page `E2EE_RATE_LIMITED` before entropy with nothing charged and the cuts unchanged; the next quantum serves it. |
| `e2ee::coordinator::tests::sequence::listing_pages::refusals::a_cut_whose_index_exceeds_the_query_bytes_ceiling_is_refused_before_entropy` | A global query byte ceiling one byte below a cut's snapshot and cursor index refuses it before entropy, keeping nothing; at exactly their sum it is served. |
| `e2ee::coordinator::tests::sequence::listing_pages::refusals::a_continuation_whose_successor_index_exceeds_the_query_bytes_ceiling_is_refused_before_entropy` | Under a global query byte ceiling of exactly what a held cut and its cursor index charge, a middle page is refused `E2EE_RATE_LIMITED` before entropy; once the ceiling allows, its successor's index is charged on top of the cut while the page is prepared, its receipt returns the consumed cursor's index, and the last page, which names no successor, is served at that ceiling. |
| `e2ee::coordinator::tests::sequence::listing_pages::refusals::a_cut_whose_lifetime_cannot_be_represented_is_refused_before_entropy` | A cut whose lifetime would end past the clock's last instant is refused `E2EE_RATE_LIMITED`; one ending at that instant is kept. |
| `e2ee::coordinator::tests::sequence::listing_pages::refusals::an_expired_cut_is_left_out_of_the_next_replacement` | A cut expired at the next request's time is left out of the replacement that request prepares, before its wake releases it. |
| `e2ee::coordinator::tests::sync::superseded_attachments::a_refused_declaration_releases_its_origins_listing_cuts` | A refused declaration of an origin releases its cut. |
| `federation::coordinator::tests::companion_refusals::listing_cuts::a_page_that_keeps_a_cut_arms_its_expiry_and_the_owner_releases_it` | Through real storage: the first page of 41 receipts arms the wake before its batch commits, its receipt publishes the cut, and the owner's wake at the deadline releases it and disarms. |
| `federation::coordinator::tests::companion_refusals::listing_cuts::a_cut_paged_to_its_end_through_the_owner_disarms_its_expiry` | Through real storage: the last page's receipt releases the cut and cancels the wake. |
| `federation::coordinator::tests::companion_refusals::listing_cuts::the_expiry_wake_rearms_for_the_next_cut` | Through real storage: the wake releases the earlier of two cuts and is armed again for the later one. |
| `federation::coordinator::tests::companion_refusals::listing_cuts::a_wake_that_cannot_be_armed_again_releases_every_cut` | Through real storage: a wake that cannot be armed again for the cut left releases every cut. |
| `federation::coordinator::tests::companion_refusals::listing_cuts::a_cut_whose_expiry_cannot_be_armed_is_answered_with_its_failed_result` | Through real storage: with a full timer heap the first page of a longer listing is answered with its failed result `E2EE_RATE_LIMITED`, no cut is published, and the link stays up. |
| `federation::coordinator::companion::transfer_tests::timers::a_due_listing_expiry_releases_its_reservation_through_the_owner` | A due wake with no cut disarms and leaves no heap entry. |
| `federation::coordinator::companion::transfer_tests::timers::the_listing_expiry_wake_is_owned_only_as_the_global_entry` | The owner claims no listing entry addressed to a peer, and owns the global one without an executor. |

The coordinator handler tests seed the objects of a listing where the
handlers that write them need more than one connection or leaf: binding
locks beyond the bound channel's, acknowledgements beyond the attached
device's, and receipts, whose packing needs records of chosen sizes. The
root chain, the capability set and the approvals are published through the
handlers.

With `ops/directory.rs` and `ops/sequence.rs` set back to the start commit,
and dead code allowed in the new module those files no longer call, 47 of
the 56 tests fail; the nine that pass test the packer and the expiry wake
alone. Forty-eight single edits each fail at least one test: in the packer,
a fragment ceiling of twice the published one fails three tests, a byte
ceiling of twice the published one four, a count ceiling one higher
twenty-one, rounding the page's summed bytes instead of each object's three,
and a chain overhead without its vector length one; a lookup comparing only
the listing fails one test and one comparing only the origin two, and one
serving a cursor at its expiry instant one; a replacement keeping the
consumed cursor fails thirteen, one keeping a cut expired at the request's
time one, one ignoring a refused index reservation two, and one charging its
index nothing to the query bytes one; a publication keeping a cut whose
origin is suspended, fenced, reattached, at another generation or another
account, or whose cut expired, fails one test each; a capture without the
row ceiling fails two, one truncating a longer set one, one refusing a
longer lock run as a set one, one charging a cut a single query row one, one
drawing entropy before its reservations eleven, one refusing a requester
without a session with `E2EE_RATE_LIMITED` one, and one whose lifetime
saturates at the clock's last instant one; a continuation serving an object
whose retained size changed fails one; a successor equal to the cursor it
consumes, a duplicate live cursor, a run skipping a gap and a page admitting
an object larger than a batch fail one, one, two and two tests; a link
closure releasing another edge's cuts, and a `close_home` keeping its
edge's, fail one test each; a reset fencing another edge's incarnations and
a fence keeping older incarnations one each; a refused declaration keeping
its origin's cuts one, and a deletion keeping them two; a `close_origin`
keeping a cut of another generation three; an expiry keeping a cut at its
deadline three; staging without the wake, staging past a wake it cannot arm,
a page naming no expiry, a commit scheduling no listing expiry and a
schedule keeping an empty wake two, one, five, one and one; and an owner
ignoring the listing wake five, a wake claiming a peer's entry one, a wake
keeping its arm two, a wake that cannot be armed again keeping its cuts one,
and an expiry reservation keeping a later deadline one.

The release coverage policy gains eighteen regions: `listing-snapshot-listed`,
`-run`, `-packer-admit`, `-page-end`, `-first-page`, `-capture`,
`-continue-cut`, `-install`, `-store-lookup`, `-store-prepare-replace`,
`-store-publish`, `-store-close-origin`, `-store-fence-incarnations`,
`-store-close-home`, `-store-expire` and `-reserve-expiry` in
`listing_snapshot.rs`, and `companion-schedule-listing-expiry` and
`companion-listing-timer-fired` in `companion.rs`. It re-reviews and
re-spans the eight regions whose text these rules changed:
`cap78-sync-origin-reset`, `cap78-sync-origin-del`,
`companion-refused-declaration`, `companion-closed-link-request-classification`,
`cap90-current-base-origin-admission`, `companion-fresh-request-staging`,
`cap79-fresh-object-012-fetch-object` and
`cap79-fresh-object-020-request-committed`. The other regions of the changed
files move with unchanged spans, and both source inventories are refreshed
(1,068 files).

A runtime library branch report at this commit, compared with the same
report at the start commit, scores every new region in full except two,
which name their scores in their reasons: `listing-snapshot-capture` 137/141
and `listing-snapshot-store-prepare-replace` 45/48 regions, refusals of a
count or charge that cannot be computed, which no cut within the row
ceiling reaches. `listing-snapshot-run` is scored by regions, since its span
holds no branch records. No re-reviewed region holds more uncovered regions
than at the start commit: `cap78-sync-origin-reset` is 63/72 regions (59/68
at the start commit), `cap78-sync-origin-del` 51/52 (48/49),
`cap90-current-base-origin-admission` 23/24 branches (23/24),
`companion-refused-declaration` 23/23 (20/20) and
`companion-closed-link-request-classification` 26/26 (23/23), and the three
whose reasons name their scores name the new ones over the same uncovered
regions: `companion-fresh-request-staging` 114/154 (106/146),
`cap79-fresh-object-012-fetch-object` 55/64 (56/65, one fewer region since
its page helper takes no cursor) and
`cap79-fresh-object-020-request-committed` 27/34 (24/31).

## Validation

First commit, with tests in the program's test environment (HOME and
XDG_RUNTIME_DIR on the ext4 test file system, TMPDIR on the root file
system):

- `cargo nextest run -p agenc-relay-runtime --lib --all-features --locked
  --no-fail-fast`: 2,997 of 2,997 pass, exit 0.
- The 56 tests above, `-E 'test(/listing/)'`: 56 of 56 pass, exit 0. With
  `ops/directory.rs` and `ops/sequence.rs` set back to the start commit, 47
  fail, exit 100; under each of the 48 single edits at least one fails,
  exit 100.
- `RUSTC_BOOTSTRAP=1 cargo llvm-cov nextest --branch -p agenc-relay-runtime
  --lib --all-features --locked --no-fail-fast --json`: 2,997 of 2,997
  pass, exit 0; at the start commit, through an export of it, 2,941 of
  2,941 pass, exit 0.
- `cargo fmt --all --check`: exit 0.
- `cargo clippy --workspace --all-targets --all-features --locked --
  -D warnings`: exit 0.
- `python3 scripts/check-coverage.py audit` and `self-test` on both
  policies: exit 0.
- `git diff --cached --check`: exit 0.
- The program's 59-command fast gate on the staged tree: 59 of 59 exit 0.
- Not run here: the full stage-nine gate.

## What stays open

- **The edge checks two of the three limits.** The edge refuses a result
  whose descriptors exceed the object count or the summed bytes, and its
  refusal closes the link; it does not sum the descriptors' fragment counts.
  The coordinator now packs every page within all three limits, so no
  conforming page reaches either. A fragment check at the edge would add a
  link-closing refusal of its own, so it is left to the owner.
- **A cut of an origin that moved on lingers until its expiry or the next
  publication.** A cut bound to a generation its origin has since left can
  no longer be continued, but it is released only at its expiry, at the next
  page receipt of any listing, or when the origin ends, as a mailbox cut is,
  and it counts against its session's query snapshots meanwhile.
- **Approval slots are not bounded per candidate.** The coordinator keeps one
  approval per signer root fingerprint and device without verifying the
  approval, so a device can fill a candidate's approval set; a set longer
  than the row ceiling is refused, not truncated.
- **An answer longer than the link's writer queue relies on the writer
  draining.** The coordinator queues a committed answer on the requesting
  edge's link in one pass, without waiting for room: its result's `ERESULT`
  lines and one `ERESPONSE` line for each fragment of each response object
  (`request_committed`, `send_response`). The link's writer queue holds
  1,024 lines, and a full queue fails the link (Architecture Section 21.3:
  "StateCore -> federation writer | 1,024 objects / configured
  `federation_output_bytes` | mark link unhealthy; no state loss"). A page
  within all three batch limits may hold 1,427 fragments, so a listing page
  of more than 1,023 response fragments, like a large object answer or
  mailbox page, is an answer of more than 1,024 lines: it keeps the link up
  only if the writer drains while it is queued, and a replay of the same
  request queues the same lines again. These rules keep every page within
  the batch limits; they do not pace an answer into the queue.
