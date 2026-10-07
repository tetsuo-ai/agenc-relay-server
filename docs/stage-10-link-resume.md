# A federation link resumes after a lost acknowledgement (D-44)

This record covers part 1 of decision D-44 of the SDK server program
(2026-10-07, outside master #35), which follows D-43: a federation link
resumes after an acknowledgement is lost in a link cut or a coordinator
restart, and local write contention never fails it. The first commit has the
coordinator take an `ERESUME` cursor that names a retained delivered row past
its committed acknowledgement as that row's cumulative `EACK`, committed
before `ERESUME OK`. The second has the edge admit each event at the next
exact cursor after the events still committing or queued, acknowledge an
exact duplicate at its installed cursor again without reapplying it, and
resume from the cursor its last event commit installs. The third keeps the
coordinator's link traffic and companion batches waiting while any batch is
open, so local write contention never fails a link. No specification,
profile hash, registry entry, named limit, reply code, wire object, table,
key, row kind, field or storage generation changed.

## Decision: the reading of companion Section 12.5 for a resume cursor

The companion text, Section 12.5, on the resume:

> After a same-incarnation link reconnect and profile negotiation, the edge
> sends ERESUME with its durable cursor. Both star fields are present
> together only before sequence zero. Otherwise both are concrete and
> identify the exact last ACK. The coordinator's peer record retains that
> cursor even after deleting the corresponding event body. It returns ERESUME
> OK with zero or the next sequence and retransmits every unacknowledged row
> byte-for-byte. A generation, incarnation, cursor, or event-ID mismatch is
> fatal and cannot be repaired by guessing a later cursor.

On the acknowledgement it resumes from:

> The edge admits the complete event and payload, validates the next exact
> cursor [...]. That one transaction applies any route/projection change,
> [...] advances the event cursor, and records any locally required pending
> fanout. Only after commit does it make frames visible and send EACK. [...]
> EACK is cumulative through its named sequence and is accepted only when its
> Event ID matches that delivered row; outside a cross-profile barrier it
> advances by exactly one.

> Cross-profile parts instead stage and commit under the base Section-20.8
> combined transaction; no individual part advances this cursor or emits
> EACK.

> Unacknowledged event rows are never evicted or replaced by a route
> snapshot.

The base profile's resume, Architecture Section 20.9: "If the exact cursor is
retained, the coordinator replies `FRESUME OK` and replays the next event."

The reading this topic implements:

- The edge's durable cursor is the last position it acknowledged: it sends
  the `EACK` only after the commit that installs the cursor. The
  coordinator's record is the last acknowledgement it committed. When an
  `EACK` is lost on the way, in a link cut or across a coordinator restart,
  the two differ: the edge's cursor names a later row, which the coordinator
  delivered and still retains, since unacknowledged rows are never evicted.
- Such a cursor is not a mismatch. It names a row of this delivery
  generation, past the committed acknowledgement, at the end of a contiguous
  unacknowledged prefix, with that row's exact Event ID, a fresh random value
  the edge can only have learned from the row itself. It carries exactly what
  the lost `EACK` carried, so the coordinator applies it as that `EACK`
  ("cumulative through its named sequence and [...] accepted only when its
  Event ID matches that delivered row"), commits it before `ERESUME OK`, and
  `ERESUME OK` then names the following sequence and retransmits every row
  still unacknowledged. The coordinator guesses nothing: the cursor names the
  row and its identity, and the coordinator checks both against its own
  retained row.
- Several acknowledgements may be lost in one cut, each of which advanced by
  exactly one. The cursor then covers their whole prefix, as an `EACK` is
  cumulative. Inside an open cross-profile barrier the edge's cursor can stop
  only before the barrier or at its end, since no part advances it alone;
  rows after a barrier stay held until both profiles acknowledged it.
- Every other cursor remains a fatal mismatch, as the text says: another
  generation or incarnation; a cursor behind the committed acknowledgement;
  a row this stream never delivered or no longer retains; another Event ID; a
  gap in the unacknowledged prefix; a barrier part other than the barrier's
  end; and a row a barrier still holds back. The coordinator never moves a
  cursor the edge did not name.
- This matches the base profile, whose coordinator already reconciles a
  retained `FRESUME` cursor past its committed acknowledgement durably before
  `FRESUME OK`, and the companion barrier resume, which already accepts a
  cursor at a barrier's end as the cumulative acknowledgement of the ordinary
  prefix before it.

## A resume cursor past the committed acknowledgement is its lost EACK (first commit)

The rules, in `crates/agenc-relay-runtime/src/e2ee/coordinator/` and
`crates/agenc-relay-runtime/src/federation/coordinator/companion.rs`:

- **The cursor names a retained delivered row.** An `ERESUME` whose cursor
  differs from the committed acknowledgement is admitted only when it names
  an unacknowledged retained row of the stream's generation, at the end of a
  contiguous unacknowledged prefix, with its exact Event ID
  (`DeliveryStream::validate_resume`, `validate_prefix`). Inside an open
  barrier only the barrier's end qualifies (`validate_barrier_resume`), and a
  row past the barrier's held end is refused whether or not this profile
  already acknowledged the barrier (`hold_after`). Any other cursor is a
  violation, and nothing is staged.
- **Its acknowledgement commits before ERESUME OK.** The admitted cursor
  stages the cumulative acknowledgement through the named row, with its
  replay ledger rows, as an ordinary or barrier acknowledgement is staged
  (`prepare_resume`, `PreparedAck`); the coordinator sends nothing on the
  link until that batch commits. Its receipt records the acknowledgement
  (`DeliveryStream::acknowledge_resume`), and only then does `ERESUME OK` go
  out, naming the sequence after the named row, with every row still
  unacknowledged retransmitted (`resume_ack_committed`). A cursor before an
  open barrier leaves the barrier open; its rows are retransmitted and
  acknowledged by their own `EACK`.
- **An acknowledgement that does not persist retires its link.** When
  storage refuses the batch of a companion acknowledgement, a resumed one or
  an ordinary `EACK`, the coordinator fails its live link, as it already
  does for a base acknowledgement (`reject_pending_batch`). The edge resumes
  from its durable cursor, which names the same row again, and the next
  link commits it.
- **A resume needs no barrier.** A resumed acknowledgement is staged whether
  or not a barrier is open (`companion::stage`); a cursor at or past a
  barrier's first part must still name its end
  (`federation::coordinator::barriers::prepare`).
- **An ordinary EACK on a live link still advances by exactly one**
  (`DeliveryStream::acknowledge`); only a resume carries a cursor that skips
  ahead.

| Test | What it pins |
| --- | --- |
| `e2ee::coordinator::events::resume_cursor_tests::a_cursor_naming_a_delivered_row_past_the_committed_ack_is_admitted` | Every delivered row past the committed acknowledgement may be the edge's last, one or several rows ahead. |
| `e2ee::coordinator::events::resume_cursor_tests::a_cursor_naming_no_retained_delivered_row_is_refused` | Another row's or an unknown Event ID, a row never delivered, the committed row under another ID, a cursor behind the committed acknowledgement, a gap, and a committed acknowledgement with no successor are refused. |
| `e2ee::coordinator::events::resume_cursor_tests::inside_an_open_barrier_only_its_end_and_never_a_held_row` | A row before an open barrier and the barrier's end are admitted; a part before the end and a held row are refused, and a held row stays refused after this profile acknowledged the barrier. |
| `e2ee::coordinator::events::resume_cursor_tests::a_resume_acknowledges_the_prefix_cumulatively` | An unacknowledged receipt records nothing; the resume acknowledges every row through the named one and leaves an open barrier after it open. |
| `e2ee::coordinator::tests::sync::delivery_restart::a_lost_ack_cursor_after_a_real_restart_commits_before_resume_ok` | Through real storage: after a restart the edge's cursor names the last delivered row; the resume stages its acknowledgement and sends nothing, the commit's receipt sends `ERESUME OK` naming the next sequence, every row is acknowledged, and after another restart the same resume is exact. |
| `federation::coordinator::tests::combined_barriers::lost_acks::a_resume_naming_a_lost_ordinary_ack_commits_it_before_resume_ok` | Through the federation coordinator and real storage, with an open barrier after two ordinary rows: a resume naming either ordinary row stages one batch and sends nothing before its receipt; then `ERESUME OK` names the next sequence, every later row is retransmitted, the barrier stays stored, and a restart reloads the acknowledgement. |
| `federation::coordinator::tests::combined_barriers::lost_acks::a_resume_naming_no_retained_delivered_row_stays_fatal` | Another row's Event ID, a row never delivered and an unknown Event ID are violations; nothing is staged or sent, and a restart finds no acknowledgement. |
| `federation::coordinator::tests::combined_barriers::lost_acks::a_resume_acknowledgement_storage_refused_retires_its_link` | Through real storage: storage refuses the resumed acknowledgement's batch; the link is retired with nothing recorded or sent; on the next link the same cursor commits, `ERESUME OK` names the next sequence and the later rows are retransmitted, and a restart reloads the acknowledgement. |
| `federation::coordinator::tests::combined_barriers::lost_acks::an_acknowledgement_storage_refused_retires_its_link` | Through real storage: storage refuses an ordinary `EACK`'s batch on an active link; the link is retired and nothing is recorded. |

The restart test above replaces
`e2ee::coordinator::tests::sync::delivery_restart::current_profile_exposes_the_lost_ack_cursor_mismatch_after_a_real_restart`.
The barrier resume tests call the renamed `acknowledge_resume`.

Single edits fail tests, each run on the tests above and the barrier resume
tests: requiring an open barrier for a resume in `validate_resume` fails
five; dropping the held-row check fails one; dropping the barrier-end rule
fails one; accepting the named row under any Event ID fails two; restoring
the barrier requirement in `prepare_resume` fails two; restoring it in
`companion::stage` fails one; keeping the link of a refused acknowledgement
fails both refusal tests; and retiring it only for a resumed one fails the
ordinary refusal test.

The release coverage policy gains `companion-resume-cursor` and
`companion-resume-prefix` (branches), and re-reviews and respans
`cap79-maintenance-056-reject-pending-batch`,
`s10-cap70-companion-ack-prepare-resume`,
`s10-cap94-validate-barrier-resume`,
`s10-cap94-acknowledge-barrier-resume` (whose item is now
`acknowledge_resume`), `companion-acknowledgement-preparedack-apply` and
`companion-companion-stage`; the other regions of the changed files move
with unchanged spans. Both source inventories are refreshed.

## The edge admits events in order and acknowledges a duplicate again (second commit)

The companion text this rule implements, Section 12.5:

- "The edge admits the complete event and payload, validates the next exact
  cursor and all route/origin/source constraints, and obtains the complete
  bounded client-fanout reservation before opening its apply transaction";
  "Only after commit does it make frames visible and send EACK".
- "An exact duplicate at the installed cursor is re-ACKed without
  reapplying state or rerendering; a gap, conflicting ID/object, decreased
  state generation, or other generation blocks E2EE processing and closes
  the link."
- "After a same-incarnation link reconnect and profile negotiation, the edge
  sends ERESUME with its durable cursor"; the coordinator "retransmits every
  unacknowledged row byte-for-byte".

The rules, in `crates/agenc-relay-runtime/src/e2ee/edge/events.rs`,
`sync.rs` and `crates/agenc-relay-runtime/src/registration.rs`:

- **An exact duplicate at the installed cursor is acknowledged again.** An
  ordinary event whose delivery generation, sequence and Event ID equal the
  installed cursor is answered with its `EACK` again; nothing applies,
  commits or renders (`acknowledge_duplicate`). The edge keeps the object
  identifier of the event it applied last beside its position, in memory
  only, and a duplicate whose object differs from it is refused and the link
  closes. When the cursor moved otherwise, by a restart, a snapshot or a
  barrier, that object is unknown and the Event ID identifies the event. The
  installed sequence under another Event ID, a sequence behind the cursor
  and another generation are still refused, and the link closes.
  Cross-profile parts are acknowledged by the combined transaction alone
  (Section 12.5: "no individual part [...] emits EACK") and are not covered
  by this rule.
- **The next exact cursor follows the events already admitted.** An event
  is admitted at one past the last event the edge admitted, whether that
  event is installed, committing, or queued behind a commit
  (`next_admitted_sequence`), so an event admitted while an earlier one
  commits or waits takes its exact place. A gap is still refused.
- **An event waits while the state core cannot take its batch.** It queues,
  in order, while the edge's own commit is open, while a batch is in flight,
  or while another router gathers a batch (`holds_events`), and while earlier
  events still wait (`admit_ordinary`). Every receipt drains the queue in
  order, and so does every refusal: once every role has settled a batch that
  storage refused, the router applies the events that waited for it
  (`RegistrationRouter::drain_e2ee_events`,
  `E2eeEdge::drain_waiting_events`). The state core reads link traffic only
  while no batch is open, so the queue holds only events admitted behind the
  batch they wait for and never outlives it; it needs no bound of its own.
- **A resume names the cursor its event commit installs.** While an event's
  commit is in flight, the next link's `ERESUME` waits for its receipt
  (`link_active`). The receipt sends the event's `EACK` only on the link
  that delivered it, in the origin or active phase (`acknowledge_applied`);
  after link loss the next `ERESUME` names that cursor instead.

| Test | What it pins |
| --- | --- |
| `e2ee::edge::tests::projection::event_admission::an_exact_duplicate_at_the_installed_cursor_is_acknowledged_again` | An exact duplicate at the installed cursor gets its `EACK` again with nothing staged; the installed sequence under another Event ID, a sequence behind the cursor and another generation are refused. |
| `e2ee::edge::tests::projection::event_admission::a_duplicate_carrying_another_object_at_the_installed_cursor_is_refused` | After an event applies, another object under its position and Event ID is refused with no `EACK`, and the exact object is acknowledged again with nothing staged. |
| `e2ee::edge::tests::projection::event_admission::the_next_events_wait_behind_the_one_committing` | While the first event commits, the next two are admitted and queued, a gap past them is refused, and the three commit and are acknowledged in order. |
| `e2ee::edge::tests::projection::event_admission::an_event_waits_while_another_router_gathers_a_batch` | An event that arrives while another router's batch gathers is queued, applies at that batch's receipt and is acknowledged at its own. |
| `e2ee::edge::tests::projection::event_admission::events_stay_in_order_behind_a_refused_batch` | After storage refuses the batch an event waited for, the event applies at the refusal; the next event queues behind it, and the receipts acknowledge both in order. |
| `e2ee::edge::tests::projection::event_admission::an_event_never_applies_ahead_of_one_still_waiting` | With an event still waiting and no batch open, the next event queues behind it, and a drain applies both in order. |
| `e2ee::edge::tests::projection::event_admission::a_resume_names_the_cursor_its_event_commit_installs` | The link closes while an event commits: no `ERESUME` goes out before the receipt, the receipt sends no `EACK`, and the `ERESUME` then names the event's position. |
| `registration::e2ee_line_tests::companion_events_waiting_for_a_refused_batch_apply_at_the_refusal` | Through the registration router: an event that waits for another router's batch applies when the router settles that batch's refusal. |

Single edits fail tests, each run on the edge and registration router
tests: dropping the duplicate rule fails the two duplicate tests; admitting
only at the installed cursor fails the committing and refused-batch tests;
holding events only for a batch in flight fails the gathering, refused-batch
and router tests; resuming during an event commit fails the resume test;
sending the receipt's `EACK` whatever the phase fails the resume test;
applying an event while earlier ones still wait fails the ordering test;
ignoring a conflicting object, or not recording the applied object, fails
the object test; draining nothing at a refusal fails the refused-batch and
router tests; and a router that does not drain at a refusal fails the router
test.

The release coverage policy gains `edge-event-admission`,
`edge-duplicate-event` and `edge-applied-event-ack` (branches) and
`edge-event-hold` (regions), and re-reviews and respans
`cap74-sync-link-active`; the other regions of the changed files move with
unchanged spans. Both source inventories are refreshed.

## Local write contention never fails a link (third commit)

The state core stages one batch at a time: a plan staged while a batch is in
flight, or while another router's batch gathers, is refused as busy, since
it cannot join that batch. The rules, in
`crates/agenc-relay-runtime/src/federation/coordinator/`:

- **Link traffic waits while any batch is open.** Base frames and objects
  and admitted companion frames wait in the coordinator's backlog, in
  arrival order, while a batch is open, the coordinator's own or one another
  router staged, and while companion work owns the next batch
  (`FederationCoordinator::holds_traffic`, used by `inbound` and
  `drain_backlog`). Every commit and every refusal replays the backlog. A
  base `FACK`, an origin declaration or a snapshot `READY` that arrives
  while another router's batch is open therefore stages its batch once that
  batch settles, as each already did behind the coordinator's own batch.
  The backlog's bound is unchanged.
- **A companion batch waits for a free slot.** A companion batch that finds
  a batch open, staged after a commit (a snapshot page, a fetch), after a
  storage read (an acknowledgement prefix, a page) or by a frame, is held
  (`companion::stage`, `HeldStage`) and staged once no batch is open
  (`stage_held`), first at the next commit's receipt and also after a
  refused batch; at a receipt where an earlier role has already staged its
  next batch, it stays held for that one. While it is held, companion work
  owns the next batch
  (`companion_busy`): link traffic, queued companion and base requests,
  background work and a reload wait for it. A refusal when it is finally
  staged is the batch's own and fails its link as before.
- **Queued requests wait for an open batch.** A companion request arriving
  while any batch is open joins its peer's queue (`execute_or_queue`), and
  the queue drains only when no batch is open and no other companion work
  owns the next one (`companion::drain_queued`). Queued base requests also
  wait while companion work owns the next batch (`request::drain_queued`),
  so a companion read's completion never finds a batch of this coordinator
  open. A refused batch drains both queues and the backlog, as a receipt
  does (`batch_rejected_with_error`), and so does a receipt that retires
  its link because its request cannot settle (`batch_applied`).
- **A quarantine waits for an open batch.** `PEER QUARANTINE` is refused as
  busy while any batch is open or companion work owns the next batch,
  before it changes anything; a fence that storage does not take leaves the
  peer unquarantined (`admin_quarantine_peer`).

The held batch is boxed: it adds one pointer to the coordinator.

| Test | What it pins |
| --- | --- |
| `federation::coordinator::tests::combined_barriers::write_contention::a_base_ack_waits_while_another_router_has_a_batch_open` | Through real storage: a base `FACK` that arrives while another router's batch gathers waits in the backlog; that batch's receipt replays it, it stages and commits, and the link stays up. |
| `federation::coordinator::tests::combined_barriers::write_contention::a_companion_frame_waits_while_another_router_has_a_batch_open` | An admitted companion frame waits in the backlog while another router's batch is open, and nothing is staged or sent. |
| `federation::coordinator::tests::combined_barriers::write_contention::a_companion_batch_that_finds_a_batch_open_is_staged_when_it_settles` | A resume acknowledgement staged while another router's batch is open is held, holds link traffic and any reload, and is staged at that batch's receipt or after storage refuses it; `ERESUME OK` follows its own commit. |
| `federation::coordinator::tests::companion_refusals::a_companion_request_waits_while_another_router_has_a_batch_open` | A companion request arriving while another router's batch is open joins its queue, a drain then leaves it there, and the batch's receipt runs it at its sequence. |
| `federation::coordinator::tests::combined_barriers::ack_read::a_queued_base_request_waits_for_a_companion_read_in_flight` | A queued base request does not run while a companion acknowledgement read is in flight; the read then stages its acknowledgement. |
| `federation::coordinator::tests::combined_barriers::write_contention::a_held_batch_stays_held_while_another_batch_opens_at_its_receipt` | The batch a held one waited for commits, and another router stages its next batch before the coordinator's receipt: the held batch stays held with the link up, is staged at the next receipt, and `ERESUME OK` follows its own. |
| `federation::coordinator::tests::companion_refusals::a_companion_request_waiting_for_a_refused_batch_runs_at_the_refusal` | Storage refuses the batch a queued companion request waited for: the refusal runs the request, which is answered at its sequence. |
| `federation::coordinator::tests::a_receipt_that_retires_its_link_still_replays_the_backlog` | A receipt whose request cannot settle retires its link, and another peer's frame waiting in the backlog still runs. |
| `federation::coordinator::tests::combined_barriers::write_contention::a_quarantine_is_refused_while_a_batch_is_open_and_changes_nothing` | With another router's batch open, or a companion batch held, `PEER QUARANTINE` is refused as busy, the peer stays unquarantined and its link up. |

`federation::coordinator::tests::a_request_waits_while_another_router_has_a_batch_open`
now requires the request to wait in the backlog rather than in its peer's
request queue.

Single edits fail tests, each run on the coordinator tests above, the
combined barrier and companion refusal tests: holding traffic only for the
coordinator's own batch fails three; refusing a companion batch that finds a
batch open fails the held-batch test; staging the held batch at no commit,
or at no refusal, fails it as well; running a companion request into
another router's batch fails the request test; not counting the held batch
as companion work fails the held-batch test; letting queued base requests
run during a companion read fails the read test; draining companion
requests while another router's batch is open fails the request test;
staging the held batch whatever batch is open fails the receipt-order test;
not draining companion requests at a refusal fails the refused-request
test; stopping at a receipt that retires its link fails the backlog test;
and refusing a quarantine only for the coordinator's own batch fails the
quarantine test.

The release coverage policy gains `companion-companion-stage-now`
(regions), `companion-held-stage` (branches), `coordinator-traffic-hold`
and `coordinator-companion-busy` (regions) and
`coordinator-quarantine-admission` (branches); re-reviews and respans
`companion-companion-stage` (now the hold decision of `stage`),
`cap81-mod-federationcoordinator-batch-rejected-with-error`,
`cap79-maintenance-056-reject-pending-batch`,
`cap79-mailbox-expiry-027-batch-applied` and
`cap79-request-expiry-022-apply-pending-receipt`; and moves the other
regions of the changed files, whose spans are unchanged. Both source
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

Not run here: the full stage-nine gate, which cannot finish on this host.
