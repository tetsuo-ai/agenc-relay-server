# A federation link resumes after a lost acknowledgement (D-44)

This record covers part 1 of decision D-44 of the SDK server program
(2026-10-07, outside master #35), which follows D-43: a federation link
resumes after an acknowledgement is lost in a link cut or a coordinator
restart, and local write contention never fails it. The first commit has the
coordinator take an `ERESUME` cursor that names a retained delivered row past
its committed acknowledgement as that row's cumulative `EACK`, committed
before `ERESUME OK`. No specification, profile hash, registry entry, named
limit, reply code, wire object, table, key, row kind, field or storage
generation changed.

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
