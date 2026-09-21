# Expired object collection

This record closes ENC-09 (issue #67): an idle coordinator now physically
deletes expired unowned table-22 bodies. Selection reads only the ENC-08
ownership accounts, one pass is bounded by rows and bytes, its continuation
is durable, and the body, its account and the accounting all leave in one
storage transaction. Nothing here decides retention from anything a client
supplied, and nothing deletes an object any row still names.

## What a pass may take

An account is a candidate only when every one of these holds:

| Condition | Source |
| --- | --- |
| no owning row names the object | the `owner/v1/` references ENC-08 derives |
| the acceptance second is trusted | `accepted_at`, neither `0` nor `UNDATED_SECOND` |
| the retirement second is trusted | `retired_at`, neither `0` nor `UNDATED_SECOND` |
| the class window has elapsed | `now >= retired_at + retention`, on the trusted UTC second the pass was admitted with |

`now` is the wall second the drift monitor accepts (`utc_now` filtered by
`accepts_wall`); without one the pass stages nothing and retries. An account
rebuilt by startup without evidence of an age (`accepted_at == 0`), and an
account a clockless batch retired at `UNDATED_SECOND`, are retained until a
later dated batch dates them. An object still named by any row, and an
object whose account was never written, are never chosen.

The window each class serves after its last owner retired (companion 15
and 16):

| Class | Window | Named limit |
| --- | ---: | --- |
| `SecurityProof` | 30 days | `SEQUENCER_RECORD_RETENTION` |
| `Ordinary` | 30 days | `SEQUENCER_RECORD_RETENTION` |
| `Mailbox` | 7 days | `WELCOME_RETENTION` |
| `Replay` | 24 hours | `ACKED_E2EE_EVENT_REPLAY_TARGET_SECONDS` |

A security proof takes the longest published window rather than
`SECURITY_PROOF_RETENTION`'s `WELCOME_RETENTION` tail: the accounts prove
only that no row names the proof, which is weaker evidence than the final
close that clause measures from, and over-retaining a proof is safe where
under-retaining one is not.

## Bounded pass

`crates/agenc-relay-runtime/src/e2ee/coordinator/object_expiry.rs` reserves
its work buffer before it reads an account, then walks at most
`MAX_EXPIRY_ACCOUNTS` (64) accounts from the continuation, in the key order
of the `owner/v1/` rows, and deletes at most `MAX_EXPIRY_BYTES` (4 MiB) of
bodies. A candidate that would cross the byte budget stops the pass *before*
the cursor names it, so the budget can never hide an unexamined account. The
batch itself reserves output backing before it stages.

`crates/agenc-relay-runtime/src/federation/coordinator/object_expiry.rs` is
the idle owner: a `CompanionObjectMaintenance` timer, independent of peer
connectivity, that runs only when the loader admits, no batch is pending, no
replay read is in flight, and the executor holds nothing. It retries after
one second and idles for sixty after a wrap.

## Durable continuation

`object-expiry/v1` (state record kind 20,
`crates/agenc-relay-storage/src/e2ee_records/expiry.rs`) persists the last
account a committed pass examined, the sweeps that wrapped, and the objects
and bytes deleted since the store was created. The E2EE state ceiling moved
from 19 to 20 and the prefix joined `PREFIX_KINDS`, `validate_state_body`
and the codec fixtures. Startup restores the row into the executor; a
malformed row poisons the reload rather than restarting the sweep at an
invented position.

The row rides the batch that deletes, so the cursor and the counters move
exactly with the deletions they describe: a restart resumes at the page of
the last committed deletion, skips no undeleted account and charges no
deletion twice. A page that deletes nothing changes no accounting and stages
no batch at all — only the live cursor moves — so an idle store writes
nothing and a restart simply re-reads those pages.

## One transaction

Each pass stages, through the existing account-service checkpoint and
`stage_durable_with_account_service`:

- one `E2eeObject` delete per object, keyed by the object identifier;
- one `E2eeState` delete of that object's `owner/v1/` account, which is the
  durable form of the global and per-conversation charge;
- one `object-expiry/v1` put at the batch revision.

`stage_owners` still runs on the batch, as at every other batch site. It
derives no account change from it and appends no row, and it would refuse a
batch that named an owner. An unowned account charges no conversation by
construction, so no conversation total moves; the global total and
`ConversationState::stored_bytes` are re-synchronised from the ledger after
the receipt. Resident bodies, their memory permits and `object_bytes` are
released only in `committed`, against the receipt, never at staging.

## Race safety

Only one batch is in flight, so no reference can commit between a capture
and its receipt. The pass does not rely on that alone: every candidate is
revalidated at capture and again at the receipt against the live account —
no owner, the same retirement second, the same kind, size, class and
acceptance second — and, when the body is resident, against its exact
content identifier and accounted length. A reference accepted after the
capture reinstates an owner and clears `retired_at`, so the acquisition wins
and the pass refuses its own receipt rather than publishing a deletion; the
next capture sees the new owner and chooses nothing.

A determinate refusal publishes nothing, advances no continuation and
retries the same page. An indeterminate write leaves the durable row
authoritative: the batch either committed, and a restart reads the advanced
continuation with the object gone, or it did not, and the next pass chooses
the same page. A receipt lost before publication is recovered by the restart
alone. Cancellation is the ordinary `batch_rejected` path.

## Limitations

- Deleting a logical redb row makes its space reusable; it does not shrink
  the database file, and no claim here is made from total file size.
  Native ext4 growth, reuse and cleanup qualification depends on the
  published backend integration of STO-03 (#61) and is owned by REL-08
  (#81). No measurement here was taken on tmpfs.
- The durable continuation advances only with a batch that deletes.
  Pages that delete nothing are re-read after a restart, which costs a
  bounded idle scan and deletes nothing twice.
- The collector never deletes an object with any accepted owner, an object
  whose account startup could not date, or an object whose account
  disagrees with its body. Such objects are retained, not collected.
- One store has one continuation. Selection order is the object-identifier
  order of the `owner/v1/` rows, not an age order, so a long-expired object
  waits at most one sweep behind a recently expired one.
- Real MLS endpoint evidence remains outside this record.

## Evidence

- `crates/agenc-relay-storage/tests/e2ee_records.rs`:
  `object_expiry_progress_rows_round_trip_and_refuse_inconsistent_totals` —
  the fresh, resumed and wrapped rows round-trip, the singleton key
  classifies as kind 20, and a count without bytes, bytes without a count,
  fewer bytes than objects, trailing bytes, an empty body and a cross-kind
  replay of an ownership account are all refused.
- `crates/agenc-relay-runtime/src/e2ee/coordinator/tests/sequence/object_expiry.rs`
  (14 tests):
  `an_expired_unowned_object_is_deleted_only_at_its_trusted_retention_boundary`
  (the boundary and ±1 second),
  `each_retention_class_waits_exactly_its_published_window`,
  `no_uploaded_or_row_supplied_time_can_accelerate_collection`,
  `an_undated_or_unaged_account_is_retained_rather_than_collected`,
  `a_still_owned_object_is_never_chosen_and_stays_byte_identical`,
  `a_reference_accepted_after_the_capture_keeps_its_object`,
  `a_replaced_body_under_the_same_account_refuses_the_receipt`,
  `one_pass_is_bounded_by_rows_and_two_passes_finish_without_skipping`,
  `the_byte_budget_stops_a_pass_before_its_cursor_names_the_account`,
  `a_pass_stages_the_body_its_account_and_the_continuation_as_one_batch`,
  `the_resident_body_is_released_only_by_the_receipt`,
  `a_restart_resumes_at_the_continuation_the_last_committed_pass_wrote`,
  `a_resumed_continuation_skips_the_accounts_the_committed_pass_examined`,
  and `an_object_record_write_is_never_produced_by_a_collection_pass`.
- `crates/agenc-relay-runtime/src/federation/coordinator/tests/startup_payloads/object_expiry.rs`
  (4 tests against sealed storage through the real timer, staging and
  receipt path):
  `idle_collection_deletes_an_expired_unowned_object_and_survives_restart`
  (the object row, its `owner/v1/` account and the resident body and its
  backing are gone after the receipt, the progress row reads 1 object and 1
  wrap, and a reopen finds the same),
  `a_rejected_collection_keeps_the_object_and_retries_the_same_page`,
  `a_receipt_lost_before_publication_reopens_with_the_object_deleted`,
  and `a_still_owned_object_is_never_collected_by_an_idle_pass`.
- The existing mailbox, request-result and replay maintenance suites, the
  startup payload suites and the ENC-08 ownership suite run unchanged
  beside the new collector.

Commands (Rust 1.98.0, from the repository root):
`cargo fmt --all --check`; `python3 scripts/check-source.py check`;
`cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`;
`cargo test -p agenc-relay-runtime --all-features`;
`cargo test -p agenc-relay-storage --all-features`;
`cargo test -p agenc-relay-e2ee --all-features`.
