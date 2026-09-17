# Durable object ownership

This record closes ENC-08 (issue #53): every accepted table-22 object now
carries a durable ownership account, the per-conversation and global disk
quotas of companion Sections 15 and 16 are enforced before a batch stages,
and startup reconstructs the accounts from the authoritative rows without
inventing an age. Nothing here deletes an object; physical cleanup remains
ENC-09's, which now has complete owner, class, and trusted-age inputs.

## Owner matrix

The owning set of an object is derived from the table-23 rows that name it,
never declared separately, so one derivation (`owners::owned_by`) serves live
batches and startup alike. The creation and retirement transaction of every
owner is the batch that puts or deletes its row.

| Row | Objects owned | Class | Conversation charge |
| --- | --- | --- | --- |
| `route/v1/` | the route state object | security proof | yes |
| `reservation/v1/` | the reservation object | ordinary | no |
| `record/v1/` | the sequencer record | security proof when the row is flagged, else ordinary | yes |
| `candidate/v1/` | the candidate Commit | ordinary | yes |
| `approval/v1/`, `ack/v1/`, `vote/v1/` | the retained proof object | ordinary | yes |
| `policy/v1/` | the policy | security proof | yes |
| `membership/v1/` | the leaf-membership proof | security proof | yes |
| `identity/v1/` | the root identity and its chain objects | security proof | no |
| `roster/v1/`, `binding-lock/v1/` | the roster; the lock object | security proof | no |
| `capability/v1/` | the capability object | ordinary | no |
| `package/v1/`, `claim/v1/` | the KeyPackage; the claimed package | ordinary | no |
| `attach/v1/` | the open challenge object | ordinary | no |
| `mailbox/v1/`, `token/v1/`, `ack-mailbox/v1/` | the item object | mailbox | no |
| `replay/v1/irc-mls-v1/` | the request, result and response objects | replay | no |
| `cross-profile/part/v1/`, delivery outbox rows | the event and payload objects | replay | no |

Rows of other kinds own nothing. A row naming an object this coordinator
never retained (an edge-held event) charges nothing. A completed
`DeviceAttach` object and, in the in-process harness, request and result
objects without replay rows are retained unowned: they are never deleted and
their account records that no row names them.

The class an account carries is the strongest any owner ever implied
(security proof over ordinary over mailbox over replay) and never weakens
while the object is retained, so ancestry protection survives the retirement
of the row that introduced it. `retired_at` is set by the batch that deletes
the last owner and cleared by any batch that names the object again.

## Durable account

`owner/v1/<object-id>` (state record kind 16) persists the object kind,
complete encoded size, retention class, trusted acceptance second, whether
that second is a reconstruction floor, and the trusted retirement second.
The owning rows are the record's typed references, at most
`MAX_RECORD_REFERENCES`, so a reader validates key, body and references
together. The row is written by `owners::stage` alone; a batch that puts one
itself is refused as `E2EE_INVALID_FRAGMENT`.

`CompanionCoordinator::stage_owners` runs at every batch site: request
execution, companion acknowledgements, publications and snapshots, mailbox
and request expiry, replay maintenance, and startup retirement. It derives the
accounts the batch changes against the retained ledger, checks the quotas,
appends the owner rows at the batch revision, and returns the accounts, which
install only when the batch commits (`batch_applied`, the request effects, or
the worker receipt). A rejected batch installs nothing. The acceptance time
is the trusted UTC second the batch was admitted with; a batch that changes
any account without a trusted clock is refused as `E2EE_RATE_LIMITED`.
Upload time and cache residency play no part.

Time is the trusted UTC second the batch was admitted with. A batch that
introduces an account or an owner without a trusted clock is refused
(`E2EE_RATE_LIMITED`); a batch that only retires owners without one, such
as maintenance running while the wall clock is untrusted, records the
retirement at the undated second `UNDATED_SECOND` (`u64::MAX`), and a
reconstructed account persisted by such a batch keeps that undated
acceptance floor. The next dated batch that touches the account replaces
the undated second with its own; nothing ages by it. A `storage restore`
does not carry replay, delivery, barrier or delivery-recovery rows, so it
drops an account's references to them and retires an account whose every
owner it dropped at the undated second; startup then reconciles the
restored accounts against the rows exactly as after any restart.

## Quotas

An object is charged once to every conversation whose rows name it, however
many rows do, and once to the global total. Before any row is staged:

- a conversation's charge may not exceed `MAX_STORED_BYTES_PER_CONVERSATION`;
- a proof-producing batch (`security_mutation`) that grows a conversation
  must leave `RECOVERY_HEADROOM_BYTES` free below the quota, so a finalized
  close, its route state, the open recovery submissions of Section 13.7.4 and
  the leaf proofs a close names always fit; retirements need no headroom;
- a nonzero `e2ee.global_disk_bytes` bounds the global total.

A refusal is `E2EE_RATE_LIMITED`, changes nothing, and deletes no ancestry.
`ConversationState::stored_bytes` mirrors the ledger's per-conversation
charge after every commit and reload.

## Reconstruction

Startup reads every object's identity, kind and size, every owner row, and
the owners every other row derives, then reconciles once all rows are known:

- an account naming exactly the rows that name its object, with the object's
  kind and size and a retirement matching its owner count, is trusted as
  stored;
- an account whose references, retirement or object disagree with the rows is
  rebuilt from the rows (`mismatched`); the trusted acceptance second is kept
  when the row proved the same object and dropped otherwise;
- an object without an account is rebuilt from the rows with an unknown age
  (`reconstructed`, `accepted_at = 0`), and counted `unowned` when no row
  names it; the first later batch that touches it dates it as a floor;
- an account whose object no longer exists is ignored (`orphaned`); a row
  that does not decode restores nothing (`undecodable`).

The result is `CompanionCoordinator::owner_reconstruction`; a clean store
reports zero in every field. No account is invented with an age, so
reconstruction cannot make an existing proof older than its evidence.

## Evidence

- `crates/agenc-ircd-storage/tests/e2ee_records.rs`: the owner row codec
  round trip and every inconsistent account refusal (unknown kind, empty or
  oversize object, missing acceptance, retirement before acceptance).
- `crates/agenc-ircd-runtime/src/e2ee/coordinator/tests/sequence/owners.rs`:
  one object shared by a security proof, a directory row, a mailbox
  acknowledgement and a replay row retired in all 24 orders with the class,
  conversation charge and retirement checked at every step; the ledger alone
  writes owner rows; an untrusted clock refuses only a changing batch; the
  conversation quota one byte below, at and above 256 MiB; the recovery
  headroom for proof-producing batches and its absence for retirements;
  deduplicated charging of one object across rows and conversations; the
  global ceiling with zero meaning unlimited and atomic refusal; the
  `MAX_RECORD_REFERENCES` owner ceiling; a re-put of an accounted object; a
  barrier part's event and payload objects; a foreign reference or another
  kind discrediting a stored account; startup
  reconstruction of a complete store in both traversal orders, a store
  without owner rows, an orphan account, a short reference set, a wrong-size
  account and a stale retirement; the reconstruction floor taken by the first
  trusted batch; and, through the in-process coordinator, every owner class
  the handlers write sealed and reopened with identical accounts, retention
  classes, acceptance seconds and conversation totals, then reopened without
  its owner rows with the expected diagnostics.
- The existing restart, delivery-restart, origin-replay, mailbox and
  result-memory suites run with the ledger at every batch site.

The delivery-restart fixtures and the in-process harness stage owner rows on
every batch as the coordinator does. Real MLS endpoint evidence remains
outside this record.

Six release critical regions (`e2ee-owner-*`) cover derivation, the ledger
index, batch derivation, owner-row staging, the quotas and reconstruction;
a branch-instrumented run of the coordinator suite reaches every branch
outcome in all six.
