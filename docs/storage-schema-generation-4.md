# Storage schema generation 4

Generation 4 adds an explicit delivery replay journal and a stopped-daemon
3-to-4 migration. Ordinary service opens only generation 4. An existing
generation-3 directory must be migrated to a new directory before this source
can serve it. Generations 1 and 2 require each preceding migration in order.

This format checkpoint does not repair CAP-79 by itself. Live ACK handling
still uses the earlier retention implementation. The runtime must adopt and
validate the journal, page retained objects, and complete bounded cleanup
before CAP-79 can close. No migration of a deployed database has been performed.

The new body uses E2eeState table 23, delivery record kind 14, protocol profile
1, and inner version 2. Version 1 keeps its exact encoding and decoder. The
generic validator selects the body version explicitly and binds it to its
key namespace. A generation-3 source always uses the version-1 decoder for
kind 14, even when the current record library accepts version 2.

| Inner arm | Key prefix | Body fields after version and arm |
| --- | --- | --- |
| 1: ReplayOwner | `delivery-replay-owner/v1/` | Full DeliveryScope, delivery generation, legacy ACK baseline, latest ACK sequence and event ID, first retained sequence, retained row and byte totals, optional trusted ACK time |
| 2: AckRange | `delivery-ack-range/v1/` | Full DeliveryScope, delivery generation, first and last sequence, last event ID, original acknowledgement metadata |

Both keys include the complete 120-byte scope and delivery generation. Range
keys also include the final sequence. All integer fields use the existing
storage codec's network byte order. The owner body is at most 216 bytes before
the protocol envelope. Decoders enforce complete consumption and exact key
equality. Zero generation, sequence, and event-ID values retain their ordinary
meaning.

The owner describes a contiguous acknowledged suffix. `first_retained` equal
to the latest ACK sequence plus one means an empty suffix. Row and byte counts
must agree with that representation and stay within the published million-row
and 1 GiB limits. Bytes count complete events and required payloads per copy.
The last ACK remains recorded when the suffix is empty. Its legacy baseline
cannot be later than the latest ACK or name a different event at the same
position. Each range covers at most 262,144 rows and carries an acknowledged
state with either the original 24-hour deadline or explicit time uncertainty.
An unavailable timestamp never becomes a fabricated age.

Constructing or decoding these records grants no runtime authority. The
runtime transition must validate the full scope, cursor, contiguous range
coverage, object identities, byte totals, and existing storage preconditions.
The new cursor, owner, range, and any paired barrier change must share one
commit receipt. Physical cleanup must follow the committed retention cutoff
in bounded batches. Undeleted rows and objects continue to count against the
global disk limit. Cryptographic objects and security proofs retain their
longer protocol obligations.

The [3-to-4 registry](storage-migration-3-to-4.registry) uses copy-rule IDs
512 plus the table ID. It preserves validated logical records, rejects live
construction records, and derives binding-dependent keys for the fresh target
database. It does not create ACK history or change existing delivery bytes.
The 1-to-2 and 2-to-3 registry files remain byte-for-byte unchanged.

The command authenticates the exact generation-3 source and validates the
complete mixed audit chain before creating a signed source backup or target.
The source command grammar consists of the frozen generation-2 grammar plus
`AUDIT EXPORT from to maintenance-v1`. Both audit event encodings retain their
original signatures and historical scope. Unknown command meanings, bad
signatures, sequence gaps, unresolved operator intents, and inconsistent
checkpoint anchors are refused.

Migration preserves the server incarnation, recovery epoch, state generation,
account response count, and logical record bytes. It uses a fresh database
instance and incremented storage-key generation. The authenticated profile
hash binds both generations and the exact registry bytes. Resume requires
that same profile and revalidates the source even when a target is already
installed. Restore preserves a backup's generation; restoring generation 3
does not bypass the explicit migration required for service.

Before the migrated target accepts writes, the untouched source and verified
backup remain rollback inputs. After new writes, reopening the old source
would lose newer state and is not a valid rollback. Use the declared recovery
procedure when recovery changes the accepted history.
