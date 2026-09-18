# Stage 10 incremental online backup

This record closes STO-05 (issue #68). `BACKUP CREATE` ran three whole-database
passes on the storage owner thread before it yielded once: `start_backup`
called `startup_scan` (the full integrity, reference and history
reconstruction, itself building a recovery scratch and replaying every
retained manifest) and then `verify_snapshot_accounting` (a second decrypt of
every row) synchronously, and `BackupJob::finish` ran the complete
`verify_backup` pass in one call. Only the copy between them was sliced. A
commit or read queued behind a backup of a large database waited for each of
those passes to finish. The backup format, the receipt, the `BackupDestination`
and `BackupOutput` publication contract of STO-06 (#48), the `backup_stream_bytes`
contract and the storage format are unchanged.

The issue was written against a published upstream redb release. That plan is
withdrawn: the bounded write transaction is the project-owned fork at
`vendor/redb-4.2.0` (STO-02 record), and "published release" reads "this
vendored source" throughout.

## The phase machine

`crates/agenc-ircd-storage/src/engine/backup_job.rs` owns the online backup
as a phase machine. `StorageEngine::start_backup` captures the cut and every
later `service_backup` call runs one bounded slice of one phase and returns,
so `owner_step` admits a queued request beside every slice exactly as it does
for a checkpoint scan. The slice budget is the Section 23.5.2 service slice,
4,096 records or 16 MiB, for the accounting, resolution, copy and
verification passes.

1. **Capture** (`start_backup`, nothing proportional to the database). The
   single snapshot slot is taken (`QueueFull` if a backup or checkpoint is
   active), the table inventory and meta membership are checked, the
   reservation and guard are re-authenticated, the pair must classify as an
   exact committed or reserved boundary through `classify_recovery_state`,
   the `BackupHeader` is built (which runs `verify_guard_pair`), the engine's
   authenticated `StateMeta` is copied, and one redb read transaction is
   opened. No file is created.
2. **Accounting.** Each slice of that read transaction is decrypted and
   checked through the same `BackupRecordVerification` the post-write pass
   uses (seal, key generation, closed schema, singleton, manifest-chain,
   checkpoint and history accumulators), plus the startup scan's per-row
   domain checks (reference legality, required references, the private index
   binding). The logical and exact stream counters are recomputed row by row
   and refuse `LimitExceeded` the moment either passes its ceiling. Every
   integrity-tracked row's identity and references go into a scratch redb
   database through one bounded transaction per slice. The last slice binds
   the accumulators and the recomputed stream length to the authenticated
   `StateMeta` row of the cut, and that row must equal the engine's copy. The
   exact final length `O` is fixed here, before any output exists.
3. **Resolution.** Every recorded reference must resolve to a recorded row,
   read back in slices from the scratch. The scratch is dropped on the way
   out of this phase.
4. **Admission.** The temporary is created in the backup directory and
   admitted at `R(F) + O` by the unchanged `admit_backup_output`, then the
   magic and header are written with `O` as the writer's ceiling.
5. **Copy.** The read transaction is reset and streamed again, slice by
   slice, through the same writer.
6. **Seal.** The trailer is signed and written; the temporary's length must
   be exactly `O`; the post-write verifier is opened on a duplicate of the
   same descriptor.
7. **Verification.** `BackupStreamVerifier` re-reads the temporary frame by
   frame in slices. The last slice binds the trailer's count, digest and
   signature to what was observed and requires the verified length, trailer,
   `StateMeta` and header to equal the sealed trailer and the captured cut.
8. **Publication.** `BackupOutput::publish` renames the verified inode in
   place, exactly as STO-06 left it, and the receipt reports the verified
   length, count and digest.

A failure in any phase drops the job: `BackupOutput` unlinks the temporary,
the scratch guard unlinks the scratch, the completion holder gets the error,
and nothing is published. `StorageOwner` shutdown now cancels a backup still
in its phases the same way (its holder receives `Unavailable`) instead of
waiting behind it; a dropped completion receiver cancels nothing, and the
artifact is still published under its name.

## One authenticated cut

The read transaction opened at capture is the only snapshot the job ever
reads: accounting and copy both iterate it, and `SnapshotScan::reset` rewinds
it between them. Writers advance freely between slices and never change what
the job sees. The proof is byte identity: the engine-level test takes one
quiescent backup, then a second at the same cut with the same creation time
and identity while a new row is committed between every slice of every phase,
and the two files are equal byte for byte (same length, same digest, same
signature); a third backup after those commits sees them. The same proof runs
through the real `StorageOwner` with a 4,200-row corpus (at least two
production slices per pass) and three commits submitted behind the backup
request.

`backup_stream_bytes` keeps its contract from both sides: the accounting phase
recomputes it from the cut and must find the authenticated value before the
temporary is created, the writer refuses any byte past it, the seal requires
the file length to equal it, and the post-write pass recomputes it once more.

## The bounded scratch

The reference scratch is the one place the online backup path writes a redb
database, and it is written only through the fork's bounded API:
`Database::begin_write_bounded(AllocationAllowance)` with
`set_two_phase_commit(true)`, `prepare` and `PreparedTransaction::publish`
for every slice, and `Database::persist_allocator_state_bounded` at close so
dropping the database never runs an unmetered transaction. The allowance is
the Section 19.3 per-transaction growth ceiling `G` (256 MiB); one slice
records at most the identities and references of 16 MiB of sealed rows, far
inside it. References are keyed by the row's ordinal in cut order and the
reference index, so a row's identity is stored once however many references
it carries and the scratch bytes of a slice stay proportional to the slice.
A refusal, wherever the fork raises it (a table operation, the preparation or
the publication), is the determinate `AllowanceRefused` with its phase; it leaves the scratch
exactly as it was and the following backup runs. The scratch database is
created with `set_region_size(64 MiB)`: a bounded database is created with
regions of at most half its allowance, because every file extension is
charged at full length and the file grows by up to two regions at a time.

The scratch is not admitted against the filesystem reserve. It exists only
during accounting and resolution, is unlinked before the output is admitted
at `R(F) + O`, and lives in the state directory under the recovery-scratch
prefix that `StateDirectory::open` sweeps, so a kill between phases leaves
nothing the next open does not remove. An `R(F) + G` admission on it would
have refused the Section 28.7 backup boundaries whenever the state and backup
directories share a filesystem, which the qualification workload's boundary
cases do. `reclaim_bounded` is not used: a single-use scratch that is
unlinked has nothing to reclaim.

After the storage lanes were stacked, the scratch was moved onto STO-04's
(#65) shared `ScratchDatabase` (`src/scratch.rs`) and STO-03's (#61) error
mappers (`map_table_error`, `map_write_error`): bounded transactions, the
64 MiB regions, the bounded close and the unlink are its, and the allowance
is fixed when the scratch is created. What stays private to the backup is the
reference layout (identities, ordinal-keyed references, sliced resolution),
the two-phase setting on each transaction, and an admission that always
admits, which is the deliberate no-`R(F) + G` decision above. The
full tracked-record replay against the retained manifests that
`verify_integrity_ledger` performs is not run by the backup: it is the
whole-database phase this issue removes, its bounded form is #65's, and the
manifest chain, checkpoint facts and counters the backup format authenticates
are checked by the reconstruction accumulators on both passes.

## Indeterminate outcomes

Nothing in the backup path writes the main database. No backup outcome is a
claim about durable state, so a failure is always reported as the error the
phase raised, with the temporary gone; the Section 21.5 indeterminate path
belongs to the write path alone. A real I/O failure inside the scratch is
`DatabaseRejected`, and the scratch is discarded with the job. After the
rename, the STO-06 retraction rule is unchanged: a failure retracts the final
name only if it still refers to the verified inode.

## Tests

Engine level, `crates/agenc-ircd-storage/src/engine/backup_job/tests/phases.rs`:
the byte-identity proof under interleaved commits with every phase serviced
in at least two slices; a `BackupRecord` fault on both sides of the first row
of each pass (accounting, copy, verification) refusing with no temporary, no
scratch and the same name publishing on retry; every publication fault site
on both sides; a zero and a one-byte scratch allowance refusing determinately
with a following backup publishing; ceiling exhaustion refusing during
accounting before any output and during verification before publication; a
dangling reference refused during resolution; the largest legal record
forming its own slice in every pass; the single snapshot slot against a second
backup and a checkpoint, and an orderly restart in each of the seven phases
leaving nothing behind. Owner level,
`crates/agenc-ircd-storage/src/owner/tests/backup_phases.rs`: a read or a
commit served beside every phase and both beside every sliced pass, the cut's
row count unchanged; shutdown cancelling an active backup with its temporary
gone; a dropped receiver neither cancelling nor leaking; a competing backup
waiting for the slot. Through the real `StorageOwner`,
`crates/agenc-ircd-storage/tests/stage_five_completion/backup_phases.rs`: a
backup that fits writes exactly the authenticated length and equals the
single-cut stream with commits submitted behind it; a refusal at each pass
boundary leaving no temporary with the same name retrying; the `R(F) + O - 1`,
equal and plus-one admission boundaries against the live filesystem (the
fixed reserve is placed from a `statvfs` sample and an attempt whose outcome
the moving free space contradicts is resampled); and stale temporaries from a
killed backup swept by the next open and the next backup, plus an orderly
stop with a backup pending. The existing
`real_startup_and_backup_inject_read_and_publication_boundaries`,
`audit_backup_rename_error_leaves_final_name_and_blocks_retry`, the restore
and construction-reader suites and the daemon's `BACKUP CREATE` transcript
run unchanged.

## Limitations

The slice budget bounds records and bytes, not wall time; a 16 MiB record is
one slice. The scratch's growth is bounded per transaction by `G` and not
admitted against the reserve, as recorded above. Fairness is proved
deterministically at the owner level with a shrunken slice budget and through
the real owner with a corpus larger than one production slice; the production
budget itself is the checkpoint scan's. Native release qualification of the
whole path remains with REL-10 (#84).
