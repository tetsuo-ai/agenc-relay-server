# Backup publication repair

This record closes the backup post-rename failure finding (STO-06, issue
#48). It changes no backup format, receipt type, storage format, protocol
registry, cryptographic primitive, or dependency pin; the closed
`BackupReceipt` contract and the administrative backup command are unchanged.

## Defect

`BackupOutput::publish` renamed the temporary under its final name with
`RENAME_NOREPLACE` and then still had to survive the post-rename fault hook,
the directory sync, the final-file reopen, and its mode and filesystem checks.
`BackupJob::finish` then ran a second complete `verify_backup` over the
published file. A failure at any of those points returned an error while the
complete file stayed under the final name; `Drop` only tried to unlink the old
temporary name. The next same-name backup then failed on the occupied name.
The audit regression `audit_backup_rename_error_leaves_final_name_and_blocks_retry`
reproduced this on the unrepaired source:

```text
result=Err(DatabaseRejected) final_exists=true retry=Err(FilesystemRejected)
```

## Repair

The one required full verification already ran on the temporary file before
the rename, over the same descriptor that the rename carries under the final
name. Publication now uses that identity:

- The rename is the irreversible boundary. Before it, a failure leaves only
  the temporary, which `Drop` removes as before.
- After it, the reopened final file must be a regular mode-0600 file on the
  same filesystem **and the same device and inode as the written, verified
  descriptor**. That identity check replaces the second O(database)
  verification on the owner thread; the receipt still reports the exact
  verified stream length, record count, and signed digest, and `finish`
  cross-checks the published length against the verified length.
- A failure after the rename (post-rename fault, directory sync, reopen,
  validation) retracts the artifact: the final name is unlinked only if
  `statat` of the name and `fstat` of the written descriptor agree on device
  and inode, and the directory is synced afterwards. The original error is
  returned. A name that refers to any other inode is left alone, publication
  fails with `FilesystemRejected`, and a same-name retry against it is
  refused by `RENAME_NOREPLACE` rather than replacing it.
- A crash after the rename cannot retract. The file under the final name is
  then complete: it was fully verified and `fsync`ed before the rename. The
  recoverable state is explicit: a same-name retry is refused, the artifact
  verifies with the stopped restore tooling, and a fresh name publishes.

After the repair the same regression prints:

```text
result=Err(DatabaseRejected) final_exists=false retry=Ok(BackupReceipt { stream_bytes: 1763, record_count: 4, .. })
```

## Tests

- `platform::tests`: a post-rename failure retracts only the written inode
  and frees the name for a retry; a replaced final inode fails publication
  without touching the foreign file and refuses the same-name retry; a final
  artifact whose mode changed after the rename fails validation and is
  retracted; a simulated crash after the rename leaves the complete artifact,
  refuses a same-name retry, and still publishes a fresh name.
- `stage_five_completion::real_startup_and_backup_inject_read_and_publication_boundaries`
  now asserts, at each of the record, file-sync, rename, and directory-sync
  boundaries on both sides, that the backup directory holds neither the final
  name nor a temporary, that the same producer publishes the same name on the
  retry, and that the retried artifact verifies to the receipt's exact stream
  length, record count, and digest.
- The audit regression above is retained with its baseline output.

Commands: `cargo test -p agenc-relay-storage --locked --lib platform::tests`,
`cargo test -p agenc-relay-storage --locked --test stage_five stage_five_completion::audit_backup_rename_error_leaves_final_name_and_blocks_retry -- --exact`,
`cargo test -p agenc-relay-storage --locked --test stage_five real_startup_and_backup_inject_read_and_publication_boundaries`,
`cargo test -p agenc-relay-storage --all-features --locked`, workspace Clippy,
and the stage-nine gate.
