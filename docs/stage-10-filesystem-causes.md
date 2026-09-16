# Filesystem rejection causes

This record closes the operator-diagnostics follow-up that every raw errno
collapsed to `FilesystemRejected` (STO-09, issue #50). It changes no storage
format, wire protocol, failure policy, or dependency pin.

## Change

`StorageError::FilesystemRejected` now carries a closed `FilesystemCause`:
`missing_state`, `permission_rejected`, `insufficient_capacity`,
`unqualified`, `io_failure`, `unsafe_path`, and `unknown`. The platform and
backup adapters classify a raw `rustix` errno or `std::io::Error` once, at the
boundary, through `filesystem_rejected`, and keep nothing but the cause; every
explicit policy check (mode and ownership, file type, single-component names,
symlinks and link counts, cross-filesystem boundaries, capacity reserves,
qualification tuples, absent or unexpected guards, read-only inspection
handles) names its own cause. The public outcome is unchanged: a rejection is
still `FilesystemRejected` before any irreversible boundary, an uncertain write
still forces the stop-and-reconcile path, and no code branches on a cause to
retry. Nothing matches a specific cause outside tests.

The `Display` text is the fixed prefix `filesystem policy rejected storage:`
followed by the label. The runtime's closed public error code registry gained
`filesystem_<cause>` labels, so a `RuntimeError::Storage` carrying a rejection
renders its cause on log events; other storage failures still map to
`storage_unavailable`. The operator guide maps each cause to an action and
states that a missing or malformed guard remains fail-closed.

## Tests

- `stage_five_completion::storage_errors_and_fault_controllers_cover_the_closed_failure_surface`:
  the seven labels are distinct lowercase identifiers, every cause renders
  inside the same rejection text, ENOENT, EACCES, ENOSPC, EIO, EEXIST, and
  ELOOP classify as specified with EINTR and an errno-less error falling back
  to `unknown`, and a permission error carrying a path and a canary renders
  only the fixed label.
- `platform::tests::file_validation_and_backup_admission_fail_closed`: wrong
  type, wrong mode, invalid reserve configuration, exhausted capacity, and a
  non-empty output file each carry their distinct cause; the adapter maps raw
  ENOENT, EACCES, ENOSPC, and EIO to their causes; an absent guard reads as
  `missing_state`.
- `observe::events` tests pin the `filesystem_<cause>` labels and the
  `RuntimeError` mapping.
- Every existing fault-injection, initialization-guard, restore, and backup
  test still passes with pattern matches on the outer variant, which shows the
  outer outcome classification did not move.
