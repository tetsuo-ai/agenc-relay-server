# Maintenance audit export v1

This schema-three administration extension exports the shared audit chain,
including stopped login-index rotation events. An authenticated operator with
the `audit` permission selects it with this exact signed command:

```text
AUDIT EXPORT <from> <to> maintenance-v1
```

The profile parameter is case-sensitive. The inclusive sequence bounds use
canonical unsigned decimal. Unknown profiles, extra parameters, leading zeroes,
and reversed bounds are refused. The schema-two command parser continues to
refuse this extension during legacy migration and restore admission.

The response uses a fresh server-generated batch ID:

```text
BATCH +<batch-id> agenc.ag/audit-maintenance-v1 <from> <to> <event-count> <checkpoint-count>
@batch=<batch-id> NOTE AUDIT CHECKPOINT <base64url-AdminAuditCheckpoint> :Audit checkpoint
@batch=<batch-id> NOTE AUDIT EVENT <base64url-AdminAuditEvent> :Audit event
@batch=<batch-id> NOTE AUDIT MAINTENANCE <base64url-MaintenanceAuditEvent> :Maintenance audit event
BATCH -<batch-id>
```

Checkpoint lines precede event lines in checkpoint-sequence order. Admin and
maintenance lines then appear together in audit-sequence order. `event-count`
includes both kinds of event. Each count is exact; each token is canonical
unpadded base64url containing one complete signed object. The batch contains
only the lines needed for the selected range.

`EVENT` retains encoding one and its original operator and server signatures.
`MAINTENANCE` carries the existing encoding-two, profile-version-one body:
358 bytes of signed maintenance facts, followed by its 32-byte event hash and
64-byte server signature. Its exact 454-byte codec is
[`MaintenanceAuditEvent`](../crates/agenc-relay-admin/src/maintenance/mod.rs),
with the field order in
[`MaintenanceAuditEventTbs`](../crates/agenc-relay-admin/src/maintenance/tbs.rs).
The dedicated audit-key signature covers the existing maintenance hash and
signature domains. Export preserves every original byte, including historical
database, incarnation, recovery epoch, key-state, time, and chain fields.

The server verifies the complete retained chain and checkpoint chain, including
unselected records, against the captured cursor and configured historical trust
keys. Every previously allocated sequence in the requested range must be
covered exactly once by an event or an intersecting checkpoint range. A range
above the highest allocated sequence is empty. Combined event and checkpoint
count is at most 10,000; the existing 67,108,864-byte export and 8,703-byte output
line ceilings apply. Invalid source records, gaps, overlaps, unavailable trust,
or exceeded bounds prevent a partial batch.

The export command itself creates an ordinary signed `observed` admin event.
Its canonical command includes the profile parameter. That event appears in the
batch when its sequence is selected. The complete response remains private
until the observed event's storage receipt succeeds. A refused commit returns
`FAIL AUDIT STORAGE_UNAVAILABLE :Administrative audit unavailable` and emits no
batch. Rendering and receipt validation bind the observed command to the exact
requested profile and range.

Without the profile parameter, `AUDIT EXPORT <from> <to>` keeps the original
`agenc.ag/audit` framing. A selected maintenance event returns
`FAIL AUDIT UNAVAILABLE :Audit export unavailable` after source validation,
without an observed append. A maintenance event is never labelled `EVENT` or
decoded as an `AdminAuditEvent`.
