//! Explicit export framing preserves each signed event's assigned encoding.
#![forbid(unsafe_code)]

use super::*;
use crate::{AuditEvent, MaintenanceAuditEvent};

#[derive(Clone, Copy)]
pub(super) enum EventRef<'a> {
    Admin(&'a AdminAuditEvent),
    Maintenance(&'a MaintenanceAuditEvent),
}

impl EventRef<'_> {
    const fn sequence(self) -> u64 {
        match self {
            Self::Admin(event) => event.tbs().audit_sequence,
            Self::Maintenance(event) => event.tbs().position().audit_sequence(),
        }
    }

    fn render(self, batch_id: &str) -> Result<String, AdminError> {
        match self {
            Self::Admin(event) => {
                let token = encode_base64url(&event.encode()?);
                Ok(format!(
                    "@batch={batch_id} NOTE AUDIT EVENT {token} :Audit event"
                ))
            }
            Self::Maintenance(event) => {
                let token = encode_base64url(&event.encode()?);
                Ok(format!(
                    "@batch={batch_id} NOTE AUDIT MAINTENANCE {token} :Maintenance audit event"
                ))
            }
        }
    }
}

impl<'a> From<&'a AuditEvent> for EventRef<'a> {
    fn from(event: &'a AuditEvent) -> Self {
        match event {
            AuditEvent::Admin(event) => Self::Admin(event),
            AuditEvent::Maintenance(event) => Self::Maintenance(event),
        }
    }
}

pub(super) fn render<'a>(
    batch_id: &[u8; 16],
    range: AuditRange,
    checkpoints: &[AdminAuditCheckpoint],
    events: impl ExactSizeIterator<Item = EventRef<'a>> + Clone,
) -> Result<Vec<String>, AdminError> {
    let records = checkpoints
        .len()
        .checked_add(events.len())
        .ok_or(AdminError::Overflow)?;
    if records > MAX_AUDIT_EXPORT_RECORDS {
        return Err(AdminError::Limit);
    }
    check_checkpoint_order(range, checkpoints)?;
    check_event_order(range, events.clone().map(EventRef::sequence))?;
    check_export_coverage(range, checkpoints, events.clone().map(EventRef::sequence))?;
    let id = encode_base64url(batch_id);
    let mut lines = Vec::with_capacity(records.saturating_add(2));
    lines.push(format!(
        "BATCH +{id} agenc.ag/audit {} {} {} {}",
        range.from(),
        range.to(),
        events.len(),
        checkpoints.len()
    ));
    for checkpoint in checkpoints {
        let token = encode_base64url(&checkpoint.encode()?);
        lines.push(format!(
            "@batch={id} NOTE AUDIT CHECKPOINT {token} :Audit checkpoint"
        ));
    }
    for event in events {
        lines.push(event.render(&id)?);
    }
    lines.push(format!("BATCH -{id}"));
    check_export_bytes(&lines)?;
    Ok(lines)
}
