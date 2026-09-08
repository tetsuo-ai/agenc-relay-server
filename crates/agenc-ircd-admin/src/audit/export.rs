//! Explicit export framing preserves each signed event's assigned encoding.
#![forbid(unsafe_code)]

use super::*;
use crate::{AuditEvent, MaintenanceAuditEvent};

/// The signed command selects one exact output profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AuditExportProfile {
    /// Original `agenc.ag/audit` framing admits only administration events.
    Legacy,
    /// `agenc.ag/audit-maintenance-v1` also admits labelled maintenance events.
    MaintenanceV1,
}

impl AuditExportProfile {
    const fn batch_type(self) -> &'static str {
        match self {
            Self::Legacy => "agenc.ag/audit",
            Self::MaintenanceV1 => "agenc.ag/audit-maintenance-v1",
        }
    }
}

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

    fn render(self, batch_id: &str, profile: AuditExportProfile) -> Result<String, AdminError> {
        match self {
            Self::Admin(event) => {
                let token = encode_base64url(&event.encode()?);
                Ok(format!(
                    "@batch={batch_id} NOTE AUDIT EVENT {token} :Audit event"
                ))
            }
            Self::Maintenance(event) if profile == AuditExportProfile::MaintenanceV1 => {
                let token = encode_base64url(&event.encode()?);
                Ok(format!(
                    "@batch={batch_id} NOTE AUDIT MAINTENANCE {token} :Maintenance audit event"
                ))
            }
            Self::Maintenance(_) => Err(AdminError::Audit),
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

/// Renders a fully verified mixed chain in the selected profile without rewriting signed bytes.
///
/// The caller authenticates every record before calling. Ordering, coverage,
/// exact counts, profile admission, and the existing byte limits are enforced here.
pub fn render_export_batch_with_profile(
    batch_id: &[u8; 16],
    range: AuditRange,
    checkpoints: &[AdminAuditCheckpoint],
    events: &[AuditEvent],
    profile: AuditExportProfile,
) -> Result<Vec<String>, AdminError> {
    render(
        batch_id,
        range,
        checkpoints,
        events.iter().map(EventRef::from),
        profile,
    )
}

pub(super) fn render<'a>(
    batch_id: &[u8; 16],
    range: AuditRange,
    checkpoints: &[AdminAuditCheckpoint],
    events: impl ExactSizeIterator<Item = EventRef<'a>> + Clone,
    profile: AuditExportProfile,
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
        "BATCH +{id} {} {} {} {} {}",
        profile.batch_type(),
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
        lines.push(event.render(&id, profile)?);
    }
    lines.push(format!("BATCH -{id}"));
    check_export_bytes(&lines)?;
    Ok(lines)
}
