//! Every retained event has one closed decoder and one complete trust path.
#![forbid(unsafe_code)]

use super::*;

pub(super) fn decode_event(
    sequence: u64,
    kind: u16,
    body: &[u8],
) -> Result<AuditEvent, RuntimeError> {
    let event = AuditEvent::decode_exact(body).map_err(|_| RuntimeError::InvalidValue)?;
    if event.encoding() != kind || event.audit_sequence() != sequence {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(event)
}

pub(super) fn permitted_kind(table: TableId, kind: u16) -> bool {
    matches!(
        (table, kind),
        (TableId::Audit, 1 | 2) | (TableId::AuditCheckpoint, 1)
    )
}

impl EventVerifier<'_> {
    pub(super) fn observe_event(&mut self, event: &AuditEvent) -> Result<(), RuntimeError> {
        match event {
            AuditEvent::Admin(event) => self.observe(event),
            AuditEvent::Maintenance(event) => {
                if self.unmatched_intent.is_some() {
                    return Err(RuntimeError::InvalidValue);
                }
                let tbs = event.tbs();
                let key = self
                    .trust
                    .resolve(tbs.audit_signing_key_id(), tbs.position().created_at())?;
                event
                    .verify(self.binding.network_id, self.binding.server_id, key)
                    .map_err(|_| RuntimeError::InvalidValue)?;
                self.cursor = self
                    .cursor
                    .advance_event(&AuditEvent::Maintenance(event.clone()))
                    .map_err(|_| RuntimeError::InvalidValue)?;
                self.latest_created_at = self.latest_created_at.max(tbs.position().created_at());
                Ok(())
            }
        }
    }
}

impl ExportSelection {
    /// Returns false for a verified selected body outside the legacy profile.
    /// The caller must still verify the complete source before reporting refusal.
    pub(super) fn consider_mixed(&mut self, event: AuditEvent) -> Result<bool, RuntimeError> {
        if !self.range.contains(event.audit_sequence()) {
            return Ok(true);
        }
        match event {
            AuditEvent::Admin(event) => self.push_event(event).map(|()| true),
            AuditEvent::Maintenance(_) => Ok(false),
        }
    }
}

impl RetentionSelector {
    pub(super) fn observe_event(&mut self, event: &AuditEvent) -> Result<(), RuntimeError> {
        if let AuditEvent::Admin(event) = event {
            return self.observe(event);
        }
        if self.complete || self.examined == MAX_AUDIT_RETENTION_EVENTS {
            self.complete = true;
            return Ok(());
        }
        if event.created_at() >= self.cutoff {
            self.complete = true;
            return Ok(());
        }
        if !self.pending.is_empty() {
            return Err(RuntimeError::InvalidValue);
        }
        self.examined = self.examined.checked_add(1).ok_or(RuntimeError::Overflow)?;
        self.candidate = Some((event.audit_sequence(), event.event_hash()));
        Ok(())
    }
}
