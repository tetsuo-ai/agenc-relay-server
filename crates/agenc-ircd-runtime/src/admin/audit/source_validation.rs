//! Streaming legacy audit admission for stopped schema construction.
#![forbid(unsafe_code)]

use agenc_ircd_storage::{
    AuthenticatedSourceRecord, ConstructionSourceFacts, SourceRecordValidator, StorageError,
};

use super::*;

mod schema_three;
pub use schema_three::SchemaThreeAuditSourceValidator;

#[cfg(test)]
mod tests;

/// Verifies schema-two audit meanings, signatures, and complete retained chains.
///
/// Storage supplies authenticated original records. This validator owns no
/// signing key, writes no output, and retains at most one unmatched intent.
pub struct LegacyAuditSourceValidator {
    binding: AdminSessionBinding,
    trust: AuditTrust,
    operators: OperatorRegistry,
    scan: Option<SourceAuditScan>,
}

impl LegacyAuditSourceValidator {
    /// Pins the maintenance configuration's public identity and verification keys.
    pub fn new(
        binding: AdminSessionBinding,
        trust_entries: &[AuditTrustManifestEntry],
        operators: OperatorRegistry,
    ) -> Result<Self, RuntimeError> {
        Ok(Self {
            binding,
            trust: AuditTrust::new(trust_entries)?,
            operators,
            scan: None,
        })
    }
}

impl SourceRecordValidator for LegacyAuditSourceValidator {
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError> {
        self.scan = None;
        let header = facts.header.tbs();
        if header.schema_generation != 2
            || header.network_id != self.binding.network_id
            || header.server_id != self.binding.server_id
        {
            return Err(StorageError::UnsupportedMigration);
        }
        self.scan = Some(SourceAuditScan::new(self));
        Ok(())
    }

    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        // Taking the transcript poisons this invocation on every refused row.
        let mut scan = self.scan.take().ok_or(StorageError::StaleState)?;
        if record.source_schema_generation() != 2 {
            return Err(StorageError::UnsupportedMigration);
        }
        scan.observe_record(self, record)
            .map_err(|_| StorageError::InvalidEncoding)?;
        self.scan = Some(scan);
        Ok(())
    }

    fn finish_source(&mut self) -> Result<(), StorageError> {
        self.scan
            .take()
            .ok_or(StorageError::StaleState)?
            .finish()
            .map_err(|_| StorageError::InvalidEncoding)
    }
}

struct SourceAuditScan {
    first_event: Option<AuditChainCursor>,
    events: Option<EventVerification>,
    checkpoints: CheckpointVerification,
    checkpoint_seen: bool,
}

impl SourceAuditScan {
    fn new(context: &LegacyAuditSourceValidator) -> Self {
        Self {
            first_event: None,
            events: None,
            checkpoints: CheckpointVerifier::new(context.binding, &context.trust).finish(),
            checkpoint_seen: false,
        }
    }

    fn observe_record(
        &mut self,
        context: &LegacyAuditSourceValidator,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), RuntimeError> {
        if !matches!(record.table(), TableId::Audit | TableId::AuditCheckpoint) {
            return Ok(());
        }
        let value = PersistentRecordValue::decode(record.table(), record.plaintext())?;
        self.observe(context, record.table(), record.key(), &value)
    }

    fn observe(
        &mut self,
        context: &LegacyAuditSourceValidator,
        table: TableId,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let sequence = legacy_envelope(key, value)?;
        match table {
            TableId::Audit => self.event(context, sequence, value.body()),
            TableId::AuditCheckpoint => self.checkpoint(context, sequence, value.body()),
            _ => Err(RuntimeError::InvalidValue),
        }
    }

    fn event(
        &mut self,
        context: &LegacyAuditSourceValidator,
        sequence: u64,
        body: &[u8],
    ) -> Result<(), RuntimeError> {
        let event = AdminAuditEvent::decode_exact(body).map_err(|_| RuntimeError::InvalidValue)?;
        if self.checkpoint_seen || event.tbs().audit_sequence != sequence {
            return Err(RuntimeError::InvalidValue);
        }
        let command = CanonicalCommand::check(event.tbs().command_tbs.canonical_command())
            .map_err(|_| RuntimeError::InvalidValue)?;
        AdminCommand::parse_schema_two(command).map_err(|_| RuntimeError::InvalidValue)?;
        let anchor = AuditChainCursor {
            next_sequence: sequence,
            previous_event_hash: event.tbs().previous_event_hash,
        };
        self.first_event.get_or_insert(anchor);
        let previous = self.events.take();
        let mut verifier = EventVerifier {
            binding: context.binding,
            trust: &context.trust,
            operators: &context.operators,
            cursor: previous.as_ref().map_or(anchor, |state| state.cursor),
            unmatched_intent: previous.and_then(|state| state.pending_startup_action),
            policy: AdminPolicySeed::default(),
            latest_created_at: 0,
        };
        verifier.observe(&event)?;
        let mut verified = verifier.finish();
        // Policy mutation shapes are checked, but source admission does not
        // reconstruct or retain a second copy of live administrative policy.
        verified.policy = AdminPolicySeed::default();
        self.events = Some(verified);
        Ok(())
    }

    fn checkpoint(
        &mut self,
        context: &LegacyAuditSourceValidator,
        sequence: u64,
        body: &[u8],
    ) -> Result<(), RuntimeError> {
        let checkpoint =
            AdminAuditCheckpoint::decode_exact(body).map_err(|_| RuntimeError::InvalidValue)?;
        if checkpoint.tbs().checkpoint_sequence != sequence {
            return Err(RuntimeError::InvalidValue);
        }
        let mut verifier = CheckpointVerifier {
            binding: context.binding,
            trust: &context.trust,
            next_sequence: self.checkpoints.next_sequence,
            next_deleted: self.checkpoints.cursor.next_sequence,
            previous_hash: self.checkpoints.previous_hash,
            cursor: self.checkpoints.cursor,
            latest_created_at: self.checkpoints.latest_created_at,
        };
        verifier.observe(&checkpoint)?;
        self.checkpoints = verifier.finish();
        self.checkpoint_seen = true;
        Ok(())
    }

    fn finish(self) -> Result<(), RuntimeError> {
        if self
            .first_event
            .is_some_and(|first| first != self.checkpoints.cursor)
            || self
                .events
                .is_some_and(|events| events.pending_startup_action.is_some())
        {
            return Err(RuntimeError::InvalidValue);
        }
        Ok(())
    }
}

fn legacy_envelope(key: &StoredKey, value: &PersistentRecordValue) -> Result<u64, RuntimeError> {
    let sequence = sequence_key(key)?;
    let revision = sequence.checked_add(1).ok_or(RuntimeError::Overflow)?;
    if value.record_kind() != 1
        || value.revision() != revision
        || value.generation() != 0
        || value.expires_at().is_some()
        || !value.references().is_empty()
    {
        return Err(RuntimeError::InvalidValue);
    }
    Ok(sequence)
}
