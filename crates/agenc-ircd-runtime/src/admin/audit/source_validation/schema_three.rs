//! Frozen schema-three audit meanings for the explicit successor migration.
#![forbid(unsafe_code)]

use super::*;

/// Verifies both schema-three event encodings with a bounded retained-chain scan.
pub struct SchemaThreeAuditSourceValidator {
    context: LegacyAuditSourceValidator,
    scan: Option<SourceAuditScan>,
}

impl LegacyAuditSourceValidator {
    /// Starts an independent schema-three scan using the same public verification keys.
    /// Any earlier schema-two transcript is discarded.
    pub fn into_schema_three_validator(self) -> SchemaThreeAuditSourceValidator {
        SchemaThreeAuditSourceValidator {
            context: Self { scan: None, ..self },
            scan: None,
        }
    }
}

impl SourceRecordValidator for SchemaThreeAuditSourceValidator {
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError> {
        self.scan = None;
        let header = facts.header.tbs();
        if header.schema_generation != 3
            || header.network_id != self.context.binding.network_id
            || header.server_id != self.context.binding.server_id
        {
            return Err(StorageError::UnsupportedMigration);
        }
        self.scan = Some(SourceAuditScan::new(&self.context));
        Ok(())
    }

    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        let mut scan = self.scan.take().ok_or(StorageError::StaleState)?;
        if record.source_schema_generation() != 3 {
            return Err(StorageError::UnsupportedMigration);
        }
        if matches!(record.table(), TableId::Audit | TableId::AuditCheckpoint) {
            let value = PersistentRecordValue::decode(record.table(), record.plaintext())?;
            scan.observe_schema_three(&self.context, record.table(), record.key(), &value)
                .map_err(|_| StorageError::InvalidEncoding)?;
        }
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

impl SourceAuditScan {
    pub(super) fn observe_schema_three(
        &mut self,
        context: &LegacyAuditSourceValidator,
        table: TableId,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let sequence = sequence_key(key)?;
        if !mixed::permitted_kind(table, value.record_kind())
            || value.revision() != sequence.checked_add(1).ok_or(RuntimeError::Overflow)?
            || value.generation() != 0
            || value.expires_at().is_some()
            || !value.references().is_empty()
        {
            return Err(RuntimeError::InvalidValue);
        }
        if table == TableId::AuditCheckpoint {
            return self.checkpoint(context, sequence, value.body());
        }
        let event = mixed::decode_event(sequence, value.record_kind(), value.body())?;
        self.schema_three_event(context, &event)
    }

    fn schema_three_event(
        &mut self,
        context: &LegacyAuditSourceValidator,
        event: &AuditEvent,
    ) -> Result<(), RuntimeError> {
        if self.checkpoint_seen {
            return Err(RuntimeError::InvalidValue);
        }
        if let AuditEvent::Admin(event) = event {
            validate_schema_three_command(event)?;
        }
        let anchor = AuditChainCursor {
            next_sequence: event.audit_sequence(),
            previous_event_hash: event.previous_event_hash(),
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
        verifier.observe_event(event)?;
        let mut verified = verifier.finish();
        verified.policy = AdminPolicySeed::default();
        self.events = Some(verified);
        Ok(())
    }
}

fn validate_schema_three_command(event: &AdminAuditEvent) -> Result<(), RuntimeError> {
    let command = CanonicalCommand::check(event.tbs().command_tbs.canonical_command())
        .map_err(|_| RuntimeError::InvalidValue)?;
    let parameters = command.parameters();
    if let ("AUDIT", ["EXPORT", from, to, "maintenance-v1"]) =
        (command.verb(), parameters.as_slice())
    {
        AuditRange::parse(from, to).map_err(|_| RuntimeError::InvalidValue)?;
    } else {
        AdminCommand::parse_schema_two(command).map_err(|_| RuntimeError::InvalidValue)?;
    }
    Ok(())
}
