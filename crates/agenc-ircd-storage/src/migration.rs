//! The sole compiled schema-generation 1 to 2 construction profile.

use std::fs::File;

use agenc_ircd_crypto::{DatabaseBinding, StorageDigest, StorageMasterKey};
use agenc_ircd_domain::HistoryPolicy;
use zeroize::Zeroizing;

use crate::history_records::{HistoryControlRecord, history_control_key};
use crate::{
    ChannelRecordBody, ConstructionLimits, ConstructionPlan, ConstructionPlanBuilder,
    ConstructionSourceDatabase, ConstructionSourceRecord, ConstructionTransformer,
    PersistentRecordValue, StorageConstructionAction, StorageConstructionKind,
    StorageConstructionPlanEntry, StorageConstructionSource, StorageConstructionSourceKind,
    StorageError, StorageOpenConfig, StoredKey, TableId,
};

const REGISTRY: &[u8] = include_bytes!("../../../docs/storage-migration-1-to-2.registry");
const INITIALIZE_HISTORY_RULE: u16 = 27;

pub(crate) fn profile_hash() -> Result<StorageDigest, StorageError> {
    agenc_ircd_crypto::storage_migration_profile_hash(1, 2, REGISTRY).map_err(StorageError::from)
}

pub(crate) fn validate_source_record(
    generation: u64,
    table: TableId,
    key: &StoredKey,
    schema: u32,
    plaintext: &[u8],
) -> Result<(), StorageError> {
    if generation == 1 {
        if table == TableId::History || schema != 1 {
            return Err(StorageError::UnsupportedMigration);
        }
        if table == TableId::RequestResult {
            let value = PersistentRecordValue::decode(table, plaintext)?;
            if value.record_kind() > 4 {
                return Err(StorageError::UnsupportedVersion);
            }
        }
    } else if !matches!(generation, 2..=4) {
        return Err(StorageError::UnsupportedVersion);
    }
    if generation <= 2 {
        validate_legacy_kind(table, plaintext)?;
    }
    if generation == 3 {
        validate_schema_three_kind(table, key, plaintext)?;
    }
    crate::validate_record_plaintext(table, key, schema, plaintext)
}

// This source profile stays closed when current storage gains new body versions.
fn validate_schema_three_kind(
    table: TableId,
    key: &StoredKey,
    plaintext: &[u8],
) -> Result<(), StorageError> {
    if !matches!(table, TableId::E2eeState | TableId::Audit) {
        return Ok(());
    }
    let value = PersistentRecordValue::decode(table, plaintext)?;
    let maximum = if table == TableId::E2eeState { 15 } else { 2 };
    if value.record_kind() > maximum {
        return Err(StorageError::UnsupportedVersion);
    }
    if table == TableId::E2eeState
        && value.record_kind() == crate::e2ee_records::DELIVERY_RECOVERY_ROW_KIND
    {
        crate::e2ee_records::delivery_recovery::DeliveryRecoveryRow::decode_at(key, value.body())?;
    }
    Ok(())
}

fn validate_legacy_kind(table: TableId, plaintext: &[u8]) -> Result<(), StorageError> {
    if matches!(table, TableId::E2eeState | TableId::Audit) {
        let value = PersistentRecordValue::decode(table, plaintext)?;
        let maximum = if table == TableId::E2eeState { 12 } else { 1 };
        if value.record_kind() > maximum {
            return Err(StorageError::UnsupportedVersion);
        }
    }
    Ok(())
}

pub(crate) fn valid_rule_sources(
    sources: &[StorageConstructionSource],
    target: TableId,
    rule: u16,
) -> bool {
    let [source] = sources else { return false };
    source.kind() == StorageConstructionSourceKind::DatabaseRecord
        && source.record_schema() == 1
        && ((preserved_table(source.table())
            && rule == source.table().as_u16()
            && target == source.table())
            || (rule == INITIALIZE_HISTORY_RULE
                && source.table() == TableId::Channel
                && target == TableId::History))
}

fn preserved_table(table: TableId) -> bool {
    matches!(table.as_u16(), 1..=13 | 17 | 18 | 20..=24 | 26)
}

impl ConstructionSourceDatabase {
    /// Authenticates a stopped generation-one source without allowing service access.
    pub fn open_migration(config: StorageOpenConfig) -> Result<Self, StorageError> {
        let engine = crate::engine::StorageEngine::open_migration_source(config)?;
        let _capacity = engine.startup_scan()?;
        Ok(Self { engine })
    }

    /// Rebuilds the exact target-sorted generation-one to two migration plan.
    pub fn rebuild_migration_plan(
        &self,
        file: File,
        target_master: &StorageMasterKey,
        target_binding: DatabaseBinding,
        target_generation: u32,
        limits: ConstructionLimits,
    ) -> Result<ConstructionPlan, StorageError> {
        let facts = self.facts()?;
        let limits = limits.validate()?;
        if facts.header.tbs().schema_generation != 1
            || facts.header.tbs().storage_key_generation.checked_add(1) != Some(target_generation)
            || !self
                .engine
                .construction_source_master_key()
                .matches(target_master)
        {
            return Err(StorageError::UnsupportedMigration);
        }
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Migrate,
            file,
            limits,
        )?;
        let mut controls = 0_u64;
        self.engine
            .visit_construction_source_records(|source, record| {
                validate_source_record(
                    1,
                    source.table(),
                    source.key(),
                    source.record_schema(),
                    record.plaintext(),
                )?;
                if !preserved_table(source.table()) {
                    return Err(StorageError::UnsupportedMigration);
                }
                let target_key = crate::construction_runtime::rekey_target_stored_key(
                    &source,
                    &record,
                    self.engine.construction_source_master_key(),
                    self.engine.construction_source_binding(),
                    facts.header.tbs().storage_key_generation,
                    target_master,
                    target_binding,
                    target_generation,
                )?;
                if let Some(control) =
                    legacy_history_control(&record, facts.state.state_generation)?
                {
                    controls = controls.checked_add(1).ok_or(StorageError::Overflow)?;
                    if controls > 4_096 {
                        return Err(StorageError::LimitExceeded);
                    }
                    builder.push(migration_entry(
                        copy_source(&source)?,
                        TableId::History,
                        history_control_key(control.channel_id)?,
                        INITIALIZE_HISTORY_RULE,
                    )?)?;
                }
                let table = source.table();
                builder.push(migration_entry(source, table, target_key, table.as_u16())?)
            })?;
        builder.finish()
    }
}

fn migration_entry(
    source: StorageConstructionSource,
    target: TableId,
    key: StoredKey,
    rule: u16,
) -> Result<StorageConstructionPlanEntry, StorageError> {
    StorageConstructionPlanEntry::new(
        StorageConstructionKind::Migrate,
        vec![source],
        target,
        key,
        1,
        StorageConstructionAction::MigrateTransform,
        rule,
    )
}

fn copy_source(
    source: &StorageConstructionSource,
) -> Result<StorageConstructionSource, StorageError> {
    StorageConstructionSource::new(
        source.kind(),
        source.table(),
        StoredKey::new(source.key().as_bytes().to_vec())?,
        source.record_schema(),
        source.sealed_record_id(),
        source.backup_byte_offset(),
    )
}

fn legacy_history_control(
    source: &ConstructionSourceRecord,
    state_generation: u64,
) -> Result<Option<HistoryControlRecord>, StorageError> {
    if source.table() != TableId::Channel {
        return Ok(None);
    }
    let value = PersistentRecordValue::decode(TableId::Channel, source.plaintext())?;
    if value.record_kind() != 1 {
        return Ok(None);
    }
    let channel = ChannelRecordBody::decode(value.body())?;
    if channel.history == HistoryPolicy::Off {
        return Ok(None);
    }
    HistoryControlRecord::empty(channel.channel_id, state_generation).map(Some)
}

/// Exact copy and conditional empty history-control initializer for schema 1 to 2.
pub struct MigrationTransformV1 {
    state_generation: u64,
}

impl MigrationTransformV1 {
    /// Binds synthesized controls to the authenticated source logical generation.
    #[must_use]
    pub const fn new(state_generation: u64) -> Self {
        Self { state_generation }
    }
}

impl ConstructionTransformer for MigrationTransformV1 {
    fn transform(
        &mut self,
        kind: StorageConstructionKind,
        entry: &StorageConstructionPlanEntry,
        sources: &[ConstructionSourceRecord],
    ) -> Result<Zeroizing<Vec<u8>>, StorageError> {
        let [source] = sources else {
            return Err(StorageError::InvalidEncoding);
        };
        if kind != StorageConstructionKind::Migrate
            || entry.action() != StorageConstructionAction::MigrateTransform
            || entry.target_record_schema() != 1
            || !valid_rule_sources(
                entry.sources(),
                entry.target_table(),
                entry.transform_rule_id(),
            )
        {
            return Err(StorageError::UnsupportedMigration);
        }
        validate_source_record(
            1,
            source.table(),
            source.key(),
            source.record_schema(),
            source.plaintext(),
        )?;
        if entry.transform_rule_id() != INITIALIZE_HISTORY_RULE {
            if !matches!(
                source.table(),
                TableId::NicknameReservation | TableId::ChannelName
            ) && source.key().as_bytes() != entry.target_key().as_bytes()
            {
                return Err(StorageError::StaleState);
            }
            return Ok(Zeroizing::new(source.plaintext().to_vec()));
        }
        let control = legacy_history_control(source, self.state_generation)?
            .ok_or(StorageError::StaleState)?;
        if history_control_key(control.channel_id)?.as_bytes() != entry.target_key().as_bytes() {
            return Err(StorageError::StaleState);
        }
        let value = PersistentRecordValue::new(
            TableId::History,
            2,
            self.state_generation,
            0,
            None,
            vec![crate::RecordReference::new(
                TableId::Channel,
                StoredKey::new(control.channel_id.as_bytes().to_vec())?,
            )?],
            control.encode()?,
        )?;
        Ok(Zeroizing::new(value.encode()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agenc_ircd_types::ChannelInstanceId;

    #[test]
    fn migration_rule_sources_require_one_known_database_row_and_exact_target()
    -> Result<(), StorageError> {
        let source = |kind, table, schema| {
            StorageConstructionSource::new(
                kind,
                table,
                StoredKey::new(vec![1; if table == TableId::History { 24 } else { 16 }])?,
                schema,
                StorageDigest::from_bytes([2; 32]),
                0,
            )
        };
        let channel = source(
            StorageConstructionSourceKind::DatabaseRecord,
            TableId::Channel,
            1,
        )?;
        assert!(!valid_rule_sources(&[], TableId::Channel, 8));
        assert!(!valid_rule_sources(
            &[
                source(
                    StorageConstructionSourceKind::DatabaseRecord,
                    TableId::Channel,
                    1
                )?,
                source(
                    StorageConstructionSourceKind::DatabaseRecord,
                    TableId::Channel,
                    1
                )?,
            ],
            TableId::Channel,
            8
        ));
        assert!(!valid_rule_sources(
            &[source(
                StorageConstructionSourceKind::BackupRecord,
                TableId::Channel,
                1
            )?],
            TableId::Channel,
            8
        ));
        assert!(!valid_rule_sources(
            &[source(
                StorageConstructionSourceKind::DatabaseRecord,
                TableId::Channel,
                2
            )?],
            TableId::Channel,
            8
        ));
        assert!(!valid_rule_sources(
            &[source(
                StorageConstructionSourceKind::DatabaseRecord,
                TableId::History,
                1
            )?],
            TableId::History,
            19
        ));
        assert!(!valid_rule_sources(
            &[source(
                StorageConstructionSourceKind::DatabaseRecord,
                TableId::Session,
                1
            )?],
            TableId::History,
            27
        ));
        assert!(!valid_rule_sources(
            std::slice::from_ref(&channel),
            TableId::Channel,
            27
        ));
        assert!(!valid_rule_sources(
            std::slice::from_ref(&channel),
            TableId::History,
            8
        ));
        assert!(!valid_rule_sources(
            std::slice::from_ref(&channel),
            TableId::Channel,
            7
        ));
        assert!(valid_rule_sources(
            std::slice::from_ref(&channel),
            TableId::Channel,
            8
        ));
        assert!(valid_rule_sources(&[channel], TableId::History, 27));
        Ok(())
    }

    #[test]
    fn compiled_migration_hash_binds_the_exact_twenty_four_rule_registry()
    -> Result<(), StorageError> {
        assert_eq!(
            profile_hash()?.as_bytes(),
            &[
                0xed, 0xd0, 0x93, 0x60, 0x0b, 0xb6, 0x17, 0x0b, 0x28, 0x9f, 0x8a, 0xc6, 0xda, 0xf3,
                0x81, 0xfe, 0x33, 0xe2, 0xb8, 0x13, 0x25, 0xbb, 0x53, 0x94, 0x87, 0xc0, 0x3f, 0x68,
                0x2b, 0x24, 0xe2, 0x6d
            ]
        );
        assert_eq!(REGISTRY.iter().filter(|byte| **byte == b'\n').count(), 24);
        Ok(())
    }

    #[test]
    fn predecessor_history_is_rejected_even_when_its_target_body_is_valid()
    -> Result<(), StorageError> {
        let channel = ChannelInstanceId::from_bytes([1; 16]);
        let control = HistoryControlRecord::empty(channel, 1)?;
        let key = history_control_key(channel)?;
        let body = PersistentRecordValue::new(
            TableId::History,
            2,
            1,
            0,
            None,
            Vec::new(),
            control.encode()?,
        )?
        .encode()?;
        validate_source_record(2, TableId::History, &key, 1, &body)?;
        assert_eq!(
            validate_source_record(1, TableId::History, &key, 1, &body),
            Err(StorageError::UnsupportedMigration)
        );
        Ok(())
    }

    #[test]
    fn migration_entries_reject_unknown_rules_wrong_targets_and_record_schemas()
    -> Result<(), StorageError> {
        let source = || {
            StorageConstructionSource::new(
                StorageConstructionSourceKind::DatabaseRecord,
                TableId::Channel,
                StoredKey::new(vec![1; 16])?,
                1,
                StorageDigest::from_bytes([2; 32]),
                0,
            )
        };
        assert!(valid_rule_sources(&[source()?], TableId::Channel, 8));
        assert!(valid_rule_sources(&[source()?], TableId::History, 27));
        for (target, rule) in [
            (TableId::Channel, 0),
            (TableId::History, 19),
            (TableId::Channel, 27),
            (TableId::History, 8),
            (TableId::Account, 1),
        ] {
            assert!(!valid_rule_sources(&[source()?], target, rule));
        }
        assert!(
            StorageConstructionPlanEntry::new(
                StorageConstructionKind::Migrate,
                vec![source()?],
                TableId::Channel,
                StoredKey::new(vec![1; 16])?,
                2,
                StorageConstructionAction::MigrateTransform,
                8
            )
            .is_err()
        );
        Ok(())
    }
}
