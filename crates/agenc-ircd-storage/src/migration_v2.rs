//! Exact schema-two logical rows copied into the schema-three storage profile.
#![forbid(unsafe_code)]

use std::fs::File;

use agenc_ircd_crypto::{DatabaseBinding, StorageDigest, StorageMasterKey};
use zeroize::Zeroizing;

use crate::{
    ConstructionLimits, ConstructionPlan, ConstructionPlanBuilder, ConstructionSourceDatabase,
    ConstructionSourceRecord, ConstructionTransformer, PersistentRecordValue,
    StorageConstructionAction, StorageConstructionKind, StorageConstructionPlanEntry,
    StorageConstructionSource, StorageConstructionSourceKind, StorageError, StoredKey, TableId,
};

const REGISTRY: &[u8] = include_bytes!("../../../docs/storage-migration-2-to-3.registry");
const COPY_RULE_BASE: u16 = 256;

pub(crate) fn profile_hash() -> Result<StorageDigest, StorageError> {
    agenc_ircd_crypto::storage_migration_profile_hash(2, 3, REGISTRY).map_err(StorageError::from)
}

pub(crate) fn valid_rule_sources(
    sources: &[StorageConstructionSource],
    target: TableId,
    rule: u16,
) -> bool {
    let [source] = sources else { return false };
    source.kind() == StorageConstructionSourceKind::DatabaseRecord
        && source.record_schema() == 1
        && preserved_table(source.table())
        && source.table() == target
        && rule == COPY_RULE_BASE + target.as_u16()
}

fn preserved_table(table: TableId) -> bool {
    matches!(table.as_u16(), 1..=13 | 17..=24 | 26)
}

impl ConstructionSourceDatabase {
    pub(crate) fn rebuild_migration_profile_plan(
        &self,
        profile: crate::migration_profile::MigrationProfile,
        file: File,
        target_master: &StorageMasterKey,
        target_binding: DatabaseBinding,
        target_generation: u32,
        limits: ConstructionLimits,
    ) -> Result<ConstructionPlan, StorageError> {
        if profile == crate::migration_profile::MigrationProfile::OneToTwo {
            return self.rebuild_migration_plan(
                file,
                target_master,
                target_binding,
                target_generation,
                limits,
            );
        }
        let facts = self.facts()?;
        if facts.header.tbs().schema_generation != 2
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
            limits.validate()?,
        )?;
        self.engine
            .visit_construction_source_records(|source, record| {
                validate_source(
                    source.table(),
                    source.key(),
                    source.record_schema(),
                    record.plaintext(),
                )?;
                let key = crate::construction_runtime::rekey_target_stored_key(
                    &source,
                    &record,
                    self.engine.construction_source_master_key(),
                    self.engine.construction_source_binding(),
                    facts.header.tbs().storage_key_generation,
                    target_master,
                    target_binding,
                    target_generation,
                )?;
                let table = source.table();
                builder.push(StorageConstructionPlanEntry::new(
                    StorageConstructionKind::Migrate,
                    vec![source],
                    table,
                    key,
                    1,
                    StorageConstructionAction::MigrateTransform,
                    COPY_RULE_BASE + table.as_u16(),
                )?)
            })?;
        builder.finish()
    }
}

pub(crate) fn validate_source(
    table: TableId,
    key: &StoredKey,
    schema: u32,
    plaintext: &[u8],
) -> Result<(), StorageError> {
    crate::migration::validate_source_record(2, table, key, schema, plaintext)?;
    if !preserved_table(table) {
        return Err(StorageError::UnsupportedMigration);
    }
    if table == TableId::E2eeState {
        let value = PersistentRecordValue::decode(table, plaintext)?;
        if matches!(
            value.record_kind(),
            crate::e2ee_records::MAILBOX_ROW_KIND
                | crate::e2ee_records::DELIVERY_ROW_KIND
                | crate::e2ee_records::BARRIER_ROW_KIND
        ) {
            return Err(StorageError::UnsupportedMigration);
        }
    }
    Ok(())
}

/// Copies validated schema-two rows without synthesizing history or authority.
pub struct MigrationTransformV2;

impl ConstructionTransformer for MigrationTransformV2 {
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
        validate_source(
            source.table(),
            source.key(),
            source.record_schema(),
            source.plaintext(),
        )?;
        if !matches!(
            source.table(),
            TableId::NicknameReservation | TableId::ChannelName
        ) && source.key().as_bytes() != entry.target_key().as_bytes()
        {
            return Err(StorageError::StaleState);
        }
        Ok(Zeroizing::new(source.plaintext().to_vec()))
    }
}
