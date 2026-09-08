//! Exact schema-three logical rows copied into the schema-four storage profile.
#![forbid(unsafe_code)]

use agenc_ircd_crypto::StorageDigest;
use zeroize::Zeroizing;

use crate::{
    ConstructionSourceRecord, ConstructionTransformer, StorageConstructionAction,
    StorageConstructionKind, StorageConstructionPlanEntry, StorageConstructionSource,
    StorageConstructionSourceKind, StorageError, StoredKey, TableId,
};

const REGISTRY: &[u8] = include_bytes!("../../../docs/storage-migration-3-to-4.registry");
const COPY_RULE_BASE: u16 = 512;

pub(crate) fn profile_hash() -> Result<StorageDigest, StorageError> {
    agenc_ircd_crypto::storage_migration_profile_hash(3, 4, REGISTRY).map_err(StorageError::from)
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

pub(crate) fn validate_source(
    table: TableId,
    key: &StoredKey,
    schema: u32,
    plaintext: &[u8],
) -> Result<(), StorageError> {
    crate::migration::validate_source_record(3, table, key, schema, plaintext)?;
    if !preserved_table(table) {
        return Err(StorageError::UnsupportedMigration);
    }
    Ok(())
}

/// Copies validated schema-three rows without synthesizing history or authority.
pub struct MigrationTransformV3;

impl ConstructionTransformer for MigrationTransformV3 {
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
