//! A legacy restore source requires full stream integrity and semantic admission.
#![forbid(unsafe_code)]

use std::io::{Read, Seek, SeekFrom};

use agenc_ircd_crypto::{RollbackGuardRootKey, StorageMasterKey};

use crate::{
    AuthenticatedSourceRecord, BackupTrustKey, ConstructionSourceFacts, SourceRecordValidator,
    StorageError, VerifiedBackup,
};

pub(super) enum RecordObservation<'a> {
    IntegrityOnly,
    Semantic(&'a mut dyn SourceRecordValidator),
}

impl RecordObservation<'_> {
    pub(super) fn observe(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        match self {
            Self::IntegrityOnly => Ok(()),
            Self::Semantic(validator) => validator.validate_record(record),
        }
    }
}

/// Verifies a schema-two backup completely before admitting it for legacy restore.
///
/// The first full signed pass supplies authenticated facts to `begin_source`.
/// The second full pass observes original plaintexts and must match the exact
/// signed stream before `finish_source`. No usable source or output is produced
/// for a partial, substituted, unsupported, or semantically refused stream.
pub fn verify_legacy_backup_with_validator<R: Read + Seek>(
    input: &mut R,
    source_master_key: &StorageMasterKey,
    source_guard_root: &RollbackGuardRootKey,
    trusted_keys: &[BackupTrustKey],
    maximum_bytes: u64,
    validator: &mut dyn SourceRecordValidator,
) -> Result<VerifiedBackup, StorageError> {
    rewind(input)?;
    let expected = super::verify_backup(
        &mut *input,
        source_master_key,
        source_guard_root,
        trusted_keys,
        maximum_bytes,
    )?;
    admit_verified_legacy_backup(
        input,
        expected,
        source_master_key,
        source_guard_root,
        trusted_keys,
        maximum_bytes,
        validator,
    )
}

pub(crate) fn admit_verified_legacy_backup<R: Read + Seek>(
    input: &mut R,
    expected: VerifiedBackup,
    source_master_key: &StorageMasterKey,
    source_guard_root: &RollbackGuardRootKey,
    trusted_keys: &[BackupTrustKey],
    maximum_bytes: u64,
    validator: &mut dyn SourceRecordValidator,
) -> Result<VerifiedBackup, StorageError> {
    if expected.header.source_header().tbs().schema_generation != 2 {
        return Err(StorageError::UnsupportedMigration);
    }
    validator.begin_source(&source_facts(&expected)?)?;
    rewind(input)?;
    let observed = super::verify_backup_reader(
        input,
        source_master_key,
        source_guard_root,
        trusted_keys,
        maximum_bytes,
        RecordObservation::Semantic(validator),
    )?;
    // The signed digest covers the header and every numbered record. Comparing
    // the complete trailer and byte count refuses even a valid replacement.
    if expected.trailer != observed.trailer || expected.stream_bytes != observed.stream_bytes {
        return Err(StorageError::StaleState);
    }
    validator.finish_source()?;
    Ok(observed)
}

fn rewind(input: &mut impl Seek) -> Result<(), StorageError> {
    input
        .seek(SeekFrom::Start(0))
        .map_err(|_| StorageError::FilesystemRejected)?;
    Ok(())
}

fn source_facts(verified: &VerifiedBackup) -> Result<ConstructionSourceFacts, StorageError> {
    Ok(ConstructionSourceFacts {
        header: *verified.header.source_header(),
        state: *verified.state_meta.tbs(),
        rollback_guard_hash: verified.header.source_rollback_guard().complete_hash()?,
    })
}
