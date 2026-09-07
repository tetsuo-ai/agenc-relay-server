//! Complete signed backup verification precedes legacy semantic admission.
#![forbid(unsafe_code)]

use std::io::{Cursor, Read, Seek, SeekFrom};

use super::*;

#[path = "legacy_restore.rs"]
mod legacy_restore;

fn signed_backup() -> Result<(Fixture, Vec<u8>), StorageError> {
    let fixture = Fixture::new()?;
    initialize_two(&fixture, source_records(&fixture)?)?;
    let receipt = crate::execute_validated_migration_command(
        request_three(&fixture, false)?,
        &fixture.qualifications,
        &mut SourceTranscript::default(),
    )?;
    let bytes =
        std::fs::read(receipt.source_backup).map_err(|_| StorageError::FilesystemRejected)?;
    Ok((fixture, bytes))
}

fn validate(
    input: &mut (impl Read + Seek),
    validator: &mut dyn SourceRecordValidator,
) -> Result<crate::VerifiedBackup, StorageError> {
    crate::verify_legacy_backup_with_validator(
        input,
        &StorageMasterKey::from_bytes([27; 32]),
        &RollbackGuardRootKey::from_bytes([28; 32]),
        &[BackupTrustKey::new(
            Ed25519SecretKey::from_bytes([30; 32]).public_key(),
        )?],
        engine_limits().backup_max_bytes,
        validator,
    )
}

#[test]
fn legacy_backup_checks_every_original_row_before_finishing_source_admission()
-> Result<(), StorageError> {
    let (_fixture, bytes) = signed_backup()?;
    let mut input = Cursor::new(bytes.clone());
    let mut validator = SourceTranscript::default();
    let verified = validate(&mut input, &mut validator)?;
    assert_eq!(verified.header.source_header().tbs().schema_generation, 2);
    assert_eq!(validator.begins, 1);
    assert!(validator.finished);
    assert!(validator.records.len() > 3);
    assert_eq!(input.into_inner(), bytes);
    Ok(())
}

struct RefuseHistory(SourceTranscript);

impl SourceRecordValidator for RefuseHistory {
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError> {
        self.0.begin_source(facts)
    }

    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        let table = record.table();
        self.0.validate_record(record)?;
        if table == TableId::History {
            return Err(StorageError::UnsupportedVersion);
        }
        Ok(())
    }

    fn finish_source(&mut self) -> Result<(), StorageError> {
        self.0.finish_source()
    }
}

#[test]
fn a_late_semantic_backup_refusal_never_finishes_or_returns_a_source() -> Result<(), StorageError> {
    let (_fixture, bytes) = signed_backup()?;
    let mut validator = RefuseHistory(SourceTranscript::default());
    assert!(matches!(
        validate(&mut Cursor::new(bytes), &mut validator),
        Err(StorageError::UnsupportedVersion)
    ));
    assert_eq!(validator.0.begins, 1);
    assert!(!validator.0.finished);
    assert!(
        validator
            .0
            .records
            .keys()
            .any(|(table, _)| *table == TableId::History)
    );
    Ok(())
}

#[test]
fn an_incomplete_or_badly_signed_backup_never_starts_semantic_admission() -> Result<(), StorageError>
{
    let (_fixture, bytes) = signed_backup()?;
    let mut corrupted = bytes.clone();
    *corrupted.last_mut().ok_or(StorageError::InvalidEncoding)? ^= 1;
    let mut truncated = bytes;
    truncated.pop().ok_or(StorageError::InvalidEncoding)?;
    for bytes in [corrupted, truncated] {
        let mut validator = SourceTranscript::default();
        assert!(validate(&mut Cursor::new(bytes), &mut validator).is_err());
        assert_eq!(validator.begins, 0);
        assert!(!validator.finished);
        assert!(validator.records.is_empty());
    }
    Ok(())
}

struct ReplaceOnSecondPass {
    input: Cursor<Vec<u8>>,
    replacement: Option<Vec<u8>>,
    rewinds: u8,
}

impl Read for ReplaceOnSecondPass {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        self.input.read(output)
    }
}

impl Seek for ReplaceOnSecondPass {
    fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
        if position == SeekFrom::Start(0) {
            self.rewinds += 1;
            if self.rewinds == 2 {
                self.input = Cursor::new(self.replacement.take().ok_or_else(|| {
                    std::io::Error::other("replacement backup was already consumed")
                })?);
            }
        }
        self.input.seek(position)
    }
}

#[test]
fn a_different_fully_signed_second_pass_cannot_inherit_the_first_admission()
-> Result<(), StorageError> {
    let (_first_fixture, first) = signed_backup()?;
    let (_second_fixture, second) = signed_backup()?;
    assert_ne!(first, second);
    let mut input = ReplaceOnSecondPass {
        input: Cursor::new(first),
        replacement: Some(second),
        rewinds: 0,
    };
    let mut validator = SourceTranscript::default();
    assert!(matches!(
        validate(&mut input, &mut validator),
        Err(StorageError::StaleState)
    ));
    assert_eq!(validator.begins, 1);
    assert!(!validator.finished);
    assert!(
        validator
            .records
            .keys()
            .any(|(table, _)| *table == TableId::History)
    );
    Ok(())
}
