//! Mandatory semantic admission under an exact predecessor source profile.
#![forbid(unsafe_code)]

use crate::migration_profile::MigrationProfile;
use crate::{
    AuthenticatedSourceRecord, ConstructionSourceDatabase, ConstructionSourceFacts,
    SourceRecordValidator, StorageError,
};

pub(super) enum SourceAdmission<'a> {
    LegacyOne,
    SchemaTwo(&'a mut dyn SourceRecordValidator),
    SchemaThree(&'a mut dyn SourceRecordValidator),
}

impl SourceAdmission<'_> {
    pub(super) const fn profile(&self) -> MigrationProfile {
        match self {
            Self::LegacyOne => MigrationProfile::OneToTwo,
            Self::SchemaTwo(_) => MigrationProfile::TwoToThree,
            Self::SchemaThree(_) => MigrationProfile::ThreeToFour,
        }
    }

    pub(super) fn validate(
        &mut self,
        source: &ConstructionSourceDatabase,
    ) -> Result<(), StorageError> {
        match self {
            Self::LegacyOne => {}
            Self::SchemaTwo(validator) => {
                source.validate_source_records(&mut SchemaTwoValidator {
                    validator: *validator,
                })?
            }
            Self::SchemaThree(validator) => {
                source.validate_source_records(&mut SchemaThreeValidator {
                    validator: *validator,
                })?
            }
        }
        Ok(())
    }
}

struct SchemaTwoValidator<'a> {
    validator: &'a mut dyn SourceRecordValidator,
}

impl SourceRecordValidator for SchemaTwoValidator<'_> {
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError> {
        if facts.header.tbs().schema_generation != 2 {
            return Err(StorageError::UnsupportedMigration);
        }
        self.validator.begin_source(facts)
    }

    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        crate::migration_v2::validate_source(
            record.table(),
            record.key(),
            record.record_schema(),
            record.plaintext(),
        )?;
        self.validator.validate_record(record)
    }

    fn finish_source(&mut self) -> Result<(), StorageError> {
        self.validator.finish_source()
    }
}

struct SchemaThreeValidator<'a> {
    validator: &'a mut dyn SourceRecordValidator,
}

impl SourceRecordValidator for SchemaThreeValidator<'_> {
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError> {
        if facts.header.tbs().schema_generation != 3 {
            return Err(StorageError::UnsupportedMigration);
        }
        self.validator.begin_source(facts)
    }

    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        crate::migration_v3::validate_source(
            record.table(),
            record.key(),
            record.record_schema(),
            record.plaintext(),
        )?;
        self.validator.validate_record(record)
    }

    fn finish_source(&mut self) -> Result<(), StorageError> {
        self.validator.finish_source()
    }
}
