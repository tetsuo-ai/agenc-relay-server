//! Composition-owned semantic checks over an authenticated offline source.
#![forbid(unsafe_code)]

use crate::{
    ConstructionSourceDatabase, ConstructionSourceFacts, StorageError, StoredKey, TableId,
};

/// A borrowed source row whose seal and source-generation grammar were checked.
///
/// Storage constructs this view while the authenticated source remains owned.
/// The bytes retain their original encoding. A record callback does not prove
/// that a complete database or signed backup has passed semantic validation.
pub struct AuthenticatedSourceRecord<'a> {
    source_schema_generation: u64,
    table: TableId,
    key: &'a StoredKey,
    record_schema: u32,
    plaintext: &'a [u8],
}

impl<'a> AuthenticatedSourceRecord<'a> {
    pub(crate) fn checked(
        source_schema_generation: u64,
        table: TableId,
        key: &'a StoredKey,
        record_schema: u32,
        plaintext: &'a [u8],
    ) -> Result<Self, StorageError> {
        crate::migration::validate_source_record(
            source_schema_generation,
            table,
            key,
            record_schema,
            plaintext,
        )?;
        Ok(Self {
            source_schema_generation,
            table,
            key,
            record_schema,
            plaintext,
        })
    }

    /// Returns the generation in the authenticated source header.
    #[must_use]
    pub const fn source_schema_generation(&self) -> u64 {
        self.source_schema_generation
    }

    /// Returns the authenticated source table.
    #[must_use]
    pub const fn table(&self) -> TableId {
        self.table
    }

    /// Borrows the exact authenticated stored key.
    #[must_use]
    pub const fn key(&self) -> &'a StoredKey {
        self.key
    }

    /// Returns the authenticated per-record schema.
    #[must_use]
    pub const fn record_schema(&self) -> u32 {
        self.record_schema
    }

    /// Borrows the exact original plaintext without normalizing signed content.
    #[must_use]
    pub const fn plaintext(&self) -> &'a [u8] {
        self.plaintext
    }
}

/// Required semantic policy supplied by the maintenance command's composition.
///
/// Implementations must bind the source profile in `begin_source`, validate
/// embedded protocol meanings and signatures, and require complete chain and
/// checkpoint reconciliation in `finish_source`. Neither callback may create
/// output or advance authority. Failed validation must discard its transient
/// state; another scan starts with `begin_source` again.
pub trait SourceRecordValidator {
    /// Starts a fresh validation transcript for these exact authenticated facts.
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError>;

    /// Observes one original authenticated record in source table/key order.
    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError>;

    /// Requires all cross-record checks to finish before source admission.
    fn finish_source(&mut self) -> Result<(), StorageError>;
}

impl ConstructionSourceDatabase {
    /// Runs the required semantic policy over the continuously locked source.
    ///
    /// A maintenance caller must complete this scan before creating a backup or
    /// target, including on resume and already-installed-output paths. Success
    /// does not remove the construction executor's exact sealed-source checks.
    pub fn validate_source_records(
        &self,
        validator: &mut dyn SourceRecordValidator,
    ) -> Result<(), StorageError> {
        let facts = self.facts()?;
        validator.begin_source(&facts)?;
        self.engine
            .visit_construction_source_records(|source, record| {
                validator.validate_record(AuthenticatedSourceRecord::checked(
                    facts.header.tbs().schema_generation,
                    source.table(),
                    source.key(),
                    source.record_schema(),
                    record.plaintext(),
                )?)
            })?;
        validator.finish_source()
    }
}
