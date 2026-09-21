//! Complete semantic-source callbacks remain inside the locked read boundary.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::{
    AuthenticatedSourceRecord, ConstructionSourceFacts, SourceRecordValidator,
};

#[derive(Clone, Copy, Eq, PartialEq)]
enum RefuseAt {
    Never,
    Begin,
    Record(u64),
    Finish,
}

struct ValidationTranscript {
    facts: ConstructionSourceFacts,
    refuse: RefuseAt,
    begins: u64,
    observed: u64,
    previous: Option<(TableId, StoredKey)>,
    finished: bool,
}

impl ValidationTranscript {
    fn new(facts: ConstructionSourceFacts, refuse: RefuseAt) -> Self {
        Self {
            facts,
            refuse,
            begins: 0,
            observed: 0,
            previous: None,
            finished: false,
        }
    }
}

impl SourceRecordValidator for ValidationTranscript {
    fn begin_source(&mut self, facts: &ConstructionSourceFacts) -> Result<(), StorageError> {
        assert_eq!(facts, &self.facts);
        self.begins += 1;
        self.observed = 0;
        self.previous = None;
        self.finished = false;
        if self.refuse == RefuseAt::Begin {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    fn validate_record(
        &mut self,
        record: AuthenticatedSourceRecord<'_>,
    ) -> Result<(), StorageError> {
        assert_eq!(
            record.source_schema_generation(),
            self.facts.header.tbs().schema_generation,
        );
        validate_record_plaintext(
            record.table(),
            record.key(),
            record.record_schema(),
            record.plaintext(),
        )?;
        if let Some((table, key)) = &self.previous {
            assert!((*table, key) < (record.table(), record.key()));
        }
        self.observed += 1;
        self.previous = Some((record.table(), record.key().clone()));
        if self.refuse == RefuseAt::Record(self.observed) {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(())
    }

    fn finish_source(&mut self) -> Result<(), StorageError> {
        if self.refuse == RefuseAt::Finish {
            return Err(StorageError::InvalidEncoding);
        }
        self.finished = true;
        Ok(())
    }
}

fn validation_source(
    fixture: &InitializedLiveFixture,
) -> Result<ConstructionSourceDatabase, StorageError> {
    ConstructionSourceDatabase::open(live_open_config(StateDirectory::open(
        fixture.directory.path(),
        &[fixture.qualification],
    )?))
}

#[test]
fn a_complete_locked_source_scan_preserves_exact_facts_and_source_order()
-> Result<(), Box<dyn Error>> {
    let fixture = initialized_live_fixture_from(comprehensive_initial_state()?.records)?;
    let source = validation_source(&fixture)?;
    let facts = source.facts()?;
    let expected_records = 21;
    let mut validator = ValidationTranscript::new(facts, RefuseAt::Never);
    source.validate_source_records(&mut validator)?;
    assert_eq!(validator.begins, 1);
    assert_eq!(validator.observed, expected_records);
    assert!(validator.finished);
    assert_eq!(source.facts()?, facts);
    source.validate_source_records(&mut validator)?;
    assert_eq!(validator.begins, 2);
    assert_eq!(validator.observed, expected_records);
    assert!(validator.finished);
    assert_eq!(source.facts()?, facts);
    Ok(())
}

#[test]
fn a_source_validator_refusal_never_completes_or_changes_the_source() -> Result<(), Box<dyn Error>>
{
    let fixture = initialized_live_fixture_from(comprehensive_initial_state()?.records)?;
    let source = validation_source(&fixture)?;
    let facts = source.facts()?;
    let expected_records = 21;
    for (refuse, observed) in [
        (RefuseAt::Begin, 0),
        (RefuseAt::Record(5), 5),
        (RefuseAt::Finish, expected_records),
    ] {
        let mut validator = ValidationTranscript::new(facts, refuse);
        assert_eq!(
            source.validate_source_records(&mut validator),
            Err(StorageError::InvalidEncoding),
        );
        assert_eq!(validator.begins, 1);
        assert_eq!(validator.observed, observed);
        assert!(!validator.finished);
        assert_eq!(source.facts()?, facts);
        validator.refuse = RefuseAt::Never;
        source.validate_source_records(&mut validator)?;
        assert_eq!(validator.begins, 2);
        assert_eq!(validator.observed, expected_records);
        assert!(validator.finished);
    }
    Ok(())
}
