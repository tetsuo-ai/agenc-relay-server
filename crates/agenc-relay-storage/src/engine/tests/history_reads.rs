//! Exact multi-key reads preserve order and never return intervening rows.
#![forbid(unsafe_code)]

use super::*;

#[test]
fn exact_multi_key_read_preserves_order_omits_missing_and_skips_intervening_rows()
-> Result<(), StorageError> {
    let mut fixture = EngineFixture::create()?;
    for byte in [1, 2, 3] {
        let engine = fixture.engine_mut()?;
        let batch = EngineFixture::advancing_batch(engine, byte)?;
        assert!(matches!(engine.commit(batch), CommitOutcome::Committed(_)));
    }
    let plan = ReadPlan::exact_keys(
        TableId::Account,
        vec![
            EngineFixture::account_key(3)?,
            EngineFixture::account_key(99)?,
            EngineFixture::account_key(1)?,
        ],
    )?;
    let result = fixture.engine()?.read(&plan)?;
    assert!(!result.truncated);
    assert_eq!(result.records.len(), 2);
    let expected = [
        EngineFixture::account_key(3)?,
        EngineFixture::account_key(1)?,
    ];
    for (record, key) in result.records.iter().zip(expected) {
        assert_eq!(record.key.as_bytes(), key.as_bytes());
    }
    Ok(())
}
