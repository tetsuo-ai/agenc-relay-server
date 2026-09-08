//! Startup must not publish a state with silently omitted durable objects.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_e2ee::limits::WIRE_OBJECT_ENVELOPE_BYTES;
use agenc_ircd_e2ee::tls::TlsEncode;
use agenc_ircd_storage::e2ee_records::{OBJECT_RECORD_KIND, ObjectRow};
use agenc_ircd_types::ServerId;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn coordinator() -> CompanionCoordinator {
    CompanionCoordinator::new(
        [1; 32],
        ServerId::from_bytes([2; 16]),
        "coordinator.test".into(),
    )
}

fn admit(coordinator: &mut CompanionCoordinator, marker: u8, bytes: usize) -> TestResult {
    let body_bytes = bytes
        .checked_sub(WIRE_OBJECT_ENVELOPE_BYTES)
        .ok_or("short object")?;
    let object = IrcWireObject::new(IrcWireObjectKind::WelcomeMls, vec![marker; body_bytes])?;
    let row = ObjectRow::new(object.encode()?)?;
    let value = PersistentRecordValue::new(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    coordinator.admit_restored(TableId::E2eeObject, &row.key()?, &value);
    Ok(())
}

#[test]
fn startup_refuses_object_capacity_loss_before_publishing_any_objects() -> TestResult {
    let mut coordinator = coordinator();
    // Every row passes the real storage envelope codec. No route requires
    // these objects, so only complete object reconstruction can reject the loss.
    for marker in 0..=64 {
        admit(&mut coordinator, marker, 4 * 1024 * 1024)?;
    }
    assert!(
        coordinator.finish_restore().is_err(),
        "startup accepted an incomplete object cache"
    );
    assert!(
        coordinator.state.objects.is_empty(),
        "failed startup published a partial cache"
    );
    Ok(())
}

#[test]
fn startup_preserves_each_object_when_capacity_is_available() -> TestResult {
    let mut coordinator = coordinator();
    admit(&mut coordinator, 1, 1024)?;
    admit(&mut coordinator, 2, 2048)?;
    coordinator.finish_restore()?;
    assert_eq!(coordinator.state.objects.len(), 2);
    assert_eq!(coordinator.state.object_bytes, 3072);
    Ok(())
}

#[test]
fn repeated_object_does_not_consume_capacity_twice() -> TestResult {
    let mut coordinator = coordinator();
    admit(&mut coordinator, 1, 1024)?;
    admit(&mut coordinator, 1, 1024)?;
    coordinator.finish_restore()?;
    assert_eq!(coordinator.state.objects.len(), 1);
    assert_eq!(coordinator.state.object_bytes, 1024);
    admit(&mut coordinator, 1, 1024)?;
    admit(&mut coordinator, 2, 1024)?;
    coordinator.finish_restore()?;
    assert_eq!(coordinator.state.objects.len(), 2);
    assert_eq!(coordinator.state.object_bytes, 2048);
    Ok(())
}

#[test]
fn wrong_object_key_poisons_restore_even_when_valid_rows_follow() -> TestResult {
    let mut coordinator = coordinator();
    let row =
        ObjectRow::new(IrcWireObject::new(IrcWireObjectKind::WelcomeMls, vec![1; 32])?.encode()?)?;
    let value = PersistentRecordValue::new(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    let wrong = StoredKey::new(vec![7; 32])?;
    assert!(wrong != row.key()?);
    coordinator.admit_restored(TableId::E2eeObject, &wrong, &value);
    admit(&mut coordinator, 2, 1024)?;
    assert!(coordinator.finish_restore().is_err());
    assert!(coordinator.state.objects.is_empty());
    Ok(())
}

#[test]
fn existing_objects_and_restored_objects_share_one_capacity_limit() -> TestResult {
    let mut coordinator = coordinator();
    for marker in 0..64 {
        admit(&mut coordinator, marker, 4 * 1024 * 1024)?;
    }
    coordinator.finish_restore()?;
    assert_eq!(coordinator.state.objects.len(), 64);
    assert_eq!(coordinator.state.object_bytes, 256 * 1024 * 1024);
    admit(&mut coordinator, 64, 1024)?;
    assert!(coordinator.finish_restore().is_err());
    assert_eq!(coordinator.state.objects.len(), 64);
    assert_eq!(coordinator.state.object_bytes, 256 * 1024 * 1024);
    Ok(())
}
