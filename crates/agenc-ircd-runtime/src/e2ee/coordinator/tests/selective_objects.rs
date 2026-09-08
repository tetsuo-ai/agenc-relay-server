//! Object selection tests cover envelopes and ownership; mailbox lineage has separate tests.
#![forbid(unsafe_code)]
use super::*;
use crate::budget::MemoryBudget;
use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind as Kind};
use agenc_ircd_e2ee::tls::TlsEncode;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{MailboxKind, MailboxRow};
use std::sync::Arc;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn body(kind: Kind, marker: u8) -> TestResult<(StoredKey, PersistentRecordValue, Vec<u8>)> {
    let bytes = IrcWireObject::new(kind, vec![marker; 32])?.encode()?;
    let row = ObjectRow::new(bytes.clone())?;
    let value = PersistentRecordValue::new(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    Ok((row.key()?, value, bytes))
}
fn item(kind: MailboxKind, bytes: &[u8], marker: u8) -> TestResult<(StoredKey, MailboxRow)> {
    Ok((
        MailboxRow::item_key(&[marker; 32], &[1; 16], kind, 0)?,
        MailboxRow::Item {
            object_id: *ObjectId::compute(bytes).as_bytes(),
            conversation_id: [2; 32],
            inserted_at: 1,
            expires_at: 1000,
            grant: None,
        },
    ))
}
fn pool(bytes: u64) -> (Arc<MemoryBudget>, BackingReservationPort) {
    let budget = Arc::new(MemoryBudget::new(bytes));
    let backing = BackingReservationPort::new(Arc::clone(&budget));
    (budget, backing)
}

#[test]
fn selected_mailbox_payloads_and_control_objects_keep_their_backing_after_restore() -> TestResult {
    let (budget, backing) = pool(1 << 20);
    let mut rows = Vec::new();
    let mut bodies = Vec::new();
    for (kind, mailbox, marker) in [
        (Kind::ApplicationMls, MailboxKind::Application, 1),
        (Kind::WelcomeMls, MailboxKind::Welcome, 2),
        (Kind::StagedReinit, MailboxKind::StagedReinit, 3),
    ] {
        let object = body(kind, marker)?;
        rows.push(item(mailbox, &object.2, marker)?);
        bodies.push(object);
    }
    let mut restore = Restore::default();
    restore.select(&rows, backing)?;
    for (key, value, _) in &bodies {
        restore.admit(key, value);
    }
    let (cold_key, cold, _) = body(Kind::ApplicationMls, 4)?;
    restore.admit(&cold_key, &cold);
    let (control_key, control, _) = body(Kind::CommitMls, 5)?;
    restore.admit(&control_key, &control);
    let mut state = CompanionState::default();
    restore.apply(&mut state)?;
    assert_eq!(state.objects.len(), 4);
    assert_eq!(state.object_memory.len(), 4);
    assert!(budget.charged() > 0);
    for (_, _, bytes) in bodies {
        assert_eq!(
            state.objects.get(ObjectId::compute(&bytes).as_bytes()),
            Some(&bytes)
        );
    }
    assert!(
        !state
            .objects
            .contains_key(&<[u8; 32]>::try_from(cold_key.as_bytes())?)
    );
    drop(state);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn shared_mailbox_payload_is_retained_once_and_conflicting_kinds_are_refused() -> TestResult {
    let (_, backing) = pool(1 << 20);
    let (key, value, bytes) = body(Kind::WelcomeMls, 6)?;
    let mut rows = vec![
        item(MailboxKind::Welcome, &bytes, 1)?,
        item(MailboxKind::Welcome, &bytes, 2)?,
    ];
    let mut restore = Restore::default();
    restore.select(&rows, backing.clone())?;
    restore.admit(&key, &value);
    let mut state = CompanionState::default();
    restore.apply(&mut state)?;
    assert_eq!(state.objects.len(), 1);
    assert_eq!(state.object_memory.len(), 1);
    rows.push(item(MailboxKind::Application, &bytes, 3)?);
    assert!(Restore::default().select(&rows, backing).is_err());
    Ok(())
}

#[test]
fn missing_or_wrong_kind_required_bodies_refuse_before_publishing() -> TestResult {
    for missing in [true, false] {
        let (budget, backing) = pool(1 << 20);
        let (key, value, bytes) = body(Kind::ApplicationMls, 8)?;
        let rows = vec![item(MailboxKind::Welcome, &bytes, 1)?];
        let mut restore = Restore::default();
        restore.select(&rows, backing)?;
        if !missing {
            restore.admit(&key, &value);
        }
        let mut state = CompanionState::default();
        assert!(restore.apply(&mut state).is_err());
        assert!(state.objects.is_empty());
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}

#[test]
fn a_malformed_unselected_row_poisoning_cannot_be_hidden_by_later_valid_rows() -> TestResult {
    let (budget, backing) = pool(1 << 20);
    let mut restore = Restore::default();
    restore.select(&[], backing)?;
    let (_, value, _) = body(Kind::ApplicationMls, 9)?;
    restore.admit(&StoredKey::new(vec![99; 32])?, &value);
    let (key, value, _) = body(Kind::CommitMls, 10)?;
    restore.admit(&key, &value);
    let mut state = CompanionState::default();
    assert!(restore.apply(&mut state).is_err());
    assert!(state.objects.is_empty());
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn selection_cannot_start_twice_or_after_object_collection() -> TestResult {
    let (_, backing) = pool(1 << 20);
    let mut restore = Restore::default();
    restore.select(&[], backing.clone())?;
    assert!(restore.select(&[], backing.clone()).is_err());
    let mut full = Restore::default();
    let (key, value, _) = body(Kind::CommitMls, 11)?;
    full.admit(&key, &value);
    assert!(full.select(&[], backing).is_err());
    Ok(())
}

#[test]
fn required_existing_objects_cannot_bypass_kind_or_hash_checks() -> TestResult {
    let (_, backing) = pool(1 << 20);
    let (_, _, bytes) = body(Kind::ApplicationMls, 12)?;
    let mut state = CompanionState::default();
    state
        .objects
        .insert(*ObjectId::compute(&bytes).as_bytes(), bytes.clone());
    let mut restore = Restore::default();
    restore.select(&[item(MailboxKind::Welcome, &bytes, 1)?], backing)?;
    assert!(restore.apply(&mut state).is_err());
    Ok(())
}

#[test]
fn failed_body_reservation_releases_the_private_selection_and_bodies() -> TestResult {
    let (budget, backing) = pool(16_384);
    let mut restore = Restore::default();
    restore.select(&[], backing)?;
    let bytes = IrcWireObject::new(Kind::CommitMls, vec![1; 16_000])?.encode()?;
    let row = ObjectRow::new(bytes)?;
    let value = PersistentRecordValue::new(
        TableId::E2eeObject,
        OBJECT_RECORD_KIND,
        1,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    restore.admit(&row.key()?, &value);
    let mut state = CompanionState::default();
    assert!(restore.apply(&mut state).is_err());
    assert!(state.objects.is_empty());
    assert_eq!(budget.charged(), 0);
    Ok(())
}
