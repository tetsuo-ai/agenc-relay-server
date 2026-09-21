//! These row fixtures check admission and ownership, not MLS message semantics.
#![forbid(unsafe_code)]
use super::*;
mod retirement;
use crate::budget::MemoryBudget;
use agenc_relay_e2ee::{ObjectId, object::ArcWireObject, tls::TlsEncode};
use agenc_relay_storage::e2ee_records::{MAILBOX_ROW_KIND, MailboxKind, MailboxRow};
use std::sync::Arc;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn pool(bytes: u64) -> (Arc<MemoryBudget>, BackingReservationPort) {
    let budget = Arc::new(MemoryBudget::new(bytes));
    let port = BackingReservationPort::new(Arc::clone(&budget));
    (budget, port)
}
fn object(kind: Kind, marker: u8, size: usize) -> TestResult<(Vec<u8>, Write)> {
    let bytes = ArcWireObject::new(kind, vec![marker; size])?.encode()?;
    let write = super::super::CompanionCoordinator::object_write(&bytes)
        .map_err(|e| format!("object write: {e:?}"))?;
    Ok((bytes, write))
}
fn mailbox(bytes: &[u8], kind: MailboxKind, target: u8) -> TestResult<Write> {
    let key = MailboxRow::item_key(&[target; 32], &[1; 16], kind, 0)?;
    let row = MailboxRow::Item {
        object_id: *ObjectId::compute(bytes).as_bytes(),
        conversation_id: [2; 32],
        inserted_at: 1,
        expires_at: 1000,
        grant: None,
    };
    super::super::request::state_row(TableId::E2eeState, MAILBOX_ROW_KIND, key, row.encode()?)
        .map_err(|e| format!("mailbox write: {e:?}").into())
}
fn admitted(
    state: &CompanionState,
    writes: &[Write],
    backing: &BackingReservationPort,
) -> TestResult<Prepared> {
    prepare(state, writes, backing, None).map_err(|e| format!("admit: {e:?}").into())
}

#[test]
fn rejected_preparation_drops_bodies_while_a_receipt_transfers_each_charge() -> TestResult {
    let (budget, port) = pool(1 << 20);
    let mut state = CompanionState::default();
    let (bytes, write) = object(Kind::CommitMls, 1, 100)?;
    let writes = vec![write];
    let prepared = admitted(&state, &writes, &port)?;
    assert!(budget.charged() > 0);
    assert!(state.objects.is_empty());
    drop(prepared);
    assert_eq!(budget.charged(), 0);
    admitted(&state, &writes, &port)?.apply(&mut state);
    assert_eq!(
        state.objects.get(ObjectId::compute(&bytes).as_bytes()),
        Some(&bytes)
    );
    assert_eq!(state.object_memory.len(), 1);
    assert_eq!(state.object_bytes, bytes.len());
    assert!(budget.charged() > 0);
    drop(state);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn one_shared_mailbox_body_is_charged_once_across_rows_and_existing_state() -> TestResult {
    let (budget, port) = pool(1 << 20);
    let mut state = CompanionState::default();
    let (bytes, first) = object(Kind::WelcomeMls, 2, 100)?;
    let (_, duplicate) = object(Kind::WelcomeMls, 2, 100)?;
    let writes = vec![
        mailbox(&bytes, MailboxKind::Welcome, 1)?,
        first,
        mailbox(&bytes, MailboxKind::Welcome, 2)?,
        duplicate,
    ];
    admitted(&state, &writes, &port)?.apply(&mut state);
    let charged = budget.charged();
    assert_eq!(state.objects.len(), 1);
    assert_eq!(state.object_memory.len(), 1);
    admitted(&state, &writes, &port)?.apply(&mut state);
    assert_eq!(budget.charged(), charged);
    assert_eq!(state.object_bytes, bytes.len());
    Ok(())
}

#[test]
fn unreferenced_payloads_stay_cold_while_required_payloads_and_controls_remain_resident()
-> TestResult {
    let (_, port) = pool(1 << 20);
    let mut state = CompanionState::default();
    let mut writes = Vec::new();
    for (kind, mailbox_kind, marker) in [
        (Kind::ApplicationMls, MailboxKind::Application, 1),
        (Kind::WelcomeMls, MailboxKind::Welcome, 2),
        (Kind::StagedReinit, MailboxKind::StagedReinit, 3),
    ] {
        let (bytes, write) = object(kind, marker, 100)?;
        writes.push(write);
        writes.push(mailbox(&bytes, mailbox_kind, marker)?);
        writes.push(object(kind, marker + 10, 100)?.1);
    }
    writes.push(object(Kind::CommitMls, 30, 100)?.1);
    writes.push(object(Kind::FederationEvent, 31, 100)?.1);
    admitted(&state, &writes, &port)?.apply(&mut state);
    assert_eq!(state.objects.len(), 4);
    assert_eq!(state.object_memory.len(), 4);
    Ok(())
}

#[test]
fn combined_capacity_refuses_the_whole_plan_before_any_state_change() -> TestResult {
    let (budget, port) = pool(1 << 20);
    let (bytes, first) = object(Kind::CommitMls, 1, 100)?;
    // Model an existing near-full resident counter; this is not a 256 MiB load test.
    let state = CompanionState {
        object_bytes: MAX_RETAINED_OBJECT_BYTES - bytes.len(),
        ..CompanionState::default()
    };
    let writes = vec![first, object(Kind::CommitMls, 2, 100)?.1];
    assert!(matches!(
        prepare(&state, &writes, &port, None),
        Err(Code::RateLimited)
    ));
    assert!(state.objects.is_empty());
    assert_eq!(state.object_bytes, MAX_RETAINED_OBJECT_BYTES - bytes.len());
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn later_decode_refusal_releases_all_earlier_prepared_bodies() -> TestResult {
    let (budget, port) = pool(32_768);
    let state = CompanionState::default();
    let writes = vec![
        object(Kind::CommitMls, 1, 100)?.1,
        object(Kind::CommitMls, 2, 16_000)?.1,
    ];
    assert!(matches!(
        prepare(&state, &writes, &port, None),
        Err(Code::RateLimited)
    ));
    assert!(state.objects.is_empty());
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn missing_wrong_kind_and_conflicting_required_rows_refuse_private_preparation() -> TestResult {
    for fault in 0..3 {
        let (budget, port) = pool(1 << 20);
        let state = CompanionState::default();
        let (bytes, write) = object(Kind::WelcomeMls, 1, 100)?;
        let mut writes = vec![mailbox(
            &bytes,
            if fault == 1 {
                MailboxKind::Application
            } else {
                MailboxKind::Welcome
            },
            1,
        )?];
        if fault != 0 {
            writes.push(write);
        }
        if fault == 2 {
            writes.push(mailbox(&bytes, MailboxKind::Application, 2)?);
        }
        assert!(matches!(
            prepare(&state, &writes, &port, None),
            Err(Code::InvalidFragment)
        ));
        assert!(state.objects.is_empty());
        assert_eq!(budget.charged(), 0);
    }
    Ok(())
}

#[test]
fn an_unselected_body_cannot_hide_a_wrong_storage_key() -> TestResult {
    let (budget, port) = pool(1 << 20);
    let (_, mut write) = object(Kind::ApplicationMls, 1, 100)?;
    let Write::Put { key, .. } = &mut write else {
        return Err("put".into());
    };
    *key = StoredKey::new(vec![99; 32])?;
    assert!(matches!(
        prepare(&CompanionState::default(), &[write], &port, None),
        Err(Code::InvalidFragment)
    ));
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn cold_fetch_exclusion_does_not_create_a_new_copy_or_hide_required_mailbox_data() -> TestResult {
    let (budget, port) = pool(1 << 20);
    let mut state = CompanionState::default();
    let (bytes, write) = object(Kind::CommitMls, 1, 100)?;
    prepare(
        &state,
        &[write],
        &port,
        Some(*ObjectId::compute(&bytes).as_bytes()),
    )
    .map_err(|e| format!("exclude: {e:?}"))?
    .apply(&mut state);
    assert!(state.objects.is_empty());
    assert_eq!(budget.charged(), 0);
    let (bytes, write) = object(Kind::WelcomeMls, 1, 100)?;
    assert!(matches!(
        prepare(
            &state,
            &[write, mailbox(&bytes, MailboxKind::Welcome, 1)?],
            &port,
            Some(*ObjectId::compute(&bytes).as_bytes())
        ),
        Err(Code::InvalidFragment)
    ));
    assert_eq!(budget.charged(), 0);
    Ok(())
}
