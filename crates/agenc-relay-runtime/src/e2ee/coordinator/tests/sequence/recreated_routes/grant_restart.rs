//! A durable lease keeps the same authority across a coordinator restart.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::request_expiry::{Cursor, Prepared};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_storage::e2ee_records::ClaimRow;

#[test]
fn channel_grant_survives_reopen_and_bind_consumes_only_its_claim() -> TestResult {
    let mut source = Harness::new()?;
    source.publish_identity_and_roster()?;
    source.attach()?;
    let grant = ok_reservation(reserve_channel(&mut source, SECOND_INSTANCE)?)?;
    let group = next_channel(&source, 0, [0; 32])?;
    let mut reopened = source.reloaded()?;
    assert_eq!(
        refusal(reserve_channel(&mut reopened, SECOND_INSTANCE)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    bind_and_publish(&mut reopened, grant, &group)?;
    let key = ClaimRow::reservation_key(&grant)?;
    assert!(
        !reopened
            .writes
            .iter()
            .any(|row| matches!(row, Write::Put {key: k, ..} if *k == key))
    );
    let again = reopened.reloaded()?;
    assert_eq!(
        again
            .coordinator
            .state
            .routes
            .route(&ConversationId(group.conversation))
            .ok_or("missing route")?
            .conversation_id,
        ConversationId(group.conversation)
    );
    Ok(())
}

#[test]
fn direct_grant_survives_reopen_and_renewal_uses_a_fresh_nonce() -> TestResult {
    let mut source = Harness::new()?;
    source.publish_identity_and_roster()?;
    source.attach()?;
    let peer = direct_peer(&mut source)?;
    let account = peer.root.tbs.account_id.as_slice().try_into()?;
    let (old, nonce) = ok_reservation(reserve_direct(&mut source, &account)?)?;
    let expires = source
        .coordinator
        .state
        .routes
        .reservations()
        .find(|r| r.reservation_id.0 == old)
        .ok_or("missing grant")?
        .expires_at;
    let before = direct_group(&source, &peer, (0, [0; 32]), nonce, DIRECT_GROUP)?;
    let mut live = source.reloaded()?;
    live.now = expires - 1;
    assert_eq!(
        refusal(reserve_direct(&mut live, &account)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    bind_and_publish(&mut live, old, &before)?;
    let mut late = source.reloaded()?;
    late.now = expires;
    assert_eq!(
        code(bind(&mut late, old, &before)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let (new, next_nonce) = ok_reservation(reserve_direct(&mut late, &account)?)?;
    let old_key = ClaimRow::reservation_key(&old)?;
    assert!(
        !late
            .writes
            .iter()
            .any(|row| matches!(row, Write::Put {key,..} if key == &old_key))
    );
    // A clock adjustment before another maintenance turn cannot revive it.
    late.now = expires - 1;
    assert_eq!(
        code(bind(&mut late, old, &before)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    late.now = expires;
    assert_ne!(old, new);
    assert_ne!(nonce, next_nonce);
    assert_eq!(
        code(bind(&mut late, new, &before)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let after = direct_group(&late, &peer, (0, [0; 32]), next_nonce, SECOND_DIRECT_GROUP)?;
    bind_and_publish(&mut late, new, &after)
        .map_err(|e| format!("renewed Direct publication: {e}"))?;
    Ok(())
}

#[test]
fn maintenance_releases_unconsumed_claims_after_restart_at_the_deadline() -> TestResult {
    let mut source = Harness::new()?;
    source.publish_identity_and_roster()?;
    source.attach()?;
    let a = ok_reservation(reserve_channel(&mut source, INSTANCE)?)?;
    let b = ok_reservation(reserve_channel(&mut source, SECOND_INSTANCE)?)?;
    let expires = source
        .coordinator
        .state
        .routes
        .reservations()
        .next()
        .ok_or("missing grant")?
        .expires_at;
    let mut reopened = source.reloaded()?;
    let prepare =
        |h: &Harness, now| Prepared::capture(&h.coordinator, Cursor::default(), now, &h.backing);
    assert!(prepare(&reopened, expires - 1)?.is_empty());
    let batch = prepare(&reopened, expires)?;
    let planned = batch.writes(1)?;
    for id in [a, b] {
        let key = ClaimRow::reservation_key(&id)?;
        assert!(
            planned
                .iter()
                .any(|row| matches!(row, Write::Delete {key: k, ..} if *k == key))
        );
    }
    assert_eq!(planned.len(), 2);
    batch.apply(&mut reopened.coordinator)?;
    assert!(prepare(&reopened, expires)?.is_empty());
    Ok(())
}

#[test]
fn legacy_grants_for_one_target_are_reclaimed_independently() -> TestResult {
    let mut source = Harness::new()?;
    source.publish_identity_and_roster()?;
    source.attach()?;
    let old = ok_reservation(reserve_channel(&mut source, INSTANCE)?)?;
    let key = ClaimRow::reservation_key(&old)?;
    let old_row = archived_claim(&source, &key)?;
    source.now += agenc_relay_e2ee::limits::RESERVATION_TIMEOUT_SECONDS;
    let current = ok_reservation(reserve_channel(&mut source, INSTANCE)?)?;
    // A pre-upgrade store could contain several ordinary owner rows for one
    // target. Keep the earlier row as it appeared on disk alongside the new one.
    source
        .writes
        .push(Write::put(old_row.0, key.clone(), old_row.1)?);
    let mut reopened = source.reloaded()?;
    reopened.now = source.now;
    let batch = Prepared::capture(
        &reopened.coordinator,
        Cursor::default(),
        reopened.now,
        &reopened.backing,
    )?;
    let writes = batch.writes(1)?;
    assert!(matches!(writes.as_slice(), [Write::Delete {key: removed, ..}] if *removed == key));
    batch.apply(&mut reopened.coordinator)?;
    assert_eq!(
        refusal(reserve_channel(&mut reopened, INSTANCE)?),
        Some(E2eeReplyCode::GroupConflict)
    );
    let group = group(
        &reopened,
        &[creator(&reopened)?],
        channel_route(b"#room", root_fingerprint(&reopened.principal.root)?)?,
        (Some(INSTANCE), None),
        SECOND_GROUP,
    )?;
    bind_and_publish(&mut reopened, current, &group)?;
    Ok(())
}

/// A reservation row exactly as a pre-upgrade server would leave it on disk.
fn archived_claim(
    h: &Harness,
    key: &agenc_relay_storage::StoredKey,
) -> TestResult<(agenc_relay_storage::TableId, Vec<u8>)> {
    h.writes
        .iter()
        .find_map(|row| match row {
            Write::Put {
                table,
                key: found,
                plaintext,
            } if found == key => Some((*table, plaintext.to_vec())),
            _ => None,
        })
        .ok_or_else(|| "archived reservation claim".into())
}

#[test]
fn a_consumed_legacy_direct_grant_does_not_delay_the_next_authorized_incarnation() -> TestResult {
    let mut source = Harness::new()?;
    source.publish_identity_and_roster()?;
    source.attach()?;
    let peer = direct_peer(&mut source)?;
    let account = peer.root.tbs.account_id.as_slice().try_into()?;
    let (old, first_nonce) = ok_reservation(reserve_direct(&mut source, &account)?)?;
    let key = ClaimRow::reservation_key(&old)?;
    let row = archived_claim(&source, &key)?;
    let original = direct_group(&source, &peer, (0, [0; 32]), first_nonce, DIRECT_GROUP)?;
    bind_and_publish(&mut source, old, &original)?;
    operate(&mut source, original.conversation, None)?;
    let closed = close(&mut source, original.conversation, 2)?;
    source.writes.push(Write::put(row.0, key.clone(), row.1)?);
    let mut reopened = source.reloaded()?;
    let batch = Prepared::capture(
        &reopened.coordinator,
        Cursor::default(),
        reopened.now,
        &reopened.backing,
    )?;
    assert!(
        matches!(batch.writes(1)?.as_slice(), [Write::Delete {key: removed, ..}] if *removed == key)
    );
    let (next, nonce) = ok_reservation(reserve_direct(&mut reopened, &account)?)?;
    assert_ne!(nonce, first_nonce);
    let successor = direct_group(&reopened, &peer, (1, closed), nonce, SECOND_DIRECT_GROUP)?;
    bind_and_publish(&mut reopened, next, &successor)?;
    Ok(())
}

#[test]
fn selective_startup_keeps_one_backing_charge_per_old_grant() -> TestResult {
    use crate::budget::{BackingReservationPort, MemoryBudget};
    use agenc_relay_storage::e2ee_records::{CLAIM_ROW_KIND, ObjectRow};
    use agenc_relay_storage::{PersistentRecordValue, TableId};
    use std::sync::Arc;

    let mut source = Harness::new()?;
    source.publish_identity_and_roster()?;
    source.attach()?;
    let mut grants = Vec::new();
    for instance in [31, 32, 33, 34] {
        grants.push(ok_reservation(reserve_channel(
            &mut source,
            [instance; 16],
        )?)?);
    }
    let budget = Arc::new(MemoryBudget::new(8 * 4096));
    let port = BackingReservationPort::new(Arc::clone(&budget));
    let mut fresh = Harness::new()?;
    let mut objects = Vec::new();
    for write in &source.writes {
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            continue;
        };
        if *table != TableId::E2eeState {
            continue;
        }
        let value = PersistentRecordValue::decode(*table, plaintext)?;
        if value.record_kind() == CLAIM_ROW_KIND
            && let ClaimRow::Reservation {
                reservation_object_id,
                ..
            } = ClaimRow::decode(value.body())?
        {
            objects.push(reservation_object_id);
            fresh
                .coordinator
                .admit_restored_with_backing(*table, key, &value, &port);
        }
    }
    assert_eq!(objects.len(), grants.len());
    fresh.coordinator.select_restored_objects(port.clone())?;
    for write in &source.writes {
        let Write::Put {
            table,
            key,
            plaintext,
        } = write
        else {
            continue;
        };
        if *table != TableId::E2eeObject {
            continue;
        }
        let value = PersistentRecordValue::decode(*table, plaintext)?;
        let row = ObjectRow::decode(value.body())?;
        if objects.contains(agenc_relay_e2ee::ObjectId::compute(&row.bytes).as_bytes()) {
            fresh
                .coordinator
                .admit_restored_with_backing(*table, key, &value, &port);
        }
    }
    fresh.coordinator.finish_restore_with_backing(port)?;
    assert!(
        objects
            .iter()
            .all(|id| !fresh.coordinator.state.objects.contains_key(id))
    );
    assert!(
        grants
            .iter()
            .all(|id| fresh.coordinator.state.reservations.contains(id))
    );
    assert_eq!(budget.charged(), 4 * 4096);
    drop(fresh);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn a_reopened_channel_grant_keeps_the_original_account_as_owner() -> TestResult {
    let mut source = Harness::new()?;
    source.publish_identity_and_roster()?;
    source.attach()?;
    let peer = direct_peer(&mut source)?;
    let grant = ok_reservation(reserve_channel(&mut source, SECOND_INSTANCE)?)?;
    let group = next_channel(&source, 0, [0; 32])?;
    let mut reopened = source.reloaded()?;
    let account = peer.root.tbs.account_id.as_slice().try_into()?;
    let origin = reopened
        .coordinator
        .state
        .origins
        .get_mut(&origin_key())
        .ok_or("origin")?;
    origin.account_id = Some(account);
    origin.account_digest = Some(agenc_relay_e2ee::ids::account_id_digest(
        &NETWORK, &account,
    )?);
    origin.device = None;
    reopened.attach_as(PEER_DEVICE)?;
    assert_eq!(
        code(bind(&mut reopened, grant, &group)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    Ok(())
}

#[test]
fn overlapping_legacy_rows_wait_for_expiry_before_publication() -> TestResult {
    let mut source = Harness::new()?;
    source.publish_identity_and_roster()?;
    source.attach()?;
    let first = ok_reservation(reserve_channel(&mut source, SECOND_INSTANCE)?)?;
    let group = next_channel(&source, 0, [0; 32])?;
    // Import another historical row with the same signed instance and deadline.
    let mut archive = Harness::new()?;
    archive.publish_identity_and_roster()?;
    archive.attach()?;
    ok_reservation(reserve_channel(&mut archive, THIRD_INSTANCE)?)?;
    let second = ok_reservation(reserve_channel(&mut archive, SECOND_INSTANCE)?)?;
    assert_ne!(first, second);
    let key = ClaimRow::reservation_key(&second)?;
    let row = archived_claim(&archive, &key)?;
    let stored = agenc_relay_storage::PersistentRecordValue::decode(row.0, &row.1)?;
    let ClaimRow::Reservation {
        reservation_object_id,
        ..
    } = ClaimRow::decode(stored.body())?
    else {
        return Err("archive grant".into());
    };
    source.writes.push(Write::put(row.0, key, row.1)?);
    for write in archive.writes {
        if let Write::Put {
            table: agenc_relay_storage::TableId::E2eeObject,
            ref key,
            ..
        } = write
            && key.as_bytes() == reservation_object_id
        {
            source.writes.push(write);
        }
    }
    let mut reopened = source.reloaded()?;
    for grant in [first, second] {
        assert_eq!(
            code(bind(&mut reopened, grant, &group)?),
            Some(E2eeReplyCode::BindingAuthInvalid)
        );
    }
    reopened.now += agenc_relay_e2ee::limits::RESERVATION_TIMEOUT_SECONDS;
    let fresh = ok_reservation(reserve_channel(&mut reopened, SECOND_INSTANCE)?)?;
    bind_and_publish(&mut reopened, fresh, &group)?;
    Ok(())
}
