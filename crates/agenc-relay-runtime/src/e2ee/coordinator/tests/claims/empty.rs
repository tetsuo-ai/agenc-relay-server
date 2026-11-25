//! Durable no-stock operations through the production directory handler.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::CompanionFault;
use crate::e2ee::coordinator::empty_claims::{GLOBAL, PER_ACCOUNT};
use agenc_relay_domain::e2ee::directory::ClaimOutcome;
use agenc_relay_storage::PersistentRecordValue;
use agenc_relay_storage::e2ee_records::{ClaimOutcome as Stored, PACKAGE_ROW_KIND};

fn empty(answer: &Outcome) {
    assert_eq!(answer.result, ResultBody::Empty(EmptyKind::Package));
    assert!(answer.responses.is_empty());
    assert!(answer.snapshot_token.is_none());
}

fn expect_refusal(result: Result<Outcome, Fail>, code: E2eeReplyCode) -> TestResult {
    let Err(fail) = result else {
        return Err("expected a refused claim".into());
    };
    assert_eq!(fail.code, code);
    Ok(())
}

fn ready() -> TestResult<Harness> {
    let mut harness = Harness::with_devices(&[DEVICE, SIBLING])?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    Ok(harness)
}

fn empty_row(target: [u8; 32], deadline: u64) -> PackageRow {
    PackageRow::Claim {
        target_account_digest: target,
        target_device_id: DEVICE_ID,
        suite: 1,
        outcome: Stored::KeyUnavailable,
        key_package_ref: Vec::new(),
        object_id: None,
        retain_until: deadline,
    }
}

#[test]
fn empty_replay_survives_refill_and_restart_until_the_deletion_commits() -> TestResult {
    let mut h = ready()?;
    let claimant = account_id_digest(&NETWORK, &h.account)?;
    let key = PackageRow::claim_key(&claimant, &OPERATION)?;
    let deadline = h.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS;
    let params = claim_params(&h, 1, OPERATION);
    let first = ok(h.run(Op::ClaimPackage, &params, None)?)?;
    empty(&first);
    let [
        Write::Put {
            table,
            key: stored,
            plaintext,
        },
    ] = first.writes.as_slice()
    else {
        return Err("one objectless claim row".into());
    };
    assert_eq!(table, &TableId::E2eeState);
    assert!(stored == &key);
    let value = PersistentRecordValue::decode(*table, plaintext)?;
    assert_eq!(value.record_kind(), PACKAGE_ROW_KIND);
    assert_eq!(
        PackageRow::decode(value.body())?,
        empty_row(claimant, deadline)
    );

    let mut h = h.reloaded()?;
    let _ = publish_stock(&mut h)?;
    h.attach_as(SIBLING)?;
    for _ in 0..2 {
        empty(&ok(h.run(Op::ClaimStatus, &OPERATION, None)?)?);
        let same = ok(h.run(Op::ClaimPackage, &params, None)?)?;
        empty(&same);
        assert!(same.writes.is_empty());
        for (target, device, suite) in [
            (h.account, DEVICE_ID, 3u16),
            (h.account, [SIBLING; 16], 1),
            (account_bytes(10)?, DEVICE_ID, 1),
        ] {
            let mut changed = account_param(&target);
            changed.extend_from_slice(&device);
            changed.extend_from_slice(&suite.to_be_bytes());
            changed.extend_from_slice(&OPERATION);
            expect_refusal(
                h.run(Op::ClaimPackage, &changed, None)?,
                E2eeReplyCode::OperationConflict,
            )?;
        }
        assert_eq!(
            h.coordinator.state.directory.stock(&claimant, &DEVICE_ID),
            1
        );
        h = h.reloaded()?;
    }
    let capture =
        |h: &Harness, now| Prepared::capture(&h.coordinator, Default::default(), now, &h.backing);
    assert!(capture(&h, deadline - 1)?.is_empty());
    h.now = deadline;
    let expiry = capture(&h, deadline)?;
    let mut writes = expiry.writes(STATE_GENERATION)?;
    let owners = h
        .coordinator
        .stage_owners(&mut writes, deadline, false, STATE_GENERATION)
        .map_err(|e| format!("empty claim retirement: {e:?}"))?;
    assert!(
        matches!(writes.as_slice(), [Write::Delete { table: TableId::E2eeState, key: deleted }] if deleted == &key)
    );
    // Dropped or uncommitted maintenance neither opens the slot nor changes its replay.
    drop(expiry);
    empty(&ok(h.run(Op::ClaimPackage, &params, None)?)?);
    let expiry = capture(&h, deadline)?;
    expiry.apply(&mut h.coordinator)?;
    owners.apply(&mut h.coordinator.state);
    h.apply_logical_write(writes.first().ok_or("missing delete")?)?;
    h = h.reloaded()?;
    assert!(
        h.coordinator
            .state
            .directory
            .claim_status(&claimant, &OPERATION)
            .is_none()
    );
    assert!(
        !h.coordinator
            .state
            .empty_claims
            .contains(&(claimant, OPERATION))
    );
    // At the real cutoff the original package has expired. The same operation
    // can now bind different parameters, with a fresh seven-day deadline.
    h.now = deadline;
    let next = ok(h.run(Op::ClaimPackage, &claim_params(&h, 3, OPERATION), None)?)?;
    empty(&next);
    assert_eq!(next.writes.len(), 1);
    let (parameters, _) = h
        .coordinator
        .state
        .directory
        .stored_claim(&claimant, &OPERATION)
        .ok_or("new operation mapping")?;
    assert_eq!(parameters.suite, 3);
    assert_eq!(
        h.coordinator
            .state
            .directory
            .claim_retained_until(&claimant, &OPERATION),
        Some(deadline + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS)
    );
    Ok(())
}

#[test]
fn route_and_package_claims_retire_in_one_bounded_receipt_with_independent_progress() -> TestResult
{
    use agenc_relay_storage::e2ee_records::ClaimRow;
    let mut h = ready()?;
    let claimant = account_id_digest(&NETWORK, &h.account)?;
    let later = [10; 16];
    for op in [OPERATION, later] {
        empty(&ok(h.run(
            Op::ClaimPackage,
            &claim_params(&h, 1, op),
            None,
        )?)?);
    }
    let mut route = INSTANCE.to_vec();
    route.extend_from_slice(b"\x05#room");
    let ResultBody::Reserved(grant, _) = ok(h.run(Op::ReserveChannel, &route, None)?)?.result
    else {
        return Err("expected a normal channel reservation".into());
    };
    let deadline = h.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS;
    let mut h = h.reloaded()?;
    let due = Prepared::capture(&h.coordinator, Default::default(), deadline, &h.backing)?;
    let first = PackageRow::claim_key(&claimant, &OPERATION)?;
    let grant_key = ClaimRow::reservation_key(&grant)?;
    let mut writes = due.writes(STATE_GENERATION)?;
    assert_eq!(writes.len(), 2);
    for key in [first, grant_key] {
        assert!(writes.iter().any(|w| matches!(w, Write::Delete { table: TableId::E2eeState, key: actual } if actual == &key)));
    }
    let next = due.next_cursor();
    assert!(!due.completes_cycle());
    assert!(
        h.coordinator
            .state
            .empty_claims
            .contains(&(claimant, OPERATION))
    );
    assert!(h.coordinator.state.reservations.contains(&grant));
    let owners = h
        .coordinator
        .stage_owners(&mut writes, deadline, false, STATE_GENERATION)
        .map_err(|e| format!("joined claim retirement: {e:?}"))?;
    for write in &writes {
        h.apply_logical_write(write)?;
    }
    due.apply(&mut h.coordinator)?;
    owners.apply(&mut h.coordinator.state);
    let h = h.reloaded()?;
    assert!(
        !h.coordinator
            .state
            .empty_claims
            .contains(&(claimant, OPERATION))
    );
    assert!(
        h.coordinator
            .state
            .empty_claims
            .contains(&(claimant, later))
    );
    assert!(!h.coordinator.state.reservations.contains(&grant));
    let remaining = Prepared::capture(&h.coordinator, next, deadline, &h.backing)?;
    let last = PackageRow::claim_key(&claimant, &later)?;
    assert!(
        matches!(remaining.writes(STATE_GENERATION)?.as_slice(), [Write::Delete {table: TableId::E2eeState, key}] if key == &last)
    );
    Ok(())
}

#[test]
fn claimant_limit_preserves_replay_and_stocked_claims_and_declines_only_fresh_empty_operations()
-> TestResult {
    let mut h = ready()?;
    let claimant = account_id_digest(&NETWORK, &h.account)?;
    for operation in 1..=PER_ACCOUNT {
        let params = claim_params(&h, 1, u128::try_from(operation)?.to_be_bytes());
        empty(&ok(h.run(Op::ClaimPackage, &params, None)?)?);
    }
    let mut h = h.reloaded()?;
    let retained = 1u128.to_be_bytes();
    let extra = u128::try_from(PER_ACCOUNT + 1)?.to_be_bytes();
    let extra_params = claim_params(&h, 1, extra);
    expect_refusal(
        h.run(Op::ClaimPackage, &extra_params, None)?,
        E2eeReplyCode::RateLimited,
    )?;
    assert!(
        h.coordinator
            .state
            .directory
            .claim_status(&claimant, &extra)
            .is_none()
    );
    empty(&ok(h.run(
        Op::ClaimPackage,
        &claim_params(&h, 1, retained),
        None,
    )?)?);
    expect_refusal(
        h.run(Op::ClaimPackage, &claim_params(&h, 3, retained), None)?,
        E2eeReplyCode::OperationConflict,
    )?;
    let _ = publish_stock(&mut h)?;
    let stocked = ok(h.run(Op::ClaimPackage, &extra_params, None)?)?;
    assert!(matches!(stocked.result, ResultBody::Claimed(..)));
    Ok(())
}

#[test]
fn a_retirement_receipt_cannot_release_a_different_committed_claim() -> TestResult {
    let mut h = ready()?;
    let claimant = account_id_digest(&NETWORK, &h.account)?;
    let params = claim_params(&h, 1, OPERATION);
    empty(&ok(h.run(Op::ClaimPackage, &params, None)?)?);
    let deadline = h.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS;
    let due = Prepared::capture(&h.coordinator, Default::default(), deadline, &h.backing)?;

    // Model the immutable durable view at receipt having different parameters
    // but the same operation, outcome and cutoff.
    let changed = request::state_row(
        TableId::E2eeState,
        PACKAGE_ROW_KIND,
        PackageRow::claim_key(&claimant, &OPERATION)?,
        empty_row([0x52; 32], deadline).encode()?,
    )
    .map_err(|e| format!("changed fixture mapping: {e:?}"))?;
    h.apply_logical_write(&changed)?;
    let mut recovered = h.reloaded()?;
    assert!(matches!(
        due.apply(&mut recovered.coordinator),
        Err(CompanionFault::Storage)
    ));
    assert!(
        recovered
            .coordinator
            .state
            .empty_claims
            .contains(&(claimant, OPERATION))
    );
    let (parameters, _) = recovered
        .coordinator
        .state
        .directory
        .stored_claim(&claimant, &OPERATION)
        .ok_or("replacement mapping missing")?;
    assert_eq!(parameters.target_account_digest, [0x52; 32]);
    Ok(())
}

#[test]
fn committed_package_and_claim_keys_and_outcome_tags_must_agree_at_startup() -> TestResult {
    use agenc_relay_storage::StoredKey;
    use agenc_relay_storage::e2ee_records::{ATTACH_ROW_KIND, AttachRow, PackageState};
    let empty = empty_row([7; 32], 10_000);
    let mut limited = empty.clone();
    let PackageRow::Claim { outcome, .. } = &mut limited else {
        return Err("expected a claim fixture".into());
    };
    *outcome = Stored::RateLimited;
    let stock = PackageRow::Package {
        account_digest: [7; 32],
        device_id: DEVICE_ID,
        suite: 1,
        expires_at: 10_000,
        object_id: [5; 32],
        state: PackageState::Published,
        claimed_by: None,
    };
    let key = PackageRow::claim_key(&[6; 32], &OPERATION)?;
    let package = PackageRow::package_key(b"package-ref")?;
    assert!(
        PersistentRecordValue::new(
            TableId::E2eeState,
            PACKAGE_ROW_KIND,
            1,
            0,
            None,
            vec![],
            vec![0]
        )
        .is_err()
    );
    for (label, stored_key, kind, bytes) in [
        (
            "truncated claim key",
            StoredKey::new(b"claim/v1/short".to_vec())?,
            PACKAGE_ROW_KIND,
            empty.encode()?,
        ),
        (
            "empty stock reference",
            StoredKey::new(b"package/v1/".to_vec())?,
            PACKAGE_ROW_KIND,
            stock.encode()?,
        ),
        (
            "claim under stock",
            package.clone(),
            PACKAGE_ROW_KIND,
            empty.encode()?,
        ),
        (
            "stock under claim",
            key.clone(),
            PACKAGE_ROW_KIND,
            stock.encode()?,
        ),
        (
            "unsupported retained refusal",
            key.clone(),
            PACKAGE_ROW_KIND,
            limited.encode()?,
        ),
        (
            "misclassified authenticated row",
            key.clone(),
            ATTACH_ROW_KIND,
            AttachRow {
                session_generation: 1,
                challenge: None,
            }
            .encode()?,
        ),
    ] {
        let mut h = ready()?;
        let value =
            PersistentRecordValue::new(TableId::E2eeState, kind, 1, 0, None, vec![], bytes)?;
        h.coordinator.admit_restored_with_backing(
            TableId::E2eeState,
            &stored_key,
            &value,
            &h.backing,
        );
        assert!(
            matches!(
                h.coordinator.finish_restore_with_backing(h.backing.clone()),
                Err(CompanionFault::Storage)
            ),
            "{label}"
        );
        assert!(
            !h.coordinator
                .state
                .empty_claims
                .contains(&([6; 32], OPERATION))
        );
    }
    Ok(())
}

#[test]
fn an_empty_claim_requires_backing_when_its_durable_row_is_admitted() -> TestResult {
    let mut h = ready()?;
    let claimant = account_id_digest(&NETWORK, &h.account)?;
    let key = PackageRow::claim_key(&claimant, &OPERATION)?;
    let row = PersistentRecordValue::new(
        TableId::E2eeState,
        PACKAGE_ROW_KIND,
        1,
        0,
        None,
        vec![],
        empty_row(claimant, h.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS).encode()?,
    )?;
    h.coordinator.admit_restored(TableId::E2eeState, &key, &row);
    assert!(matches!(
        h.coordinator.finish_restore_with_backing(h.backing.clone()),
        Err(CompanionFault::Ceiling)
    ));
    assert!(
        !h.coordinator
            .state
            .empty_claims
            .contains(&(claimant, OPERATION))
    );
    assert!(
        h.coordinator
            .state
            .directory
            .stored_claim(&claimant, &OPERATION)
            .is_none()
    );

    h.coordinator
        .admit_restored_with_backing(TableId::E2eeState, &key, &row, &h.backing);
    h.coordinator
        .finish_restore_with_backing(h.backing.clone())?;
    assert!(
        h.coordinator
            .state
            .empty_claims
            .contains(&(claimant, OPERATION))
    );
    assert_eq!(
        h.coordinator
            .state
            .directory
            .claim_status(&claimant, &OPERATION),
        Some(&ClaimOutcome::Unavailable)
    );
    Ok(())
}

#[test]
fn a_duplicate_row_cannot_obtain_a_second_resident_slot_during_recovery() -> TestResult {
    let mut h = ready()?;
    let claimant = account_id_digest(&NETWORK, &h.account)?;
    let row = empty_row(claimant, h.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS).encode()?;
    let key = PackageRow::claim_key(&claimant, &OPERATION)?;
    for _ in 0..2 {
        h.writes.push(
            request::state_row(
                TableId::E2eeState,
                PACKAGE_ROW_KIND,
                key.clone(),
                row.clone(),
            )
            .map_err(|e| format!("duplicate fixture mapping: {e:?}"))?,
        );
    }
    assert!(h.reloaded().is_err());
    Ok(())
}

#[test]
fn a_declined_memory_reservation_leaves_the_same_claim_available_to_retry() -> TestResult {
    use crate::budget::{BackingReservationPort, MemoryBudget};
    let mut h = ready()?;
    let claimant = account_id_digest(&NETWORK, &h.account)?;
    let params = claim_params(&h, 1, OPERATION);
    let normal = h.backing.clone();
    h.backing = BackingReservationPort::new(std::sync::Arc::new(MemoryBudget::new(0)));
    expect_refusal(
        h.run(Op::ClaimPackage, &params, None)?,
        E2eeReplyCode::RateLimited,
    )?;
    assert!(
        !h.coordinator
            .state
            .empty_claims
            .contains(&(claimant, OPERATION))
    );
    assert!(
        h.coordinator
            .state
            .directory
            .stored_claim(&claimant, &OPERATION)
            .is_none()
    );
    h.backing = normal;
    let retry = ok(h.run(Op::ClaimPackage, &params, None)?)?;
    empty(&retry);
    assert_eq!(retry.writes.len(), 1);
    Ok(())
}

#[test]
fn global_empty_slots_apply_to_the_restored_profile_and_release_only_at_receipt() -> TestResult {
    let mut h = ready()?;
    let target = account_id_digest(&NETWORK, &h.account)?;
    let row = empty_row(target, h.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS).encode()?;
    // Distinct canonical persisted observations reach the production global bound.
    for i in 0..GLOBAL {
        let claimant = [u8::try_from(i / PER_ACCOUNT)?; 32];
        assert_ne!(claimant, target);
        let operation = u128::try_from(i % PER_ACCOUNT)?.to_be_bytes();
        h.writes.push(
            request::state_row(
                TableId::E2eeState,
                PACKAGE_ROW_KIND,
                PackageRow::claim_key(&claimant, &operation)?,
                row.clone(),
            )
            .map_err(|e| format!("fixture mapping: {e:?}"))?,
        );
    }
    // Recovery refuses an unadmittable durable set as a whole. Silently
    // dropping one entry here would let its operation consume real stock.
    let overflow = request::state_row(
        TableId::E2eeState,
        PACKAGE_ROW_KIND,
        PackageRow::claim_key(&target, &OPERATION)?,
        row,
    )
    .map_err(|e| format!("overflow fixture mapping: {e:?}"))?;
    h.writes.push(overflow);
    assert!(h.reloaded().is_err());
    h.writes.pop().ok_or("overflow fixture row")?;
    let mut h = h.reloaded()?;
    let params = claim_params(&h, 1, OPERATION);
    expect_refusal(
        h.run(Op::ClaimPackage, &params, None)?,
        E2eeReplyCode::RateLimited,
    )?;
    let deadline = h.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS;
    h.now = deadline;
    let due = Prepared::capture(&h.coordinator, Default::default(), h.now, &h.backing)?;
    expect_refusal(
        h.run(Op::ClaimPackage, &params, None)?,
        E2eeReplyCode::RateLimited,
    )?;
    let writes = due.writes(STATE_GENERATION)?;
    assert_eq!(writes.len(), 1);
    h.apply_logical_write(writes.first().ok_or("missing slot delete")?)?;
    due.apply(&mut h.coordinator)?;
    empty(&ok(h.run(Op::ClaimPackage, &params, None)?)?);
    h = h.reloaded()?;
    h.now = deadline;
    empty(&ok(h.run(Op::ClaimPackage, &params, None)?)?);
    expect_refusal(
        h.run(Op::ClaimPackage, &claim_params(&h, 1, [77; 16]), None)?,
        E2eeReplyCode::RateLimited,
    )?;
    Ok(())
}
