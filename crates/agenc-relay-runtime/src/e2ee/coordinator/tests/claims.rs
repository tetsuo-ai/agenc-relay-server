#![forbid(unsafe_code)]

//! Claim operations under `(claimant, operation-id)` (companion 11.6):
//! `CLAIM STATUS` returns the stored result of the original claim, naming its
//! target device, package reference and object, whichever device of the
//! claimant asks and after the coordinator restarts.

use super::*;
use crate::e2ee::coordinator::request_expiry::Prepared;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_domain::e2ee::limits::KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS;
use agenc_relay_storage::TableId;
use agenc_relay_storage::e2ee_records::PackageRow;

/// A second device of the harness principal, the one that claims.
const SIBLING: u8 = DEVICE + 1;
const OPERATION: [u8; 16] = [9; 16];

/// Publishes one suite-1 package as the attached `DEVICE`, then attaches
/// `SIBLING` in its place.
fn stocked_then_sibling(harness: &mut Harness) -> TestResult<Vec<u8>> {
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let package = publish_stock(harness)?;
    harness.attach_as(SIBLING)?;
    Ok(package)
}

fn publish_stock(harness: &mut Harness) -> TestResult<Vec<u8>> {
    let package = key_package_bytes(harness)?;
    let mut publish = DEVICE_ID.to_vec();
    publish.extend_from_slice(&1_u16.to_be_bytes());
    publish.extend_from_slice(&LEAF_INTERVAL.1.to_be_bytes());
    let outcome = ok(harness.run(Op::PublishPackage, &publish, Some(&package))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Package, object_id(&package))
    );
    Ok(package)
}

/// `CLAIM PACKAGE` parameters naming `DEVICE` of the harness account.
fn claim_params(harness: &Harness, suite: u16, operation: [u8; 16]) -> Vec<u8> {
    let mut claim = account_param(&harness.account);
    claim.extend_from_slice(&DEVICE_ID);
    claim.extend_from_slice(&suite.to_be_bytes());
    claim.extend_from_slice(&operation);
    claim
}

fn response_bytes(outcome: &Outcome) -> Vec<Vec<u8>> {
    outcome
        .responses
        .iter()
        .map(|response| response.bytes.clone())
        .collect()
}

/// The same result tuple and the same response objects as `first`.
fn assert_same_answer(answer: &Outcome, first: &Outcome, context: &str) {
    assert_eq!(answer.result, first.result, "{context}");
    assert_eq!(response_bytes(answer), response_bytes(first), "{context}");
}

#[test]
fn claim_status_names_the_claim_target_from_another_device_and_after_a_restart() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SIBLING])?;
    let package = stocked_then_sibling(&mut harness)?;
    let first = ok(harness.run(
        Op::ClaimPackage,
        &claim_params(&harness, 1, OPERATION),
        None,
    )?)?;
    let ResultBody::Claimed(device, _, claimed_object) = first.result.clone() else {
        return Err("expected a claimed result".into());
    };
    assert_eq!(device, DEVICE_ID, "the claim names its target device");
    assert_eq!(claimed_object, object_id(&package));
    assert_eq!(response_bytes(&first), vec![package]);

    // The claiming device lost the reply and asks for the stored result.
    let status = ok(harness.run(Op::ClaimStatus, &OPERATION, None)?)?;
    assert_same_answer(&status, &first, "status from the claiming device");
    let retry = ok(harness.run(
        Op::ClaimPackage,
        &claim_params(&harness, 1, OPERATION),
        None,
    )?)?;
    assert_same_answer(&retry, &first, "identical retry");

    // The durable claim row restores the same answer after a restart, asked
    // from the claiming device and from the target device itself.
    let mut reloaded = harness.reloaded()?;
    let status = ok(reloaded.run(Op::ClaimStatus, &OPERATION, None)?)?;
    assert_same_answer(&status, &first, "status after a restart");
    reloaded.attach_as(DEVICE)?;
    let status = ok(reloaded.run(Op::ClaimStatus, &OPERATION, None)?)?;
    assert_same_answer(&status, &first, "status from the target device");
    // An operation the claimant never made still answers EMPTY PACKAGE.
    let unknown = ok(reloaded.run(Op::ClaimStatus, &[99; 16], None)?)?;
    assert_eq!(unknown.result, ResultBody::Empty(EmptyKind::Package));
    assert!(unknown.responses.is_empty());
    Ok(())
}

#[test]
fn request_maintenance_retires_an_expired_mapping_and_its_owner_together() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SIBLING])?;
    let package = stocked_then_sibling(&mut harness)?;
    let claim = ok(harness.run(
        Op::ClaimPackage,
        &claim_params(&harness, 1, OPERATION),
        None,
    )?)?;
    let claimant = account_id_digest(&NETWORK, &harness.account)?;
    let key = PackageRow::claim_key(&claimant, &OPERATION)?;
    let object = object_id(&package);
    let deadline = harness.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS;
    let mut reloaded = harness.reloaded()?;
    let status = ok(reloaded.run(Op::ClaimStatus, &OPERATION, None)?)?;
    assert_same_answer(&status, &claim, "reloaded live claim");
    let capture = |harness: &Harness, now| {
        Prepared::capture(
            &harness.coordinator,
            Default::default(),
            now,
            &harness.backing,
        )
    };
    assert!(capture(&reloaded, deadline - 1)?.is_empty());
    let expired = capture(&reloaded, deadline)?;
    let mut writes = expired.writes(STATE_GENERATION)?;
    assert!(matches!(
        writes.as_slice(),
        [Write::Delete { table: TableId::E2eeState, key: removed }] if *removed == key
    ));
    let staged = reloaded
        .coordinator
        .stage_owners(&mut writes, deadline, false, STATE_GENERATION)
        .map_err(|failure| format!("owner retirement: {failure:?}"))?;
    assert_eq!(writes.len(), 2, "the owner change shares the delete batch");
    let status = ok(reloaded.run(Op::ClaimStatus, &OPERATION, None)?)?;
    assert_same_answer(&status, &claim, "pre-commit claims still replay");
    expired.apply(&mut reloaded.coordinator)?;
    staged.apply(&mut reloaded.coordinator.state);
    for write in &writes {
        reloaded.apply_logical_write(write)?;
    }
    let owner = reloaded
        .coordinator
        .state
        .owners
        .account(&object)
        .ok_or("owner")?;
    assert!(owner.owners.is_empty());
    assert_eq!(owner.retired_at, Some(deadline));
    assert!(reloaded.coordinator.state.objects.contains_key(&object));

    let mut restarted = reloaded.reloaded()?;
    let status = ok(restarted.run(Op::ClaimStatus, &OPERATION, None)?)?;
    assert_eq!(status.result, ResultBody::Empty(EmptyKind::Package));
    assert!(status.responses.is_empty());
    let owner = restarted
        .coordinator
        .state
        .owners
        .account(&object)
        .ok_or("reloaded owner")?;
    assert!(owner.owners.is_empty());
    assert_eq!(owner.retired_at, Some(deadline));
    Ok(())
}

#[test]
fn claim_retirement_honors_the_signed_lifetime_of_an_old_row() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SIBLING])?;
    stocked_then_sibling(&mut harness)?;
    let _ = ok(harness.run(
        Op::ClaimPackage,
        &claim_params(&harness, 1, OPERATION),
        None,
    )?)?;
    let claimant = account_id_digest(&NETWORK, &harness.account)?;
    let directory = &mut harness.coordinator.state.directory;
    let (parameters, outcome) = directory
        .stored_claim(&claimant, &OPERATION)
        .ok_or("claim")?;
    // Model an older row whose recorded timeout preceded the signed end.
    let early = LEAF_INTERVAL.1 - 1;
    directory.restore_claim(claimant, OPERATION, parameters, outcome.clone(), early);
    let capture = |now| {
        Prepared::capture(
            &harness.coordinator,
            Default::default(),
            now,
            &harness.backing,
        )
    };
    assert!(capture(early)?.is_empty());
    assert!(!capture(LEAF_INTERVAL.1)?.is_empty());
    Ok(())
}

#[test]
fn a_retired_package_row_cannot_be_republished_without_a_claim_mapping() -> TestResult {
    use agenc_relay_storage::e2ee_records::{PACKAGE_ROW_KIND, PackageState, object_key};
    let mut harness = Harness::with_devices(&[DEVICE, SIBLING])?;
    let bytes = stocked_then_sibling(&mut harness)?;
    let package = super::super::ops::directory::retained_key_package(&bytes).ok_or("package")?;
    let account_digest = account_id_digest(&NETWORK, &harness.account)?;
    let id = object_id(&bytes);
    // An old database can retain the terminal package row without a result
    // row. The reference remains occupied even if its public body is missing.
    let row = PackageRow::Package {
        account_digest,
        device_id: DEVICE_ID,
        suite: 1,
        expires_at: LEAF_INTERVAL.1,
        object_id: id,
        state: PackageState::Claimed,
        claimed_by: Some((account_digest, OPERATION)),
    };
    let write = request::state_row(
        TableId::E2eeState,
        PACKAGE_ROW_KIND,
        PackageRow::package_key(&package.key_package_ref)?,
        row.encode()?,
    )
    .map_err(|code| format!("legacy package row: {code:?}"))?;
    harness.apply_logical_write(&write)?;
    let mut publish = DEVICE_ID.to_vec();
    publish.extend_from_slice(&1_u16.to_be_bytes());
    publish.extend_from_slice(&LEAF_INTERVAL.1.to_be_bytes());
    for retained in [true, false] {
        if !retained {
            harness.apply_logical_write(&Write::delete(TableId::E2eeObject, object_key(&id)?)?)?;
        }
        let mut rebuilt = harness.reloaded()?;
        rebuilt.attach_as(DEVICE)?;
        assert!(
            rebuilt
                .coordinator
                .state
                .directory
                .claim_status(&account_digest, &OPERATION)
                .is_none()
        );
        assert_eq!(
            rebuilt
                .coordinator
                .state
                .directory
                .stock(&account_digest, &DEVICE_ID),
            0
        );
        assert_eq!(
            code(rebuilt.run(Op::PublishPackage, &publish, Some(&bytes))?),
            Some(E2eeReplyCode::OperationConflict)
        );
        let fresh =
            ok(rebuilt.run(Op::ClaimPackage, &claim_params(&rebuilt, 1, [3; 16]), None)?)?;
        assert_eq!(fresh.result, ResultBody::Empty(EmptyKind::Package));
    }
    Ok(())
}

#[test]
fn stale_legacy_stock_cannot_be_claimed_and_retires_with_its_last_owner() -> TestResult {
    use crate::e2ee::coordinator::request_expiry::MAX_EXPIRY_ENTRIES;
    use agenc_relay_storage::e2ee_records::{PackageState, ReplayKey, ReplayRow};
    let mut harness = Harness::with_devices(&[DEVICE, SIBLING])?;
    let bytes = stocked_then_sibling(&mut harness)?;
    let first = ok(harness.run(
        Op::ClaimPackage,
        &claim_params(&harness, 1, OPERATION),
        None,
    )?)?;
    let ResultBody::Claimed(_, reference, object_id) = &first.result else {
        return Err("expected signed package".into());
    };
    let claimant = account_id_digest(&NETWORK, &harness.account)?;
    let stock_key = PackageRow::package_key(reference)?;
    let claim_key = PackageRow::claim_key(&claimant, &OPERATION)?;
    let deadline = harness.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS;
    let stale_row = |expires_at| {
        PackageRow::Package {
            account_digest: claimant,
            device_id: DEVICE_ID,
            suite: 1,
            expires_at,
            object_id: *object_id,
            state: PackageState::Published,
            claimed_by: None,
        }
        .encode()
    };
    // Model a previous release where the publisher submitted the spent package again.
    // Even an old row with a falsely extended expiry must not outlive the claim evidence.
    for recorded_expiry in [LEAF_INTERVAL.1, deadline + 10_000] {
        let staged = request::state_row(
            TableId::E2eeState,
            agenc_relay_storage::e2ee_records::PACKAGE_ROW_KIND,
            stock_key.clone(),
            stale_row(recorded_expiry)?,
        )
        .map_err(|code| format!("stock row: {code:?}"))?;
        harness.apply_logical_write(&staged)?;
        let mut recovered = harness.reloaded()?;
        assert!(
            recovered
                .coordinator
                .state
                .spent_package_rows
                .contains_key(&claim_key)
        );
        assert_eq!(
            recovered
                .coordinator
                .state
                .spent_package_rows
                .contains_key(&stock_key),
            recorded_expiry != LEAF_INTERVAL.1
        );
        assert_eq!(
            recovered
                .coordinator
                .state
                .directory
                .stock(&claimant, &DEVICE_ID),
            0
        );
        let status = ok(recovered.run(Op::ClaimStatus, &OPERATION, None)?)?;
        assert_eq!(response_bytes(&status), vec![bytes.clone()]);
        // Two full maintenance pages share their primary row budget with
        // both the spent claim and its redundant stock row on the first pass.
        assert!(recovered.coordinator.state.replays.is_empty());
        for index in 1..=2 * MAX_EXPIRY_ENTRIES - 2 {
            let key = ReplayKey {
                home_server_id: [1; 16],
                server_incarnation: [2; 16],
                origin_id: [3; 16],
                origin_generation: 1,
                operation_sequence: u64::try_from(index)?,
            };
            recovered.coordinator.state.replays.insert(
                key,
                ReplayRow {
                    request_id: u128::try_from(index)?.to_be_bytes(),
                    request_object_id: [4; 32],
                    result_object_id: None,
                    response_object_ids: Vec::new(),
                    security_mutation: false,
                    retain_until: 0,
                },
            );
        }
        let due = Prepared::capture(
            &recovered.coordinator,
            Default::default(),
            deadline,
            &recovered.backing,
        )?;
        let mut writes = due.writes(STATE_GENERATION)?;
        assert!(writes.iter().any(
            |w| matches!(w, Write::Delete {table: TableId::E2eeState, key} if key == &stock_key)
        ));
        let owners = recovered
            .coordinator
            .stage_owners(&mut writes, deadline, false, STATE_GENERATION)
            .map_err(|code| format!("owner retirement: {code:?}"))?;
        due.apply(&mut recovered.coordinator)?;
        assert!(recovered.coordinator.state.spent_package_rows.is_empty());
        owners.apply(&mut recovered.coordinator.state);
        let second = Prepared::capture(
            &recovered.coordinator,
            due.next_cursor(),
            deadline,
            &recovered.backing,
        )?;
        assert!(second.is_empty());
        assert!(!second.completes_cycle());
        assert!(
            Prepared::capture(
                &recovered.coordinator,
                second.next_cursor(),
                deadline,
                &recovered.backing,
            )?
            .completes_cycle()
        );
        for write in &writes {
            recovered.apply_logical_write(write)?;
        }
        let mut rebuilt = recovered.reloaded()?;
        rebuilt.now = deadline;
        let fresh = ok(rebuilt.run(
            Op::ClaimPackage,
            &claim_params(&rebuilt, 1, [0x88; 16]),
            None,
        )?)?;
        assert_eq!(fresh.result, ResultBody::Empty(EmptyKind::Package));
        assert!(
            rebuilt
                .coordinator
                .state
                .owners
                .account(object_id)
                .ok_or("owner account")?
                .owners
                .is_empty()
        );
    }
    Ok(())
}

#[test]
fn a_successful_claim_holds_its_own_backing_until_committed_retirement() -> TestResult {
    use super::super::resident::SPENT_PACKAGE_ROW_BACKING;
    use crate::budget::{BackingReservationPort, MemoryBudget, MemoryCharge};
    let mut h = Harness::with_devices(&[DEVICE, SIBLING])?;
    let _ = stocked_then_sibling(&mut h)?;
    let claimant = account_id_digest(&NETWORK, &h.account)?;
    let key = PackageRow::claim_key(&claimant, &OPERATION)?;
    let params = claim_params(&h, 1, OPERATION);
    let charge = MemoryCharge::allocation(u64::try_from(SPENT_PACKAGE_ROW_BACKING)?)?.bytes();

    // No holder or durable result can be published if this additional owner cannot fit.
    h.backing = BackingReservationPort::new(std::sync::Arc::new(MemoryBudget::new(charge - 1)));
    assert_eq!(
        code(h.run(Op::ClaimPackage, &params, None)?),
        Some(E2eeReplyCode::RateLimited)
    );
    assert!(h.coordinator.state.spent_package_rows.is_empty());
    assert_eq!(
        h.coordinator.state.directory.stock(&claimant, &DEVICE_ID),
        1
    );
    assert!(
        h.coordinator
            .state
            .directory
            .claim_status(&claimant, &OPERATION)
            .is_none()
    );

    let budget = std::sync::Arc::new(MemoryBudget::new(1 << 23));
    h.backing = BackingReservationPort::new(budget.clone());
    let first = ok(h.run(Op::ClaimPackage, &params, None)?)?;
    assert!(matches!(first.result, ResultBody::Claimed(..)));
    assert!(h.coordinator.state.spent_package_rows.contains_key(&key));
    assert_eq!(budget.charged(), charge);
    let deadline = h.now + KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS;
    let capture =
        |h: &Harness| Prepared::capture(&h.coordinator, Default::default(), deadline, &h.backing);
    drop(capture(&h)?);
    assert_eq!(budget.charged(), charge);
    assert_same_answer(
        &ok(h.run(Op::ClaimPackage, &params, None)?)?,
        &first,
        "retry while retained",
    );
    let due = capture(&h)?;
    due.apply(&mut h.coordinator)?;
    drop(due);
    assert!(h.coordinator.state.spent_package_rows.is_empty());
    assert_eq!(budget.charged(), 0);
    Ok(())
}

mod empty;
