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
    publish.extend_from_slice(&50_000_u64.to_be_bytes());
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

mod empty;
