//! A device's capability row holds the roster its head names (companion
//! 8.5 and 14), so a restart re-verifies the head against that roster after
//! the account renewed it: the replaced roster stays resident while a head
//! names it, also through object expiry past every window and restarts.
//! Once the device's next statement names a later roster, or the device
//! leaves the roster, the replaced roster retires and object expiry
//! collects it.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::tests::ROOT_SEED;
use crate::e2ee::coordinator::tests::support::{capabilities, roster, roster_id};
use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::ids::{account_id_digest, semantic_id_of};
use agenc_relay_e2ee::objects::identity::{ArcDeviceCapabilities, ArcDeviceRoster};
use agenc_relay_storage::MAX_RECORD_REFERENCES;
use agenc_relay_storage::e2ee_records::DirectoryRow;

/// A second device of the account.
const SECOND_DEVICE: u8 = DEVICE + 1;

/// The key of device `seed`'s capability row.
fn capability_row(harness: &Harness, seed: u8) -> TestResult<Vec<u8>> {
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    Ok(DirectoryRow::capability_key(&digest, &[seed; 16])?
        .as_bytes()
        .to_vec())
}

/// The key of the account's roster row.
fn roster_row(harness: &Harness) -> TestResult<Vec<u8>> {
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    Ok(DirectoryRow::roster_key(&digest)?.as_bytes().to_vec())
}

/// Publishes device `seed`'s statement of `generation` naming `roster` and
/// the statement `previous`, attached as that device, and returns it.
fn publish_statement(
    harness: &mut Harness,
    seed: u8,
    roster: &ArcDeviceRoster,
    generation: u64,
    previous: [u8; 32],
) -> TestResult<ArcDeviceCapabilities> {
    harness.attach_as(seed)?;
    let statement = capabilities(seed, roster, generation, previous, (100, 200), vec![1, 3])?;
    let bytes = wire(ArcWireObjectKind::DeviceCapabilities, &statement)?;
    let outcome = ok(harness.run(Op::PublishCapabilities, &[seed; 16], Some(&bytes))?)?;
    assert_eq!(
        outcome.result,
        ResultBody::Stored(StoreKind::Capabilities, object_id(&bytes))
    );
    Ok(statement)
}

fn capability_id(statement: &ArcDeviceCapabilities) -> TestResult<[u8; 32]> {
    Ok(semantic_id_of(
        SemanticHashDomain::CapabilityId,
        &statement.tbs,
    )?)
}

/// Publishes the account's next roster under its root, keeping the
/// devices whose seeds are `kept` with their certificates, and returns it.
fn renew(
    harness: &mut Harness,
    previous: &ArcDeviceRoster,
    kept: &[u8],
) -> TestResult<ArcDeviceRoster> {
    let certificates = previous
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .filter(|entry| kept.iter().any(|seed| entry.device_id == [*seed; 16]))
        .map(|entry| entry.certificate.clone())
        .collect();
    let next = roster(
        &key(ROOT_SEED),
        &harness.principal.root,
        previous.tbs.roster_generation + 1,
        roster_id(previous)?,
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &next)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    Ok(next)
}

/// The retained object of `roster`.
fn roster_object(roster: &ArcDeviceRoster) -> TestResult<[u8; 32]> {
    Ok(object_id(&wire(ArcWireObjectKind::DeviceRoster, roster)?))
}

/// The restored head of device `seed`: its generation and the roster it
/// names.
fn head(harness: &Harness, seed: u8) -> TestResult<Option<(u64, [u8; 32])>> {
    let digest = account_id_digest(&NETWORK, &harness.account)?;
    Ok(harness
        .coordinator
        .state
        .directory
        .account(&digest)
        .and_then(|entry| entry.capabilities.get(&[seed; 16]))
        .map(|head| (head.generation, head.roster_id)))
}

#[test]
fn a_capability_head_holds_the_roster_it_names_until_its_device_moves_on() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let first_roster = harness.principal.roster.clone();
    let first = publish_statement(&mut harness, DEVICE, &first_roster, 0, [0; 32])?;
    let replaced = roster_object(&first_roster)?;
    let capability = capability_row(&harness, DEVICE)?;
    // The roster row owns the current roster and the capability row holds
    // the roster its head names.
    assert_held_by(
        &harness,
        replaced,
        &[capability.clone(), roster_row(&harness)?],
    )?;
    let renewed = renew(&mut harness, &first_roster, &[DEVICE])?;
    // After the renewal the capability row alone holds the replaced roster,
    // past every retention window and across a restart.
    assert_held_by(&harness, replaced, std::slice::from_ref(&capability))?;
    assert!(!expire(&mut harness, PAST_EVERY_WINDOW)?.contains(&replaced));
    let mut restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    assert_held_by(&restarted, replaced, std::slice::from_ref(&capability))?;
    assert_eq!(
        head(&restarted, DEVICE)?,
        Some((0, roster_id(&first_roster)?))
    );
    // The next statement names the current roster: the replaced roster
    // retires with the head that named it, and expiry collects it.
    publish_statement(&mut restarted, DEVICE, &renewed, 1, capability_id(&first)?)?;
    let account = restarted
        .coordinator
        .state
        .owners
        .account(&replaced)
        .ok_or("the replaced roster's account")?;
    assert!(account.owners.is_empty());
    assert!(account.retired_at.is_some());
    assert!(expire(&mut restarted, PAST_EVERY_WINDOW)?.contains(&replaced));
    let reopened = restarted.reloaded()?;
    assert!(reopened.coordinator.owner_reconstruction.is_clean());
    assert_eq!(head(&reopened, DEVICE)?, Some((1, roster_id(&renewed)?)));
    assert_held_by(
        &reopened,
        roster_object(&renewed)?,
        &[capability, roster_row(&reopened)?],
    )?;
    Ok(())
}

#[test]
fn a_device_leaving_the_roster_releases_the_roster_its_head_named() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, SECOND_DEVICE])?;
    harness.publish_identity_and_roster()?;
    let first_roster = harness.principal.roster.clone();
    let first = publish_statement(&mut harness, DEVICE, &first_roster, 0, [0; 32])?;
    publish_statement(&mut harness, SECOND_DEVICE, &first_roster, 0, [0; 32])?;
    let replaced = roster_object(&first_roster)?;
    // The renewal drops the second device: its capability row goes, and the
    // replaced roster stays held by the first device's row alone.
    let renewed = renew(&mut harness, &first_roster, &[DEVICE])?;
    assert_held_by(&harness, replaced, &[capability_row(&harness, DEVICE)?])?;
    publish_statement(&mut harness, DEVICE, &renewed, 1, capability_id(&first)?)?;
    assert!(expire(&mut harness, PAST_EVERY_WINDOW)?.contains(&replaced));
    let restarted = harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    assert_eq!(head(&restarted, SECOND_DEVICE)?, None);
    assert_eq!(head(&restarted, DEVICE)?, Some((1, roster_id(&renewed)?)));
    Ok(())
}

#[test]
fn a_capability_row_adds_no_holder_to_a_roster_at_the_reference_ceiling() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let current = harness.principal.roster.clone();
    let roster = roster_object(&current)?;
    let mut account = harness
        .coordinator
        .state
        .owners
        .account(&roster)
        .ok_or("its account")?
        .clone();
    let filler = MAX_RECORD_REFERENCES - account.owners.len();
    for index in 0..filler {
        account
            .owners
            .insert(format!("filler/{index:08}").into_bytes(), None);
    }
    harness
        .coordinator
        .state
        .owners
        .install(roster, account.clone());
    // The statement naming that roster is admitted; the roster, which as
    // many rows hold as one owner row can reference, takes no holder.
    publish_statement(&mut harness, DEVICE, &current, 0, [0; 32])?;
    let after = harness
        .coordinator
        .state
        .owners
        .account(&roster)
        .ok_or("its account")?;
    assert_eq!(after.owners, account.owners);
    Ok(())
}
