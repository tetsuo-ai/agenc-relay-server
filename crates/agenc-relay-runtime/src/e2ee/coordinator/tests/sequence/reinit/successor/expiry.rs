//! A ReInit after object expiry (companion 13.8): the attempt check, the
//! activation and the restore of an installed successor read the facts of
//! the old binding that the coordinator retained when it verified the
//! binding, so none of them needs the roster snapshot that binding names
//! once the principal's roster has moved on, and a later rotation of the
//! principal's account root refuses none of them either.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::tests::sequence::object_expiry::sweep_writes;
use crate::state_core::durable::AccountServiceDurableWrite as Write;

/// Publishes the principal's next roster with the same devices, then runs
/// object expiry past the retention of the roster it replaced. Returns that
/// roster's object, which is no longer resident, and the passes' writes.
fn move_on_and_expire(harness: &mut Harness) -> TestResult<([u8; 32], Vec<Write>)> {
    use crate::e2ee::coordinator::tests::support;
    let principal = &harness.principal;
    let named = support::roster_id(&principal.roster)?;
    let certificates = principal
        .roster
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .map(|entry| entry.certificate.clone())
        .collect();
    let next = support::roster(
        &principal.root_secret,
        &principal.root,
        1,
        named,
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &next)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    let object = harness
        .coordinator
        .state
        .roster_snapshots
        .get(&named)
        .copied()
        .ok_or("the named roster snapshot")?;
    let due = crate::e2ee::coordinator::tests::NOW
        + agenc_relay_e2ee::limits::SEQUENCER_RECORD_RETENTION_SECONDS
        + 1;
    let mut writes = Vec::new();
    for _ in 0..16 {
        writes.extend(sweep_writes(&mut harness.coordinator, due)?);
    }
    // Whatever expiry retains, none of the checks below may need it.
    harness.coordinator.state.objects.remove(&object);
    Ok((object, writes))
}

#[test]
fn an_attempt_and_its_activation_follow_the_expiry_of_the_roster_the_binding_names() -> TestResult {
    let mut harness = Harness::new()?;
    let old = harness.bind_channel()?;
    harness.finalize_reinit(old)?;
    let binding = harness
        .coordinator
        .state
        .conversations
        .get(&old)
        .ok_or("old state")?
        .binding_object_id;
    move_on_and_expire(&mut harness)?;
    harness.coordinator.state.objects.remove(&binding);
    // The attempt is admitted and the activation installs the successor.
    let mut fixture = Fixture::prepare_staged(harness, old)?;
    let outcome = fixture.activate()?;
    assert!(matches!(outcome.result, ResultBody::ReinitActivated(..)));
    assert!(
        fixture
            .harness
            .coordinator
            .state
            .conversations
            .contains_key(&fixture.new)
    );
    Ok(())
}

#[test]
fn an_installed_successor_restarts_without_the_roster_its_predecessor_named() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let (object, _) = move_on_and_expire(&mut fixture.harness)?;
    // The restart reads a store without that roster: its object row and its
    // owner row are removed.
    let names = |key: &agenc_relay_storage::StoredKey| {
        key.as_bytes().windows(32).any(|window| window == object)
    };
    let before = fixture.harness.writes.len();
    fixture
        .harness
        .writes
        .retain(|stored| !matches!(stored, Write::Put { key, .. } if names(key)));
    assert_eq!(fixture.harness.writes.len() + 2, before);
    let restarted = fixture.harness.reloaded()?;
    let state = &restarted.coordinator.state;
    assert_eq!(
        state.logs.get(&fixture.new).map(SequencerLog::phase),
        Some(Phase::Open)
    );
    assert_eq!(
        state
            .routes
            .channel_route(&agenc_relay_types::ChannelInstanceId::from_bytes(INSTANCE))
            .map(|route| route.conversation_id.0),
        Some(fixture.new)
    );
    Ok(())
}

#[test]
fn an_installed_successor_restarts_after_its_principal_rotates_the_account_root() -> TestResult {
    use crate::e2ee::coordinator::tests::{DEVICE, ROOT_SEED, support};
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let harness = &mut fixture.harness;
    let secret = support::key(ROOT_SEED + 1);
    let root = support::root(
        &secret,
        &harness.account,
        1,
        (0, 2_000_000),
        Some((&harness.principal.root_secret, &harness.principal.root)),
    )?;
    let bytes = wire(ArcWireObjectKind::RootIdentity, &root)?;
    ok(harness.run(Op::PublishIdentity, &[], Some(&bytes))?)?;
    let mut device = support::DeviceSpec::new(DEVICE);
    device.target_roster_generation = 1;
    let roster = support::roster(
        &secret,
        &root,
        1,
        support::roster_id(&harness.principal.roster)?,
        (100, 100 + 6 * 24 * 3600),
        vec![support::certificate(&secret, &root, &device)?],
        Vec::new(),
    )?;
    let bytes = wire(ArcWireObjectKind::DeviceRoster, &roster)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&bytes))?)?;
    // The principal's newest root is no longer the one the bindings name.
    let restarted = fixture.harness.reloaded()?;
    let state = &restarted.coordinator.state;
    assert_eq!(
        state.logs.get(&fixture.new).map(SequencerLog::phase),
        Some(Phase::Open)
    );
    assert_eq!(
        state.logs.get(&fixture.old).map(SequencerLog::phase),
        Some(Phase::Migrated {
            activation_id: fixture.activation_id,
            new_conversation_id: fixture.new,
        })
    );
    assert_eq!(
        state
            .routes
            .channel_route(&agenc_relay_types::ChannelInstanceId::from_bytes(INSTANCE))
            .map(|route| route.conversation_id.0),
        Some(fixture.new)
    );
    Ok(())
}
