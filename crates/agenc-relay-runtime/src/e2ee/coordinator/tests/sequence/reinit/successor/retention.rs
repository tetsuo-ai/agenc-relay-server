//! The binding packages of a migrated predecessor and of the successor its
//! activation installed stay held by their route rows (companion 11.7, 13.8
//! and 15), so a restart after object expiry has collected everything no
//! row names restores both routes, from the harness store and from sealed
//! storage alike.

#![forbid(unsafe_code)]

use super::reconstruction::reconstruct;
use super::*;
use crate::e2ee::coordinator::tests::sequence::retention::{
    PAST_EVERY_WINDOW, assert_held_by, binding_object, expire,
};

#[test]
fn an_installed_successor_restarts_after_expiry_collects_every_unowned_object() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    let installed = binding_object(&fixture.harness, fixture.new)?;
    let predecessor = binding_object(&fixture.harness, fixture.old)?;
    assert_eq!(installed, object_id(&fixture.package_bytes()?));
    for (conversation, package) in [(fixture.new, installed), (fixture.old, predecessor)] {
        let row = RouteRow::key(&conversation)?.as_bytes().to_vec();
        assert_held_by(&fixture.harness, package, std::slice::from_ref(&row))?;
    }
    let collected = expire(&mut fixture.harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&installed) && !collected.contains(&predecessor));
    let restarted = fixture.harness.reloaded()?;
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
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
    assert_eq!(binding_object(&restarted, fixture.new)?, installed);
    assert_eq!(binding_object(&restarted, fixture.old)?, predecessor);
    assert_eq!(
        state
            .routes
            .channel_route(&agenc_relay_types::ChannelInstanceId::from_bytes(INSTANCE))
            .map(|route| route.conversation_id.0),
        Some(fixture.new)
    );
    Ok(())
}

#[tokio::test]
async fn an_installed_successor_restores_from_sealed_storage_after_expiry() -> TestResult {
    let mut fixture = Fixture::prepare()?;
    fixture.activate()?;
    expire(&mut fixture.harness, PAST_EVERY_WINDOW)?;
    let (restored, result) = Box::pin(reconstruct(&fixture.harness.writes)).await?;
    result?;
    assert!(restored.owner_reconstruction.is_clean());
    assert_eq!(
        restored
            .state
            .logs
            .get(&fixture.new)
            .map(SequencerLog::phase),
        Some(Phase::Open)
    );
    Ok(())
}
