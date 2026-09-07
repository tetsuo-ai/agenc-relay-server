#![forbid(unsafe_code)]

//! Reassembly completion is not proof of current base-origin authority.

use super::*;

fn assert_accepted(sync: &mut Sync, generation: u64, bytes: &[u8]) -> TestResult {
    let actions = sync.declare(generation != 0, generation, bytes)?;
    assert!(matches!(
        frames(&actions)?.as_slice(),
        [CompanionFrame::OriginAck { origin_generation, object_id: Some(id), .. }]
            if *origin_generation == generation && *id == object_id(bytes)
    ));
    let key = CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
    };
    let stored = sync
        .harness
        .coordinator
        .state
        .origins
        .get(&key)
        .ok_or("origin")?;
    assert_eq!(stored.generation, generation);
    assert!(!stored.suspended);
    assert!(!stored.fenced);
    Ok(())
}

#[test]
fn a_declaration_refused_before_reset_is_reassembled_after_reset() -> TestResult {
    let mut sync = Sync::new()?;
    let (_, bytes) = origin_object(0, [0; 32], None, None)?;
    assert_eq!(
        sync.declare(false, 0, &bytes).err(),
        Some(CompanionFault::Protocol)
    );
    assert!(sync.harness.coordinator.state.origins.is_empty());
    sync.reset()?;
    assert_accepted(&mut sync, 0, &bytes)
}

#[test]
fn a_declaration_refused_without_base_authority_is_reassembled_after_reconnect() -> TestResult {
    let mut sync = Sync::new()?;
    let (_, bytes) = origin_object(0, [0; 32], None, None)?;
    let base = sync.host.origin.take();
    sync.reset()?;
    assert_eq!(
        sync.declare(false, 0, &bytes).err(),
        Some(CompanionFault::Protocol)
    );
    assert!(sync.harness.coordinator.state.origins.is_empty());
    sync.harness.coordinator.link_lost(home());
    sync.host.origin = base;
    sync.reset()?;
    assert_accepted(&mut sync, 0, &bytes)
}

#[test]
fn a_future_declaration_is_reassembled_after_its_base_generation_commits() -> TestResult {
    let mut sync = Sync::new()?;
    let (_, bytes) = origin_object(1, [8; 32], None, None)?;
    sync.reset()?;
    assert_eq!(
        sync.declare(true, 1, &bytes).err(),
        Some(CompanionFault::Protocol)
    );
    assert!(sync.harness.coordinator.state.origins.is_empty());
    sync.harness.coordinator.link_lost(home());
    sync.host.origin.as_mut().ok_or("base origin")?.generation = 1;
    sync.reset()?;
    assert_accepted(&mut sync, 1, &bytes)
}

fn reject_cached_origin(missing: bool) -> TestResult {
    let mut sync = Sync::new()?;
    let (_, bytes) = origin_object(0, [0; 32], None, None)?;
    sync.reset()?;
    assert_accepted(&mut sync, 0, &bytes)?;
    sync.harness.coordinator.link_lost(home());
    if missing {
        sync.host.origin = None;
    } else {
        sync.host.origin.as_mut().ok_or("base origin")?.generation = 1;
    }
    sync.reset()?;
    assert_eq!(
        sync.declare(false, 0, &bytes).err(),
        Some(CompanionFault::Protocol),
        "a cached declaration bypassed current base authority"
    );
    assert!(
        sync.harness
            .coordinator
            .state
            .origins
            .values()
            .all(|origin| origin.suspended)
    );
    Ok(())
}

#[test]
fn a_cached_declaration_cannot_resume_an_origin_without_live_base_authority() -> TestResult {
    reject_cached_origin(true)
}

#[test]
fn a_cached_declaration_cannot_resume_an_obsolete_base_generation() -> TestResult {
    reject_cached_origin(false)
}
