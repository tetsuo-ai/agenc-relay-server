#![forbid(unsafe_code)]

//! An `EORIGIN` declaration naming a device attachment another attachment of
//! the device superseded is refused for its origin alone (companion 11.6,
//! 12.5): nothing is acknowledged, the origin is fenced at the generation
//! and next sequence it holds, every later declaration of it is refused
//! alike, the edge's deletion naming the refused generation is acknowledged,
//! and the link stays up.

use super::*;

const DEVICE_ID: [u8; 16] = [7; 16];

/// A synchronization fixture whose principal's device attached `attaches`
/// times, so the directory holds that session generation; the base origin
/// carries the account at generation zero.
fn attached(attaches: u64) -> TestResult<Sync> {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    for _ in 0..attaches {
        let _attached = harness.attach()?;
    }
    harness.coordinator.state.origins.clear();
    let account = harness.account;
    let mut sync = Sync {
        harness,
        host: FakeHost::default(),
        entropy: Counter(0),
    };
    sync.host.origin.as_mut().ok_or("base origin")?.account = Some((account, 3));
    Ok(sync)
}

/// Declares generation zero and returns its accepted state identifier.
fn opened(sync: &mut Sync) -> TestResult<[u8; 32]> {
    sync.reset()?;
    let account = sync.harness.account;
    let (origin, bytes) = origin_object(0, [0; 32], Some((account, 3)), None)?;
    let acknowledged = frames(
        &sync
            .declare(false, 0, &bytes)
            .map_err(|f| format!("{f:?}"))?,
    )?;
    assert_eq!(acknowledged.len(), 1);
    Ok(semantic_id_of(
        SemanticHashDomain::FederationOriginState,
        &origin,
    )?)
}

/// The base origin moves to `generation`, as the attachment's base
/// transition does.
fn base_generation(sync: &mut Sync, generation: u64) -> TestResult {
    sync.host.origin.as_mut().ok_or("base origin")?.generation = generation;
    Ok(())
}

fn held(sync: &Sync) -> TestResult<(u64, u64, bool)> {
    let origin = sync
        .harness
        .coordinator
        .state
        .origins
        .get(&CompanionOriginKey {
            home_server_id: HOME,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
        })
        .ok_or("held origin")?;
    Ok((origin.generation, origin.next_sequence, origin.fenced))
}

fn deletion(generation: u64) -> CompanionFrame {
    CompanionFrame::OriginDel {
        coordinator_server_id: COORDINATOR,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: generation,
        next_operation_sequence: 0,
    }
}

#[test]
fn a_declaration_naming_a_superseded_attachment_closes_only_its_origin() -> TestResult {
    // The device attached a second time elsewhere: the directory is at two.
    let mut sync = attached(2)?;
    let previous = opened(&mut sync)?;
    sync.harness
        .coordinator
        .state
        .origins
        .values_mut()
        .for_each(|origin| origin.next_sequence = 4);
    base_generation(&mut sync, 1)?;
    let account = sync.harness.account;
    let (stale, bytes) = origin_object(1, previous, Some((account, 3)), Some((DEVICE_ID, 1)))?;
    let refused = sync
        .declare(true, 1, &bytes)
        .map_err(|f| format!("{f:?}"))?;
    assert!(frames(&refused)?.is_empty(), "nothing is acknowledged");
    assert_eq!(held(&sync)?, (0, 4, true), "fenced where it stood");
    // A later declaration of the origin is refused alike, here a logout that
    // still names the device.
    base_generation(&mut sync, 2)?;
    sync.host.origin.as_mut().ok_or("base origin")?.account = None;
    let stale_id = semantic_id_of(SemanticHashDomain::FederationOriginState, &stale)?;
    let (_, later) = origin_object(2, stale_id, None, Some((DEVICE_ID, 1)))?;
    let refused = sync
        .declare(true, 2, &later)
        .map_err(|f| format!("{f:?}"))?;
    assert!(frames(&refused)?.is_empty());
    // The edge's deletion names the generation refused last.
    let acknowledged = frames(&sync.frame(deletion(2)).map_err(|f| format!("{f:?}"))?)?;
    assert!(matches!(
        acknowledged.as_slice(),
        [CompanionFrame::OriginAck {
            origin_generation: 2,
            object_id: None,
            ..
        }]
    ));
    assert_eq!(held(&sync)?, (0, 4, true));
    Ok(())
}

#[test]
fn an_attachment_the_directory_never_reached_is_still_a_violation() -> TestResult {
    let mut sync = attached(1)?;
    let previous = opened(&mut sync)?;
    base_generation(&mut sync, 1)?;
    let account = sync.harness.account;
    let (_, ahead) = origin_object(1, previous, Some((account, 3)), Some((DEVICE_ID, 2)))?;
    assert_eq!(
        sync.declare(true, 1, &ahead).err(),
        Some(CompanionFault::Protocol)
    );
    assert_eq!(held(&sync)?, (0, 0, false));
    Ok(())
}

#[test]
fn a_refused_declaration_replayed_on_the_next_link_is_refused_again() -> TestResult {
    let mut sync = attached(2)?;
    let previous = opened(&mut sync)?;
    base_generation(&mut sync, 1)?;
    let account = sync.harness.account;
    let (_, bytes) = origin_object(1, previous, Some((account, 3)), Some((DEVICE_ID, 1)))?;
    assert!(
        frames(
            &sync
                .declare(true, 1, &bytes)
                .map_err(|f| format!("{f:?}"))?
        )?
        .is_empty()
    );
    sync.harness.coordinator.link_closed(home());
    let ready = sync.reset()?;
    assert!(matches!(
        ready.as_slice(),
        [CompanionFrame::OriginReady { .. }]
    ));
    let replayed = sync
        .declare(true, 1, &bytes)
        .map_err(|f| format!("{f:?}"))?;
    assert!(frames(&replayed)?.is_empty(), "refused again, link kept");
    let acknowledged = frames(&sync.frame(deletion(1)).map_err(|f| format!("{f:?}"))?)?;
    assert_eq!(acknowledged.len(), 1);
    Ok(())
}

#[test]
fn an_accepted_attachment_is_acknowledged_again_after_another_supersedes_it() -> TestResult {
    let mut sync = attached(1)?;
    let previous = opened(&mut sync)?;
    base_generation(&mut sync, 1)?;
    let account = sync.harness.account;
    let (_, bytes) = origin_object(1, previous, Some((account, 3)), Some((DEVICE_ID, 1)))?;
    assert_eq!(
        frames(
            &sync
                .declare(true, 1, &bytes)
                .map_err(|f| format!("{f:?}"))?
        )?
        .len(),
        1
    );
    // The device attaches again on another connection; the link is
    // replaced and the edge replays the declaration the coordinator
    // accepted.
    let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, &account)?;
    let directory = &mut sync.harness.coordinator.state.directory;
    let challenge = directory
        .attach_begin(digest, DEVICE_ID, [12; 16], super::super::NOW)
        .map_err(|error| format!("{error:?}"))?;
    let superseding = directory
        .attach_finish(
            digest,
            DEVICE_ID,
            [12; 16],
            challenge.reserved_generation,
            super::super::NOW,
        )
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(superseding, 2);
    sync.harness.coordinator.link_closed(home());
    sync.reset()?;
    let acknowledged = frames(
        &sync
            .declare(true, 1, &bytes)
            .map_err(|f| format!("{f:?}"))?,
    )?;
    assert!(matches!(
        acknowledged.as_slice(),
        [CompanionFrame::OriginAck {
            origin_generation: 1,
            object_id: Some(_),
            ..
        }]
    ));
    let (generation, _, fenced) = held(&sync)?;
    assert_eq!((generation, fenced), (1, false));
    Ok(())
}
