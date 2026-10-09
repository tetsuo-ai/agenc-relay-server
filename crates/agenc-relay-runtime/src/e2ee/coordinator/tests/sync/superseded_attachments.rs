#![forbid(unsafe_code)]

//! A device attachment an `EORIGIN` declaration names is mirrored when the
//! directory reached its session generation for the declared account: the
//! current one, or one another attachment of the device superseded since,
//! which stays mirrored as an accepted attachment does and holds no device
//! authority (companion 11.6, 11.9, 12.5). An attachment the declared
//! principal does not hold, a device named without an account or at a
//! generation the directory never reached for that account, is refused for
//! its origin alone: nothing is acknowledged, the origin is fenced at the
//! generation and next sequence it holds, every later declaration of it is
//! refused alike, its deletion is acknowledged, and the link stays up.

use super::*;

const DEVICE_ID: [u8; 16] = [7; 16];
const OTHER_ACCOUNT: [u8; 24] = [b'b'; 24];

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
    let origin = held_origin(sync)?;
    Ok((origin.generation, origin.next_sequence, origin.fenced))
}

fn held_origin(sync: &Sync) -> TestResult<&crate::e2ee::coordinator::CompanionOrigin> {
    Ok(sync
        .harness
        .coordinator
        .state
        .origins
        .get(&CompanionOriginKey {
            home_server_id: HOME,
            server_incarnation: INCARNATION,
            origin_id: ORIGIN,
        })
        .ok_or("held origin")?)
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

/// Declares generation one naming `account` and `device` and returns the
/// frames the coordinator answers with.
fn declare_one(
    sync: &mut Sync,
    previous: [u8; 32],
    account: Option<([u8; 24], u64)>,
    device: Option<([u8; 16], u64)>,
) -> TestResult<Vec<CompanionFrame>> {
    base_generation(sync, 1)?;
    let (_, bytes) = origin_object(1, previous, account, device)?;
    frames(
        &sync
            .declare(true, 1, &bytes)
            .map_err(|f| format!("{f:?}"))?,
    )
}

#[test]
fn a_declaration_naming_a_superseded_attachment_is_mirrored_as_it_stands() -> TestResult {
    // The device attached a second time elsewhere: the directory is at two.
    let mut sync = attached(2)?;
    let previous = opened(&mut sync)?;
    let account = sync.harness.account;
    let acknowledged = declare_one(
        &mut sync,
        previous,
        Some((account, 3)),
        Some((DEVICE_ID, 1)),
    )?;
    assert!(matches!(
        acknowledged.as_slice(),
        [CompanionFrame::OriginAck {
            origin_generation: 1,
            object_id: Some(_),
            ..
        }]
    ));
    assert_eq!(held(&sync)?, (1, 0, false));
    assert_eq!(held_origin(&sync)?.device, Some((DEVICE_ID, 1)));
    Ok(())
}

#[test]
fn an_attachment_the_directory_never_reached_closes_only_its_origin() -> TestResult {
    let mut sync = attached(1)?;
    let previous = opened(&mut sync)?;
    sync.harness
        .coordinator
        .state
        .origins
        .values_mut()
        .for_each(|origin| origin.next_sequence = 4);
    let account = sync.harness.account;
    let refused = declare_one(
        &mut sync,
        previous,
        Some((account, 3)),
        Some((DEVICE_ID, 2)),
    )?;
    assert!(refused.is_empty(), "nothing is acknowledged");
    assert_eq!(held(&sync)?, (0, 4, true), "fenced where it stood");
    // The edge's deletion names the generation it declared last.
    let acknowledged = frames(&sync.frame(deletion(1)).map_err(|f| format!("{f:?}"))?)?;
    assert!(matches!(
        acknowledged.as_slice(),
        [CompanionFrame::OriginAck {
            origin_generation: 1,
            object_id: None,
            ..
        }]
    ));
    assert_eq!(held(&sync)?, (0, 4, true));
    Ok(())
}

/// A logout, or a switch to another account, that still names the device
/// attached under the first account names an attachment its principal does
/// not hold (companion 11.6).
#[test]
fn a_principal_change_that_still_names_the_device_closes_only_its_origin() -> TestResult {
    for (case, account) in [
        ("logout", None),
        ("account switch", Some((OTHER_ACCOUNT, 1))),
    ] {
        let mut sync = attached(1)?;
        let previous = opened(&mut sync)?;
        sync.host.origin.as_mut().ok_or("base origin")?.account = account;
        let refused = declare_one(&mut sync, previous, account, Some((DEVICE_ID, 1)))?;
        assert!(refused.is_empty(), "{case}: nothing is acknowledged");
        assert_eq!(held(&sync)?, (0, 0, true), "{case}");
        // A later declaration of the origin is refused alike.
        base_generation(&mut sync, 2)?;
        let (_, later) = origin_object(2, [9; 32], account, None)?;
        let refused = sync
            .declare(true, 2, &later)
            .map_err(|f| format!("{case}: {f:?}"))?;
        assert!(frames(&refused)?.is_empty(), "{case}");
        let acknowledged = frames(&sync.frame(deletion(2)).map_err(|f| format!("{f:?}"))?)?;
        assert_eq!(acknowledged.len(), 1, "{case}");
    }
    Ok(())
}

#[test]
fn a_refused_declaration_replayed_on_the_next_link_is_refused_again() -> TestResult {
    let mut sync = attached(1)?;
    let previous = opened(&mut sync)?;
    let account = sync.harness.account;
    base_generation(&mut sync, 1)?;
    let (_, bytes) = origin_object(1, previous, Some((account, 3)), Some((DEVICE_ID, 2)))?;
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
    supersede(&mut sync.harness, 2)?;
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

/// The device attaches on another connection: the directory moves to
/// `expected`.
fn supersede(harness: &mut Harness, expected: u64) -> TestResult {
    let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, &harness.account)?;
    let directory = &mut harness.coordinator.state.directory;
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
    assert_eq!(superseding, expected);
    Ok(())
}

/// The session generation `WHOAMI` reports: the current attachment's, or
/// zero for none (companion 11.6).
fn whoami_generation(harness: &mut Harness) -> TestResult<u64> {
    let outcome = super::super::ok(harness.run(super::super::Op::Whoami, &[], None)?)?;
    match outcome.result {
        crate::e2ee::coordinator::request::ResultBody::Account(_, generation) => Ok(generation),
        _ => Err("not an account result".into()),
    }
}

/// An attachment another attachment of the device superseded holds no
/// device authority (companion 11.9: `E2EE_DEVICE_REQUIRED` is "Connection
/// lacks a current roster-active device attachment"), and `WHOAMI`, which
/// is still served, reports no attachment (11.6: zero means no attached
/// device).
#[test]
fn a_superseded_attachment_holds_no_device_authority() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let (generation, _) = harness.attach()?;
    assert_eq!(generation, 1);
    super::super::ok(harness.run(super::super::Op::FetchMailbox, &[2, 0], None)?)?;
    assert_eq!(whoami_generation(&mut harness)?, 1);
    supersede(&mut harness, 2)?;
    assert_eq!(
        super::super::code(harness.run(super::super::Op::FetchMailbox, &[2, 0], None)?),
        Some(agenc_relay_e2ee::wire::reply::E2eeReplyCode::DeviceRequired)
    );
    assert_eq!(whoami_generation(&mut harness)?, 0);
    Ok(())
}

/// A superseded attachment is no attachment for delivery either: an edge
/// whose only origin of the account holds one is not targeted with the
/// account's direct events (companion 12.5: "whose Device ID is attached
/// and roster-active"), and it holds no direct standing.
#[test]
fn a_superseded_attachment_is_neither_targeted_nor_standing() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let _attached = harness.attach()?;
    let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, &harness.account)?;
    let accounts = [harness.account, OTHER_ACCOUNT];
    let standing = |harness: &Harness| {
        crate::e2ee::coordinator::direct_release::attached_at(
            &harness.coordinator.state,
            &NETWORK,
            (home(), false),
            &accounts,
        )
    };
    assert_eq!(
        crate::e2ee::coordinator::execute::attached_origin_edges(&harness.coordinator, &digest),
        vec![home()]
    );
    assert!(standing(&harness));
    supersede(&mut harness, 2)?;
    assert!(
        crate::e2ee::coordinator::execute::attached_origin_edges(&harness.coordinator, &digest)
            .is_empty()
    );
    assert!(!standing(&harness));
    Ok(())
}
