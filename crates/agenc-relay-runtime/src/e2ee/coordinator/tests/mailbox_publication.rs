//! Prepared cuts cannot revive closed origins or expired snapshots on receipt.

#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::sync::OriginDescriptor;
use crate::e2ee::coordinator::tests::{HOME, INCARNATION, ORIGIN, origin_key};

fn apply(source: &mut Harness, mut outcome: Outcome) {
    for effect in std::mem::take(&mut outcome.effects) {
        effect(&mut source.coordinator.state);
    }
}

fn close(source: &mut Harness, key: crate::e2ee::coordinator::CompanionOriginKey) -> TestResult {
    let origin = source.coordinator.state.origins.get(&key).ok_or("origin")?;
    let descriptor = OriginDescriptor {
        coordinator_server_id: *source.coordinator.server_id.as_bytes(),
        server_incarnation: key.server_incarnation,
        origin_id: key.origin_id,
        origin_generation: origin.generation,
        object_id: [0; 32],
    };
    source.coordinator.origin_del(
        ServerId::from_bytes(key.home_server_id),
        descriptor,
        origin.next_sequence,
        &Host(key.server_incarnation),
    )?;
    Ok(())
}

#[test]
fn mailbox_publication_discards_a_cut_whose_origin_closed_during_the_receipt() -> TestResult {
    let (mut source, mut entropy) = mailbox()?;
    let candidate = ok(evaluate_request_with_entropy(
        &source,
        Op::FetchMailbox,
        &[2, 0],
        None,
        &mut entropy,
    )?)?;
    close(&mut source, origin_key())?;
    assert_eq!(
        source.query_sessions.queue_snapshot().query_snapshots(),
        1,
        "pending work stays charged until its receipt"
    );
    apply(&mut source, candidate);
    assert_eq!(
        source.coordinator.state.mailbox_snapshots.next_expiry(),
        None
    );
    let usage = source.query_sessions.queue_snapshot();
    assert_eq!(
        (
            usage.query_snapshots(),
            usage.query_rows(),
            usage.query_bytes()
        ),
        (0, 0, 0)
    );
    Ok(())
}

fn other_request(source: &mut Harness) -> TestResult<crate::e2ee::coordinator::CompleteRequest> {
    let mut origin = source
        .coordinator
        .state
        .origins
        .get(&origin_key())
        .cloned()
        .ok_or("origin")?;
    origin.origin_id = [198; 16];
    origin.connection_id = [197; 16];
    origin.connection_nonce = [196; 32];
    let key = crate::e2ee::coordinator::CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: origin.origin_id,
    };
    source.coordinator.state.origins.insert(key, origin);
    let mut complete = source.request(Op::FetchMailbox, &[2, 0], None)?;
    let mut request = request::decode(&source.coordinator, &complete)
        .map_err(|code| format!("request: {code:?}"))?
        .request;
    request.origin_id = key.origin_id;
    complete.correlation.origin_id = key.origin_id;
    complete.request = crate::e2ee::coordinator::tests::wire(
        agenc_relay_e2ee::object::ArcWireObjectKind::FederationRequest,
        &request,
    )?;
    Ok(complete)
}

#[test]
fn mailbox_publication_cannot_restore_another_closed_origin_from_a_copied_store() -> TestResult {
    let (mut source, _, _, mut entropy) = paged_mailbox()?;
    let complete = other_request(&mut source)?;
    let port = source.query_sessions.query_reservations(
        UserId::from_bytes([195; 16]),
        source.query_limits,
        source.backing.clone(),
    );
    let candidate = ok(evaluate_complete_with_queries(
        &source,
        complete,
        &mut entropy,
        port,
    )?)?;
    assert_eq!(source.query_sessions.queue_snapshot().query_snapshots(), 2);
    close(&mut source, origin_key())?;
    apply(&mut source, candidate);
    assert_eq!(
        source.query_sessions.queue_snapshot().query_snapshots(),
        1,
        "only the requesting live origin remains"
    );
    let other = crate::e2ee::coordinator::CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: [198; 16],
    };
    close(&mut source, other)?;
    assert_eq!(source.query_sessions.queue_snapshot().query_bytes(), 0);
    assert!(
        source
            .coordinator
            .state
            .origins
            .get(&origin_key())
            .is_some_and(|origin| origin.fenced)
    );
    assert_ne!(other.origin_id, ORIGIN);
    Ok(())
}

#[test]
fn mailbox_publication_drops_a_cut_that_expired_while_storage_was_pending() -> TestResult {
    let (mut source, mut entropy) = mailbox()?;
    let candidate = ok(evaluate_request_with_entropy(
        &source,
        Op::FetchMailbox,
        &[2, 0],
        None,
        &mut entropy,
    )?)?;
    source.coordinator.state.mailbox_snapshot_now = source.monotonic_millis + 600_000;
    apply(&mut source, candidate);
    assert_eq!(
        source.coordinator.state.mailbox_snapshots.next_expiry(),
        None
    );
    assert_eq!(source.query_sessions.queue_snapshot().query_bytes(), 0);
    Ok(())
}

/// A cut whose origin's attachment another attachment of its device
/// superseded is dropped at the next publication: that origin holds no
/// current attachment (companion 11.6, 11.9), as one whose device changed
/// holds none.
#[test]
fn mailbox_publication_drops_the_cut_of_a_superseded_attachment() -> TestResult {
    let (mut source, _, _, mut entropy) = paged_mailbox()?;
    let complete = other_request(&mut source)?;
    let (device, generation) = source
        .coordinator
        .state
        .origins
        .get(&origin_key())
        .and_then(|origin| origin.device)
        .ok_or("attached origin")?;
    // The other connection attaches the device again.
    let digest = agenc_relay_e2ee::ids::account_id_digest(&NETWORK, &source.account)?;
    let directory = &mut source.coordinator.state.directory;
    let challenge = directory
        .attach_begin(digest, device, [197; 16], NOW)
        .map_err(|error| format!("{error:?}"))?;
    let superseding = directory
        .attach_finish(
            digest,
            device,
            [197; 16],
            challenge.reserved_generation,
            NOW,
        )
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(superseding, generation + 1);
    let other = crate::e2ee::coordinator::CompanionOriginKey {
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: [198; 16],
    };
    source
        .coordinator
        .state
        .origins
        .get_mut(&other)
        .ok_or("other origin")?
        .device = Some((device, superseding));
    let port = source.query_sessions.query_reservations(
        UserId::from_bytes([195; 16]),
        source.query_limits,
        source.backing.clone(),
    );
    let candidate = ok(evaluate_complete_with_queries(
        &source,
        complete,
        &mut entropy,
        port,
    )?)?;
    assert_eq!(source.query_sessions.queue_snapshot().query_snapshots(), 2);
    apply(&mut source, candidate);
    assert_eq!(
        source.query_sessions.queue_snapshot().query_snapshots(),
        1,
        "only the current attachment's cut remains"
    );
    Ok(())
}
