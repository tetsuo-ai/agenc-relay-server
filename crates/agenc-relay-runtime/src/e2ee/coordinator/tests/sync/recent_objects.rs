#![forbid(unsafe_code)]

//! The coordinator's recent-object cache (companion 11.8, 16): each peer has
//! its own ceiling, a request past it is refused per request, completed
//! objects are forgotten once their idempotency window ends, an answered
//! request releases its objects, and a declaration holds no slot.

use agenc_relay_e2ee::federation::frames::Correlation;
use agenc_relay_e2ee::limits::RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS;
use agenc_relay_e2ee::objects::federation::{ArcFederationOpcode as Op, ArcFederationRequest};
use agenc_relay_e2ee::wire::assembly::{AssemblyKey, Direction, MAX_RECENT_OBJECTS, Sender};
use agenc_relay_e2ee::wire::carrier::CarrierCommand;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::*;
use crate::e2ee::coordinator::{CompleteRequest, PendingCompanion};

/// One distinct `whoami` request at `count` with its wire correlation.
fn request(count: u64, payload: Option<&[u8]>) -> TestResult<(Correlation, Vec<u8>)> {
    let mut request_id = [0xa5; 16];
    request_id
        .get_mut(..8)
        .ok_or("request id")?
        .copy_from_slice(&count.to_be_bytes());
    let request = ArcFederationRequest {
        profile_version: 1,
        network_id: NETWORK,
        home_server_id: HOME,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: 0,
        operation_sequence: count,
        request_id,
        opcode: if payload.is_some() {
            Op::PublishIdentity
        } else {
            Op::Whoami
        },
        encoded_parameters: Opaque::new(Vec::new())?,
        payload_object_id: Opaque::new(
            payload
                .map(|bytes| object_id(bytes).to_vec())
                .unwrap_or_default(),
        )?,
    };
    let correlation = Correlation {
        peer_server_id: COORDINATOR,
        server_incarnation: INCARNATION,
        origin_id: ORIGIN,
        origin_generation: 0,
        operation_sequence: count,
        request_id,
    };
    Ok((
        correlation,
        wire(ArcWireObjectKind::FederationRequest, &request)?,
    ))
}

/// Feeds every fragment of one request (and its payload) from `peer` at
/// `now_millis` and returns the one request the coordinator completes.
fn submit(
    sync: &mut Sync,
    peer: ServerId,
    count: u64,
    payload: Option<&[u8]>,
    now_millis: u64,
) -> Result<CompleteRequest, CompanionFault> {
    let (correlation, bytes) = request(count, payload).map_err(|_| CompanionFault::Protocol)?;
    let mut frames = Vec::new();
    for fragment in fragment_object(&bytes).map_err(|_| CompanionFault::Protocol)? {
        frames.push(CompanionFrame::Request {
            correlation,
            object_id: object_id(&bytes),
            fragment,
        });
    }
    if let Some(payload) = payload {
        for fragment in fragment_object(payload).map_err(|_| CompanionFault::Protocol)? {
            frames.push(CompanionFrame::Payload {
                correlation,
                object_id: object_id(payload),
                fragment,
            });
        }
    }
    let mut complete = None;
    for frame in frames {
        for action in sync.harness.coordinator.on_frame(
            LinkId::new(1),
            peer,
            frame,
            now_millis,
            &sync.host,
            &mut sync.entropy,
        )? {
            if let Action::Execute(request) = action {
                complete = Some(request);
            }
        }
    }
    complete.ok_or(CompanionFault::Storage)
}

/// The recent-cache key of the request or payload object `bytes` of the
/// request at `count` from `peer`.
fn key_of(peer: ServerId, count: u64, bytes: &[u8]) -> TestResult<AssemblyKey> {
    let (correlation, _) = request(count, None)?;
    let mut route = [0; 32];
    route
        .get_mut(..16)
        .ok_or("route")?
        .copy_from_slice(&correlation.request_id);
    Ok(AssemblyKey {
        direction: Direction::Remote,
        sender: Sender::Peer(*peer.as_bytes()),
        command: CarrierCommand::Federation(ArcWireObjectKind::FederationRequest),
        route,
        scope: None,
        object_id: agenc_relay_e2ee::ObjectId::from_bytes(object_id(bytes)),
    })
}

/// Fills the peer's ceiling with requests that complete and await the
/// executor at `now_millis`.
fn fill(sync: &mut Sync, now_millis: u64) -> TestResult {
    for count in 0..u64::try_from(MAX_RECENT_OBJECTS)? {
        let complete =
            submit(sync, home(), count, None, now_millis).map_err(|f| format!("{f:?}"))?;
        assert_eq!(complete.refusal, None, "request {count} is run");
    }
    Ok(())
}

#[test]
fn a_request_past_its_peers_ceiling_is_refused_per_request() -> TestResult {
    let mut sync = Sync::new()?;
    fill(&mut sync, NOW_MILLIS)?;
    let past = u64::try_from(MAX_RECENT_OBJECTS)?;
    // The link stays: the request completes, to be answered with its refusal.
    let refused =
        submit(&mut sync, home(), past, None, NOW_MILLIS).map_err(|f| format!("{f:?}"))?;
    assert_eq!(refused.refusal, Some(E2eeReplyCode::ReassemblyLimit));
    // A request with a payload past the ceiling is refused the same way.
    let payload = super::super::wire_raw(ArcWireObjectKind::RootIdentity, vec![1; 8])?;
    let refused = submit(&mut sync, home(), past + 1, Some(&payload), NOW_MILLIS)
        .map_err(|f| format!("{f:?}"))?;
    assert_eq!(refused.refusal, Some(E2eeReplyCode::ReassemblyLimit));
    assert!(refused.payload.is_some());
    // Another peer keeps its own ceiling.
    let other = ServerId::from_bytes([9; 16]);
    let run = submit(&mut sync, other, past, None, NOW_MILLIS).map_err(|f| format!("{f:?}"))?;
    assert_eq!(run.refusal, None);
    Ok(())
}

#[test]
fn completed_objects_are_forgotten_when_their_window_ends() -> TestResult {
    let mut sync = Sync::new()?;
    fill(&mut sync, NOW_MILLIS)?;
    let window = RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS * 1_000;
    let past = u64::try_from(MAX_RECENT_OBJECTS)?;
    let inside = submit(&mut sync, home(), past, None, NOW_MILLIS + window - 1_000)
        .map_err(|f| format!("{f:?}"))?;
    assert_eq!(inside.refusal, Some(E2eeReplyCode::ReassemblyLimit));
    let ended = NOW_MILLIS + window;
    let after = submit(&mut sync, home(), past + 1, None, ended).map_err(|f| format!("{f:?}"))?;
    assert_eq!(
        after.refusal, None,
        "the expired objects freed the peer's slots"
    );
    // The first request's copy is no longer answered from the cache: it
    // assembles again and is classified against the replay rows.
    let first = submit(&mut sync, home(), 0, None, ended).map_err(|f| format!("{f:?}"))?;
    assert_eq!(first.refusal, None);
    Ok(())
}

#[test]
fn an_answered_request_releases_its_objects() -> TestResult {
    let mut sync = Sync::new()?;
    let payload = super::super::wire_raw(ArcWireObjectKind::RootIdentity, vec![2; 8])?;
    let answered =
        submit(&mut sync, home(), 0, Some(&payload), NOW_MILLIS).map_err(|f| format!("{f:?}"))?;
    let waiting = submit(&mut sync, home(), 1, None, NOW_MILLIS).map_err(|f| format!("{f:?}"))?;
    let request_key = key_of(home(), 0, &answered.request)?;
    let payload_key = key_of(home(), 0, &payload)?;
    let waiting_key = key_of(home(), 1, &waiting.request)?;
    let assembler = &sync.harness.coordinator.assembler;
    assert!(assembler.is_recent(&request_key) && assembler.is_recent(&payload_key));
    // The request's batch commits: its replay row answers any later copy.
    sync.harness
        .coordinator
        .set_pending(PendingWork::Request(Box::new(PendingCompanion {
            link: LinkId::new(1),
            peer: home(),
            correlation: Correlation {
                peer_server_id: HOME,
                ..answered.correlation
            },
            request_object_id: object_id(&answered.request),
            result: Vec::new(),
            responses: Vec::new(),
            events: Vec::new(),
            effects: Vec::new(),
            barriers: Vec::new(),
            object_backing: None,
            request: CompleteRequest {
                correlation: answered.correlation,
                request: answered.request.clone(),
                payload: answered.payload.clone(),
                refusal: None,
            },
        })));
    let committed = sync
        .harness
        .coordinator
        .batch_applied(None)
        .map_err(|f| format!("{f:?}"))?;
    assert!(matches!(committed, Some(Committed::Request(_))));
    let assembler = &sync.harness.coordinator.assembler;
    assert!(!assembler.is_recent(&request_key));
    assert!(!assembler.is_recent(&payload_key));
    assert!(
        assembler.is_recent(&waiting_key),
        "another request keeps its objects"
    );
    Ok(())
}

#[test]
fn a_declaration_holds_no_slot_and_is_acknowledged_again() -> TestResult {
    let mut sync = Sync::new()?;
    sync.reset()?;
    let (_, bytes) = origin_object(0, [0; 32], None, None)?;
    for _ in 0..2 {
        let acknowledged = frames(
            &sync
                .declare(false, 0, &bytes)
                .map_err(|f| format!("{f:?}"))?,
        )?;
        assert!(matches!(
            acknowledged.as_slice(),
            [CompanionFrame::OriginAck {
                object_id: Some(_),
                ..
            }]
        ));
        let mut route = [0; 32];
        route.get_mut(..16).ok_or("route")?.copy_from_slice(&ORIGIN);
        let declared = AssemblyKey {
            direction: Direction::Remote,
            sender: Sender::Peer(HOME),
            command: CarrierCommand::Federation(ArcWireObjectKind::FederationOrigin),
            route,
            scope: None,
            object_id: agenc_relay_e2ee::ObjectId::from_bytes(object_id(&bytes)),
        };
        assert!(!sync.harness.coordinator.assembler.is_recent(&declared));
    }
    Ok(())
}
