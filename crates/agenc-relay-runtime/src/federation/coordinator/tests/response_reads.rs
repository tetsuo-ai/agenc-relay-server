//! Complete and recently assembled replies read sealed response bodies before publication.
#![forbid(unsafe_code)]

mod failures;
mod fixture;
mod validation;

use super::*;
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::e2ee::coordinator::request::{self, Decoded, Outcome, ResponseObject, ResultBody};
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::federation::frames::Correlation;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{ArcFederationOpcode, ArcFederationRequest};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_storage::e2ee_records::ReplayKey as CompanionReplayKey;
use fixture::Fixture;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

#[tokio::test]
async fn complete_and_recent_requests_replay_all_cold_bodies_in_original_order() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let initial = fixture.core.context_mut()?.head().storage_commit_sequence;
    for replay_count in 1..=2 {
        // Each ingress assembles and decodes the complete request: the
        // previous replay released its objects from the recent-object cache.
        fixture.submit()?;
        assert!(fixture.coordinator.companion_response_read.is_some());
        assert!(!fixture.coordinator.reload_ready());
        assert_eq!(fixture.handle.queued_bytes(), 0);
        assert_eq!(fixture.finish_reads().await?, 3);
        assert!(fixture.coordinator.reload_ready());
        assert_eq!(fixture.coordinator.counters.requests_replayed, replay_count);
        fixture.expect_complete_output().await?;
        assert_eq!(
            fixture.core.context_mut()?.head().storage_commit_sequence,
            initial
        );
        assert!(fixture.coordinator.pending.is_none());
        assert!(fixture.executor()?.state.objects.is_empty());
    }
    Ok(())
}

/// A request whose stored result is read back from storage keeps its
/// request and payload objects while the read runs, and releases them when
/// the result is sent, as a resident replay does (companion 12.5).
#[tokio::test]
async fn a_cold_replay_releases_the_request_and_payload_objects() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let correlation = Correlation {
        peer_server_id: *PEER.as_bytes(),
        server_incarnation: *INCARNATION.as_bytes(),
        origin_id: fixture.decoded.request.origin_id,
        origin_generation: fixture.decoded.request.origin_generation,
        operation_sequence: fixture.decoded.request.operation_sequence,
        request_id: fixture.decoded.request.request_id,
    };
    let payload = vec![7; 64];
    let payload_id = *ObjectId::compute(&payload).as_bytes();
    let request_id = fixture.decoded.request_object_id;
    let now = crate::e2ee::link::tick_millis(fixture.core.context_mut()?.now());
    fixture
        .coordinator
        .companion_exec
        .as_mut()
        .ok_or("executor")?
        .complete_request_object(PEER, &correlation, &payload, now)
        .map_err(|e| format!("payload: {e:?}"))?;
    fixture.submit()?;
    assert!(fixture.coordinator.companion_response_read.is_some());
    let executor = fixture.executor()?;
    assert!(executor.holds_request_object(PEER, &correlation, request_id));
    assert!(executor.holds_request_object(PEER, &correlation, payload_id));
    fixture.finish_reads().await?;
    fixture.expect_complete_output().await?;
    let executor = fixture.executor()?;
    assert!(!executor.holds_request_object(PEER, &correlation, request_id));
    assert!(!executor.holds_request_object(PEER, &correlation, payload_id));
    Ok(())
}

#[tokio::test]
async fn missing_first_middle_or_last_stored_body_emits_no_reply() -> TestResult {
    for missing in 0..3 {
        let mut fixture = Box::pin(Fixture::new(Some(missing))).await?;
        fixture.submit()?;
        assert_eq!(fixture.finish_reads().await?, missing + 1);
        assert_eq!(fixture.handle.queued_bytes(), 0);
        assert_eq!(fixture.coordinator.counters.requests_replayed, 0);
        assert_eq!(fixture.coordinator.counters.violations, 1);
        assert!(!fixture.coordinator.link_is_live(LinkId::new(1), PEER));
        assert!(fixture.coordinator.pending.is_none());
    }
    Ok(())
}
