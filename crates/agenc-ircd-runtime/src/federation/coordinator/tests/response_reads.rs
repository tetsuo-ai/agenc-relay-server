//! Complete and recently assembled replies read sealed response bodies before publication.
#![forbid(unsafe_code)]

mod failures;
mod fixture;
mod validation;

use super::*;
use crate::bridge::{StorageReadCompletionMessage, StorageReadId};
use crate::e2ee::coordinator::request::{self, Decoded, Outcome, ResponseObject, ResultBody};
use crate::e2ee::coordinator::{CompanionCoordinator, StoredResult};
use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::federation::frames::Correlation;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::{IrcFederationOpcode, IrcFederationRequest};
use agenc_ircd_e2ee::tls::{Opaque, TlsEncode};
use agenc_ircd_storage::e2ee_records::ReplayKey as CompanionReplayKey;
use fixture::Fixture;

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);

#[tokio::test]
async fn complete_and_recent_requests_replay_all_cold_bodies_in_original_order() -> TestResult {
    let mut fixture = Box::pin(Fixture::new(None)).await?;
    let initial = fixture.core.context_mut()?.head().storage_commit_sequence;
    for replay_count in 1..=2 {
        // First ingress assembles and decodes the complete request; second ingress hits Recent.
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
