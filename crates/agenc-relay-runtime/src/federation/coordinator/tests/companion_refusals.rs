//! A companion request the coordinator refuses is answered with its failed
//! result, which consumes its operation sequence and commits no semantic
//! mutation (companion 12.5); the link stays up.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::sync::Action;
use crate::e2ee::coordinator::tests::fresh_fetch_fixture;
use crate::e2ee::coordinator::{CompanionCoordinator, CompleteRequest};
use agenc_relay_e2ee::ObjectId;
use agenc_relay_e2ee::federation::frames::Correlation;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{
    ArcFederationOpcode, ArcFederationRequest, ArcFederationResult, ArcFederationResultKind,
};
use agenc_relay_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

const PEER: ServerId = ServerId::from_bytes([2; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([4; 16]);
const COORDINATOR: ServerId = ServerId::from_bytes([3; 16]);
const COORDINATOR_NAME: &str = "coordinator.example";

/// The coordinator of an active, synchronized peer whose one attached
/// account origin runs requests against real storage.
struct Fixture {
    core: StateCoreFixture,
    coordinator: FederationCoordinator,
    handle: LinkHandle,
    queue: LinkQueue,
    origin_id: [u8; 16],
}

/// The answer one ERESULT carries.
#[derive(Debug, Eq, PartialEq)]
enum Answered {
    /// A failed result with its reply code.
    Failed(String),
    /// Any other result kind.
    Other(ArcFederationResultKind),
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let authority = fresh_fetch_fixture()?;
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        core.context_mut()?.set_wall_for_test(500);
        let mut coordinator = standalone_coordinator(PEER);
        coordinator.config.network_id = NetworkId::from_bytes([1; 32]);
        coordinator.config.server_id = COORDINATOR;
        coordinator.config.server_name = COORDINATOR_NAME.into();
        let origins = authority.executor.state.origins.clone();
        let origin_id = authority.complete.correlation.origin_id;
        coordinator
            .install_companion_executor(authority.executor, core.identity.server_incarnation)?;
        let (handle, queue) = link_queue(1 << 20);
        let peer = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
        peer.phase = PeerPhase::Ready;
        peer.live = Some(LiveLink {
            link: LinkId::new(1),
            handle: handle.clone(),
            incarnation: INCARNATION,
        });
        let mut fixture = Self {
            core,
            coordinator,
            handle,
            queue,
            origin_id,
        };
        fixture.activate().await?;
        fixture.executor_mut()?.state.origins = origins;
        Ok(fixture)
    }

    fn executor(&self) -> TestResult<&CompanionCoordinator> {
        self.coordinator
            .companion_exec
            .as_ref()
            .ok_or_else(|| "executor".into())
    }

    fn executor_mut(&mut self) -> TestResult<&mut CompanionCoordinator> {
        self.coordinator
            .companion_exec
            .as_mut()
            .ok_or_else(|| "executor".into())
    }

    async fn activate(&mut self) -> TestResult {
        for frame in [
            CompanionFrame::OriginReset {
                coordinator_server_id: *COORDINATOR.as_bytes(),
                server_incarnation: *INCARNATION.as_bytes(),
            },
            CompanionFrame::Resume {
                coordinator_server_id: *COORDINATOR.as_bytes(),
                server_incarnation: *INCARNATION.as_bytes(),
                delivery_generation: 0,
                last: None,
            },
        ] {
            companion::admitted(
                &mut self.coordinator,
                self.core.context_mut()?,
                LinkId::new(1),
                PEER,
                frame,
            )
            .map_err(|e| format!("sync: {e:?}"))?;
        }
        self.commit_pending().await?;
        let mut ready = None;
        while self.handle.queued_bytes() != 0 {
            let line = self.queue.recv().await.ok_or("sync line")?;
            if let ParsedLine::Companion(CompanionFrame::StateBegin {
                snapshot_token,
                state_generation,
                delivery_generation,
                snapshot_digest,
                ..
            }) = parse_line(
                line.as_str().strip_suffix("\r\n").ok_or("CRLF")?,
                COORDINATOR_NAME,
            )
            .map_err(|e| format!("sync line: {e:?}"))?
            {
                ready = Some(CompanionFrame::StateCut {
                    active: false,
                    server_id: *COORDINATOR.as_bytes(),
                    snapshot_token,
                    state_generation,
                    delivery_generation,
                    snapshot_digest,
                });
            }
        }
        companion::admitted(
            &mut self.coordinator,
            self.core.context_mut()?,
            LinkId::new(1),
            PEER,
            ready.ok_or("empty cut")?,
        )
        .map_err(|e| format!("ready: {e:?}"))?;
        self.commit_pending().await?;
        while self.handle.queued_bytes() != 0 {
            drop(self.queue.recv().await.ok_or("active line")?);
        }
        assert!(self.executor()?.accepting_requests(PEER));
        Ok(())
    }

    async fn commit_pending(&mut self) -> TestResult {
        let mut count = 0;
        while self.coordinator.pending.is_some() {
            self.core.commit_staged_batch().await?;
            self.coordinator.batch_applied(self.core.context_mut()?);
            count += 1;
            assert!(count <= 4);
        }
        Ok(())
    }

    fn next_sequence(&self) -> TestResult<u64> {
        Ok(self
            .executor()?
            .state
            .origins
            .values()
            .next()
            .ok_or("origin")?
            .next_sequence)
    }

    /// One `whoami` request of the origin at `sequence`.
    fn whoami(&self, sequence: u64) -> TestResult<CompleteRequest> {
        let mut request_id = [0x5c; 16];
        request_id
            .get_mut(..8)
            .ok_or("request id")?
            .copy_from_slice(&sequence.to_be_bytes());
        let request = ArcFederationRequest {
            profile_version: 1,
            network_id: [1; 32],
            home_server_id: *PEER.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
            origin_id: self.origin_id,
            origin_generation: 0,
            operation_sequence: sequence,
            request_id,
            opcode: ArcFederationOpcode::Whoami,
            encoded_parameters: Opaque::new(Vec::new())?,
            payload_object_id: Opaque::new(Vec::new())?,
        };
        Ok(CompleteRequest {
            correlation: Correlation {
                peer_server_id: *PEER.as_bytes(),
                server_incarnation: *INCARNATION.as_bytes(),
                origin_id: self.origin_id,
                origin_generation: 0,
                operation_sequence: sequence,
                request_id,
            },
            request: ArcWireObject::new(ArcWireObjectKind::FederationRequest, request.encode()?)?
                .encode()?,
            payload: None,
            refusal: None,
        })
    }

    /// Delivers `complete` as the link carries it.
    fn submit(&mut self, complete: &CompleteRequest) -> TestResult {
        let correlation = Correlation {
            peer_server_id: *COORDINATOR.as_bytes(),
            ..complete.correlation
        };
        for fragment in agenc_relay_e2ee::wire::fragment::fragment_object(&complete.request)? {
            companion::admitted(
                &mut self.coordinator,
                self.core.context_mut()?,
                LinkId::new(1),
                PEER,
                CompanionFrame::Request {
                    correlation,
                    object_id: *ObjectId::compute(&complete.request).as_bytes(),
                    fragment,
                },
            )
            .map_err(|e| format!("request: {e:?}"))?;
        }
        Ok(())
    }

    /// The answers of every ERESULT the link carries now, by sequence.
    async fn answers(&mut self) -> TestResult<Vec<(u64, Answered)>> {
        let mut answers = Vec::new();
        while self.handle.queued_bytes() != 0 {
            let line = self.queue.recv().await.ok_or("line")?;
            if let ParsedLine::Companion(CompanionFrame::Result {
                correlation,
                fragment,
                ..
            }) = parse_line(
                line.as_str().strip_suffix("\r\n").ok_or("CRLF")?,
                COORDINATOR_NAME,
            )
            .map_err(|e| format!("line: {e:?}"))?
            {
                answers.push((correlation.operation_sequence, answered(&fragment.segment)?));
            }
        }
        Ok(answers)
    }

    fn live(&self) -> bool {
        self.coordinator.link_is_live(LinkId::new(1), PEER)
    }
}

/// Decodes one single-fragment result object.
fn answered(bytes: &[u8]) -> TestResult<Answered> {
    let mut budget = DecodeBudget::new(1 << 16, 4_096);
    let object = ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::FederationResult),
        &mut budget,
    )?;
    let result = ArcFederationResult::decode_exact(object.body(), &mut budget)?;
    if result.result_kind != ArcFederationResultKind::Failed {
        return Ok(Answered::Other(result.result_kind));
    }
    let encoded = result.encoded_result.as_slice();
    let length = usize::from(*encoded.first().ok_or("code length")?);
    let code = encoded.get(1..=length).ok_or("code")?;
    Ok(Answered::Failed(String::from_utf8(code.to_vec())?))
}

#[tokio::test]
async fn a_refused_request_commits_its_failed_result_at_its_sequence() -> TestResult {
    let mut f = Box::pin(Fixture::new()).await?;
    let sequence = f.next_sequence()?;
    let mut refused = f.whoami(sequence)?;
    refused.refusal = Some(E2eeReplyCode::ReassemblyLimit);
    let request = refused.request.clone();
    companion::apply(
        &mut f.coordinator,
        f.core.context_mut()?,
        LinkId::new(1),
        PEER,
        Action::Execute(refused),
    )
    .map_err(|e| format!("refusal: {e:?}"))?;
    assert!(f.coordinator.pending.is_some());
    f.commit_pending().await?;
    let failed = Answered::Failed(E2eeReplyCode::ReassemblyLimit.token().to_owned());
    assert_eq!(f.answers().await?, vec![(sequence, failed)]);
    assert_eq!(f.next_sequence()?, sequence + 1, "the refusal consumed it");
    // The same request again is answered from its replay row, and its
    // object leaves the recent-object cache: a further copy is classified
    // against the replay rows again.
    let mut again = f.whoami(sequence)?;
    again.request = request;
    for replayed in 1..=2 {
        f.submit(&again)?;
        f.commit_pending().await?;
        let failed = Answered::Failed(E2eeReplyCode::ReassemblyLimit.token().to_owned());
        assert_eq!(f.answers().await?, vec![(sequence, failed)]);
        assert_eq!(f.coordinator.counters.requests_replayed, replayed);
    }
    // The next request runs at the following sequence.
    let next = f.whoami(sequence + 1)?;
    f.submit(&next)?;
    f.commit_pending().await?;
    assert_eq!(
        f.answers().await?,
        vec![(
            sequence + 1,
            Answered::Other(ArcFederationResultKind::Account)
        )]
    );
    assert!(f.live());
    assert_eq!(f.coordinator.counters.violations, 0);
    Ok(())
}
