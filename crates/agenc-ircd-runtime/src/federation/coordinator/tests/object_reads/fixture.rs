//! Fresh reads use valid handler authority and the actual root storage and receipt path.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::tests::fresh_fetch_fixture;
use crate::state_core::durable::AccountServiceDurableWrite;

pub(super) struct Fixture {
    pub(super) core: StateCoreFixture,
    pub(super) coordinator: FederationCoordinator,
    pub(super) handle: LinkHandle,
    pub(super) queue: LinkQueue,
    pub(super) complete: CompleteRequest,
    pub(super) conversation: [u8; 32],
    pub(super) object_id: [u8; 32],
    pub(super) bytes: Vec<u8>,
}
impl Fixture {
    pub(super) async fn new(persist: bool) -> TestResult<Self> {
        let authority = fresh_fetch_fixture()?;
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        core.context_mut()?.set_wall_for_test(500);
        if persist {
            commit(
                &mut core,
                vec![
                    CompanionCoordinator::object_write(&authority.bytes)
                        .map_err(|e| format!("object: {e:?}"))?,
                ],
            )
            .await?;
        }
        let mut coordinator = standalone_coordinator(PEER);
        coordinator.config.network_id = NetworkId::from_bytes([1; 32]);
        coordinator.config.server_id = COORDINATOR;
        coordinator.config.server_name = COORDINATOR_NAME.into();
        // The handler fixture supplies verified attachment and log authority. The empty
        // base projection intentionally contributes no channel membership or leaf proof.
        let origins = authority.executor.state.origins.clone();
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
            complete: authority.complete,
            conversation: authority.conversation,
            object_id: authority.object_id,
            bytes: authority.bytes,
        };
        fixture.activate().await?;
        fixture.executor_mut()?.state.origins = origins;
        Ok(fixture)
    }
    pub(super) fn executor(&self) -> TestResult<&CompanionCoordinator> {
        self.coordinator
            .companion_exec
            .as_ref()
            .ok_or_else(|| "executor".into())
    }
    pub(super) fn executor_mut(&mut self) -> TestResult<&mut CompanionCoordinator> {
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
                total_entry_count,
                snapshot_digest,
                ..
            }) = parse_line(
                line.as_str().strip_suffix("\r\n").ok_or("CRLF")?,
                COORDINATOR_NAME,
            )
            .map_err(|e| format!("sync line: {e:?}"))?
            {
                assert_eq!(total_entry_count, 0);
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
    pub(super) async fn commit_pending(&mut self) -> TestResult {
        let mut count = 0;
        while self.coordinator.pending.is_some() {
            self.core.commit_staged_batch().await?;
            self.coordinator.batch_applied(self.core.context_mut()?);
            count += 1;
            assert!(count <= 4);
        }
        Ok(())
    }
    pub(super) fn submit(&mut self) -> TestResult {
        let correlation = Correlation {
            peer_server_id: *COORDINATOR.as_bytes(),
            ..self.complete.correlation
        };
        for fragment in agenc_ircd_e2ee::wire::fragment::fragment_object(&self.complete.request)? {
            companion::admitted(
                &mut self.coordinator,
                self.core.context_mut()?,
                LinkId::new(1),
                PEER,
                CompanionFrame::Request {
                    correlation,
                    object_id: *ObjectId::compute(&self.complete.request).as_bytes(),
                    fragment,
                },
            )
            .map_err(|e| format!("request: {e:?}"))?;
        }
        Ok(())
    }
    pub(super) async fn next_read(&mut self) -> TestResult<StorageReadCompletionMessage> {
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.core.next_storage_read(),
        )
        .await?
    }
    pub(super) async fn resolve(&mut self) -> TestResult {
        assert!(self.coordinator.companion_object_read.is_some());
        let message = self.next_read().await?;
        self.coordinator
            .storage_read_completed(self.core.context_mut()?, message);
        assert!(self.coordinator.companion_object_read.is_none());
        Ok(())
    }
    pub(super) async fn output(&mut self) -> TestResult<Vec<Vec<u8>>> {
        let mut bodies = std::collections::BTreeMap::<u16, Vec<u8>>::new();
        let mut result = Vec::new();
        while self.handle.queued_bytes() != 0 {
            let line = self.queue.recv().await.ok_or("line")?;
            match parse_line(
                line.as_str().strip_suffix("\r\n").ok_or("CRLF")?,
                COORDINATOR_NAME,
            )
            .map_err(|e| format!("line: {e:?}"))?
            {
                ParsedLine::Companion(CompanionFrame::Response {
                    response_index,
                    object_id,
                    fragment,
                    ..
                }) => {
                    assert_eq!(object_id, self.object_id);
                    bodies
                        .entry(response_index)
                        .or_default()
                        .extend_from_slice(&fragment.segment);
                }
                ParsedLine::Companion(CompanionFrame::Result { fragment, .. }) => {
                    result.extend_from_slice(&fragment.segment)
                }
                _ => return Err("unexpected frame".into()),
            }
        }
        assert!(!result.is_empty());
        let stored = self
            .executor()?
            .state
            .results
            .get(ObjectId::compute(&self.complete.request).as_bytes())
            .ok_or("stored result")?;
        assert_eq!(result, stored.result);
        Ok(bodies.into_values().collect())
    }
    pub(super) fn next_sequence(&self) -> TestResult<u64> {
        Ok(self
            .executor()?
            .state
            .origins
            .values()
            .next()
            .ok_or("origin")?
            .next_sequence)
    }
}
pub(super) async fn commit(
    core: &mut StateCoreFixture,
    writes: Vec<AccountServiceDurableWrite>,
) -> TestResult {
    let context = core.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(revision))
        .collect::<Result<Vec<_>, _>>()?;
    context
        .stage_durable_with_account_service(
            plan,
            crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
            None,
            0,
            writes,
        )
        .map_err(|e| format!("stage replay: {e:?}"))?;
    core.commit_staged_batch().await?;
    Ok(())
}
