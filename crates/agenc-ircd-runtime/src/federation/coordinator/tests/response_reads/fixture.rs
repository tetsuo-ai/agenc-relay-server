//! Replay metadata and signed capability bodies are committed through the actual storage owner.
#![forbid(unsafe_code)]

use super::*;
use crate::e2ee::coordinator::tests::support::{NETWORK as E2EE_NETWORK, capabilities, principal};
use crate::state_core::durable::AccountServiceDurableWrite;

pub(super) struct Fixture {
    pub(super) core: StateCoreFixture,
    pub(super) coordinator: FederationCoordinator,
    pub(super) handle: LinkHandle,
    pub(super) queue: LinkQueue,
    pub(super) decoded: Decoded,
    pub(super) responses: Vec<Vec<u8>>,
    pub(super) key: CompanionReplayKey,
    pub(super) request_bytes: Vec<u8>,
}

impl Fixture {
    pub(super) async fn new(missing: Option<usize>) -> TestResult<Self> {
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        let mut coordinator = standalone_coordinator(PEER);
        coordinator.config.network_id = NetworkId::from_bytes(E2EE_NETWORK);
        let mut executor =
            CompanionCoordinator::new(E2EE_NETWORK, COORDINATOR, COORDINATOR_NAME.into());
        let FixtureObjects {
            decoded,
            request_bytes,
            responses,
            outcome,
        } = objects()?;
        let result =
            request::encode_result(&executor, *PEER.as_bytes(), &decoded, &outcome, 1, None)
                .map_err(|e| format!("encode result: {e:?}"))?;
        let key = CompanionReplayKey {
            home_server_id: *PEER.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
            origin_id: decoded.request.origin_id,
            origin_generation: decoded.request.origin_generation,
            operation_sequence: decoded.request.operation_sequence,
        };
        let (row, replay_write) =
            request::replay_write(&key, &decoded, &result, &outcome.responses, false, 1000)
                .map_err(|e| format!("replay row: {e:?}"))?;
        let mut writes = vec![
            replay_write,
            CompanionCoordinator::object_write(&result)
                .map_err(|e| format!("result object: {e:?}"))?,
        ];
        for (index, bytes) in responses.iter().enumerate() {
            if Some(index) != missing {
                writes.push(
                    CompanionCoordinator::object_write(bytes)
                        .map_err(|e| format!("response object: {e:?}"))?,
                );
            }
        }
        commit(&mut core, writes).await?;
        executor.state.results.insert(
            decoded.request_object_id,
            StoredResult {
                result,
                responses: row.response_object_ids.clone(),
            },
        );
        executor.state.replays.insert(key, row);
        coordinator.install_companion_executor(executor, core.identity.server_incarnation)?;
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
            decoded,
            responses,
            key,
            request_bytes,
        };
        fixture.activate().await?;
        Ok(fixture)
    }

    pub(super) fn executor(&self) -> TestResult<&CompanionCoordinator> {
        self.coordinator
            .companion_exec
            .as_ref()
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

    pub(super) fn submit(&mut self) -> TestResult {
        let correlation = Correlation {
            peer_server_id: *COORDINATOR.as_bytes(),
            server_incarnation: *INCARNATION.as_bytes(),
            origin_id: self.decoded.request.origin_id,
            origin_generation: self.decoded.request.origin_generation,
            operation_sequence: self.decoded.request.operation_sequence,
            request_id: self.decoded.request.request_id,
        };
        for fragment in agenc_ircd_e2ee::wire::fragment::fragment_object(&self.request_bytes)? {
            companion::admitted(
                &mut self.coordinator,
                self.core.context_mut()?,
                LinkId::new(1),
                PEER,
                CompanionFrame::Request {
                    correlation,
                    object_id: self.decoded.request_object_id,
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

    pub(super) async fn finish_reads(&mut self) -> TestResult<usize> {
        let mut count = 0;
        while self.coordinator.companion_response_read.is_some() {
            assert_eq!(
                self.handle.queued_bytes(),
                0,
                "no reply before the final body"
            );
            let message = self.next_read().await?;
            assert!(self.coordinator.owns_storage_read(message.read_id));
            self.coordinator
                .storage_read_completed(self.core.context_mut()?, message);
            count += 1;
            assert!(count <= 3);
        }
        Ok(count)
    }

    pub(super) async fn expect_complete_output(&mut self) -> TestResult {
        let mut result_fragments = Vec::new();
        let mut bodies: std::collections::BTreeMap<u16, Vec<u8>> =
            std::collections::BTreeMap::new();
        while self.handle.queued_bytes() != 0 {
            let line = tokio::time::timeout(std::time::Duration::from_secs(5), self.queue.recv())
                .await?
                .ok_or("line")?;
            let parsed = parse_line(
                line.as_str().strip_suffix("\r\n").ok_or("CRLF")?,
                COORDINATOR_NAME,
            )
            .map_err(|e| format!("line: {e:?}"))?;
            match parsed {
                ParsedLine::Companion(CompanionFrame::Response {
                    response_index,
                    object_id,
                    fragment,
                    ..
                }) => {
                    let expected = self
                        .responses
                        .get(usize::from(response_index))
                        .ok_or("response index")?;
                    assert_eq!(&object_id, ObjectId::compute(expected).as_bytes());
                    bodies
                        .entry(response_index)
                        .or_default()
                        .extend_from_slice(&fragment.segment);
                }
                ParsedLine::Companion(CompanionFrame::Result { fragment, .. }) => {
                    result_fragments.extend_from_slice(&fragment.segment);
                }
                _ => return Err("unexpected replay line".into()),
            }
        }
        assert_eq!(bodies.len(), self.responses.len());
        for (index, expected) in self.responses.iter().enumerate() {
            assert_eq!(bodies.get(&u16::try_from(index)?), Some(expected));
        }
        assert_eq!(
            result_fragments,
            self.executor()?
                .state
                .results
                .get(&self.decoded.request_object_id)
                .ok_or("stored result")?
                .result
        );
        Ok(())
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

struct FixtureObjects {
    decoded: Decoded,
    request_bytes: Vec<u8>,
    responses: Vec<Vec<u8>>,
    outcome: Outcome,
}

fn objects() -> TestResult<FixtureObjects> {
    let account = agenc_ircd_types::AccountId::from_random(
        agenc_ircd_types::AccountRandomId::from_bytes([30; 16]),
    )
    .to_text();
    let identity = principal(30, &account.as_bytes().try_into()?, &[31, 32, 33])?;
    let mut parameters = vec![24];
    parameters.extend_from_slice(account.as_bytes());
    parameters.push(0);
    let request = IrcFederationRequest {
        profile_version: 1,
        network_id: E2EE_NETWORK,
        home_server_id: *PEER.as_bytes(),
        server_incarnation: *INCARNATION.as_bytes(),
        origin_id: [55; 16],
        origin_generation: 0,
        operation_sequence: 0,
        request_id: [56; 16],
        opcode: IrcFederationOpcode::FetchCapabilities,
        encoded_parameters: Opaque::new(parameters)?,
        payload_object_id: Opaque::new(Vec::new())?,
    };
    let bytes =
        IrcWireObject::new(IrcWireObjectKind::FederationRequest, request.encode()?)?.encode()?;
    let decoded = Decoded {
        request_object_id: *ObjectId::compute(&bytes).as_bytes(),
        request,
        payload: None,
        payload_bytes: None,
    };
    let mut outcome = Outcome::scalar(ResultBody::ObjectPage);
    outcome.snapshot_token = Some([19; 32]);
    let mut responses = Vec::new();
    for seed in [31, 32, 33] {
        let capability = capabilities(seed, &identity.roster, 0, [0; 32], (100, 1000), vec![1])?;
        let bytes =
            IrcWireObject::new(IrcWireObjectKind::DeviceCapabilities, capability.encode()?)?
                .encode()?;
        responses.push(bytes.clone());
        outcome.responses.push(ResponseObject {
            bytes,
            delivery_token: None,
            target_device_id: None,
        });
    }
    Ok(FixtureObjects {
        decoded,
        request_bytes: bytes,
        responses,
        outcome,
    })
}
