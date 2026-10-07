//! Both streams and ACK transitions pass through the actual storage owner.
#![forbid(unsafe_code)]

mod ack_faults;
mod ack_read;
mod lost_acks;
mod maintenance;
mod page_read;
mod replay;
mod resume_prefix;
mod write_contention;

use super::*;
use crate::e2ee::coordinator::events::{self, DeliveryStream, EventContent};
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::projector::{CrossProfileAssignment, barrier};
use agenc_relay_domain::e2ee::projection::{EventKind, EventPlan, PlannedEvent};
use agenc_relay_storage::e2ee_records::delivery_recovery::{
    BarrierEndpoint, CutPhase, DeliveryBarrier, DeliveryCursor, DeliveryOwner, DeliveryRecoveryRow,
    DeliveryScope, DeliveryScopeFields, LastAcknowledged, SnapshotCut, SnapshotCutFields,
};
use agenc_relay_storage::federation_records::{OUTBOX_EVENT_KIND, OutboxEventRecord, outbox_key};

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const INCARNATION: ServerIncarnation = ServerIncarnation::from_bytes([51; 16]);
const MUTATION: [u8; 16] = [81; 16];

struct Fixture {
    core: StateCoreFixture,
    coordinator: FederationCoordinator,
    gate: DeliveryBarrier,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        Box::pin(Self::seed(false)).await
    }

    async fn seed(prefix: bool) -> TestResult<Self> {
        let mut core = StateCoreFixture::with_registration_router(entropy_script())?;
        let mut coordinator = standalone_coordinator(PEER);
        coordinator.install_companion_executor(
            CompanionCoordinator::new(
                *NETWORK.as_bytes(),
                COORDINATOR,
                COORDINATOR_NAME.to_owned(),
            ),
            core.identity.server_incarnation,
        )?;
        let scope = DeliveryScope::new(DeliveryScopeFields {
            network_id: *NETWORK.as_bytes(),
            coordinator_server_id: *COORDINATOR.as_bytes(),
            coordinator_incarnation: *core.identity.server_incarnation.as_bytes(),
            coordinator_recovery_epoch: *coordinator.config.recovery_epoch.as_bytes(),
            target_server_id: *PEER.as_bytes(),
            target_incarnation: *INCARNATION.as_bytes(),
            covered_base_client_resync_epoch: 0,
        })?;
        let owner = DeliveryOwner::new(
            scope,
            DeliveryCursor::new(0, 0, LastAcknowledged::BeforeFirst)?,
            SnapshotCut::new(SnapshotCutFields {
                token: [71; 32],
                state_generation: 0,
                delivery_generation: 0,
                entry_count: 0,
                digest: [72; 32],
                page_count: 1,
                total_object_bytes: 0,
            })?,
            CutPhase::Ready,
        )?;
        let executor = coordinator.companion_exec.as_mut().ok_or("executor")?;
        executor.state.streams.insert(
            PEER,
            DeliveryStream {
                owner: Some(owner),
                ..DeliveryStream::default()
            },
        );
        let plan = EventPlan::order(
            [7, 8]
                .into_iter()
                .map(|seed| PlannedEvent {
                    kind: EventKind::RouteStateHidden,
                    conversation_id: Some([seed; 32]),
                    target: PEER,
                    payload_object_id: None,
                    completion: false,
                    route_sequence: 0,
                    bytes: 1024,
                })
                .collect(),
        )?;
        let contents = plan
            .events()
            .iter()
            .cloned()
            .map(|planned| EventContent {
                planned,
                origin: None,
                source_view: Vec::new(),
                correlation: None,
                encoded_result: Vec::new(),
                payload: None,
            })
            .collect::<Vec<_>>();
        let backing = core.context_mut()?.backing_reservations();
        if prefix {
            let ordinary = events::sequence_copies(
                executor,
                &plan,
                &contents,
                1,
                core.context_mut()?.entropy_mut(),
                &std::collections::BTreeMap::new(),
                &backing,
            )
            .map_err(|e| format!("ordinary sequence: {e:?}"))?;
            let context = core.context_mut()?;
            let checkpoint = context.domain().plan_account_service_checkpoint()?;
            let revision = checkpoint.resulting_revision().get();
            let writes = ordinary
                .writes
                .into_iter()
                .map(|write| write.at_revision(revision))
                .collect::<Result<Vec<_>, _>>()?;
            context
                .stage_durable_with_account_service(
                    checkpoint,
                    crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
                    None,
                    0,
                    writes,
                )
                .map_err(|e| format!("prefix stage: {e:?}"))?;
            core.commit_staged_batch().await?;
            executor.state.streams.extend(ordinary.streams);
        }
        let state_generation = if prefix { 2 } else { 1 };
        let assignments = std::collections::BTreeMap::from([(
            PEER,
            events::BarrierAssignment {
                mutation_id: MUTATION,
                base_parts: 2,
                part_count: 4,
            },
        )]);
        let sequenced = events::sequence_copies(
            executor,
            &plan,
            &contents,
            state_generation,
            core.context_mut()?.entropy_mut(),
            &assignments,
            &backing,
        )
        .map_err(|e| format!("sequence: {e:?}"))?;
        let first = sequenced.copies.first().ok_or("companion first")?;
        let last = sequenced.copies.last().ok_or("companion final")?;
        let assignment = CrossProfileAssignment {
            mutation_id: MUTATION,
            part_count: 4,
            companion_scope: scope,
            companion: BarrierEndpoint::new(
                0,
                first.row.sequence,
                last.row.sequence,
                last.row.event_id,
            )?,
        };
        let mut writes = sequenced.writes;
        let mut outbound = Vec::new();
        for sequence in 0..2 {
            let event = ProjectedEvent::NetworkNotice {
                code: "BARRIER".to_owned(),
                text: "base part".to_owned(),
            };
            let header = EventHeader {
                network_id: NETWORK,
                target_server_id: PEER,
                projection_generation: 0,
                coordinator_state_generation: state_generation,
                delivery_sequence: sequence,
                event_id: agenc_relay_types::EventId::from_bytes(
                    [u8::try_from(sequence)? + 61; 16],
                ),
                event_kind: event.kind(),
                correlation: None,
                cross_profile: Some(agenc_relay_federation_wire::CrossProfilePart {
                    mutation_id: MUTATION,
                    part_index: u16::try_from(sequence)?,
                    part_count: 4,
                }),
            };
            let arm = crate::federation::codec::events::event_arm_object(&event)?;
            let bytes = header.build(&arm)?.encode_canonical()?.as_slice().to_vec();
            let object_id = federation_object_id(&bytes);
            let record = OutboxEventRecord {
                event_id: *header.event_id.as_bytes(),
                event_object_id: *object_id.as_bytes(),
                event_object: bytes.clone(),
                coordinator_state_generation: state_generation,
                acknowledged: false,
                completion_replay_key: None,
            };
            let value = PersistentRecordValue::new(
                TableId::EdgeOutbox,
                OUTBOX_EVENT_KIND,
                1,
                0,
                None,
                Vec::new(),
                record.encode()?,
            )?;
            writes.push(AccountServiceDurableWrite::put(
                TableId::EdgeOutbox,
                outbox_key(PEER, 0, sequence)?,
                value.encode()?,
            )?);
            outbound.push(OutboundEvent {
                target: PEER,
                projection_generation: 0,
                delivery_sequence: sequence,
                event_id: header.event_id,
                object_id,
                encoded: bytes,
                combined_barrier: None,
            });
        }
        let gate = barrier::attach(
            NETWORK,
            COORDINATOR,
            PEER,
            &assignment,
            state_generation,
            &mut outbound,
        )?;
        writes.push(barrier::write(&gate, state_generation)?);
        let state = coordinator.peers.get_mut(&PEER).ok_or("peer")?;
        state.incarnation = Some(INCARNATION);
        state.phase = PeerPhase::Ready;
        state.projection_generation = 0;
        state.outbox.reserved_next = 2;
        writes.push(coordinator.peer_row_at(PEER, state_generation, None)?);
        let mut fixture = Self {
            core,
            coordinator,
            gate,
        };
        fixture.commit(writes).await?;
        fixture.restart().await?;
        assert!(fixture.coordinator.loaded());
        Ok(fixture)
    }

    async fn commit(&mut self, writes: Vec<AccountServiceDurableWrite>) -> TestResult {
        let context = self.core.context_mut()?;
        let plan = context.domain().plan_account_service_checkpoint()?;
        let revision = plan.resulting_revision().get();
        let writes = writes
            .into_iter()
            .map(|w| w.at_revision(revision))
            .collect::<Result<Vec<_>, _>>()?;
        context
            .stage_durable_with_account_service(
                plan,
                crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
                None,
                0,
                writes,
            )
            .map_err(|e| format!("stage: {e:?}"))?;
        self.core.commit_staged_batch().await
    }

    async fn restart(&mut self) -> TestResult {
        let mut coordinator = standalone_coordinator(PEER);
        coordinator.install_companion_executor(
            CompanionCoordinator::new(
                *NETWORK.as_bytes(),
                COORDINATOR,
                COORDINATOR_NAME.to_owned(),
            ),
            self.core.identity.server_incarnation,
        )?;
        coordinator.startup(self.core.context_mut()?);
        for _ in 0..64 {
            if coordinator.loaded()
                || coordinator
                    .peers
                    .get(&PEER)
                    .is_some_and(|peer| peer.quarantined)
            {
                break;
            }
            let message = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.core.next_storage_read(),
            )
            .await??;
            coordinator.storage_read_completed(self.core.context_mut()?, message);
        }
        self.coordinator = coordinator;
        Ok(())
    }

    async fn stored_gate(&mut self) -> TestResult<Option<DeliveryBarrier>> {
        let row = DeliveryRecoveryRow::Barrier(self.gate.clone());
        let key = row.key()?;
        let read =
            self.core
                .context_mut()?
                .submit_storage_read(agenc_relay_storage::ReadPlan::exact(
                    TableId::E2eeState,
                    key.clone(),
                ))?;
        let message = self.core.next_storage_read().await?;
        assert_eq!(message.read_id, read);
        let result = message.result?;
        let Some(record) = result.records.first() else {
            return Ok(None);
        };
        let bytes = self.core.context_mut()?.open_storage_plaintext(
            TableId::E2eeState,
            &key,
            &record.sealed_record,
        )?;
        let value =
            PersistentRecordValue::decode(TableId::E2eeState, bytes.expose_for_storage_codec())?;
        let DeliveryRecoveryRow::Barrier(gate) =
            DeliveryRecoveryRow::decode_at(&key, value.body())?
        else {
            return Err("gate row".into());
        };
        Ok(Some(gate))
    }

    fn stage_base_ack(&mut self) -> TestResult {
        self.coordinator
            .acknowledge(
                self.core.context_mut()?,
                PEER,
                self.gate.base().last(),
                agenc_relay_types::EventId::from_bytes(self.gate.base().final_event_id()),
            )
            .map_err(|e| format!("base ACK: {e:?}"))?;
        Ok(())
    }

    fn stage_companion_ack(&mut self) -> TestResult {
        let (handle, _queue) = link_queue(1 << 20);
        let state = self.coordinator.peers.get_mut(&PEER).ok_or("peer")?;
        state.live = Some(LiveLink {
            link: LinkId::new(1),
            handle,
            incarnation: INCARNATION,
        });
        let endpoint = self.gate.companion();
        let context = self.core.context_mut()?;
        companion::admitted(
            &mut self.coordinator,
            context,
            LinkId::new(1),
            PEER,
            CompanionFrame::Resume {
                coordinator_server_id: *COORDINATOR.as_bytes(),
                server_incarnation: *INCARNATION.as_bytes(),
                delivery_generation: endpoint.generation(),
                last: None,
            },
        )
        .map_err(|e| format!("resume: {e:?}"))?;
        companion::admitted(
            &mut self.coordinator,
            context,
            LinkId::new(1),
            PEER,
            CompanionFrame::Ack(agenc_relay_e2ee::federation::frames::DeliveryPosition {
                server_id: *COORDINATOR.as_bytes(),
                delivery_generation: endpoint.generation(),
                delivery_sequence: endpoint.last(),
                event_id: endpoint.final_event_id(),
            }),
        )
        .map_err(|e| format!("companion ACK: {e:?}"))?;
        Ok(())
    }
}

#[tokio::test]
async fn both_ack_orders_persist_the_gate_until_the_second_receipt_and_restart() -> TestResult {
    for base_first in [true, false] {
        let mut fixture = Box::pin(Fixture::new()).await?;
        assert_eq!(fixture.coordinator.barriers.get(&PEER), Some(&fixture.gate));
        for first in [true, false] {
            let before = fixture.stored_gate().await?.ok_or("before gate")?;
            if base_first == first {
                fixture.stage_base_ack()?;
            } else {
                fixture.stage_companion_ack()?;
            }
            assert_eq!(fixture.stored_gate().await?, Some(before.clone()));
            assert_eq!(fixture.coordinator.barriers.get(&PEER), Some(&before));
            fixture.core.commit_staged_batch().await?;
            assert_eq!(
                fixture.coordinator.barriers.get(&PEER),
                Some(&before),
                "a storage write alone is not a publication receipt"
            );
            fixture
                .coordinator
                .batch_applied(fixture.core.context_mut()?);
            let stored = fixture.stored_gate().await?;
            assert_eq!(stored.is_some(), first);
            if let Some(gate) = stored {
                assert_eq!(gate.base_acked(), base_first);
                assert_eq!(gate.companion_acked(), !base_first);
            }
            fixture.restart().await?;
            assert!(
                fixture.coordinator.loaded(),
                "base_first={base_first}, first={first}"
            );
            assert_eq!(fixture.coordinator.barriers.contains_key(&PEER), first);
        }
    }
    Ok(())
}

#[tokio::test]
async fn a_partial_base_ack_cannot_commit_half_a_barrier() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    assert_eq!(
        fixture.coordinator.acknowledge(
            fixture.core.context_mut()?,
            PEER,
            0,
            agenc_relay_types::EventId::from_bytes([61; 16])
        ),
        Err(Violation::Acknowledgement)
    );
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.stored_gate().await?, Some(fixture.gate.clone()));
    Ok(())
}

#[tokio::test]
async fn a_missing_base_part_or_gate_refuses_the_complete_loader() -> TestResult {
    for remove_gate in [false, true] {
        let mut fixture = Box::pin(Fixture::new()).await?;
        let write = if remove_gate {
            barrier::delete(&fixture.gate)?
        } else {
            AccountServiceDurableWrite::delete(TableId::EdgeOutbox, outbox_key(PEER, 0, 0)?)?
        };
        fixture.commit(vec![write]).await?;
        fixture.restart().await?;
        assert!(!fixture.coordinator.loaded());
        assert!(
            fixture
                .coordinator
                .peers
                .get(&PEER)
                .is_some_and(|peer| peer.quarantined)
        );
    }
    Ok(())
}

#[tokio::test]
async fn either_refused_ack_leaves_both_durable_and_live_coverage_unchanged() -> TestResult {
    for base in [true, false] {
        let mut fixture = Box::pin(Fixture::new()).await?;
        if base {
            fixture.stage_base_ack()?;
        } else {
            fixture.stage_companion_ack()?;
        }
        fixture
            .core
            .state_mut()?
            .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
        fixture
            .coordinator
            .batch_rejected(fixture.core.context_mut()?);
        assert_eq!(fixture.stored_gate().await?, Some(fixture.gate.clone()));
        assert_eq!(fixture.coordinator.barriers.get(&PEER), Some(&fixture.gate));
        assert!(
            fixture
                .coordinator
                .peers
                .get(&PEER)
                .ok_or("peer")?
                .outbox
                .cursor
                .is_none()
        );
        fixture.restart().await?;
        assert!(fixture.coordinator.loaded());
    }
    Ok(())
}

#[tokio::test]
async fn lost_final_acknowledgements_resume_only_after_their_storage_receipts() -> TestResult {
    for base in [true, false] {
        let mut fixture = Box::pin(Fixture::new()).await?;
        let (handle, mut queue) = link_queue(1 << 20);
        fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
            link: LinkId::new(1),
            handle,
            incarnation: INCARNATION,
        });
        if base {
            snapshot::resume(
                &mut fixture.coordinator,
                fixture.core.context_mut()?,
                LinkId::new(1),
                PEER,
                0,
                agenc_relay_federation_wire::DeliveryCursor::At {
                    delivery_sequence: fixture.gate.base().last(),
                    event_id: agenc_relay_types::EventId::from_bytes(
                        fixture.gate.base().final_event_id(),
                    ),
                },
            )
            .map_err(|e| format!("base resume: {e:?}"))?;
        } else {
            companion::admitted(
                &mut fixture.coordinator,
                fixture.core.context_mut()?,
                LinkId::new(1),
                PEER,
                CompanionFrame::Resume {
                    coordinator_server_id: *COORDINATOR.as_bytes(),
                    server_incarnation: *INCARNATION.as_bytes(),
                    delivery_generation: fixture.gate.companion().generation(),
                    last: Some((
                        fixture.gate.companion().last(),
                        fixture.gate.companion().final_event_id(),
                    )),
                },
            )
            .map_err(|e| format!("companion resume: {e:?}"))?;
        }
        assert_eq!(fixture.stored_gate().await?, Some(fixture.gate.clone()));
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), queue.recv())
                .await
                .is_err()
        );
        fixture.core.commit_staged_batch().await?;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), queue.recv())
                .await
                .is_err()
        );
        fixture
            .coordinator
            .batch_applied(fixture.core.context_mut()?);
        let line = tokio::time::timeout(std::time::Duration::from_secs(2), queue.recv())
            .await?
            .ok_or("resume reply")?;
        assert!(
            line.as_str()
                .contains(if base { " FRESUME OK " } else { " ERESUME OK " }),
            "{}",
            line.as_str()
        );
        let gate = fixture.stored_gate().await?.ok_or("remaining half")?;
        assert_eq!(gate.base_acked(), base);
        assert_eq!(gate.companion_acked(), !base);
        fixture.restart().await?;
        assert!(fixture.coordinator.loaded());
    }
    Ok(())
}

#[tokio::test]
async fn contradictory_gate_fields_refuse_authenticated_reconstruction() -> TestResult {
    for defect in 0..8 {
        let mut fixture = Box::pin(Fixture::new()).await?;
        let gate = &fixture.gate;
        let mut fields =
            agenc_relay_storage::e2ee_records::delivery_recovery::DeliveryBarrierFields {
                scope: *gate.scope(),
                mutation_id: gate.mutation_id(),
                state_generation: gate.state_generation(),
                part_count: gate.part_count(),
                base: *gate.base(),
                companion: *gate.companion(),
                base_acked: false,
                companion_acked: false,
            };
        match defect {
            0 => fields.mutation_id = [99; 16],
            1 => fields.state_generation += 1,
            2 => fields.base = BarrierEndpoint::new(1, 0, 1, fields.base.final_event_id())?,
            3 => {
                fields.companion = BarrierEndpoint::new(1, 0, 1, fields.companion.final_event_id())?
            }
            4 => fields.base = BarrierEndpoint::new(0, 0, 1, [99; 16])?,
            5 => fields.companion = BarrierEndpoint::new(0, 0, 1, [99; 16])?,
            6 => fields.base_acked = true,
            7 => fields.companion_acked = true,
            _ => return Err("defect case".into()),
        }
        fixture
            .commit(vec![barrier::write(&DeliveryBarrier::new(fields)?, 1)?])
            .await?;
        fixture.restart().await?;
        assert!(!fixture.coordinator.loaded(), "defect {defect}");
    }
    Ok(())
}

#[tokio::test]
async fn restart_between_storage_commit_and_receipt_recovers_either_ack_order() -> TestResult {
    for base_first in [true, false] {
        let mut fixture = Box::pin(Fixture::new()).await?;
        for first in [true, false] {
            if base_first == first {
                fixture.stage_base_ack()?;
            } else {
                fixture.stage_companion_ack()?;
            }
            let before = fixture.coordinator.barriers.get(&PEER).cloned();
            fixture.core.commit_staged_batch().await?;
            assert_eq!(fixture.coordinator.barriers.get(&PEER), before.as_ref());
            // Drop the old coordinator without invoking its publication receipt.
            fixture.restart().await?;
            assert!(fixture.coordinator.loaded());
            assert_eq!(fixture.coordinator.barriers.contains_key(&PEER), first);
            if first {
                let gate = fixture
                    .coordinator
                    .barriers
                    .get(&PEER)
                    .ok_or("remaining gate")?;
                assert_eq!(gate.base_acked(), base_first);
                assert_eq!(gate.companion_acked(), !base_first);
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn missing_companion_bytes_and_changed_base_scope_refuse_restart() -> TestResult {
    for defect in 0..3 {
        let mut fixture = Box::pin(Fixture::new()).await?;
        let write = if defect == 0 {
            let row = fixture
                .coordinator
                .companion_exec
                .as_ref()
                .ok_or("executor")?
                .state
                .streams
                .get(&PEER)
                .ok_or("stream")?
                .rows
                .front()
                .ok_or("part")?;
            let id = agenc_relay_e2ee::ObjectId::compute(&row.event);
            AccountServiceDurableWrite::delete(
                TableId::E2eeObject,
                agenc_relay_storage::e2ee_records::object_key(id.as_bytes())?,
            )?
        } else {
            let peer = fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?;
            if defect == 1 {
                peer.client_resync_epoch = 1;
            } else {
                peer.outbox.snapshot_required = true;
            }
            fixture.coordinator.peer_row_at(PEER, 1, None)?
        };
        fixture.commit(vec![write]).await?;
        fixture.restart().await?;
        assert!(!fixture.coordinator.loaded(), "defect {defect}");
    }
    Ok(())
}

#[tokio::test]
async fn neither_profile_can_replace_an_open_barrier_with_a_new_snapshot() -> TestResult {
    let mut fixture = Box::pin(Fixture::new()).await?;
    let (handle, _queue) = link_queue(1 << 20);
    fixture.coordinator.peers.get_mut(&PEER).ok_or("peer")?.live = Some(LiveLink {
        link: LinkId::new(1),
        handle,
        incarnation: INCARNATION,
    });
    assert_eq!(
        snapshot::resume(
            &mut fixture.coordinator,
            fixture.core.context_mut()?,
            LinkId::new(1),
            PEER,
            1,
            agenc_relay_federation_wire::DeliveryCursor::Empty
        ),
        Err(Violation::Acknowledgement)
    );
    fixture
        .coordinator
        .peers
        .get_mut(&PEER)
        .ok_or("peer")?
        .client_resync_epoch = 1;
    assert!(
        companion::admitted(
            &mut fixture.coordinator,
            fixture.core.context_mut()?,
            LinkId::new(1),
            PEER,
            CompanionFrame::Resume {
                coordinator_server_id: *COORDINATOR.as_bytes(),
                server_incarnation: *INCARNATION.as_bytes(),
                delivery_generation: 0,
                last: None
            }
        )
        .is_err()
    );
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.stored_gate().await?, Some(fixture.gate.clone()));
    Ok(())
}
