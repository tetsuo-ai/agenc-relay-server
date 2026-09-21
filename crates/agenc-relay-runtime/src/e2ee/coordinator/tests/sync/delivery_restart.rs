//! Companion restart preserves retained delivery under an unchanged base scope.
#![forbid(unsafe_code)]

mod acknowledged_barriers;
mod combined_owner;
mod pending_publication;
mod pending_recovery;
mod replay_job;
mod replay_startup;
mod retention;
mod scoped_outbox;

use std::collections::BTreeMap;

use agenc_relay_domain::e2ee::projection::{EventKind, EventPlan, PlannedEvent};
use agenc_relay_storage::{PersistentRecordValue, ReadPlan, StoredKey, TableId};

use super::super::super::CompanionCoordinator;
use super::super::super::events::{self, CopyToSend, EventContent};
use super::*;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::fanout::FanoutRequest;
use crate::test_support::StateCoreFixture;

struct RestartFixture {
    storage: StateCoreFixture,
    coordinator: CompanionCoordinator,
    host: FakeHost,
    entropy: Counter,
    keys: Vec<(TableId, StoredKey)>,
    copies: Vec<CopyToSend>,
}

impl RestartFixture {
    /// The construction future is boxed so every test's own future stays
    /// small.
    async fn new() -> TestResult<Self> {
        Box::pin(Self::build()).await
    }

    async fn build() -> TestResult<Self> {
        let storage = StateCoreFixture::new(vec![44; 65_536])?;
        let mut coordinator = CompanionCoordinator::new(
            *storage.identity.network_id.as_bytes(),
            storage.identity.server_id,
            SERVER_NAME.into(),
        );
        coordinator.configure_delivery_identity(
            storage.identity.server_incarnation,
            storage.identity.recovery_epoch,
        )?;
        let mut fixture = Self {
            storage,
            coordinator,
            host: FakeHost::default(),
            entropy: Counter(60),
            keys: Vec::new(),
            copies: Vec::new(),
        };
        fixture.activate().await?;
        fixture.append().await?;
        Ok(fixture)
    }

    fn frame(&mut self, frame: CompanionFrame) -> TestResult<Vec<Action>> {
        Ok(self.coordinator.on_frame(
            LinkId::new(1),
            home(),
            frame,
            NOW_MILLIS,
            &self.host,
            &mut self.entropy,
        )?)
    }

    async fn commit(&mut self, writes: Vec<AccountServiceDurableWrite>) -> TestResult {
        for write in &writes {
            let AccountServiceDurableWrite::Put { table, key, .. } = write else {
                return Err("fixture seed must only put validated rows".into());
            };
            if !self.keys.contains(&(*table, key.clone())) {
                self.keys.push((*table, key.clone()));
            }
        }
        let context = self.storage.context_mut()?;
        let plan = context.domain().plan_account_service_checkpoint()?;
        let revision = plan.resulting_revision().get();
        // The owner rows ride every batch, as the federation coordinator stages them.
        let mut writes = writes;
        let owners = self
            .coordinator
            .stage_owners(&mut writes, NOW_MILLIS / 1_000, false, revision)
            .map_err(|code| format!("owner staging: {code:?}"))?;
        let writes = writes
            .into_iter()
            .map(|write| write.at_revision(revision))
            .collect::<Result<Vec<_>, _>>()?;
        let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
        context
            .stage_durable_with_account_service(plan, fanout, None, 0, writes)
            .map_err(|error| format!("fixture stage: {error:?}"))?;
        Box::pin(self.storage.commit_staged_batch()).await?;
        owners.apply(&mut self.coordinator.state);
        Ok(())
    }

    async fn activate(&mut self) -> TestResult {
        let actions = self.frame(CompanionFrame::Resume {
            coordinator_server_id: *self.storage.identity.server_id.as_bytes(),
            server_incarnation: INCARNATION,
            delivery_generation: 0,
            last: None,
        })?;
        let (cut, _, _) = begin_cut(&self.publish_cut(actions).await?)?;
        let actions = self.frame(CompanionFrame::StateCut {
            active: false,
            server_id: *self.storage.identity.server_id.as_bytes(),
            snapshot_token: cut.token,
            state_generation: cut.state_generation,
            delivery_generation: cut.delivery_generation,
            snapshot_digest: cut.digest,
        })?;
        let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
            return Err("activation must stage durable state".into());
        };
        self.coordinator.set_pending(work);
        self.commit(writes).await?;
        assert!(matches!(
            self.coordinator.batch_applied(Some(0))?,
            Some(Committed::Lines(_))
        ));
        let actions = self.frame(CompanionFrame::OriginReset {
            coordinator_server_id: *self.storage.identity.server_id.as_bytes(),
            server_incarnation: INCARNATION,
        })?;
        assert!(matches!(
            frames(&actions)?.as_slice(),
            [CompanionFrame::OriginReady { .. }]
        ));
        assert_eq!(self.host.resync_epoch, 0);
        Ok(())
    }

    async fn append(&mut self) -> TestResult {
        let planned: Vec<_> = [5, 6]
            .into_iter()
            .map(|seed| PlannedEvent {
                kind: EventKind::RouteStateHidden,
                conversation_id: Some([seed; 32]),
                target: home(),
                payload_object_id: None,
                completion: false,
                route_sequence: 0,
                bytes: 1024,
            })
            .collect();
        let plan = EventPlan::order(planned)?;
        let contents: Vec<_> = plan
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
            .collect();
        let sequenced = events::sequence_copies(
            &self.coordinator,
            &plan,
            &contents,
            41,
            &mut self.entropy,
            &BTreeMap::new(),
            &self.storage.context_mut()?.backing_reservations(),
        )
        .map_err(|error| format!("sequence: {error:?}"))?;
        self.commit(sequenced.writes).await?;
        self.coordinator.state.streams.extend(sequenced.streams);
        self.copies = sequenced.copies;
        assert_eq!(self.copies.len(), 2);
        Ok(())
    }

    async fn restart(&mut self) -> TestResult {
        let mut restored = CompanionCoordinator::new(
            *self.storage.identity.network_id.as_bytes(),
            self.storage.identity.server_id,
            SERVER_NAME.into(),
        );
        restored.configure_delivery_identity(
            self.storage.identity.server_incarnation,
            self.storage.identity.recovery_epoch,
        )?;
        for (table, key) in &self.keys {
            let read_id = self
                .storage
                .context_mut()?
                .submit_storage_read(ReadPlan::exact(*table, key.clone()))?;
            let message = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.storage.next_storage_read(),
            )
            .await??;
            assert_eq!(message.read_id, read_id);
            let result = message.result?;
            assert_eq!(result.records.len(), 1);
            for record in result.records {
                let plaintext = self.storage.context_mut()?.open_storage_plaintext(
                    *table,
                    &record.key,
                    &record.sealed_record,
                )?;
                let value =
                    PersistentRecordValue::decode(*table, plaintext.expose_for_storage_codec())?;
                restored.admit_restored(*table, &record.key, &value);
            }
        }
        replay_startup::recover(self, &mut restored).await?;
        restored.finish_restore_with_backing(self.storage.context_mut()?.backing_reservations())?;
        self.coordinator = restored;
        Ok(())
    }
}

#[tokio::test]
async fn intact_companion_restart_replays_retained_bytes_without_a_paired_snapshot() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let incarnation = fixture.storage.identity.server_incarnation;
    let epoch = fixture.storage.identity.recovery_epoch;
    let expected: Vec<_> = fixture
        .copies
        .iter()
        .map(|copy| events::render_copy(SERVER_NAME, copy))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| format!("render: {error:?}"))?
        .into_iter()
        .flatten()
        .map(|line| line.as_str().to_owned())
        .collect();
    assert!(!expected.is_empty());
    fixture.restart().await?;
    assert_eq!(fixture.storage.identity.server_incarnation, incarnation);
    assert_eq!(fixture.storage.identity.recovery_epoch, epoch);
    assert_eq!(fixture.host.incarnation, Some(INCARNATION));
    assert_eq!(fixture.host.resync_epoch, 0);
    let actions = fixture.frame(CompanionFrame::Resume {
        coordinator_server_id: *fixture.storage.identity.server_id.as_bytes(),
        server_incarnation: INCARNATION,
        delivery_generation: 0,
        last: None,
    })?;
    let actual = frames(&actions)?;
    assert!(
        matches!(
            actual.first(),
            Some(CompanionFrame::ResumeOk {
                delivery_generation: 0,
                next_delivery_sequence: 0,
                ..
            })
        ),
        "intact same-scope restart must resume retained events, received {actual:?}"
    );
    let lines: Vec<_> = actions
        .iter()
        .flat_map(|action| match action {
            Action::Send(lines) => lines.iter().map(|line| line.as_str().to_owned()).collect(),
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(lines.get(1..), Some(expected.as_slice()));
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .map(|stream| stream.generation),
        Some(0)
    );
    Ok(())
}

#[tokio::test]
async fn companion_acknowledgement_keeps_the_authoritative_cursor_behind_its_receipt() -> TestResult
{
    let mut fixture = RestartFixture::new().await?;
    let first = fixture.copies.first().ok_or("first durable event")?;
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: first.generation,
        delivery_sequence: first.row.sequence,
        event_id: first.row.event_id,
    };
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .and_then(|stream| stream.acked),
        None
    );
    let actions = fixture.frame(CompanionFrame::Ack(position))?;
    assert!(
        matches!(actions.as_slice(), [Action::Stage { .. }]),
        "EACK must stage an exact durable cursor transition before its acceptance"
    );
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .and_then(|stream| stream.acked),
        None,
        "an uncommitted EACK cannot authorize later delivery or discard replay ownership"
    );
    assert!(frames(&actions)?.is_empty());
    Ok(())
}

#[tokio::test]
async fn committed_companion_ack_restarts_with_the_exact_cursor_and_replay_flags() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let first = fixture.copies.first().ok_or("first durable event")?;
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: first.generation,
        delivery_sequence: first.row.sequence,
        event_id: first.row.event_id,
    };
    let before = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .and_then(|stream| stream.owner.clone())
        .ok_or("exact pre-ACK owner")?;
    let actions = fixture.frame(CompanionFrame::Ack(position))?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("EACK must stage its cursor and row flags".into());
    };
    let expected_cursor =
        agenc_relay_storage::e2ee_records::delivery_recovery::DeliveryCursor::new(
            position.delivery_generation,
            before.cursor().next_sequence(),
            agenc_relay_storage::e2ee_records::delivery_recovery::LastAcknowledged::At {
                sequence: position.delivery_sequence,
                event_id: position.event_id,
            },
        )?;
    let expected = agenc_relay_storage::e2ee_records::delivery_recovery::DeliveryOwner::new(
        *before.scope(),
        expected_cursor,
        *before.cut(),
        before.phase(),
    )?;
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .and_then(|stream| stream.owner.as_ref()),
        Some(&before)
    );
    assert!(matches!(fixture.coordinator.batch_applied(Some(0))?,
        Some(Committed::Acknowledged(peer)) if peer == home()));
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .and_then(|stream| stream.owner.as_ref()),
        Some(&expected)
    );
    fixture.restart().await?;
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("restored stream")?;
    assert_eq!(stream.owner.as_ref(), Some(&expected));
    assert_eq!(
        stream.acked,
        Some((position.delivery_sequence, position.event_id))
    );
    assert_eq!(
        stream
            .rows
            .iter()
            .map(|row| row.acked())
            .collect::<Vec<_>>(),
        [true, false]
    );
    let actions = fixture.frame(CompanionFrame::Resume {
        coordinator_server_id: position.server_id,
        server_incarnation: INCARNATION,
        delivery_generation: position.delivery_generation,
        last: Some((position.delivery_sequence, position.event_id)),
    })?;
    assert!(matches!(
        frames(&actions)?.first(),
        Some(CompanionFrame::ResumeOk {
            next_delivery_sequence: 1,
            ..
        })
    ));
    assert!(fixture.frame(CompanionFrame::Ack(position))?.is_empty());
    Ok(())
}

fn ready_frame(fixture: &RestartFixture) -> TestResult<CompanionFrame> {
    let cut = fixture
        .coordinator
        .peer_sync(home())
        .and_then(|sync| sync.ready_cut)
        .ok_or("durable Ready cut")?;
    Ok(CompanionFrame::StateCut {
        active: false,
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        snapshot_token: cut.token,
        state_generation: cut.state_generation,
        delivery_generation: cut.delivery_generation,
        snapshot_digest: cut.digest,
    })
}

#[tokio::test]
async fn recorded_ready_retries_after_restart_without_reopening_the_pending_deadline() -> TestResult
{
    let mut fixture = RestartFixture::new().await?;
    let frame = ready_frame(&fixture)?;
    fixture.restart().await?;
    let actions = fixture.coordinator.on_frame(
        LinkId::new(2),
        home(),
        frame,
        NOW_MILLIS + super::super::super::sync::SNAPSHOT_TOKEN_MILLIS + 1,
        &fixture.host,
        &mut fixture.entropy,
    )?;
    assert!(matches!(
        frames(&actions)?.first(),
        Some(CompanionFrame::StateCut { active: true, .. })
    ));
    assert!(fixture.coordinator.delivering(home()));
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .map(|stream| stream.rows.len()),
        Some(2)
    );
    Ok(())
}

#[tokio::test]
async fn a_recorded_ready_refuses_a_changed_target_incarnation_or_paired_base_epoch() -> TestResult
{
    for change_incarnation in [true, false] {
        let mut fixture = RestartFixture::new().await?;
        let frame = ready_frame(&fixture)?;
        fixture.restart().await?;
        if change_incarnation {
            fixture.host.incarnation = Some([99; 16]);
        } else {
            fixture.host.resync_epoch = 1;
        }
        let result = fixture.coordinator.on_frame(
            LinkId::new(2),
            home(),
            frame,
            NOW_MILLIS,
            &fixture.host,
            &mut fixture.entropy,
        );
        assert!(matches!(result, Err(CompanionFault::Protocol)));
        assert!(!fixture.coordinator.delivering(home()));
        assert_eq!(
            fixture
                .coordinator
                .peer_sync(home())
                .map(|sync| sync.resync_epoch),
            Some(0)
        );
    }
    Ok(())
}

fn stage_ack_for_rejection(
    fixture: &mut RestartFixture,
    writes: Vec<AccountServiceDurableWrite>,
) -> TestResult {
    let context = fixture.storage.context_mut()?;
    let plan = context.domain().plan_account_service_checkpoint()?;
    let revision = plan.resulting_revision().get();
    let writes = writes
        .into_iter()
        .map(|write| write.at_revision(revision))
        .collect::<Result<Vec<_>, _>>()?;
    let fanout = FanoutRequest::new(Vec::new(), Vec::new())?;
    context
        .stage_durable_with_account_service(plan, fanout, None, 0, writes)
        .map_err(|error| format!("ACK fixture stage: {error:?}"))?;
    Ok(())
}

#[tokio::test]
async fn a_rejected_ack_preserves_the_old_durable_cursor_and_replay_class() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let first = fixture.copies.first().ok_or("first event")?;
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: first.generation,
        delivery_sequence: first.row.sequence,
        event_id: first.row.event_id,
    };
    let actions = fixture.frame(CompanionFrame::Ack(position))?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("ACK stage".into());
    };
    fixture.coordinator.set_pending(work);
    stage_ack_for_rejection(&mut fixture, writes)?;
    let before = fixture
        .storage
        .context_mut()?
        .head()
        .storage_commit_sequence;
    fixture
        .storage
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    fixture.coordinator.batch_rejected();
    assert_eq!(
        fixture
            .storage
            .context_mut()?
            .head()
            .storage_commit_sequence,
        before
    );
    fixture.restart().await?;
    let stream = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .ok_or("restored stream")?;
    assert_eq!(stream.acked, None);
    assert!(stream.rows.iter().all(|row| !row.acked()));
    assert_eq!(stream.rows.len(), 2);
    Ok(())
}

#[tokio::test]
async fn wrong_event_generation_id_and_partial_barrier_ack_do_not_stage_a_cursor() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let first = fixture.copies.first().ok_or("first event")?;
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: first.generation,
        delivery_sequence: first.row.sequence,
        event_id: first.row.event_id,
    };
    for wrong in [
        DeliveryPosition {
            event_id: [77; 16],
            ..position
        },
        DeliveryPosition {
            delivery_generation: 1,
            ..position
        },
    ] {
        assert!(fixture.frame(CompanionFrame::Ack(wrong)).is_err());
    }
    fixture
        .coordinator
        .state
        .streams
        .get_mut(&home())
        .ok_or("stream")?
        .barrier = Some((0, 1));
    assert!(fixture.frame(CompanionFrame::Ack(position)).is_err());
    assert!(!fixture.coordinator.has_pending());
    assert_eq!(
        fixture
            .coordinator
            .state
            .streams
            .get(&home())
            .and_then(|stream| stream.acked),
        None
    );
    Ok(())
}

#[tokio::test]
async fn current_profile_exposes_the_lost_ack_cursor_mismatch_after_a_real_restart() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let last = fixture.copies.last().ok_or("last event")?;
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: last.generation,
        delivery_sequence: last.row.sequence,
        event_id: last.row.event_id,
    };
    fixture.restart().await?;
    let result = fixture.frame(CompanionFrame::Resume {
        coordinator_server_id: position.server_id,
        server_incarnation: INCARNATION,
        delivery_generation: position.delivery_generation,
        last: Some((position.delivery_sequence, position.event_id)),
    });
    assert!(
        result.is_err(),
        "this is evidence of the current profile's unresolved lost-EACK boundary"
    );
    let stream = fixture
        .coordinator
        .state
        .streams
        .get_mut(&home())
        .ok_or("stream")?;
    assert_eq!(stream.acked, None);
    assert_eq!(
        stream.acknowledge(position.delivery_sequence, position.event_id, agenc_relay_storage::e2ee_records::delivery_recovery::Acknowledgement::AcknowledgedTimeUnknown),
        Err(CompanionFault::Protocol)
    );
    assert_eq!(stream.rows.len(), 2);
    Ok(())
}

async fn activate_second_target(fixture: &mut RestartFixture, target: ServerId) -> TestResult {
    let actions = fixture.coordinator.on_frame(
        LinkId::new(2),
        target,
        CompanionFrame::Resume {
            coordinator_server_id: *fixture.storage.identity.server_id.as_bytes(),
            server_incarnation: INCARNATION,
            delivery_generation: 0,
            last: None,
        },
        NOW_MILLIS,
        &fixture.host,
        &mut fixture.entropy,
    )?;
    let (cut, _, _) = begin_cut(&fixture.publish_cut(actions).await?)?;
    let actions = fixture.coordinator.on_frame(
        LinkId::new(2),
        target,
        CompanionFrame::StateCut {
            active: false,
            server_id: *fixture.storage.identity.server_id.as_bytes(),
            snapshot_token: cut.token,
            state_generation: cut.state_generation,
            delivery_generation: cut.delivery_generation,
            snapshot_digest: cut.digest,
        },
        NOW_MILLIS,
        &fixture.host,
        &mut fixture.entropy,
    )?;
    let Some(Action::Stage { writes, work }) = actions.into_iter().next() else {
        return Err("READY stage".into());
    };
    fixture.coordinator.set_pending(work);
    fixture.commit(writes).await?;
    assert!(matches!(
        fixture.coordinator.batch_applied(Some(0))?,
        Some(Committed::Lines(_))
    ));
    Ok(())
}

fn route_payload(network_id: [u8; 32]) -> TestResult<Vec<u8>> {
    use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
    use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
    let state = ArcFederationRouteState {
        profile_version: 1,
        network_id,
        state_generation: 41,
        conversation_id: [9; 32],
        conversation_kind: ArcConversationKind::Channel,
        route_binding: [11; 32],
        semantic_route_lock_id: [12; 32],
        channel_instance_id: Opaque::new(vec![13; 16])?,
        canonical_channel_name_hash: [14; 32],
        direct_account_a: Opaque::new(Vec::new())?,
        direct_account_b: Opaque::new(Vec::new())?,
        binding_id: [15; 32],
        finalized_epoch: 1,
        accepted_state_id: [16; 32],
        sequencer_record_head_sequence: 0,
        sequencer_record_head_id: [17; 32],
        state: ArcRouteStateKind::ActiveRoute,
    };
    wire(ArcWireObjectKind::FederationState, &state)
}

fn shared_payload_plan(
    targets: [ServerId; 2],
    bytes: Vec<u8>,
) -> TestResult<(EventPlan, Vec<EventContent>)> {
    let id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
    let planned = targets
        .into_iter()
        .map(|target| PlannedEvent {
            kind: EventKind::RouteStateChanged,
            conversation_id: Some([9; 32]),
            target,
            payload_object_id: Some(id),
            completion: false,
            route_sequence: 0,
            bytes: 1024,
        })
        .collect();
    let plan = EventPlan::order(planned)?;
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
            payload: Some(bytes.clone()),
        })
        .collect();
    Ok((plan, contents))
}

#[tokio::test]
async fn shared_event_payload_and_response_storage_puts_are_exactly_deduplicated() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let second = ServerId::from_bytes([30; 16]);
    activate_second_target(&mut fixture, second).await?;
    let bytes = route_payload(*fixture.storage.identity.network_id.as_bytes())?;
    let object = agenc_relay_storage::e2ee_records::ObjectRow::new(bytes.clone())?;
    let key = object.key()?;
    let (plan, contents) = shared_payload_plan([home(), second], bytes.clone())?;
    let mut sequenced = events::sequence_copies(
        &fixture.coordinator,
        &plan,
        &contents,
        41,
        &mut fixture.entropy,
        &BTreeMap::new(),
        &fixture.storage.context_mut()?.backing_reservations(),
    )
    .map_err(|error| format!("sequence: {error:?}"))?;
    super::super::super::delivery_owner::append_object(&mut sequenced.writes, &bytes)
        .map_err(|error| format!("response object: {error:?}"))?;
    let count = sequenced.writes.iter().filter(|write| matches!(write,
        AccountServiceDurableWrite::Put { table: TableId::E2eeObject, key: stored, .. } if *stored == key)).count();
    assert_eq!(
        count, 1,
        "one immutable payload can be referenced by several events and a response"
    );
    fixture.commit(sequenced.writes).await?;
    fixture.coordinator.state.streams.extend(sequenced.streams);
    fixture.restart().await?;
    for target in [home(), second] {
        let row = fixture
            .coordinator
            .state
            .streams
            .get(&target)
            .and_then(|stream| stream.rows.back())
            .ok_or("retained copy")?;
        assert_eq!(
            row.payload.as_ref().map(|(_, bytes)| &**bytes),
            Some(bytes.as_slice())
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_acknowledgement_behind_another_pending_batch_is_a_ceiling() -> TestResult {
    let mut fixture = RestartFixture::new().await?;
    let first = fixture.copies.first().ok_or("first durable event")?;
    let position = DeliveryPosition {
        server_id: *fixture.storage.identity.server_id.as_bytes(),
        delivery_generation: first.generation,
        delivery_sequence: first.row.sequence,
        event_id: first.row.event_id,
    };
    let owner = fixture
        .coordinator
        .state
        .streams
        .get(&home())
        .and_then(|stream| stream.owner.clone())
        .ok_or("stream owner")?;
    fixture.coordinator.set_pending(PendingWork::Activate {
        peer: home(),
        link: LinkId::new(1),
        owner,
    });
    let mut probe = |frame: CompanionFrame| {
        fixture
            .coordinator
            .on_frame(
                LinkId::new(1),
                home(),
                frame,
                NOW_MILLIS,
                &fixture.host,
                &mut fixture.entropy,
            )
            .err()
    };
    assert_eq!(
        probe(CompanionFrame::Ack(position)),
        Some(CompanionFault::Ceiling)
    );
    Ok(())
}
