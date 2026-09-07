#![forbid(unsafe_code)]

//! Ordinary events queued behind storage must retain their publication boundary.

mod barrier;
mod join;
mod projection;
mod replacement;
mod resources;

use agenc_ircd_client_wire::CapabilityState;
use agenc_ircd_domain::federation::{DeliveredMessageRecord, DeliveryTarget, ProjectionRecord};
use agenc_ircd_types::MessageId;

use super::*;
use crate::federation::link::LinkHandle;
use crate::sync::Arc;
use crate::test_support::{bind_live_session, seed_session};

struct PrefixFixture {
    core: StateCoreFixture,
    edge: EdgeFederation,
    sink: Arc<FrameSink>,
    handle: LinkHandle,
    queue: LinkQueue,
    recipient: UserId,
}

impl PrefixFixture {
    fn new() -> TestResult<Self> {
        let mut core = StateCoreFixture::new(entropy_script())?;
        let context = core.context_mut()?;
        let identity = seed_session(context, 1, "recipient", None)?;
        let sink = bind_live_session(context, 1, identity, CapabilityState::default(), true)?;
        let mut edge = resync_edge();
        edge.replica.install(
            1,
            vec![ProjectionRecord::Session(session_record(
                identity.session_id,
                identity.user_id,
                "recipient",
                1,
                1,
            )?)],
        )?;
        let (handle, queue) = link_queue(1 << 20);
        edge.live = Some(LiveLink {
            link: LinkId::new(1),
            handle: handle.clone(),
            coordinator_epoch: COORDINATOR_EPOCH,
            coordinator_incarnation: HUB_INCARNATION,
        });
        edge.phase = Phase::Active;
        Ok(Self {
            core,
            edge,
            sink,
            handle,
            queue,
            recipient: identity.user_id,
        })
    }

    fn receive(&mut self, sequence: u64) -> TestResult {
        let (descriptor, object) = ordinary_message(self.recipient, sequence)?;
        let outputs = events::receive(
            &mut self.edge,
            self.core.context_mut()?,
            descriptor,
            &object,
        )
        .map_err(|error| format!("ordinary event refused: {error:?}"))?;
        assert!(outputs.is_empty());
        Ok(())
    }

    fn head(&mut self) -> TestResult<u64> {
        Ok(self.core.context_mut()?.head().storage_commit_sequence)
    }

    fn settle_edge(&mut self) -> TestResult {
        assert!(self.edge.batch_applied(self.core.context_mut()?).is_empty());
        Ok(())
    }
}

fn event_identity(sequence: u64) -> TestResult<EventId> {
    if let Some(byte) = u8::try_from(sequence)
        .ok()
        .and_then(|byte| byte.checked_add(40))
    {
        return Ok(EventId::from_bytes([byte; 16]));
    }
    let mut bytes = [255; 16];
    bytes
        .get_mut(8..)
        .ok_or("event identity")?
        .copy_from_slice(&sequence.to_be_bytes());
    Ok(EventId::from_bytes(bytes))
}

fn ordinary_message(
    recipient: UserId,
    sequence: u64,
) -> TestResult<(agenc_ircd_federation_wire::EventDescriptor, AssembledObject)> {
    let projected = ProjectedEvent::MessageDelivered(DeliveredMessageRecord {
        message_id: MessageId::from_bytes(*event_identity(sequence)?.as_bytes()),
        kind: agenc_ircd_domain::MessageKind::Privmsg,
        target: DeliveryTarget::User(recipient),
        sender: source(UserId::from_bytes([19; 16]), "sender", 2)?,
        target_revision: Revision::new(1)?,
        channel_event_sequence: 0,
        received_unix_milliseconds: 1_000,
        tags: Vec::new(),
        body: format!("ordinary prefix event {sequence}"),
    });
    let header = EventHeader {
        network_id: NETWORK,
        target_server_id: EDGE,
        projection_generation: 1,
        coordinator_state_generation: sequence.checked_add(10).ok_or("generation overflow")?,
        delivery_sequence: sequence,
        event_id: event_identity(sequence)?,
        event_kind: projected.kind(),
        correlation: None,
        cross_profile: None,
    };
    let bytes = header
        .build(&event_arm_object(&projected)?)?
        .encode_canonical()?;
    let descriptor = agenc_ircd_federation_wire::EventDescriptor {
        target_server_id: EDGE,
        delivery_sequence: sequence,
        event_id: header.event_id,
        object_id: federation_object_id(bytes.as_slice()),
    };
    let object = resync_assembled(bytes.as_slice(), |fragment| FederationFrame::Event {
        descriptor,
        fragment,
    })?;
    Ok((descriptor, object))
}

fn assert_outputs(sink: &FrameSink, expected: usize) {
    let lines = sink.lines();
    assert_eq!(
        lines.len(),
        expected,
        "one committed prefix must publish every selected event exactly once"
    );
    for (sequence, line) in lines.iter().enumerate() {
        assert!(line.starts_with(":sender!"));
        assert!(line.ends_with(&format!(
            " PRIVMSG recipient :ordinary prefix event {sequence}"
        )));
    }
}

async fn assert_next_ack(queue: &mut LinkQueue, sequence: u64) -> TestResult {
    let line = tokio::time::timeout(std::time::Duration::from_secs(1), queue.recv())
        .await?
        .ok_or("expected a committed FACK")?;
    let frame = parse_frame(line.as_str().trim_end_matches("\r\n"), EDGE_NAME)
        .map_err(|error| format!("acknowledgement grammar: {error:?}"))?;
    let FederationFrame::Ack {
        coordinator_server_id,
        delivery_sequence,
        event_id,
    } = frame
    else {
        return Err("expected an ordinary per-event FACK".into());
    };
    assert_eq!(coordinator_server_id, COORDINATOR);
    assert_eq!(delivery_sequence, sequence, "FACK order changed");
    assert_eq!(event_id, event_identity(sequence)?);
    Ok(())
}

#[tokio::test]
async fn queued_ordinary_events_share_one_following_storage_receipt() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    let initial_head = fixture.head()?;
    fixture.receive(0)?;
    assert!(fixture.edge.commit.is_some());
    fixture.receive(1)?;
    fixture.receive(2)?;
    assert_outputs(&fixture.sink, 0);
    assert_eq!(
        fixture.handle.queued_bytes(),
        0,
        "FACK escaped before storage"
    );
    fixture.core.commit_staged_batch().await?;
    let first_head = initial_head.checked_add(1).ok_or("head overflow")?;
    assert_eq!(fixture.head()?, first_head);
    assert_outputs(&fixture.sink, 1);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert_no_ack(&mut fixture.queue).await?;
    assert_outputs(&fixture.sink, 1);
    assert!(fixture.edge.commit.is_some());
    fixture.core.commit_staged_batch().await?;
    assert_eq!(
        fixture.head()?,
        first_head.checked_add(1).ok_or("head overflow")?
    );
    assert_no_ack(&mut fixture.queue).await?;
    assert_outputs(&fixture.sink, 3);
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    assert_eq!(fixture.handle.queued_bytes(), 0, "duplicate or extra FACK");
    assert_eq!(fixture.edge.cursor, Some((2, event_identity(2)?)));
    assert_eq!(fixture.edge.counters.events_applied, 3);
    assert!(fixture.edge.commit.is_none());
    assert!(fixture.edge.queued_events.is_empty());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    Ok(())
}

async fn assert_no_ack(queue: &mut LinkQueue) -> TestResult {
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(2), queue.recv())
            .await
            .is_err(),
        "an acknowledgment became visible before its receipt"
    );
    Ok(())
}

async fn queued_prefix() -> TestResult<PrefixFixture> {
    let mut fixture = PrefixFixture::new()?;
    fixture.receive(0)?;
    fixture.receive(1)?;
    fixture.receive(2)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::OrdinaryBatch(_))
    ));
    Ok(fixture)
}

#[tokio::test]
async fn rejected_ordinary_prefix_publishes_nothing_and_replays_exactly() -> TestResult {
    let mut fixture = queued_prefix().await?;
    let before = fixture
        .edge
        .event_before
        .as_ref()
        .ok_or("preimage")?
        .replica
        .clone();
    let head = fixture.head()?;
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(
            agenc_ircd_storage::StorageError::FilesystemRejected,
        )?;
    fixture.edge.batch_rejected_with_error(
        fixture.core.context_mut()?,
        agenc_ircd_storage::StorageError::FilesystemRejected,
    );
    assert_outputs(&fixture.sink, 1);
    assert_eq!(fixture.head()?, head);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert!(fixture.edge.replica == before);
    assert_eq!(fixture.edge.cursor, Some((0, event_identity(0)?)));
    assert!(fixture.edge.event_before.is_none());
    assert!(fixture.edge.commit.is_none());
    let (handle, queue) = link_queue(1 << 20);
    fixture.handle = handle.clone();
    fixture.queue = queue;
    fixture.edge.live = Some(LiveLink {
        link: LinkId::new(2),
        handle,
        coordinator_epoch: COORDINATOR_EPOCH,
        coordinator_incarnation: HUB_INCARNATION,
    });
    fixture.edge.phase = Phase::Active;
    fixture.receive(1)?;
    fixture.receive(2)?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    assert_outputs(&fixture.sink, 3);
    Ok(())
}

#[tokio::test]
async fn an_older_callback_cannot_settle_the_new_ordinary_prefix() -> TestResult {
    let mut fixture = queued_prefix().await?;
    fixture.settle_edge()?;
    assert_no_ack(&mut fixture.queue).await?;
    assert_outputs(&fixture.sink, 1);
    assert_eq!(fixture.edge.cursor, Some((0, event_identity(0)?)));
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::OrdinaryBatch(_))
    ));
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 1).await?;
    assert_next_ack(&mut fixture.queue, 2).await?;
    Ok(())
}

#[tokio::test]
async fn a_lost_link_releases_reserved_acks_before_the_ordinary_receipt() -> TestResult {
    let mut fixture = queued_prefix().await?;
    assert!(fixture.handle.queued_bytes() > 0);
    fixture
        .edge
        .link_closed(fixture.core.context_mut()?, LinkId::new(1));
    assert_eq!(fixture.handle.queued_bytes(), 0);
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_outputs(&fixture.sink, 3);
    assert_eq!(fixture.edge.cursor, Some((2, event_identity(2)?)));
    assert_no_ack(&mut fixture.queue).await?;
    Ok(())
}

#[tokio::test]
async fn a_full_ordinary_queue_commits_256_events_with_ordered_per_event_acks() -> TestResult {
    let mut fixture = PrefixFixture::new()?;
    let initial_head = fixture.head()?;
    for sequence in 0..=256 {
        fixture.receive(sequence)?;
    }
    assert_eq!(fixture.edge.queued_events.len(), 256);
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_next_ack(&mut fixture.queue, 0).await?;
    assert_no_ack(&mut fixture.queue).await?;
    let Some(PendingCommit::OrdinaryBatch(pending)) = &fixture.edge.commit else {
        return Err("full prefix was not batched".into());
    };
    assert_eq!(pending.receipts.len(), 256);
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    assert_eq!(fixture.head()?, initial_head.checked_add(2).ok_or("head")?);
    for sequence in 1..=256 {
        assert_next_ack(&mut fixture.queue, sequence).await?;
    }
    assert_outputs(&fixture.sink, 257);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    assert_eq!(fixture.edge.phase, Phase::Active);
    Ok(())
}

pub(crate) async fn committed_ordinary_acknowledgements()
-> TestResult<(Vec<Vec<u8>>, Vec<FederationFrame>)> {
    let mut fixture = PrefixFixture::new()?;
    fixture.edge.config.coordinator = PeerIdentity::new(
        HUB,
        HUB_NAME,
        FederationRole::Coordinator,
        HUB_EPOCH,
        agenc_ircd_crypto::Ed25519SecretKey::from_bytes([12; 32]).public_key(),
        [13; 32],
    );
    let mut objects = Vec::new();
    for sequence in 0..3 {
        let (descriptor, object) = ordinary_message(fixture.recipient, sequence)?;
        objects.push(object.as_slice().to_vec());
        events::receive(
            &mut fixture.edge,
            fixture.core.context_mut()?,
            descriptor,
            &object,
        )
        .map_err(|error| format!("ordinary source: {error:?}"))?;
    }
    assert_outputs(&fixture.sink, 0);
    assert_eq!(fixture.handle.queued_bytes(), 0);
    let mut frames = Vec::new();
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    frames.push(take_ack(&mut fixture.queue).await?);
    assert_outputs(&fixture.sink, 1);
    assert_no_ack(&mut fixture.queue).await?;
    assert!(matches!(
        fixture.edge.commit,
        Some(PendingCommit::OrdinaryBatch(_))
    ));
    fixture.core.commit_staged_batch().await?;
    fixture.settle_edge()?;
    frames.push(take_ack(&mut fixture.queue).await?);
    frames.push(take_ack(&mut fixture.queue).await?);
    assert_outputs(&fixture.sink, 3);
    assert_no_ack(&mut fixture.queue).await?;
    Ok((objects, frames))
}

async fn take_ack(queue: &mut LinkQueue) -> TestResult<FederationFrame> {
    let line = tokio::time::timeout(std::time::Duration::from_secs(1), queue.recv())
        .await?
        .ok_or("expected FACK")?;
    parse_frame(line.as_str().trim_end_matches("\r\n"), EDGE_NAME)
        .map_err(|error| format!("FACK source: {error:?}").into())
}
