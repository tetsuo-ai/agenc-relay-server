#![forbid(unsafe_code)]

//! Companion 12.5 on the edge: each event is admitted at the next exact
//! cursor, after the events already committing or queued; an exact
//! duplicate at the installed cursor is acknowledged again without
//! reapplying state; and a resume names the cursor its last event commit
//! installs.

use std::time::Duration;

use crate::federation::link::{LinkHandle, LinkQueue, link_queue};
use crate::federation::{FederationInbound, LinkEvent, LinkId, LinkSession};

use super::*;

/// Generation and cursor of the edge before each test.
const GENERATION: u64 = 2;
const INSTALLED: (u64, [u8; 16]) = (6, [12; 16]);

struct Fixture {
    core: StateCoreFixture,
    companion: E2eeEdge,
    base: EdgeFederation,
    _handle: LinkHandle,
    queue: LinkQueue,
}

impl Fixture {
    async fn new() -> TestResult<Self> {
        let mut core = StateCoreFixture::new(vec![0; 16_384])?;
        let mut base = base_edge();
        let (handle, mut queue) = link_queue(1 << 20);
        let peer = ServerId::from_bytes([3; 16]);
        let session = LinkSession {
            link: LinkId::new(1),
            peer,
            peer_incarnation: ServerIncarnation::from_bytes([17; 16]),
            peer_recovery_epoch: RecoveryEpoch::from_bytes([5; 16]),
            transition: agenc_relay_federation_wire::EpochTransition::Initial,
        };
        assert!(
            base.inbound(
                core.context_mut()?,
                FederationInbound {
                    link: LinkId::new(1),
                    peer,
                    event: LinkEvent::Established {
                        session,
                        handle: handle.clone(),
                    },
                    charge: None,
                },
            )
            .is_empty()
        );
        for _ in 0..4 {
            if core.context_mut()?.pending_len() == 0 {
                break;
            }
            core.commit_staged_batch().await?;
            assert!(base.batch_applied(core.context_mut()?).is_empty());
        }
        assert_eq!(core.context_mut()?.pending_len(), 0);
        while let Ok(line) = tokio::time::timeout(Duration::from_millis(5), queue.recv()).await {
            drop(line.ok_or("base link closed during setup")?);
        }
        let mut companion = edge();
        companion.phase = crate::e2ee::edge::Phase::Active;
        companion.delivery.generation = GENERATION;
        companion.delivery.cursor = Some(INSTALLED);
        // The cursor is durable, as a restart's restore leaves it.
        companion.witness_snapshot_required = false;
        Ok(Self {
            core,
            companion,
            base,
            _handle: handle,
            queue,
        })
    }

    /// Delivers the ordinary event at `sequence` named `id`, of `generation`,
    /// and reports whether the edge refused it.
    fn deliver_at(&mut self, generation: u64, sequence: u64, id: [u8; 16]) -> TestResult<bool> {
        self.deliver_object(generation, sequence, id, 5)
    }

    /// As `deliver_at`, with the event's coordinator state generation set
    /// to `state`, which changes its object.
    fn deliver_object(
        &mut self,
        generation: u64,
        sequence: u64,
        id: [u8; 16],
        state: u64,
    ) -> TestResult<bool> {
        let position = DeliveryPosition {
            server_id: [2; 16],
            delivery_generation: generation,
            delivery_sequence: sequence,
            event_id: id,
        };
        let event = ArcFederationEvent {
            profile_version: 1,
            network_id: [1; 32],
            target_server_id: [2; 16],
            delivery_generation: generation,
            coordinator_state_generation: state,
            delivery_sequence: sequence,
            event_id: id,
            event_kind: ArcFederationEventKind::RequestCompleted,
            cross_profile_mutation_id: Opaque::new(Vec::new())?,
            cross_profile_part_index: 0,
            cross_profile_part_count: 0,
            conversation_id: Opaque::new(Vec::new())?,
            route_sequence: 0,
            origin_id: Opaque::new(Vec::new())?,
            origin_generation: 0,
            source_view: Opaque::new(Vec::new())?,
            request_home_server_id: Opaque::new(Vec::new())?,
            request_server_incarnation: Opaque::new(Vec::new())?,
            request_origin_id: Opaque::new(Vec::new())?,
            request_origin_generation: 0,
            request_operation_sequence: 0,
            request_id: Opaque::new(Vec::new())?,
            payload_object_id: Opaque::new(Vec::new())?,
            encoded_event_result: Opaque::new(Vec::new())?,
        };
        let bytes =
            ArcWireObject::new(ArcWireObjectKind::FederationEvent, event.encode()?)?.encode()?;
        let object_id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
        let mut refused = false;
        for fragment in agenc_relay_e2ee::wire::fragment::fragment_object(&bytes)? {
            refused |= self
                .companion
                .on_event_frame(
                    self.core.context_mut()?,
                    &mut self.base,
                    position,
                    object_id,
                    fragment,
                    false,
                )
                .is_err();
        }
        Ok(refused)
    }

    fn deliver(&mut self, sequence: u64) -> TestResult<bool> {
        self.deliver_at(GENERATION, sequence, id(sequence))
    }

    /// Commits the staged batch and runs the edge's receipt.
    async fn commit(&mut self) -> TestResult {
        self.core.commit_staged_batch().await?;
        let _outputs = self
            .companion
            .batch_applied(self.core.context_mut()?, &mut self.base);
        Ok(())
    }

    /// Every companion line sent so far.
    async fn sent(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Ok(Some(line)) =
            tokio::time::timeout(Duration::from_millis(20), self.queue.recv()).await
        {
            lines.push(line.as_str().trim_end().to_owned());
        }
        lines
    }
}

/// The event identity at `sequence`.
fn id(sequence: u64) -> [u8; 16] {
    [u8::try_from(sequence).unwrap_or(u8::MAX).wrapping_add(30); 16]
}

/// The delivery sequence each `EACK` line names.
fn acknowledged(lines: &[String]) -> Vec<u64> {
    lines
        .iter()
        .filter_map(|line| {
            let mut words = line.split(' ').skip_while(|word| *word != "EACK");
            words.nth(3).and_then(|word| word.parse().ok())
        })
        .collect()
}

#[tokio::test]
async fn an_exact_duplicate_at_the_installed_cursor_is_acknowledged_again() -> TestResult {
    let mut fixture = Fixture::new().await?;
    assert!(!fixture.deliver_at(GENERATION, INSTALLED.0, INSTALLED.1)?);
    assert_eq!(
        fixture.core.context_mut()?.pending_len(),
        0,
        "nothing applies"
    );
    assert!(fixture.companion.commit.is_none());
    assert_eq!(fixture.companion.delivery.cursor, Some(INSTALLED));
    let lines = fixture.sent().await;
    assert_eq!(acknowledged(&lines), vec![INSTALLED.0], "{lines:?}");
    // Anything else at or behind the cursor stays refused.
    assert!(
        fixture.deliver_at(GENERATION, INSTALLED.0, [99; 16])?,
        "the installed sequence under another event ID"
    );
    assert!(
        fixture.deliver_at(GENERATION, INSTALLED.0 - 1, id(5))?,
        "a sequence behind the cursor"
    );
    assert!(
        fixture.deliver_at(GENERATION + 1, INSTALLED.0, INSTALLED.1)?,
        "the installed position of another generation"
    );
    assert!(fixture.sent().await.is_empty());
    assert_eq!(fixture.companion.delivery.cursor, Some(INSTALLED));
    Ok(())
}

#[tokio::test]
async fn the_next_events_wait_behind_the_one_committing() -> TestResult {
    let mut fixture = Fixture::new().await?;
    assert!(!fixture.deliver(7)?);
    assert!(matches!(
        fixture.companion.commit,
        Some(crate::e2ee::edge::PendingCommit::Event { .. })
    ));
    // The next sequence after the committing event is admitted and waits.
    assert!(!fixture.deliver(8)?);
    assert_eq!(fixture.companion.queued.len(), 1);
    // A gap past the last admitted event is still refused.
    assert!(fixture.deliver(10)?, "a gap after the queued event");
    assert!(!fixture.deliver(9)?);
    assert_eq!(fixture.companion.queued.len(), 2);
    for expected in [7, 8, 9] {
        fixture.commit().await?;
        assert_eq!(acknowledged(&fixture.sent().await), vec![expected]);
        assert_eq!(
            fixture.companion.delivery.cursor,
            Some((expected, id(expected)))
        );
    }
    assert!(fixture.companion.queued.is_empty());
    assert!(fixture.companion.commit.is_none());
    Ok(())
}

impl Fixture {
    /// Another router's checkpoint gathers in the state core.
    fn stage_other_batch(&mut self) -> TestResult {
        let context = self.core.context_mut()?;
        let plan = context.domain().plan_account_service_checkpoint()?;
        let write = crate::e2ee::edge::events::cursor_write(
            &self.companion.config,
            &self.companion.delivery,
        )
        .map_err(|code| code.to_string())?
        .at_revision(plan.resulting_revision().get())?;
        context
            .stage_durable_with_account_service(
                plan,
                crate::state_core::fanout::FanoutRequest::new(Vec::new(), Vec::new())?,
                None,
                0,
                vec![write],
            )
            .map_err(|error| format!("other batch: {error:?}"))?;
        Ok(())
    }
}

#[tokio::test]
async fn an_event_waits_while_another_router_gathers_a_batch() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.stage_other_batch()?;
    assert!(!fixture.core.context_mut()?.in_flight());
    assert!(!fixture.deliver(7)?, "the event waits instead of failing");
    assert_eq!(fixture.companion.queued.len(), 1);
    assert!(fixture.companion.commit.is_none());
    // The other batch's receipt lets the event apply, and its own receipt
    // acknowledges it.
    fixture.commit().await?;
    assert!(matches!(
        fixture.companion.commit,
        Some(crate::e2ee::edge::PendingCommit::Event { .. })
    ));
    assert!(acknowledged(&fixture.sent().await).is_empty());
    fixture.commit().await?;
    assert_eq!(acknowledged(&fixture.sent().await), vec![7]);
    Ok(())
}

#[tokio::test]
async fn a_resume_names_the_cursor_its_event_commit_installs() -> TestResult {
    let mut fixture = Fixture::new().await?;
    assert!(!fixture.deliver(7)?);
    // The link closes while the event commits; the next link's resume waits
    // for the receipt.
    fixture.companion.link_down();
    assert!(
        !fixture
            .companion
            .link_active(fixture.core.context_mut()?, &mut fixture.base)
    );
    assert!(
        fixture.sent().await.is_empty(),
        "no resume before the receipt"
    );
    // The receipt sends no EACK, since its link closed.
    fixture.commit().await?;
    assert!(acknowledged(&fixture.sent().await).is_empty());
    assert_eq!(fixture.companion.delivery.cursor, Some((7, id(7))));
    assert!(
        fixture
            .companion
            .link_active(fixture.core.context_mut()?, &mut fixture.base)
    );
    let lines = fixture.sent().await;
    let resume = lines.first().ok_or("ERESUME")?;
    assert!(
        resume.contains(" ERESUME ") && resume.contains(&format!(" {GENERATION} 7 ")),
        "{resume}"
    );
    Ok(())
}

#[tokio::test]
async fn events_stay_in_order_behind_a_refused_batch() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.stage_other_batch()?;
    assert!(!fixture.deliver(7)?);
    // Storage refuses the other batch; no receipt follows, and the waiting
    // event applies at the refusal.
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    fixture
        .companion
        .batch_rejected(fixture.core.context_mut()?, &mut fixture.base);
    let context = fixture.core.context_mut()?;
    let _outputs = fixture
        .companion
        .drain_waiting_events(context, &mut fixture.base);
    assert!(fixture.companion.queued.is_empty());
    assert!(matches!(
        fixture.companion.commit,
        Some(crate::e2ee::edge::PendingCommit::Event { .. })
    ));
    // The next event waits behind it, and the receipts apply both in order.
    assert!(!fixture.deliver(8)?);
    assert_eq!(fixture.companion.queued.len(), 1);
    for expected in [7, 8] {
        fixture.commit().await?;
        assert_eq!(acknowledged(&fixture.sent().await), vec![expected]);
    }
    assert_eq!(fixture.companion.delivery.cursor, Some((8, id(8))));
    assert!(fixture.companion.queued.is_empty());
    Ok(())
}

#[tokio::test]
async fn a_duplicate_carrying_another_object_at_the_installed_cursor_is_refused() -> TestResult {
    let mut fixture = Fixture::new().await?;
    assert!(!fixture.deliver(7)?);
    fixture.commit().await?;
    assert_eq!(acknowledged(&fixture.sent().await), vec![7]);
    // The applied event's object is known: another object under its
    // position and Event ID conflicts, and the link closes.
    assert!(fixture.deliver_object(GENERATION, 7, id(7), 6)?);
    assert!(fixture.sent().await.is_empty());
    // The exact object is acknowledged again, with nothing applied.
    assert!(!fixture.deliver(7)?);
    assert_eq!(acknowledged(&fixture.sent().await), vec![7]);
    assert!(fixture.companion.commit.is_none());
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    Ok(())
}

#[tokio::test]
async fn an_event_never_applies_ahead_of_one_still_waiting() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.stage_other_batch()?;
    assert!(!fixture.deliver(7)?);
    // The batch it waited for leaves without a receipt that drains it.
    fixture.core.context_mut()?.discard_pending_for_test();
    // The next event queues behind the waiting one rather than applying
    // first, and a drain applies them in order.
    assert!(!fixture.deliver(8)?);
    assert_eq!(fixture.companion.queued.len(), 2);
    assert!(fixture.companion.commit.is_none());
    let context = fixture.core.context_mut()?;
    let _outputs = fixture
        .companion
        .drain_waiting_events(context, &mut fixture.base);
    for expected in [7, 8] {
        fixture.commit().await?;
        assert_eq!(acknowledged(&fixture.sent().await), vec![expected]);
    }
    Ok(())
}

/// Storage refuses the event's own batch: the event is undone and the
/// federation link closes, as for a refused batch of the base edge's, so
/// the next link resumes from the durable cursor; nothing goes out on the
/// link that delivered the event.
#[tokio::test]
async fn a_refused_event_batch_closes_the_link() -> TestResult {
    let mut fixture = Fixture::new().await?;
    assert!(!fixture.deliver(7)?);
    assert!(matches!(
        fixture.companion.commit,
        Some(crate::e2ee::edge::PendingCommit::Event { .. })
    ));
    assert!(fixture.base.current_companion_link_id().is_some());
    fixture
        .core
        .state_mut()?
        .reject_fixture_batch_before_submission(agenc_relay_storage::StorageError::QueueFull)?;
    fixture
        .companion
        .batch_rejected(fixture.core.context_mut()?, &mut fixture.base);
    assert!(
        fixture.base.current_companion_link_id().is_none(),
        "the link closed"
    );
    assert_eq!(fixture.companion.phase(), crate::e2ee::edge::Phase::Down);
    assert!(fixture.companion.commit.is_none());
    assert_eq!(fixture.companion.delivery.cursor, Some(INSTALLED));
    assert!(fixture.sent().await.is_empty());
    Ok(())
}

/// An event that arrives while a batch of the edge's waits for a free slot
/// queues behind it: the held batch stages first, and the event applies at
/// that batch's receipt.
#[tokio::test]
async fn an_event_waits_behind_a_held_batch() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.stage_other_batch()?;
    assert!(fixture.hold_step()?);
    assert!(fixture.companion.held.is_some());
    // The other batch is gone; the held batch still owns the next one.
    fixture.core.context_mut()?.discard_pending_for_test();
    assert!(!fixture.deliver(7)?);
    assert_eq!(fixture.companion.queued.len(), 1, "the event waits");
    assert!(fixture.companion.commit.is_none());
    let _outputs = fixture
        .companion
        .batch_applied(fixture.core.context_mut()?, &mut fixture.base);
    assert!(fixture.companion.held.is_none());
    assert!(matches!(
        fixture.companion.commit,
        Some(crate::e2ee::edge::PendingCommit::SnapshotStep { .. })
    ));
    assert_eq!(fixture.companion.queued.len(), 1);
    fixture.commit().await?;
    assert!(matches!(
        fixture.companion.commit,
        Some(crate::e2ee::edge::PendingCommit::Event { .. })
    ));
    fixture.commit().await?;
    assert_eq!(acknowledged(&fixture.sent().await), vec![7]);
    Ok(())
}

impl Fixture {
    /// Offers a migration step of the edge's while another router's batch
    /// gathers; reports whether it was held.
    fn hold_step(&mut self) -> TestResult<bool> {
        let write = crate::e2ee::edge::events::cursor_write(
            &self.companion.config,
            &self.companion.delivery,
        )
        .map_err(|code| code.to_string())?;
        Ok(self
            .companion
            .stage_or_hold(
                self.core.context_mut()?,
                vec![write],
                crate::e2ee::edge::PendingCommit::SnapshotStep {
                    done: false,
                    switched_through: None,
                },
            )
            .is_ok())
    }
}

/// No batch of the edge's goes ahead of a queued event: a batch that finds
/// an event queued is refused and not held, and the event applies at the
/// other router's receipt.
#[tokio::test]
async fn a_batch_that_finds_an_event_queued_is_refused() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.stage_other_batch()?;
    assert!(!fixture.deliver(7)?);
    assert_eq!(fixture.companion.queued.len(), 1, "the event waits");
    assert!(!fixture.hold_step()?, "the batch is refused");
    assert!(fixture.companion.held.is_none());
    fixture.commit().await?;
    assert!(matches!(
        fixture.companion.commit,
        Some(crate::e2ee::edge::PendingCommit::Event { .. })
    ));
    Ok(())
}

/// A held batch belongs to the link whose frame made it: a link loss drops
/// it, so nothing stages it at the receipt of the batch it waited for, and
/// nothing waits behind it; the next link carries its frame again.
#[tokio::test]
async fn a_link_loss_drops_the_held_batch() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.stage_other_batch()?;
    assert!(fixture.hold_step()?);
    fixture.companion.link_down();
    assert!(fixture.companion.held.is_none());
    fixture.commit().await?;
    assert!(
        fixture.companion.commit.is_none(),
        "nothing of the edge's staged"
    );
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert!(
        !fixture.companion.holds_events(fixture.core.context_mut()?),
        "a later event does not wait"
    );
    Ok(())
}

/// Only one batch is held: a second one that finds a batch open is refused
/// and the first stays held.
#[tokio::test]
async fn a_second_batch_is_refused_while_one_is_held() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.stage_other_batch()?;
    assert!(fixture.hold_step()?);
    assert!(!fixture.hold_step()?, "a second batch is refused");
    // While the other batch is still open, nothing stages the held one.
    let _outputs = fixture
        .companion
        .drain_waiting_events(fixture.core.context_mut()?, &mut fixture.base);
    assert!(fixture.companion.held.is_some());
    assert!(fixture.companion.commit.is_none());
    Ok(())
}

/// A held batch the state core refuses once no batch is open closes the
/// link, as a frame whose batch cannot be staged does.
#[tokio::test]
async fn a_held_batch_the_state_core_refuses_closes_the_link() -> TestResult {
    let mut fixture = Fixture::new().await?;
    fixture.stage_other_batch()?;
    assert!(fixture.hold_step()?);
    fixture.core.context_mut()?.discard_pending_for_test();
    fixture
        .core
        .state_mut()?
        .step_message(crate::state_core::inbox::StateCoreMessage::Signal(
            crate::state_core::inbox::SignalEvent::Terminate,
        ));
    let _outputs = fixture
        .companion
        .batch_applied(fixture.core.context_mut()?, &mut fixture.base);
    assert!(fixture.companion.held.is_none());
    assert!(fixture.companion.commit.is_none());
    assert!(fixture.base.current_companion_link_id().is_none());
    assert_eq!(fixture.companion.phase(), crate::e2ee::edge::Phase::Down);
    Ok(())
}
