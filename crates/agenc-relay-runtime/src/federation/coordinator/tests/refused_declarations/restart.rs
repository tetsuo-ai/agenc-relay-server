#![forbid(unsafe_code)]

//! A refused declaration across a coordinator restart (Architecture 20.5,
//! 20.7): the origin's closure is its durable row, written before the
//! sessions it owned close through cleanup; the reloaded coordinator refuses
//! a replay of the refused declaration again and READY follows; the edge's
//! deletion naming the refused generation is acknowledged during the reset
//! and after READY; and a session whose cleanup never committed is swept at
//! READY.

use agenc_relay_domain::federation::{OriginKey, OriginStatus};

use super::*;

const SEED: u8 = 56;

/// One coordinator over real storage, rebuilt from it on demand, and the
/// edge whose links it serves, driven batch by batch.
struct Restartable {
    core: StateCoreFixture,
    coordinator: FederationCoordinator,
    edge: Edge,
}

impl Restartable {
    fn new() -> TestResult<Self> {
        let (inbox, _unused) = mpsc::channel(1);
        let edge = Edge::new(inbox, SEED);
        Ok(Self {
            core: StateCoreFixture::with_registration_router(entropy_script())?,
            coordinator: standalone_coordinator(edge.server_id),
            edge,
        })
    }

    /// Rebuilds the coordinator from what storage holds.
    async fn restart(&mut self) -> TestResult {
        let mut coordinator = standalone_coordinator(self.edge.server_id);
        coordinator.startup(self.core.context_mut()?);
        for _ in 0..64 {
            if coordinator.loaded() {
                break;
            }
            let message = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                self.core.next_storage_read(),
            )
            .await??;
            coordinator.storage_read_completed(self.core.context_mut()?, message);
        }
        if !coordinator.loaded() {
            return Err("the coordinator never finished loading".into());
        }
        self.coordinator = coordinator;
        Ok(())
    }

    /// Establishes link `number` and resets the edge's origins on it.
    fn link(&mut self, number: u64) -> TestResult {
        let (handle, queue) = link_queue(1 << 20);
        self.edge.handle = handle.clone();
        self.edge.queue = queue;
        self.edge.link = LinkId::new(number);
        let peer = self.edge.server_id;
        let incarnation = self.edge.incarnation;
        let context = self.core.context_mut()?;
        self.coordinator
            .inbound(context, established(number, peer, incarnation, handle));
        self.coordinator
            .inbound(context, reset_frame(number, peer, incarnation));
        Ok(())
    }

    /// Commits every staged batch and applies its receipt.
    async fn settle(&mut self) -> TestResult {
        for _ in 0..16 {
            if self.core.context_mut()?.pending_len() == 0 {
                return Ok(());
            }
            self.core.commit_staged_batch().await?;
            self.coordinator.batch_applied(self.core.context_mut()?);
        }
        Err("staged batches kept coming".into())
    }

    /// Hands the coordinator one declaration of `origin`, naming `account`,
    /// and returns its object identity.
    fn declare(
        &mut self,
        origin: &Origin,
        update: bool,
        account: Option<OriginAccount>,
    ) -> TestResult<[u8; 32]> {
        let mut record = origin.record(&self.edge);
        record.account = account;
        let bytes = record.to_object()?.encode_canonical()?.as_slice().to_vec();
        let object_id = federation_object_id(&bytes);
        let descriptor = OriginDescriptor {
            coordinator_server_id: COORDINATOR,
            server_incarnation: self.edge.incarnation,
            origin_id: origin.id,
            generation: origin.generation,
            object_id,
        };
        let context = self.core.context_mut()?;
        inbound_object(
            &mut self.coordinator,
            context,
            &mut self.edge,
            &bytes,
            |fragment| {
                if update {
                    FederationFrame::OriginUpdate {
                        descriptor,
                        fragment,
                    }
                } else {
                    FederationFrame::OriginAdd {
                        descriptor,
                        fragment,
                    }
                }
            },
        )?;
        Ok(*object_id.as_bytes())
    }

    /// Hands the coordinator the edge's deletion of `origin` at `generation`
    /// and sequence zero.
    fn delete(&mut self, origin: &Origin, generation: u64) -> TestResult {
        let link = self.edge.link;
        let peer = self.edge.server_id;
        let frame = FederationFrame::OriginDel {
            coordinator_server_id: COORDINATOR,
            server_incarnation: self.edge.incarnation,
            origin_id: origin.id,
            generation,
            next_operation_sequence: 0,
        };
        self.coordinator.inbound(
            self.core.context_mut()?,
            FederationInbound {
                link,
                peer,
                event: LinkEvent::Frame(frame),
                charge: None,
            },
        );
        Ok(())
    }

    /// Every frame the coordinator queued on the current link; the link
    /// must still be up.
    async fn frames(&mut self) -> TestResult<Vec<FederationFrame>> {
        let mut frames = Vec::new();
        while self.edge.handle.queued_bytes() != 0 {
            let line = self.edge.queue.recv().await.ok_or("the link closed")?;
            let text = line.as_str().trim_end_matches("\r\n").to_owned();
            frames
                .push(parse_frame(&text, COORDINATOR_NAME).map_err(|e| format!("{e:?}: {text}"))?);
        }
        if !self
            .coordinator
            .link_is_live(self.edge.link, self.edge.server_id)
        {
            return Err("the coordinator failed the link".into());
        }
        Ok(frames)
    }

    fn key(&self, origin: &Origin) -> OriginKey {
        OriginKey {
            home_server_id: self.edge.server_id,
            server_incarnation: self.edge.incarnation,
            origin_id: origin.id,
        }
    }
}

/// Whether `frames` acknowledge `origin` at `generation`.
fn acknowledges(frames: &[FederationFrame], origin: &Origin, generation: u64) -> bool {
    frames.iter().any(|frame| {
        matches!(frame, FederationFrame::OriginAck { origin_id, generation: acked, .. }
            if *origin_id == origin.id && *acked == generation)
    })
}

fn ready(frames: &[FederationFrame]) -> bool {
    frames
        .iter()
        .any(|frame| matches!(frame, FederationFrame::OriginReady { .. }))
}

/// Refuses the next generation of an origin whose session is live but not
/// authenticated as the account it names, and stops before the session's
/// cleanup commits. Returns the fixture, the refused origin at its refused
/// generation, another live origin, and the session's user.
async fn refused_before_cleanup() -> TestResult<(Restartable, Origin, Origin, UserId)> {
    let mut fixture = Restartable::new()?;
    fixture.link(1)?;
    fixture.settle().await?;
    let mut origin = Origin::new(57);
    let mut other = Origin::new(58);
    for declared in [&mut origin, &mut other] {
        declared.object_id = fixture.declare(declared, false, None)?;
        fixture.settle().await?;
    }
    let user = host_session(fixture.core.context_mut()?, fixture.edge.server_id, "kate")?;
    let session = fixture
        .core
        .context_mut()?
        .domain()
        .session(user)
        .ok_or("hosted session")?
        .session_id();
    origin.session = Some((session, user));
    origin.advance_generation();
    origin.object_id = fixture.declare(&origin, true, None)?;
    fixture.settle().await?;
    assert!(acknowledges(&fixture.frames().await?, &origin, 1));
    origin.advance_generation();
    let account = OriginAccount {
        account_id: AccountId::from_random(AccountRandomId::from_bytes([59; 16])),
        account_session_generation: 1,
    };
    let _refused = fixture.declare(&origin, true, Some(account))?;
    // The refusal stages the origin's row alone; once it commits, the
    // session's cleanup is staged as a batch of its own, which never commits
    // here: the coordinator restarts first.
    fixture.core.commit_staged_batch().await?;
    fixture
        .coordinator
        .batch_applied(fixture.core.context_mut()?);
    if fixture.core.context_mut()?.pending_len() != 0 {
        fixture
            .core
            .state_mut()?
            .reject_fixture_batch_before_submission(
                agenc_relay_storage::StorageError::Unavailable,
            )?;
    }
    assert!(!acknowledges(&fixture.frames().await?, &origin, 2));
    assert!(fixture.core.context_mut()?.domain().session(user).is_some());
    fixture.restart().await?;
    // The closure is durable: the origin was reloaded deleted at the
    // generation and next sequence it held.
    let entry = fixture
        .coordinator
        .origins
        .origin(&fixture.key(&origin))
        .ok_or("reloaded origin")?;
    assert_eq!(entry.status, OriginStatus::Deleted);
    assert_eq!((entry.generation, entry.deleted_after), (1, Some(0)));
    Ok((fixture, origin, other, user))
}

#[tokio::test]
async fn a_refusal_replayed_after_a_restart_is_refused_again_and_its_deletion_acknowledged()
-> TestResult {
    let (mut fixture, origin, other, user) = Box::pin(refused_before_cleanup()).await?;
    fixture.link(2)?;
    fixture.settle().await?;
    let key = fixture.key(&origin);
    // The replayed refused declaration is refused again: nothing is staged
    // or acknowledged, and the refusal is recorded anew.
    let _replayed = fixture.declare(
        &origin,
        true,
        Some(OriginAccount {
            account_id: AccountId::from_random(AccountRandomId::from_bytes([59; 16])),
            account_session_generation: 1,
        }),
    )?;
    assert_eq!(fixture.core.context_mut()?.pending_len(), 0);
    assert_eq!(fixture.coordinator.refused_declarations.get(&key), Some(&2));
    let _other = fixture.declare(&other, false, None)?;
    fixture.settle().await?;
    let frames = fixture.frames().await?;
    assert!(acknowledges(&frames, &other, 0));
    assert!(!acknowledges(&frames, &origin, 2));
    assert!(ready(&frames), "the closed origin does not hold READY back");
    // READY swept the session no live origin binds.
    assert!(fixture.core.context_mut()?.domain().session(user).is_none());
    // The edge's deletion after READY names the refused generation.
    fixture.delete(&origin, 2)?;
    fixture.settle().await?;
    assert!(acknowledges(&fixture.frames().await?, &origin, 2));
    assert!(
        !fixture.coordinator.refused_declarations.contains_key(&key),
        "the acknowledged deletion ends the refusal"
    );
    Ok(())
}

#[tokio::test]
async fn a_refused_origin_deleted_during_the_reset_after_a_restart_is_acknowledged() -> TestResult {
    let (mut fixture, origin, other, user) = Box::pin(refused_before_cleanup()).await?;
    fixture.link(2)?;
    fixture.settle().await?;
    // The edge's connection ended while the coordinator was away: it deletes
    // the origin at the refused generation instead of replaying it.
    fixture.delete(&origin, 2)?;
    fixture.settle().await?;
    assert!(acknowledges(&fixture.frames().await?, &origin, 2));
    let _other = fixture.declare(&other, false, None)?;
    fixture.settle().await?;
    let frames = fixture.frames().await?;
    assert!(acknowledges(&frames, &other, 0));
    assert!(ready(&frames));
    assert!(fixture.core.context_mut()?.domain().session(user).is_none());
    Ok(())
}
