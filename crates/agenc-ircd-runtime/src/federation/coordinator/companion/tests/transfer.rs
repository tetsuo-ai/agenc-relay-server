//! One live companion transfer on the composed coordinator owner: the ESTATE
//! cut is published through `admitted`, its pages are fetched through the
//! owner's commit receipt, and its expiry timers are fired off the owner's
//! own heap rather than by calling a handler.
#![forbid(unsafe_code)]

mod fetch;
mod timers;

use agenc_ircd_e2ee::ObjectId;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::conversation::IrcConversationKind;
use agenc_ircd_e2ee::objects::federation::{IrcFederationRouteState, IrcRouteStateKind};
use agenc_ircd_e2ee::tls::{Opaque, TlsEncode};

use super::*;
use crate::bridge::crypto::ChannelKeyVerifierRecord;
use crate::e2ee::coordinator::CompanionCoordinator;
use crate::federation::coordinator::{CoordinatorConfig, LiveLink};
use crate::federation::link::{LinkHandle, LinkQueue, ParsedLine, link_queue, parse_line};
use crate::test_support::{StateCoreFixture, TestResult};

const COORDINATOR_NAME: &str = "coordinator.example";

const PEER: ServerId = ServerId::from_bytes([50; 16]);
const LINK: LinkId = LinkId::new(11);
/// The canonical entry count of every nonfinal snapshot page.
const PER_PAGE: u32 = agenc_ircd_storage::e2ee_records::delivery_recovery::ENTRIES_PER_PAGE;

fn incarnation() -> ServerIncarnation {
    ServerIncarnation::from_bytes([51; 16])
}

/// A xorshift script with no repeating window in practice, so the cut token
/// and every page cursor this fixture draws are distinct.
fn entropy_script() -> Vec<u8> {
    let mut state: u32 = 0x2545_f491;
    (0..65_536)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            u8::try_from(state & 0xff).unwrap_or(0)
        })
        .collect()
}

/// One route-state envelope, the only cut entry shape this fixture needs.
fn route_state(network_id: [u8; 32], conversation_id: [u8; 32]) -> TestResult<Vec<u8>> {
    let value = IrcFederationRouteState {
        profile_version: 1,
        network_id,
        state_generation: 0,
        conversation_id,
        conversation_kind: IrcConversationKind::Channel,
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
        state: IrcRouteStateKind::ActiveRoute,
    };
    Ok(IrcWireObject::new(IrcWireObjectKind::FederationState, value.encode()?)?.encode()?)
}

/// Gives `PEER` `entries` entitled routes, so its cut spans several pages.
fn seed(executor: &mut CompanionCoordinator, network_id: [u8; 32], entries: u32) -> TestResult {
    for sequence in 0..entries {
        let mut conversation = [0_u8; 32];
        conversation
            .get_mut(..4)
            .ok_or("conversation prefix")?
            .copy_from_slice(&sequence.to_be_bytes());
        let bytes = route_state(network_id, conversation)?;
        let object = *ObjectId::compute(&bytes).as_bytes();
        executor
            .state
            .conversations
            .entry(conversation)
            .or_default()
            .route_object_id = object;
        executor.state.objects.insert(object, bytes);
        executor
            .state
            .entitlements
            .set_channel(PEER, conversation, true);
    }
    Ok(())
}

fn owner(core: &StateCoreFixture) -> TestResult<FederationCoordinator> {
    let identity = &core.identity;
    let mut coordinator = FederationCoordinator::new(
        CoordinatorConfig {
            network_id: identity.network_id,
            server_id: identity.server_id,
            server_name: COORDINATOR_NAME.into(),
            recovery_epoch: identity.recovery_epoch,
            query_cursor_key: [21; 32],
            process_nonce: [22; 16],
            outbox_bytes_per_edge: 1 << 20,
            outbox_objects_per_edge: 64,
        },
        vec![crate::federation::PeerIdentity::new(
            PEER,
            "edge.example",
            agenc_ircd_types::FederationRole::Edge,
            identity.recovery_epoch,
            agenc_ircd_crypto::Ed25519SecretKey::from_bytes([9; 32]).public_key(),
            [8; 32],
        )],
        std::sync::Arc::new(crate::test_support::TestChannelKeyVerifier),
        ChannelKeyVerifierRecord::new([7; 16], [1; 32]),
    );
    coordinator.install_companion_executor(
        CompanionCoordinator::new(
            *identity.network_id.as_bytes(),
            identity.server_id,
            COORDINATOR_NAME.into(),
        ),
        identity.server_incarnation,
    )?;
    Ok(coordinator)
}

/// The composed owner, one edge, and the edge's live link queue.
struct Transfer {
    core: StateCoreFixture,
    coordinator: FederationCoordinator,
    handle: LinkHandle,
    queue: LinkQueue,
    /// The link the edge currently holds.
    link: LinkId,
    /// The cut token the coordinator published.
    token: [u8; 32],
    /// The cursor of each page the edge has received, by page sequence.
    cursors: std::collections::BTreeMap<u32, [u8; 32]>,
    /// The page whose `ESTATE END` carried no cursor, which closes the cut.
    final_page: Option<u32>,
}

impl Transfer {
    /// Opens a cut of `pages` pages with a link queue of `capacity` bytes.
    /// The construction future is boxed so every test's own future stays small.
    async fn open(pages: u32, capacity: u64) -> TestResult<Self> {
        Box::pin(Self::build(pages, capacity)).await
    }

    async fn build(pages: u32, capacity: u64) -> TestResult<Self> {
        let core = StateCoreFixture::new(entropy_script())?;
        let mut coordinator = owner(&core)?;
        let network_id = *core.identity.network_id.as_bytes();
        let entries = pages
            .checked_mul(PER_PAGE)
            .and_then(|count| count.checked_sub(PER_PAGE / 2))
            .ok_or("entry count")?;
        seed(
            coordinator
                .companion_exec
                .as_mut()
                .ok_or("installed executor")?,
            network_id,
            entries,
        )?;
        let (handle, queue) = link_queue(capacity);
        let state = coordinator.peers.get_mut(&PEER).ok_or("configured peer")?;
        state.phase = PeerPhase::Ready;
        state.incarnation = Some(incarnation());
        state.live = Some(LiveLink {
            link: LINK,
            handle: handle.clone(),
            incarnation: incarnation(),
        });
        let mut transfer = Self {
            core,
            coordinator,
            handle,
            queue,
            link: LINK,
            token: [0; 32],
            cursors: std::collections::BTreeMap::new(),
            final_page: None,
        };
        transfer.resume().await?;
        Ok(transfer)
    }

    /// Drives ERESUME, which publishes page zero of the cut.
    async fn resume(&mut self) -> TestResult {
        let server_id = *self.core.identity.server_id.as_bytes();
        self.admit(CompanionFrame::Resume {
            coordinator_server_id: server_id,
            server_incarnation: *incarnation().as_bytes(),
            delivery_generation: 0,
            last: None,
        })?;
        self.settle().await?;
        self.read_pages().await?;
        if self.token == [0; 32] {
            return Err("the cut published no ESTATE BEGIN".into());
        }
        Ok(())
    }

    fn admit(&mut self, frame: CompanionFrame) -> TestResult {
        let link = self.link;
        admitted(
            &mut self.coordinator,
            self.core.context_mut()?,
            link,
            PEER,
            frame,
        )
        .map_err(|violation| format!("companion frame refused: {violation:?}"))?;
        Ok(())
    }

    /// Commits every batch the owner staged, through real storage.
    async fn settle(&mut self) -> TestResult {
        for _ in 0..8 {
            if self.coordinator.pending.is_none() {
                return Ok(());
            }
            self.core.commit_staged_batch().await?;
            self.coordinator.batch_applied(self.core.context_mut()?);
        }
        Err("staged batch bound".into())
    }

    /// Drains the link queue, recording every page cursor the edge sees.
    async fn read_pages(&mut self) -> TestResult<usize> {
        let mut lines = 0_usize;
        while self.handle.queued_bytes() != 0 {
            let line = self.queue.recv().await.ok_or("closed link queue")?;
            lines = lines.saturating_add(1);
            let parsed = parse_line(
                line.as_str().strip_suffix("\r\n").ok_or("CRLF")?,
                COORDINATOR_NAME,
            )
            .map_err(|error| format!("rendered line: {error:?}"))?;
            match parsed {
                ParsedLine::Companion(CompanionFrame::StateBegin { snapshot_token, .. }) => {
                    self.token = snapshot_token;
                }
                ParsedLine::Companion(CompanionFrame::StateEnd {
                    page_sequence,
                    next_cursor,
                    ..
                }) => match next_cursor {
                    Some(cursor) => {
                        self.cursors.insert(page_sequence, cursor);
                    }
                    None => self.final_page = Some(page_sequence),
                },
                _ => {}
            }
        }
        Ok(lines)
    }

    /// Sends `ESTATE FETCH` for `page`, quoting the cursor its predecessor ended on.
    fn fetch(&mut self, page: u32) -> TestResult {
        let cursor = *self
            .cursors
            .get(&page.checked_sub(1).ok_or("page zero is never fetched")?)
            .ok_or("the predecessor page ended with no cursor")?;
        let server_id = *self.core.identity.server_id.as_bytes();
        self.admit(CompanionFrame::StateFetch {
            coordinator_server_id: server_id,
            snapshot_token: self.token,
            next_page_sequence: page,
            cursor,
        })
    }

    fn executor(&self) -> TestResult<&CompanionCoordinator> {
        self.coordinator
            .companion_exec
            .as_ref()
            .ok_or_else(|| "installed executor".into())
    }

    /// Moves `PEER` to a fresh link of `capacity` bytes, as a reconnection
    /// does, and answers with the queue of the link it replaced.
    fn relink(&mut self, link: LinkId, capacity: u64) -> TestResult<LinkQueue> {
        let (handle, queue) = link_queue(capacity);
        self.coordinator
            .companion_exec
            .as_mut()
            .ok_or("installed executor")?
            .peers
            .get_mut(&PEER)
            .ok_or("a synchronized peer")?
            .link = Some(link);
        let state = self.coordinator.peers.get_mut(&PEER).ok_or("peer")?;
        state.live = Some(LiveLink {
            link,
            handle: handle.clone(),
            incarnation: incarnation(),
        });
        self.handle = handle;
        self.link = link;
        Ok(std::mem::replace(&mut self.queue, queue))
    }

    /// Drops the delivery owner the staged fetch named, which is what a
    /// continuation that no longer matches its private publication sees.
    fn drop_owner(&mut self) -> TestResult {
        self.coordinator
            .companion_exec
            .as_mut()
            .ok_or("installed executor")?
            .state
            .streams
            .get_mut(&PEER)
            .ok_or("a delivery stream")?
            .owner = None;
        Ok(())
    }

    /// Commits the staged batch, then hands the receipt's own publication to
    /// `continue_fetch` with the executor removed. The owner's receipt path
    /// returns before that guard, so it has no other reachable caller.
    async fn settle_without_executor(&mut self) -> TestResult {
        self.core.commit_staged_batch().await?;
        let epoch = self
            .coordinator
            .peers
            .get(&PEER)
            .map(|state| state.client_resync_epoch);
        let receipt = self
            .coordinator
            .companion_exec
            .as_mut()
            .ok_or("installed executor")?
            .batch_applied(epoch)
            .map_err(|fault| format!("receipt refused: {fault:?}"))?;
        let Some(Committed::Fetch(publication)) = receipt else {
            return Err("the receipt was not a fetch continuation".into());
        };
        self.coordinator.pending = None;
        let executor = self.coordinator.companion_exec.take();
        assert!(executor.is_some());
        continue_fetch(&mut self.coordinator, self.core.context_mut()?, publication);
        Ok(())
    }

    /// Whether the executor still holds the Pending cut of `PEER`.
    fn cut_is_live(&self) -> TestResult<bool> {
        Ok(self
            .executor()?
            .peers
            .get(&PEER)
            .is_some_and(|sync| sync.snapshot.is_some()))
    }
}
