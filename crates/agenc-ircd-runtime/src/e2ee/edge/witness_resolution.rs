//! Edge witness resolution (companion 12.5.1): a durable `witness/v1` row
//! blocks its conversation until the coordinator proves how the retained
//! record chain continues. After `ERESUME OK` the edge sends one `EWITNESS
//! REQUEST` per unresolved row and accepts only `EWITNESS` frames; each
//! delivered `sequencer_record` must occupy the next contiguous position,
//! name its predecessor, and verify under a credential of the negotiated
//! key set: the active credential, or its successor only inside the overlap
//! window at the second the record signed. The complete set installs its proven head and deletes the row
//! in one durable transaction, and only that receipt sends `EWITNESS
//! RESOLVED`. An empty answer retains the row and repeats the request; a
//! record that verifies at the expected position under another predecessor
//! marks the row `conflict` for good; every other failure closes the link.

#![forbid(unsafe_code)]

use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::identity::ValidationTime;
use agenc_ircd_e2ee::limits::{
    MAX_WITNESS_RESOLUTION_BYTES, MAX_WITNESS_RESOLUTION_RECORDS, MAX_WITNESS_RESOLUTION_SECONDS,
    PROFILE_VERSION,
};
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::IrcFederationWitnessResolution;
use agenc_ircd_e2ee::record_authentication::{
    authenticate_decoded, declared_sequenced_at, decode_record,
};
use agenc_ircd_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_ircd_e2ee::wire::assembly::{AssemblyKey, Direction, Ingest, QuotaScopes, Sender};
use agenc_ircd_e2ee::wire::carrier::CarrierCommand;
use agenc_ircd_e2ee::wire::fragment::FragmentTag;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;
use agenc_ircd_storage::TableId;
use agenc_ircd_storage::e2ee_records::{WITNESS_ROW_KIND, WitnessRow};
use agenc_ircd_types::MonotonicTick;

use super::events::{ChainHead, state_row};
use super::router::Refusal;
use super::{E2eeEdge, PendingCommit, Phase};
use crate::budget::MemoryPermit;
use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;
use crate::state_core::durable::AccountServiceDurableWrite;
use crate::state_core::timers::{TimedId, TimerEntry, TimerKind};

/// The bytes charged beside one retained object identifier.
const ID_OVERHEAD: usize = 64;

/// What one delivered record proved.
enum RecordOutcome {
    /// It extended the verified prefix by exactly one position.
    Extended,
    /// It verified at the expected position under another predecessor: the
    /// chain forked and no head can be installed.
    Forked,
}

/// One open `EWITNESS` resolution on the current link incarnation.
pub(super) struct OpenResolution {
    /// The conversation whose durable row this resolution answers.
    conversation: [u8; 32],
    /// The token the coordinator opened it with.
    token: [u8; 16],
    /// The position and head the durable row retained.
    expected: (u64, [u8; 32]),
    /// The declared record count.
    record_count: u32,
    /// The head the coordinator claims the set ends at.
    new_head: (u64, [u8; 32]),
    /// The declared object identifiers, in chain order.
    record_object_ids: Vec<[u8; 32]>,
    /// The next entry position expected, counted from zero.
    next_entry: u32,
    /// The head the verified prefix reached, once a record verified.
    verified: Option<(u64, [u8; 32])>,
    /// The complete record bytes accepted so far.
    accepted_bytes: u64,
    /// Whether a durable outcome is already staged for this token.
    settled: bool,
    /// The charge of the retained identifiers.
    permit: Option<MemoryPermit>,
}

impl OpenResolution {
    /// The position and predecessor the next record must occupy.
    fn next_position(&self) -> (u64, [u8; 32]) {
        self.verified.map_or(self.expected, |(sequence, id)| {
            (sequence.saturating_add(1), id)
        })
    }

    /// Whether `object_id` is the declared identifier at `entry_sequence`.
    fn declares(&self, entry_sequence: u32, object_id: &[u8; 32]) -> bool {
        usize::try_from(entry_sequence)
            .ok()
            .and_then(|index| self.record_object_ids.get(index))
            == Some(object_id)
    }
}

impl E2eeEdge {
    /// `ERESUME OK` with unresolved rows: the blocked phase opens and one
    /// request goes out per row before any other companion frame is read.
    pub(super) fn begin_witness_resolution(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Result<(), Refusal> {
        self.phase = Phase::Witness;
        self.witness_resolution = None;
        self.send_witness_requests(context, edge)
    }

    /// One `EWITNESS REQUEST` per unresolved durable row, in conversation
    /// order, followed by the wake that repeats them.
    fn send_witness_requests(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Result<(), Refusal> {
        let coordinator = *self.config.coordinator_server_id.as_bytes();
        let lines = self
            .unresolved_witnesses()
            .into_iter()
            .map(|(conversation, row)| {
                self.line(&CompanionFrame::WitnessRequest {
                    coordinator_server_id: coordinator,
                    conversation_id: conversation,
                    expected_sequence: row.expected_sequence,
                    expected_head_id: row.expected_head_id,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;
        if lines.is_empty() || !self.send(context, edge, lines) {
            return Err(E2eeReplyCode::Syncing.into());
        }
        self.arm_witness_request_wake(context);
        Ok(())
    }

    /// Reserves the wake that repeats an unanswered request after
    /// `MAX_WITNESS_RESOLUTION_SECONDS`; a refused reservation only loses
    /// the repeat, which the next link re-sends.
    fn arm_witness_request_wake(&mut self, context: &mut StateCoreContext) {
        if self.witness_request_wake.is_some() {
            return;
        }
        let _armed = self.try_arm_witness_request_wake(context);
    }

    fn try_arm_witness_request_wake(&mut self, context: &mut StateCoreContext) -> Option<()> {
        let deadline = MonotonicTick::from_ticks(
            context
                .now()
                .get()
                .checked_add(MAX_WITNESS_RESOLUTION_SECONDS.checked_mul(1_000)?)?,
        );
        let kind = TimerKind::CompanionWitnessResolution;
        let id = TimedId::Peer(self.config.coordinator_server_id);
        let generation = context.timers_mut().schedule(deadline, kind, id).ok()?;
        self.witness_request_wake = Some(TimerEntry {
            deadline,
            kind,
            id,
            generation,
        });
        Some(())
    }

    /// The repeat wake: an open resolution keeps its token, otherwise every
    /// unresolved row asks again.
    pub(super) fn witness_request_wake_fired(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        entry: TimerEntry,
    ) {
        let owned = self.witness_request_wake.is_some_and(|wake| {
            wake.id == entry.id
                && wake.generation == entry.generation
                && wake.deadline == entry.deadline
        });
        if !owned {
            return;
        }
        self.witness_request_wake = None;
        if self.phase != Phase::Witness || self.witness_resolution.is_some() {
            return;
        }
        if self.send_witness_requests(context, edge).is_err() {
            self.fail_frame(context, edge);
        }
    }

    /// `EWITNESS BEGIN`: one `witness_resolution` object opens the answer to
    /// exactly one durable row.
    pub(super) fn witness_begin(
        &mut self,
        context: &StateCoreContext,
        target_server_id: [u8; 16],
        conversation_id: [u8; 32],
        token: [u8; 16],
        object_id: [u8; 32],
        fragment: &FragmentTag,
    ) -> Result<(), Refusal> {
        let addressed = self.phase == Phase::Witness
            && target_server_id == *self.config.server_id.as_bytes()
            && self
                .witness_resolution
                .as_ref()
                .is_none_or(|open| open.token == token && open.conversation == conversation_id);
        if !addressed {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let Some(bytes) = self.witness_object(
            context,
            IrcWireObjectKind::WitnessResolution,
            conversation_id,
            object_id,
            fragment,
        )?
        else {
            return Ok(());
        };
        if self.witness_resolution.is_some() {
            return Ok(());
        }
        self.open_resolution(conversation_id, token, &bytes)
    }

    /// Verifies one complete `witness_resolution` against the durable row
    /// and the request it answers, then retains only its identifiers.
    fn open_resolution(
        &mut self,
        conversation: [u8; 32],
        token: [u8; 16],
        bytes: &[u8],
    ) -> Result<(), Refusal> {
        let row = self
            .durable_witness_row(&conversation)
            .filter(|row| !row.conflict)
            .ok_or(E2eeReplyCode::Syncing)?;
        let body = decode_resolution(bytes)?;
        let ids = body.record_object_ids.as_slice();
        let count = usize::try_from(body.record_count).map_err(|_| E2eeReplyCode::Syncing)?;
        let addressed = body.profile_version == PROFILE_VERSION
            && body.network_id == self.config.network_id
            && body.coordinator_server_id == *self.config.coordinator_server_id.as_bytes()
            && body.target_server_id == *self.config.server_id.as_bytes()
            && body.conversation_id == conversation
            && body.resolution_token == token;
        let bounded = body.record_count <= MAX_WITNESS_RESOLUTION_RECORDS
            && ids.len() == count.saturating_mul(32);
        let anchored = body.expected_sequence == row.expected_sequence
            && body.expected_head_id == row.expected_head_id;
        (addressed && bounded && anchored)
            .then_some(())
            .ok_or(E2eeReplyCode::Syncing)?;
        let permit = self
            .witness_backing()
            .ok_or(E2eeReplyCode::RateLimited)?
            .reserve(ids.len().saturating_add(ID_OVERHEAD))
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        self.witness_resolution = Some(OpenResolution {
            conversation,
            token,
            expected: (row.expected_sequence, row.expected_head_id),
            record_count: body.record_count,
            new_head: (body.new_head_sequence, body.new_head_id),
            record_object_ids: ids.as_chunks::<32>().0.to_vec(),
            next_entry: 0,
            verified: None,
            accepted_bytes: 0,
            settled: false,
            permit: Some(permit),
        });
        Ok(())
    }

    /// `EWITNESS ENTRY`: the record at the next contiguous entry position.
    pub(super) fn witness_entry(
        &mut self,
        context: &mut StateCoreContext,
        target_server_id: [u8; 16],
        token: [u8; 16],
        entry_sequence: u32,
        object_id: [u8; 32],
        fragment: &FragmentTag,
    ) -> Result<(), Refusal> {
        let open = self
            .witness_resolution
            .as_ref()
            .filter(|open| open.token == token)
            .ok_or(E2eeReplyCode::Syncing)?;
        if open.settled {
            return Ok(());
        }
        let conversation = open.conversation;
        let placed = self.phase == Phase::Witness
            && target_server_id == *self.config.server_id.as_bytes()
            && open.next_entry == entry_sequence
            && entry_sequence < open.record_count
            && open.declares(entry_sequence, &object_id);
        if !placed {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let Some(bytes) = self.witness_object(
            context,
            IrcWireObjectKind::SequencerRecord,
            conversation,
            object_id,
            fragment,
        )?
        else {
            return Ok(());
        };
        match self.verify_record(&bytes)? {
            RecordOutcome::Extended => Ok(()),
            RecordOutcome::Forked => self.stage_witness_conflict(context),
        }
    }

    /// Authenticates one delivered record at the position the verified
    /// prefix reached and advances that prefix.
    fn verify_record(&mut self, bytes: &[u8]) -> Result<RecordOutcome, Refusal> {
        let open = self
            .witness_resolution
            .as_ref()
            .ok_or(E2eeReplyCode::Syncing)?;
        let (sequence, predecessor) = open.next_position();
        let first = open.verified.is_none();
        let conversation = open.conversation;
        let accepted = open
            .accepted_bytes
            .checked_add(u64::try_from(bytes.len()).map_err(|_| E2eeReplyCode::ObjectTooLarge)?)
            .filter(|total| *total <= MAX_WITNESS_RESOLUTION_BYTES)
            .ok_or(E2eeReplyCode::ObjectTooLarge)?;
        let mut budget = DecodeBudget::new(1 << 23, 4_096);
        let (record, declared) =
            decode_record(bytes, &mut budget).map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let placed = declared.network_id == self.config.network_id
            && declared.conversation_id == conversation
            && declared.route_sequence == sequence;
        placed.then_some(()).ok_or(E2eeReplyCode::RouteInvalid)?;
        // The active credential signs at any time; its successor only
        // inside the overlap window at the second the record itself signed.
        // A successor outside that window is any other key (12.5.1).
        let sequenced_at = ValidationTime(declared_sequenced_at(&record));
        let credential = self
            .config
            .sequencer_key_set
            .as_ref()
            .and_then(|set| set.credential_at(&declared.sequencer_credential_id, sequenced_at))
            .ok_or(E2eeReplyCode::RouteInvalid)?;
        let authenticated =
            authenticate_decoded(&record, bytes, None, &declared, credential, &mut budget)
                .map_err(|_| E2eeReplyCode::RouteInvalid)?;
        // The record is authentic at this position; only its predecessor
        // decides whether it continues the retained chain or forks it.
        if declared.predecessor_record_id != predecessor {
            return first
                .then_some(RecordOutcome::Forked)
                .ok_or_else(|| E2eeReplyCode::RouteInvalid.into());
        }
        let open = self
            .witness_resolution
            .as_mut()
            .ok_or(E2eeReplyCode::Syncing)?;
        open.verified = Some((sequence, *authenticated.semantic_id()));
        open.next_entry = open.next_entry.saturating_add(1);
        open.accepted_bytes = accepted;
        Ok(RecordOutcome::Extended)
    }

    /// `EWITNESS END`: the complete set installs its head, an empty set
    /// retains the row for the next request.
    pub(super) fn witness_end(
        &mut self,
        context: &mut StateCoreContext,
        edge: &EdgeFederation,
        target_server_id: [u8; 16],
        token: [u8; 16],
        record_count: u32,
    ) -> Result<(), Refusal> {
        let open = self
            .witness_resolution
            .as_ref()
            .filter(|open| open.token == token)
            .ok_or(E2eeReplyCode::Syncing)?;
        if open.settled {
            return Ok(());
        }
        let complete = self.phase == Phase::Witness
            && target_server_id == *self.config.server_id.as_bytes()
            && record_count == open.record_count
            && open.next_entry == open.record_count;
        complete.then_some(()).ok_or(E2eeReplyCode::Syncing)?;
        let Some(verified) = open.verified else {
            // The coordinator holds nothing beyond the expected position:
            // the row stands and the request repeats (12.5.1).
            self.witness_resolution = None;
            self.arm_witness_request_wake(context);
            return Ok(());
        };
        (verified == open.new_head)
            .then_some(())
            .ok_or(E2eeReplyCode::Syncing)?;
        self.stage_witness_resolved(context, edge, verified)
    }

    /// One durable transaction installs the proven head and deletes the row.
    /// The head is installed only on a route the base profile still entitles
    /// this edge to; otherwise the link closes and the row stands (12.5).
    fn stage_witness_resolved(
        &mut self,
        context: &mut StateCoreContext,
        edge: &EdgeFederation,
        verified: (u64, [u8; 32]),
    ) -> Result<(), Refusal> {
        let open = self
            .witness_resolution
            .as_ref()
            .ok_or(E2eeReplyCode::Syncing)?;
        let (conversation, token) = (open.conversation, open.token);
        let entitled = self
            .conversations
            .get(&conversation)
            .is_none_or(|known| self.projected_route_entitled(edge, known));
        entitled.then_some(()).ok_or(E2eeReplyCode::Syncing)?;
        let head = ChainHead {
            sequence: verified.0,
            record_id: verified.1,
            recorded: true,
        };
        let mut writes = Vec::new();
        if let Some(write) = self.route_checkpoint(conversation, head)? {
            writes.push(write);
        }
        writes.push(witness_delete(conversation)?);
        self.stage(
            context,
            writes,
            PendingCommit::WitnessResolved {
                conversation,
                token,
                head,
            },
        )?;
        self.settle_resolution();
        Ok(())
    }

    /// One durable transaction marks the row an unresolvable fork.
    fn stage_witness_conflict(&mut self, context: &mut StateCoreContext) -> Result<(), Refusal> {
        let conversation = self
            .witness_resolution
            .as_ref()
            .ok_or(E2eeReplyCode::Syncing)?
            .conversation;
        let row = self
            .durable_witness_row(&conversation)
            .ok_or(E2eeReplyCode::Syncing)?;
        let marked = WitnessRow {
            conflict: true,
            ..row
        };
        let write = state_row(
            WitnessRow::key(&conversation).map_err(|_| E2eeReplyCode::InvalidFragment)?,
            WITNESS_ROW_KIND,
            marked
                .encode()
                .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        )?;
        self.stage(
            context,
            vec![write],
            PendingCommit::WitnessConflict { conversation },
        )?;
        self.settle_resolution();
        Ok(())
    }

    /// The staged outcome owns the token: later frames of the same set are
    /// accepted and ignored until the receipt stands.
    fn settle_resolution(&mut self) {
        if let Some(open) = self.witness_resolution.as_mut() {
            open.settled = true;
            open.record_object_ids = Vec::new();
            open.permit = None;
        }
    }

    /// The installation committed: the head is live, the row is gone, and
    /// `EWITNESS RESOLVED` goes out.
    pub(super) fn witness_resolved(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        conversation: [u8; 32],
        token: [u8; 16],
        head: ChainHead,
    ) {
        self.witness_resolution = None;
        if let Some(known) = self.conversations.get_mut(&conversation) {
            known.head = head;
        }
        self.forget_durable_witness(&conversation);
        if let Ok(line) = self.line(&CompanionFrame::WitnessResolved {
            coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
            conversation_id: conversation,
            resolution_token: token,
            new_head_sequence: head.sequence,
            new_head_id: head.record_id,
        }) {
            self.send(context, edge, vec![line]);
        }
        self.continue_witness(context, edge);
    }

    /// The conflict mark committed: this conversation stays blocked and the
    /// others resume.
    pub(super) fn witness_conflicted(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        conversation: [u8; 32],
    ) {
        self.witness_resolution = None;
        self.mark_durable_conflict(&conversation);
        self.continue_witness(context, edge);
    }

    /// Every row resolved or permanently conflicted: the origins replay.
    fn continue_witness(&mut self, context: &mut StateCoreContext, edge: &mut EdgeFederation) {
        if self.phase != Phase::Witness {
            return;
        }
        if self.witness_recovery_pending() {
            self.arm_witness_request_wake(context);
            return;
        }
        if let Some(wake) = self.witness_request_wake.take() {
            context.timers_mut().cancel(wake.kind, wake.id);
        }
        if self.begin_origins(context, edge).is_err() {
            self.fail_frame(context, edge);
        }
    }

    /// Assembles one `EWITNESS` object fragment; `None` until it completes.
    fn witness_object(
        &mut self,
        context: &StateCoreContext,
        kind: IrcWireObjectKind,
        route: [u8; 32],
        object_id: [u8; 32],
        fragment: &FragmentTag,
    ) -> Result<Option<Vec<u8>>, Refusal> {
        let coordinator = *self.config.coordinator_server_id.as_bytes();
        let command = CarrierCommand::Federation(kind);
        let key = AssemblyKey {
            direction: Direction::Remote,
            sender: Sender::Peer(coordinator),
            command,
            route,
            scope: None,
            object_id: agenc_ircd_e2ee::ObjectId::from_bytes(object_id),
        };
        let scopes = QuotaScopes {
            peer: Some(coordinator),
            ..QuotaScopes::default()
        };
        match self.assembler.ingest(
            key,
            scopes,
            command.limit(),
            fragment,
            context.now().get() / 1_000,
        ) {
            Ok(Ingest::Complete(bytes)) => Ok(Some(bytes)),
            Ok(Ingest::Incomplete | Ingest::Duplicate | Ingest::Recent) => Ok(None),
            Err(error) => Err(error.reply_code().into()),
        }
    }

    /// Whether `conversation` is one an unresolvable fork blocked for good,
    /// or one whose resolution has not yet installed its head.
    pub(super) fn blocked_conversation(&self, conversation: &[u8; 32]) -> bool {
        *conversation != [0; 32] && self.witness_conversation_blocked(conversation)
    }
}

/// Decodes one complete `witness_resolution` object body.
fn decode_resolution(bytes: &[u8]) -> Result<IrcFederationWitnessResolution, Refusal> {
    let mut budget = DecodeBudget::new(1 << 17, 4_096);
    let object = IrcWireObject::decode_kind(
        bytes,
        Some(IrcWireObjectKind::WitnessResolution),
        &mut budget,
    )
    .map_err(|_| E2eeReplyCode::InvalidFragment)?;
    IrcFederationWitnessResolution::decode_exact(object.body(), &mut budget)
        .map_err(|_| E2eeReplyCode::InvalidFragment.into())
}

/// The write that removes a resolved `witness/v1` row.
fn witness_delete(conversation: [u8; 32]) -> Result<AccountServiceDurableWrite, Refusal> {
    let key = WitnessRow::key(&conversation).map_err(|_| E2eeReplyCode::InvalidFragment)?;
    AccountServiceDurableWrite::delete(TableId::E2eeState, key)
        .map_err(|_| E2eeReplyCode::InvalidFragment.into())
}
