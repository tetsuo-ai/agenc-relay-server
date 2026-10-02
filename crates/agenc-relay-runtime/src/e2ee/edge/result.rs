//! Results on the edge: every `ERESULT` and `ERESPONSE` reassembles, the
//! 12.5 result tuple decodes by its kind, and the requester's labeled line
//! or object batch renders only after its completion event is covered
//! (companion 11.7, 12.5).

use agenc_relay_client_wire::WireMessage;
use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::federation::frames::{CompanionFrame, Correlation};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{
    ArcFederationEmptyKind, ArcFederationPendingKind, ArcFederationResponseDescriptor,
    ArcFederationResult, ArcFederationResultKind, ArcFederationStoreKind,
};
use agenc_relay_e2ee::tls::{DecodeBudget, Reader, TlsDecode};
use agenc_relay_e2ee::wire::assembly::{AssemblyKey, Direction, Ingest, QuotaScopes, Sender};
use agenc_relay_e2ee::wire::carrier::CarrierCommand;
use agenc_relay_e2ee::wire::command::ClientCommand;
use agenc_relay_e2ee::wire::fragment::{FragmentTag, fragment_object};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_e2ee::wire::response::{
    BatchChild, BatchOpener, EmptyGroupKind, PendingKind, StoreKind, SuccessLine, render_broadcast,
    render_eobject, render_fail, render_labeled, render_labeled_fail,
};

use super::router::{Refusal, Resolved};
use super::{ClientOutput, E2eeEdge, PendingRequest};
use crate::state_core::StateCoreContext;

/// The typed value of one result tuple (12.5).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ResultValue {
    /// `failed`.
    Failed {
        /// The reply code token.
        code: String,
        /// Copied context.
        context: Vec<u8>,
    },
    /// A kind whose tuple is empty.
    Empty,
    /// `bound`.
    Bound([u8; 32], [u8; 32], [u8; 32]),
    /// `closed`.
    Closed([u8; 32], [u8; 32]),
    /// `stored`.
    Stored(ArcFederationStoreKind, [u8; 32]),
    /// Three identifiers.
    Triple([u8; 32], [u8; 32], [u8; 32]),
    /// `pending`.
    Pending([u8; 32], ArcFederationPendingKind, [u8; 32]),
    /// `empty`.
    EmptyKind(ArcFederationEmptyKind),
    /// `account`.
    Account([u8; 24], u64),
    /// `attached`.
    Attached([u8; 16], u64),
    /// `attach_challenge`.
    AttachChallenge([u8; 16], [u8; 32]),
    /// `revoked`.
    Revoked(Vec<u8>),
    /// `reserved`.
    Reserved([u8; 16], [u8; 32]),
    /// `finalized`.
    Finalized([u8; 32], u64, [u8; 32], [u8; 32]),
    /// Four identifiers.
    Quad([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    /// `claimed`.
    Claimed([u8; 16], Vec<u8>, [u8; 32]),
    /// `mailbox_acked`.
    MailboxAcked([u8; 32], [u8; 32]),
    /// `recovery_accepted`: conversation and submission identifiers.
    RecoveryAccepted([u8; 32], [u8; 32]),
    /// `recovery_extended`: conversation, route sequence and record identifier.
    RecoveryExtended([u8; 32], u64, [u8; 32]),
    /// `recovery_closed`: conversation and close identifiers.
    RecoveryClosed([u8; 32], [u8; 32]),
    /// `recovery_conflict`: conversation, route sequence and both record identifiers.
    RecoveryConflict([u8; 32], u64, [u8; 32], [u8; 32]),
}

/// One decoded result with its descriptors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecodedResult {
    /// The request object the result answers.
    pub request_object_id: [u8; 32],
    /// The result kind.
    pub kind: ArcFederationResultKind,
    /// The decoded tuple.
    pub value: ResultValue,
    /// The completion event, when the result completes something.
    pub completion_event_id: Option<[u8; 16]>,
    /// The snapshot token of a page.
    pub snapshot_token: Option<[u8; 32]>,
    /// The next cursor of a page.
    pub next_cursor: Option<[u8; 32]>,
    /// The response descriptors in index order.
    pub descriptors: Vec<ArcFederationResponseDescriptor>,
}

fn optional<const N: usize>(field: &[u8]) -> Result<Option<[u8; N]>, E2eeError> {
    match field {
        [] => Ok(None),
        bytes => bytes
            .try_into()
            .map(Some)
            .map_err(|_| E2eeError::InvalidValue),
    }
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match reads every 12.5 result tuple beside its kind, mirroring the coordinator's encoder arm for arm
/// Decodes the result tuple of `kind`.
pub fn decode_value(kind: ArcFederationResultKind, bytes: &[u8]) -> Result<ResultValue, E2eeError> {
    use ArcFederationResultKind as K;
    let mut budget = DecodeBudget::new(1_024, 64);
    let mut reader = Reader::new(bytes, &mut budget);
    let value = match kind {
        K::Failed => ResultValue::Failed {
            code: String::from_utf8(reader.opaque(1, 64)?).map_err(|_| E2eeError::InvalidValue)?,
            context: reader.opaque(0, 255)?,
        },
        K::AcceptedEvent | K::ObjectPage | K::MailboxPage => ResultValue::Empty,
        K::Bound => ResultValue::Bound(reader.fixed()?, reader.fixed()?, reader.fixed()?),
        K::Closed => ResultValue::Closed(reader.fixed()?, reader.fixed()?),
        K::Stored => ResultValue::Stored(
            ArcFederationStoreKind::from_value(reader.u8()?)?,
            reader.fixed()?,
        ),
        K::CommitAcked | K::ReinitStaged | K::ReinitAcked => {
            ResultValue::Triple(reader.fixed()?, reader.fixed()?, reader.fixed()?)
        }
        K::Pending => ResultValue::Pending(
            reader.fixed()?,
            ArcFederationPendingKind::from_value(reader.u8()?)?,
            reader.fixed()?,
        ),
        K::Empty => ResultValue::EmptyKind(ArcFederationEmptyKind::from_value(reader.u8()?)?),
        K::Account => {
            let account: [u8; 24] = reader
                .opaque(1, 255)?
                .as_slice()
                .try_into()
                .map_err(|_| E2eeError::InvalidValue)?;
            ResultValue::Account(account, reader.u64()?)
        }
        K::Attached => ResultValue::Attached(reader.fixed()?, reader.u64()?),
        K::AttachChallenge => ResultValue::AttachChallenge(reader.fixed()?, reader.fixed()?),
        K::Revoked => ResultValue::Revoked(reader.opaque(1, 255)?),
        K::Reserved => ResultValue::Reserved(reader.fixed()?, reader.fixed()?),
        K::Finalized => ResultValue::Finalized(
            reader.fixed()?,
            reader.u64()?,
            reader.fixed()?,
            reader.fixed()?,
        ),
        K::Aborted | K::ReinitActivated | K::ReinitAborted => ResultValue::Quad(
            reader.fixed()?,
            reader.fixed()?,
            reader.fixed()?,
            reader.fixed()?,
        ),
        K::Claimed => {
            let device = reader.fixed()?;
            if reader.u8()? != 1 {
                return Err(E2eeError::InvalidValue);
            }
            ResultValue::Claimed(device, reader.opaque(1, 255)?, reader.fixed()?)
        }
        K::MailboxAcked => ResultValue::MailboxAcked(reader.fixed()?, reader.fixed()?),
        K::RecoveryAccepted => ResultValue::RecoveryAccepted(reader.fixed()?, reader.fixed()?),
        K::RecoveryExtended => {
            ResultValue::RecoveryExtended(reader.fixed()?, reader.u64()?, reader.fixed()?)
        }
        K::RecoveryClosed => ResultValue::RecoveryClosed(reader.fixed()?, reader.fixed()?),
        K::RecoveryConflict => ResultValue::RecoveryConflict(
            reader.fixed()?,
            reader.u64()?,
            reader.fixed()?,
            reader.fixed()?,
        ),
    };
    reader.finish()?;
    Ok(value)
}

/// Decodes one complete `federation_result` object.
pub fn decode_result(bytes: &[u8]) -> Result<DecodedResult, E2eeError> {
    let mut budget = DecodeBudget::new(1 << 16, 4_096);
    let object = ArcWireObject::decode_kind(
        bytes,
        Some(ArcWireObjectKind::FederationResult),
        &mut budget,
    )?;
    let result = ArcFederationResult::decode_exact(object.body(), &mut budget)?;
    Ok(DecodedResult {
        request_object_id: result.request_object_id,
        kind: result.result_kind,
        value: decode_value(result.result_kind, result.encoded_result.as_slice())?,
        completion_event_id: optional(result.completion_event_id.as_slice())?,
        snapshot_token: optional(result.snapshot_token.as_slice())?,
        next_cursor: optional(result.next_cursor.as_slice())?,
        descriptors: result.responses.into_items(),
    })
}

impl E2eeEdge {
    /// `ERESULT` and `ERESPONSE` fragments: the coordinator's answer to one
    /// request assembles out of order.
    pub(super) fn on_result_frame(
        &mut self,
        context: &mut StateCoreContext,
        frame: CompanionFrame,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let (correlation, object_id, fragment, index) = match frame {
            CompanionFrame::Result {
                correlation,
                object_id,
                fragment,
            } => (correlation, object_id, fragment, None),
            CompanionFrame::Response {
                correlation,
                object_id,
                fragment,
                response_index,
            } => (correlation, object_id, fragment, Some(response_index)),
            _ => return Err(E2eeReplyCode::InvalidFragment.into()),
        };
        if !self.pending.contains_key(&correlation.request_id) {
            // A result for a request this edge no longer holds: the
            // requester is gone, and the coordinator's replay row answers a
            // later retry.
            return Ok(Vec::new());
        }
        let Some(bytes) =
            self.assemble_response(&correlation, object_id, index.is_none(), &fragment, context)?
        else {
            return Ok(Vec::new());
        };
        self.record_answer(&correlation, index, bytes)?;
        self.render_ready(context, correlation.request_id)
    }

    fn assemble_response(
        &mut self,
        correlation: &Correlation,
        object_id: [u8; 32],
        result: bool,
        fragment: &FragmentTag,
        context: &StateCoreContext,
    ) -> Result<Option<Vec<u8>>, Refusal> {
        // A response object is any client-visible kind; its ceiling is the
        // largest one (the Welcome mailbox object) until it decodes.
        let command = if result {
            CarrierCommand::Federation(ArcWireObjectKind::FederationResult)
        } else {
            CarrierCommand::Response(ArcWireObjectKind::WelcomeMls)
        };
        let mut route = [0; 32];
        if let Some(head) = route.get_mut(..16) {
            head.copy_from_slice(&correlation.request_id);
        }
        let key = AssemblyKey {
            direction: Direction::Response,
            sender: Sender::Peer(*self.config.coordinator_server_id.as_bytes()),
            command,
            route,
            scope: None,
            object_id: agenc_relay_e2ee::ObjectId::from_bytes(object_id),
        };
        let scopes = QuotaScopes {
            peer: Some(*self.config.coordinator_server_id.as_bytes()),
            ..QuotaScopes::default()
        };
        let now = context.now().get() / 1_000;
        match self
            .assembler
            .ingest(key, scopes, command.limit(), fragment, now)
        {
            Ok(Ingest::Complete(bytes)) => Ok(Some(bytes)),
            Ok(Ingest::Incomplete | Ingest::Duplicate | Ingest::Recent) => Ok(None),
            Err(error) => Err(error.reply_code().into()),
        }
    }

    fn record_answer(
        &mut self,
        correlation: &Correlation,
        index: Option<u16>,
        bytes: Vec<u8>,
    ) -> Result<(), Refusal> {
        let pending = self
            .pending
            .get_mut(&correlation.request_id)
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let Some(index) = index else {
            let decoded = decode_result(&bytes).map_err(|_| E2eeReplyCode::InvalidFragment)?;
            if decoded.request_object_id != pending.request_object_id {
                return Err(E2eeReplyCode::InvalidFragment.into());
            }
            let object_id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
            super::response_validation::result(pending, &decoded, object_id)?;
            if pending.result_object_id.is_some() {
                return Ok(());
            }
            if let Some(completion) = decoded.completion_event_id {
                if self.covered.remove(&completion) {
                    pending.completion_seen = true;
                } else {
                    self.by_completion
                        .insert(completion, correlation.request_id);
                }
            }
            pending.result = Some(decoded);
            pending.result_object_id = Some(object_id);
            return Ok(());
        };
        if super::response_validation::response(pending, index, &bytes)? {
            pending.responses.insert(index, bytes);
        }
        Ok(())
    }

    /// A completion event arrived for `request_id`, or for a request whose
    /// result has not arrived yet.
    pub(super) fn completion_arrived(&mut self, event_id: [u8; 16]) -> Option<[u8; 16]> {
        match self.by_completion.remove(&event_id) {
            Some(request_id) => {
                if let Some(pending) = self.pending.get_mut(&request_id) {
                    pending.completion_seen = true;
                }
                Some(request_id)
            }
            None => {
                self.covered.insert(event_id);
                None
            }
        }
    }

    /// Renders the answer once the result, every response, and the
    /// completion are present; the pending entry is retired afterwards.
    pub(super) fn render_ready(
        &mut self,
        context: &mut StateCoreContext,
        request_id: [u8; 16],
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let ready = self.pending.get(&request_id).is_some_and(|pending| {
            pending.result.as_ref().is_some_and(|result| {
                let complete = result
                    .descriptors
                    .iter()
                    .all(|descriptor| pending.responses.contains_key(&descriptor.response_index));
                let covered = result.completion_event_id.is_none() || pending.completion_seen;
                complete && covered && !pending.rendered
            })
        });
        if !ready {
            return Ok(Vec::new());
        }
        let Some(pending) = self.pending.remove(&request_id) else {
            return Ok(Vec::new());
        };
        let Some(result) = pending.result.clone() else {
            return Ok(Vec::new());
        };
        let generation = pending.generation;
        let lines = self.render_answer(context, &pending, &result)?;
        let mut retry_outputs = self.publish_reply(context, &pending, &lines)?;
        let frames = lines
            .iter()
            .map(|line| WireMessage::extension_line(line))
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        retry_outputs.insert(0, ClientOutput { generation, frames });
        Ok(retry_outputs)
    }

    /// The lines of one answer: a failure, a scalar success, or an object
    /// batch; an accepted event renders through its echo instead.
    pub(super) fn render_answer(
        &mut self,
        context: &mut StateCoreContext,
        pending: &PendingRequest,
        result: &DecodedResult,
    ) -> Result<Vec<String>, Refusal> {
        let server = self.config.server_name.clone();
        let label = pending.label.as_deref();
        match &result.value {
            ResultValue::Failed {
                code,
                context: copied,
            } => {
                let code = E2eeReplyCode::from_token(code).unwrap_or(E2eeReplyCode::RateLimited);
                let context_token = (!copied.is_empty())
                    .then(|| agenc_relay_e2ee::wire::tokens::base64url_encode(copied));
                let body =
                    code.render_fail(command_name(&pending.command), context_token.as_deref());
                let rendered = match label {
                    Some(label) => render_labeled_fail(label, &server, &body),
                    None => render_fail(&server, &body),
                }
                .map_err(|_| E2eeReplyCode::InvalidFragment)?;
                Ok(vec![rendered])
            }
            ResultValue::Empty if result.kind == ArcFederationResultKind::AcceptedEvent => {
                Ok(Vec::new())
            }
            _ if result.descriptors.is_empty() => {
                let line = scalar_line(result, pending).ok_or(E2eeReplyCode::InvalidFragment)?;
                let rendered = match label {
                    Some(label) => render_labeled(label, &server, &line),
                    None => render_broadcast(&server, &line),
                }
                .map_err(|_| E2eeReplyCode::InvalidFragment)?;
                Ok(vec![rendered])
            }
            _ => self.render_batch(context, pending, result),
        }
    }

    /// One object batch: the opener, the metadata child, every object's
    /// fragments (a mailbox child before each), and the close.
    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one batch is opened, filled in descriptor order with its metadata children, and closed as one unit
    fn render_batch(
        &mut self,
        context: &mut StateCoreContext,
        pending: &PendingRequest,
        result: &DecodedResult,
    ) -> Result<Vec<String>, Refusal> {
        let server = self.config.server_name.clone();
        let mut scope = [0; 16];
        context
            .entropy_mut()
            .fill_exact(&mut scope)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        self.counters.results_rendered = self.counters.results_rendered.saturating_add(0);
        let batch_id = batch_id_for(&scope);
        let first = result
            .descriptors
            .first()
            .ok_or(E2eeReplyCode::InvalidFragment)?;
        let opener = BatchOpener {
            label: pending.label.clone().unwrap_or_else(|| "-".to_owned()),
            batch_id: batch_id.clone(),
            request_command: match &pending.command {
                Resolved::Command(ClientCommand::Ekey(_)) => "EKEY",
                _ => "EGROUP",
            },
            object_kind: first.wire_kind,
            scope,
            snapshot: result.snapshot_token.unwrap_or([0; 32]),
            next_cursor: result.next_cursor,
        };
        let mut lines = vec![
            opener
                .render(&server)
                .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        ];
        if let Some(child) = metadata_child(result) {
            lines.push(
                child
                    .render(&server, &batch_id)
                    .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            );
        }
        for descriptor in &result.descriptors {
            let bytes = pending
                .responses
                .get(&descriptor.response_index)
                .ok_or(E2eeReplyCode::InvalidFragment)?;
            if let (Some(token), Some(device)) = (
                optional::<32>(descriptor.delivery_token.as_slice())
                    .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                optional::<16>(descriptor.target_device_id.as_slice())
                    .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            ) {
                let child = BatchChild::Mailbox(token, device, descriptor.object_id);
                lines.push(
                    child
                        .render(&server, &batch_id)
                        .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                );
            }
            for fragment in fragment_object(bytes).map_err(|_| E2eeReplyCode::ObjectTooLarge)? {
                lines.push(
                    render_eobject(&server, &batch_id, &fragment, descriptor.wire_kind, &scope)
                        .map_err(|_| E2eeReplyCode::InvalidFragment)?,
                );
            }
        }
        lines.push(
            opener
                .render_close(&server)
                .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        );
        Ok(lines)
    }
}

/// The client command name a failure line names.
fn command_name(command: &Resolved) -> &'static str {
    match command {
        Resolved::ChannelApplication { .. } => "TAGMSG",
        Resolved::ChannelRoute { .. } => "EGROUP",
        Resolved::Command(ClientCommand::Egroup(_)) => "EGROUP",
        Resolved::Command(ClientCommand::Ekey(_)) => "EKEY",
        Resolved::Command(ClientCommand::Edirect(_)) => "EDIRECT",
    }
}

fn store_kind(kind: ArcFederationStoreKind) -> Option<StoreKind> {
    Some(match kind {
        ArcFederationStoreKind::StoreAuthorization
        | ArcFederationStoreKind::StorePolicy
        | ArcFederationStoreKind::StoreMembership => {
            return None;
        }
        ArcFederationStoreKind::StoreIdentity => StoreKind::Identity,
        ArcFederationStoreKind::StoreRoster => StoreKind::Roster,
        ArcFederationStoreKind::StoreCapabilities => StoreKind::Capabilities,
        ArcFederationStoreKind::StorePackage => StoreKind::Package,
        ArcFederationStoreKind::StoreApplication => StoreKind::Application,
        ArcFederationStoreKind::StoreBinding => StoreKind::Binding,
        ArcFederationStoreKind::StoreWelcome => StoreKind::Welcome,
        ArcFederationStoreKind::StoreStagedReinit => StoreKind::StagedReinit,
    })
}

const fn pending_kind(kind: ArcFederationPendingKind) -> PendingKind {
    match kind {
        ArcFederationPendingKind::PendingFinalization => PendingKind::Finalization,
        ArcFederationPendingKind::PendingAbort => PendingKind::Abort,
        ArcFederationPendingKind::PendingReinitAttempt => PendingKind::ReinitAttempt,
        ArcFederationPendingKind::PendingReinitActivate => PendingKind::ReinitActivate,
        ArcFederationPendingKind::PendingReinitAbort => PendingKind::ReinitAbort,
    }
}

fn empty_line(kind: ArcFederationEmptyKind) -> SuccessLine {
    use ArcFederationEmptyKind as E;
    match kind {
        E::EmptyAuthorizations => SuccessLine::EmptyGroup(EmptyGroupKind::Authorizations),
        E::EmptyAcks => SuccessLine::EmptyGroup(EmptyGroupKind::Acks),
        E::EmptyReceipts => SuccessLine::EmptyGroup(EmptyGroupKind::Receipts),
        E::EmptyObjects => SuccessLine::EmptyGroup(EmptyGroupKind::Objects),
        E::EmptyIdentity => SuccessLine::EmptyKey(StoreKind::Identity),
        E::EmptyRootChain => SuccessLine::EmptyKey(StoreKind::RootChain),
        E::EmptyRoster => SuccessLine::EmptyKey(StoreKind::Roster),
        E::EmptyCapabilities => SuccessLine::EmptyKey(StoreKind::Capabilities),
        E::EmptyPackage => SuccessLine::EmptyKey(StoreKind::Package),
        E::EmptyApplication => SuccessLine::EmptyKey(StoreKind::Application),
        E::EmptyBinding => SuccessLine::EmptyKey(StoreKind::Binding),
        E::EmptyBindingLock => SuccessLine::EmptyKey(StoreKind::BindingLock),
        E::EmptyWelcome => SuccessLine::EmptyKey(StoreKind::Welcome),
        E::EmptyStagedReinit => SuccessLine::EmptyKey(StoreKind::StagedReinit),
    }
}

/// The success line of a three-identifier tuple, which `commit_acked`,
/// `reinit_staged` and `reinit_acked` share: each kind keeps its own 11.7
/// result (12.5 maps every selector one-to-one).
fn triple_line(
    kind: ArcFederationResultKind,
    (a, b, c): ([u8; 32], [u8; 32], [u8; 32]),
) -> Option<SuccessLine> {
    use ArcFederationResultKind as K;
    Some(match kind {
        K::CommitAcked => SuccessLine::Acked(a, b, c),
        K::ReinitStaged => SuccessLine::ReinitStaged(a, b, c),
        K::ReinitAcked => SuccessLine::ReinitAcked(a, b, c),
        _ => return None,
    })
}

/// The success line of a four-identifier tuple, which `aborted`,
/// `reinit_activated` and `reinit_aborted` share, chosen by its kind.
fn quad_line(
    kind: ArcFederationResultKind,
    (a, b, c, d): ([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
) -> Option<SuccessLine> {
    use ArcFederationResultKind as K;
    Some(match kind {
        K::Aborted => SuccessLine::Aborted(a, b, c, d),
        K::ReinitActivated => SuccessLine::ReinitActivated(a, b, c, d),
        K::ReinitAborted => SuccessLine::ReinitAborted(a, b, c, d),
        _ => return None,
    })
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match maps every scalar result value to its 11.7 success line
/// The labeled scalar success line of a result without responses; a
/// `STORED` group line names the request's conversation and subject.
fn scalar_line(result: &DecodedResult, pending: &PendingRequest) -> Option<SuccessLine> {
    let route = pending.command.route_key();
    let subject = pending.subject.unwrap_or([0; 32]);
    Some(match &result.value {
        ResultValue::Bound(conversation, binding, _) => SuccessLine::Bound(*conversation, *binding),
        ResultValue::Closed(conversation, close) => SuccessLine::Closed(*conversation, *close),
        ResultValue::Stored(ArcFederationStoreKind::StoreAuthorization, object) => {
            SuccessLine::StoredAuthorization(route, subject, *object)
        }
        ResultValue::Stored(ArcFederationStoreKind::StorePolicy, object) => {
            SuccessLine::StoredPolicy(route, subject, *object)
        }
        ResultValue::Stored(ArcFederationStoreKind::StoreMembership, object) => {
            SuccessLine::StoredMembership(route, subject, *object)
        }
        ResultValue::Stored(kind, object) => SuccessLine::Stored(store_kind(*kind)?, *object),
        ResultValue::Triple(a, b, c) => triple_line(result.kind, (*a, *b, *c))?,
        ResultValue::Pending(conversation, kind, object) => {
            SuccessLine::Pending(*conversation, pending_kind(*kind), *object)
        }
        ResultValue::EmptyKind(kind) => empty_line(*kind),
        ResultValue::Account(account, generation) => SuccessLine::Account(*account, *generation),
        ResultValue::Attached(device, generation) => SuccessLine::Attached(*device, *generation),
        ResultValue::Revoked(reference) => SuccessLine::Revoked(reference.clone()),
        ResultValue::Finalized(a, epoch, c, d) => SuccessLine::Finalized(*a, *epoch, *c, *d),
        ResultValue::Quad(a, b, c, d) => quad_line(result.kind, (*a, *b, *c, *d))?,
        ResultValue::MailboxAcked(token, object) => SuccessLine::MailboxAcked(*token, *object),
        ResultValue::RecoveryAccepted(a, b) => SuccessLine::RecoveryAccepted(*a, *b),
        ResultValue::RecoveryExtended(a, sequence, c) => {
            SuccessLine::RecoveryExtended(*a, *sequence, *c)
        }
        ResultValue::RecoveryClosed(a, b) => SuccessLine::RecoveryClosed(*a, *b),
        ResultValue::RecoveryConflict(a, sequence, c, d) => {
            SuccessLine::RecoveryConflict(*a, *sequence, *c, *d)
        }
        ResultValue::Empty
        | ResultValue::Failed { .. }
        | ResultValue::AttachChallenge(..)
        | ResultValue::Reserved(..)
        | ResultValue::Claimed(..) => return None,
    })
}

/// The metadata child of an object batch, when the result carries one. Only
/// an `aborted` four-identifier tuple has a child form; a ReInit terminal
/// sharing its shape never renders as `ABORTED`.
fn metadata_child(result: &DecodedResult) -> Option<BatchChild> {
    Some(match &result.value {
        ResultValue::Reserved(reservation, object) => BatchChild::Reserved(*reservation, *object),
        ResultValue::Bound(conversation, binding, object) => {
            BatchChild::Bound(*conversation, *binding, *object)
        }
        ResultValue::AttachChallenge(device, object) => {
            BatchChild::AttachChallenge(*device, *object)
        }
        ResultValue::Claimed(device, reference, object) => {
            BatchChild::Claimed(*device, reference.clone(), *object)
        }
        ResultValue::Finalized(a, epoch, c, d) => BatchChild::Finalized(*a, *epoch, *c, *d),
        ResultValue::Quad(a, b, c, d) if result.kind == ArcFederationResultKind::Aborted => {
            BatchChild::Aborted(*a, *b, *c, *d)
        }
        _ => return None,
    })
}

/// The batch identifier of one response scope: `batch-id` admits letters,
/// digits, and `-` only (11.7), so the scope bytes render as hex.
fn batch_id_for(scope: &[u8; 16]) -> String {
    let mut id = String::with_capacity(37);
    id.push_str("e2ee-");
    for byte in scope {
        id.push_str(&format!("{byte:02x}"));
    }
    id
}
