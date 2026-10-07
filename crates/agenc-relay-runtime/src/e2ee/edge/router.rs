//! Client lines on the edge: the capability, account, attachment, and
//! `STATE_ACTIVE` gates, one in-progress object per sender, and the
//! companion request each accepted line becomes (companion 11.3 to 11.8).

use agenc_relay_client_wire::{ParsedMessage, WireMessage};
use agenc_relay_e2ee::federation::frames::{CompanionFrame, Correlation};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::{ArcFederationOpcode, ArcFederationRequest};
use agenc_relay_e2ee::tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, Writer};
use agenc_relay_e2ee::wire::assembly::{AssemblyKey, Direction, Ingest, QuotaScopes, Sender};
use agenc_relay_e2ee::wire::carrier::CarrierCommand;
use agenc_relay_e2ee::wire::command::{
    ClientCommand, EgroupCommand, EkeyCommand, MailboxKind, SubmitKind, parse_command,
};
use agenc_relay_e2ee::wire::fragment::{FragmentTag, fragment_object, fragment_tag_of};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_e2ee::wire::response::{render_fail, render_labeled_fail};
use agenc_relay_types::ChannelInstanceId;

use crate::connection::ConnectionGeneration;

use super::{ClientOutput, E2eeEdge, Ingress, PendingRequest, SessionFacts};
use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;

/// The capability every E2EE line requires.
pub const E2EE_CAPABILITY: &str = "agenc.ag/e2ee-mls";
/// The client-only fragment tag key as the client sends it.
const CLIENT_FRAGMENT_KEY: &str = "+agenc.ag/e2ee";

/// One client command resolved against the edge's base replica: channel
/// names became channel instances, and a bound-channel `TAGMSG` became the
/// channel application carrier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Resolved {
    /// A command the coordinator executes as parsed.
    Command(ClientCommand),
    /// `RESERVE CHANNEL` or `QUERY CHANNEL` with the resolved instance.
    ChannelRoute {
        opcode: ArcFederationOpcode,
        instance: ChannelInstanceId,
        name: Vec<u8>,
    },
    /// A bound-channel `TAGMSG` application frame.
    ChannelApplication {
        conversation_id: [u8; 32],
        channel: ChannelInstanceId,
    },
}

impl Resolved {
    /// The carrier an object on this command rides, if any.
    pub(crate) fn carrier(&self) -> Option<CarrierCommand> {
        match self {
            Self::Command(command) => command.carrier(),
            Self::ChannelRoute { .. } => None,
            Self::ChannelApplication { .. } => Some(CarrierCommand::Tagmsg),
        }
    }

    /// The normalized route of the assembly tuple (11.8).
    pub(crate) fn route_key(&self) -> [u8; 32] {
        match self {
            Self::Command(ClientCommand::Edirect(conversation))
            | Self::ChannelApplication {
                conversation_id: conversation,
                ..
            } => *conversation,
            Self::Command(ClientCommand::Egroup(
                EgroupCommand::Submit {
                    conversation_id, ..
                }
                | EgroupCommand::SubmitRecoveryElement {
                    conversation_id, ..
                }
                | EgroupCommand::Close {
                    conversation_id, ..
                },
            )) => *conversation_id,
            _ => [0; 32],
        }
    }
}

/// Why a client line was refused, with the context the failure line copies.
pub(super) struct Refusal {
    pub(super) code: E2eeReplyCode,
    pub(super) context: Option<String>,
}

impl From<E2eeReplyCode> for Refusal {
    fn from(code: E2eeReplyCode) -> Self {
        Self {
            code,
            context: None,
        }
    }
}

/// Whether `message` is an E2EE line this router owns: the three extension
/// commands, or a `TAGMSG` carrying the fragment tag.
#[must_use]
pub fn is_e2ee_line(message: &ParsedMessage) -> bool {
    matches!(message.command(), "EGROUP" | "EKEY" | "EDIRECT")
        || (message.command() == "TAGMSG"
            && message
                .tags()
                .iter()
                .any(|tag| tag.key() == CLIENT_FRAGMENT_KEY))
}

impl E2eeEdge {
    /// Handles one E2EE client line; returns the frames for the connection.
    pub fn client_line(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        generation: ConnectionGeneration,
        message: &ParsedMessage,
        facts: &SessionFacts<'_>,
    ) -> Vec<ClientOutput> {
        match self.accept_line(context, edge, generation, message, facts) {
            Ok(outputs) => outputs,
            Err(refusal) => {
                self.counters.refusals = self.counters.refusals.saturating_add(1);
                self.refuse(generation, message, &refusal)
            }
        }
    }

    /// The `FAIL` line of one refusal, labeled when the line was (11.7).
    pub(super) fn refuse(
        &self,
        generation: ConnectionGeneration,
        message: &ParsedMessage,
        refusal: &Refusal,
    ) -> Vec<ClientOutput> {
        let body = refusal
            .code
            .render_fail(message.command(), refusal.context.as_deref());
        let label = message
            .tags()
            .iter()
            .find(|tag| tag.key() == "label")
            .and_then(|tag| tag.value())
            .filter(|label| agenc_relay_e2ee::wire::tokens::is_safe_label(label));
        let line = match label {
            Some(label) => render_labeled_fail(label, &self.config.server_name, &body),
            None => render_fail(&self.config.server_name, &body),
        }
        .ok()
        .and_then(|line| WireMessage::extension_line(&line).ok());
        match line {
            Some(frame) => vec![ClientOutput {
                generation,
                frames: vec![frame],
            }],
            None => Vec::new(),
        }
    }

    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one function applies the capability account attachment and state gates in the order the companion specifies before the line is parsed and assembled
    fn accept_line(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        generation: ConnectionGeneration,
        message: &ParsedMessage,
        facts: &SessionFacts<'_>,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let now = context.now().get() / 1_000;
        self.replies.expire(now);
        let expired = self.assembler.expire(now);
        self.ingress.retain(|_, open| !expired.contains(&open.key));
        if !facts.capabilities.enabled(E2EE_CAPABILITY) {
            return Err(E2eeReplyCode::CapRequired.into());
        }
        if !self.is_active() {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let command = self.parse_line(edge, message)?;
        if self.witness_blocks(&command) {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let account = facts.account.ok_or(E2eeReplyCode::AccountRequired)?;
        let _ = account;
        let device = self
            .origins
            .get(&generation)
            .and_then(|origin| origin.device);
        if requires_device(&command) && device.is_none() {
            return Err(E2eeReplyCode::DeviceRequired.into());
        }
        if !self.origins.get(&generation).is_some_and(settled) {
            return Err(E2eeReplyCode::Syncing.into());
        }
        let label = message
            .tags()
            .iter()
            .find(|tag| tag.key() == "label")
            .and_then(|tag| tag.value())
            .filter(|label| agenc_relay_e2ee::wire::tokens::is_safe_label(label))
            .map(str::to_owned);
        let tags: Vec<(&str, &str)> = message
            .tags()
            .iter()
            .filter_map(|tag| tag.value().map(|value| (tag.key(), value)))
            .collect();
        let fragment = fragment_tag_of(&tags)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?
            .map(|(_, raw)| FragmentTag::parse(raw))
            .transpose()
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        match (command.carrier(), fragment) {
            (Some(carrier), Some(tag)) => {
                let session = device.map_or(0, |(_, session)| session);
                let key = (
                    generation.get(),
                    session,
                    *tag.object_id.as_bytes(),
                    request_scope(&command)?,
                );
                if tag.part == 0 {
                    // A new fragment zero ends the retry the connection held.
                    self.retried.remove(&generation);
                }
                if tag.part == 0
                    && let Some(output) = self.replies.replay(key, &command, label.as_deref())?
                {
                    self.retried.insert(generation, *tag.object_id.as_bytes());
                    return Ok(vec![output]);
                }
                if tag.part == 0
                    && let Some(pending) = self
                        .pending
                        .values_mut()
                        .find(|pending| pending.reply_key == Some(key))
                {
                    pending.retry_label = Some(label.clone());
                    self.retried.insert(generation, *tag.object_id.as_bytes());
                }
                if tag.part == 0
                    && !self.ingress.contains_key(&generation)
                    && !self
                        .pending
                        .values()
                        .any(|pending| pending.reply_key == Some(key))
                    && !self.replies.admits(self.pending.len())
                {
                    return Err(E2eeReplyCode::RateLimited.into());
                }
                let payload = self.ingest(generation, facts, &command, carrier, &tag, context)?;
                match payload {
                    Some(bytes) => self
                        .send_request(
                            context,
                            edge,
                            generation,
                            account,
                            label,
                            command,
                            Some(bytes),
                        )
                        .map(|()| Vec::new()),
                    None => Ok(Vec::new()),
                }
            }
            (Some(_), None) | (None, Some(_)) => Err(E2eeReplyCode::InvalidFragment.into()),
            (None, None) => self
                .send_request(context, edge, generation, account, label, command, None)
                .map(|()| Vec::new()),
        }
    }

    /// Parses the extension command, resolving a bound-channel `TAGMSG` to
    /// its channel application carrier.
    fn parse_line(
        &self,
        edge: &EdgeFederation,
        message: &ParsedMessage,
    ) -> Result<Resolved, Refusal> {
        let params: Vec<&str> = message
            .middle()
            .iter()
            .map(String::as_str)
            .chain(message.trailing())
            .collect();
        if message.command() == "TAGMSG" {
            let [target] = params.as_slice() else {
                return Err(E2eeReplyCode::RouteInvalid.into());
            };
            let (channel_id, conversation) = self
                .bound_channel(edge, target)
                .ok_or(E2eeReplyCode::RouteInvalid)?;
            return Ok(Resolved::ChannelApplication {
                conversation_id: conversation,
                channel: channel_id,
            });
        }
        let command = parse_command(message.command(), &params)
            .map_err(|_| Refusal::from(E2eeReplyCode::InvalidFragment))?;
        let (opcode, name) = match &command {
            ClientCommand::Egroup(EgroupCommand::ReserveChannel(name)) => {
                (ArcFederationOpcode::ReserveChannel, name)
            }
            ClientCommand::Egroup(EgroupCommand::QueryChannel(name)) => {
                (ArcFederationOpcode::QueryChannel, name)
            }
            _ => return Ok(Resolved::Command(command)),
        };
        let text = std::str::from_utf8(name).map_err(|_| E2eeReplyCode::RouteInvalid)?;
        let parsed = agenc_relay_domain::ChannelNameValue::parse(text)
            .map_err(|_| E2eeReplyCode::RouteInvalid)?;
        let instance = edge
            .replica()
            .channel_by_name(&parsed)
            .map(|record| record.channel_id)
            .ok_or(E2eeReplyCode::RouteInvalid)?;
        Ok(Resolved::ChannelRoute {
            opcode,
            instance,
            name: name.clone(),
        })
    }

    /// Whether a durable `witness/v1` row still blocks the conversation this
    /// command names, including one an unresolvable fork blocked for good
    /// (companion 12.5.1).
    pub(super) fn witness_blocks(&self, command: &Resolved) -> bool {
        let named = match command {
            Resolved::ChannelRoute { instance, .. } => self
                .routes
                .channel_route(instance)
                .map(|route| route.conversation_id.0),
            other => Some(other.route_key()),
        };
        named.is_some_and(|conversation| self.blocked_conversation(&conversation))
    }

    /// The channel instance and conversation of a bound channel name.
    pub(super) fn bound_channel(
        &self,
        edge: &EdgeFederation,
        target: &str,
    ) -> Option<(ChannelInstanceId, [u8; 32])> {
        let name = agenc_relay_domain::ChannelNameValue::parse(target).ok()?;
        let record = edge.replica().channel_by_name(&name)?;
        let route = self.routes.channel_route(&record.channel_id)?;
        Some((record.channel_id, route.conversation_id.0))
    }

    /// Feeds one fragment to the sender's one in-progress assembly.
    fn ingest(
        &mut self,
        generation: ConnectionGeneration,
        facts: &SessionFacts<'_>,
        command: &Resolved,
        carrier: CarrierCommand,
        tag: &FragmentTag,
        context: &StateCoreContext,
    ) -> Result<Option<Vec<u8>>, Refusal> {
        let session_generation = self
            .origins
            .get(&generation)
            .and_then(|origin| origin.device)
            .map_or(0, |(_, session)| session);
        let key = AssemblyKey {
            direction: Direction::LocalIngress,
            sender: Sender::Connection {
                connection: generation.get(),
                session_generation,
            },
            command: carrier,
            route: request_scope(command)?,
            scope: None,
            object_id: tag.object_id,
        };
        if let Some(open) = self.ingress.get(&generation)
            && (open.key != key || open.command != *command)
        {
            return Err(E2eeReplyCode::ReassemblyLimit.into());
        }
        let scopes = QuotaScopes {
            connection: Some(generation.get()),
            account: facts.account.and_then(|account| {
                agenc_relay_e2ee::ids::account_id_digest(&self.config.network_id, &account).ok()
            }),
            route: Some(command.route_key()),
            peer: None,
        };
        let now = context.now().get() / 1_000;
        match self
            .assembler
            .ingest(key.clone(), scopes, carrier.limit(), tag, now)
        {
            Ok(Ingest::Complete(bytes)) => {
                self.ingress.remove(&generation);
                Ok(Some(bytes))
            }
            Ok(Ingest::Incomplete) => {
                self.ingress.entry(generation).or_insert(Ingress {
                    key,
                    command: command.clone(),
                });
                Ok(None)
            }
            Ok(Ingest::Duplicate) => Ok(None),
            Ok(Ingest::Recent) => {
                let scope = request_scope(command)?;
                let pending = self.pending.values().any(|request| {
                    request.reply_key
                        == Some((
                            generation.get(),
                            session_generation,
                            *tag.object_id.as_bytes(),
                            scope,
                        ))
                        && request.command == *command
                });
                if pending || tag.part != 0 {
                    Ok(None)
                } else {
                    Err(E2eeReplyCode::RateLimited.into())
                }
            }
            Err(error) => {
                self.ingress.remove(&generation);
                Err(error.reply_code().into())
            }
        }
    }

    /// Encodes and sends one request under the connection's origin.
    // agenc-review: allow owner=runtime reviewed=2026-09-03 reason=one request needs the context the edge the connection its account label command and payload together
    #[allow(clippy::too_many_arguments)]
    fn send_request(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        generation: ConnectionGeneration,
        _account: [u8; 24],
        label: Option<String>,
        command: Resolved,
        payload: Option<Vec<u8>>,
    ) -> Result<(), Refusal> {
        if !self.replies.admits(self.pending.len()) {
            return Err(E2eeReplyCode::RateLimited.into());
        }
        let origin = self
            .origins
            .get_mut(&generation)
            .filter(|origin| settled(origin))
            .ok_or(E2eeReplyCode::Syncing)?;
        let mut request_id = [0; 16];
        context
            .entropy_mut()
            .fill_exact(&mut request_id)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        let payload_id = payload
            .as_ref()
            .map(|bytes| {
                agenc_relay_e2ee::ObjectId::compute(bytes)
                    .as_bytes()
                    .to_vec()
            })
            .unwrap_or_default();
        let (opcode, parameters) =
            encode_parameters(&command).map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let request = ArcFederationRequest {
            profile_version: 1,
            network_id: self.config.network_id,
            home_server_id: *self.config.server_id.as_bytes(),
            server_incarnation: self.config.incarnation,
            origin_id: origin.origin_id,
            origin_generation: origin.acked.unwrap_or(0),
            operation_sequence: origin.next_sequence,
            request_id,
            opcode,
            encoded_parameters: Opaque::new(parameters)
                .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            payload_object_id: Opaque::new(payload_id)
                .map_err(|_| E2eeReplyCode::InvalidFragment)?,
        };
        let bytes = request
            .encode()
            .and_then(|body| ArcWireObject::new(ArcWireObjectKind::FederationRequest, body))
            .and_then(|object| object.encode())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let correlation = Correlation {
            peer_server_id: *self.config.coordinator_server_id.as_bytes(),
            server_incarnation: self.config.incarnation,
            origin_id: origin.origin_id,
            origin_generation: origin.acked.unwrap_or(0),
            operation_sequence: origin.next_sequence,
            request_id,
        };
        origin.next_sequence = origin.next_sequence.saturating_add(1);
        let request_object_id = *agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes();
        let subject = subject_of(&command, payload.as_deref());
        let reply_scope = request_scope(&command)?;
        let reply_key = payload.as_ref().map(|bytes| {
            (
                generation.get(),
                origin.device.map_or(0, |(_, session)| session),
                *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes(),
                reply_scope,
            )
        });
        let mut frames = Vec::new();
        for fragment in fragment_object(&bytes).map_err(|_| E2eeReplyCode::ObjectTooLarge)? {
            frames.push(CompanionFrame::Request {
                correlation,
                object_id: request_object_id,
                fragment,
            });
        }
        if let Some(bytes) = &payload {
            let object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
            for fragment in fragment_object(bytes).map_err(|_| E2eeReplyCode::ObjectTooLarge)? {
                frames.push(CompanionFrame::Payload {
                    correlation,
                    object_id,
                    fragment,
                });
            }
        }
        let lines = frames
            .iter()
            .map(|frame| self.line(frame))
            .collect::<Result<Vec<_>, _>>()?;
        self.pending.insert(
            request_id,
            PendingRequest {
                reply_key,
                echo_lines: Vec::new(),
                retry_label: None,
                generation,
                label,
                command,
                subject,
                request_object_id,
                sequence: correlation.operation_sequence,
                origin_generation: correlation.origin_generation,
                frames,
                result: None,
                result_object_id: None,
                responses: std::collections::BTreeMap::new(),
                completion_seen: false,
                rendered: false,
            },
        );
        self.counters.requests_sent = self.counters.requests_sent.saturating_add(1);
        if !self.send(context, edge, lines) {
            return Err(E2eeReplyCode::Syncing.into());
        }
        Ok(())
    }

    /// Renders one companion frame under the edge's name.
    pub(super) fn line(
        &self,
        frame: &CompanionFrame,
    ) -> Result<agenc_relay_federation_wire::FederationLineText, Refusal> {
        let text = frame
            .render(&self.config.server_name)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        agenc_relay_federation_wire::FederationLineText::from_rendered(text)
            .map_err(|_| E2eeReplyCode::InvalidFragment.into())
    }
}

/// Whether the command needs a connection-bound attached device (11.6).
/// The identifier a `STORED` success line names besides the object: the
/// candidate of a submitted approval, the policy identifier of a published
/// policy (11.7).
fn subject_of(command: &Resolved, payload: Option<&[u8]>) -> Option<[u8; 32]> {
    use agenc_relay_e2ee::objects::conversation::{ArcCommitApprovalEnvelope, ArcPolicy};
    let Resolved::Command(ClientCommand::Egroup(EgroupCommand::Submit { kind, .. })) = command
    else {
        return None;
    };
    let bytes = payload?;
    let (expected, limit) = match kind {
        SubmitKind::Authorization => (
            ArcWireObjectKind::CommitApproval,
            agenc_relay_e2ee::limits::MAX_COMMIT_APPROVAL_OBJECT,
        ),
        SubmitKind::Policy => (
            ArcWireObjectKind::Policy,
            agenc_relay_e2ee::limits::MAX_POLICY_OBJECT,
        ),
        SubmitKind::Membership => (
            ArcWireObjectKind::LeafMembershipProof,
            agenc_relay_e2ee::limits::MAX_LEAF_MEMBERSHIP_OBJECT,
        ),
        _ => return None,
    };
    let mut budget = DecodeBudget::new(limit, 1 << 16);
    let object = ArcWireObject::decode_kind(bytes, Some(expected), &mut budget).ok()?;
    match kind {
        SubmitKind::Authorization => {
            let envelope =
                ArcCommitApprovalEnvelope::decode_exact(object.body(), &mut budget).ok()?;
            Some(envelope.tbs.candidate_id)
        }
        SubmitKind::Policy => {
            let policy = ArcPolicy::decode_exact(object.body(), &mut budget).ok()?;
            agenc_relay_e2ee::ids::semantic_id_of(
                agenc_relay_crypto::SemanticHashDomain::PolicyId,
                &policy.tbs,
            )
            .ok()
        }
        SubmitKind::Membership => {
            let proof =
                agenc_relay_e2ee::objects::membership::ArcLeafMembershipProof::decode_exact(
                    object.body(),
                    &mut budget,
                )
                .ok()?;
            agenc_relay_e2ee::ids::semantic_id_of(
                agenc_relay_crypto::SemanticHashDomain::LeafMembershipId,
                &proof.tbs,
            )
            .ok()
        }
        _ => None,
    }
}

/// Whether the coordinator holds this origin's current declaration: the
/// declared generation is acknowledged and no attachment awaits the
/// declaration of the advanced base generation.
pub(super) fn settled(origin: &super::LocalOrigin) -> bool {
    origin.acked.is_some() && origin.acked == origin.declared && origin.predates_device.is_none()
}

fn requires_device(command: &Resolved) -> bool {
    let Resolved::Command(command) = command else {
        return matches!(command, Resolved::ChannelApplication { .. });
    };
    !matches!(
        command,
        ClientCommand::Ekey(
            EkeyCommand::Whoami
                | EkeyCommand::AttachBegin(_)
                | EkeyCommand::AttachFinish(_)
                | EkeyCommand::PublishIdentity
                | EkeyCommand::PublishRoster
                | EkeyCommand::FetchIdentity(_)
                | EkeyCommand::FetchRootChain { .. }
                | EkeyCommand::FetchRoster(_)
                | EkeyCommand::FetchCapabilities { .. }
                | EkeyCommand::FetchBindingLocks { .. }
        ) | ClientCommand::Egroup(EgroupCommand::QueryChannel(_) | EgroupCommand::QueryDirect(_))
    )
}

fn account(writer: &mut Writer, account: &[u8; 24]) -> Result<(), agenc_relay_e2ee::E2eeError> {
    writer.opaque(account, 1, 255)
}

fn cursor(
    writer: &mut Writer,
    cursor: Option<[u8; 32]>,
) -> Result<(), agenc_relay_e2ee::E2eeError> {
    writer.opaque(cursor.as_ref().map_or(&[][..], |cursor| &cursor[..]), 0, 32)
}

const fn mailbox_kind(kind: MailboxKind) -> u8 {
    match kind {
        MailboxKind::Application => 1,
        MailboxKind::Binding => 2,
        MailboxKind::Welcome => 3,
        MailboxKind::StagedReinit => 4,
    }
}

const fn submit_opcode(kind: SubmitKind) -> ArcFederationOpcode {
    use ArcFederationOpcode as Op;
    match kind {
        SubmitKind::Candidate => Op::SubmitCandidate,
        SubmitKind::Authorization => Op::SubmitAuthorization,
        SubmitKind::Ack => Op::SubmitCommitAck,
        SubmitKind::Finalization => Op::SubmitFinalization,
        SubmitKind::Policy => Op::SubmitPolicy,
        SubmitKind::Membership => Op::SubmitMembership,
        SubmitKind::Recovery => Op::SubmitRecovery,
        SubmitKind::Abort => Op::SubmitAbort,
        SubmitKind::ReinitAttempt => Op::SubmitReinitAttempt,
        SubmitKind::ReinitAck => Op::SubmitReinitAck,
        SubmitKind::ReinitActivate => Op::SubmitReinitActivate,
        SubmitKind::ReinitAbort => Op::SubmitReinitAbort,
    }
}

/// Separates local retries by opcode and the complete canonical parameter
/// tuple, including mailbox recipient and device, without changing route quotas.
pub(super) fn request_scope(command: &Resolved) -> Result<[u8; 32], Refusal> {
    let (opcode, parameters) =
        encode_parameters(command).map_err(|_| E2eeReplyCode::InvalidFragment)?;
    let mut bytes = b"arc-mls-v1/local-command/v1\0".to_vec();
    bytes.extend_from_slice(&opcode.value().to_be_bytes());
    bytes.extend_from_slice(&parameters);
    Ok(*agenc_relay_e2ee::ObjectId::compute(&bytes).as_bytes())
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match writes every 12.5 parameter tuple beside the opcode it belongs to; splitting it would separate the encodings from the opcode table
/// The opcode and the exact encoded parameter tuple of one command.
pub(super) fn encode_parameters(
    command: &Resolved,
) -> Result<(ArcFederationOpcode, Vec<u8>), agenc_relay_e2ee::E2eeError> {
    use ArcFederationOpcode as Op;
    let mut writer = Writer::new();
    let command = match command {
        Resolved::ChannelApplication {
            conversation_id,
            channel,
        } => {
            writer.fixed(conversation_id)?;
            writer.fixed(channel.as_bytes())?;
            return Ok((Op::ApplicationChannel, writer.into_bytes()));
        }
        Resolved::ChannelRoute {
            opcode,
            instance,
            name,
        } => {
            writer.fixed(instance.as_bytes())?;
            writer.opaque(name, 1, 255)?;
            return Ok((*opcode, writer.into_bytes()));
        }
        Resolved::Command(command) => command,
    };
    let opcode = match command {
        ClientCommand::Edirect(conversation_id) => {
            writer.fixed(conversation_id)?;
            Op::ApplicationDirect
        }
        ClientCommand::Egroup(
            EgroupCommand::ReserveChannel(_) | EgroupCommand::QueryChannel(_),
        ) => return Err(agenc_relay_e2ee::E2eeError::InvalidValue),
        ClientCommand::Egroup(EgroupCommand::ReserveDirect(peer)) => {
            account(&mut writer, peer)?;
            Op::ReserveDirect
        }
        ClientCommand::Egroup(EgroupCommand::Bind {
            reservation_id,
            conversation_id,
            context_digest,
        }) => {
            writer.fixed(reservation_id)?;
            writer.fixed(conversation_id)?;
            writer.fixed(context_digest)?;
            Op::BindGroup
        }
        ClientCommand::Egroup(EgroupCommand::QueryDirect(peer)) => {
            account(&mut writer, peer)?;
            Op::QueryDirect
        }
        ClientCommand::Egroup(EgroupCommand::Close {
            conversation_id,
            reason_code,
        }) => {
            writer.fixed(conversation_id)?;
            writer.u16(*reason_code)?;
            Op::CloseGroup
        }
        ClientCommand::Egroup(EgroupCommand::Submit {
            kind,
            conversation_id,
        }) => {
            writer.fixed(conversation_id)?;
            submit_opcode(*kind)
        }
        ClientCommand::Egroup(EgroupCommand::SubmitRecoveryElement {
            conversation_id,
            submission_id,
        }) => {
            writer.fixed(conversation_id)?;
            writer.fixed(submission_id)?;
            Op::SubmitRecoveryElement
        }
        ClientCommand::Egroup(EgroupCommand::FetchObject {
            conversation_id,
            object_id,
        }) => {
            writer.fixed(conversation_id)?;
            writer.fixed(object_id)?;
            Op::FetchObject
        }
        ClientCommand::Egroup(EgroupCommand::FetchAuthorizations {
            conversation_id,
            candidate_id,
            cursor: next,
        }) => {
            writer.fixed(conversation_id)?;
            writer.fixed(candidate_id)?;
            cursor(&mut writer, *next)?;
            Op::FetchAuthorizations
        }
        ClientCommand::Egroup(EgroupCommand::FetchAcks {
            conversation_id,
            selector,
            cursor: next,
        }) => {
            writer.fixed(conversation_id)?;
            writer.fixed(selector)?;
            cursor(&mut writer, *next)?;
            Op::FetchAcks
        }
        ClientCommand::Egroup(EgroupCommand::FetchReceipts {
            conversation_id,
            first_route_sequence,
            cursor: next,
        }) => {
            writer.fixed(conversation_id)?;
            writer.u64(*first_route_sequence)?;
            cursor(&mut writer, *next)?;
            Op::FetchReceipts
        }
        ClientCommand::Ekey(command) => encode_ekey(&mut writer, command)?,
    };
    Ok((opcode, writer.into_bytes()))
}

// agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one match writes every EKEY parameter tuple beside its opcode
fn encode_ekey(
    writer: &mut Writer,
    command: &EkeyCommand,
) -> Result<ArcFederationOpcode, agenc_relay_e2ee::E2eeError> {
    use ArcFederationOpcode as Op;
    Ok(match command {
        EkeyCommand::FetchIdentity(target) => {
            account(writer, target)?;
            Op::FetchIdentity
        }
        EkeyCommand::FetchRootChain {
            account: target,
            first_generation,
            cursor: next,
        } => {
            account(writer, target)?;
            writer.u64(*first_generation)?;
            cursor(writer, *next)?;
            Op::FetchRootChain
        }
        EkeyCommand::PublishIdentity => Op::PublishIdentity,
        EkeyCommand::FetchRoster(target) => {
            account(writer, target)?;
            Op::FetchRoster
        }
        EkeyCommand::PublishRoster => Op::PublishRoster,
        EkeyCommand::FetchCapabilities {
            account: target,
            cursor: next,
        } => {
            account(writer, target)?;
            cursor(writer, *next)?;
            Op::FetchCapabilities
        }
        EkeyCommand::PublishCapabilities(device) => {
            writer.fixed(device)?;
            Op::PublishCapabilities
        }
        EkeyCommand::FetchBindingLocks {
            account: target,
            root_fingerprint,
            first_sequence,
            cursor: next,
        } => {
            account(writer, target)?;
            writer.fixed(root_fingerprint)?;
            writer.u64(*first_sequence)?;
            cursor(writer, *next)?;
            Op::FetchBindingLocks
        }
        EkeyCommand::Whoami => Op::Whoami,
        EkeyCommand::AttachBegin(device) => {
            writer.fixed(device)?;
            Op::AttachBegin
        }
        EkeyCommand::AttachFinish(device) => {
            writer.fixed(device)?;
            Op::AttachFinish
        }
        EkeyCommand::ClaimPackage {
            account: target,
            device_id,
            suite,
            operation_id,
        } => {
            account(writer, target)?;
            writer.fixed(device_id)?;
            writer.u16(*suite)?;
            writer.fixed(operation_id)?;
            Op::ClaimPackage
        }
        EkeyCommand::ClaimStatus(operation_id) => {
            writer.fixed(operation_id)?;
            Op::ClaimStatus
        }
        EkeyCommand::PublishPackage {
            device_id,
            suite,
            expires_at,
        } => {
            writer.fixed(device_id)?;
            writer.u16(*suite)?;
            writer.u64(*expires_at)?;
            Op::PublishPackage
        }
        EkeyCommand::RevokePackage(reference) => {
            writer.opaque(reference, 1, 255)?;
            Op::RevokePackage
        }
        EkeyCommand::DeliverBinding {
            account: target,
            device_id,
        } => {
            account(writer, target)?;
            writer.fixed(device_id)?;
            Op::DeliverBinding
        }
        EkeyCommand::DeliverWelcome {
            account: target,
            device_id,
            conversation_id,
            authorization_id,
        } => {
            account(writer, target)?;
            writer.fixed(device_id)?;
            writer.fixed(conversation_id)?;
            writer.fixed(authorization_id)?;
            Op::DeliverWelcome
        }
        EkeyCommand::FetchMailbox { kind, cursor: next } => {
            writer.u8(mailbox_kind(*kind))?;
            cursor(writer, *next)?;
            Op::FetchMailbox
        }
        EkeyCommand::AckMailbox {
            delivery_token,
            object_id,
        } => {
            writer.fixed(delivery_token)?;
            writer.fixed(object_id)?;
            Op::AcknowledgeMailbox
        }
    })
}
