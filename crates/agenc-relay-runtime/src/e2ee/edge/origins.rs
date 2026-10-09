//! Companion origins on the edge (12.5): each connection's origin mirrors
//! the acknowledged base declaration exactly, adds the device attachment,
//! and is re-declared after every base generation change.

use crate::connection::ConnectionGeneration;
use agenc_relay_crypto::SemanticHashDomain;
use agenc_relay_e2ee::federation::frames::CompanionFrame;
use agenc_relay_e2ee::ids::semantic_id_of;
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::ArcFederationOrigin;
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_e2ee::wire::fragment::fragment_object;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::router::Refusal;
use super::{E2eeEdge, LocalOrigin, Phase};
use crate::federation::edge::{BaseOriginFacts, EdgeFederation};
use crate::state_core::StateCoreContext;

#[cfg(test)]
#[path = "tests/origins.rs"]
mod tests;

/// The user and account one declaration names.
pub(crate) type Principal = (Option<agenc_relay_types::UserId>, Option<[u8; 24]>);

/// The attachment a declaration naming `principal` carries: the
/// connection's device while the session and account it was attached under
/// still hold, and none once a logout, an account switch or a replaced
/// session ended it (companion 11.6: these invalidate the attachment).
fn attachment(origin: &LocalOrigin, principal: Principal) -> Option<([u8; 16], u64)> {
    origin
        .device
        .filter(|_| origin.device_principal == Some(principal))
}

impl E2eeEdge {
    /// Declares or re-declares every origin whose acknowledged base
    /// generation is ahead of its companion declaration.
    pub fn declare_origins(&mut self, context: &mut StateCoreContext, edge: &mut EdgeFederation) {
        if !matches!(self.phase, Phase::Origins | Phase::Active) {
            return;
        }
        let generations: Vec<ConnectionGeneration> = edge.connection_generations();
        for generation in generations {
            let Some(facts) = edge.origin_facts(generation) else {
                continue;
            };
            let Some(acked) = facts.acked_generation else {
                continue;
            };
            let declared = self
                .origins
                .get(&generation)
                .and_then(|origin| origin.declared);
            if declared == Some(acked) {
                continue;
            }
            if let Err(_refusal) = self.declare_origin(context, edge, generation, &facts, acked) {
                self.counters.violations = self.counters.violations.saturating_add(1);
            }
        }
    }

    /// Sends one EORIGIN ADD or UPDATE mirroring the base declaration at
    /// `base_generation`.
    // agenc-review: focus owner=runtime reviewed=2026-09-03 reason=one function fills every field of the companion origin object from the base facts in the 12.5 field order so the mirror stays reviewable against the table
    fn declare_origin(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        generation: ConnectionGeneration,
        facts: &BaseOriginFacts,
        base_generation: u64,
    ) -> Result<(), Refusal> {
        let replay = self.origins.get_mut(&generation).and_then(|origin| {
            let (cached_generation, bytes) = origin.declaration.as_ref()?;
            if origin.origin_id != facts.origin_id || *cached_generation != base_generation {
                return None;
            }
            origin.declared = Some(base_generation);
            Some(bytes.clone())
        });
        if let Some(bytes) = replay {
            let lines = self.origin_lines(facts.origin_id, base_generation, &bytes)?;
            return self
                .send(context, edge, lines)
                .then_some(())
                .ok_or_else(|| E2eeReplyCode::Syncing.into());
        }
        let previous = self.origins.get(&generation).cloned();
        let previous_state_id = previous.as_ref().map_or([0; 32], |origin| origin.state_id);
        let principal = (
            facts
                .session
                .map(|(_, user)| agenc_relay_types::UserId::from_bytes(user)),
            facts.account.map(|(account, _)| account),
        );
        let device = previous
            .as_ref()
            .and_then(|origin| attachment(origin, principal));
        if device.is_none()
            && previous
                .as_ref()
                .is_some_and(|origin| origin.device.is_some())
        {
            self.attachment_ended(generation);
        }
        let object = ArcFederationOrigin {
            profile_version: 1,
            network_id: self.config.network_id,
            home_server_id: *self.config.server_id.as_bytes(),
            server_incarnation: self.config.incarnation,
            origin_id: facts.origin_id,
            origin_generation: base_generation,
            previous_origin_state_id: if base_generation == 0 {
                [0; 32]
            } else {
                previous_state_id
            },
            connection_id: facts.connection_id,
            session_id: Opaque::new(
                facts
                    .session
                    .map(|(session, _)| session.to_vec())
                    .unwrap_or_default(),
            )
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            user_id: Opaque::new(
                facts
                    .session
                    .map(|(_, user)| user.to_vec())
                    .unwrap_or_default(),
            )
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            account_id: Opaque::new(
                facts
                    .account
                    .map(|(account, _)| account.to_vec())
                    .unwrap_or_default(),
            )
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            account_session_generation: facts.account.map_or(0, |(_, generation)| generation),
            connection_nonce: facts.connection_nonce,
            attached_device_id: Opaque::new(
                device
                    .map(|(device, _)| device.to_vec())
                    .unwrap_or_default(),
            )
            .map_err(|_| E2eeReplyCode::InvalidFragment)?,
            device_session_generation: device.map_or(0, |(_, generation)| generation),
        };
        let state_id = semantic_id_of(SemanticHashDomain::FederationOriginState, &object)
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let bytes = object
            .encode()
            .and_then(|body| ArcWireObject::new(ArcWireObjectKind::FederationOrigin, body))
            .and_then(|object| object.encode())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let lines = self.origin_lines(facts.origin_id, base_generation, &bytes)?;
        let entry = self.origins.entry(generation).or_insert(LocalOrigin {
            origin_id: facts.origin_id,
            declared: None,
            acked: None,
            predates_device: None,
            next_sequence: 0,
            sequenced: None,
            state_id: [0; 32],
            declaration: None,
            user_id: None,
            account: None,
            device: None,
            device_principal: None,
        });
        entry.origin_id = facts.origin_id;
        entry.declared = Some(base_generation);
        entry.state_id = state_id;
        entry.declaration = Some((base_generation, bytes));
        (entry.user_id, entry.account) = principal;
        if !self.send(context, edge, lines) {
            return Err(E2eeReplyCode::Syncing.into());
        }
        Ok(())
    }

    /// Renders the retained object under its original descriptor on each link.
    fn origin_lines(
        &self,
        origin_id: [u8; 16],
        base_generation: u64,
        bytes: &[u8],
    ) -> Result<Vec<agenc_relay_federation_wire::FederationLineText>, Refusal> {
        let object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
        let mut lines = Vec::new();
        for fragment in fragment_object(bytes).map_err(|_| E2eeReplyCode::ObjectTooLarge)? {
            lines.push(self.line(&CompanionFrame::OriginState {
                update: base_generation != 0,
                coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
                server_incarnation: self.config.incarnation,
                origin_id,
                origin_generation: base_generation,
                object_id,
                fragment,
            })?);
        }
        Ok(lines)
    }

    /// `EORIGIN ACK`: the declared generation is in force. A new generation
    /// starts its operation sequence at zero; the replayed declaration of
    /// the generation already in force keeps counting, as the coordinator
    /// does. An origin's first acknowledgement on a link already past
    /// EORIGIN READY resends its unanswered requests, as READY resends
    /// those of the origins acknowledged before it.
    pub(super) fn origin_acked(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        origin_id: [u8; 16],
        generation: u64,
        state_object: bool,
    ) -> Result<(), Refusal> {
        if !state_object {
            // A deletion is acknowledged after every request ahead of it ran
            // or was dropped: the closed connection's requests hold no place.
            self.closed_requests
                .retain(|_, (origin, _)| *origin != origin_id);
        }
        let settled = self.acknowledge_origin(origin_id, generation);
        if self.phase == Phase::Active {
            // Only the connections this acknowledgement settled resend, and
            // only their requests named under this generation.
            let order = self.unanswered_of(|connection| settled.contains(connection));
            self.resend_pending(context, edge, order);
        }
        Ok(())
    }

    /// Applies one acknowledged declaration to every origin that declared
    /// `generation`, and returns the connections it settles there: those
    /// whose declaration on the link was not yet acknowledged at that
    /// generation. A repeated acknowledgement settles nothing.
    pub(super) fn acknowledge_origin(
        &mut self,
        origin_id: [u8; 16],
        generation: u64,
    ) -> Vec<ConnectionGeneration> {
        let mut settled = Vec::new();
        for (connection, origin) in self.origins.iter_mut() {
            if origin.origin_id == origin_id && origin.declared == Some(generation) {
                let first = origin.acked != Some(generation);
                origin.acked = Some(generation);
                if origin
                    .predates_device
                    .is_some_and(|stale| generation > stale)
                {
                    origin.predates_device = None;
                }
                if origin.sequenced != Some(generation) {
                    origin.next_sequence = 0;
                    origin.sequenced = Some(generation);
                }
                if first {
                    settled.push(*connection);
                }
            }
        }
        settled
    }

    /// A device attached on `generation`: the shared base origin generation
    /// advances and the companion declaration follows with the device.
    pub fn device_attached(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        generation: ConnectionGeneration,
        device: [u8; 16],
        session_generation: u64,
    ) {
        if let Some(origin) = self.origins.get_mut(&generation) {
            origin.device = Some((device, session_generation));
            // The attachment holds while its principal does (companion 11.6).
            origin.device_principal = Some((origin.user_id, origin.account));
            // The acknowledged declaration predates the device; requests wait
            // for the declaration the advanced base generation carries.
            origin.predates_device = origin.acked;
        }
        edge.advance_origin(context, generation);
    }

    /// Logout, an account switch or a replaced session ended the
    /// connection's attachment: submission under it stops, so its
    /// in-progress object is discarded (companion 11.6, 11.8).
    fn attachment_ended(&mut self, generation: ConnectionGeneration) {
        self.origins.entry(generation).and_modify(|origin| {
            origin.device = None;
            origin.device_principal = None;
        });
        self.retried.remove(&generation);
        if let Some(ingress) = self.ingress.remove(&generation) {
            self.assembler.discard(&ingress.key);
        }
    }

    /// A connection ended: its companion origin is deleted at the generation
    /// the coordinator holds and the next unused sequence under it (12.5).
    /// The coordinator holds the last declaration this link carried, which
    /// precedes the DEL, whether or not its acknowledgement has arrived; a
    /// generation the edge has not sequenced yet starts at zero. An origin
    /// no declaration on the live link names sends no DEL; either way the
    /// connection's companion state is released.
    pub fn delete_origin(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        generation: ConnectionGeneration,
    ) {
        let deletion = self.origins.get(&generation).and_then(|origin| {
            let declared = origin.declared?;
            let next_operation_sequence = if origin.sequenced == Some(declared) {
                origin.next_sequence
            } else {
                0
            };
            Some((
                origin.origin_id,
                CompanionFrame::OriginDel {
                    coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
                    server_incarnation: self.config.incarnation,
                    origin_id: origin.origin_id,
                    origin_generation: declared,
                    next_operation_sequence,
                },
            ))
        });
        let line = deletion.map(|(origin_id, frame)| (origin_id, self.line(&frame)));
        let deleted = match line {
            Some((origin_id, Ok(line))) => {
                self.send(context, edge, vec![line]).then_some(origin_id)
            }
            _ => None,
        };
        if let Some(origin_id) = deleted {
            // The coordinator runs or drops the connection's requests ahead
            // of the deletion and may still hold them queued: the unanswered
            // ones keep their places in the outstanding bounds (companion
            // 16) until a frame of their result arrives, the deletion is
            // acknowledged or the link ends.
            for (request_id, pending) in &self.pending {
                if pending.generation == generation && pending.result.is_none() {
                    self.closed_requests
                        .insert(*request_id, (origin_id, pending.account));
                }
            }
        }
        self.connection_closed(generation);
    }
}
