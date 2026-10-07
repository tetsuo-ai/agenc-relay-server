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
        let device = previous.as_ref().and_then(|origin| origin.device);
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
        });
        entry.origin_id = facts.origin_id;
        entry.declared = Some(base_generation);
        entry.state_id = state_id;
        entry.declaration = Some((base_generation, bytes));
        entry.user_id = facts
            .session
            .map(|(_, user)| agenc_relay_types::UserId::from_bytes(user));
        entry.account = facts.account.map(|(account, _)| account);
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
        _state_object: bool,
    ) -> Result<(), Refusal> {
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
    /// `generation`, and returns the connections it settles there.
    pub(super) fn acknowledge_origin(
        &mut self,
        origin_id: [u8; 16],
        generation: u64,
    ) -> Vec<ConnectionGeneration> {
        let mut settled = Vec::new();
        for (connection, origin) in self.origins.iter_mut() {
            if origin.origin_id == origin_id && origin.declared == Some(generation) {
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
                settled.push(*connection);
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
            // The acknowledged declaration predates the device; requests wait
            // for the declaration the advanced base generation carries.
            origin.predates_device = origin.acked;
        }
        edge.advance_origin(context, generation);
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
            Some(CompanionFrame::OriginDel {
                coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
                server_incarnation: self.config.incarnation,
                origin_id: origin.origin_id,
                origin_generation: declared,
                next_operation_sequence,
            })
        });
        if let Some(Ok(line)) = deletion.map(|frame| self.line(&frame)) {
            self.send(context, edge, vec![line]);
        }
        self.connection_closed(generation);
    }
}
