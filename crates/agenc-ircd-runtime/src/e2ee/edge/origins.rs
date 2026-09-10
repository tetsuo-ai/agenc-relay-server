//! Companion origins on the edge (12.5): each connection's origin mirrors
//! the acknowledged base declaration exactly, adds the device attachment,
//! and is re-declared after every base generation change.

use crate::connection::ConnectionGeneration;
use agenc_ircd_crypto::SemanticHashDomain;
use agenc_ircd_e2ee::federation::frames::CompanionFrame;
use agenc_ircd_e2ee::ids::semantic_id_of;
use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
use agenc_ircd_e2ee::objects::federation::IrcFederationOrigin;
use agenc_ircd_e2ee::tls::{Opaque, TlsEncode};
use agenc_ircd_e2ee::wire::fragment::fragment_object;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

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
        let object = IrcFederationOrigin {
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
            .and_then(|body| IrcWireObject::new(IrcWireObjectKind::FederationOrigin, body))
            .and_then(|object| object.encode())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let lines = self.origin_lines(facts.origin_id, base_generation, &bytes)?;
        let entry = self.origins.entry(generation).or_insert(LocalOrigin {
            origin_id: facts.origin_id,
            declared: None,
            acked: None,
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
            .map(|(_, user)| agenc_ircd_types::UserId::from_bytes(user));
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
    ) -> Result<Vec<agenc_ircd_federation_wire::FederationLineText>, Refusal> {
        let object_id = *agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes();
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
    /// does.
    pub(super) fn origin_acked(
        &mut self,
        _context: &mut StateCoreContext,
        _edge: &mut EdgeFederation,
        origin_id: [u8; 16],
        generation: u64,
        _state_object: bool,
    ) -> Result<(), Refusal> {
        self.acknowledge_origin(origin_id, generation);
        Ok(())
    }

    /// Applies one acknowledged declaration to every origin that declared
    /// `generation`.
    pub(super) fn acknowledge_origin(&mut self, origin_id: [u8; 16], generation: u64) {
        for origin in self.origins.values_mut() {
            if origin.origin_id == origin_id && origin.declared == Some(generation) {
                origin.acked = Some(generation);
                if origin.sequenced != Some(generation) {
                    origin.next_sequence = 0;
                    origin.sequenced = Some(generation);
                }
            }
        }
    }

    /// A connection ended: its companion origin is deleted at the next
    /// unused sequence.
    pub fn delete_origin(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        generation: ConnectionGeneration,
    ) {
        let Some(origin) = self.origins.remove(&generation) else {
            return;
        };
        let Some(acked) = origin.acked else {
            return;
        };
        if let Ok(line) = self.line(&CompanionFrame::OriginDel {
            coordinator_server_id: *self.config.coordinator_server_id.as_bytes(),
            server_incarnation: self.config.incarnation,
            origin_id: origin.origin_id,
            origin_generation: acked,
            next_operation_sequence: origin.next_sequence,
        }) {
            self.send(context, edge, vec![line]);
        }
        self.connection_closed(generation);
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
        }
        edge.advance_origin(context, generation);
    }
}
