//! Generation-bound live outputs for direct application events (companion 11.6 and 12.5).
//! The coordinator owns the current attachment. Its ordinary authenticated WHOAMI
//! result verifies a local origin without adding recipient identities to events.

use super::events::OpenEvent;
use super::router::{Refusal, RequestSource, Resolved, settled};
use super::{ClientOutput, E2eeEdge, LocalOrigin, ResultValue};
use crate::budget::MemoryPermit;
use crate::connection::ConnectionGeneration;
use crate::federation::edge::EdgeFederation;
use crate::state_core::StateCoreContext;
use agenc_relay_e2ee::wire::command::{ClientCommand, EkeyCommand};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_types::UserId;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Sink {
    connection: ConnectionGeneration,
    origin_id: [u8; 16],
    origin_generation: u64,
    user: UserId,
    account: [u8; 24],
    attachment: ([u8; 16], u64),
    verified: bool,
}

impl Sink {
    fn capture(connection: ConnectionGeneration, origin: &LocalOrigin) -> Option<Self> {
        if !settled(origin) {
            return None;
        }
        Some(Self {
            connection,
            origin_id: origin.origin_id,
            origin_generation: origin.acked?,
            user: origin.user_id?,
            account: origin.account?,
            attachment: origin.device?,
            verified: false,
        })
    }

    fn still_bound(&self, router: &E2eeEdge, context: &StateCoreContext) -> bool {
        context.sessions().generation_for_user(self.user) == Some(self.connection)
            && router
                .origins
                .get(&self.connection)
                .and_then(|origin| Self::capture(self.connection, origin))
                .is_some_and(|current| {
                    current
                        == Self {
                            verified: false,
                            ..*self
                        }
                })
    }

    pub(super) fn recipient(
        &self,
        router: &E2eeEdge,
        context: &StateCoreContext,
    ) -> Option<(ConnectionGeneration, UserId)> {
        (self.verified && self.still_bound(router, context)).then_some((self.connection, self.user))
    }
}

pub(crate) struct VerifiedSinks {
    pub(super) sinks: Vec<Sink>,
    _backing: MemoryPermit,
}

impl VerifiedSinks {
    pub(super) fn permits(
        &self,
        output: &ClientOutput,
        router: &E2eeEdge,
        context: &StateCoreContext,
    ) -> bool {
        self.sinks
            .binary_search_by_key(&output.generation, |sink| sink.connection)
            .ok()
            .and_then(|index| self.sinks.get(index))
            .and_then(|sink| sink.recipient(router, context))
            .is_some()
    }
}

pub(super) struct Delivery {
    open: OpenEvent,
    payload: Option<Vec<u8>>,
    sinks: Vec<Sink>,
    index: usize,
    awaiting: Option<[u8; 16]>,
    _backing: MemoryPermit,
}

impl Delivery {
    pub(super) fn sequence(&self) -> u64 {
        self.open.position.delivery_sequence
    }

    fn observe(&mut self, id: [u8; 16], value: &ResultValue) -> Result<(), Refusal> {
        if self.awaiting != Some(id) {
            return Ok(());
        }
        let sink = self
            .sinks
            .get_mut(self.index)
            .ok_or(E2eeReplyCode::Syncing)?;
        match value {
            ResultValue::Account(account, generation) => {
                sink.verified = *account == sink.account
                    && *generation == sink.attachment.1
                    && *generation != 0;
            }
            ResultValue::Failed { code, .. }
                if code == E2eeReplyCode::AccountRequired.token()
                    || code == E2eeReplyCode::DeviceRequired.token() => {}
            _ => return Err(E2eeReplyCode::Syncing.into()),
        }
        self.index += 1;
        self.awaiting = None;
        Ok(())
    }
}

impl E2eeEdge {
    pub(super) fn check_direct_delivery(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
        open: OpenEvent,
        payload: Option<Vec<u8>>,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        let conversation = <[u8; 32]>::try_from(open.event.conversation_id.as_slice())
            .map_err(|_| E2eeReplyCode::InvalidFragment)?;
        let accounts = self
            .conversations
            .get(&conversation)
            .and_then(|known| known.direct)
            .ok_or(E2eeReplyCode::RouteInvalid)?;
        let eligible = || {
            self.origins.iter().filter_map(|(id, origin)| {
                let account = origin.account?;
                if account != accounts.0 && account != accounts.1 {
                    return None;
                }
                Sink::capture(*id, origin)
            })
        };
        let count = eligible().count();
        let bytes = count
            .checked_mul(std::mem::size_of::<Sink>())
            .and_then(|size| size.checked_add(payload.as_ref().map_or(0, Vec::capacity)))
            .ok_or(E2eeReplyCode::RateLimited)?;
        let backing = context
            .reserve_output_backing(bytes.max(1))
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        let mut sinks = Vec::new();
        sinks
            .try_reserve_exact(count)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        sinks.extend(eligible());
        self.direct_delivery = Some(Delivery {
            open,
            payload,
            sinks,
            index: 0,
            awaiting: None,
            _backing: backing,
        });
        self.advance_direct_delivery(context, edge)
    }

    /// The query may outlive its original event across a lost federation link.
    /// Its correlated reply stays internal until the ordinary replay completes.
    pub(super) fn direct_answer(
        &mut self,
        id: [u8; 16],
        value: &ResultValue,
    ) -> Result<bool, Refusal> {
        if self.direct_probe != Some(id) {
            return Ok(false);
        }
        self.direct_probe = None;
        if let Some(delivery) = &mut self.direct_delivery {
            delivery.observe(id, value)?;
        }
        Ok(true)
    }

    pub(super) fn advance_direct_delivery(
        &mut self,
        context: &mut StateCoreContext,
        edge: &mut EdgeFederation,
    ) -> Result<Vec<ClientOutput>, Refusal> {
        if self
            .direct_probe
            .is_some_and(|id| !self.pending.contains_key(&id))
        {
            self.direct_probe = None;
        }
        if self.direct_probe.is_some()
            || context.in_flight()
            || context.pending_len() != 0
            || self.commit.is_some()
        {
            return Ok(Vec::new());
        }
        let Some(mut delivery) = self.direct_delivery.take() else {
            return Ok(Vec::new());
        };
        while let Some(sink) = delivery.sinks.get(delivery.index) {
            if !sink.still_bound(self, context) {
                delivery.index += 1;
                continue;
            }
            let id = self.send_request(
                context,
                edge,
                sink.connection,
                sink.account,
                RequestSource::Attachment,
                Resolved::Command(ClientCommand::Ekey(EkeyCommand::Whoami)),
                None,
            )?;
            delivery.awaiting = Some(id);
            self.direct_delivery = Some(delivery);
            return Ok(Vec::new());
        }
        self.project_ordinary(
            context,
            edge,
            delivery.open,
            delivery.payload,
            Some(VerifiedSinks {
                sinks: delivery.sinks,
                _backing: delivery._backing,
            }),
        )
    }
}
