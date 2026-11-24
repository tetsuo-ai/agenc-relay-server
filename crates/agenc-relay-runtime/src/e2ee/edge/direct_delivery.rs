//! Generation-bound live outputs for direct application events (companion 11.6 and 12.5).
//! The coordinator owns the current attachment. Its ordinary authenticated WHOAMI
//! result verifies a local origin without adding recipient identities to events.

use super::events::OpenEvent;
use super::router::{Refusal, RequestSource, Resolved, settled};
use super::{ClientOutput, E2eeEdge, LocalOrigin, ResultValue};
use crate::budget::MemoryPermit;
use crate::connection::ConnectionGeneration;
use crate::federation::edge::{BaseOriginFacts, EdgeFederation};
use crate::state_core::StateCoreContext;
use agenc_relay_e2ee::wire::command::{ClientCommand, EkeyCommand};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_types::UserId;

#[cfg(test)]
#[path = "tests/direct_delivery.rs"]
mod tests;

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) struct Sink {
    connection: ConnectionGeneration,
    origin_id: [u8; 16],
    origin_generation: u64,
    user: UserId,
    account: [u8; 24],
    attachment: ([u8; 16], u64),
    // None until this event's probe is answered or the captured endpoint is gone.
    verified: Option<bool>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OriginStatus {
    Gone,
    AwaitingAck,
    Ready,
}

impl Sink {
    fn capture(
        connection: ConnectionGeneration,
        origin: &LocalOrigin,
        base: &BaseOriginFacts,
    ) -> Option<Self> {
        let user = origin.user_id?;
        let account = origin.account?;
        let attachment = origin.device?;
        if origin.origin_id != base.origin_id
            || base.session.map(|(_, user)| user) != Some(*user.as_bytes())
            || base.account.map(|(account, _)| account) != Some(account)
            || origin.device_principal != Some((Some(user), Some(account)))
        {
            return None;
        }
        // Before the base ACK, its held generation can still describe the
        // previous device. The first new declaration can carry this device.
        let origin_generation = match origin.predates_device {
            Some(previous) if previous >= base.generation => previous.checked_add(1)?,
            _ => base.generation,
        };
        Some(Self {
            connection,
            origin_id: origin.origin_id,
            origin_generation,
            user,
            account,
            attachment,
            verified: None,
        })
    }

    fn status(
        &self,
        router: &E2eeEdge,
        edge: &EdgeFederation,
        context: &StateCoreContext,
    ) -> OriginStatus {
        if context.sessions().generation_for_user(self.user) != Some(self.connection) {
            return OriginStatus::Gone;
        }
        let Some(origin) = router.origins.get(&self.connection) else {
            return OriginStatus::Gone;
        };
        let Some(base) = edge.origin_facts(self.connection) else {
            return OriginStatus::Gone;
        };
        self.origin_status(origin, &base)
    }

    fn origin_status(&self, origin: &LocalOrigin, base: &BaseOriginFacts) -> OriginStatus {
        if Self::capture(self.connection, origin, base)
            != Some(Self {
                verified: None,
                ..*self
            })
        {
            return OriginStatus::Gone;
        }
        if settled(origin) && origin.acked == Some(self.origin_generation) {
            OriginStatus::Ready
        } else {
            OriginStatus::AwaitingAck
        }
    }

    pub(super) fn recipient(
        &self,
        router: &E2eeEdge,
        edge: &EdgeFederation,
        context: &StateCoreContext,
    ) -> Option<(ConnectionGeneration, UserId)> {
        (self.verified == Some(true) && self.status(router, edge, context) == OriginStatus::Ready)
            .then_some((self.connection, self.user))
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
        edge: &EdgeFederation,
        context: &StateCoreContext,
    ) -> bool {
        self.sinks
            .binary_search_by_key(&output.generation, |sink| sink.connection)
            .ok()
            .and_then(|index| self.sinks.get(index))
            .and_then(|sink| sink.recipient(router, edge, context))
            .is_some()
    }
}

pub(super) struct Delivery {
    open: OpenEvent,
    payload: Option<crate::e2ee::spool::CompanionBytes>,
    sinks: Vec<Sink>,
    index: usize,
    awaiting: Option<([u8; 16], usize)>,
    _backing: MemoryPermit,
}

enum NextSink {
    Probe(usize, ConnectionGeneration, [u8; 24]),
    AwaitingAck,
    Complete,
}

impl Delivery {
    pub(super) fn sequence(&self) -> u64 {
        self.open.position.delivery_sequence
    }

    /// Visit each unchecked endpoint once per pass. A pending declaration
    /// cannot prevent another ready endpoint from issuing WHOAMI. The vector
    /// stays in connection order for the commit's publication check.
    fn next_sink(
        &mut self,
        router: &E2eeEdge,
        edge: &EdgeFederation,
        context: &StateCoreContext,
    ) -> Result<NextSink, Refusal> {
        let count = self.sinks.len();
        let mut next = NextSink::Complete;
        for _ in 0..count {
            let index = self.index;
            self.index = if index + 1 == count { 0 } else { index + 1 };
            let sink = self.sinks.get_mut(index).ok_or(E2eeReplyCode::Syncing)?;
            if sink.verified.is_some() {
                continue;
            }
            match sink.status(router, edge, context) {
                OriginStatus::Gone => sink.verified = Some(false),
                OriginStatus::AwaitingAck => next = NextSink::AwaitingAck,
                OriginStatus::Ready => {
                    return Ok(NextSink::Probe(index, sink.connection, sink.account));
                }
            }
        }
        Ok(next)
    }

    fn observe(&mut self, id: [u8; 16], value: &ResultValue) -> Result<(), Refusal> {
        let Some((_, index)) = self.awaiting.filter(|(request, _)| *request == id) else {
            return Ok(());
        };
        let sink = self.sinks.get_mut(index).ok_or(E2eeReplyCode::Syncing)?;
        sink.verified = Some(match value {
            ResultValue::Account(account, generation) => {
                *account == sink.account && *generation == sink.attachment.1 && *generation != 0
            }
            ResultValue::Failed { code, .. }
                if code == E2eeReplyCode::AccountRequired.token()
                    || code == E2eeReplyCode::DeviceRequired.token() =>
            {
                false
            }
            _ => return Err(E2eeReplyCode::Syncing.into()),
        });
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
        payload: Option<crate::e2ee::spool::CompanionBytes>,
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
                Sink::capture(*id, origin, &edge.origin_facts(*id)?)
            })
        };
        let count = eligible().count();
        let bytes = count
            .checked_mul(std::mem::size_of::<Sink>())
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
        match delivery.next_sink(self, edge, context)? {
            NextSink::Probe(index, connection, account) => {
                let id = self.send_request(
                    context,
                    edge,
                    connection,
                    account,
                    RequestSource::Attachment,
                    Resolved::Command(ClientCommand::Ekey(EkeyCommand::Whoami)),
                    None,
                )?;
                delivery.awaiting = Some((id, index));
                self.direct_delivery = Some(delivery);
                return Ok(Vec::new());
            }
            NextSink::AwaitingAck => {
                self.direct_delivery = Some(delivery);
                return Ok(Vec::new());
            }
            NextSink::Complete => {}
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
