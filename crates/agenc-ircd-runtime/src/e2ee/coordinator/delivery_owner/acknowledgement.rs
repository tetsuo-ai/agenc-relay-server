//! EACK validation and the private transition owned by its storage receipt.
#![forbid(unsafe_code)]

use agenc_ircd_e2ee::federation::frames::DeliveryPosition;
use agenc_ircd_storage::e2ee_records::delivery_recovery::{
    Acknowledgement, CutPhase, DeliveryCursor, DeliveryOwner, LastAcknowledged, outbox,
};
use agenc_ircd_types::ServerId;

use super::super::events::{self, DeliveryStream, MAX_ACKED_REPLAY_ROWS};
use super::super::sync::{Action, PendingWork};
use super::super::{CompanionCoordinator, CompanionFault};
use crate::federation::LinkId;
use crate::state_core::durable::AccountServiceDurableWrite;

/// A staged ACK cannot publish its proposed cursor before its matched receipt.
pub struct PreparedAck {
    peer: ServerId,
    link: LinkId,
    position: DeliveryPosition,
    resume: bool,
    expected: DeliveryOwner,
    proposed: DeliveryCursor,
    acknowledgement: Acknowledgement,
}

impl PreparedAck {
    pub(crate) const fn resumes(&self) -> bool {
        self.resume
    }

    pub(crate) const fn position(&self) -> DeliveryPosition {
        self.position
    }

    pub(crate) const fn peer(&self) -> ServerId {
        self.peer
    }

    fn repeats(&self, link: LinkId, peer: ServerId, position: DeliveryPosition) -> bool {
        self.link == link && self.peer == peer && self.position == position
    }

    pub(crate) fn apply(
        self,
        coordinator: &mut CompanionCoordinator,
    ) -> Result<(), CompanionFault> {
        coordinator.validate_delivery_scope(self.expected.scope())?;
        let proposed = DeliveryOwner::new(
            *self.expected.scope(),
            self.proposed,
            *self.expected.cut(),
            self.expected.phase(),
        )
        .map_err(|_| CompanionFault::Storage)?;
        let stream = coordinator
            .state
            .streams
            .get_mut(&self.peer)
            .ok_or(CompanionFault::Storage)?;
        if stream.owner.as_ref() != Some(&self.expected)
            || super::cursor(stream)? != *self.expected.cursor()
        {
            return Err(CompanionFault::Storage);
        }
        stream.acknowledge(
            self.position.delivery_sequence,
            self.position.event_id,
            self.acknowledgement,
        )?;
        stream.owner = Some(proposed);
        Ok(())
    }
}

pub(crate) fn prepare(
    coordinator: &CompanionCoordinator,
    link: LinkId,
    peer: ServerId,
    position: DeliveryPosition,
    trusted_ack_unix_seconds: Option<u64>,
) -> Result<Vec<Action>, CompanionFault> {
    if let Some(PendingWork::Acknowledgement(ack)) = &coordinator.pending {
        return if ack.repeats(link, peer, position) {
            Ok(Vec::new())
        } else {
            Err(CompanionFault::Protocol)
        };
    }
    if coordinator.pending.is_some() {
        return Err(CompanionFault::Ceiling);
    }
    let stream = coordinator
        .state
        .streams
        .get(&peer)
        .ok_or(CompanionFault::Protocol)?;
    let owner = stream.owner.as_ref().ok_or(CompanionFault::Protocol)?;
    validate_source(coordinator, link, peer, position, stream, owner)?;
    if stream.acked == Some((position.delivery_sequence, position.event_id)) {
        return Ok(Vec::new());
    }
    if stream.rows.iter().any(|row| {
        row.acked()
            && row.sequence == position.delivery_sequence
            && row.event_id == position.event_id
    }) {
        return Ok(Vec::new());
    }
    validate_coverage(stream, position)?;
    let cursor = DeliveryCursor::new(
        stream.generation,
        stream.next_sequence,
        LastAcknowledged::At {
            sequence: position.delivery_sequence,
            event_id: position.event_id,
        },
    )
    .map_err(|_| CompanionFault::Protocol)?;
    let proposed = DeliveryOwner::new(*owner.scope(), cursor, *owner.cut(), owner.phase())
        .map_err(|_| CompanionFault::Storage)?;
    let acknowledgement = Acknowledgement::received_at(trusted_ack_unix_seconds);
    let writes = writes(
        stream,
        position.delivery_sequence,
        &proposed,
        acknowledgement,
    )?;
    Ok(vec![Action::Stage {
        writes,
        work: PendingWork::Acknowledgement(PreparedAck {
            peer,
            link,
            position,
            resume: false,
            expected: owner.clone(),
            proposed: cursor,
            acknowledgement,
        }),
    }])
}

fn validate_source(
    coordinator: &CompanionCoordinator,
    link: LinkId,
    peer: ServerId,
    position: DeliveryPosition,
    stream: &DeliveryStream,
    owner: &DeliveryOwner,
) -> Result<(), CompanionFault> {
    coordinator.validate_delivery_scope(owner.scope())?;
    let active = coordinator
        .peers
        .get(&peer)
        .is_some_and(|sync| sync.active && sync.link == Some(link));
    if !active
        || owner.phase() != CutPhase::Ready
        || position.server_id != *coordinator.server_id.as_bytes()
        || position.delivery_generation != stream.generation
        || owner.scope().target_server_id() != *peer.as_bytes()
        || super::cursor(stream)? != *owner.cursor()
    {
        return Err(CompanionFault::Protocol);
    }
    Ok(())
}

fn validate_coverage(
    stream: &DeliveryStream,
    position: DeliveryPosition,
) -> Result<(), CompanionFault> {
    let mut expected = stream
        .acked
        .map_or(Some(0), |(sequence, _)| sequence.checked_add(1))
        .ok_or(CompanionFault::Protocol)?;
    let through = position.delivery_sequence;
    let through_expected = match stream.barrier {
        Some((first, last)) if expected >= first => through == last,
        _ => through == expected,
    };
    if !through_expected {
        return Err(CompanionFault::Protocol);
    }
    for row in stream
        .rows
        .iter()
        .filter(|row| !row.acked() && row.sequence <= through)
    {
        if row.sequence != expected {
            return Err(CompanionFault::Protocol);
        }
        if row.sequence == through {
            return if row.event_id == position.event_id {
                Ok(())
            } else {
                Err(CompanionFault::Protocol)
            };
        }
        expected = expected.checked_add(1).ok_or(CompanionFault::Protocol)?;
    }
    Err(CompanionFault::Protocol)
}

fn writes(
    stream: &DeliveryStream,
    through: u64,
    proposed: &DeliveryOwner,
    acknowledgement: Acknowledgement,
) -> Result<Vec<AccountServiceDurableWrite>, CompanionFault> {
    let mut writes = vec![super::write(proposed)?];
    let covered = stream
        .rows
        .iter()
        .filter(|row| row.sequence <= through)
        .count();
    let mut trim = covered.saturating_sub(MAX_ACKED_REPLAY_ROWS);
    for row in stream.rows.iter().take_while(|row| row.sequence <= through) {
        if trim > 0 {
            let key = outbox::outbox_key(proposed.scope(), stream.generation, row.sequence)
                .map_err(|_| CompanionFault::Storage)?;
            writes.push(AccountServiceDurableWrite::Delete {
                table: agenc_ircd_storage::TableId::E2eeState,
                key,
            });
            trim -= 1;
        } else if !row.acked() {
            writes.push(
                events::outbox_write(proposed.scope(), stream.generation, row, acknowledgement)
                    .map_err(|_| CompanionFault::Storage)?,
            );
        }
    }
    Ok(writes)
}

#[cfg(test)]
#[path = "acknowledgement/tests/reconstruction.rs"]
mod reconstruction_tests;

/// The caller has checked the historical resume scope and exact barrier endpoint.
pub(crate) fn prepare_resume(
    coordinator: &CompanionCoordinator,
    peer: ServerId,
    position: DeliveryPosition,
    trusted_ack_unix_seconds: Option<u64>,
) -> Result<Vec<Action>, CompanionFault> {
    if coordinator.pending.is_some() {
        return Err(CompanionFault::Ceiling);
    }
    let sync = coordinator
        .peers
        .get(&peer)
        .ok_or(CompanionFault::Protocol)?;
    let link = sync.link.ok_or(CompanionFault::Protocol)?;
    if sync.active {
        return Err(CompanionFault::Protocol);
    }
    let stream = coordinator
        .state
        .streams
        .get(&peer)
        .ok_or(CompanionFault::Protocol)?;
    let owner = stream.owner.as_ref().ok_or(CompanionFault::Storage)?;
    coordinator.validate_delivery_scope(owner.scope())?;
    if owner.phase() != CutPhase::Ready
        || super::cursor(stream)? != *owner.cursor()
        || position.server_id != *coordinator.server_id.as_bytes()
        || position.delivery_generation != stream.generation
        || stream
            .barrier
            .is_none_or(|(_, last)| last != position.delivery_sequence)
    {
        return Err(CompanionFault::Protocol);
    }
    validate_coverage(stream, position)?;
    let proposed = DeliveryCursor::new(
        stream.generation,
        stream.next_sequence,
        LastAcknowledged::At {
            sequence: position.delivery_sequence,
            event_id: position.event_id,
        },
    )
    .map_err(|_| CompanionFault::Protocol)?;
    let updated = DeliveryOwner::new(*owner.scope(), proposed, *owner.cut(), owner.phase())
        .map_err(|_| CompanionFault::Storage)?;
    let acknowledgement = Acknowledgement::received_at(trusted_ack_unix_seconds);
    let writes = writes(
        stream,
        position.delivery_sequence,
        &updated,
        acknowledgement,
    )?;
    Ok(vec![Action::Stage {
        writes,
        work: PendingWork::Acknowledgement(PreparedAck {
            peer,
            link,
            position,
            resume: true,
            expected: owner.clone(),
            proposed,
            acknowledgement,
        }),
    }])
}
