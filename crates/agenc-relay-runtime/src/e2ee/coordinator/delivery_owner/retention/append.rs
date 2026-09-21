//! A new ACK range covers exactly one complete, bounded, contiguous prefix.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_e2ee::limits::{
    MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE, MAX_UNACKED_E2EE_EVENTS_PER_EDGE,
};
use agenc_relay_storage::e2ee_records::delivery_recovery::outbox::replay::AckRangeFields;

pub(super) fn begin(
    current: &DeliveryOwner,
    previous: Option<ReplayOwner>,
    through: u64,
    event_id: [u8; 16],
    rows: impl IntoIterator<Item = Result<Row, CompanionFault>>,
    trusted_now: Option<u64>,
) -> Result<Draft, CompanionFault> {
    validate_previous(current, previous)?;
    let first = match current.cursor().last_ack() {
        LastAcknowledged::BeforeFirst => 0,
        LastAcknowledged::At { sequence, .. } => {
            sequence.checked_add(1).ok_or(CompanionFault::Storage)?
        }
    };
    if through < first || through >= current.cursor().next_sequence() {
        return Err(CompanionFault::Protocol);
    }
    let (count, bytes) = scan(first, through, event_id, rows)?;
    let acknowledgement = Acknowledgement::received_at(trusted_now);
    let range = AckRange::new(AckRangeFields {
        scope: *current.scope(),
        generation: current.cursor().generation(),
        first,
        last: through,
        event_id,
        acknowledgement,
    })
    .map_err(|_| CompanionFault::Storage)?;
    let mut fields = previous.map_or(
        ReplayOwnerFields {
            scope: *current.scope(),
            generation: current.cursor().generation(),
            through,
            event_id,
            first_retained: first,
            retained_rows: 0,
            retained_bytes: 0,
            trusted_unix_seconds: None,
        },
        |owner| *owner.fields(),
    );
    fields.through = through;
    fields.event_id = event_id;
    fields.retained_rows = fields
        .retained_rows
        .checked_add(count)
        .ok_or(CompanionFault::Storage)?;
    fields.retained_bytes = fields
        .retained_bytes
        .checked_add(bytes)
        .ok_or(CompanionFault::Storage)?;
    let now = accepted_time(trusted_now);
    if let Some(now) = now {
        fields.trusted_unix_seconds =
            Some(fields.trusted_unix_seconds.map_or(now, |old| old.max(now)));
    }
    Ok(Draft {
        fields,
        range: Some(range),
        now,
    })
}

fn scan(
    first: u64,
    through: u64,
    event_id: [u8; 16],
    rows: impl IntoIterator<Item = Result<Row, CompanionFault>>,
) -> Result<(u64, u64), CompanionFault> {
    let mut next = first;
    let mut bytes = 0_u64;
    let mut count = 0_u64;
    for row in rows {
        let row = row?;
        if row.sequence != next
            || row.sequence > through
            || row.acknowledgement.is_acknowledged()
            || (row.sequence == through && row.event_id != event_id)
        {
            return Err(CompanionFault::Protocol);
        }
        next = next.checked_add(1).ok_or(CompanionFault::Protocol)?;
        bytes = bytes
            .checked_add(row.bytes)
            .ok_or(CompanionFault::Protocol)?;
        count = count.checked_add(1).ok_or(CompanionFault::Protocol)?;
        if count > MAX_UNACKED_E2EE_EVENTS_PER_EDGE || bytes > MAX_UNACKED_E2EE_EVENT_BYTES_PER_EDGE
        {
            return Err(CompanionFault::Protocol);
        }
    }
    if through.checked_add(1) != Some(next) {
        return Err(CompanionFault::Protocol);
    }
    Ok((count, bytes))
}
