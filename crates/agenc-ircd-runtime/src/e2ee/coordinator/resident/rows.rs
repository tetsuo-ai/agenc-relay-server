//! Row decoding owns temporary allocations until resident admission has its own charge.
#![forbid(unsafe_code)]
use super::*;
use agenc_ircd_storage::e2ee_records::{MAILBOX_ROW_KIND, MailboxKind, MailboxRow};

pub(super) struct Decoded {
    pub(super) value: PersistentRecordValue,
    _memory: MemoryPermit,
}

pub(super) fn decode(
    table: TableId,
    encoded: &[u8],
    backing: &BackingReservationPort,
) -> Result<Decoded, Code> {
    let bytes = encoded
        .len()
        .checked_mul(3)
        .and_then(|n| n.checked_add(8192))
        .ok_or(Code::RateLimited)?;
    let memory = backing.reserve(bytes).map_err(|_| Code::RateLimited)?;
    let value = PersistentRecordValue::decode(table, encoded).map_err(|_| Code::InvalidFragment)?;
    Ok(Decoded {
        value,
        _memory: memory,
    })
}

pub(super) fn required(
    writes: &[Write],
    backing: &BackingReservationPort,
) -> Result<BTreeMap<[u8; 32], Kind>, Code> {
    let mut required = BTreeMap::new();
    for write in writes {
        let Some((TableId::E2eeState, key, encoded)) = write.encoded_record() else {
            continue;
        };
        let decoded = decode(TableId::E2eeState, encoded, backing)?;
        if decoded.value.record_kind() != MAILBOX_ROW_KIND {
            continue;
        }
        let row = MailboxRow::decode(decoded.value.body()).map_err(|_| Code::InvalidFragment)?;
        let MailboxRow::Item { object_id, .. } = row else {
            continue;
        };
        let key = MailboxRow::parse_item_key(key).map_err(|_| Code::InvalidFragment)?;
        let kind = match key.kind {
            MailboxKind::Application => Kind::ApplicationMls,
            MailboxKind::Binding => Kind::ConversationBinding,
            MailboxKind::Welcome => Kind::WelcomeMls,
            MailboxKind::StagedReinit => Kind::StagedReinit,
        };
        if required
            .insert(object_id, kind)
            .is_some_and(|previous| previous != kind)
        {
            return Err(Code::InvalidFragment);
        }
    }
    Ok(required)
}

pub(super) fn complete(
    required: &BTreeMap<[u8; 32], Kind>,
    state: &CompanionState,
    objects: &BTreeMap<[u8; 32], Vec<u8>>,
) -> Result<(), Code> {
    for (id, expected) in required {
        let bytes = objects
            .get(id)
            .or_else(|| state.objects.get(id))
            .ok_or(Code::InvalidFragment)?;
        let (kind, _) = agenc_ircd_e2ee::object::IrcWireObject::peek(bytes)
            .map_err(|_| Code::InvalidFragment)?;
        if kind != *expected || agenc_ircd_e2ee::ObjectId::compute(bytes).as_bytes() != id {
            return Err(Code::InvalidFragment);
        }
    }
    Ok(())
}
