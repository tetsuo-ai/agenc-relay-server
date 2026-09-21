//! One exact final mailbox deletion can fund its ACK result without publishing early.
#![forbid(unsafe_code)]
use super::*;
use agenc_relay_domain::e2ee::mailbox::{MailboxKind as DomainKind, Target};
use agenc_relay_storage::e2ee_records::{MailboxItemKey, MailboxKind, MailboxRow};

pub(super) fn credit(
    state: &CompanionState,
    writes: &[Write],
    required: &BTreeMap<[u8; 32], Kind>,
) -> Option<([u8; 32], usize)> {
    let item = deleted_item(writes)?;
    let target = Target {
        account_digest: item.account_digest,
        device_id: item.device_id,
    };
    let kind = match item.kind {
        MailboxKind::Application => DomainKind::Application,
        MailboxKind::Binding => DomainKind::Binding,
        MailboxKind::Welcome => DomainKind::Welcome,
        MailboxKind::StagedReinit => DomainKind::StagedReinit,
    };
    let id = state
        .mailboxes
        .last_object_reference(target, kind, item.sequence)?;
    if required.contains_key(&id) {
        return None;
    }
    let bytes = state.objects.get(&id)?;
    let (wire_kind, _) = agenc_relay_e2ee::object::ArcWireObject::peek(bytes).ok()?;
    if !matches!(
        (item.kind, wire_kind),
        (MailboxKind::Application, Kind::ApplicationMls)
            | (MailboxKind::Welcome, Kind::WelcomeMls)
            | (MailboxKind::StagedReinit, Kind::StagedReinit)
    ) {
        return None;
    }
    let remaining = state.object_bytes.checked_sub(bytes.len())?;
    Some((id, remaining))
}

fn deleted_item(writes: &[Write]) -> Option<MailboxItemKey> {
    let mut deleted = None;
    for write in writes {
        let Write::Delete {
            table: TableId::E2eeState,
            key,
        } = write
        else {
            continue;
        };
        let Ok(item) = MailboxRow::parse_item_key(key) else {
            continue;
        };
        if deleted.replace(item).is_some() {
            return None;
        }
    }
    deleted
}
