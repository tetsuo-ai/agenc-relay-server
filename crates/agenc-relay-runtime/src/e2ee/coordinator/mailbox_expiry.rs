//! Bounded expiry owns its captured metadata until an exact storage receipt.
#![forbid(unsafe_code)]

use super::{CompanionCoordinator, CompanionFault, resident};
use crate::budget::{BackingReservationPort, MemoryPermit};
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_domain::e2ee::mailbox::MailboxKind;
use agenc_relay_domain::e2ee::mailbox::expiry::{
    Change, Cursor, ItemAction, MAX_EXPIRY_ENTRIES, Plan,
};
use agenc_relay_storage::e2ee_records::{MAILBOX_ROW_KIND, MailboxKind as RowKind, MailboxRow};
use agenc_relay_storage::{PersistentRecordValue, TableId};

pub(crate) struct Prepared {
    plan: Plan,
    _backing: MemoryPermit,
}

impl Prepared {
    pub(crate) fn capture(
        executor: &CompanionCoordinator,
        cursor: Cursor,
        now: u64,
        backing: &BackingReservationPort,
    ) -> Result<Self, CompanionFault> {
        let backing = backing
            .reserve(MAX_EXPIRY_ENTRIES * 512 + 8192)
            .map_err(|_| CompanionFault::Ceiling)?;
        let plan = Plan::capture(&executor.state.mailboxes, cursor, now);
        plan.validate(&executor.state.mailboxes)
            .map_err(|_| CompanionFault::Storage)?;
        Ok(Self {
            plan,
            _backing: backing,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.plan.is_empty()
    }

    pub(crate) fn next_cursor(&self) -> Cursor {
        self.plan.next_cursor()
    }

    pub(crate) fn completes_cycle(&self) -> bool {
        self.plan.completes_cycle()
    }

    pub(crate) fn writes(&self, revision: u64) -> Result<Vec<Write>, crate::RuntimeError> {
        let mut writes = Vec::with_capacity(MAX_EXPIRY_ENTRIES * 2);
        for change in self.plan.changes() {
            append_change(&mut writes, change, revision)?;
        }
        Ok(writes)
    }

    pub(crate) fn apply(&self, executor: &mut CompanionCoordinator) -> Result<(), CompanionFault> {
        self.plan
            .apply(&mut executor.state.mailboxes)
            .map_err(|_| CompanionFault::Storage)?;
        for change in self.plan.changes() {
            if let Change::Item {
                before,
                action: ItemAction::Remove,
                ..
            } = change
            {
                resident::retire_payload(&mut executor.state, &before.object_id);
            }
        }
        Ok(())
    }
}

fn append_change(
    writes: &mut Vec<Write>,
    change: Change,
    revision: u64,
) -> Result<(), crate::RuntimeError> {
    match change {
        Change::Item {
            target,
            kind,
            sequence,
            before,
            action,
        } => {
            let kind = match kind {
                MailboxKind::Application => RowKind::Application,
                MailboxKind::Binding => RowKind::Binding,
                MailboxKind::Welcome => RowKind::Welcome,
                MailboxKind::StagedReinit => RowKind::StagedReinit,
            };
            let key =
                MailboxRow::item_key(&target.account_digest, &target.device_id, kind, sequence)?;
            writes.push(item_write(key, action.after(before), revision)?);
            if let Some(grant) = before.grant {
                writes.push(Write::delete(
                    TableId::E2eeState,
                    MailboxRow::token_key(&grant.token)?,
                )?);
            }
        }
        Change::Ack { target, token, .. } => writes.push(Write::delete(
            TableId::E2eeState,
            MailboxRow::ack_key(&target.account_digest, &target.device_id, &token)?,
        )?),
    }
    Ok(())
}

fn item_write(
    key: agenc_relay_storage::StoredKey,
    after: Option<agenc_relay_domain::e2ee::mailbox::Item>,
    revision: u64,
) -> Result<Write, crate::RuntimeError> {
    let Some(item) = after else {
        return Write::delete(TableId::E2eeState, key);
    };
    let row = MailboxRow::Item {
        object_id: item.object_id,
        conversation_id: item.conversation_id,
        inserted_at: item.inserted_at,
        expires_at: item.expires_at,
        grant: None,
    };
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        MAILBOX_ROW_KIND,
        revision,
        0,
        None,
        Vec::new(),
        row.encode()?,
    )?;
    Write::put(TableId::E2eeState, key, value.encode()?)
}
