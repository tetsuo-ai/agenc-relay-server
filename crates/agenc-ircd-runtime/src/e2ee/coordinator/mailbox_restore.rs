//! Authenticated mailbox sequence ownership survives item retirement.

#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use agenc_ircd_domain::e2ee::mailbox::{MailboxKind, Mailboxes, Target};
use agenc_ircd_storage::e2ee_records::{MailboxKind as RowKind, MailboxRow, MailboxSequenceRow};
use agenc_ircd_storage::{StorageError, StoredKey};

use super::CompanionFault;

type Scope = (Target, MailboxKind);

/// Every used scope needs an explicit owner; retained rows never invent one.
#[derive(Default)]
pub(super) struct Restore {
    owners: BTreeMap<Scope, u64>,
    positions: BTreeMap<Scope, u64>,
    acknowledged_targets: BTreeSet<Target>,
    failed: bool,
}

impl Restore {
    pub(super) fn admit(&mut self, key: &StoredKey, body: &[u8]) {
        match MailboxSequenceRow::decode_keyed(key, body) {
            Ok(row) => {
                let target = Target {
                    account_digest: *row.account_digest(),
                    device_id: *row.device_id(),
                };
                self.failed |= self
                    .owners
                    .insert((target, kind(row.kind())), row.next_sequence())
                    .is_some();
            }
            Err(_) => self.failed = true,
        }
    }

    /// The existing row collector receives only rows with a valid exact key.
    pub(super) fn admit_mailbox(&mut self, key: &StoredKey, body: &[u8]) -> Option<MailboxRow> {
        let parsed = MailboxRow::decode(body).and_then(|row| {
            self.require_owner(key, &row)?;
            Ok(row)
        });
        match parsed {
            Ok(row) => Some(row),
            Err(_) => {
                self.failed = true;
                None
            }
        }
    }

    fn require_owner(&mut self, key: &StoredKey, row: &MailboxRow) -> Result<(), StorageError> {
        let (target, mailbox_kind, sequence) = match row {
            MailboxRow::Item { .. } => {
                let parts = MailboxRow::parse_item_key(key)?;
                (
                    Target {
                        account_digest: parts.account_digest,
                        device_id: parts.device_id,
                    },
                    kind(parts.kind),
                    parts.sequence,
                )
            }
            MailboxRow::Token {
                account_digest,
                device_id,
                kind: item_kind,
                sequence,
                ..
            } => {
                MailboxRow::parse_token_key(key)?;
                (
                    Target {
                        account_digest: *account_digest,
                        device_id: *device_id,
                    },
                    kind(*item_kind),
                    *sequence,
                )
            }
            MailboxRow::Ack { .. } => {
                let (account_digest, device_id, _) = MailboxRow::parse_ack_key(key)?;
                self.acknowledged_targets.insert(Target {
                    account_digest,
                    device_id,
                });
                return Ok(());
            }
        };
        let position = self.positions.entry((target, mailbox_kind)).or_default();
        *position = (*position).max(sequence);
        Ok(())
    }

    pub(super) fn apply(self, mailboxes: &mut Mailboxes) -> Result<(), CompanionFault> {
        if self.failed {
            return Err(CompanionFault::Storage);
        }
        for (scope, sequence) in self.positions {
            if !self.owners.get(&scope).is_some_and(|next| sequence < *next) {
                return Err(CompanionFault::Storage);
            }
        }
        for target in self.acknowledged_targets {
            if self
                .owners
                .range((target, MailboxKind::Application)..=(target, MailboxKind::StagedReinit))
                .next()
                .is_none()
            {
                return Err(CompanionFault::Storage);
            }
        }
        for ((target, item_kind), next) in self.owners {
            mailboxes
                .restore_sequence(target, item_kind, next)
                .map_err(|_| CompanionFault::Storage)?;
        }
        Ok(())
    }
}

const fn kind(kind: RowKind) -> MailboxKind {
    match kind {
        RowKind::Application => MailboxKind::Application,
        RowKind::Binding => MailboxKind::Binding,
        RowKind::Welcome => MailboxKind::Welcome,
        RowKind::StagedReinit => MailboxKind::StagedReinit,
    }
}
