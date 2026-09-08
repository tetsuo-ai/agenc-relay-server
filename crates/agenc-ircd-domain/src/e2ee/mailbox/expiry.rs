//! Bounded, read-only expiry plans publish exact changes after the caller's durable receipt.
#![forbid(unsafe_code)]

use super::{AckRecord, Id, Item, ItemKey, MailboxError, MailboxKind, Mailboxes, Target};
use std::ops::Bound::{Excluded, Unbounded};

/// Maximum metadata entries examined by one plan, including unexpired entries.
pub const MAX_EXPIRY_ENTRIES: usize = 128;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum Phase {
    #[default]
    Items,
    Acks,
}

/// Process-local scan position. Restarting from the beginning cannot lower sequence owners.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Cursor {
    phase: Phase,
    item_after: Option<ItemKey>,
    ack_after: Option<(Target, Id)>,
}

/// The only permitted changes to an expiring mailbox item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ItemAction {
    /// Remove the item after its retention boundary.
    Remove,
    /// Preserve every item field except its expired grant.
    ClearGrant,
}

impl ItemAction {
    /// Derives the exact after-image from the captured item without storing a second copy.
    #[must_use]
    pub fn after(self, before: Item) -> Option<Item> {
        match self {
            Self::Remove => None,
            Self::ClearGrant => Some(Item {
                grant: None,
                ..before
            }),
        }
    }
}

/// One captured metadata change, never an object-body deletion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Change {
    /// Remove an expired item or clear its expired grant.
    Item {
        /// Exact mailbox owner.
        target: Target,
        /// Exact mailbox kind.
        kind: MailboxKind,
        /// Exact item position.
        sequence: u64,
        /// Committed item captured while planning.
        before: Item,
        /// Whether item retention or only its grant expired.
        action: ItemAction,
    },
    /// Remove an expired idempotent acknowledgement.
    Ack {
        /// Exact mailbox owner.
        target: Target,
        /// Exact retained token.
        token: Id,
        /// Captured result identity.
        object_id: Id,
        /// Captured result retention boundary.
        retain_until: u64,
    },
}

/// A bounded captured page. The caller must reserve memory before creating it.
pub struct Plan {
    changes: Vec<Change>,
    next: Cursor,
}

impl Plan {
    /// Captures at most one page without mutating mailboxes or allocating a full clone.
    #[must_use]
    pub fn capture(mailboxes: &Mailboxes, cursor: Cursor, now: u64) -> Self {
        let mut plan = Self {
            changes: Vec::with_capacity(MAX_EXPIRY_ENTRIES),
            next: cursor,
        };
        match cursor.phase {
            Phase::Items => plan.items(mailboxes, cursor, now),
            Phase::Acks => plan.acks(mailboxes, cursor, now),
        }
        plan
    }

    fn items(&mut self, mailboxes: &Mailboxes, cursor: Cursor, now: u64) {
        let start = cursor.item_after.map_or(Unbounded, Excluded);
        let mut scanned = 0;
        for (key, item) in mailboxes
            .items
            .range((start, Unbounded))
            .take(MAX_EXPIRY_ENTRIES)
        {
            scanned += 1;
            self.next.item_after = Some(*key);
            let action = if item.expires_at <= now {
                ItemAction::Remove
            } else if item.grant.is_some_and(|grant| grant.expires_at <= now) {
                ItemAction::ClearGrant
            } else {
                continue;
            };
            self.changes.push(Change::Item {
                target: key.target,
                kind: key.kind,
                sequence: key.sequence,
                before: *item,
                action,
            });
        }
        if scanned < MAX_EXPIRY_ENTRIES {
            self.next = Cursor {
                phase: Phase::Acks,
                ..Cursor::default()
            };
        }
    }

    fn acks(&mut self, mailboxes: &Mailboxes, cursor: Cursor, now: u64) {
        let start = cursor.ack_after.map_or(Unbounded, Excluded);
        let mut scanned = 0;
        for ((target, token), record) in mailboxes
            .acks
            .range((start, Unbounded))
            .take(MAX_EXPIRY_ENTRIES)
        {
            scanned += 1;
            self.next.ack_after = Some((*target, *token));
            if record.retain_until <= now {
                self.changes.push(Change::Ack {
                    target: *target,
                    token: *token,
                    object_id: record.object_id,
                    retain_until: record.retain_until,
                });
            }
        }
        if scanned < MAX_EXPIRY_ENTRIES {
            self.next = Cursor::default();
        }
    }

    /// Captured changes in scan order.
    pub fn changes(&self) -> impl Iterator<Item = Change> + '_ {
        self.changes.iter().copied()
    }

    /// Whether this page requires no durable write.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.changes.is_empty()
    }

    /// Position that is safe after this page's receipt, or immediately for an empty page.
    #[must_use]
    pub fn next_cursor(&self) -> Cursor {
        self.next
    }

    /// Whether the next scan starts a new complete cycle.
    #[must_use]
    pub fn completes_cycle(&self) -> bool {
        self.next == Cursor::default()
    }

    /// Every changed item, token index and ACK must still match before publication.
    pub fn validate(&self, mailboxes: &Mailboxes) -> Result<(), MailboxError> {
        if self.changes.iter().all(|change| change.matches(mailboxes)) {
            Ok(())
        } else {
            Err(MailboxError::AdmissionRefused)
        }
    }

    /// Publishes only a wholly matching page; a changed row prevents every mutation.
    pub fn apply(&self, mailboxes: &mut Mailboxes) -> Result<(), MailboxError> {
        self.validate(mailboxes)?;
        for change in &self.changes {
            change.apply(mailboxes);
        }
        Ok(())
    }
}

impl Change {
    fn matches(&self, mailboxes: &Mailboxes) -> bool {
        match *self {
            Self::Item {
                target,
                kind,
                sequence,
                before,
                ..
            } => {
                let key = ItemKey {
                    target,
                    kind,
                    sequence,
                };
                mailboxes.items.get(&key) == Some(&before)
                    && before
                        .grant
                        .is_none_or(|grant| mailboxes.tokens.get(&grant.token) == Some(&key))
            }
            Self::Ack {
                target,
                token,
                object_id,
                retain_until,
            } => {
                mailboxes.acks.get(&(target, token))
                    == Some(&AckRecord {
                        object_id,
                        retain_until,
                    })
            }
        }
    }

    fn apply(&self, mailboxes: &mut Mailboxes) {
        match *self {
            Self::Item {
                target,
                kind,
                sequence,
                before,
                action,
            } => {
                let key = ItemKey {
                    target,
                    kind,
                    sequence,
                };
                apply_item(mailboxes, key, before, action);
            }
            Self::Ack { target, token, .. } => {
                mailboxes.acks.remove(&(target, token));
            }
        }
    }
}

fn apply_item(mailboxes: &mut Mailboxes, key: ItemKey, before: Item, action: ItemAction) {
    if let Some(grant) = before.grant {
        mailboxes.tokens.remove(&grant.token);
    }
    match (action.after(before), mailboxes.items.get_mut(&key)) {
        (Some(item), Some(current)) => *current = item,
        (None, _) => {
            mailboxes.items.remove(&key);
        }
        (Some(_), None) => {} // Complete validation excludes absence before this mutation.
    }
}
