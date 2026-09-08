//! Device mailboxes (companion 11.6): per-device queues per kind, delivery
//! tokens bound to the snapshot, object, device, and attachment session
//! generation, idempotent acknowledgements with retained results, and
//! retention.
//!
//! Tokens are supplied by the caller from its entropy source; the model
//! never generates randomness.

use std::collections::BTreeMap;
use std::fmt;

use super::limits::{
    MAILBOX_ACK_RETENTION_SECONDS, MAILBOX_DELIVERY_TOKEN_TIMEOUT_SECONDS, MAX_BATCH_OBJECTS,
};

/// A 32-byte identifier.
pub type Id = [u8; 32];
/// A 16-byte identifier.
pub type Id16 = [u8; 16];

/// The four mailbox kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum MailboxKind {
    /// Queued application objects.
    Application,
    /// Delivered bindings.
    Binding,
    /// Delivered Welcomes.
    Welcome,
    /// Staged ReInits.
    StagedReinit,
}

/// One mailbox target.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct Target {
    /// Account digest.
    pub account_digest: Id,
    /// Device identity.
    pub device_id: Id16,
}

/// Why a mailbox operation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxError {
    /// The token is unknown, expired, or bound to another session.
    TokenInvalid,
    /// The acknowledgement names a different object under a used token.
    ObjectMismatch,
    /// Arithmetic overflow.
    Overflow,
    /// The caller could not validate the retained item's admission context.
    AdmissionRefused,
}

impl fmt::Display for MailboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TokenInvalid => "the delivery token is invalid",
            Self::ObjectMismatch => "the object does not match the token",
            Self::Overflow => "sequence overflow",
            Self::AdmissionRefused => "mailbox item admission was refused",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for MailboxError {}

/// An issued delivery grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Grant {
    /// The token.
    pub token: Id,
    /// The attachment session generation the token is bound to.
    pub session_generation: u64,
    /// Expiry second.
    pub expires_at: u64,
}

/// One queued item.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Item {
    /// The retained object identifier.
    pub object_id: Id,
    /// The conversation the item belongs to, zero for bindings.
    pub conversation_id: Id,
    /// Insertion second.
    pub inserted_at: u64,
    /// Retention boundary.
    pub expires_at: u64,
    /// The outstanding grant.
    pub grant: Option<Grant>,
}

/// One page entry handed to a fetching device.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Delivery {
    /// Item sequence.
    pub sequence: u64,
    /// The object identifier.
    pub object_id: Id,
    /// The fresh or still-valid token.
    pub token: Id,
}

/// A fetched page.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Page {
    /// Deliveries in sequence order.
    pub deliveries: Vec<Delivery>,
    /// The sequence to continue from, if more items remain.
    pub next: Option<u64>,
}

/// One exact mailbox and inclusive continuation position.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FetchSelector {
    /// Account and device whose items are selected.
    pub target: Target,
    /// The selected object kind.
    pub kind: MailboxKind,
    /// First sequence to consider, or the beginning of the mailbox.
    pub cursor: Option<u64>,
}

/// The outcome of an acknowledgement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AckOutcome {
    /// First acknowledgement; the item is now unavailable.
    Acked,
    /// An identical retry within the retention window.
    Replayed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AckRecord {
    object_id: Id,
    retain_until: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
struct ItemKey {
    target: Target,
    kind: MailboxKind,
    sequence: u64,
}

/// The mailboxes.
#[derive(Clone, Debug, Default)]
pub struct Mailboxes {
    items: BTreeMap<ItemKey, Item>,
    next_sequence: BTreeMap<(Target, MailboxKind), u64>,
    tokens: BTreeMap<Id, ItemKey>,
    acks: BTreeMap<(Target, Id), AckRecord>,
}

impl Mailboxes {
    /// Returns the object's ID only when this exact item owns its last mailbox reference.
    #[must_use]
    pub fn last_object_reference(
        &self,
        target: Target,
        kind: MailboxKind,
        sequence: u64,
    ) -> Option<Id> {
        let key = ItemKey {
            target,
            kind,
            sequence,
        };
        let id = self.items.get(&key)?.object_id;
        (!self
            .items
            .iter()
            .any(|(other, item)| *other != key && item.object_id == id))
        .then_some(id)
    }

    /// Any retained item keeps its object referenced until that item is removed.
    #[must_use]
    pub fn references_object(&self, object_id: &Id) -> bool {
        self.items.values().any(|item| item.object_id == *object_id)
    }

    /// The number of undelivered or unacknowledged items.
    #[must_use]
    pub fn item_count(&self) -> usize {
        self.items.len()
    }

    /// Borrows one exact retained item without granting, consuming or expiring it.
    #[must_use]
    pub fn retained_item(&self, target: Target, kind: MailboxKind, sequence: u64) -> Option<&Item> {
        self.items.get(&ItemKey {
            target,
            kind,
            sequence,
        })
    }

    /// Empty mailboxes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores one durable item at startup under its stored sequence; the
    /// next sequence of that mailbox advances past it.
    pub fn restore_item(&mut self, target: Target, kind: MailboxKind, sequence: u64, item: Item) {
        let key = ItemKey {
            target,
            kind,
            sequence,
        };
        let next = self.next_sequence.entry((target, kind)).or_insert(0);
        *next = (*next).max(sequence.saturating_add(1));
        if let Some(grant) = item.grant {
            self.tokens.insert(grant.token, key);
        }
        self.items.insert(key, item);
    }

    /// Restores one acknowledgement result at startup.
    pub fn restore_ack(&mut self, target: Target, token: Id, object_id: Id, retain_until: u64) {
        self.acks.insert(
            (target, token),
            AckRecord {
                object_id,
                retain_until,
            },
        );
    }

    /// Restores an authenticated exclusive sequence floor without lowering any
    /// retained item's position. A used scope never has a zero floor.
    pub fn restore_sequence(
        &mut self,
        target: Target,
        kind: MailboxKind,
        next_sequence: u64,
    ) -> Result<(), MailboxError> {
        let current = self
            .next_sequence
            .get(&(target, kind))
            .copied()
            .unwrap_or(0);
        let last = ItemKey {
            target,
            kind,
            sequence: u64::MAX,
        };
        let first = ItemKey {
            sequence: 0,
            ..last
        };
        let last_item = self.items.range(first..=last).next_back();
        if next_sequence == 0
            || current > next_sequence
            || last_item.is_some_and(|(key, _)| key.sequence >= next_sequence)
        {
            return Err(MailboxError::AdmissionRefused);
        }
        self.next_sequence.insert((target, kind), next_sequence);
        Ok(())
    }

    /// Queues an object for `target`; returns its sequence.
    pub fn deliver(
        &mut self,
        target: Target,
        kind: MailboxKind,
        object_id: Id,
        conversation_id: Id,
        now: u64,
        retention_seconds: u64,
    ) -> Result<u64, MailboxError> {
        let next = self.next_sequence.entry((target, kind)).or_insert(0);
        let sequence = *next;
        *next = next.checked_add(1).ok_or(MailboxError::Overflow)?;
        self.items.insert(
            ItemKey {
                target,
                kind,
                sequence,
            },
            Item {
                object_id,
                conversation_id,
                inserted_at: now,
                expires_at: now
                    .checked_add(retention_seconds)
                    .ok_or(MailboxError::Overflow)?,
                grant: None,
            },
        );
        Ok(sequence)
    }

    /// Fetches up to a batch of items from `cursor`, issuing a fresh token
    /// from `tokens` for every item whose grant is missing, expired, or
    /// bound to another session generation.
    pub fn fetch(
        &mut self,
        target: Target,
        kind: MailboxKind,
        cursor: Option<u64>,
        session_generation: u64,
        now: u64,
        tokens: &mut dyn FnMut() -> Id,
    ) -> Result<Page, MailboxError> {
        self.fetch_admitted(
            FetchSelector {
                target,
                kind,
                cursor,
            },
            session_generation,
            now,
            tokens,
            &mut |_| Ok(true),
        )
    }

    /// Applies the caller's read-only admission check to each selected item
    /// before issuing any grant. Excluded items remain queued unchanged.
    pub fn fetch_admitted(
        &mut self,
        selector: FetchSelector,
        session_generation: u64,
        now: u64,
        tokens: &mut dyn FnMut() -> Id,
        admit: &mut dyn FnMut(&Item) -> Result<bool, MailboxError>,
    ) -> Result<Page, MailboxError> {
        let keys = self.admitted_keys(selector, now, admit)?;
        let mut page = Page::default();
        for key in keys.iter().take(MAX_BATCH_OBJECTS) {
            let token = self.grant_for(*key, session_generation, now, tokens)?;
            let item = self.items.get(key).ok_or(MailboxError::TokenInvalid)?;
            page.deliveries.push(Delivery {
                sequence: key.sequence,
                object_id: item.object_id,
                token,
            });
        }
        page.next = keys.get(MAX_BATCH_OBJECTS).map(|key| key.sequence);
        Ok(page)
    }

    /// Borrows the live ordered contents before a caller reserves an immutable cut.
    pub fn snapshot_items(
        &self,
        target: Target,
        kind: MailboxKind,
        now: u64,
    ) -> impl Iterator<Item = (u64, &Item)> {
        let first = ItemKey {
            target,
            kind,
            sequence: 0,
        };
        let last = ItemKey {
            sequence: u64::MAX,
            ..first
        };
        self.items
            .range(first..=last)
            .filter_map(move |(key, item)| (item.expires_at > now).then_some((key.sequence, item)))
    }

    /// Grants only an exact retained snapshot page. Every item is checked before
    /// the first token changes; a consumed or expired item never reappears.
    pub fn grant_snapshot(
        &mut self,
        selector: FetchSelector,
        rows: &[(u64, Item)],
        session_generation: u64,
        now: u64,
        tokens: &mut dyn FnMut() -> Id,
    ) -> Result<Vec<Delivery>, MailboxError> {
        if rows.len() > MAX_BATCH_OBJECTS {
            return Err(MailboxError::AdmissionRefused);
        }
        for (sequence, expected) in rows {
            let key = ItemKey {
                target: selector.target,
                kind: selector.kind,
                sequence: *sequence,
            };
            let actual = self.items.get(&key).ok_or(MailboxError::TokenInvalid)?;
            let mut expected = *expected;
            expected.grant = actual.grant;
            if expected != *actual || actual.expires_at <= now {
                return Err(MailboxError::TokenInvalid);
            }
        }
        let mut deliveries = Vec::new();
        for (sequence, item) in rows {
            let key = ItemKey {
                target: selector.target,
                kind: selector.kind,
                sequence: *sequence,
            };
            let token = self.grant_for(key, session_generation, now, tokens)?;
            deliveries.push(Delivery {
                sequence: *sequence,
                object_id: item.object_id,
                token,
            });
        }
        Ok(deliveries)
    }

    fn admitted_keys(
        &self,
        selector: FetchSelector,
        now: u64,
        admit: &mut dyn FnMut(&Item) -> Result<bool, MailboxError>,
    ) -> Result<Vec<ItemKey>, MailboxError> {
        let FetchSelector {
            target,
            kind,
            cursor,
        } = selector;
        let start = ItemKey {
            target,
            kind,
            sequence: cursor.unwrap_or(0),
        };
        let end = ItemKey {
            target,
            kind,
            sequence: u64::MAX,
        };
        let mut keys = Vec::new();
        for (key, item) in self.items.range(start..=end) {
            if item.expires_at <= now || !admit(item)? {
                continue;
            }
            keys.push(*key);
            if keys.len() == MAX_BATCH_OBJECTS + 1 {
                break;
            }
        }
        Ok(keys)
    }

    fn grant_for(
        &mut self,
        key: ItemKey,
        session_generation: u64,
        now: u64,
        tokens: &mut dyn FnMut() -> Id,
    ) -> Result<Id, MailboxError> {
        let item = self.items.get_mut(&key).ok_or(MailboxError::TokenInvalid)?;
        if let Some(grant) = item.grant {
            if grant.session_generation == session_generation && grant.expires_at > now {
                return Ok(grant.token);
            }
            self.tokens.remove(&grant.token);
        }
        let grant = Grant {
            token: tokens(),
            session_generation,
            expires_at: now
                .checked_add(MAILBOX_DELIVERY_TOKEN_TIMEOUT_SECONDS)
                .ok_or(MailboxError::Overflow)?,
        };
        item.grant = Some(grant);
        self.tokens.insert(grant.token, key);
        Ok(grant.token)
    }

    /// Acknowledges `object_id` under `token` for the attached device at
    /// `session_generation`. The first acknowledgement removes the item and
    /// records the result; an identical retry replays it.
    pub fn acknowledge(
        &mut self,
        target: Target,
        token: Id,
        object_id: Id,
        session_generation: u64,
        now: u64,
    ) -> Result<AckOutcome, MailboxError> {
        let Some(key) =
            self.acknowledgement_key(target, token, object_id, session_generation, now)?
        else {
            return Ok(AckOutcome::Replayed);
        };
        self.acks.insert(
            (target, token),
            AckRecord {
                object_id,
                retain_until: now
                    .checked_add(MAILBOX_ACK_RETENTION_SECONDS)
                    .ok_or(MailboxError::Overflow)?,
            },
        );
        self.items.remove(&key);
        self.tokens.remove(&token);
        Ok(AckOutcome::Acked)
    }

    /// Resolves a fully validated live token without consuming it. `None`
    /// means an exact retained ACK replay, never an absent or expired token.
    pub fn acknowledgement_item(
        &self,
        target: Target,
        token: Id,
        object_id: Id,
        session_generation: u64,
        now: u64,
    ) -> Result<Option<(MailboxKind, u64, &Item)>, MailboxError> {
        let key = self.acknowledgement_key(target, token, object_id, session_generation, now)?;
        key.map(|key| {
            self.items
                .get(&key)
                .map(|item| (key.kind, key.sequence, item))
                .ok_or(MailboxError::TokenInvalid)
        })
        .transpose()
    }

    fn acknowledgement_key(
        &self,
        target: Target,
        token: Id,
        object_id: Id,
        session_generation: u64,
        now: u64,
    ) -> Result<Option<ItemKey>, MailboxError> {
        if let Some(record) = self.acks.get(&(target, token)) {
            if record.object_id != object_id {
                return Err(MailboxError::ObjectMismatch);
            }
            return Ok(None);
        }
        let key = *self.tokens.get(&token).ok_or(MailboxError::TokenInvalid)?;
        let item = self.items.get(&key).ok_or(MailboxError::TokenInvalid)?;
        let grant = item.grant.ok_or(MailboxError::TokenInvalid)?;
        let valid = key.target == target
            && grant.token == token
            && grant.session_generation == session_generation
            && grant.expires_at > now;
        if !valid {
            return Err(MailboxError::TokenInvalid);
        }
        if item.object_id != object_id {
            return Err(MailboxError::ObjectMismatch);
        }
        Ok(Some(key))
    }

    /// Invalidates every token of `target` (detach, logout, reconnect); the
    /// items stay queued.
    pub fn detach(&mut self, target: &Target) -> usize {
        let mut invalidated = 0;
        for (key, item) in self.items.iter_mut() {
            if key.target != *target {
                continue;
            }
            if let Some(grant) = item.grant.take() {
                self.tokens.remove(&grant.token);
                invalidated += 1;
            }
        }
        invalidated
    }

    /// Removes expired items and acknowledgement results; returns the
    /// object identifiers of the expired items.
    pub fn expire(&mut self, now: u64) -> Vec<Id> {
        let expired: Vec<ItemKey> = self
            .items
            .iter()
            .filter(|(_, item)| item.expires_at <= now)
            .map(|(key, _)| *key)
            .collect();
        let mut objects = Vec::with_capacity(expired.len());
        for key in expired {
            if let Some(item) = self.items.remove(&key) {
                if let Some(grant) = item.grant {
                    self.tokens.remove(&grant.token);
                }
                objects.push(item.object_id);
            }
        }
        self.acks.retain(|_, record| record.retain_until > now);
        objects
    }

    /// Whether any live item for `target` references `conversation_id`.
    #[must_use]
    pub fn references(&self, target: &Target, conversation_id: &Id) -> bool {
        self.items
            .iter()
            .any(|(key, item)| key.target == *target && item.conversation_id == *conversation_id)
    }

    /// Queued items for `target` of `kind`.
    #[must_use]
    pub fn queued(&self, target: &Target, kind: MailboxKind) -> usize {
        self.items
            .keys()
            .filter(|key| key.target == *target && key.kind == kind)
            .count()
    }
}

#[cfg(test)]
#[path = "tests/mailbox.rs"]
mod tests;
