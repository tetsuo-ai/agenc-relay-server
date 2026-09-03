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
}

impl fmt::Display for MailboxError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::TokenInvalid => "the delivery token is invalid",
            Self::ObjectMismatch => "the object does not match the token",
            Self::Overflow => "sequence overflow",
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
    /// Empty mailboxes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        let keys: Vec<ItemKey> = self
            .items
            .range(start..=end)
            .filter(|(_, item)| item.expires_at > now)
            .map(|(key, _)| *key)
            .take(MAX_BATCH_OBJECTS + 1)
            .collect();
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
        if let Some(record) = self.acks.get(&(target, token)) {
            if record.object_id != object_id {
                return Err(MailboxError::ObjectMismatch);
            }
            return Ok(AckOutcome::Replayed);
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
