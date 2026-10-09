//! Bounded, connection-local replies to already completed object submissions.
//!
//! A reply kept for its submission's retries counts against its connection's
//! and its account's own quota, and its memory is charged to the process
//! budget (architecture 19.2), so no connection or account holds what
//! another client's replies need (companion 16).

use std::collections::{BTreeMap, BTreeSet};

use agenc_relay_client_wire::{MAX_PHYSICAL_LINE_BYTES, WireMessage};
use agenc_relay_e2ee::limits::RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS;
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;

use super::router::{Refusal, Resolved};
use super::{ClientOutput, PendingRequest};
use crate::budget::{MemoryCharge, MemoryPermit};
use crate::connection::ConnectionGeneration;

/// Connection, attached session, content address, and canonical command scope.
pub(super) type ReplyKey = (u64, u64, [u8; 32], [u8; 32]);
/// The replies one connection keeps, with the reservations of its
/// outstanding submissions.
pub(super) const CONNECTION_REPLIES: usize = 512;
/// The bytes those replies and reservations are charged.
pub(super) const CONNECTION_REPLY_BYTES: u64 = 4 * 1024 * 1024;
/// The replies one account keeps over all its connections on the edge,
/// with their reservations.
pub(super) const ACCOUNT_REPLIES: usize = 1_024;
/// The bytes those replies and reservations are charged.
pub(super) const ACCOUNT_REPLY_BYTES: u64 = 8 * 1024 * 1024;
/// What one kept reply holds besides its lines: its key, its command and
/// its entries in the maps.
const ENTRY_BYTES: usize = 512;

/// The most the reply to `command` is charged when it is kept: a live
/// carrier's echo to its requester, one line per fragment of its object,
/// or any other submission's one line (companion 11.7), each at most one
/// physical client line. Zero for a command that carries no object, whose
/// reply is never kept.
pub(super) fn reply_reservation(command: &Resolved) -> u64 {
    let Some(carrier) = command.carrier() else {
        return 0;
    };
    let lines = if carrier.is_live() {
        usize::try_from(carrier.limit().max_fragments).unwrap_or(usize::MAX)
    } else {
        1
    };
    lines
        .checked_mul(MAX_PHYSICAL_LINE_BYTES)
        .and_then(|bytes| bytes.checked_add(lines.saturating_sub(1)))
        .and_then(charge)
        .unwrap_or(u64::MAX)
}

/// The charge of one kept reply whose lines, joined, are `text` bytes.
fn charge(text: usize) -> Option<u64> {
    let capacity = u64::try_from(text.checked_add(ENTRY_BYTES)?).ok()?;
    MemoryCharge::allocation(capacity)
        .ok()
        .map(MemoryCharge::bytes)
}

/// The replies and bytes one holder keeps or reserves.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(super) struct Usage {
    pub(super) replies: usize,
    pub(super) bytes: u64,
}

impl Usage {
    /// This usage with one more reply of `bytes`.
    pub(super) const fn with(self, bytes: u64) -> Self {
        Self {
            replies: self.replies.saturating_add(1),
            bytes: self.bytes.saturating_add(bytes),
        }
    }

    const fn plus(self, other: Self) -> Self {
        Self {
            replies: self.replies.saturating_add(other.replies),
            bytes: self.bytes.saturating_add(other.bytes),
        }
    }

    const fn within(self, replies: usize, bytes: u64) -> bool {
        self.replies <= replies && self.bytes <= bytes
    }
}

struct Reply {
    command: Resolved,
    account: [u8; 24],
    text: Box<str>,
    charge: u64,
    until: u64,
    _memory: MemoryPermit,
}

#[derive(Default)]
pub(super) struct Replies {
    entries: BTreeMap<ReplyKey, Reply>,
    /// Every entry by when it expires, so expiry visits only what expired.
    expiry: BTreeSet<(u64, ReplyKey)>,
    connections: BTreeMap<u64, Usage>,
    accounts: BTreeMap<[u8; 24], Usage>,
}

impl Replies {
    pub(super) fn expire(&mut self, now: u64) {
        while let Some(&(until, key)) = self.expiry.first() {
            if until > now {
                break;
            }
            self.remove(&key);
        }
    }

    pub(super) fn disconnect(&mut self, generation: ConnectionGeneration) {
        let connection = generation.get();
        let keys: Vec<ReplyKey> = self
            .entries
            .range(
                (connection, 0, [0; 32], [0; 32])
                    ..=(connection, u64::MAX, [u8::MAX; 32], [u8::MAX; 32]),
            )
            .map(|(key, _)| *key)
            .collect();
        for key in keys {
            self.remove(&key);
        }
    }

    fn remove(&mut self, key: &ReplyKey) {
        let Some(reply) = self.entries.remove(key) else {
            return;
        };
        self.expiry.remove(&(reply.until, *key));
        release(&mut self.connections, key.0, reply.charge);
        release(&mut self.accounts, reply.account, reply.charge);
    }

    /// Whether one more submission of `generation` under `account` whose
    /// reply is kept for its retries fits, reserving `reservation` bytes:
    /// the connection's and the account's kept replies, with `outstanding`,
    /// the reservations of their submissions still outstanding, stay within
    /// their own quotas. Nothing another connection or account keeps
    /// counts, and a holder at its quota is refused, never evicted.
    pub(super) fn admits(
        &self,
        generation: ConnectionGeneration,
        account: &[u8; 24],
        outstanding: (Usage, Usage),
        reservation: u64,
    ) -> bool {
        let kept = |usage: Option<&Usage>| usage.copied().unwrap_or_default();
        kept(self.connections.get(&generation.get()))
            .plus(outstanding.0)
            .with(reservation)
            .within(CONNECTION_REPLIES, CONNECTION_REPLY_BYTES)
            && kept(self.accounts.get(account))
                .plus(outstanding.1)
                .with(reservation)
                .within(ACCOUNT_REPLIES, ACCOUNT_REPLY_BYTES)
    }

    /// Keeps the reply `lines` of `pending` for its retries, charged out of
    /// the memory its submission reserved; the rest of that reservation
    /// returns to the budget.
    pub(super) fn remember(
        &mut self,
        pending: &mut PendingRequest,
        lines: Vec<String>,
        now: u64,
    ) -> Result<(), Refusal> {
        let Some(key) = pending.reply_key else {
            return Ok(());
        };
        let text = lines
            .iter()
            .map(|line| line.trim_end_matches("\r\n"))
            .collect::<Vec<_>>()
            .join("\n")
            .into_boxed_str();
        let charge = charge(text.len()).ok_or(E2eeReplyCode::ObjectTooLarge)?;
        let memory = pending
            .reservation
            .take()
            .and_then(|mut reserved| reserved.split_exact(charge))
            .ok_or(E2eeReplyCode::ObjectTooLarge)?;
        self.remove(&key);
        let until = now.saturating_add(RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS);
        self.expiry.insert((until, key));
        acquire(&mut self.connections, key.0, charge);
        acquire(&mut self.accounts, pending.account, charge);
        self.entries.insert(
            key,
            Reply {
                command: pending.command.clone(),
                account: pending.account,
                text,
                charge,
                until,
                _memory: memory,
            },
        );
        Ok(())
    }

    pub(super) fn replay(
        &self,
        key: ReplyKey,
        command: &Resolved,
        label: Option<&str>,
    ) -> Result<Option<ClientOutput>, Refusal> {
        let Some(reply) = self.entries.get(&key) else {
            return Ok(None);
        };
        if &reply.command != command {
            return Err(E2eeReplyCode::InvalidFragment.into());
        }
        let frames = reply
            .text
            .split('\n')
            .filter(|line| !line.is_empty())
            .enumerate()
            .map(|(index, line)| {
                WireMessage::extension_line(&relabel(line, label, index == 0))
                    .map_err(|_| Refusal::from(E2eeReplyCode::InvalidFragment))
            })
            .collect::<Result<_, _>>()?;
        Ok(Some(ClientOutput {
            generation: ConnectionGeneration::new(key.0),
            frames,
        }))
    }
}

fn acquire<K: Ord>(usage: &mut BTreeMap<K, Usage>, holder: K, charge: u64) {
    let held = usage.entry(holder).or_default();
    *held = held.with(charge);
}

fn release<K: Ord>(usage: &mut BTreeMap<K, Usage>, holder: K, charge: u64) {
    let std::collections::btree_map::Entry::Occupied(mut held) = usage.entry(holder) else {
        return;
    };
    let left = Usage {
        replies: held.get().replies.saturating_sub(1),
        bytes: held.get().bytes.saturating_sub(charge),
    };
    if left.replies == 0 {
        held.remove();
    } else {
        *held.get_mut() = left;
    }
}

/// Preserve fragment and batch tags, replacing only the request label.
fn relabel(line: &str, label: Option<&str>, first: bool) -> String {
    let (tags, body) = line
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(' '))
        .map_or((Vec::new(), line), |(tags, body)| {
            (tags.split(';').collect::<Vec<_>>(), body)
        });
    let had_label = tags.iter().any(|tag| tag.starts_with("label="));
    let mut tags: Vec<String> = tags
        .into_iter()
        .filter(|tag| !tag.starts_with("label="))
        .map(str::to_owned)
        .collect();
    if (first || had_label)
        && let Some(label) = label
    {
        tags.insert(0, format!("label={label}"));
    }
    if tags.is_empty() {
        body.to_owned()
    } else {
        format!("@{} {body}", tags.join(";"))
    }
}

#[cfg(test)]
impl Replies {
    /// Retry tests: what `connection` and `account` keep, with no entry for
    /// a holder that keeps nothing.
    pub(super) fn usage_for_test(
        &self,
        connection: u64,
        account: &[u8; 24],
    ) -> (Option<Usage>, Option<Usage>) {
        (
            self.connections.get(&connection).copied(),
            self.accounts.get(account).copied(),
        )
    }
}
