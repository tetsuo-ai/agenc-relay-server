//! Coordinator query-cursor bindings, one-slot continuation, and expiry
//! (spec B.3, B.6).
//!
//! The runtime computes the HMAC and draws the process key and nonce; this
//! module owns the binding tuple, the live table, and every expiry rule so
//! they can be model-tested with a controlled clock.

use std::error::Error;
use std::fmt;

use std::collections::BTreeMap;

use agenc_ircd_types::{
    AccountId, FederationDirectoryQueryKind, Generation, MonotonicTick, NetworkId,
    QUERY_CURSOR_SECONDS, QUERY_SNAPSHOT_ABSOLUTE_SECONDS, ServerId, SessionId, UserId,
};

const MILLIS_PER_SECOND: u64 = 1_000;

/// The complete `QueryCursorBindingTBS` tuple.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryCursorBinding {
    /// The network identity.
    pub network_id: NetworkId,
    /// The coordinator identity.
    pub coordinator_server_id: ServerId,
    /// The process nonce drawn at startup.
    pub process_nonce: [u8; 16],
    /// The bound session.
    pub session_id: SessionId,
    /// The bound user.
    pub user_id: UserId,
    /// The bound account and generation, or none for a guest.
    pub account: Option<(AccountId, Generation)>,
    /// The query kind.
    pub query_kind: FederationDirectoryQueryKind,
    /// The exact query arm bytes without the cursor.
    pub query_arm: Vec<u8>,
    /// The state generation the snapshot was cut at.
    pub state_generation: u64,
    /// The snapshot token.
    pub snapshot_token: [u8; 32],
    /// The page sequence the cursor continues to.
    pub next_page_sequence: u32,
    /// The process-unique counter value.
    pub cursor_counter: u64,
}

/// The continuation-independent part of a binding that a continuation must
/// repeat exactly.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ContinuationRequest {
    /// The requesting session.
    pub session_id: SessionId,
    /// The requesting user.
    pub user_id: UserId,
    /// The requesting account and generation, or none for a guest.
    pub account: Option<(AccountId, Generation)>,
    /// The query kind.
    pub query_kind: FederationDirectoryQueryKind,
    /// The exact query arm bytes.
    pub query_arm: Vec<u8>,
}

/// Why a presented cursor is answered with `QUERY_EXPIRED`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CursorRejection {
    /// No live cursor has these bytes.
    Unknown,
    /// The idle or absolute lifetime passed.
    Expired,
    /// The cursor is bound to another session, account, or query.
    WrongBinding,
}

impl fmt::Display for CursorRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Unknown => "query cursor is unknown",
            Self::Expired => "query cursor expired",
            Self::WrongBinding => "query cursor is bound to another query",
        };
        formatter.write_str(message)
    }
}

impl Error for CursorRejection {}

/// The monotonic process-unique counter behind every cursor.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CursorCounter(u64);

impl CursorCounter {
    /// Uses the current value and advances, or reports exhaustion.
    pub fn draw(&mut self) -> Option<u64> {
        let value = self.0;
        self.0 = self.0.checked_add(1)?;
        Some(value)
    }

    /// Returns the next value without advancing.
    #[must_use]
    pub const fn peek(self) -> u64 {
        self.0
    }
}

/// One live snapshot with its single replace-in-place cursor slot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveCursor {
    /// The bound tuple.
    pub binding: QueryCursorBinding,
    /// When the snapshot was created.
    pub created_at: MonotonicTick,
    /// When the last page was installed.
    pub last_used_at: MonotonicTick,
}

impl LiveCursor {
    /// Reports whether the idle or absolute lifetime has passed at `now`.
    #[must_use]
    pub fn expired(&self, now: MonotonicTick) -> bool {
        let idle = now.get().saturating_sub(self.last_used_at.get());
        let age = now.get().saturating_sub(self.created_at.get());
        idle >= QUERY_CURSOR_SECONDS.saturating_mul(MILLIS_PER_SECOND)
            || age >= QUERY_SNAPSHOT_ABSOLUTE_SECONDS.saturating_mul(MILLIS_PER_SECOND)
    }

    fn matches(&self, request: &ContinuationRequest) -> bool {
        self.binding.session_id == request.session_id
            && self.binding.user_id == request.user_id
            && self.binding.account == request.account
            && self.binding.query_kind == request.query_kind
            && self.binding.query_arm == request.query_arm
    }
}

/// The live table of cursors keyed by their HMAC bytes.
#[derive(Default)]
pub struct QueryCursorTable {
    cursors: BTreeMap<[u8; 32], LiveCursor>,
}

impl QueryCursorTable {
    /// Creates an empty table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of live cursors.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cursors.len()
    }

    /// Reports whether no cursor is live.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cursors.is_empty()
    }

    /// Installs a freshly computed cursor for a new snapshot.
    ///
    /// A collision with a live cursor is a fatal cryptographic-process
    /// failure and is returned as an error rather than retried.
    pub fn install_new(
        &mut self,
        cursor: [u8; 32],
        binding: QueryCursorBinding,
        now: MonotonicTick,
    ) -> Result<(), CursorCollision> {
        if self.cursors.contains_key(&cursor) {
            return Err(CursorCollision);
        }
        self.cursors.insert(
            cursor,
            LiveCursor {
                binding,
                created_at: now,
                last_used_at: now,
            },
        );
        Ok(())
    }

    /// Reports whether a cursor is live, regardless of expiry.
    #[must_use]
    pub fn contains(&self, cursor: &[u8; 32]) -> bool {
        self.cursors.contains_key(cursor)
    }

    /// Validates a presented cursor for one continuation without consuming it.
    pub fn check(
        &self,
        cursor: &[u8; 32],
        request: &ContinuationRequest,
        now: MonotonicTick,
    ) -> Result<&LiveCursor, CursorRejection> {
        let live = self.cursors.get(cursor).ok_or(CursorRejection::Unknown)?;
        if live.expired(now) {
            return Err(CursorRejection::Expired);
        }
        if !live.matches(request) {
            return Err(CursorRejection::WrongBinding);
        }
        Ok(live)
    }

    /// Consumes the presented cursor and installs its precomputed successor
    /// in the same slot, keeping the original creation instant.
    ///
    /// `successor` is `None` on a final page, which releases the slot.
    pub fn replace(
        &mut self,
        cursor: &[u8; 32],
        successor: Option<([u8; 32], QueryCursorBinding)>,
        now: MonotonicTick,
    ) -> Result<(), CursorRejection> {
        let live = self
            .cursors
            .remove(cursor)
            .ok_or(CursorRejection::Unknown)?;
        if let Some((next, binding)) = successor {
            if self.cursors.contains_key(&next) {
                self.cursors.insert(*cursor, live);
                return Err(CursorRejection::WrongBinding);
            }
            self.cursors.insert(
                next,
                LiveCursor {
                    binding,
                    created_at: live.created_at,
                    last_used_at: now,
                },
            );
        }
        Ok(())
    }

    /// Removes every cursor bound to one session.
    pub fn release_session(&mut self, session_id: SessionId) -> usize {
        let before = self.cursors.len();
        self.cursors
            .retain(|_, live| live.binding.session_id != session_id);
        before.saturating_sub(self.cursors.len())
    }

    /// Removes every expired cursor.
    pub fn expire(&mut self, now: MonotonicTick) -> usize {
        let before = self.cursors.len();
        self.cursors.retain(|_, live| !live.expired(now));
        before.saturating_sub(self.cursors.len())
    }
}

/// A computed cursor collided with a live one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CursorCollision;

#[cfg(test)]
#[path = "tests/query_cursor.rs"]
mod tests;
