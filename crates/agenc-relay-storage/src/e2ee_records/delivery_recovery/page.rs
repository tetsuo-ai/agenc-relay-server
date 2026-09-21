//! Exact immutable page bytes, canonical partition, and original cursor ownership.
#![forbid(unsafe_code)]

use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::federation::ArcFederationRouteState;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};

use super::{
    DeliveryOwner, ENTRIES_PER_PAGE, MAX_ENTRY_BYTES, MAX_PAGE_BODY_BYTES, MAX_SNAPSHOT_PAGES,
};
use crate::StorageError;
use crate::codec::{Decoder, Encoder};

/// Complete identity used by an immutable page key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotPageIdentity {
    target_server_id: [u8; 16],
    delivery_generation: u64,
    token: [u8; 32],
    page_sequence: u32,
}

impl SnapshotPageIdentity {
    /// Validates the page position against the closed snapshot ceiling.
    pub fn new(
        target_server_id: [u8; 16],
        delivery_generation: u64,
        token: [u8; 32],
        page_sequence: u32,
    ) -> Result<Self, StorageError> {
        if page_sequence >= MAX_SNAPSHOT_PAGES {
            return Err(StorageError::LimitExceeded);
        }
        Ok(Self {
            target_server_id,
            delivery_generation,
            token,
            page_sequence,
        })
    }

    /// Returns the exact target server identity.
    #[must_use]
    pub const fn target_server_id(&self) -> [u8; 16] {
        self.target_server_id
    }
    /// Returns the delivery generation, including a valid generation zero.
    #[must_use]
    pub const fn delivery_generation(&self) -> u64 {
        self.delivery_generation
    }
    /// Returns the original cut token.
    #[must_use]
    pub const fn token(&self) -> [u8; 32] {
        self.token
    }
    /// Returns the zero-based page sequence.
    #[must_use]
    pub const fn page_sequence(&self) -> u32 {
        self.page_sequence
    }

    fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_fixed(&self.target_server_id)?;
        encoder.put_u64(self.delivery_generation)?;
        encoder.put_fixed(&self.token)?;
        encoder.put_u32(self.page_sequence)
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(
            decoder.array()?,
            decoder.u64()?,
            decoder.array()?,
            decoder.u32()?,
        )
    }
}

/// One complete FederationState envelope bound to its conversation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotEntry {
    conversation_id: [u8; 32],
    bytes: Box<[u8]>,
}

impl SnapshotEntry {
    /// Validates envelope kind, profile, full consumption, and conversation identity.
    pub fn new(conversation_id: [u8; 32], bytes: Vec<u8>) -> Result<Self, StorageError> {
        let route = route_state(&bytes)?;
        if route.conversation_id != conversation_id {
            return Err(StorageError::StaleState);
        }
        Ok(Self {
            conversation_id,
            bytes: bytes.into_boxed_slice(),
        })
    }

    /// Returns the entry's canonical ordering identity.
    #[must_use]
    pub const fn conversation_id(&self) -> [u8; 32] {
        self.conversation_id
    }
    /// Returns the exact retained wire bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_fixed(&self.conversation_id)?;
        encoder.put_vector_u32(&self.bytes)
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let conversation_id = decoder.array()?;
        let bytes = decoder.vector_u32(MAX_ENTRY_BYTES)?;
        let mut owned = Vec::new();
        owned
            .try_reserve_exact(bytes.len())
            .map_err(|_| StorageError::AllocationFailed)?;
        owned.extend_from_slice(bytes);
        Self::new(conversation_id, owned)
    }
}

fn route_state(bytes: &[u8]) -> Result<ArcFederationRouteState, StorageError> {
    if bytes.is_empty() || bytes.len() > MAX_ENTRY_BYTES {
        return Err(StorageError::LimitExceeded);
    }
    let mut budget = DecodeBudget::new(MAX_ENTRY_BYTES, 64);
    let object =
        ArcWireObject::decode_kind(bytes, Some(ArcWireObjectKind::FederationState), &mut budget)
            .map_err(|_| StorageError::InvalidEncoding)?;
    let route = ArcFederationRouteState::decode_exact(object.body(), &mut budget)
        .map_err(|_| StorageError::InvalidEncoding)?;
    if route.profile_version != 1 {
        return Err(StorageError::UnsupportedVersion);
    }
    Ok(route)
}

/// One bounded page whose object and cursor bytes never change after publication.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SnapshotPage {
    identity: SnapshotPageIdentity,
    entries: Box<[SnapshotEntry]>,
    next_cursor: Option<[u8; 32]>,
}

impl SnapshotPage {
    /// Validates the local page bound, entry order, and nonfinal page shape.
    pub fn new(
        identity: SnapshotPageIdentity,
        entries: Vec<SnapshotEntry>,
        next_cursor: Option<[u8; 32]>,
    ) -> Result<Self, StorageError> {
        if entries.len() > ENTRIES_PER_PAGE as usize {
            return Err(StorageError::LimitExceeded);
        }
        if next_cursor.is_some() && entries.len() != ENTRIES_PER_PAGE as usize {
            return Err(StorageError::InvalidEncoding);
        }
        if entries.windows(2).any(|pair| {
            let [left, right] = pair else { return true };
            left.conversation_id >= right.conversation_id
        }) {
            return Err(StorageError::InvalidEncoding);
        }
        let page = Self {
            identity,
            entries: entries.into_boxed_slice(),
            next_cursor,
        };
        if page.encoded_len()? > MAX_PAGE_BODY_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        Ok(page)
    }

    /// Returns the complete key identity.
    #[must_use]
    pub const fn identity(&self) -> SnapshotPageIdentity {
        self.identity
    }
    /// Returns the canonical ordered entries without copying their bytes.
    #[must_use]
    pub fn entries(&self) -> &[SnapshotEntry] {
        &self.entries
    }
    /// Returns the original cursor, or None for final END.
    #[must_use]
    pub const fn next_cursor(&self) -> Option<[u8; 32]> {
        self.next_cursor
    }

    /// Validates this page against its historical cut; whole-cut digest remains a streamed check.
    pub fn validate_for(&self, owner: &DeliveryOwner) -> Result<(), StorageError> {
        let cut = owner.cut();
        if self.identity.target_server_id != owner.scope().target_server_id()
            || self.identity.delivery_generation != cut.delivery_generation()
            || self.identity.token != cut.token()
            || self.identity.page_sequence >= cut.page_count()
        {
            return Err(StorageError::StaleState);
        }
        let start = self
            .identity
            .page_sequence
            .checked_mul(ENTRIES_PER_PAGE)
            .ok_or(StorageError::Overflow)?;
        let expected = cut
            .entry_count()
            .checked_sub(start)
            .ok_or(StorageError::InvalidEncoding)?
            .min(ENTRIES_PER_PAGE);
        let final_page = self.identity.page_sequence.checked_add(1) == Some(cut.page_count());
        if self.entries.len() != expected as usize || self.next_cursor.is_some() == final_page {
            return Err(StorageError::InvalidEncoding);
        }
        for entry in &self.entries {
            let state = route_state(entry.bytes())?;
            if state.network_id != owner.scope().network_id()
                || state.state_generation > cut.state_generation()
            {
                return Err(StorageError::StaleState);
            }
        }
        Ok(())
    }

    pub(super) fn encoded_len(&self) -> Result<usize, StorageError> {
        let prefix = 68_usize + if self.next_cursor.is_some() { 32 } else { 0 };
        self.entries.iter().try_fold(prefix, |length, entry| {
            length
                .checked_add(36)
                .and_then(|length| length.checked_add(entry.bytes.len()))
                .ok_or(StorageError::Overflow)
        })
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.identity.put(encoder)?;
        encoder
            .put_u16(u16::try_from(self.entries.len()).map_err(|_| StorageError::LimitExceeded)?)?;
        for entry in &self.entries {
            entry.put(encoder)?;
        }
        encoder.put_u16(u16::from(self.next_cursor.is_some()))?;
        if let Some(cursor) = self.next_cursor {
            encoder.put_fixed(&cursor)?;
        }
        Ok(())
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let identity = SnapshotPageIdentity::take(decoder)?;
        let count = usize::from(decoder.u16()?);
        if count > ENTRIES_PER_PAGE as usize {
            return Err(StorageError::LimitExceeded);
        }
        let mut entries = Vec::new();
        entries
            .try_reserve_exact(count)
            .map_err(|_| StorageError::AllocationFailed)?;
        for _ in 0..count {
            entries.push(SnapshotEntry::take(decoder)?);
        }
        let cursor = match decoder.u16()? {
            0 => None,
            1 => Some(decoder.array()?),
            _ => return Err(StorageError::InvalidEncoding),
        };
        Self::new(identity, entries, cursor)
    }
}
