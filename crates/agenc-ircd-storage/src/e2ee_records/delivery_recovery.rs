//! Schema-three companion delivery, immutable cut, and combined barrier owners.
#![forbid(unsafe_code)]

mod barrier;
mod clock;
mod cut;
pub mod outbox;
mod page;
mod scope;

#[cfg(test)]
mod tests;

pub use barrier::{BarrierEndpoint, DeliveryBarrier, DeliveryBarrierFields};
pub use clock::{PendingDeadline, PendingDeadlineFields};
pub use cut::{CutPhase, DeliveryOwner, RetirementReason, SnapshotCut, SnapshotCutFields};
pub use outbox::{Acknowledgement, ScopedOutbox, ScopedOutboxFields};
pub use page::{SnapshotEntry, SnapshotPage, SnapshotPageIdentity};
pub use scope::{DeliveryCursor, DeliveryScope, DeliveryScopeFields, LastAcknowledged};

use crate::codec::{Decoder, Encoder};
use crate::{ProtocolRecordBody, ReadPlan, StorageError, StoredKey, TableId};

use super::{DELIVERY_RECOVERY_ROW_KIND, key_of, prefix_range_from, slice_array, suffix};

/// Closed version of the schema-three delivery owner body.
pub const DELIVERY_RECOVERY_VERSION: u16 = 1;
/// Exact coordinator delivery owner prefix.
pub const OWNER_PREFIX: &[u8] = b"delivery-owner/v1/";
/// Exact immutable cut page prefix.
pub const CUT_PAGE_PREFIX: &[u8] = b"delivery-cut-page/v1/";
/// Exact combined coordinator barrier prefix.
pub const BARRIER_PREFIX: &[u8] = b"delivery-barrier/v1/";

/// Canonical number of entries in every nonfinal snapshot page.
pub const ENTRIES_PER_PAGE: u32 = 32;
/// Maximum complete FederationState envelope bytes per entry.
pub const MAX_ENTRY_BYTES: usize = 65_536;
/// Maximum entries in one immutable cut.
pub const MAX_SNAPSHOT_ENTRIES: u32 = 1_000_000;
/// Maximum complete object bytes in one immutable cut.
pub const MAX_SNAPSHOT_BYTES: u64 = 536_870_912;
/// Maximum pages, including one page for an empty cut.
pub const MAX_SNAPSHOT_PAGES: u32 = 31_250;
/// Maximum unwrapped page body, including metadata and a final cursor field.
pub const MAX_PAGE_BODY_BYTES: usize = 2_098_404;

const OWNER_ARM: u16 = 1;
const PAGE_ARM: u16 = 2;
const BARRIER_ARM: u16 = 3;
const OUTBOX_ARM: u16 = 4;
const MAX_OWNER_BODY_BYTES: usize = 322;
const BARRIER_BODY_BYTES: usize = 234;
const PROTOCOL_ENVELOPE_BYTES: usize =
    crate::MAX_DOMAIN_RECORD_BODY_BYTES - crate::MAX_PROTOCOL_BODY_BYTES;
const MAX_WRAPPED_BODY_BYTES: usize = MAX_PAGE_BODY_BYTES + PROTOCOL_ENVELOPE_BYTES;

/// Validates an explicitly selected delivery body version without a fallback decoder.
pub fn validate_body(body: &[u8]) -> Result<(), StorageError> {
    let version = body
        .get(PROTOCOL_ENVELOPE_BYTES..PROTOCOL_ENVELOPE_BYTES + 2)
        .ok_or(StorageError::InvalidEncoding)?;
    match version {
        [0, 1] => DeliveryRecoveryRow::decode(body).map(|_| ()),
        [0, 2] => outbox::replay::ReplayLedgerRow::decode(body).map(|_| ()),
        _ => Err(StorageError::UnsupportedVersion),
    }
}

/// Binds a delivery record to the key namespace of its exact body version.
pub fn validate_at(key: &StoredKey, body: &[u8]) -> Result<(), StorageError> {
    use outbox::replay::{ACK_RANGE_PREFIX, REPLAY_OWNER_PREFIX, ReplayLedgerRow};
    if key.as_bytes().starts_with(REPLAY_OWNER_PREFIX)
        || key.as_bytes().starts_with(ACK_RANGE_PREFIX)
    {
        ReplayLedgerRow::decode_at(key, body).map(|_| ())
    } else {
        DeliveryRecoveryRow::decode_at(key, body).map(|_| ())
    }
}

/// A closed durable owner record; constructors do not grant runtime authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum DeliveryRecoveryRow {
    /// Full accepted scope, cursor, and immutable cut ownership.
    Owner(DeliveryOwner),
    /// One exact ordered cut page and its original random cursor.
    CutPage(SnapshotPage),
    /// Combined delivery endpoints and their separately committed ACKs.
    Barrier(DeliveryBarrier),
    /// Exact event scope, payload references, and durable ACK retention facts.
    Outbox(ScopedOutbox),
}

impl DeliveryRecoveryRow {
    /// Decodes the exact table- and kind-bound body, consuming every byte.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() > MAX_WRAPPED_BODY_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let arm_offset = PROTOCOL_ENVELOPE_BYTES + 2;
        if body.get(arm_offset..arm_offset + 2) == Some(OUTBOX_ARM.to_be_bytes().as_slice())
            && body.len() > PROTOCOL_ENVELOPE_BYTES + outbox::MAX_OUTBOX_BODY_BYTES
        {
            return Err(StorageError::LimitExceeded);
        }
        let envelope =
            ProtocolRecordBody::decode(TableId::E2eeState, DELIVERY_RECOVERY_ROW_KIND, body)?;
        let inner = envelope.canonical_object();
        if inner.len() > MAX_PAGE_BODY_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(inner);
        if decoder.u16()? != DELIVERY_RECOVERY_VERSION {
            return Err(StorageError::UnsupportedVersion);
        }
        let row = match decoder.u16()? {
            OWNER_ARM => Self::Owner(DeliveryOwner::take(&mut decoder)?),
            PAGE_ARM => Self::CutPage(SnapshotPage::take(&mut decoder)?),
            BARRIER_ARM => Self::Barrier(DeliveryBarrier::take(&mut decoder)?),
            OUTBOX_ARM => {
                if inner.len() > outbox::MAX_OUTBOX_BODY_BYTES {
                    return Err(StorageError::LimitExceeded);
                }
                Self::Outbox(ScopedOutbox::take(&mut decoder)?)
            }
            _ => return Err(StorageError::InvalidEncoding),
        };
        decoder.finish()?;
        Ok(row)
    }

    /// Decodes a row and binds every key field to the decoded body identity.
    pub fn decode_at(key: &StoredKey, body: &[u8]) -> Result<Self, StorageError> {
        let row = Self::decode(body)?;
        row.validate_key(key)?;
        Ok(row)
    }

    /// Encodes the closed body without changing its scope or protocol bytes.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let capacity = match self {
            Self::Owner(_) => MAX_OWNER_BODY_BYTES,
            Self::CutPage(page) => page.encoded_len()?,
            Self::Barrier(_) => BARRIER_BODY_BYTES,
            Self::Outbox(_) => outbox::MAX_OUTBOX_BODY_BYTES,
        };
        let mut encoder = Encoder::with_capacity(capacity, MAX_PAGE_BODY_BYTES)?;
        encoder.put_u16(DELIVERY_RECOVERY_VERSION)?;
        match self {
            Self::Owner(owner) => {
                encoder.put_u16(OWNER_ARM)?;
                owner.put(&mut encoder)?;
            }
            Self::CutPage(page) => {
                encoder.put_u16(PAGE_ARM)?;
                page.put(&mut encoder)?;
            }
            Self::Barrier(barrier) => {
                encoder.put_u16(BARRIER_ARM)?;
                barrier.put(&mut encoder)?;
            }
            Self::Outbox(row) => {
                encoder.put_u16(OUTBOX_ARM)?;
                row.put(&mut encoder)?;
            }
        }
        ProtocolRecordBody::new(
            TableId::E2eeState,
            DELIVERY_RECOVERY_ROW_KIND,
            1,
            encoder.finish(),
        )?
        .encode()
    }

    /// Returns the exact key derived from this body's identity.
    pub fn key(&self) -> Result<StoredKey, StorageError> {
        match self {
            Self::Owner(owner) => owner_key(&owner.scope().target_server_id()),
            Self::CutPage(page) => cut_page_key(&page.identity()),
            Self::Barrier(barrier) => barrier_key(&barrier.scope().target_server_id()),
            Self::Outbox(row) => row.key(),
        }
    }

    /// Rejects a different arm, short key, or mismatched identity.
    pub fn validate_key(&self, key: &StoredKey) -> Result<(), StorageError> {
        if self.key()? != *key {
            return Err(StorageError::StaleState);
        }
        Ok(())
    }
}

/// Returns the exact owner key for one target.
pub fn owner_key(target: &[u8; 16]) -> Result<StoredKey, StorageError> {
    key_of(&[OWNER_PREFIX, target])
}

/// Parses the exact owner key, rejecting a suffix or truncated identity.
pub fn parse_owner_key(key: &StoredKey) -> Result<[u8; 16], StorageError> {
    slice_array(suffix(key, OWNER_PREFIX, 16)?, 0)
}

/// Returns the combined barrier owner key for one target.
pub fn barrier_key(target: &[u8; 16]) -> Result<StoredKey, StorageError> {
    key_of(&[BARRIER_PREFIX, target])
}

/// Parses the exact combined barrier key.
pub fn parse_barrier_key(key: &StoredKey) -> Result<[u8; 16], StorageError> {
    slice_array(suffix(key, BARRIER_PREFIX, 16)?, 0)
}

/// Returns the exact key of one immutable page.
pub fn cut_page_key(id: &SnapshotPageIdentity) -> Result<StoredKey, StorageError> {
    key_of(&[
        CUT_PAGE_PREFIX,
        &id.target_server_id(),
        &id.delivery_generation().to_be_bytes(),
        &id.token(),
        &id.page_sequence().to_be_bytes(),
    ])
}

/// Parses every field of an immutable page key.
pub fn parse_cut_page_key(key: &StoredKey) -> Result<SnapshotPageIdentity, StorageError> {
    let rest = suffix(key, CUT_PAGE_PREFIX, 60)?;
    SnapshotPageIdentity::new(
        slice_array(rest, 0)?,
        u64::from_be_bytes(slice_array(rest, 16)?),
        slice_array(rest, 24)?,
        u32::from_be_bytes(slice_array(rest, 56)?),
    )
}

/// Reads a bounded range belonging to only this target, generation, and token.
pub fn cut_pages_from(
    target: &[u8; 16],
    generation: u64,
    token: &[u8; 32],
    first_page: u32,
    limit: u16,
) -> Result<ReadPlan, StorageError> {
    let scope = key_of(&[CUT_PAGE_PREFIX, target, &generation.to_be_bytes(), token])?;
    let id = SnapshotPageIdentity::new(*target, generation, *token, first_page)?;
    prefix_range_from(scope.as_bytes(), &cut_page_key(&id)?, limit)
}

/// One valid kind-fourteen body for construction and codec fixtures.
pub fn fixture_body(seed: u8) -> Result<Vec<u8>, StorageError> {
    let scope = DeliveryScope::new(DeliveryScopeFields {
        network_id: [seed; 32],
        coordinator_server_id: [seed; 16],
        coordinator_incarnation: [seed; 16],
        coordinator_recovery_epoch: [seed; 16],
        target_server_id: [seed; 16],
        target_incarnation: [seed; 16],
        covered_base_client_resync_epoch: u64::from(seed),
    })?;
    let cursor = DeliveryCursor::new(0, 0, LastAcknowledged::BeforeFirst)?;
    let cut = SnapshotCut::new(SnapshotCutFields {
        token: [seed; 32],
        state_generation: 0,
        delivery_generation: 0,
        entry_count: 0,
        digest: [seed; 32],
        page_count: 1,
        total_object_bytes: 0,
    })?;
    DeliveryRecoveryRow::Owner(DeliveryOwner::new(scope, cursor, cut, CutPhase::Ready)?).encode()
}
