//! Immutable cut identity and cut-local Pending, Ready, or Retired state.
#![forbid(unsafe_code)]

use super::{DeliveryCursor, DeliveryScope, PendingDeadline};
use super::{ENTRIES_PER_PAGE, MAX_ENTRY_BYTES, MAX_SNAPSHOT_BYTES, MAX_SNAPSHOT_ENTRIES};
use crate::StorageError;
use crate::codec::{Decoder, Encoder};

/// Immutable snapshot identity and bounded totals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotCutFields {
    /// Original snapshot token.
    pub token: [u8; 32],
    /// Coordinator state generation at the immutable cut.
    pub state_generation: u64,
    /// Delivery generation opened by this cut.
    pub delivery_generation: u64,
    /// Total number of route entries.
    pub entry_count: u32,
    /// Existing federation snapshot digest.
    pub digest: [u8; 32],
    /// Exact number of retained pages, including one empty page.
    pub page_count: u32,
    /// Sum of complete route object bytes.
    pub total_object_bytes: u64,
}

/// Validated immutable snapshot identity and bounded totals.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SnapshotCut {
    fields: SnapshotCutFields,
}

impl SnapshotCut {
    /// Validates one complete set of fields.
    pub fn new(fields: SnapshotCutFields) -> Result<Self, StorageError> {
        if fields.entry_count > MAX_SNAPSHOT_ENTRIES
            || fields.total_object_bytes > MAX_SNAPSHOT_BYTES
        {
            return Err(StorageError::LimitExceeded);
        }
        let expected_pages = fields.entry_count.div_ceil(ENTRIES_PER_PAGE).max(1);
        let maximum_bytes = u64::from(fields.entry_count) * MAX_ENTRY_BYTES as u64;
        if fields.page_count != expected_pages
            || fields.total_object_bytes > maximum_bytes
            || fields.total_object_bytes < u64::from(fields.entry_count)
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self { fields })
    }

    /// Returns original snapshot token.
    #[must_use]
    pub const fn token(&self) -> [u8; 32] {
        self.fields.token
    }

    /// Returns coordinator state generation at the immutable cut.
    #[must_use]
    pub const fn state_generation(&self) -> u64 {
        self.fields.state_generation
    }

    /// Returns delivery generation opened by this cut.
    #[must_use]
    pub const fn delivery_generation(&self) -> u64 {
        self.fields.delivery_generation
    }

    /// Returns total number of route entries.
    #[must_use]
    pub const fn entry_count(&self) -> u32 {
        self.fields.entry_count
    }

    /// Returns existing federation snapshot digest.
    #[must_use]
    pub const fn digest(&self) -> [u8; 32] {
        self.fields.digest
    }

    /// Returns exact number of retained pages, including one empty page.
    #[must_use]
    pub const fn page_count(&self) -> u32 {
        self.fields.page_count
    }

    /// Returns sum of complete route object bytes.
    #[must_use]
    pub const fn total_object_bytes(&self) -> u64 {
        self.fields.total_object_bytes
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        encoder.put_fixed(&self.fields.token)?;
        encoder.put_u64(self.fields.state_generation)?;
        encoder.put_u64(self.fields.delivery_generation)?;
        encoder.put_u32(self.fields.entry_count)?;
        encoder.put_fixed(&self.fields.digest)?;
        encoder.put_u32(self.fields.page_count)?;
        encoder.put_u64(self.fields.total_object_bytes)?;
        Ok(())
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(SnapshotCutFields {
            token: decoder.array()?,
            state_generation: decoder.u64()?,
            delivery_generation: decoder.u64()?,
            entry_count: decoder.u32()?,
            digest: decoder.array()?,
            page_count: decoder.u32()?,
            total_object_bytes: decoder.u64()?,
        })
    }
}

/// Why only the pending token ceased to authorize transfer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetirementReason {
    /// Its original monotonic deadline was reached.
    DeadlineReached,
    /// Its boot or namespace coordinate is no longer available.
    ClockScopeLost,
    /// Clock input failed validation or moved backwards.
    ClockInvalid,
    /// The peer supplied a conflicting transfer request.
    TransferRejected,
}

impl RetirementReason {
    fn code(self) -> u16 {
        match self {
            Self::DeadlineReached => 1,
            Self::ClockScopeLost => 2,
            Self::ClockInvalid => 3,
            Self::TransferRejected => 4,
        }
    }

    fn decode(value: u16) -> Result<Self, StorageError> {
        match value {
            1 => Ok(Self::DeadlineReached),
            2 => Ok(Self::ClockScopeLost),
            3 => Ok(Self::ClockInvalid),
            4 => Ok(Self::TransferRejected),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// Durable cut phase; connection activity is never serialized here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CutPhase {
    /// Immutable pages may be fetched until the original deadline.
    Pending {
        /// Number of durably offered pages, starting at one.
        offered_pages: u32,
        /// Nonextendable absolute deadline in its original coordinate.
        deadline: PendingDeadline,
    },
    /// Exact READY was durably accepted, independent of pending expiry.
    Ready,
    /// Only this token is retired; stream and barrier ownership survives.
    Retired(RetirementReason),
}

impl CutPhase {
    fn put(self, encoder: &mut Encoder) -> Result<(), StorageError> {
        match self {
            Self::Pending {
                offered_pages,
                deadline,
            } => {
                encoder.put_u16(1)?;
                encoder.put_u32(offered_pages)?;
                deadline.put(encoder)
            }
            Self::Ready => encoder.put_u16(2),
            Self::Retired(reason) => {
                encoder.put_u16(3)?;
                encoder.put_u16(reason.code())
            }
        }
    }

    fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        match decoder.u16()? {
            1 => Ok(Self::Pending {
                offered_pages: decoder.u32()?,
                deadline: PendingDeadline::take(decoder)?,
            }),
            2 => Ok(Self::Ready),
            3 => Ok(Self::Retired(RetirementReason::decode(decoder.u16()?)?)),
            _ => Err(StorageError::InvalidEncoding),
        }
    }
}

/// The sole durable owner of one coordinator-to-target companion stream.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryOwner {
    scope: DeliveryScope,
    cursor: DeliveryCursor,
    cut: SnapshotCut,
    phase: CutPhase,
}

impl DeliveryOwner {
    /// Validates exact generation and offered-page ownership.
    pub fn new(
        scope: DeliveryScope,
        cursor: DeliveryCursor,
        cut: SnapshotCut,
        phase: CutPhase,
    ) -> Result<Self, StorageError> {
        if cursor.generation() != cut.delivery_generation() {
            return Err(StorageError::InvalidEncoding);
        }
        if matches!(phase, CutPhase::Pending { offered_pages, .. }
            if offered_pages == 0 || offered_pages > cut.page_count())
        {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            scope,
            cursor,
            cut,
            phase,
        })
    }

    /// Returns the exact accepted historical scope.
    #[must_use]
    pub const fn scope(&self) -> &DeliveryScope {
        &self.scope
    }

    /// Returns the durable event cursor.
    #[must_use]
    pub const fn cursor(&self) -> &DeliveryCursor {
        &self.cursor
    }

    /// Returns the immutable cut identity.
    #[must_use]
    pub const fn cut(&self) -> &SnapshotCut {
        &self.cut
    }

    /// Returns cut-local transfer ownership.
    #[must_use]
    pub const fn phase(&self) -> CutPhase {
        self.phase
    }

    pub(super) fn put(&self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.scope.put(encoder)?;
        self.cursor.put(encoder)?;
        self.cut.put(encoder)?;
        self.phase.put(encoder)
    }

    pub(super) fn take(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        Self::new(
            DeliveryScope::take(decoder)?,
            DeliveryCursor::take(decoder)?,
            SnapshotCut::take(decoder)?,
            CutPhase::take(decoder)?,
        )
    }
}
