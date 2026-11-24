//! Heap and authenticated spool backing for an open fragment assembly.

use std::fmt;
use std::ops::Deref;

use super::{AssemblyError, QuotaReservation};

/// A caller-owned allocation charge. Dropping it returns the underlying capacity.
pub trait BackingPermit: Send + Sync {}
impl<T: Send + Sync> BackingPermit for T {}

/// A caller's authenticated, random-access spool for one admitted object.
/// Offsets and lengths refer to the decoded bytes. A repeated part is only
/// compared with its first authenticated copy and is never overwritten.
pub trait FragmentSpool: fmt::Debug + Send {
    /// Stores the first copy of a fragment.
    fn write(&mut self, offset: usize, segment: &[u8]) -> Result<(), AssemblyError>;
    /// Opens a previously stored fragment and checks for an identical retry.
    fn matches(&mut self, offset: usize, segment: &[u8]) -> Result<bool, AssemblyError>;
    /// Reserves complete-object memory, then authenticates and reads the extents.
    fn finish(self: Box<Self>) -> Result<ChargedBuffer, AssemblyError>;
}

/// Bytes accompanied by their allocation charge.
pub struct ChargedBuffer {
    bytes: Vec<u8>,
    _permit: Box<dyn BackingPermit>,
}

impl ChargedBuffer {
    /// Moves an allocation and the permit obtained for it into one owner.
    pub fn new(bytes: Vec<u8>, permit: Box<dyn BackingPermit>) -> Self {
        Self {
            bytes,
            _permit: permit,
        }
    }
}

impl fmt::Debug for ChargedBuffer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ChargedBuffer")
            .field("length", &self.bytes.len())
            .finish_non_exhaustive()
    }
}

/// Selects where a new assembly is held. A factory is called exactly once,
/// after the decoded-byte ledger admits the object and before allocation.
pub enum AssemblyBacking<'a> {
    /// Reserve the backing memory before assembling into a contiguous buffer.
    Memory(&'a dyn Fn(usize) -> Result<Box<dyn BackingPermit>, AssemblyError>),
    /// Open an authenticated, separately charged extent for a control object.
    Spool(&'a dyn Fn(usize) -> Result<Box<dyn FragmentSpool>, AssemblyError>),
}

impl AssemblyBacking<'_> {
    pub(super) fn create(&self, total: usize) -> Result<Storage, AssemblyError> {
        match self {
            Self::Memory(reserve) => {
                let permit = reserve(total)?;
                let mut bytes = Vec::new();
                bytes
                    .try_reserve_exact(total)
                    .map_err(|_| AssemblyError::ReassemblyLimit)?;
                bytes.resize(total, 0);
                Ok(Storage::Memory(ChargedBuffer::new(bytes, permit)))
            }
            Self::Spool(open) => Ok(Storage::Spool(open(total)?)),
        }
    }
}

#[derive(Debug)]
pub(super) enum Storage {
    Memory(ChargedBuffer),
    Spool(Box<dyn FragmentSpool>),
}

impl Storage {
    pub(super) fn write(
        &mut self,
        offset: usize,
        end: usize,
        segment: &[u8],
    ) -> Result<(), AssemblyError> {
        match self {
            Self::Memory(buffer) => {
                let slot = buffer
                    .bytes
                    .get_mut(offset..end)
                    .ok_or(AssemblyError::InvalidFragment)?;
                slot.copy_from_slice(segment);
                Ok(())
            }
            Self::Spool(spool) => spool.write(offset, segment),
        }
    }

    pub(super) fn matches(
        &mut self,
        offset: usize,
        end: usize,
        segment: &[u8],
    ) -> Result<bool, AssemblyError> {
        match self {
            Self::Memory(buffer) => Ok(buffer.bytes.get(offset..end) == Some(segment)),
            Self::Spool(spool) => spool.matches(offset, segment),
        }
    }

    pub(super) fn finish(self) -> Result<ChargedBuffer, AssemblyError> {
        match self {
            Self::Memory(buffer) => Ok(buffer),
            Self::Spool(spool) => spool.finish(),
        }
    }
}

/// A completed object. Its memory and every applicable decoded-byte quota
/// remain reserved through dispatch, including while a writer retains it.
#[derive(Debug)]
pub struct ReservedObject {
    buffer: ChargedBuffer,
    reservation: QuotaReservation,
}

impl ReservedObject {
    pub(super) fn new(buffer: ChargedBuffer, reservation: QuotaReservation) -> Self {
        Self {
            buffer,
            reservation,
        }
    }

    pub(super) fn verified(&mut self) {
        self.reservation.verified();
    }

    pub(super) fn into_unreserved_bytes(self) -> Vec<u8> {
        self.buffer.bytes
    }
}

impl AsRef<[u8]> for ReservedObject {
    fn as_ref(&self) -> &[u8] {
        &self.buffer.bytes
    }
}

impl Deref for ReservedObject {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}
