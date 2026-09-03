//! Bounded, order-checked reassembly of fragmented base-federation objects.
//!
//! The assembler is a pure state machine: the link owner feeds it validated
//! fragments together with a descriptor fingerprint and its own monotonic
//! clock reading, and it hands back complete objects whose recomputed identity
//! equals the carrier's. Every ceiling is the fixed Section-20.4 value; the
//! assembler never allocates before the object's reservation is admitted.

use std::collections::BTreeMap;
use std::error::Error;
use std::fmt;

use agenc_ircd_types::{
    BASE_FRAGMENT_BYTES, BASE_FRAGMENT_IDLE_SECONDS, BASE_FRAGMENT_TOTAL_SECONDS,
    BASE_INCOMPLETE_OBJECTS_PER_LINK, BASE_OBJECT_BYTES, BASE_REASSEMBLY_BYTES_PER_LINK,
};
use sha2::{Digest as _, Sha256};
use zeroize::Zeroize as _;

use crate::objects::federation_object_id;
use crate::text::{FederationFragment, FederationHash32, FederationTextError};

const MILLIS_PER_SECOND: u64 = 1_000;

/// Closed failures from fragment admission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AssemblyError {
    /// The link already holds its maximum of incomplete objects.
    ///
    /// Thirty-two maximum objects occupy exactly the 8 MiB reassembly budget,
    /// so the object ceiling is also the byte ceiling.
    TooManyIncomplete,
    /// A later fragment repeated the command or descriptor with different bytes.
    DescriptorMismatch,
    /// A later fragment declared a different count or total than the first.
    HeaderMismatch,
    /// A fragment repeated an index that was already received.
    DuplicatePart,
    /// A fragment arrived out of contiguous order.
    OutOfOrder,
    /// The object's idle or total assembly deadline passed.
    Timeout,
    /// The recomputed identity of the complete object differs from the carrier.
    ObjectIdMismatch,
    /// A checked calculation overflowed.
    Overflow,
    /// A bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for AssemblyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::TooManyIncomplete => "too many incomplete federation objects",
            Self::DescriptorMismatch => "federation fragment descriptor mismatch",
            Self::HeaderMismatch => "federation fragment header mismatch",
            Self::DuplicatePart => "duplicate federation fragment",
            Self::OutOfOrder => "federation fragment out of order",
            Self::Timeout => "federation fragment assembly timed out",
            Self::ObjectIdMismatch => "federation object identity mismatch",
            Self::Overflow => "federation assembly calculation overflowed",
            Self::AllocationFailed => "federation assembly allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for AssemblyError {}

/// Fingerprint of the command and descriptor parameters shared by every
/// fragment of one object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FragmentDescriptorKey([u8; 32]);

impl FragmentDescriptorKey {
    /// Derives the fingerprint from the exact command form and descriptor
    /// parameters, length-prefixing each component so no two tuples collide.
    #[must_use]
    pub fn derive(form: &str, parameters: &[&str]) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(b"agenc-chat federation descriptor key v1");
        hash_component(&mut hasher, form.as_bytes());
        for parameter in parameters {
            hash_component(&mut hasher, parameter.as_bytes());
        }
        Self(hasher.finalize().into())
    }
}

fn hash_component(hasher: &mut Sha256, bytes: &[u8]) {
    let length = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
    hasher.update(length.to_be_bytes());
    hasher.update(bytes);
}

/// One complete object whose identity was verified against its carrier.
#[must_use = "an assembled object must be dispatched or explicitly dropped"]
pub struct AssembledObject {
    object_id: FederationHash32,
    bytes: Vec<u8>,
}

impl AssembledObject {
    /// Returns the verified object identity.
    #[must_use]
    pub const fn object_id(&self) -> FederationHash32 {
        self.object_id
    }

    /// Borrows the complete encoded object.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact encoded length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether the object is empty; a verified object never is.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl Drop for AssembledObject {
    fn drop(&mut self) {
        self.bytes.resize(self.bytes.capacity(), 0);
        self.bytes.as_mut_slice().zeroize();
    }
}

/// What one admitted fragment produced.
pub enum AssemblyProgress {
    /// More fragments are required.
    Incomplete {
        /// Fragments received so far.
        received: u32,
        /// Fragments declared by the object.
        count: u32,
    },
    /// The object is complete and verified.
    Complete(AssembledObject),
}

struct Incomplete {
    descriptor: FragmentDescriptorKey,
    count: u32,
    total: usize,
    next_part: u32,
    buffer: Vec<u8>,
    started_at_millis: u64,
    last_fragment_millis: u64,
}

impl Incomplete {
    fn expired(&self, now_millis: u64) -> bool {
        let idle = now_millis.saturating_sub(self.last_fragment_millis);
        let age = now_millis.saturating_sub(self.started_at_millis);
        idle >= BASE_FRAGMENT_IDLE_SECONDS.saturating_mul(MILLIS_PER_SECOND)
            || age >= BASE_FRAGMENT_TOTAL_SECONDS.saturating_mul(MILLIS_PER_SECOND)
    }
}

impl Drop for Incomplete {
    fn drop(&mut self) {
        self.buffer.resize(self.buffer.capacity(), 0);
        self.buffer.as_mut_slice().zeroize();
    }
}

/// The reassembly budget is exactly the object ceiling times the object size
/// ceiling, so counting objects is the same check as counting bytes.
// agenc-review: internal-assert owner=federation-wire reviewed=2026-09-02 reason=compile-time identity between the frozen object and byte ceilings
const _: () =
    assert!(BASE_INCOMPLETE_OBJECTS_PER_LINK * BASE_OBJECT_BYTES == BASE_REASSEMBLY_BYTES_PER_LINK);

/// Per-link reassembly state under the fixed Section-20.4 ceilings.
#[derive(Default)]
pub struct FragmentAssembler {
    incomplete: BTreeMap<[u8; 32], Incomplete>,
    reserved_bytes: usize,
}

impl FragmentAssembler {
    /// Creates an empty assembler.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the number of objects awaiting further fragments.
    #[must_use]
    pub fn incomplete_objects(&self) -> usize {
        self.incomplete.len()
    }

    /// Returns the bytes reserved by incomplete objects.
    #[must_use]
    pub const fn reserved_bytes(&self) -> usize {
        self.reserved_bytes
    }

    /// Admits one validated fragment at the given monotonic instant.
    ///
    /// A returned error other than `Timeout` on an already-open object is a
    /// peer violation; the caller closes the link. On any error the object is
    /// dropped and its reservation released.
    pub fn admit(
        &mut self,
        descriptor: FragmentDescriptorKey,
        fragment: &FederationFragment,
        now_millis: u64,
    ) -> Result<AssemblyProgress, AssemblyError> {
        let key = *fragment.object_id().as_bytes();
        let outcome = if self.incomplete.contains_key(&key) {
            self.continue_object(key, descriptor, fragment, now_millis)
        } else {
            self.open_object(key, descriptor, fragment, now_millis)
        };
        match outcome {
            Ok(progress) => Ok(progress),
            Err(error) => {
                self.remove(&key);
                Err(error)
            }
        }
    }

    /// Drops every object whose idle or total deadline has passed.
    pub fn expire(&mut self, now_millis: u64) -> usize {
        let expired: Vec<[u8; 32]> = self
            .incomplete
            .iter()
            .filter(|(_, entry)| entry.expired(now_millis))
            .map(|(key, _)| *key)
            .collect();
        for key in &expired {
            self.remove(key);
        }
        expired.len()
    }

    /// Drops one incomplete object, returning whether it existed.
    pub fn abandon(&mut self, object_id: &FederationHash32) -> bool {
        self.remove(object_id.as_bytes())
    }

    fn open_object(
        &mut self,
        key: [u8; 32],
        descriptor: FragmentDescriptorKey,
        fragment: &FederationFragment,
        now_millis: u64,
    ) -> Result<AssemblyProgress, AssemblyError> {
        if fragment.part() != 0 {
            return Err(AssemblyError::OutOfOrder);
        }
        let maximum_objects = usize::try_from(BASE_INCOMPLETE_OBJECTS_PER_LINK)
            .map_err(|_| AssemblyError::Overflow)?;
        if self.incomplete.len() >= maximum_objects {
            return Err(AssemblyError::TooManyIncomplete);
        }
        let total = usize::try_from(fragment.total()).map_err(|_| AssemblyError::Overflow)?;
        let reserved = self
            .reserved_bytes
            .checked_add(total)
            .ok_or(AssemblyError::Overflow)?;
        let mut buffer = Vec::new();
        buffer
            .try_reserve_exact(total)
            .map_err(|_| AssemblyError::AllocationFailed)?;
        self.reserved_bytes = reserved;
        self.incomplete.insert(
            key,
            Incomplete {
                descriptor,
                count: fragment.count(),
                total,
                next_part: 0,
                buffer,
                started_at_millis: now_millis,
                last_fragment_millis: now_millis,
            },
        );
        self.append(key, fragment)
    }

    fn continue_object(
        &mut self,
        key: [u8; 32],
        descriptor: FragmentDescriptorKey,
        fragment: &FederationFragment,
        now_millis: u64,
    ) -> Result<AssemblyProgress, AssemblyError> {
        let entry = self
            .incomplete
            .get_mut(&key)
            .ok_or(AssemblyError::OutOfOrder)?;
        if entry.expired(now_millis) {
            return Err(AssemblyError::Timeout);
        }
        if entry.descriptor != descriptor {
            return Err(AssemblyError::DescriptorMismatch);
        }
        let total = usize::try_from(fragment.total()).map_err(|_| AssemblyError::Overflow)?;
        if entry.count != fragment.count() || entry.total != total {
            return Err(AssemblyError::HeaderMismatch);
        }
        if fragment.part() < entry.next_part {
            return Err(AssemblyError::DuplicatePart);
        }
        if fragment.part() > entry.next_part {
            return Err(AssemblyError::OutOfOrder);
        }
        entry.last_fragment_millis = now_millis;
        self.append(key, fragment)
    }

    fn append(
        &mut self,
        key: [u8; 32],
        fragment: &FederationFragment,
    ) -> Result<AssemblyProgress, AssemblyError> {
        let entry = self
            .incomplete
            .get_mut(&key)
            .ok_or(AssemblyError::OutOfOrder)?;
        let projected = entry
            .buffer
            .len()
            .checked_add(fragment.segment().len())
            .ok_or(AssemblyError::Overflow)?;
        if projected > entry.total {
            return Err(AssemblyError::HeaderMismatch);
        }
        entry.buffer.extend_from_slice(fragment.segment());
        entry.next_part = entry
            .next_part
            .checked_add(1)
            .ok_or(AssemblyError::Overflow)?;
        if entry.next_part < entry.count {
            return Ok(AssemblyProgress::Incomplete {
                received: entry.next_part,
                count: entry.count,
            });
        }
        if entry.buffer.len() != entry.total {
            return Err(AssemblyError::HeaderMismatch);
        }
        let mut finished = self
            .incomplete
            .remove(&key)
            .ok_or(AssemblyError::OutOfOrder)?;
        self.reserved_bytes = self.reserved_bytes.saturating_sub(finished.total);
        let object_id = FederationHash32::from_bytes(key);
        if federation_object_id(&finished.buffer) != object_id {
            return Err(AssemblyError::ObjectIdMismatch);
        }
        let bytes = std::mem::take(&mut finished.buffer);
        Ok(AssemblyProgress::Complete(AssembledObject {
            object_id,
            bytes,
        }))
    }

    fn remove(&mut self, key: &[u8; 32]) -> bool {
        match self.incomplete.remove(key) {
            Some(entry) => {
                self.reserved_bytes = self.reserved_bytes.saturating_sub(entry.total);
                true
            }
            None => false,
        }
    }
}

/// Splits one complete encoded object into its canonical contiguous fragments.
pub fn split_fragments(
    object_id: FederationHash32,
    encoded: &[u8],
) -> Result<Vec<FederationFragment>, FederationTextError> {
    if encoded.is_empty() {
        return Err(FederationTextError::FragmentRange);
    }
    let fragment_bytes =
        usize::try_from(BASE_FRAGMENT_BYTES).map_err(|_| FederationTextError::Overflow)?;
    let total = u32::try_from(encoded.len()).map_err(|_| FederationTextError::Overflow)?;
    let count = encoded.len().div_ceil(fragment_bytes);
    let count_u32 = u32::try_from(count).map_err(|_| FederationTextError::Overflow)?;
    let mut fragments = Vec::new();
    fragments
        .try_reserve_exact(count)
        .map_err(|_| FederationTextError::AllocationFailed)?;
    for (index, segment) in encoded.chunks(fragment_bytes).enumerate() {
        let part = u32::try_from(index).map_err(|_| FederationTextError::Overflow)?;
        fragments.push(FederationFragment::new(
            object_id, part, count_u32, total, segment,
        )?);
    }
    Ok(fragments)
}

#[cfg(test)]
#[path = "tests/assembly.rs"]
mod tests;
