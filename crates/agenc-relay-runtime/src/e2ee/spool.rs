//! Authenticated temporary storage for large companion controls.

#[cfg(test)]
#[path = "spool/tests/boundaries.rs"]
mod tests;

use std::fmt;
use std::fs::File;
use std::os::unix::fs::FileExt as _;
use std::sync::Arc;

use agenc_relay_crypto::{SPOOL_PART_OVERHEAD, SpoolCipher};
use agenc_relay_e2ee::limits::{MAX_FRAGMENT_RAW, MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION};
use agenc_relay_e2ee::object::ArcWireObject;
use agenc_relay_e2ee::wire::assembly::{
    AssemblyBacking, AssemblyError, AssemblyKey, BackingPermit, ChargedBuffer, E2eeAssembler,
    FragmentSpool, Ingest, QuotaScopes, ReservedObject,
};
use agenc_relay_e2ee::wire::carrier::CarrierCommand;
use agenc_relay_e2ee::wire::fragment::{FragmentTag, fragment_count};
use agenc_relay_storage::{CompanionDisk, CompanionSpoolDirectory, ExtentReservation};
use tokio::sync::Semaphore;

use crate::budget::BackingReservationPort;

/// Immutable bytes shared across assembly, dispatch and the writer. A live
/// ingress object carries its backing and quota permits behind the same Arc.
#[derive(Clone)]
pub struct CompanionBytes(Arc<dyn AsRef<[u8]> + Send + Sync>);

impl From<ReservedObject> for CompanionBytes {
    fn from(value: ReservedObject) -> Self {
        Self(Arc::new(value))
    }
}

impl From<Vec<u8>> for CompanionBytes {
    fn from(value: Vec<u8>) -> Self {
        Self(Arc::new(value))
    }
}

impl AsRef<[u8]> for CompanionBytes {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref().as_ref()
    }
}

impl std::ops::Deref for CompanionBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        self.as_ref()
    }
}

impl fmt::Debug for CompanionBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompanionBytes")
            .field("length", &self.len())
            .finish_non_exhaustive()
    }
}

const REFUSED: AssemblyError = AssemblyError::ReassemblyLimit;

#[derive(Clone)]
pub(crate) struct SpoolResources {
    pub(crate) directory: Arc<CompanionSpoolDirectory>,
    pub(crate) disk: CompanionDisk,
    pub(crate) memory: BackingReservationPort,
}

struct AuthenticatedSpool {
    file: File,
    // Dropped after the file closes.
    _disk: ExtentReservation,
    _scratch: Box<dyn BackingPermit>,
    memory: IngressMemory,
    key: SpoolCipher,
    total: usize,
}

impl fmt::Debug for AuthenticatedSpool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticatedSpool")
            .field("total", &self.total)
            .finish_non_exhaustive()
    }
}

/// Both the state owner's process budget and the federation reader's ingress
/// budget stay with each heap allocation until its last dispatch use.
#[derive(Clone)]
struct IngressMemory {
    process: BackingReservationPort,
    link: Option<Arc<Semaphore>>,
}

impl IngressMemory {
    fn reserve(&self, bytes: usize) -> Result<Box<dyn BackingPermit>, AssemblyError> {
        let process = self.process.reserve(bytes).map_err(|_| REFUSED)?;
        let local = self
            .link
            .as_ref()
            .map(|link| {
                Arc::clone(link)
                    .try_acquire_many_owned(u32::try_from(bytes).map_err(|_| REFUSED)?)
                    .map_err(|_| REFUSED)
            })
            .transpose()?;
        Ok(Box::new((process, local)))
    }
}

/// The descriptor has already passed the transport's principal and carrier
/// checks. Remote fragments may start out of order only under a previously
/// identified request or response descriptor.
pub(crate) struct Admission {
    pub(crate) key: AssemblyKey,
    pub(crate) carrier: CarrierCommand,
    pub(crate) scopes: QuotaScopes,
    pub(crate) authenticated_spool: bool,
}

impl SpoolResources {
    pub(crate) fn copy_for_dispatch(
        &self,
        bytes: &[u8],
        link: Option<Arc<Semaphore>>,
    ) -> Result<CompanionBytes, AssemblyError> {
        struct Copy {
            bytes: Vec<u8>,
            _permit: Box<dyn BackingPermit>,
        }
        impl AsRef<[u8]> for Copy {
            fn as_ref(&self) -> &[u8] {
                &self.bytes
            }
        }
        let memory = IngressMemory {
            process: self.memory.clone(),
            link,
        };
        let permit = memory.reserve(bytes.len())?;
        Ok(CompanionBytes(Arc::new(Copy {
            bytes: bytes.to_owned(),
            _permit: permit,
        })))
    }

    pub(crate) fn ingest(
        &self,
        assembler: &mut E2eeAssembler,
        admission: Admission,
        tag: &FragmentTag,
        now: u64,
        link: Option<Arc<Semaphore>>,
    ) -> Result<Ingest<ReservedObject>, AssemblyError> {
        let Admission {
            key,
            carrier,
            scopes,
            authenticated_spool,
        } = admission;
        let total = usize::try_from(tag.total).map_err(|_| AssemblyError::ObjectTooLarge)?;
        let limit = carrier.limit();
        if total > limit.max_bytes || tag.count > limit.max_fragments {
            assembler.discard(&key);
            return Err(AssemblyError::ObjectTooLarge);
        }
        let memory = IngressMemory {
            process: self.memory.clone(),
            link,
        };
        let reserve = |bytes| memory.reserve(bytes);
        let open = |bytes| self.open(tag, bytes, memory.clone());
        let backing = if total > MAX_LIVE_REASSEMBLY_BYTES_PER_CONNECTION {
            if !authenticated_spool || carrier.is_live() {
                assembler.discard(&key);
                return Err(REFUSED);
            }
            if tag.part == 0
                && !ArcWireObject::peek_header(&tag.segment, total)
                    .is_ok_and(|(kind, _)| carrier.accepts(kind))
            {
                assembler.discard(&key);
                return Err(AssemblyError::InvalidFragment);
            }
            AssemblyBacking::Spool(&open)
        } else {
            AssemblyBacking::Memory(&reserve)
        };
        assembler.ingest_backed(key, scopes, limit, tag, now, backing)
    }

    fn open(
        &self,
        tag: &FragmentTag,
        total: usize,
        memory: IngressMemory,
    ) -> Result<Box<dyn FragmentSpool>, AssemblyError> {
        let count = usize::try_from(fragment_count(tag.total).map_err(|_| REFUSED)?)
            .map_err(|_| REFUSED)?;
        if u32::try_from(count).ok() != Some(tag.count) {
            return Err(AssemblyError::InvalidFragment);
        }
        let length = count
            .checked_mul(SPOOL_PART_OVERHEAD)
            .and_then(|overhead| total.checked_add(overhead))
            .and_then(|length| u64::try_from(length).ok())
            .ok_or(REFUSED)?;
        // The bitmap and the largest simultaneous plaintext, ciphertext and
        // encoded record stay bounded by this charge for the whole assembly.
        let scratch_size = count
            .checked_add(4 * (MAX_FRAGMENT_RAW + SPOOL_PART_OVERHEAD))
            .ok_or(REFUSED)?;
        let scratch = memory.reserve(scratch_size)?;
        let disk = self.disk.reserve_extent(length).map_err(|_| REFUSED)?;
        let file = self.directory.allocate(length).map_err(|_| REFUSED)?;
        let key =
            SpoolCipher::generate(*tag.object_id.as_bytes(), tag.total).map_err(|_| REFUSED)?;
        Ok(Box::new(AuthenticatedSpool {
            file,
            _disk: disk,
            _scratch: scratch,
            memory,
            key,
            total,
        }))
    }
}

impl AuthenticatedSpool {
    fn position(offset: usize) -> Result<u64, AssemblyError> {
        if !offset.is_multiple_of(MAX_FRAGMENT_RAW) {
            return Err(AssemblyError::InvalidFragment);
        }
        (offset / MAX_FRAGMENT_RAW)
            .checked_mul(MAX_FRAGMENT_RAW + SPOOL_PART_OVERHEAD)
            .and_then(|position| u64::try_from(position).ok())
            .ok_or(REFUSED)
    }

    fn read(
        &self,
        offset: usize,
        bytes: usize,
    ) -> Result<zeroize::Zeroizing<Vec<u8>>, AssemblyError> {
        let mut record = vec![0; bytes.checked_add(SPOOL_PART_OVERHEAD).ok_or(REFUSED)?];
        self.file
            .read_exact_at(&mut record, Self::position(offset)?)
            .map_err(|_| REFUSED)?;
        self.key
            .open(u32::try_from(offset).map_err(|_| REFUSED)?, &record)
            .map_err(|_| AssemblyError::HashMismatch)
    }
}

impl FragmentSpool for AuthenticatedSpool {
    fn write(&mut self, offset: usize, bytes: &[u8]) -> Result<(), AssemblyError> {
        let record = self
            .key
            .seal(u32::try_from(offset).map_err(|_| REFUSED)?, bytes)
            .map_err(|_| REFUSED)?;
        self.file
            .write_all_at(&record, Self::position(offset)?)
            .map_err(|_| REFUSED)
    }

    fn matches(&mut self, offset: usize, bytes: &[u8]) -> Result<bool, AssemblyError> {
        Ok(self.read(offset, bytes.len())?.as_slice() == bytes)
    }

    fn finish(self: Box<Self>) -> Result<ChargedBuffer, AssemblyError> {
        let permit = self.memory.reserve(self.total)?;
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(self.total).map_err(|_| REFUSED)?;
        while bytes.len() < self.total {
            let length = (self.total - bytes.len()).min(MAX_FRAGMENT_RAW);
            bytes.extend_from_slice(&self.read(bytes.len(), length)?);
        }
        Ok(ChargedBuffer::new(bytes, permit))
    }
}
