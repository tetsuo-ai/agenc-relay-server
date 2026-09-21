//! Capture allocations retain their budget reservation through element destruction.
#![forbid(unsafe_code)]

use std::sync::atomic::{AtomicBool, Ordering};

use super::super::super::CompanionOriginKey;
use super::super::super::sync::BaseOriginView;
use super::*;
use crate::budget::{BackingReservationPort, MemoryBudget, MemoryCharge};
use crate::sync::Arc;

struct Host(BackingReservationPort);

struct NoEntropy;

impl EntropySource for NoEntropy {
    fn fill_exact(&mut self, _: &mut [u8]) -> Result<(), agenc_relay_types::EntropyError> {
        Err(agenc_relay_types::EntropyError::Unavailable)
    }
}

impl CompanionHost for Host {
    fn reserve_cut_backing(&self, capacity: usize) -> Result<MemoryPermit, CompanionFault> {
        self.0
            .reserve(capacity)
            .map_err(|_| CompanionFault::Ceiling)
    }
    fn live_incarnation(&self, _: ServerId) -> Option<[u8; 16]> {
        None
    }
    fn base_origin(&self, _: &CompanionOriginKey) -> Option<BaseOriginView> {
        None
    }
    fn base_origins_ready(&self, _: ServerId) -> bool {
        false
    }
    fn base_resync_epoch(&self, _: ServerId) -> u64 {
        0
    }
    fn state_generation(&self) -> u64 {
        0
    }
    fn holds_channel(&self, _: [u8; 16]) -> bool {
        false
    }
    fn hosts_account(&self, _: &[u8; 24]) -> bool {
        false
    }
}

struct Probe {
    reservations: BackingReservationPort,
    released_early: Arc<AtomicBool>,
}

impl Drop for Probe {
    fn drop(&mut self) {
        if self.reservations.reserve(1).is_ok() {
            self.released_early.store(true, Ordering::Relaxed);
        }
    }
}

fn fail_after_allocation(
    host: &Host,
    released_early: Arc<AtomicBool>,
) -> Result<(), CompanionFault> {
    let mut owned = reserved::<Probe>(1, host)?;
    owned.values.push(Probe {
        reservations: host.0.clone(),
        released_early,
    });
    Err(CompanionFault::Protocol)
}

#[test]
fn a_capture_error_drops_allocated_elements_before_releasing_their_permit()
-> Result<(), Box<dyn std::error::Error>> {
    let charge = MemoryCharge::allocation(u64::try_from(std::mem::size_of::<Probe>())?)?;
    let host = Host(BackingReservationPort::new(Arc::new(MemoryBudget::new(
        charge.bytes(),
    ))));
    let released_early = Arc::new(AtomicBool::new(false));
    assert!(matches!(
        fail_after_allocation(&host, Arc::clone(&released_early)),
        Err(CompanionFault::Protocol)
    ));
    assert!(
        !released_early.load(Ordering::Relaxed),
        "the retained allocation outlived its charge"
    );
    assert!(host.0.reserve(1).is_ok());
    Ok(())
}

#[test]
fn captured_digest_uses_the_original_v1_bytes_and_empty_page()
-> Result<(), Box<dyn std::error::Error>> {
    let host = Host(BackingReservationPort::new(Arc::new(MemoryBudget::new(
        1_048_576,
    ))));
    let state = CompanionState::default();
    let mut entropy = NoEntropy;
    let capture = Capture::new(&state, ServerId::from_bytes([1; 16]), &host, &mut entropy)?;
    assert_eq!(capture.entry_count()?, 0);
    assert_eq!(capture.page_count(), 1);
    assert!(capture.page(0)?.is_empty());
    assert!(capture.page(1).is_err());
    assert_eq!(capture.cursor(0), None);
    assert_eq!(
        capture.digest(7, 0, &host)?,
        agenc_relay_e2ee::ids::federation_snapshot_digest(7, 0, &[])?
    );
    Ok(())
}

#[test]
fn a_million_entry_capture_digest_needs_no_additional_budget()
-> Result<(), Box<dyn std::error::Error>> {
    let count = 1_000_000_usize;
    let capacity = count
        .checked_mul(std::mem::size_of::<CapturedEntry>())
        .ok_or("capacity")?;
    let charge = MemoryCharge::allocation(u64::try_from(capacity)?)?;
    let host = Host(BackingReservationPort::new(Arc::new(MemoryBudget::new(
        charge.bytes(),
    ))));
    let mut entries = reserved::<CapturedEntry>(count, &host)?;
    for sequence in 0..count {
        let mut conversation = [0; 32];
        conversation
            .get_mut(..8)
            .ok_or("identity")?
            .copy_from_slice(&u64::try_from(sequence)?.to_be_bytes());
        entries.values.push(CapturedEntry {
            conversation,
            object: [7; 32],
        });
    }
    let capture = Capture {
        entries,
        cursors: reserved(0, &host)?,
        total_object_bytes: u64::try_from(count)?,
    };
    assert!(
        host.0.reserve(1).is_err(),
        "the retained references exhaust the supplied budget"
    );
    let actual = capture.digest(17, 23, &host)?;
    let mut expected = agenc_relay_crypto::Sha256Stream::new();
    expected.update(b"ARC-MLS/1 federation snapshot");
    expected.update(&17_u64.to_be_bytes());
    expected.update(&23_u64.to_be_bytes());
    expected.update(&32_000_000_u32.to_be_bytes());
    for entry in &capture.entries.values {
        expected.update(&entry.object);
    }
    assert_eq!(actual, *expected.finish().as_bytes());
    assert!(host.0.reserve(1).is_err());
    drop(capture);
    assert!(host.0.reserve(1).is_ok());
    Ok(())
}
