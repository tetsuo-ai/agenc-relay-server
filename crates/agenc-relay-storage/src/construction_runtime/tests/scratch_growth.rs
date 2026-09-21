//! A bounded scratch plan grows its file past the allowance in steps of at most two regions.
#![forbid(unsafe_code)]
use std::sync::{Arc, Mutex};

use super::*;
use crate::{
    ConstructionCapacityObserver, ConstructionTransaction, FilesystemCapacity,
    MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH,
};

/// Manifests observed. The slice byte bound is checked before each write, so a slice
/// holds at most two of them: one fits under the bound and the second crosses it.
const MANIFESTS: u64 = 18;
/// Mutations per manifest; with the key below each manifest is about 15 MiB.
const MUTATIONS_PER_MANIFEST: usize = 65_535;
const MUTATION_KEY_BYTES: usize = 160;
/// Region header pages a growth step adds beyond its data pages.
const REGION_HEADER_SLACK_BYTES: u64 = 1_024 * 1_024;

struct Recorder(Mutex<Vec<ConstructionTransaction>>);

impl ConstructionCapacityObserver for Recorder {
    fn observe(
        &self,
        transaction: ConstructionTransaction,
        sampled: FilesystemCapacity,
    ) -> Result<FilesystemCapacity, StorageError> {
        self.0
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .push(transaction);
        Ok(sampled)
    }
}

fn large_manifest(sequence: u64) -> Result<Vec<u8>, StorageError> {
    let mut mutations = Vec::new();
    mutations
        .try_reserve_exact(MUTATIONS_PER_MANIFEST)
        .map_err(|_| StorageError::AllocationFailed)?;
    for index in 0..MUTATIONS_PER_MANIFEST {
        let mut key = vec![0_u8; MUTATION_KEY_BYTES];
        let (head, _) = key.split_at_mut(8);
        head.copy_from_slice(
            &u64::try_from(index)
                .map_err(|_| StorageError::Overflow)?
                .to_be_bytes(),
        );
        mutations.push(IntegrityRecordMutation::new(
            TableId::Account,
            StoredKey::new(key)?,
            IntegrityRecordVersion::Absent,
            IntegrityRecordVersion::Present {
                record_schema: 1,
                sealed_record_id: StorageDigest::from_bytes([7; 32]),
            },
        )?);
    }
    let seal_count = u32::try_from(MUTATIONS_PER_MANIFEST)
        .ok()
        .and_then(|count| count.checked_add(2))
        .ok_or(StorageError::Overflow)?;
    IntegrityManifest::new(IntegrityManifestTbs::new(
        DatabaseId::from_bytes([113; 16]),
        sequence,
        sequence,
        0,
        0,
        0,
        0,
        0,
        0,
        u64::from(seal_count),
        seal_count,
        ZERO,
        mutations,
    )?)?
    .encode()
}

#[test]
fn a_bounded_scratch_plan_grows_past_the_allowance_in_steps_of_at_most_two_regions()
-> Result<(), StorageError> {
    let region = crate::bounded::LIVE_DATABASE_REGION_BYTES;
    assert!(
        region
            .checked_mul(2)
            .is_some_and(|two| two <= MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH / 2),
        "a bounded database is created with regions of at most half its allowance"
    );
    assert_eq!(
        ConstructionAdmission::allowance().bytes(),
        MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH
    );
    let (file, path) = scratch_file("bounded-growth")?;
    let probe = file.try_clone().map_err(crate::filesystem_rejected)?;
    let recorder = Arc::new(Recorder(Mutex::new(Vec::new())));
    let result = (|| {
        let policy = crate::ConstructionAdmissionPolicy::observed(
            crate::StorageEngineLimits {
                redb_cache_bytes: 8 * 1_024 * 1_024,
                fixed_reserve_bytes: 64 * 1_024 * 1_024,
                reserve_percent: 1,
                database_max_bytes: 1_073_741_824,
                backup_max_bytes: 1_073_741_824,
                integrity_checkpoint_manifests: 10_000,
            },
            recorder.clone(),
        )?;
        let admission = policy.bind(file.try_clone().map_err(crate::filesystem_rejected)?);
        let mut builder = ConstructionPlanBuilder::start_streaming(
            StorageConstructionKind::Restore,
            file,
            maximum_limits(),
            admission,
        )?;
        let mut previous = probe.metadata().map_err(crate::filesystem_rejected)?.len();
        let mut largest_step = 0_u64;
        for sequence in 1..=MANIFESTS {
            let key = StoredKey::new(sequence.to_be_bytes().to_vec())?;
            let source = backup_source(TableId::IntegrityManifest, &key, sequence)?;
            let manifest = record(
                TableId::IntegrityManifest,
                StoredKey::new(key.as_bytes().to_vec())?,
                large_manifest(sequence)?,
            );
            builder.observe_restore_source_record(&source, &manifest)?;
            let length = probe.metadata().map_err(crate::filesystem_rejected)?.len();
            largest_step = largest_step.max(length.saturating_sub(previous));
            previous = length;
        }
        builder.push(restore_entry(
            TableId::LoginIndexKeyState,
            StoredKey::new(crate::LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            StorageConstructionAction::RestoreCopy,
        )?)?;
        let plan = builder.finish()?;
        assert_eq!(plan.entry_count(), 1);
        let length = probe.metadata().map_err(crate::filesystem_rejected)?.len();
        assert!(
            length > MAX_STORAGE_TRANSACTION_PHYSICAL_GROWTH,
            "the scratch file stayed at {length} bytes"
        );
        assert!(
            largest_step
                <= region
                    .checked_mul(2)
                    .and_then(|two| two.checked_add(REGION_HEADER_SLACK_BYTES))
                    .ok_or(StorageError::Overflow)?,
            "one growth step extended the file by {largest_step} bytes"
        );
        let log = recorder
            .0
            .lock()
            .map_err(|_| StorageError::Unavailable)?
            .clone();
        let observed = log
            .iter()
            .filter(|transaction| matches!(transaction, ConstructionTransaction::ScratchObserve(_)))
            .count();
        assert!(
            u64::try_from(observed).map_err(|_| StorageError::Overflow)? >= MANIFESTS / 2,
            "{observed} observation slices admitted for {MANIFESTS} manifests"
        );
        assert_eq!(log.first(), Some(&ConstructionTransaction::ScratchCreate));
        assert_eq!(log.last(), Some(&ConstructionTransaction::ScratchClose));
        Ok(())
    })();
    std::fs::remove_file(path).map_err(crate::filesystem_rejected)?;
    result
}
