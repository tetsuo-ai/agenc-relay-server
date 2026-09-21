#![no_main]
#![forbid(unsafe_code)]

use agenc_relay_crypto::RollbackGuardRootKey;
use agenc_relay_storage::{
    BackupRecord, DatabaseHeader, IntegrityCheckpoint, IntegrityManifest, LoginIndexKeyState,
    LoginIndexStoredKey, NonceReservationState, RollbackGuard, SealedRecord, StateMeta,
    StorageConstruction, StorageConstructionKind, StorageConstructionPlanEntry, StorageError,
    StorageOperationCompletion,
};
use libfuzzer_sys::fuzz_target;

/// Every accepted unauthenticated frame must re-encode to exactly the accepted bytes.
fn assert_canonical(reencoded: Result<Vec<u8>, StorageError>, encoded: &[u8]) {
    assert_eq!(
        reencoded.ok().as_deref(),
        Some(encoded),
        "accepted bytes did not re-encode canonically"
    );
}

fuzz_target!(|data: &[u8]| {
    let Some((&selector, encoded)) = data.split_first() else {
        return;
    };
    let guard_root = RollbackGuardRootKey::from_bytes([0x51; 32]);
    let Ok(integrity_keys) = agenc_relay_crypto::derive_storage_integrity_keys(
        &guard_root,
        agenc_relay_crypto::StorageIntegrityContext::new(
            agenc_relay_types::NetworkId::from_bytes([0x53; 32]),
            agenc_relay_types::ServerId::from_bytes([0x54; 16]),
            agenc_relay_types::DatabaseId::from_bytes([0x55; 16]),
        ),
    ) else {
        return;
    };
    // Fixed public test keys allow valid authenticated seeds. Acceptance must
    // preserve canonical bytes just as it does for unauthenticated frames.
    match selector % 13 {
        0 => {
            if let Ok(header) = DatabaseHeader::decode(encoded) {
                assert_canonical(header.encode(), encoded);
            }
        }
        1 => {
            if let Ok(state) = NonceReservationState::decode_and_verify(encoded, &integrity_keys) {
                assert_canonical(state.encode(), encoded);
            }
        }
        2 => {
            if let Ok(guard) = RollbackGuard::decode_and_verify(encoded, &integrity_keys) {
                assert_canonical(guard.encode(), encoded);
            }
        }
        3 => {
            if let Ok(meta) = StateMeta::decode_and_verify(
                encoded,
                agenc_relay_crypto::StorageDigest::from_bytes([0x52; 32]),
                &integrity_keys,
            ) {
                assert_canonical(meta.encode(), encoded);
            }
        }
        4 => {
            if let Ok(manifest) = IntegrityManifest::decode(encoded) {
                assert_canonical(manifest.encode(), encoded);
            }
        }
        5 => {
            if let Ok(checkpoint) = IntegrityCheckpoint::decode(encoded) {
                assert_canonical(checkpoint.encode(), encoded);
            }
        }
        6 => {
            if let Ok(record) = SealedRecord::decode(encoded) {
                assert_canonical(record.encode(), encoded);
            }
        }
        7 => {
            if let Ok(record) = BackupRecord::decode(encoded) {
                assert_canonical(record.encode(), encoded);
            }
        }
        8 => {
            if let Ok(key) = LoginIndexStoredKey::decode(encoded) {
                assert_canonical(key.encode().map(|key| key.as_bytes().to_vec()), encoded);
            }
        }
        9 => {
            if let Ok(state) = LoginIndexKeyState::decode(encoded) {
                assert_canonical(state.encode(), encoded);
            }
        }
        10 => {
            let kind = if selector & 0x80 == 0 {
                StorageConstructionKind::Restore
            } else {
                StorageConstructionKind::Rekey
            };
            if let Ok(entry) = StorageConstructionPlanEntry::decode(kind, encoded) {
                assert_canonical(entry.encode(), encoded);
            }
        }
        11 => {
            if let Ok(construction) = StorageConstruction::decode(encoded) {
                assert_canonical(construction.encode(), encoded);
            }
        }
        _ => {
            if let Ok(completion) = StorageOperationCompletion::decode(encoded) {
                assert_canonical(completion.encode(), encoded);
            }
        }
    }
});
