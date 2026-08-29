#![no_main]
#![forbid(unsafe_code)]

use agenc_ircd_crypto::RollbackGuardRootKey;
use agenc_ircd_storage::{
    BackupRecord, DatabaseHeader, IntegrityCheckpoint, IntegrityManifest, LoginIndexKeyState,
    LoginIndexStoredKey, NonceReservationState, RollbackGuard, SealedRecord, StateMeta,
    StorageConstruction, StorageConstructionKind, StorageConstructionPlanEntry,
    StorageOperationCompletion,
};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, encoded)) = data.split_first() else {
        return;
    };
    let guard_root = RollbackGuardRootKey::from_bytes([0x51; 32]);
    let Ok(integrity_keys) = agenc_ircd_crypto::derive_storage_integrity_keys(
        &guard_root,
        agenc_ircd_crypto::StorageIntegrityContext::new(
            agenc_ircd_types::NetworkId::from_bytes([0x53; 32]),
            agenc_ircd_types::ServerId::from_bytes([0x54; 16]),
            agenc_ircd_types::DatabaseId::from_bytes([0x55; 16]),
        ),
    ) else {
        return;
    };
    match selector % 13 {
        0 => {
            let _result = DatabaseHeader::decode(encoded);
        }
        1 => {
            let _result = NonceReservationState::decode_and_verify(encoded, &integrity_keys);
        }
        2 => {
            let _result = RollbackGuard::decode_and_verify(encoded, &integrity_keys);
        }
        3 => {
            let _result = StateMeta::decode_and_verify(
                encoded,
                agenc_ircd_crypto::StorageDigest::from_bytes([0x52; 32]),
                &integrity_keys,
            );
        }
        4 => {
            let _result = IntegrityManifest::decode(encoded);
        }
        5 => {
            let _result = IntegrityCheckpoint::decode(encoded);
        }
        6 => {
            let _result = SealedRecord::decode(encoded);
        }
        7 => {
            let _result = BackupRecord::decode(encoded);
        }
        8 => {
            let _result = LoginIndexStoredKey::decode(encoded);
        }
        9 => {
            let _result = LoginIndexKeyState::decode(encoded);
        }
        10 => {
            let kind = if selector & 0x80 == 0 {
                StorageConstructionKind::Restore
            } else {
                StorageConstructionKind::Rekey
            };
            let _result = StorageConstructionPlanEntry::decode(kind, encoded);
        }
        11 => {
            let _result = StorageConstruction::decode(encoded);
        }
        _ => {
            let _result = StorageOperationCompletion::decode(encoded);
        }
    }
});
