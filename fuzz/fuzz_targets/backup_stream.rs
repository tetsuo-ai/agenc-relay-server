#![no_main]
#![forbid(unsafe_code)]

use std::io::Cursor;

use agenc_ircd_crypto::{Ed25519PublicKey, RollbackGuardRootKey, StorageMasterKey};
use agenc_ircd_storage::{BackupTrustKey, verify_backup};
use libfuzzer_sys::fuzz_target;

const MAX_FUZZ_BACKUP_BYTES: u64 = 1_048_576;

fuzz_target!(|data: &[u8]| {
    let Some(public_key_bytes) = data.get(..32) else {
        return;
    };
    let Ok(public_key_bytes) = <[u8; 32]>::try_from(public_key_bytes) else {
        return;
    };
    let Ok(public_key) = Ed25519PublicKey::from_bytes(public_key_bytes) else {
        return;
    };
    let Ok(trust_key) = BackupTrustKey::new(public_key) else {
        return;
    };
    let stream = data.get(32..).unwrap_or_default();
    let _result = verify_backup(
        Cursor::new(stream),
        &StorageMasterKey::from_bytes([0x61; 32]),
        &RollbackGuardRootKey::from_bytes([0x62; 32]),
        &[trust_key],
        MAX_FUZZ_BACKUP_BYTES,
    );
});
