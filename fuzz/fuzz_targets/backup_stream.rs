#![no_main]
#![forbid(unsafe_code)]

use std::io::Cursor;

use agenc_relay_crypto::{Ed25519PublicKey, RollbackGuardRootKey, StorageMasterKey};
use agenc_relay_storage::{BackupTrustKey, verify_backup};
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
    let trusted_keys = [trust_key];
    let result = verify_backup(
        Cursor::new(stream),
        &StorageMasterKey::from_bytes([0x61; 32]),
        &RollbackGuardRootKey::from_bytes([0x62; 32]),
        &trusted_keys,
        MAX_FUZZ_BACKUP_BYTES,
    );
    // The input chooses the trust key and may contain a valid signed fixture.
    // Successful verification must consume exactly the bounded input and must
    // not allow a byte after its authenticated trailer.
    if let Ok(verified) = result {
        assert_eq!(verified.stream_bytes, stream.len() as u64);
        assert!(verified.stream_bytes <= MAX_FUZZ_BACKUP_BYTES);
        let mut extended = stream.to_vec();
        extended.push(0);
        assert!(
            verify_backup(
                Cursor::new(extended),
                &StorageMasterKey::from_bytes([0x61; 32]),
                &RollbackGuardRootKey::from_bytes([0x62; 32]),
                &trusted_keys,
                MAX_FUZZ_BACKUP_BYTES,
            )
            .is_err()
        );
    }
});
