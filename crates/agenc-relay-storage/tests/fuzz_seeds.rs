#![forbid(unsafe_code)]

//! The committed `storage_codecs` and `backup_stream` seed corpora were written
//! once by `examples/fuzz-seeds.rs`. Every seed must keep the exact outcome the
//! fuzz oracle expects under the targets' fixed public keys: accepted inputs
//! re-encode canonically or verify completely, and each rejected variant fails.

use std::error::Error;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

use agenc_relay_crypto::{
    Ed25519PublicKey, RollbackGuardRootKey, StorageDigest, StorageIntegrityContext,
    StorageIntegrityKeys, StorageMasterKey, derive_storage_integrity_keys,
};
use agenc_relay_storage::{
    BackupRecord, BackupTrustKey, DatabaseHeader, IntegrityCheckpoint, IntegrityManifest,
    LoginIndexKeyState, LoginIndexStoredKey, NonceReservationState, RollbackGuard, SealedRecord,
    StateMeta, StorageError, verify_backup,
};
use agenc_relay_types::{DatabaseId, NetworkId, ServerId};

type TestResult = Result<(), Box<dyn Error>>;

const MAX_FUZZ_BACKUP_BYTES: u64 = 1_048_576;

fn corpus(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-data/fuzz-corpus")
        .join(name)
}

fn codec_keys() -> Result<StorageIntegrityKeys, StorageError> {
    Ok(derive_storage_integrity_keys(
        &RollbackGuardRootKey::from_bytes([0x51; 32]),
        StorageIntegrityContext::new(
            NetworkId::from_bytes([0x53; 32]),
            ServerId::from_bytes([0x54; 16]),
            DatabaseId::from_bytes([0x55; 16]),
        ),
    )?)
}

/// Mirrors the `storage_codecs` oracle: an accepted frame re-encodes to itself.
fn reencode(arm: u8, encoded: &[u8], keys: &StorageIntegrityKeys) -> Result<Vec<u8>, StorageError> {
    match arm {
        0 => DatabaseHeader::decode(encoded)?.encode(),
        1 => NonceReservationState::decode_and_verify(encoded, keys)?.encode(),
        2 => RollbackGuard::decode_and_verify(encoded, keys)?.encode(),
        3 => StateMeta::decode_and_verify(encoded, StorageDigest::from_bytes([0x52; 32]), keys)?
            .encode(),
        4 => IntegrityManifest::decode(encoded)?.encode(),
        5 => IntegrityCheckpoint::decode(encoded)?.encode(),
        6 => SealedRecord::decode(encoded)?.encode(),
        7 => BackupRecord::decode(encoded)?.encode(),
        8 => LoginIndexStoredKey::decode(encoded)?
            .encode()
            .map(|key| key.as_bytes().to_vec()),
        9 => LoginIndexKeyState::decode(encoded)?.encode(),
        _ => Err(StorageError::InvalidEncoding),
    }
}

#[test]
fn every_storage_codec_seed_keeps_its_oracle_outcome() -> TestResult {
    let expected = [
        ("header-valid", 0_u8, true),
        ("header-truncated", 0, false),
        ("nonce-reservation-valid", 1, true),
        ("nonce-reservation-tampered", 1, false),
        ("rollback-guard-valid", 2, true),
        ("rollback-guard-tampered", 2, false),
        ("state-meta-valid", 3, true),
        ("state-meta-tampered", 3, false),
        ("manifest-valid", 4, true),
        ("checkpoint-valid", 5, true),
        ("sealed-record-valid", 6, true),
        ("sealed-record-flipped-ciphertext", 6, true),
        ("backup-record-valid", 7, true),
        ("login-index-key-valid", 8, true),
        ("login-index-key-short", 8, false),
        ("login-key-state-valid", 9, true),
    ];
    let keys = codec_keys()?;
    for (name, arm, accepted) in expected {
        let bytes = fs::read(corpus("storage_codecs").join(name))?;
        let (&selector, body) = bytes.split_first().ok_or("empty seed")?;
        assert_eq!(selector % 13, arm, "{name}");
        let outcome = reencode(arm, body, &keys);
        if accepted {
            assert_eq!(
                outcome?.as_slice(),
                body,
                "{name} must re-encode canonically"
            );
        } else {
            assert!(outcome.is_err(), "{name} must be rejected");
        }
    }
    let mut names = fs::read_dir(corpus("storage_codecs"))?
        .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
        .collect::<Result<Vec<_>, std::io::Error>>()?;
    names.sort();
    let mut listed = expected
        .iter()
        .map(|(name, _, _)| (*name).to_owned())
        .collect::<Vec<_>>();
    listed.sort();
    assert_eq!(names, listed);
    Ok(())
}

fn verify_seed(bytes: &[u8]) -> Result<u64, Box<dyn Error>> {
    let public_key = <[u8; 32]>::try_from(bytes.get(..32).ok_or("seed lacks a trust key")?)?;
    let trust = BackupTrustKey::new(Ed25519PublicKey::from_bytes(public_key)?)?;
    let stream = bytes.get(32..).unwrap_or_default();
    let verified = verify_backup(
        Cursor::new(stream),
        &StorageMasterKey::from_bytes([0x61; 32]),
        &RollbackGuardRootKey::from_bytes([0x62; 32]),
        &[trust],
        MAX_FUZZ_BACKUP_BYTES,
    )?;
    assert_eq!(verified.stream_bytes, u64::try_from(stream.len())?);
    Ok(verified.stream_bytes)
}

#[test]
fn backup_stream_seeds_verify_only_for_the_untouched_signed_stream() -> TestResult {
    let signed = fs::read(corpus("backup_stream").join("signed-fresh-database"))?;
    assert!(verify_seed(&signed)? > 32);
    for name in [
        "signed-wrong-trust-key",
        "signed-trailing-byte",
        "signed-truncated-trailer",
        "signed-tampered-record",
    ] {
        let bytes = fs::read(corpus("backup_stream").join(name))?;
        assert!(verify_seed(&bytes).is_err(), "{name} must be rejected");
    }
    assert_eq!(fs::read_dir(corpus("backup_stream"))?.count(), 5);
    Ok(())
}
