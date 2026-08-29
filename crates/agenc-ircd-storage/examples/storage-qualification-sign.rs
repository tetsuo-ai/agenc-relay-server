#![forbid(unsafe_code)]

//! Offline signer for native storage qualification measurements.

use std::error::Error;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::Path;

use agenc_ircd_crypto::Ed25519SecretKey;
use agenc_ircd_storage::{StorageQualificationReport, StorageQualificationReportTbs};

const MAX_UNSIGNED_BYTES: u64 = 16_777_000;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let seed_path = arguments.next().ok_or("missing signing seed path")?;
    let unsigned_path = arguments.next().ok_or("missing unsigned report path")?;
    let signed_path = arguments.next().ok_or("missing signed report path")?;
    let public_key_path = arguments.next().ok_or("missing public key path")?;
    if arguments.next().is_some() {
        return Err(
            "usage: storage-qualification-sign <seed> <unsigned> <signed> <public-key>".into(),
        );
    }
    let seed = read_private_seed(Path::new(&seed_path))?;
    let unsigned = read_bounded(Path::new(&unsigned_path), MAX_UNSIGNED_BYTES)?;
    let tbs = StorageQualificationReportTbs::decode_unsigned(&unsigned)?;
    let key = Ed25519SecretKey::from_bytes(seed);
    let report = StorageQualificationReport::sign(tbs, &key)?;
    write_private_file(Path::new(&signed_path), &report.encode()?)?;
    write_private_file(Path::new(&public_key_path), key.public_key().as_bytes())?;
    Ok(())
}

fn read_private_seed(path: &Path) -> Result<[u8; 32], Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() != 32
    {
        return Err("signing seed file rejected".into());
    }
    let bytes = fs::read(path)?;
    bytes
        .try_into()
        .map_err(|_| "signing seed file rejected".into())
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>, Box<dyn Error>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > maximum
    {
        return Err("unsigned report file rejected".into());
    }
    Ok(fs::read(path)?)
}

fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), Box<dyn Error>> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}
