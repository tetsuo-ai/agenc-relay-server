#![forbid(unsafe_code)]

//! One-time offline key generation for storage qualification reports.

use std::error::Error;
use std::fs::OpenOptions;
use std::io::Write as _;
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::Path;

use agenc_relay_crypto::OsEntropy;

fn main() -> Result<(), Box<dyn Error>> {
    let mut arguments = std::env::args_os();
    let _program = arguments.next();
    let seed_path = arguments.next().ok_or("missing signing seed path")?;
    if arguments.next().is_some() {
        return Err("usage: storage-qualification-keygen <seed>".into());
    }
    let mut seed = [0_u8; 32];
    OsEntropy::fill(&mut seed)?;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(Path::new(&seed_path))?;
    file.write_all(&seed)?;
    file.sync_all()?;
    Ok(())
}
