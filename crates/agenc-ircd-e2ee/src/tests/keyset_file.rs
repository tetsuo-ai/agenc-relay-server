#![forbid(unsafe_code)]

//! The sequencer credentials file.

use super::*;
use crate::test_support::*;

#[test]
fn the_file_round_trips_and_verifies_as_a_key_set() -> Result<(), E2eeError> {
    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let second = sequencer_credential(
        &key(61),
        1,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    let file = SequencerCredentialsFile {
        key_set_generation: 0,
        credentials: vec![first.clone()],
    };
    let bytes = file.encode()?;
    assert_eq!(SequencerCredentialsFile::decode(&bytes)?, file);
    let set = file.verify(&NETWORK, ValidationTime(10), None)?;
    assert_eq!(set.credentials.len(), 1);
    assert_eq!(set.set_generation, 0);
    assert_eq!(
        file.verify(&NETWORK, ValidationTime(1_000_001), None)
            .map(|_| ()),
        Err(E2eeError::InvalidValue),
        "the current credential must cover now"
    );
    let pair = SequencerCredentialsFile {
        key_set_generation: 1,
        credentials: vec![first, second],
    };
    let pair_bytes = pair.encode()?;
    assert_eq!(SequencerCredentialsFile::decode(&pair_bytes)?, pair);
    assert_eq!(
        pair.verify(&NETWORK, ValidationTime(10), None)?
            .credentials
            .len(),
        2
    );
    assert_eq!(
        pair.verify(&[2; 32], ValidationTime(10), None).map(|_| ()),
        Err(E2eeError::ProfileMismatch)
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        SequencerCredentialsFile::decode(&trailing),
        Err(E2eeError::TrailingBytes)
    );
    let mut wrong_version = bytes.clone();
    if let Some(byte) = wrong_version.get_mut(1) {
        *byte = 2;
    }
    assert_eq!(
        SequencerCredentialsFile::decode(&wrong_version),
        Err(E2eeError::ProfileMismatch)
    );
    let mut zero = bytes;
    if let Some(byte) = zero.get_mut(10) {
        *byte = 0;
    }
    assert!(SequencerCredentialsFile::decode(&zero).is_err());
    assert!(SequencerCredentialsFile::decode(&vec![0; MAX_FILE_BYTES + 1]).is_err());
    assert_eq!(
        SequencerCredentialsFile {
            key_set_generation: 0,
            credentials: Vec::new(),
        }
        .encode(),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}
