#![forbid(unsafe_code)]

//! Sequencer credential chains and key sets.

use std::error::Error;

use super::*;
use crate::test_support::*;
use crate::tls::Opaque;

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn credentials_chain_by_continuity_signature() -> TestResult {
    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let verified_first = verify_sequencer_credential(&NETWORK, &first, None)?;
    assert_eq!(verified_first.generation, 0);
    assert!(verified_first.covers(ValidationTime(5)));
    assert!(!verified_first.covers(ValidationTime(1_000_001)));
    let second_secret = key(61);
    let second = sequencer_credential(
        &second_secret,
        1,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    let verified_second = verify_sequencer_credential(&NETWORK, &second, Some(&verified_first))?;
    assert_eq!(
        verified_second.previous_key_id,
        verified_first.credential_id
    );
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &second, None),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &first, Some(&verified_first)),
        Err(E2eeError::InvalidValue)
    );
    let gapped = sequencer_credential(
        &key(62),
        2,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &gapped, Some(&verified_first)),
        Err(E2eeError::InvalidValue)
    );
    let late = sequencer_credential(
        &key(63),
        1,
        (1_500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &late, Some(&verified_first)),
        Err(E2eeError::InvalidValue),
        "not_before must lie inside the predecessor interval"
    );
    let forged = sequencer_credential(&key(64), 1, (500_000, 2_000_000), Some((&key(65), &first)))?;
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &forged, Some(&verified_first)),
        Err(E2eeError::SignatureInvalid)
    );
    let mut empty_continuity = second.clone();
    empty_continuity.continuity_signature = Opaque::new(Vec::new())?;
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &empty_continuity, Some(&verified_first)),
        Err(E2eeError::InvalidValue)
    );
    let mut inverted = first;
    inverted.tbs.not_after = 0;
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &inverted, None),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_sequencer_credential(&[2; 32], &second, Some(&verified_first)),
        Err(E2eeError::ProfileMismatch)
    );
    Ok(())
}

#[test]
fn key_sets_hold_the_current_key_and_at_most_its_successor() -> TestResult {
    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let second = sequencer_credential(
        &key(61),
        1,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    let single = SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&first), 0, None)?;
    assert_eq!(single.credentials.len(), 1);
    assert!(!single.overlap_open(ValidationTime(600_000)));
    let pair = SequencerKeySet::verify(&NETWORK, &[first.clone(), second.clone()], 1, None)?;
    assert_eq!(pair.credentials.len(), 2);
    assert_ne!(pair.digest, single.digest);
    assert!(pair.overlap_open(ValidationTime(600_000)));
    assert!(!pair.overlap_open(ValidationTime(500_000 + 8 * 24 * 3600)));
    let first_id = single
        .current()
        .map(|credential| credential.credential_id)
        .ok_or("current")?;
    assert!(pair.credential(&first_id).is_some());
    assert!(pair.credential(&[9; 32]).is_none());
    assert_eq!(single.succession(&pair), Ok(()));
    let verified_first = verify_sequencer_credential(&NETWORK, &first, None)?;
    let retired = SequencerKeySet::verify(
        &NETWORK,
        std::slice::from_ref(&second),
        2,
        Some(&verified_first),
    )?;
    assert_eq!(pair.succession(&retired), Ok(()));
    assert_eq!(
        single.succession(&retired),
        Err(E2eeError::InvalidValue),
        "generation gap"
    );
    let unrelated = SequencerKeySet::verify(
        &NETWORK,
        &[sequencer_credential(&key(70), 0, (0, 10), None)?],
        1,
        None,
    )?;
    assert_eq!(single.succession(&unrelated), Err(E2eeError::InvalidValue));
    assert_eq!(
        SequencerKeySet::verify(&NETWORK, &[], 0, None).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    let third = sequencer_credential(&key(62), 2, (600_000, 3_000_000), Some((&key(61), &second)))?;
    assert_eq!(
        SequencerKeySet::verify(&NETWORK, &[first, second, third], 0, None).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}
