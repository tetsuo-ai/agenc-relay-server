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

#[test]
fn a_file_opening_above_generation_zero_verifies_structurally() -> TestResult {
    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let second = sequencer_credential(
        &key(61),
        1,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    let verified_first = verify_sequencer_credential(&NETWORK, &first, None)?;
    // The opened set names the same credential, digest, and predecessor as
    // the set verified with the predecessor at hand.
    let with_head = SequencerKeySet::verify(
        &NETWORK,
        std::slice::from_ref(&second),
        2,
        Some(&verified_first),
    )?;
    let opened = SequencerKeySet::verify_opened(&NETWORK, std::slice::from_ref(&second), 2)?;
    assert_eq!(opened, with_head);
    assert_eq!(
        SequencerKeySet::verify(&NETWORK, std::slice::from_ref(&second), 2, None).map(|_| ()),
        Err(E2eeError::InvalidValue),
        "a lone successor has no predecessor at hand"
    );
    // A generation-zero opening still verifies fully, and a successor
    // still chains from the opened credential.
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, &[first.clone(), second.clone()], 1)?,
        SequencerKeySet::verify(&NETWORK, &[first.clone(), second.clone()], 1, None)?
    );
    let third = sequencer_credential(&key(62), 2, (600_000, 3_000_000), Some((&key(61), &second)))?;
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, &[second.clone(), third.clone()], 3)?
            .credentials
            .len(),
        2
    );
    let mut forged = third.clone();
    forged.tbs.not_before = 700_000;
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, &[second.clone(), forged], 3).map(|_| ()),
        Err(E2eeError::SignatureInvalid),
        "the successor's continuity is verified against the opened credential"
    );
    // The opened credential itself must carry a continuity signature and a
    // predecessor, and match the network.
    let mut unsigned = second.clone();
    unsigned.continuity_signature = Opaque::new(Vec::new())?;
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, std::slice::from_ref(&unsigned), 2).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    let mut rootless = second.clone();
    rootless.tbs.previous_key_id = [0; 32];
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, std::slice::from_ref(&rootless), 2).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    let mut inverted = second.clone();
    inverted.tbs.not_after = inverted.tbs.not_before;
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, std::slice::from_ref(&inverted), 2).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    let mut zero_generation = second.clone();
    zero_generation.tbs.key_generation = 0;
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, std::slice::from_ref(&zero_generation), 2)
            .map(|_| ()),
        Err(E2eeError::InvalidValue),
        "generation zero opens only without a predecessor"
    );
    assert_eq!(
        verify_opened_credential(&NETWORK, &zero_generation).map(|_| ()),
        Err(E2eeError::InvalidValue),
        "an opened credential is never generation zero"
    );
    let mut wrong_profile = second.clone();
    wrong_profile.tbs.profile_version = 2;
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, std::slice::from_ref(&wrong_profile), 2)
            .map(|_| ()),
        Err(E2eeError::ProfileMismatch)
    );
    assert_eq!(
        SequencerKeySet::verify_opened(&[2; 32], std::slice::from_ref(&second), 2).map(|_| ()),
        Err(E2eeError::ProfileMismatch)
    );
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, &[second, third.clone(), third], 3).map(|_| ()),
        Err(E2eeError::InvalidValue),
        "at most one successor"
    );
    assert_eq!(
        SequencerKeySet::verify_opened(&NETWORK, &[], 0).map(|_| ()),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

/// Companion 12.5.1: a record verifies under the current credential at any
/// time, and under the overlapping successor only from its `not_before`
/// through `MAX_SEQUENCER_KEY_OVERLAP`; outside that window the successor
/// is any other key.
#[test]
fn a_successor_credential_is_admitted_only_inside_its_overlap_window() -> TestResult {
    const OPENS: u64 = 500_000;
    let closes = OPENS + crate::limits::MAX_SEQUENCER_KEY_OVERLAP_SECONDS;
    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let second = sequencer_credential(
        &key(61),
        1,
        (OPENS, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    let pair = SequencerKeySet::verify(&NETWORK, &[first, second], 1, None)?;
    let (current, successor) = match pair.credentials.as_slice() {
        [current, successor] => (current.credential_id, successor.credential_id),
        _ => return Err("the set holds the current key and its successor".into()),
    };
    // The current credential has no window.
    for time in [0, OPENS - 1, OPENS, closes, closes + 1, u64::MAX] {
        assert_eq!(
            pair.credential_at(&current, ValidationTime(time))
                .map(|credential| credential.credential_id),
            Some(current),
            "current credential at {time}"
        );
    }
    // The successor: before, at the opening, inside, at the close, and past.
    let admitted = |time: u64| {
        pair.credential_at(&successor, ValidationTime(time))
            .map(|credential| credential.credential_id)
    };
    assert_eq!(admitted(OPENS - 1), None, "before the window opens");
    assert_eq!(admitted(OPENS), Some(successor), "at the opening");
    assert_eq!(admitted(OPENS + 1), Some(successor), "inside the window");
    assert_eq!(admitted(closes), Some(successor), "at the close");
    assert_eq!(admitted(closes + 1), None, "past the window");
    assert_eq!(admitted(u64::MAX), None, "far past the window");
    // A credential the set does not hold is never admitted.
    assert!(
        pair.credential_at(&[9; 32], ValidationTime(OPENS))
            .is_none()
    );
    Ok(())
}

#[test]
fn credentials_are_checked_for_network_genesis_shape_lineage_and_file_size() -> TestResult {
    use crate::sequencer::{MAX_SEQUENCER_CREDENTIALS_FILE_BYTES, SequencerCredentialsFile};

    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let verified_first = verify_sequencer_credential(&NETWORK, &first, None)?;
    assert_eq!(
        verify_sequencer_credential(&[9; 32], &first, None),
        Err(E2eeError::ProfileMismatch),
        "another network"
    );
    let mut signed_genesis = first.clone();
    signed_genesis.continuity_signature = Opaque::new(vec![0; 64])?;
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &signed_genesis, None),
        Err(E2eeError::InvalidValue),
        "a generation-zero credential with a continuity signature"
    );
    let mut wrong_previous = sequencer_credential(
        &key(61),
        1,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    wrong_previous.tbs.previous_key_id = [9; 32];
    assert_eq!(
        verify_sequencer_credential(&NETWORK, &wrong_previous, Some(&verified_first)),
        Err(E2eeError::InvalidValue),
        "a successor naming another predecessor"
    );
    assert_eq!(
        SequencerCredentialsFile::parse(&vec![0; MAX_SEQUENCER_CREDENTIALS_FILE_BYTES + 1]).err(),
        Some(E2eeError::LimitExceeded)
    );
    Ok(())
}
