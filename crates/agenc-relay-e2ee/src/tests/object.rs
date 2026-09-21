#![forbid(unsafe_code)]

//! Envelope, kind table, and object identifier tests.

use std::error::Error;

use super::*;
use crate::limits::{MAX_DEVICE_ATTACH_OBJECT, WIRE_OBJECT_ENVELOPE_BYTES};

type TestResult = Result<(), Box<dyn Error>>;

#[test]
fn the_envelope_round_trips_and_names_its_id() -> TestResult {
    let object = ArcWireObject::new(ArcWireObjectKind::CommitAck, vec![5; 40])?;
    let encoded = object.encode()?;
    assert_eq!(encoded.get(..6), Some(&[0_u8, 1, 4, 0, 0, 40][..]));
    assert_eq!(encoded.len(), 46);
    assert_eq!(object.encoded_len(), 46);
    assert_eq!(
        ArcWireObject::peek(&encoded)?,
        (ArcWireObjectKind::CommitAck, 40)
    );
    let mut budget = DecodeBudget::new(1 << 16, 8);
    let decoded =
        ArcWireObject::decode_kind(&encoded, Some(ArcWireObjectKind::CommitAck), &mut budget)?;
    assert_eq!(decoded, object);
    assert_eq!(decoded.object_id()?, ObjectId::compute(&encoded));
    let mut budget = DecodeBudget::new(1 << 16, 8);
    assert_eq!(
        ArcWireObject::decode_kind(&encoded, Some(ArcWireObjectKind::CommitMls), &mut budget),
        Err(E2eeError::WrongKind)
    );
    Ok(())
}

#[test]
fn envelope_bounds_are_checked_before_the_body_is_copied() -> TestResult {
    let limit = MAX_DEVICE_ATTACH_OBJECT - WIRE_OBJECT_ENVELOPE_BYTES;
    assert!(ArcWireObject::new(ArcWireObjectKind::DeviceAttach, vec![0; limit]).is_ok());
    assert_eq!(
        ArcWireObject::new(ArcWireObjectKind::DeviceAttach, vec![0; limit + 1]),
        Err(E2eeError::LimitExceeded)
    );
    assert_eq!(
        ArcWireObject::new(ArcWireObjectKind::DeviceAttach, Vec::new()),
        Err(E2eeError::LengthOutOfRange)
    );
    // A declared length that does not match the input is refused by peek.
    let mut declared_long = vec![0, 1, 27, 0, 0, 9];
    declared_long.extend_from_slice(&[1; 8]);
    assert_eq!(
        ArcWireObject::peek(&declared_long),
        Err(E2eeError::LimitExceeded)
    );
    let zero = vec![0, 1, 27, 0, 0, 0];
    assert_eq!(ArcWireObject::peek(&zero), Err(E2eeError::LengthOutOfRange));
    let version = vec![0, 2, 27, 0, 0, 1, 0];
    assert_eq!(
        ArcWireObject::peek(&version),
        Err(E2eeError::ProfileMismatch)
    );
    let kind = vec![0, 1, 99, 0, 0, 1, 0];
    assert_eq!(
        ArcWireObject::peek(&kind),
        Err(E2eeError::UnknownDiscriminant)
    );
    Ok(())
}

#[test]
fn every_kind_has_a_token_a_limit_and_a_direction() -> TestResult {
    assert_eq!(ArcWireObjectKind::ALL.len(), 37);
    assert_eq!(ArcWireObjectKind::RecoverySubmission.value(), 35);
    assert_eq!(
        ArcWireObjectKind::RecoverySubmission.token(),
        "RECOVERY-SUBMISSION"
    );
    assert_eq!(
        ArcWireObjectKind::RecoverySubmission.maximum_object_bytes(),
        4_096
    );
    assert_eq!(ArcWireObjectKind::WitnessResolution.value(), 36);
    assert_eq!(
        ArcWireObjectKind::WitnessResolution.token(),
        "WITNESS-RESOLUTION"
    );
    assert_eq!(
        ArcWireObjectKind::WitnessResolution.maximum_object_bytes(),
        65_536
    );
    assert!(ArcWireObjectKind::WitnessResolution.is_server_only());
    assert_eq!(ArcWireObjectKind::LeafMembershipProof.value(), 37);
    assert_eq!(
        ArcWireObjectKind::LeafMembershipProof.token(),
        "LEAF-MEMBERSHIP-PROOF"
    );
    assert_eq!(
        ArcWireObjectKind::LeafMembershipProof.maximum_object_bytes(),
        8_192
    );
    // Kind 38 is not registered by this implementation.
    assert_eq!(
        ArcWireObject::peek(&[0, 1, 38, 0, 0, 1, 0]),
        Err(E2eeError::UnknownDiscriminant)
    );
    for kind in ArcWireObjectKind::ALL {
        assert_eq!(ArcWireObjectKind::from_token(kind.token())?, *kind);
        assert!(kind.maximum_object_bytes() >= 4_096);
        assert_eq!(
            kind.is_server_only(),
            (29..=33).contains(&kind.value()) || kind.value() == 36
        );
    }
    assert_eq!(
        ArcWireObjectKind::from_token("PLAINTEXT"),
        Err(E2eeError::UnknownDiscriminant)
    );
    assert_eq!(
        ArcWireObjectKind::FinalizationRequest.maximum_object_bytes(),
        4_190_000
    );
    assert_eq!(
        ArcWireObjectKind::WelcomeMls.maximum_object_bytes(),
        4_194_304
    );
    Ok(())
}
