#![forbid(unsafe_code)]

//! The ECAP negotiation.

use super::*;
use crate::wire::tokens::base64url_encode;

fn tuple(generation: u64) -> Result<EcapTuple, E2eeError> {
    EcapTuple::local(
        &base64url_encode(&[1; 32]),
        &base64url_encode(&[2; 16]),
        generation,
        &base64url_encode(&[4; 32]),
    )
}

#[test]
fn the_four_flags_follow_the_only_legal_transitions() -> Result<(), E2eeError> {
    let (mut negotiation, offer) = EcapNegotiation::start(tuple(1)?, 100);
    assert_eq!(offer, CompanionFrame::EcapOffer(tuple(1)?));
    assert_eq!(negotiation.flags(), [false; 4]);
    assert_eq!(negotiation.deadline(), 5_100);
    assert!(!negotiation.profile_active());
    let ack_frame = CompanionFrame::Ack(crate::federation::frames::DeliveryPosition {
        server_id: [1; 16],
        delivery_generation: 0,
        delivery_sequence: 0,
        event_id: [0; 16],
    });
    assert_eq!(negotiation.admit(&ack_frame), Err(EcapViolation::NotActive));
    assert_eq!(
        negotiation.on_ack(true, &tuple(1)?),
        Err(EcapViolation::AckBeforeOffer)
    );
    assert_eq!(
        negotiation.on_offer(false, &tuple(1)?),
        Err(EcapViolation::Prefix)
    );
    assert_eq!(
        negotiation.on_offer(true, &tuple(2)?),
        Err(EcapViolation::TupleMismatch)
    );
    let ack = negotiation.on_offer(true, &tuple(1)?)?;
    assert_eq!(ack, CompanionFrame::EcapAck(tuple(1)?));
    assert_eq!(negotiation.flags(), [true, true, false, false]);
    assert_eq!(
        negotiation.on_offer(true, &tuple(1)?),
        Err(EcapViolation::Duplicate)
    );
    assert_eq!(
        negotiation.on_ack(false, &tuple(1)?),
        Err(EcapViolation::Prefix)
    );
    assert_eq!(
        negotiation.on_ack(true, &tuple(2)?),
        Err(EcapViolation::TupleMismatch)
    );
    assert_eq!(negotiation.on_tick(5_099), Ok(()));
    assert_eq!(negotiation.on_tick(5_100), Err(EcapViolation::Timeout));
    negotiation.on_ack(true, &tuple(1)?)?;
    assert_eq!(negotiation.flags(), [true, true, true, true]);
    assert!(negotiation.profile_active());
    assert_eq!(negotiation.on_tick(9_000), Ok(()));
    assert_eq!(negotiation.admit(&ack_frame), Ok(()));
    assert_eq!(negotiation.admit(&offer), Err(EcapViolation::Duplicate));
    assert_eq!(
        negotiation.on_ack(true, &tuple(1)?),
        Err(EcapViolation::Duplicate)
    );
    assert_eq!(negotiation.local(), &tuple(1)?);
    assert_eq!(
        violation_line("s"),
        ":s ERROR :ARC-MLS profile mismatch\r\n"
    );
    assert_eq!(
        E2eeError::from(EcapViolation::Timeout),
        E2eeError::ProfileMismatch
    );
    assert!(!EcapViolation::Prefix.to_string().is_empty());
    Ok(())
}

#[test]
fn simultaneous_offers_activate_both_sides() -> Result<(), E2eeError> {
    let (mut left, left_offer) = EcapNegotiation::start(tuple(1)?, 0);
    let (mut right, right_offer) = EcapNegotiation::start(tuple(1)?, 0);
    let CompanionFrame::EcapOffer(left_tuple) = &left_offer else {
        return Err(E2eeError::InvalidValue);
    };
    let CompanionFrame::EcapOffer(right_tuple) = &right_offer else {
        return Err(E2eeError::InvalidValue);
    };
    let left_ack = left.on_offer(true, right_tuple)?;
    let right_ack = right.on_offer(true, left_tuple)?;
    let CompanionFrame::EcapAck(to_left) = &right_ack else {
        return Err(E2eeError::InvalidValue);
    };
    let CompanionFrame::EcapAck(to_right) = &left_ack else {
        return Err(E2eeError::InvalidValue);
    };
    left.on_ack(true, to_left)?;
    right.on_ack(true, to_right)?;
    assert!(left.profile_active() && right.profile_active());
    Ok(())
}

#[test]
fn the_key_set_record_rule_is_closed() -> Result<(), E2eeError> {
    let record = KeySetRecord {
        generation: 3,
        hash: [1; 32],
    };
    assert_eq!(
        accept_key_set(None, record),
        Ok(KeySetAcceptance::Initialized)
    );
    assert_eq!(
        accept_key_set(Some(record), record),
        Ok(KeySetAcceptance::Same)
    );
    assert_eq!(
        accept_key_set(
            Some(record),
            KeySetRecord {
                generation: 4,
                hash: [2; 32]
            }
        ),
        Ok(KeySetAcceptance::Successor)
    );
    assert_eq!(
        accept_key_set(
            Some(record),
            KeySetRecord {
                generation: 2,
                hash: [1; 32]
            }
        ),
        Err(KeySetError::Rollback)
    );
    assert_eq!(
        accept_key_set(
            Some(record),
            KeySetRecord {
                generation: 5,
                hash: [1; 32]
            }
        ),
        Err(KeySetError::Gap)
    );
    assert_eq!(
        accept_key_set(
            Some(record),
            KeySetRecord {
                generation: 3,
                hash: [2; 32]
            }
        ),
        Err(KeySetError::Equivocation)
    );
    let exhausted = KeySetRecord {
        generation: u64::MAX,
        hash: [1; 32],
    };
    assert_eq!(
        accept_key_set(Some(exhausted), exhausted),
        Ok(KeySetAcceptance::Same)
    );
    assert_eq!(
        accept_key_set(
            Some(exhausted),
            KeySetRecord {
                generation: u64::MAX,
                hash: [2; 32]
            }
        ),
        Err(KeySetError::Equivocation)
    );
    let almost = KeySetRecord {
        generation: u64::MAX - 1,
        hash: [1; 32],
    };
    assert_eq!(
        accept_key_set(Some(almost), exhausted),
        Ok(KeySetAcceptance::Successor)
    );
    assert_eq!(check_peer_key_set(&tuple(1)?, &tuple(1)?), Ok(()));
    assert_eq!(
        check_peer_key_set(&tuple(1)?, &tuple(2)?),
        Err(KeySetError::LocalMismatch)
    );
    assert!(!KeySetError::Exhausted.to_string().is_empty());
    Ok(())
}
