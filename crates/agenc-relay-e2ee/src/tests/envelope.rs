#![forbid(unsafe_code)]

//! Padding arithmetic and outer object checks.

use std::error::Error;

use super::*;
use crate::test_support::*;
use crate::tls::TlsEncode;

type TestResult = Result<(), Box<dyn Error>>;

const GROUP: [u8; 32] = [25; 32];

fn expectation() -> RouteExpectation {
    RouteExpectation {
        network_id: NETWORK,
        conversation_id: [20; 32],
        route_binding: [21; 32],
        group_id: GROUP,
    }
}

fn application_aad() -> ArcApplicationAad {
    ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: [20; 32],
        route_binding: [21; 32],
        latest_state_id: [22; 32],
    }
}

fn commit_aad(prior: [u8; 32], validation_time: u64) -> ArcCommitAad {
    ArcCommitAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: [20; 32],
        route_binding: [21; 32],
        validation_time,
        prior_state_id: prior,
    }
}

fn object(
    kind: ArcWireObjectKind,
    content_type: u8,
    aad: &[u8],
) -> Result<ArcWireObject, E2eeError> {
    ArcWireObject::new(kind, private_message_bytes(&GROUP, content_type, aad)?)
}

#[test]
fn padding_follows_the_two_tier_table() -> TestResult {
    let rows = [
        (0, 0),
        (1, 256),
        (255, 256),
        (256, 256),
        (257, 512),
        (4_095, 4_096),
        (4_096, 4_096),
        (4_097, 5_120),
        (5_120, 5_120),
        (5_121, 6_144),
        (65_536, 65_536),
    ];
    for (length, target) in rows {
        assert_eq!(padding_target(length)?, target, "L={length}");
        assert_eq!(padding_bytes(length)?, target - length, "L={length}");
        assert!(padding_target(length)? >= length);
    }
    assert_eq!(padding_target(usize::MAX), Err(E2eeError::Overflow));
    assert_eq!(padding_bytes(usize::MAX), Err(E2eeError::Overflow));
    assert_eq!(check_padding(4_097, &[0; 1_023]), Ok(()));
    assert_eq!(check_padding(256, &[]), Ok(()));
    assert_eq!(
        check_padding(4_097, &[0; 1_022]),
        Err(E2eeError::InvalidValue)
    );
    let mut dirty = vec![0; 1_023];
    if let Some(last) = dirty.last_mut() {
        *last = 1;
    }
    assert_eq!(check_padding(4_097, &dirty), Err(E2eeError::InvalidValue));
    Ok(())
}

#[test]
fn application_objects_must_name_their_route() -> TestResult {
    let aad = application_aad().encode()?;
    let good = object(ArcWireObjectKind::ApplicationMls, 1, &aad)?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let envelope = verify_application_object(&good, &expectation(), &mut budget)?;
    assert_eq!(envelope.header.epoch, 9);
    assert_eq!(envelope.aad.latest_state_id, [22; 32]);
    assert_eq!(
        verify_application_object(
            &object(ArcWireObjectKind::CommitMls, 1, &aad)?,
            &expectation(),
            &mut budget
        ),
        Err(E2eeError::WrongKind)
    );
    assert_eq!(
        verify_application_object(
            &object(ArcWireObjectKind::ApplicationMls, 3, &aad)?,
            &expectation(),
            &mut budget
        ),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_application_object(
            &ArcWireObject::new(ArcWireObjectKind::ApplicationMls, welcome_message(&[])?)?,
            &expectation(),
            &mut budget
        ),
        Err(E2eeError::WrongKind)
    );
    let mut other_group = expectation();
    other_group.group_id = [1; 32];
    assert_eq!(
        verify_application_object(&good, &other_group, &mut budget),
        Err(E2eeError::InvalidValue)
    );
    let mut other_conversation = expectation();
    other_conversation.conversation_id = [1; 32];
    assert_eq!(
        verify_application_object(&good, &other_conversation, &mut budget),
        Err(E2eeError::InvalidValue)
    );
    let mut trailing = aad.clone();
    trailing.push(0);
    assert_eq!(
        verify_application_object(
            &object(ArcWireObjectKind::ApplicationMls, 1, &trailing)?,
            &expectation(),
            &mut budget
        ),
        Err(E2eeError::TrailingBytes)
    );
    assert_eq!(
        verify_application_object(
            &object(
                ArcWireObjectKind::ApplicationMls,
                1,
                &commit_aad([0; 32], 1).encode()?
            )?,
            &expectation(),
            &mut budget
        ),
        Err(E2eeError::TrailingBytes),
        "a Commit AAD is longer than an application AAD"
    );
    Ok(())
}

#[test]
fn commit_objects_chain_from_the_accepted_state() -> TestResult {
    let accepted = [30; 32];
    let good = object(
        ArcWireObjectKind::CommitMls,
        3,
        &commit_aad(accepted, 500).encode()?,
    )?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let envelope = verify_commit_object(&good, &expectation(), &accepted, 500, &mut budget)?;
    assert_eq!(envelope.aad.validation_time, 500);
    assert_eq!(envelope.header.content_type, MlsContentType::Commit);
    assert_eq!(
        verify_commit_object(&good, &expectation(), &[31; 32], 500, &mut budget),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_commit_object(&good, &expectation(), &accepted, 501, &mut budget),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_commit_object(
            &object(
                ArcWireObjectKind::CommitMls,
                1,
                &commit_aad(accepted, 500).encode()?
            )?,
            &expectation(),
            &accepted,
            500,
            &mut budget
        ),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_commit_object(
            &object(
                ArcWireObjectKind::ApplicationMls,
                3,
                &commit_aad(accepted, 500).encode()?
            )?,
            &expectation(),
            &accepted,
            500,
            &mut budget
        ),
        Err(E2eeError::WrongKind)
    );
    let mut wrong_network = commit_aad(accepted, 500);
    wrong_network.network_id = [2; 32];
    assert_eq!(
        verify_commit_object(
            &object(ArcWireObjectKind::CommitMls, 3, &wrong_network.encode()?)?,
            &expectation(),
            &accepted,
            500,
            &mut budget
        ),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}
