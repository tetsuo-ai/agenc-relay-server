#![forbid(unsafe_code)]

use std::error::Error;

use agenc_ircd_crypto::SemanticHashDomain;

use super::*;
use crate::ids::semantic_id_of;
use crate::objects::AccountIdField;
use crate::objects::recovery::IrcRecoverySubmissionTbs;
use crate::tls::{DecodeBudget, TlsDecode};

type TestResult = Result<(), Box<dyn Error>>;

fn tbs(
    kind: IrcRecoveryElementKind,
    object_kind: IrcWireObjectKind,
) -> Result<IrcRecoverySubmissionTbs, Box<dyn Error>> {
    Ok(IrcRecoverySubmissionTbs {
        profile_version: 1,
        network_id: [1; 32],
        conversation_id: [2; 32],
        recovery_epoch: [3; 16],
        restored_binding_id: [4; 32],
        restored_accepted_state_id: [5; 32],
        restored_sequencer_head_id: [6; 32],
        source_rollback_guard_hash: [7; 32],
        route_sequence: 8,
        predecessor_record_id: [9; 32],
        element_kind: kind,
        element_object_kind: object_kind,
        element_object_id: [10; 32],
        account_id: AccountIdField::new([b'a'; 24].to_vec())?,
        device_id: [11; 16],
    })
}

#[test]
fn element_kinds_accept_exactly_their_object_kinds() {
    use IrcRecoveryElementKind::{CloseElement, RecordElement, ReferenceElement};
    assert!(element_kind_accepts(
        RecordElement,
        IrcWireObjectKind::SequencerRecord
    ));
    assert!(!element_kind_accepts(
        RecordElement,
        IrcWireObjectKind::CloseAuthorization
    ));
    assert!(element_kind_accepts(
        CloseElement,
        IrcWireObjectKind::CloseAuthorization
    ));
    assert!(!element_kind_accepts(
        CloseElement,
        IrcWireObjectKind::SequencerRecord
    ));
    for kind in REFERENCE_ELEMENT_KINDS {
        assert!(element_kind_accepts(ReferenceElement, kind));
    }
    assert!(!element_kind_accepts(
        ReferenceElement,
        IrcWireObjectKind::SequencerRecord
    ));
    assert!(!element_kind_accepts(
        ReferenceElement,
        IrcWireObjectKind::ApplicationMls
    ));
    assert_eq!(
        E2eeError::from(RecoveryRefusal::Invalid),
        E2eeError::InvalidValue
    );
    assert_eq!(
        E2eeError::from(RecoveryRefusal::DeviceInactive),
        E2eeError::KeyInvalid
    );
    assert_eq!(
        E2eeError::from(RecoveryRefusal::SignatureInvalid),
        E2eeError::SignatureInvalid
    );
}

#[test]
fn a_submission_round_trips_and_its_identifier_covers_every_field() -> TestResult {
    let base = tbs(
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
    )?;
    let submission = IrcRecoverySubmission {
        tbs: base.clone(),
        device_signature: [12; 64],
    };
    let encoded = submission.encode()?;
    let mut budget = DecodeBudget::new(4_096, 1 << 10);
    assert_eq!(
        IrcRecoverySubmission::decode_exact(&encoded, &mut budget)?,
        submission
    );
    let id = semantic_id_of(SemanticHashDomain::RecoverySubmissionId, &base)?;
    let mut other = base.clone();
    other.route_sequence += 1;
    assert_ne!(
        semantic_id_of(SemanticHashDomain::RecoverySubmissionId, &other)?,
        id
    );
    let mut other = base;
    other.element_kind = IrcRecoveryElementKind::CloseElement;
    assert_ne!(
        semantic_id_of(SemanticHashDomain::RecoverySubmissionId, &other)?,
        id
    );
    Ok(())
}

fn signed(
    device: u8,
    tbs: IrcRecoverySubmissionTbs,
) -> Result<IrcRecoverySubmission, Box<dyn Error>> {
    let device_signature = crate::test_support::sign(
        &crate::test_support::key(device),
        agenc_ircd_crypto::SignatureDomain::RecoverySubmission,
        &tbs,
    )?;
    Ok(IrcRecoverySubmission {
        tbs,
        device_signature,
    })
}

#[test]
fn a_submission_verifies_under_its_roster_device_and_every_defect_is_classified() -> TestResult {
    let account = [b'a'; 24];
    let principal = crate::test_support::principal(3, &account, &[11])?;
    let rosters = crate::test_support::principal_rosters(std::slice::from_ref(&principal))?;
    let (_, roster) = rosters.values().next().ok_or("roster")?;
    let base = tbs(
        IrcRecoveryElementKind::RecordElement,
        IrcWireObjectKind::SequencerRecord,
    )?;
    let verified = verify_recovery_submission(&[1; 32], &signed(11, base.clone())?, roster)
        .map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(verified.device_id, [11; 16]);
    assert_eq!(verified.account_id, account);
    assert_eq!(
        verified.submission_id,
        semantic_id_of(SemanticHashDomain::RecoverySubmissionId, &base)?
    );
    type Mutation = Box<dyn Fn(&mut IrcRecoverySubmissionTbs)>;
    let cases: Vec<(&str, Mutation, RecoveryRefusal)> = vec![
        (
            "profile",
            Box::new(|tbs| tbs.profile_version = 2),
            RecoveryRefusal::Invalid,
        ),
        (
            "network",
            Box::new(|tbs| tbs.network_id = [9; 32]),
            RecoveryRefusal::Invalid,
        ),
        (
            "element kind",
            Box::new(|tbs| tbs.element_object_kind = IrcWireObjectKind::Policy),
            RecoveryRefusal::Invalid,
        ),
        (
            "object id",
            Box::new(|tbs| tbs.element_object_id = [0; 32]),
            RecoveryRefusal::Invalid,
        ),
        (
            "device",
            Box::new(|tbs| tbs.device_id = [12; 16]),
            RecoveryRefusal::DeviceInactive,
        ),
    ];
    for (name, mutate, expected) in cases {
        let mut tbs = base.clone();
        mutate(&mut tbs);
        assert_eq!(
            verify_recovery_submission(&[1; 32], &signed(11, tbs)?, roster).err(),
            Some(expected),
            "{name}"
        );
    }
    let mut forged = signed(11, base)?;
    forged.device_signature[0] ^= 1;
    assert_eq!(
        verify_recovery_submission(&[1; 32], &forged, roster).err(),
        Some(RecoveryRefusal::SignatureInvalid)
    );
    Ok(())
}
