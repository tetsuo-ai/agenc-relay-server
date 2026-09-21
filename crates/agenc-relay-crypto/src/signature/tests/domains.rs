#![forbid(unsafe_code)]

//! Every registered Ed25519 domain carries its own label and encoding.

use std::collections::BTreeSet;

use super::super::{Ed25519SecretKey, SignatureDomain, sign_canonical, verify_canonical};

type TestResult = Result<(), Box<dyn core::error::Error>>;

/// The complete registered set. A new domain fails this list before it can
/// reach the wire, so the label table cannot gain an unexercised arm.
const REGISTERED: [SignatureDomain; 44] = [
    SignatureDomain::AccountCreationInvite,
    SignatureDomain::FederationHello,
    SignatureDomain::AdminSession,
    SignatureDomain::AdminCommand,
    SignatureDomain::AdminAuditEvent,
    SignatureDomain::MaintenanceAuditEvent,
    SignatureDomain::AdminAuditCheckpoint,
    SignatureDomain::BackupSignature,
    SignatureDomain::StorageQualificationReport,
    SignatureDomain::ReleaseDecision,
    SignatureDomain::RootIdentity,
    SignatureDomain::RootContinuity,
    SignatureDomain::DeviceEnrollmentPossession,
    SignatureDomain::DeviceEnrollmentApproval,
    SignatureDomain::DeviceCertificate,
    SignatureDomain::DeviceRoster,
    SignatureDomain::DeviceCapabilities,
    SignatureDomain::LeafAuthorization,
    SignatureDomain::SequencerContinuity,
    SignatureDomain::PolicyApproval,
    SignatureDomain::ConversationBinding,
    SignatureDomain::RootBindingLock,
    SignatureDomain::CommitAuthorization,
    SignatureDomain::ReinitAttemptAuthorization,
    SignatureDomain::Reservation,
    SignatureDomain::CloseAuthorization,
    SignatureDomain::DeviceAttachChallenge,
    SignatureDomain::DeviceAttachPossession,
    SignatureDomain::CandidateReceipt,
    SignatureDomain::CommitProcessed,
    SignatureDomain::DispositionVote,
    SignatureDomain::CommitFinalization,
    SignatureDomain::CandidateAbort,
    SignatureDomain::ReinitAttempt,
    SignatureDomain::ReinitAttemptReceipt,
    SignatureDomain::ReinitProcessed,
    SignatureDomain::ReinitDisposition,
    SignatureDomain::ReinitActivation,
    SignatureDomain::ReinitAttemptAbort,
    SignatureDomain::LeafMembership,
    SignatureDomain::LeafMembershipPossession,
    SignatureDomain::RecoverySubmission,
    SignatureDomain::MlsKeyPackageTbs,
    SignatureDomain::MlsLeafNodeTbs,
];

#[test]
fn one_key_and_one_content_produce_a_distinct_signature_for_every_domain() -> TestResult {
    let key = Ed25519SecretKey::from_bytes([31_u8; 32]);
    let public = key.public_key();
    let content = b"one canonical content";
    let mut signatures = BTreeSet::new();
    for domain in REGISTERED {
        let signature = sign_canonical(&key, domain, content)?;
        verify_canonical(public, domain, content, signature)?;
        assert!(
            signatures.insert(*signature.as_bytes()),
            "{domain:?} repeats the signature of another registered domain"
        );
    }
    assert_eq!(signatures.len(), REGISTERED.len());
    Ok(())
}

#[test]
fn a_signature_never_verifies_under_a_neighbouring_domain() -> TestResult {
    let key = Ed25519SecretKey::from_bytes([32_u8; 32]);
    let public = key.public_key();
    let content = b"one canonical content";
    let mut checked = 0_usize;
    for (index, domain) in REGISTERED.iter().enumerate() {
        let next = REGISTERED
            .get(index.checked_add(1).unwrap_or_default() % REGISTERED.len())
            .copied()
            .ok_or("successor domain")?;
        let signature = sign_canonical(&key, *domain, content)?;
        assert!(
            verify_canonical(public, next, content, signature).is_err(),
            "{domain:?} verified under {next:?}"
        );
        checked = checked.saturating_add(1);
    }
    assert_eq!(checked, REGISTERED.len());
    Ok(())
}

#[test]
fn every_registered_label_is_unique_and_matches_its_declared_encoding() -> TestResult {
    let key = Ed25519SecretKey::from_bytes([33_u8; 32]);
    let mut labels = BTreeSet::new();
    let mut irc = 0_usize;
    let mut direct = 0_usize;
    let mut mls = 0_usize;
    for domain in REGISTERED {
        let label = domain.label();
        assert!(!label.is_empty(), "{domain:?} has an empty label");
        assert!(
            labels.insert(label.to_vec()),
            "{domain:?} repeats another domain's label"
        );
        match domain.encoding() {
            super::super::SignatureEncoding::ArcSignatureInput => {
                assert!(label.starts_with(b"ARC-MLS/1 "), "{domain:?}");
                irc = irc.saturating_add(1);
            }
            super::super::SignatureEncoding::DirectPrefix => {
                assert!(label.starts_with(b"agenc-chat "), "{domain:?}");
                direct = direct.saturating_add(1);
            }
            super::super::SignatureEncoding::MlsSignWithLabel => {
                assert!(label.starts_with(b"MLS 1.0 "), "{domain:?}");
                mls = mls.saturating_add(1);
            }
        }
        // The label enters the signed input, so a changed label invalidates
        // every signature the old label produced.
        sign_canonical(&key, domain, b"content")?;
    }
    assert_eq!(irc.saturating_add(direct).saturating_add(mls), 44);
    assert_eq!((irc, direct, mls), (32, 10, 2));
    Ok(())
}
