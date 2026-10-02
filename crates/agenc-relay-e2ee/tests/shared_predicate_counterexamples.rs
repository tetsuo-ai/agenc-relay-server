#![forbid(unsafe_code)]

//! Correctly signed counterexamples to the shared public verifiers, built
//! only through public APIs: a client importing public objects runs these
//! predicates and has no daemon-side check behind them. Each `*_is_refused`
//! case is admitted by the verifiers this file was written against; each
//! `control_*` case pins the behaviour the corrections keep.

use std::error::Error;

use agenc_relay_crypto::{Ed25519SecretKey, SemanticHashDomain, SignatureDomain, sign_canonical};
use agenc_relay_e2ee::identity::{
    restore_capabilities, verify_capabilities, verify_leaf_authorization, verify_root_identity,
    verify_roster,
};
use agenc_relay_e2ee::ids::{SemanticId, semantic_id_of};
use agenc_relay_e2ee::objects::AccountIdField;
use agenc_relay_e2ee::objects::conversation::{ArcSequencerCredential, ArcSequencerCredentialTbs};
use agenc_relay_e2ee::objects::identity::{
    ArcActiveDevice, ArcDeviceCapabilities, ArcDeviceCapabilitiesTbs, ArcDeviceCertificate,
    ArcDeviceCertificateTbs, ArcDeviceEnrollment, ArcDeviceEnrollmentTbs, ArcDeviceRevocation,
    ArcDeviceRoster, ArcDeviceRosterTbs, ArcLeafAuthorization, ArcLeafAuthorizationTbs,
    ArcRootIdentity, ArcRootIdentityTbs,
};
use agenc_relay_e2ee::sequencer::{SequencerKeySet, verify_sequencer_credential};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode, TlsVec};

type TestResult = Result<(), Box<dyn Error>>;

const NET_A: [u8; 32] = [1; 32];
const ACCOUNT: [u8; 24] = [b'a'; 24];

fn key(seed: u8) -> Ed25519SecretKey {
    Ed25519SecretKey::from_bytes([seed; 32])
}

fn public(secret: &Ed25519SecretKey) -> [u8; 32] {
    *secret.public_key().as_bytes()
}

fn sign(
    secret: &Ed25519SecretKey,
    domain: SignatureDomain,
    tbs: &impl TlsEncode,
) -> Result<[u8; 64], Box<dyn Error>> {
    Ok(*sign_canonical(secret, domain, &tbs.encode()?)?.as_bytes())
}

fn account_field() -> Result<AccountIdField, Box<dyn Error>> {
    Ok(Opaque::from_slice(&ACCOUNT)?)
}

fn sequencer_credential(
    secret: &Ed25519SecretKey,
    generation: u64,
    interval: (u64, u64),
    previous: Option<(&Ed25519SecretKey, &ArcSequencerCredential)>,
) -> Result<ArcSequencerCredential, Box<dyn Error>> {
    let previous_key_id = match previous {
        Some((_, credential)) => semantic_id_of(SemanticHashDomain::SequencerKey, &credential.tbs)?,
        None => [0; 32],
    };
    let tbs = ArcSequencerCredentialTbs {
        profile_version: 1,
        network_id: NET_A,
        key_generation: generation,
        sequencer_public_key: public(secret),
        not_before: interval.0,
        not_after: interval.1,
        previous_key_id,
    };
    let continuity = match previous {
        Some((previous_secret, _)) => {
            sign(previous_secret, SignatureDomain::SequencerContinuity, &tbs)?.to_vec()
        }
        None => Vec::new(),
    };
    Ok(ArcSequencerCredential {
        tbs,
        continuity_signature: Opaque::new(continuity)?,
    })
}

fn root(secret: &Ed25519SecretKey, network: [u8; 32]) -> Result<ArcRootIdentity, Box<dyn Error>> {
    let tbs = ArcRootIdentityTbs {
        profile_version: 1,
        network_id: network,
        account_id: account_field()?,
        root_generation: 0,
        root_public_key: public(secret),
        not_before: 0,
        not_after: 1_000_000,
        previous_root_fingerprint: [0; 32],
    };
    Ok(ArcRootIdentity {
        self_signature: sign(secret, SignatureDomain::RootIdentity, &tbs)?,
        tbs,
        continuity_signature: Opaque::new(Vec::new())?,
    })
}

fn root_fingerprint(root: &ArcRootIdentity) -> Result<SemanticId, Box<dyn Error>> {
    Ok(semantic_id_of(
        SemanticHashDomain::RootFingerprint,
        &root.tbs,
    )?)
}

fn certificate(
    root_secret: &Ed25519SecretKey,
    root: &ArcRootIdentity,
    seed: u8,
    target_roster_generation: u64,
    enrollment: (u64, u64),
) -> Result<ArcDeviceCertificate, Box<dyn Error>> {
    let device_secret = key(seed);
    let enrollment_tbs = ArcDeviceEnrollmentTbs {
        profile_version: 1,
        network_id: NET_A,
        account_id: root.tbs.account_id.clone(),
        root_generation: root.tbs.root_generation,
        root_fingerprint: root_fingerprint(root)?,
        target_roster_generation,
        enrollment_challenge: [seed.wrapping_add(100); 32],
        device_id: [seed; 16],
        device_authorization_key: public(&device_secret),
        issued_at: enrollment.0,
        expires_at: enrollment.1,
    };
    let enrollment = ArcDeviceEnrollment {
        new_device_signature: sign(
            &device_secret,
            SignatureDomain::DeviceEnrollmentPossession,
            &enrollment_tbs,
        )?,
        root_signature: sign(
            root_secret,
            SignatureDomain::DeviceEnrollmentApproval,
            &enrollment_tbs,
        )?,
        tbs: enrollment_tbs,
    };
    let tbs = ArcDeviceCertificateTbs {
        profile_version: 1,
        network_id: NET_A,
        account_id: root.tbs.account_id.clone(),
        root_generation: root.tbs.root_generation,
        root_fingerprint: root_fingerprint(root)?,
        device_id: [seed; 16],
        device_authorization_key: public(&device_secret),
        target_roster_generation,
        enrollment_challenge: enrollment.tbs.enrollment_challenge,
        enrollment_id: semantic_id_of(SemanticHashDomain::EnrollmentId, &enrollment.tbs)?,
        certificate_serial: 1,
        authorization_flags: 3,
        not_before: 0,
        not_after: 1_000_000,
    };
    Ok(ArcDeviceCertificate {
        root_signature: sign(root_secret, SignatureDomain::DeviceCertificate, &tbs)?,
        tbs,
        enrollment_proof: enrollment,
    })
}

fn roster(
    root_secret: &Ed25519SecretKey,
    root: &ArcRootIdentity,
    generation: u64,
    previous_roster_id: [u8; 32],
    interval: (u64, u64),
    certificates: Vec<ArcDeviceCertificate>,
) -> Result<ArcDeviceRoster, Box<dyn Error>> {
    let active = certificates
        .into_iter()
        .map(|certificate| ArcActiveDevice {
            device_id: certificate.tbs.device_id,
            certificate,
        })
        .collect();
    let tbs = ArcDeviceRosterTbs {
        profile_version: 1,
        network_id: NET_A,
        account_id: root.tbs.account_id.clone(),
        root_generation: root.tbs.root_generation,
        root_fingerprint: root_fingerprint(root)?,
        roster_generation: generation,
        not_before: interval.0,
        not_after: interval.1,
        previous_roster_id,
        active_devices: TlsVec::new(active)?,
        revocations: TlsVec::new(Vec::<ArcDeviceRevocation>::new())?,
    };
    Ok(ArcDeviceRoster {
        root_signature: sign(root_secret, SignatureDomain::DeviceRoster, &tbs)?,
        tbs,
    })
}

fn roster_id(roster: &ArcDeviceRoster) -> Result<SemanticId, Box<dyn Error>> {
    Ok(semantic_id_of(SemanticHashDomain::RosterId, &roster.tbs)?)
}

fn capabilities(
    device_seed: u8,
    roster: &ArcDeviceRoster,
    network: [u8; 32],
) -> Result<ArcDeviceCapabilities, Box<dyn Error>> {
    let tbs = ArcDeviceCapabilitiesTbs {
        profile_version: 1,
        network_id: network,
        account_id: roster.tbs.account_id.clone(),
        root_fingerprint: roster.tbs.root_fingerprint,
        roster_generation: roster.tbs.roster_generation,
        roster_id: roster_id(roster)?,
        device_id: [device_seed; 16],
        capability_generation: 0,
        previous_capability_id: [0; 32],
        not_before: 100,
        not_after: 1_000,
        versions: TlsVec::new(vec![1])?,
        cipher_suites: TlsVec::new(vec![1u16, 3u16])?,
        extensions: TlsVec::new(vec![0xF1C1u16, 0xF1C3u16])?,
        proposals: TlsVec::new(vec![0xF1C2u16])?,
        credentials: TlsVec::new(vec![1u16])?,
    };
    Ok(ArcDeviceCapabilities {
        device_signature: sign(&key(device_seed), SignatureDomain::DeviceCapabilities, &tbs)?,
        tbs,
    })
}

fn leaf_authorization(
    device_seed: u8,
    roster: &ArcDeviceRoster,
    network: [u8; 32],
) -> Result<ArcLeafAuthorization, Box<dyn Error>> {
    let tbs = ArcLeafAuthorizationTbs {
        profile_version: 1,
        network_id: network,
        account_id: roster.tbs.account_id.clone(),
        root_generation: roster.tbs.root_generation,
        root_fingerprint: roster.tbs.root_fingerprint,
        roster_generation: roster.tbs.roster_generation,
        roster_id: roster_id(roster)?,
        device_id: [device_seed; 16],
        credential_generation: 0,
        mls_version: 1,
        cipher_suite: 1,
        leaf_signature_scheme: 0x0807,
        leaf_signature_key: Opaque::new(public(&key(200)).to_vec())?,
        leaf_capabilities_hash: [17; 32],
        package_nonce: [200; 32],
        last_resort: 0,
        not_before: 100,
        not_after: 900,
    };
    Ok(ArcLeafAuthorization {
        device_signature: sign(&key(device_seed), SignatureDomain::LeafAuthorization, &tbs)?,
        tbs,
    })
}

// ---------------------------------------------------------------- controls

#[test]
fn control_distinct_key_successor_is_accepted() -> TestResult {
    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let verified_first = verify_sequencer_credential(&NET_A, &first, None)?;
    let second = sequencer_credential(
        &key(61),
        1,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    assert!(verify_sequencer_credential(&NET_A, &second, Some(&verified_first)).is_ok());
    assert!(SequencerKeySet::verify(&NET_A, &[first, second], 1, None).is_ok());
    Ok(())
}

#[test]
fn control_valid_same_network_capability_and_leaf_are_accepted() -> TestResult {
    let root_secret = key(10);
    let root = root(&root_secret, NET_A)?;
    let verified_root = verify_root_identity(&NET_A, &root, None)?;
    let certificate = certificate(&root_secret, &root, 7, 0, (90, 100))?;
    let roster = roster(
        &root_secret,
        &root,
        0,
        [0; 32],
        (100, 900),
        vec![certificate],
    )?;
    let verified_roster = verify_roster(&verified_root, &roster, None)?;
    let statement = capabilities(7, &roster, NET_A)?;
    assert!(verify_capabilities(&verified_roster, &statement, None).is_ok());
    assert!(restore_capabilities(&verified_roster, &statement).is_ok());
    let leaf = leaf_authorization(7, &roster, NET_A)?;
    assert!(verify_leaf_authorization(&verified_roster, &leaf).is_ok());
    Ok(())
}

#[test]
fn control_current_target_certificate_outside_enrollment_window_is_refused() -> TestResult {
    let root_secret = key(10);
    let root = root(&root_secret, NET_A)?;
    let verified_root = verify_root_identity(&NET_A, &root, None)?;
    let certificate = certificate(&root_secret, &root, 7, 0, (90, 100))?;
    let roster = roster(
        &root_secret,
        &root,
        0,
        [0; 32],
        (500, 900),
        vec![certificate],
    )?;
    assert!(
        verify_roster(&verified_root, &roster, None).is_err(),
        "a current-target enrollment window must cover the roster's not_before"
    );
    Ok(())
}

// ------------------------------------------------------ counterexamples

#[test]
fn a_same_key_sequencer_successor_is_refused() -> TestResult {
    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let verified_first = verify_sequencer_credential(&NET_A, &first, None)?;
    // The successor reuses the predecessor's public key; that key signs its
    // continuity, so the signature verifies.
    let same = sequencer_credential(
        &first_secret,
        1,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    let anchored = verify_sequencer_credential(&NET_A, &same, Some(&verified_first));
    assert!(
        anchored.is_err(),
        "a successor reusing its predecessor's key was admitted: {anchored:?}"
    );
    Ok(())
}

#[test]
fn a_key_set_whose_successor_reuses_the_current_key_is_refused() -> TestResult {
    let first_secret = key(60);
    let first = sequencer_credential(&first_secret, 0, (0, 1_000_000), None)?;
    let same = sequencer_credential(
        &first_secret,
        1,
        (500_000, 2_000_000),
        Some((&first_secret, &first)),
    )?;
    assert!(
        SequencerKeySet::verify(&NET_A, &[first.clone(), same.clone()], 1, None).is_err(),
        "a two-credential set with one public key was admitted"
    );
    assert!(
        SequencerKeySet::verify_opened(&NET_A, &[first, same], 1).is_err(),
        "a credentials file set with one public key was admitted"
    );
    Ok(())
}
