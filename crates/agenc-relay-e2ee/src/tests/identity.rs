#![forbid(unsafe_code)]

//! Identity chain validation: every positive path and one negative per rule.

use std::error::Error;

use agenc_relay_crypto::SignatureDomain;

use super::*;
use crate::ids::leaf_capabilities_digest;
use crate::mls_outer::{LAST_RESORT_EXTENSION_TYPE, MlsOuterMessage, parse_mls_message};
use crate::objects::identity::ArcDeviceRevocation;
use crate::test_support::*;
use crate::tls::{DecodeBudget, Opaque, TlsVec};

type TestResult = Result<(), Box<dyn Error>>;

const ROOT_INTERVAL: (u64, u64) = (0, 2_000_000);
const ROSTER_INTERVAL: (u64, u64) = (100, 100 + 6 * 24 * 3600);

struct Account {
    root_secret: agenc_relay_crypto::Ed25519SecretKey,
    root: ArcRootIdentity,
    verified_root: VerifiedRoot,
    roster: ArcDeviceRoster,
    verified_roster: VerifiedRoster,
}

fn account_with(device_seeds: &[u8]) -> Result<Account, Box<dyn Error>> {
    let root_secret = key(40);
    let root = root(&root_secret, &ACCOUNT, 0, ROOT_INTERVAL, None)?;
    let verified_root = verify_root_identity(&NETWORK, &root, None)?;
    let certificates = device_seeds
        .iter()
        .map(|seed| certificate(&root_secret, &root, &DeviceSpec::new(*seed)))
        .collect::<Result<Vec<_>, _>>()?;
    let roster = roster(
        &root_secret,
        &root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        certificates,
        Vec::new(),
    )?;
    let verified_roster = verify_roster(&verified_root, &roster, None)?;
    Ok(Account {
        root_secret,
        root,
        verified_root,
        roster,
        verified_roster,
    })
}

#[test]
fn a_root_chain_verifies_and_every_lineage_rule_holds() -> TestResult {
    let first_secret = key(1);
    let first = root(&first_secret, &ACCOUNT, 0, ROOT_INTERVAL, None)?;
    let second_secret = key(2);
    let second = root(
        &second_secret,
        &ACCOUNT,
        1,
        (500, 3_000_000),
        Some((&first_secret, &first)),
    )?;
    let chain = verify_root_chain(&NETWORK, &[first.clone(), second.clone()], None)?;
    assert_eq!(chain.len(), 2);
    assert_eq!(chain.get(1).map(|root| root.generation), Some(1));
    assert_eq!(
        chain.get(1).map(|root| root.fingerprint),
        Some(root_fingerprint(&second)?)
    );
    // Continuing from a pinned head.
    let head = chain.first().copied();
    assert_eq!(
        verify_root_chain(&NETWORK, std::slice::from_ref(&second), head.as_ref())?.len(),
        1
    );
    assert_eq!(
        verify_root_chain(&NETWORK, &[], None),
        Err(E2eeError::InvalidValue)
    );
    // Negatives.
    assert_eq!(
        verify_root_identity(&[9; 32], &first, None),
        Err(E2eeError::ProfileMismatch)
    );
    assert_eq!(
        verify_root_identity(&NETWORK, &second, None),
        Err(E2eeError::InvalidValue),
        "a successor without its predecessor"
    );
    let first_verified = verify_root_identity(&NETWORK, &first, None)?;
    assert_eq!(
        verify_root_identity(&NETWORK, &first, Some(&first_verified)),
        Err(E2eeError::InvalidValue),
        "generation zero after a predecessor"
    );
    let skipped = root(
        &key(3),
        &ACCOUNT,
        2,
        (600, 3_000_000),
        Some((&first_secret, &first)),
    )?;
    assert_eq!(
        verify_root_identity(&NETWORK, &skipped, Some(&first_verified)),
        Err(E2eeError::InvalidValue),
        "generation gap"
    );
    let early = root(
        &key(4),
        &ACCOUNT,
        1,
        (3_000_000, 4_000_000),
        Some((&first_secret, &first)),
    )?;
    assert_eq!(
        verify_root_identity(&NETWORK, &early, Some(&first_verified)),
        Err(E2eeError::InvalidValue),
        "not_before outside the predecessor interval"
    );
    let forged = root(
        &key(5),
        &ACCOUNT,
        1,
        (500, 3_000_000),
        Some((&key(6), &first)),
    )?;
    assert_eq!(
        verify_root_identity(&NETWORK, &forged, Some(&first_verified)),
        Err(E2eeError::SignatureInvalid),
        "continuity by the wrong key"
    );
    let mut tampered = first.clone();
    tampered.tbs.not_after = 5_000_000;
    assert_eq!(
        verify_root_identity(&NETWORK, &tampered, None),
        Err(E2eeError::SignatureInvalid)
    );
    let mut inverted = first.clone();
    inverted.tbs.not_before = inverted.tbs.not_after;
    assert_eq!(
        verify_root_identity(&NETWORK, &inverted, None),
        Err(E2eeError::InvalidValue)
    );
    let mut short_account = first;
    short_account.tbs.account_id = Opaque::from_slice(b"short")?;
    assert_eq!(
        verify_root_identity(&NETWORK, &short_account, None),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn a_device_certificate_binds_its_enrollment_exactly() -> TestResult {
    let account = account_with(&[7])?;
    let good = certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?;
    let verified = verify_device_certificate(&account.verified_root, &good)?;
    assert_eq!(verified.device_id, [7; 16]);
    assert!(verified.may_bind() && verified.may_approve_policy());
    assert_eq!(verified.serial, 1);

    let unknown_flag = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            flags: 4,
            ..DeviceSpec::new(7)
        },
    )?;
    assert_eq!(
        verify_device_certificate(&account.verified_root, &unknown_flag),
        Err(E2eeError::InvalidValue)
    );
    let long_window = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            enrollment: (0, 601),
            ..DeviceSpec::new(7)
        },
    )?;
    assert_eq!(
        verify_device_certificate(&account.verified_root, &long_window),
        Err(E2eeError::InvalidValue)
    );
    let beyond_root = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            interval: (0, ROOT_INTERVAL.1 + 1),
            ..DeviceSpec::new(7)
        },
    )?;
    assert_eq!(
        verify_device_certificate(&account.verified_root, &beyond_root),
        Err(E2eeError::InvalidValue)
    );
    let mut mismatched = good.clone();
    mismatched.tbs.certificate_serial = 2;
    assert_eq!(
        verify_device_certificate(&account.verified_root, &mismatched),
        Err(E2eeError::SignatureInvalid),
        "the root signature covers the serial"
    );
    let mut wrong_enrollment = good.clone();
    wrong_enrollment.enrollment_proof.tbs.issued_at = 91;
    assert_eq!(
        verify_device_certificate(&account.verified_root, &wrong_enrollment),
        Err(E2eeError::InvalidValue),
        "the enrollment id no longer matches"
    );
    let mut wrong_device_key = good.clone();
    wrong_device_key
        .enrollment_proof
        .tbs
        .device_authorization_key = [1; 32];
    assert_eq!(
        verify_device_certificate(&account.verified_root, &wrong_device_key),
        Err(E2eeError::InvalidValue),
        "enrollment and certificate disagree"
    );
    let mut bad_possession = good;
    bad_possession.enrollment_proof.new_device_signature = [0; 64];
    assert_eq!(
        verify_device_certificate(&account.verified_root, &bad_possession),
        Err(E2eeError::SignatureInvalid)
    );
    let other_root = root(&key(41), &OTHER_ACCOUNT, 0, ROOT_INTERVAL, None)?;
    let other_verified = verify_root_identity(&NETWORK, &other_root, None)?;
    let foreign = certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?;
    assert_eq!(
        verify_device_certificate(&other_verified, &foreign),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn a_roster_is_a_complete_canonical_active_set() -> TestResult {
    let account = account_with(&[7, 8])?;
    assert_eq!(account.verified_roster.devices.len(), 2);
    assert_eq!(account.verified_roster.generation, 0);
    assert!(account.verified_roster.usable_for_add(ValidationTime(200)));
    assert!(
        !account
            .verified_roster
            .usable_for_add(ValidationTime(100 + 25 * 3600))
    );
    assert!(!account.verified_roster.usable_for_add(ValidationTime(50)));

    let cert = |seed: u8| certificate(&account.root_secret, &account.root, &DeviceSpec::new(seed));
    let unsorted = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        vec![cert(8)?, cert(7)?],
        Vec::new(),
    )?;
    assert_eq!(
        verify_roster(&account.verified_root, &unsorted, None),
        Err(E2eeError::NonCanonical)
    );
    let mut shared_key = cert(9)?;
    shared_key.tbs.device_authorization_key = public(&key(7));
    let duplicate_key = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        vec![cert(7)?, shared_key],
        Vec::new(),
    )?;
    assert!(verify_roster(&account.verified_root, &duplicate_key, None).is_err());
    let mut renamed = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        vec![cert(7)?],
        Vec::new(),
    )?;
    // Outer Device ID must equal the certificate's; re-sign to isolate the rule.
    if let Some(entry) = renamed.tbs.active_devices.as_slice().first().cloned() {
        let mut moved = entry;
        moved.device_id = [99; 16];
        renamed.tbs.active_devices = TlsVec::new(vec![moved])?;
        renamed.root_signature = sign(
            &account.root_secret,
            SignatureDomain::DeviceRoster,
            &renamed.tbs,
        )?;
    }
    assert_eq!(
        verify_roster(&account.verified_root, &renamed, None),
        Err(E2eeError::InvalidValue)
    );
    let short_cert = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            interval: (0, 500),
            ..DeviceSpec::new(7)
        },
    )?;
    let uncovered = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        vec![short_cert],
        Vec::new(),
    )?;
    assert_eq!(
        verify_roster(&account.verified_root, &uncovered, None),
        Err(E2eeError::InvalidValue)
    );
    let outside_enrollment = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        (200, 300),
        vec![cert(7)?],
        Vec::new(),
    )?;
    assert_eq!(
        verify_roster(&account.verified_root, &outside_enrollment, None),
        Err(E2eeError::InvalidValue),
        "the target roster's not_before must lie inside the enrollment window"
    );
    let long_lived = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        (90, 90 + 8 * 24 * 3600),
        vec![cert(7)?],
        Vec::new(),
    )?;
    assert_eq!(
        verify_roster(&account.verified_root, &long_lived, None),
        Err(E2eeError::LimitExceeded)
    );
    let mut too_many = Vec::new();
    for seed in 0..65_u8 {
        too_many.push(certificate(
            &account.root_secret,
            &account.root,
            &DeviceSpec::new(seed.wrapping_add(120)),
        )?);
    }
    too_many.sort_by_key(|certificate| certificate.tbs.device_id);
    let oversize = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        too_many,
        Vec::new(),
    )?;
    assert_eq!(
        verify_roster(&account.verified_root, &oversize, None),
        Err(E2eeError::LimitExceeded)
    );
    let mut forged = account.roster.clone();
    forged.root_signature = [0; 64];
    assert_eq!(
        verify_roster(&account.verified_root, &forged, None),
        Err(E2eeError::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn roster_generations_chain_and_revocations_are_append_only() -> TestResult {
    let account = account_with(&[7, 8])?;
    let cert = |seed: u8, target: u64| {
        certificate(
            &account.root_secret,
            &account.root,
            &DeviceSpec {
                target_roster_generation: target,
                enrollment: (ROSTER_INTERVAL.1 - 5, ROSTER_INTERVAL.1 + 5),
                ..DeviceSpec::new(seed)
            },
        )
    };
    let revoked = ArcDeviceRevocation {
        device_id: [8; 16],
        certificate_serial: 1,
        revoked_in_generation: 1,
        reason_code: 1,
    };
    let successor = roster(
        &account.root_secret,
        &account.root,
        1,
        account.verified_roster.roster_id,
        (ROSTER_INTERVAL.1, ROSTER_INTERVAL.1 + 1_000),
        vec![
            certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?,
            cert(9, 1)?,
        ],
        vec![revoked.clone()],
    )?;
    let verified_successor = verify_roster(
        &account.verified_root,
        &successor,
        Some(&account.verified_roster),
    )?;
    assert_eq!(verified_successor.generation, 1);
    assert_eq!(verified_successor.revocations, vec![([8; 16], 1)]);
    assert!(verified_successor.device(&[8; 16]).is_none());
    assert!(verified_successor.device(&[9; 16]).is_some());
    assert_eq!(
        verify_roster(&account.verified_root, &successor, None),
        Err(E2eeError::InvalidValue),
        "a successor needs its predecessor"
    );
    let wrong_previous = roster(
        &account.root_secret,
        &account.root,
        1,
        [3; 32],
        (ROSTER_INTERVAL.1, ROSTER_INTERVAL.1 + 1_000),
        vec![certificate(
            &account.root_secret,
            &account.root,
            &DeviceSpec::new(7),
        )?],
        vec![revoked.clone()],
    )?;
    assert_eq!(
        verify_roster(
            &account.verified_root,
            &wrong_previous,
            Some(&account.verified_roster)
        ),
        Err(E2eeError::InvalidValue)
    );
    let dropped_revocation = roster(
        &account.root_secret,
        &account.root,
        2,
        verified_successor.roster_id,
        (ROSTER_INTERVAL.1 + 1_000, ROSTER_INTERVAL.1 + 2_000),
        vec![certificate(
            &account.root_secret,
            &account.root,
            &DeviceSpec::new(7),
        )?],
        Vec::new(),
    )?;
    assert_eq!(
        verify_roster(
            &account.verified_root,
            &dropped_revocation,
            Some(&verified_successor)
        ),
        Err(E2eeError::InvalidValue)
    );
    let unsorted_revocations = roster(
        &account.root_secret,
        &account.root,
        1,
        account.verified_roster.roster_id,
        (ROSTER_INTERVAL.1, ROSTER_INTERVAL.1 + 1_000),
        vec![certificate(
            &account.root_secret,
            &account.root,
            &DeviceSpec::new(7),
        )?],
        vec![
            ArcDeviceRevocation {
                device_id: [9; 16],
                certificate_serial: 1,
                revoked_in_generation: 1,
                reason_code: 1,
            },
            revoked,
        ],
    )?;
    assert_eq!(
        verify_roster(
            &account.verified_root,
            &unsorted_revocations,
            Some(&account.verified_roster)
        ),
        Err(E2eeError::NonCanonical)
    );
    // Cross-root key distinctness.
    let other_secret = key(41);
    let other_root = root(&other_secret, &OTHER_ACCOUNT, 0, ROOT_INTERVAL, None)?;
    let other_verified = verify_root_identity(&NETWORK, &other_root, None)?;
    let other_roster = roster(
        &other_secret,
        &other_root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        vec![certificate(
            &other_secret,
            &other_root,
            &DeviceSpec::new(7),
        )?],
        Vec::new(),
    )?;
    let other_verified_roster = verify_roster(&other_verified, &other_roster, None)?;
    assert_eq!(
        ensure_distinct_device_keys([&account.verified_roster, &other_verified_roster]),
        Err(E2eeError::InvalidValue),
        "device seed 7 is shared across accounts"
    );
    assert_eq!(
        ensure_distinct_device_keys([&account.verified_roster]),
        Ok(())
    );
    Ok(())
}

#[test]
fn capability_statements_are_device_signed_canonical_and_chained() -> TestResult {
    let account = account_with(&[7])?;
    let statement = capabilities(7, &account.roster, 0, [0; 32], (100, 200), vec![1, 3])?;
    let verified = verify_capabilities(&account.verified_roster, &statement, None)?;
    assert_eq!(verified.cipher_suites, vec![1, 3]);
    let next = capabilities(
        7,
        &account.roster,
        1,
        verified.capability_id,
        (150, 250),
        vec![1],
    )?;
    let verified_next = verify_capabilities(&account.verified_roster, &next, Some(&verified))?;
    assert_eq!(verified_next.generation, 1);
    assert_eq!(
        verify_capabilities(&account.verified_roster, &next, None),
        Err(E2eeError::InvalidValue)
    );
    let skipped = capabilities(
        7,
        &account.roster,
        3,
        verified.capability_id,
        (150, 250),
        vec![1],
    )?;
    assert_eq!(
        verify_capabilities(&account.verified_roster, &skipped, Some(&verified)),
        Err(E2eeError::InvalidValue)
    );
    let unsorted = capabilities(7, &account.roster, 0, [0; 32], (100, 200), vec![3, 1])?;
    assert_eq!(
        verify_capabilities(&account.verified_roster, &unsorted, None),
        Err(E2eeError::NonCanonical)
    );
    let duplicate = capabilities(7, &account.roster, 0, [0; 32], (100, 200), vec![1, 1])?;
    assert_eq!(
        verify_capabilities(&account.verified_roster, &duplicate, None),
        Err(E2eeError::NonCanonical)
    );
    let inactive = capabilities(8, &account.roster, 0, [0; 32], (100, 200), vec![1])?;
    assert_eq!(
        verify_capabilities(&account.verified_roster, &inactive, None),
        Err(E2eeError::InvalidValue)
    );
    let long_lived = capabilities(
        7,
        &account.roster,
        0,
        [0; 32],
        (100, 100 + 8 * 24 * 3600),
        vec![1],
    )?;
    assert_eq!(
        verify_capabilities(&account.verified_roster, &long_lived, None),
        Err(E2eeError::LimitExceeded)
    );
    let mut wrong_roster = statement.clone();
    wrong_roster.tbs.roster_id = [5; 32];
    assert_eq!(
        verify_capabilities(&account.verified_roster, &wrong_roster, None),
        Err(E2eeError::InvalidValue)
    );
    let mut forged = statement;
    forged.device_signature = [1; 64];
    assert_eq!(
        verify_capabilities(&account.verified_roster, &forged, None),
        Err(E2eeError::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn leaf_authorizations_are_bounded_and_covered() -> TestResult {
    let account = account_with(&[7])?;
    let good = leaf_authorization(&account.roster, &LeafSpec::new(7, 30))?;
    let verified = verify_leaf_authorization(&account.verified_roster, &good)?;
    assert_eq!(verified.leaf_signature_key, public(&key(30)).to_vec());
    assert_eq!(verified.cipher_suite, 1);
    for (label, spec, expected) in [
        (
            "last resort",
            LeafSpec {
                last_resort: 1,
                ..LeafSpec::new(7, 30)
            },
            E2eeError::InvalidValue,
        ),
        (
            "credential generation",
            LeafSpec {
                credential_generation: 1,
                ..LeafSpec::new(7, 30)
            },
            E2eeError::InvalidValue,
        ),
        (
            "disabled suite",
            LeafSpec {
                suite: 4,
                ..LeafSpec::new(7, 30)
            },
            E2eeError::ProfileMismatch,
        ),
        (
            "lifetime too long",
            LeafSpec {
                interval: (100, 100 + 8 * 24 * 3600),
                ..LeafSpec::new(7, 30)
            },
            E2eeError::LimitExceeded,
        ),
        (
            "outside the roster",
            LeafSpec {
                interval: (10, 1_000),
                ..LeafSpec::new(7, 30)
            },
            E2eeError::InvalidValue,
        ),
        (
            "inactive device",
            LeafSpec::new(8, 30),
            E2eeError::InvalidValue,
        ),
    ] {
        let authorization = leaf_authorization(&account.roster, &spec)?;
        assert_eq!(
            verify_leaf_authorization(&account.verified_roster, &authorization),
            Err(expected),
            "{label}"
        );
    }
    let mut short_key = good.clone();
    short_key.tbs.leaf_signature_key = Opaque::new(vec![1; 31])?;
    assert_eq!(
        verify_leaf_authorization(&account.verified_roster, &short_key),
        Err(E2eeError::InvalidValue)
    );
    let mut forged = good;
    forged.device_signature = [0; 64];
    assert_eq!(
        verify_leaf_authorization(&account.verified_roster, &forged),
        Err(E2eeError::SignatureInvalid)
    );
    Ok(())
}

fn bundle(
    account: &Account,
    leaf_seed: u8,
    capabilities_hash: [u8; 32],
) -> Result<ArcCredentialBundle, Box<dyn Error>> {
    Ok(ArcCredentialBundle {
        root: account.root.clone(),
        device_certificate: certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?,
        leaf_authorization: leaf_authorization(
            &account.roster,
            &LeafSpec {
                capabilities_hash,
                ..LeafSpec::new(7, leaf_seed)
            },
        )?,
    })
}

#[test]
fn a_credential_bundle_names_one_client_and_agrees_with_its_key_package() -> TestResult {
    let account = account_with(&[7])?;
    let capability_vectors = default_capabilities();
    let capabilities_hash = leaf_capabilities_digest(&encoded_capabilities(&capability_vectors)?)?;
    let credential = bundle(&account, 30, capabilities_hash)?;
    let verified = verify_credential_bundle(&NETWORK, &account.verified_roster, &credential)?;
    assert_eq!(verified.client.device_id, [7; 16]);
    assert_eq!(verified.client.account_id, ACCOUNT);
    assert!(verified.client.same_client(&verified.client, |_, _| false));
    let identity = credential.encode()?;
    let package_bytes = key_package(&KeyPackageSpec {
        identity: &identity,
        leaf_seed: 30,
        suite: 1,
        lifetime: (100, 1_000),
        capabilities: capability_vectors.clone(),
        leaf_extensions: Vec::new(),
    })?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let MlsOuterMessage::KeyPackage(package) = parse_mls_message(&package_bytes, &mut budget)?
    else {
        return Err("expected a key package".into());
    };
    let from_package = verify_key_package_credential(&NETWORK, &account.verified_roster, &package)?;
    assert_eq!(from_package, verified);

    // Every disagreement between the leaf and its authorization is refused.
    let cases: Vec<(&str, KeyPackageSpec<'_>)> = vec![
        (
            "leaf key",
            KeyPackageSpec {
                identity: &identity,
                leaf_seed: 31,
                suite: 1,
                lifetime: (100, 1_000),
                capabilities: capability_vectors.clone(),
                leaf_extensions: Vec::new(),
            },
        ),
        (
            "lifetime",
            KeyPackageSpec {
                identity: &identity,
                leaf_seed: 30,
                suite: 1,
                lifetime: (100, 999),
                capabilities: capability_vectors.clone(),
                leaf_extensions: Vec::new(),
            },
        ),
        (
            "lifetime start",
            KeyPackageSpec {
                identity: &identity,
                leaf_seed: 30,
                suite: 1,
                lifetime: (101, 1_000),
                capabilities: capability_vectors.clone(),
                leaf_extensions: Vec::new(),
            },
        ),
        (
            "suite",
            KeyPackageSpec {
                identity: &identity,
                leaf_seed: 30,
                suite: 3,
                lifetime: (100, 1_000),
                capabilities: capability_vectors.clone(),
                leaf_extensions: Vec::new(),
            },
        ),
        (
            "capabilities hash",
            KeyPackageSpec {
                identity: &identity,
                leaf_seed: 30,
                suite: 1,
                lifetime: (100, 1_000),
                capabilities: vec![vec![0, 1], vec![0, 1], Vec::new(), Vec::new(), vec![0, 1]],
                leaf_extensions: Vec::new(),
            },
        ),
        (
            "last resort extension",
            KeyPackageSpec {
                identity: &identity,
                leaf_seed: 30,
                suite: 1,
                lifetime: (100, 1_000),
                capabilities: capability_vectors.clone(),
                leaf_extensions: vec![(LAST_RESORT_EXTENSION_TYPE, Vec::new())],
            },
        ),
    ];
    for (label, spec) in cases {
        let bytes = key_package(&spec)?;
        let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
        let MlsOuterMessage::KeyPackage(package) = parse_mls_message(&bytes, &mut budget)? else {
            return Err("expected a key package".into());
        };
        assert_eq!(
            verify_key_package_credential(&NETWORK, &account.verified_roster, &package),
            Err(E2eeError::InvalidValue),
            "{label}"
        );
    }
    // A bundle whose certificate is not the roster's active one.
    let mut stale = credential.clone();
    stale.device_certificate = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            serial: 2,
            ..DeviceSpec::new(7)
        },
    )?;
    assert_eq!(
        verify_credential_bundle(&NETWORK, &account.verified_roster, &stale),
        Err(E2eeError::InvalidValue)
    );
    // A bundle whose root is not the roster's root.
    let other = account_with(&[7])?;
    let mut foreign = credential;
    foreign.root = root(&key(42), &ACCOUNT, 0, ROOT_INTERVAL, None)?;
    assert_eq!(
        verify_credential_bundle(&NETWORK, &other.verified_roster, &foreign),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn standalone_roots_keep_their_shape_rules() -> TestResult {
    let secret = key(1);
    let first = root(&secret, &ACCOUNT, 0, ROOT_INTERVAL, None)?;
    assert!(verify_root_standalone(&NETWORK, &first).is_ok());
    let second = root(
        &key(2),
        &ACCOUNT,
        1,
        (500, 3_000_000),
        Some((&secret, &first)),
    )?;
    assert_eq!(verify_root_standalone(&NETWORK, &second)?.generation, 1);
    let mut half = second;
    half.continuity_signature = Opaque::new(Vec::new())?;
    assert_eq!(
        verify_root_standalone(&NETWORK, &half),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_root_standalone(&[2; 32], &first),
        Err(E2eeError::ProfileMismatch)
    );
    Ok(())
}

#[test]
fn pinned_heads_classify_every_observation() -> TestResult {
    let account = account_with(&[7])?;
    let mut heads = AccountHeads::new();
    assert_eq!(
        heads.observe_root(&account.verified_root),
        HeadObservation::Advanced
    );
    assert_eq!(
        heads.observe_root(&account.verified_root),
        HeadObservation::Same
    );
    assert_eq!(
        heads.observe_roster(&account.verified_roster),
        HeadObservation::Advanced
    );
    let mut equivocal = account.verified_roster.clone();
    equivocal.roster_id = [9; 32];
    assert_eq!(
        heads.observe_roster(&equivocal),
        HeadObservation::Equivocation
    );
    let mut gapped = account.verified_roster.clone();
    gapped.generation = 5;
    assert_eq!(heads.observe_roster(&gapped), HeadObservation::Gap);
    let mut next = account.verified_roster.clone();
    next.generation = 1;
    next.roster_id = [2; 32];
    assert_eq!(heads.observe_roster(&next), HeadObservation::Advanced);
    assert_eq!(
        heads.observe_roster(&account.verified_roster),
        HeadObservation::Rollback
    );
    assert_eq!(
        heads.roster_head(&account.verified_root.fingerprint),
        Some(PinnedHead {
            generation: 1,
            id: [2; 32]
        })
    );
    assert_eq!(
        heads.root_head(&ACCOUNT).map(|head| head.generation),
        Some(0)
    );
    let statement = capabilities(7, &account.roster, 0, [0; 32], (100, 200), vec![1])?;
    let verified = verify_capabilities(&account.verified_roster, &statement, None)?;
    assert_eq!(
        heads.observe_capabilities(account.verified_root.fingerprint, &verified),
        HeadObservation::Advanced
    );
    assert_eq!(
        heads.observe_binding_lock(account.verified_root.fingerprint, 0, [4; 32]),
        HeadObservation::Advanced
    );
    assert_eq!(
        heads.observe_binding_lock(account.verified_root.fingerprint, 0, [5; 32]),
        HeadObservation::Equivocation
    );
    let same = ClientIdentity {
        network_id: NETWORK,
        account_id: ACCOUNT,
        root_fingerprint: [1; 32],
        device_id: [7; 16],
    };
    let rotated = ClientIdentity {
        root_fingerprint: [2; 32],
        ..same
    };
    assert!(!same.same_client(&rotated, |_, _| false));
    assert!(same.same_client(&rotated, |_, _| true));
    let other_device = ClientIdentity {
        device_id: [8; 16],
        ..same
    };
    assert!(!same.same_client(&other_device, |_, _| true));
    Ok(())
}

#[test]
fn root_identities_are_checked_before_and_after_their_signatures() -> TestResult {
    let secret = key(50);
    let first_secret = key(51);
    let mut mismatched = root(&secret, &ACCOUNT, 0, ROOT_INTERVAL, None)?;
    mismatched.tbs.profile_version = 2;
    assert_eq!(
        verify_root_identity(&NETWORK, &mismatched, None),
        Err(E2eeError::ProfileMismatch)
    );
    assert_eq!(
        verify_root_standalone(&NETWORK, &mismatched),
        Err(E2eeError::ProfileMismatch)
    );
    let first = root(&first_secret, &ACCOUNT, 0, ROOT_INTERVAL, None)?;
    let zero_with_predecessor = root(
        &secret,
        &ACCOUNT,
        0,
        ROOT_INTERVAL,
        Some((&first_secret, &first)),
    )?;
    assert_eq!(
        verify_root_identity(&NETWORK, &zero_with_predecessor, None),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_root_standalone(&NETWORK, &zero_with_predecessor),
        Err(E2eeError::InvalidValue)
    );
    let mut stray = root(&secret, &ACCOUNT, 0, ROOT_INTERVAL, None)?;
    stray.continuity_signature = Opaque::new(vec![7; 64])?;
    assert_eq!(
        verify_root_identity(&NETWORK, &stray, None),
        Err(E2eeError::InvalidValue)
    );
    let first_verified = verify_root_identity(&NETWORK, &first, None)?;
    let other = root(&key(52), &ACCOUNT, 0, ROOT_INTERVAL, None)?;
    let other_verified = verify_root_identity(&NETWORK, &other, None)?;
    let second = root(
        &secret,
        &ACCOUNT,
        1,
        (500, 3_000_000),
        Some((&first_secret, &first)),
    )?;
    assert_eq!(
        verify_root_identity(&NETWORK, &second, Some(&other_verified)),
        Err(E2eeError::InvalidValue),
        "the predecessor fingerprint differs"
    );
    let foreign = root(
        &secret,
        &OTHER_ACCOUNT,
        1,
        (500, 3_000_000),
        Some((&first_secret, &first)),
    )?;
    assert_eq!(
        verify_root_identity(&NETWORK, &foreign, Some(&first_verified)),
        Err(E2eeError::InvalidValue),
        "the predecessor belongs to another account"
    );
    Ok(())
}

#[test]
fn a_device_certificate_is_checked_field_by_field_against_its_root_and_enrollment() -> TestResult {
    let account = account_with(&[7])?;
    let good = certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?;
    let verify = |certificate: &ArcDeviceCertificate| {
        verify_device_certificate(&account.verified_root, certificate).err()
    };
    let mut profile = good.clone();
    profile.tbs.profile_version = 2;
    assert_eq!(verify(&profile), Some(E2eeError::ProfileMismatch));
    let mut enrollment_profile = good.clone();
    enrollment_profile.enrollment_proof.tbs.profile_version = 2;
    assert_eq!(
        verify(&enrollment_profile),
        Some(E2eeError::ProfileMismatch)
    );
    let mut network = good.clone();
    network.tbs.network_id = [9; 32];
    assert_eq!(verify(&network), Some(E2eeError::InvalidValue));
    let mut generation = good.clone();
    generation.tbs.root_generation = 5;
    assert_eq!(verify(&generation), Some(E2eeError::InvalidValue));

    type Corrupt = fn(&mut ArcDeviceEnrollmentTbs) -> Result<(), E2eeError>;
    let corruptions: [Corrupt; 7] = [
        |tbs| {
            tbs.network_id = [9; 32];
            Ok(())
        },
        |tbs| {
            tbs.account_id = account_field(&OTHER_ACCOUNT)?;
            Ok(())
        },
        |tbs| {
            tbs.root_generation = 5;
            Ok(())
        },
        |tbs| {
            tbs.root_fingerprint = [9; 32];
            Ok(())
        },
        |tbs| {
            tbs.target_roster_generation = 5;
            Ok(())
        },
        |tbs| {
            tbs.enrollment_challenge = [9; 32];
            Ok(())
        },
        |tbs| {
            tbs.device_id = [9; 16];
            Ok(())
        },
    ];
    for corrupt in corruptions {
        let mut certificate = good.clone();
        corrupt(&mut certificate.enrollment_proof.tbs)?;
        assert_eq!(verify(&certificate), Some(E2eeError::InvalidValue));
    }
    let reversed_window = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            enrollment: (100, 90),
            ..DeviceSpec::new(7)
        },
    )?;
    assert_eq!(verify(&reversed_window), Some(E2eeError::InvalidValue));
    let reversed_interval = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            interval: (500, 400),
            ..DeviceSpec::new(7)
        },
    )?;
    assert_eq!(verify(&reversed_interval), Some(E2eeError::InvalidValue));
    Ok(())
}

#[test]
fn a_roster_is_checked_against_its_root_keys_windows_and_lineage() -> TestResult {
    let account = account_with(&[7])?;
    let verify =
        |roster: &ArcDeviceRoster| verify_roster(&account.verified_root, roster, None).err();
    let mut profile = account.roster.clone();
    profile.tbs.profile_version = 2;
    assert_eq!(verify(&profile), Some(E2eeError::ProfileMismatch));
    let mut network = account.roster.clone();
    network.tbs.network_id = [9; 32];
    assert_eq!(verify(&network), Some(E2eeError::InvalidValue));
    let mut generation = account.roster.clone();
    generation.tbs.root_generation = 5;
    assert_eq!(verify(&generation), Some(E2eeError::InvalidValue));

    let shared_key = vec![
        certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?,
        certificate(
            &account.root_secret,
            &account.root,
            &DeviceSpec {
                device_id: [8; 16],
                ..DeviceSpec::new(7)
            },
        )?,
    ];
    let duplicate_keys = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        shared_key,
        Vec::new(),
    )?;
    assert_eq!(verify(&duplicate_keys), Some(E2eeError::InvalidValue));

    let late_enrollment = vec![certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            enrollment: (1_000, 1_100),
            ..DeviceSpec::new(7)
        },
    )?];
    let outside_window = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        late_enrollment,
        Vec::new(),
    )?;
    assert_eq!(verify(&outside_window), Some(E2eeError::InvalidValue));

    let first_with_predecessor = roster(
        &account.root_secret,
        &account.root,
        0,
        [1; 32],
        ROSTER_INTERVAL,
        vec![certificate(
            &account.root_secret,
            &account.root,
            &DeviceSpec::new(7),
        )?],
        Vec::new(),
    )?;
    assert_eq!(
        verify(&first_with_predecessor),
        Some(E2eeError::InvalidValue)
    );
    Ok(())
}

#[test]
fn capability_statements_are_checked_against_their_roster_and_device_lineage() -> TestResult {
    let account = account_with(&[7, 8])?;
    let good = capabilities(7, &account.roster, 0, [0; 32], (100, 1_000), vec![1])?;
    let verify = |capabilities: &ArcDeviceCapabilities,
                  predecessor: Option<&VerifiedCapabilities>| {
        verify_capabilities(&account.verified_roster, capabilities, predecessor).err()
    };
    let mut profile = good.clone();
    profile.tbs.profile_version = 2;
    assert_eq!(verify(&profile, None), Some(E2eeError::ProfileMismatch));
    let mut foreign = good.clone();
    foreign.tbs.account_id = account_field(&OTHER_ACCOUNT)?;
    assert_eq!(verify(&foreign, None), Some(E2eeError::InvalidValue));
    let mut fingerprint = good.clone();
    fingerprint.tbs.root_fingerprint = [9; 32];
    assert_eq!(verify(&fingerprint, None), Some(E2eeError::InvalidValue));
    let mut generation = good.clone();
    generation.tbs.roster_generation = 5;
    assert_eq!(verify(&generation, None), Some(E2eeError::InvalidValue));

    let first_with_predecessor =
        capabilities(7, &account.roster, 0, [1; 32], (100, 1_000), vec![1])?;
    assert_eq!(
        verify(&first_with_predecessor, None),
        Some(E2eeError::InvalidValue)
    );
    let verified_good = verify_capabilities(&account.verified_roster, &good, None)?;
    let other_device = capabilities(8, &account.roster, 0, [0; 32], (100, 1_000), vec![1])?;
    let verified_other = verify_capabilities(&account.verified_roster, &other_device, None)?;
    let successor = capabilities(
        7,
        &account.roster,
        1,
        verified_good.capability_id,
        (100, 1_000),
        vec![1],
    )?;
    assert_eq!(
        verify(&successor, Some(&verified_other)),
        Some(E2eeError::InvalidValue),
        "the predecessor belongs to another device"
    );
    let wrong_predecessor = capabilities(7, &account.roster, 1, [1; 32], (100, 1_000), vec![1])?;
    assert_eq!(
        verify(&wrong_predecessor, Some(&verified_good)),
        Some(E2eeError::InvalidValue)
    );
    assert!(verify(&successor, Some(&verified_good)).is_none());
    Ok(())
}

#[test]
fn leaf_authorizations_and_bundles_are_checked_against_their_roster() -> TestResult {
    let account = account_with(&[7, 8])?;
    let good = leaf_authorization(&account.roster, &LeafSpec::new(7, 9))?;
    let verify = |leaf: &ArcLeafAuthorization| {
        verify_leaf_authorization(&account.verified_roster, leaf).err()
    };
    let mut profile = good.clone();
    profile.tbs.profile_version = 2;
    assert_eq!(verify(&profile), Some(E2eeError::ProfileMismatch));
    let mut mls = good.clone();
    mls.tbs.mls_version = 2;
    assert_eq!(verify(&mls), Some(E2eeError::ProfileMismatch));
    let mut foreign = good.clone();
    foreign.tbs.account_id = account_field(&OTHER_ACCOUNT)?;
    assert_eq!(verify(&foreign), Some(E2eeError::InvalidValue));
    let mut generation = good.clone();
    generation.tbs.root_generation = 5;
    assert_eq!(verify(&generation), Some(E2eeError::InvalidValue));
    let beyond_certificate = leaf_authorization(
        &account.roster,
        &LeafSpec {
            interval: (999_990, 1_000_010),
            ..LeafSpec::new(7, 9)
        },
    )?;
    assert_eq!(verify(&beyond_certificate), Some(E2eeError::InvalidValue));

    let mismatched = ArcCredentialBundle {
        root: account.root.clone(),
        device_certificate: certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?,
        leaf_authorization: leaf_authorization(&account.roster, &LeafSpec::new(8, 9))?,
    };
    assert_eq!(
        verify_credential_bundle(&NETWORK, &account.verified_roster, &mismatched),
        Err(E2eeError::InvalidValue)
    );

    let client = ClientIdentity {
        network_id: NETWORK,
        account_id: account.verified_root.account_id,
        root_fingerprint: account.verified_root.fingerprint,
        device_id: [7; 16],
    };
    let never = |_: &SemanticId, _: &SemanticId| false;
    assert!(client.same_client(&client, never));
    let other_network = ClientIdentity {
        network_id: [9; 32],
        ..client
    };
    assert!(!client.same_client(&other_network, never));
    let other_account = ClientIdentity {
        account_id: account_id_bytes(&account_field(&OTHER_ACCOUNT)?)?,
        ..client
    };
    assert!(!client.same_client(&other_account, never));
    Ok(())
}

/// Capability statements and leaf authorizations sign their own
/// `network_id`. A correctly signed statement for another network is
/// refused under this network's roster on the checked and the restored
/// path, and a credential bundle inherits the leaf refusal.
#[test]
fn statements_signed_for_another_network_are_refused_under_this_roster() -> TestResult {
    let account = account_with(&[7])?;
    assert_eq!(account.verified_roster.network_id, NETWORK);
    let resigned_statement = |network: [u8; 32]| -> Result<ArcDeviceCapabilities, Box<dyn Error>> {
        let mut statement = capabilities(7, &account.roster, 0, [0; 32], (100, 1_000), vec![1])?;
        statement.tbs.network_id = network;
        statement.device_signature =
            sign(&key(7), SignatureDomain::DeviceCapabilities, &statement.tbs)?;
        Ok(statement)
    };
    let foreign = resigned_statement([9; 32])?;
    assert_eq!(
        verify_capabilities(&account.verified_roster, &foreign, None),
        Err(E2eeError::ProfileMismatch)
    );
    assert_eq!(
        restore_capabilities(&account.verified_roster, &foreign),
        Err(E2eeError::ProfileMismatch)
    );
    let own = resigned_statement(NETWORK)?;
    assert!(verify_capabilities(&account.verified_roster, &own, None).is_ok());
    assert!(restore_capabilities(&account.verified_roster, &own).is_ok());

    let resigned_leaf = |network: [u8; 32]| -> Result<ArcLeafAuthorization, Box<dyn Error>> {
        let mut leaf = leaf_authorization(&account.roster, &LeafSpec::new(7, 30))?;
        leaf.tbs.network_id = network;
        leaf.device_signature = sign(&key(7), SignatureDomain::LeafAuthorization, &leaf.tbs)?;
        Ok(leaf)
    };
    let foreign_leaf = resigned_leaf([9; 32])?;
    assert_eq!(
        verify_leaf_authorization(&account.verified_roster, &foreign_leaf),
        Err(E2eeError::ProfileMismatch)
    );
    let bundle =
        |leaf_authorization: ArcLeafAuthorization| -> Result<ArcCredentialBundle, Box<dyn Error>> {
            Ok(ArcCredentialBundle {
                root: account.root.clone(),
                device_certificate: certificate(
                    &account.root_secret,
                    &account.root,
                    &DeviceSpec::new(7),
                )?,
                leaf_authorization,
            })
        };
    assert_eq!(
        verify_credential_bundle(&NETWORK, &account.verified_roster, &bundle(foreign_leaf)?),
        Err(E2eeError::ProfileMismatch),
        "the bundle inherits the leaf refusal"
    );
    let own_leaf = resigned_leaf(NETWORK)?;
    assert!(verify_leaf_authorization(&account.verified_roster, &own_leaf).is_ok());
    assert!(
        verify_credential_bundle(&NETWORK, &account.verified_roster, &bundle(own_leaf)?).is_ok()
    );
    Ok(())
}
