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

/// A certificate of `seed` under the account's root enrolled for roster
/// generation `target`, with an enrollment interval around `issued_at`.
fn enrolled(
    account: &Account,
    seed: u8,
    target: u64,
    issued_at: u64,
) -> Result<ArcDeviceCertificate, Box<dyn Error>> {
    Ok(certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            target_roster_generation: target,
            enrollment: (issued_at.saturating_sub(5), issued_at.saturating_add(5)),
            ..DeviceSpec::new(seed)
        },
    )?)
}

/// The account's roster `generation` naming `previous`, starting at
/// `not_before`, over `certificates` in Device ID order.
fn signed_roster(
    account: &Account,
    generation: u64,
    previous: [u8; 32],
    not_before: u64,
    certificates: Vec<ArcDeviceCertificate>,
) -> Result<ArcDeviceRoster, Box<dyn Error>> {
    signed_roster_revoking(
        account,
        generation,
        previous,
        not_before,
        certificates,
        Vec::new(),
    )
}

/// [`signed_roster`] that also lists `revocations`, canonical.
fn signed_roster_revoking(
    account: &Account,
    generation: u64,
    previous: [u8; 32],
    not_before: u64,
    certificates: Vec<ArcDeviceCertificate>,
    revocations: Vec<ArcDeviceRevocation>,
) -> Result<ArcDeviceRoster, Box<dyn Error>> {
    Ok(roster(
        &account.root_secret,
        &account.root,
        generation,
        previous,
        (not_before, not_before + 1_000),
        certificates,
        revocations,
    )?)
}

/// The revocation of device `seed`'s certificate `serial` in `generation`.
fn revocation(seed: u8, serial: u64, generation: u64) -> ArcDeviceRevocation {
    ArcDeviceRevocation {
        device_id: [seed; 16],
        certificate_serial: serial,
        revoked_in_generation: generation,
        reason_code: 1,
    }
}

/// Companion 8.3: a certificate is issued in its target roster. One enrolled
/// for a later generation than the roster carrying it was never issued and
/// is refused on the checked, first-contact and restore paths alike.
#[test]
fn a_certificate_enrolled_for_a_later_generation_is_refused_on_every_path() -> TestResult {
    let account = account_with(&[7])?;
    let initial = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        vec![
            certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?,
            enrolled(&account, 8, 1, ROSTER_INTERVAL.0)?,
        ],
        Vec::new(),
    )?;
    let root = &account.verified_root;
    assert_eq!(
        verify_roster(root, &initial, None),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_first_contact_roster(root, &initial, &[]),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(restore_roster(root, &initial), Err(E2eeError::InvalidValue));
    let next = ROSTER_INTERVAL.1;
    let successor = signed_roster(
        &account,
        1,
        account.verified_roster.roster_id,
        next,
        vec![
            certificate(&account.root_secret, &account.root, &DeviceSpec::new(7))?,
            enrolled(&account, 8, 2, next)?,
        ],
    )?;
    assert_eq!(
        verify_roster(root, &successor, Some(&account.verified_roster)),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        verify_first_contact_roster(
            root,
            &successor,
            std::slice::from_ref(&account.verified_roster)
        ),
        Err(E2eeError::InvalidValue)
    );
    assert_eq!(
        restore_roster(root, &successor),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

/// On succession a certificate enrolled for an earlier generation must be
/// active, unchanged, in the predecessor: it keeps working after its short
/// enrollment interval, but a certificate never issued there, a replacement
/// under a reused Device ID that claims the old target generation, and a
/// revoked certificate coming back are refused. (A replacement enrolled for
/// the roster's own generation passes the interval rule; refusing a reused
/// Device ID, key or challenge is the endpoint's consumption check.)
#[test]
fn a_continuing_certificate_must_be_active_unchanged_in_the_predecessor() -> TestResult {
    let account = account_with(&[7, 8])?;
    let root = &account.verified_root;
    let gen0 = &account.verified_roster;
    let next = ROSTER_INTERVAL.1;
    let kept = |seed: u8| certificate(&account.root_secret, &account.root, &DeviceSpec::new(seed));
    // Devices 7 and 8 continue long after their enrollment interval (90, 100)
    // closed; device 9 is enrolled for generation one.
    let renewal = signed_roster(
        &account,
        1,
        gen0.roster_id,
        next,
        vec![kept(7)?, kept(8)?, enrolled(&account, 9, 1, next)?],
    )?;
    let gen1 = verify_roster(root, &renewal, Some(gen0))?;
    assert_eq!(gen1.devices.len(), 3);
    assert_eq!(restore_roster(root, &renewal)?, gen1);
    let refused = |certificates: Vec<ArcDeviceCertificate>| -> TestResult {
        let roster = signed_roster(&account, 1, gen0.roster_id, next, certificates)?;
        assert_eq!(
            verify_roster(root, &roster, Some(gen0)),
            Err(E2eeError::InvalidValue)
        );
        Ok(())
    };
    // A new device claiming an earlier target generation.
    refused(vec![kept(7)?, kept(8)?, enrolled(&account, 9, 0, next)?])?;
    // A different certificate for an active Device ID, claiming the old target.
    let replacement = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            serial: 2,
            ..DeviceSpec::new(8)
        },
    )?;
    refused(vec![kept(7)?, replacement])?;
    // Device 8 is dropped, so revoked, in generation one; its certificate
    // cannot return in generation two.
    let dropped = signed_roster(&account, 1, gen0.roster_id, next, vec![kept(7)?])?;
    let dropped = verify_roster(root, &dropped, Some(gen0))?;
    let returned = signed_roster(
        &account,
        2,
        dropped.roster_id,
        next + 1_000,
        vec![kept(7)?, kept(8)?],
    )?;
    assert_eq!(
        verify_roster(root, &returned, Some(&dropped)),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

/// First contact checks no predecessor, so a continuing certificate shows
/// its issuance in a supplied roster of the same root at exactly its target
/// generation, and the lineage shape still holds.
#[test]
fn first_contact_requires_the_issuance_of_every_continuing_certificate() -> TestResult {
    let account = account_with(&[7, 8])?;
    let root = &account.verified_root;
    let gen0 = account.verified_roster.clone();
    assert_eq!(
        verify_first_contact_roster(root, &account.roster, &[])?,
        gen0,
        "at generation zero first contact is the initial check"
    );
    let kept = |seed: u8| certificate(&account.root_secret, &account.root, &DeviceSpec::new(seed));
    let first = ROSTER_INTERVAL.1;
    let renewal = signed_roster(
        &account,
        1,
        gen0.roster_id,
        first,
        vec![kept(7)?, kept(8)?, enrolled(&account, 9, 1, first)?],
    )?;
    let gen1 = verify_roster(root, &renewal, Some(&gen0))?;
    assert_eq!(
        verify_first_contact_roster(root, &renewal, &[]),
        Err(E2eeError::InvalidValue),
        "devices 7 and 8 show no issuance"
    );
    assert_eq!(
        verify_first_contact_roster(root, &renewal, std::slice::from_ref(&gen0))?,
        gen1
    );
    let second = first + 1_000;
    let later = signed_roster(
        &account,
        2,
        gen1.roster_id,
        second,
        vec![
            kept(7)?,
            kept(8)?,
            enrolled(&account, 9, 1, first)?,
            enrolled(&account, 10, 2, second)?,
        ],
    )?;
    let gen2 = verify_roster(root, &later, Some(&gen1))?;
    for issuance in [
        vec![gen0.clone(), gen1.clone()],
        vec![gen1.clone(), gen0.clone()],
    ] {
        assert_eq!(verify_first_contact_roster(root, &later, &issuance)?, gen2);
    }
    assert_eq!(
        verify_first_contact_roster(root, &later, std::slice::from_ref(&gen0)),
        Err(E2eeError::InvalidValue),
        "device 9 was issued in generation one"
    );
    assert_eq!(
        verify_first_contact_roster(root, &later, std::slice::from_ref(&gen1)),
        Err(E2eeError::InvalidValue),
        "devices 7 and 8 were issued in generation zero, not one"
    );
    let mut foreign = gen0.clone();
    foreign.root_fingerprint = [9; 32];
    assert_eq!(
        verify_first_contact_roster(root, &later, &[foreign, gen1.clone()]),
        Err(E2eeError::InvalidValue),
        "issuance under another root"
    );
    // The target-generation roster must hold the exact certificate: one of
    // that root and generation without the device, or holding another
    // certificate for its Device ID, shows no issuance.
    let issued_without = |certificates: Vec<ArcDeviceCertificate>| -> TestResult {
        let other = roster(
            &account.root_secret,
            &account.root,
            0,
            [0; 32],
            ROSTER_INTERVAL,
            certificates,
            Vec::new(),
        )?;
        let other = verify_roster(root, &other, None)?;
        assert_eq!(
            verify_first_contact_roster(root, &later, &[other, gen1.clone()]),
            Err(E2eeError::InvalidValue),
            "device 8's certificate was not issued in that generation-zero roster"
        );
        Ok(())
    };
    issued_without(vec![kept(7)?])?;
    let replaced = certificate(
        &account.root_secret,
        &account.root,
        &DeviceSpec {
            serial: 2,
            ..DeviceSpec::new(8)
        },
    )?;
    issued_without(vec![kept(7)?, replaced])?;
    // The current-target enrollment rule applies unchanged.
    let late = signed_roster(
        &account,
        1,
        gen0.roster_id,
        first,
        vec![kept(7)?, kept(8)?, enrolled(&account, 9, 1, first + 100)?],
    )?;
    assert_eq!(
        verify_first_contact_roster(root, &late, std::slice::from_ref(&gen0)),
        Err(E2eeError::InvalidValue)
    );
    // Generation zero alone names the all-zero predecessor.
    let rootless = signed_roster(&account, 1, [0; 32], first, vec![kept(7)?, kept(8)?])?;
    assert_eq!(
        verify_first_contact_roster(root, &rootless, std::slice::from_ref(&gen0)),
        Err(E2eeError::InvalidValue)
    );
    let named = signed_roster(&account, 0, [3; 32], ROSTER_INTERVAL.0, vec![kept(7)?])?;
    assert_eq!(
        verify_first_contact_roster(root, &named, &[]),
        Err(E2eeError::InvalidValue)
    );
    Ok(())
}

/// Companion 8.4: `(Device ID, certificate_serial)` is unique and absence
/// from the active set means revoked, so no roster lists one certificate both
/// active and revoked. Every path refuses it, at generation zero and on
/// succession, where the predecessor's revocation is carried while the
/// certificate stays listed; revoking a certificate the roster no longer
/// lists is admitted.
#[test]
fn a_certificate_listed_active_and_revoked_is_refused_on_every_path() -> TestResult {
    let account = account_with(&[7, 8])?;
    let root = &account.verified_root;
    let gen0 = &account.verified_roster;
    let kept = |seed: u8| certificate(&account.root_secret, &account.root, &DeviceSpec::new(seed));
    let refused_everywhere =
        |roster: &ArcDeviceRoster, predecessor: Option<&VerifiedRoster>| -> TestResult {
            assert_eq!(
                verify_roster(root, roster, predecessor),
                Err(E2eeError::InvalidValue)
            );
            let issuance: Vec<VerifiedRoster> = predecessor.into_iter().cloned().collect();
            assert_eq!(
                verify_first_contact_roster(root, roster, &issuance),
                Err(E2eeError::InvalidValue)
            );
            assert_eq!(restore_roster(root, roster), Err(E2eeError::InvalidValue));
            Ok(())
        };
    let initial = roster(
        &account.root_secret,
        &account.root,
        0,
        [0; 32],
        ROSTER_INTERVAL,
        vec![kept(7)?, kept(8)?],
        vec![revocation(8, 1, 0)],
    )?;
    refused_everywhere(&initial, None)?;
    let next = ROSTER_INTERVAL.1;
    let carried = signed_roster_revoking(
        &account,
        1,
        gen0.roster_id,
        next,
        vec![kept(7)?, kept(8)?],
        vec![revocation(8, 1, 1)],
    )?;
    refused_everywhere(&carried, Some(gen0))?;
    let dropped = signed_roster_revoking(
        &account,
        1,
        gen0.roster_id,
        next,
        vec![kept(7)?],
        vec![revocation(8, 1, 1)],
    )?;
    let gen1 = verify_roster(root, &dropped, Some(gen0))?;
    assert_eq!(gen1.revocations, vec![([8; 16], 1)]);
    assert_eq!(
        verify_first_contact_roster(root, &dropped, std::slice::from_ref(gen0))?,
        gen1
    );
    assert_eq!(restore_roster(root, &dropped)?, gen1);
    Ok(())
}

/// First contact given `chain`, the complete chain from generation zero
/// below `roster` under its root, decides exactly as succession from the
/// chain's last roster does; returns that decision.
fn first_contact_as_succession(
    root: &VerifiedRoot,
    roster: &ArcDeviceRoster,
    chain: &[VerifiedRoster],
) -> Result<VerifiedRoster, E2eeError> {
    let checked = verify_roster(root, roster, chain.last());
    assert_eq!(
        verify_first_contact_roster(root, roster, chain),
        checked,
        "first contact agrees with succession"
    );
    checked
}

/// First contact holds a roster to every supplied roster of its root below
/// it, as succession holds it to its predecessor (companion 8.3 and 8.4): a
/// continuing certificate is listed, unchanged, by each one from its target
/// generation on; the one just below is the predecessor the roster names;
/// and every revocation they list is still listed. Given the complete chain
/// from generation zero under its root, first contact decides exactly as the
/// checked path does.
#[test]
fn first_contact_holds_a_roster_to_every_supplied_roster_of_its_root() -> TestResult {
    let account = account_with(&[7, 8])?;
    let root = &account.verified_root;
    let gen0 = account.verified_roster.clone();
    let kept = |seed: u8| certificate(&account.root_secret, &account.root, &DeviceSpec::new(seed));
    let first = ROSTER_INTERVAL.1;
    let second = first + 1_000;
    // Generation one drops device 8 without a revocation entry; generation
    // two lists its certificate again.
    let dropped = signed_roster(&account, 1, gen0.roster_id, first, vec![kept(7)?])?;
    let dropped = verify_roster(root, &dropped, Some(&gen0))?;
    let relisted = signed_roster(
        &account,
        2,
        dropped.roster_id,
        second,
        vec![kept(7)?, kept(8)?],
    )?;
    assert_eq!(
        first_contact_as_succession(root, &relisted, &[gen0.clone(), dropped.clone()]),
        Err(E2eeError::InvalidValue),
        "the roster between shows the certificate dropped"
    );
    assert!(
        verify_first_contact_roster(root, &relisted, std::slice::from_ref(&gen0)).is_ok(),
        "without the roster that dropped it nothing shows the drop: first contact \
         claims no complete history"
    );
    // Generation one revokes device 8's certificate. Listing it again in
    // generation two is refused whether the revocation is carried or not,
    // and so is dropping the revocation alone; carrying it is admitted.
    let revoked = signed_roster_revoking(
        &account,
        1,
        gen0.roster_id,
        first,
        vec![kept(7)?],
        vec![revocation(8, 1, 1)],
    )?;
    let revoked = verify_roster(root, &revoked, Some(&gen0))?;
    let chain = [gen0.clone(), revoked.clone()];
    for (certificates, revocations) in [
        (vec![kept(7)?, kept(8)?], vec![revocation(8, 1, 1)]),
        (vec![kept(7)?, kept(8)?], Vec::new()),
        (vec![kept(7)?], Vec::new()),
    ] {
        let next = signed_roster_revoking(
            &account,
            2,
            revoked.roster_id,
            second,
            certificates,
            revocations,
        )?;
        assert_eq!(
            first_contact_as_succession(root, &next, &chain),
            Err(E2eeError::InvalidValue)
        );
    }
    let carried = signed_roster_revoking(
        &account,
        2,
        revoked.roster_id,
        second,
        vec![kept(7)?],
        vec![revocation(8, 1, 1)],
    )?;
    assert_eq!(
        first_contact_as_succession(root, &carried, &chain)?.revocations,
        vec![([8; 16], 1)]
    );
    // A supplied generation-one roster that is not the predecessor the
    // roster names (another root-signed generation one) refuses it, though
    // it lists the same certificates.
    let gen1 = signed_roster(&account, 1, gen0.roster_id, first, vec![kept(7)?, kept(8)?])?;
    let gen1 = verify_roster(root, &gen1, Some(&gen0))?;
    let fork = signed_roster(
        &account,
        1,
        gen0.roster_id,
        first + 1,
        vec![kept(7)?, kept(8)?],
    )?;
    let fork = verify_roster(root, &fork, Some(&gen0))?;
    let gen2 = signed_roster(
        &account,
        2,
        gen1.roster_id,
        second,
        vec![kept(7)?, kept(8)?],
    )?;
    assert_eq!(
        first_contact_as_succession(root, &gen2, &[gen0.clone(), fork]),
        Err(E2eeError::InvalidValue)
    );
    let verified = first_contact_as_succession(root, &gen2, &[gen0.clone(), gen1.clone()])?;
    // A supplied roster of another root is not its history either, whatever
    // its generation, identifier and revocations.
    let mut foreign = gen1.clone();
    foreign.root_fingerprint = [9; 32];
    foreign.roster_id = [5; 32];
    foreign.revocations = vec![([8; 16], 1)];
    assert_eq!(
        verify_first_contact_roster(root, &gen2, &[gen0.clone(), gen1.clone(), foreign])?,
        verified
    );
    // A supplied roster at the roster's own generation is not its history:
    // another root-signed generation two that drops and revokes device 8 is
    // not consulted (comparing heads is the caller's PinnedHead).
    let other = signed_roster_revoking(
        &account,
        2,
        gen1.roster_id,
        second + 1,
        vec![kept(7)?],
        vec![revocation(8, 1, 2)],
    )?;
    let other = verify_roster(root, &other, Some(&gen1))?;
    assert_eq!(
        verify_first_contact_roster(root, &gen2, &[gen0, gen1, other])?,
        verified
    );
    Ok(())
}

/// First contact admits a capability statement of a device active in the
/// roster at any generation with no predecessor at hand, so an imported
/// nonzero head needs neither succession nor restore. Only the lineage shape
/// replaces the predecessor step, generation zero alone naming the all-zero
/// predecessor; every other rule of the checked path applies, and with the
/// predecessor the result equals the checked one.
#[test]
fn first_contact_admits_a_capability_head_at_any_generation() -> TestResult {
    let account = account_with(&[7])?;
    let roster = &account.verified_roster;
    let statement = |device: u8, generation: u64, previous: [u8; 32]| {
        capabilities(
            device,
            &account.roster,
            generation,
            previous,
            (100, 200),
            vec![1, 3],
        )
    };
    let genesis = statement(7, 0, [0; 32])?;
    let first = verify_capabilities(roster, &genesis, None)?;
    assert_eq!(verify_first_contact_capabilities(roster, &genesis)?, first);
    let next = statement(7, 1, first.capability_id)?;
    let checked = verify_capabilities(roster, &next, Some(&first))?;
    assert_eq!(
        verify_capabilities(roster, &next, None),
        Err(E2eeError::InvalidValue),
        "succession needs the predecessor"
    );
    assert_eq!(verify_first_contact_capabilities(roster, &next)?, checked);
    let later = statement(7, 5, [4; 32])?;
    assert_eq!(
        verify_first_contact_capabilities(roster, &later)?.generation,
        5
    );
    for (generation, previous) in [(1, [0; 32]), (0, [3; 32])] {
        assert_eq!(
            verify_first_contact_capabilities(roster, &statement(7, generation, previous)?),
            Err(E2eeError::InvalidValue),
            "generation zero, and only it, names the all-zero predecessor"
        );
    }
    assert_eq!(
        verify_first_contact_capabilities(roster, &statement(8, 1, first.capability_id)?),
        Err(E2eeError::InvalidValue),
        "a device the roster does not list"
    );
    let mut foreign = next.clone();
    foreign.tbs.network_id = [9; 32];
    foreign.device_signature = sign(&key(7), SignatureDomain::DeviceCapabilities, &foreign.tbs)?;
    assert_eq!(
        verify_first_contact_capabilities(roster, &foreign),
        Err(E2eeError::ProfileMismatch)
    );
    let mut forged = next;
    forged.device_signature = [1; 64];
    assert_eq!(
        verify_first_contact_capabilities(roster, &forged),
        Err(E2eeError::SignatureInvalid)
    );
    Ok(())
}

/// Companion 8.3: a certificate enrolled for the roster's own generation
/// needs an enrollment interval that covers the roster's `not_before`, both
/// ends inclusive, on the checked, first-contact and restore paths alike.
#[test]
fn the_current_target_enrollment_interval_includes_both_ends() -> TestResult {
    let account = account_with(&[7])?;
    let root = &account.verified_root;
    let not_before = ROSTER_INTERVAL.0;
    let decisions = |enrollment: (u64, u64)| -> Result<Vec<bool>, Box<dyn Error>> {
        let certificate = certificate(
            &account.root_secret,
            &account.root,
            &DeviceSpec {
                enrollment,
                ..DeviceSpec::new(7)
            },
        )?;
        let roster = roster(
            &account.root_secret,
            &account.root,
            0,
            [0; 32],
            ROSTER_INTERVAL,
            vec![certificate],
            Vec::new(),
        )?;
        Ok(vec![
            verify_roster(root, &roster, None).is_ok(),
            verify_first_contact_roster(root, &roster, &[]).is_ok(),
            restore_roster(root, &roster).is_ok(),
        ])
    };
    for (enrollment, admitted) in [
        ((not_before, not_before + 10), true),
        ((not_before - 10, not_before), true),
        ((not_before + 1, not_before + 11), false),
        ((not_before - 11, not_before - 1), false),
    ] {
        assert_eq!(decisions(enrollment)?, vec![admitted; 3], "{enrollment:?}");
    }
    Ok(())
}
