#![forbid(unsafe_code)]

//! Directory objects bind to the origin that publishes them: a root or roster names the
//! origin's account, capabilities and KeyPackages name the attached device and its suite,
//! and an attach answers the exact challenge the coordinator signed.

use super::*;
use agenc_relay_e2ee::mls_outer::LAST_RESORT_EXTENSION_TYPE;

const OTHER_DEVICE: u8 = 8;

#[test]
fn a_root_or_roster_for_another_account_is_refused() -> TestResult {
    let mut harness = Harness::new()?;
    let stranger = principal(41, &account_bytes(10)?, &[9])?;
    let root = wire(ArcWireObjectKind::RootIdentity, &stranger.root)?;
    assert_eq!(
        code(harness.run(Op::PublishIdentity, &[], Some(&root))?),
        Some(E2eeReplyCode::AccountRequired)
    );
    let roster = wire(ArcWireObjectKind::DeviceRoster, &stranger.roster)?;
    assert_eq!(
        code(harness.run(Op::PublishRoster, &[], Some(&roster))?),
        Some(E2eeReplyCode::AccountRequired)
    );
    harness.publish_identity_and_roster()?;
    Ok(())
}

#[test]
fn capabilities_are_published_only_by_and_for_the_attached_device() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, OTHER_DEVICE])?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let other = capabilities(
        OTHER_DEVICE,
        &harness.principal.roster,
        0,
        [0; 32],
        (100, 200),
        vec![1, 3],
    )?;
    let other_bytes = wire(ArcWireObjectKind::DeviceCapabilities, &other)?;
    assert_eq!(
        code(harness.run(
            Op::PublishCapabilities,
            &[OTHER_DEVICE; 16],
            Some(&other_bytes)
        )?),
        Some(E2eeReplyCode::DeviceRequired),
        "another device cannot publish while this one is attached"
    );
    assert_eq!(
        code(harness.run(Op::PublishCapabilities, &DEVICE_ID, Some(&other_bytes))?),
        Some(E2eeReplyCode::DeviceRequired),
        "the attached device cannot publish another device's capabilities"
    );
    let own = capabilities(
        DEVICE,
        &harness.principal.roster,
        0,
        [0; 32],
        (100, 200),
        vec![1, 3],
    )?;
    let own_bytes = wire(ArcWireObjectKind::DeviceCapabilities, &own)?;
    assert!(matches!(
        ok(harness.run(Op::PublishCapabilities, &DEVICE_ID, Some(&own_bytes))?)?.result,
        ResultBody::Stored(StoreKind::Capabilities, _)
    ));
    Ok(())
}

fn challenge(harness: &mut Harness) -> TestResult<ArcDeviceAttachChallenge> {
    let outcome = ok(harness.run(Op::AttachBegin, &DEVICE_ID, None)?)?;
    let response = outcome.responses.first().ok_or("challenge response")?;
    let mut budget = DecodeBudget::new(1 << 16, 1 << 10);
    let object = ArcWireObject::decode_kind(
        &response.bytes,
        Some(ArcWireObjectKind::DeviceAttachChallenge),
        &mut budget,
    )?;
    Ok(ArcDeviceAttachChallenge::decode_exact(
        object.body(),
        &mut budget,
    )?)
}

fn attach_bytes(challenge: ArcDeviceAttachChallenge) -> TestResult<Vec<u8>> {
    let device_signature = sign(
        &key(DEVICE),
        SignatureDomain::DeviceAttachPossession,
        &challenge.tbs,
    )?;
    wire(
        ArcWireObjectKind::DeviceAttach,
        &ArcDeviceAttach {
            challenge,
            device_signature,
        },
    )
}

#[test]
fn an_attach_must_answer_the_exact_challenge_the_coordinator_signed() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    let issued = challenge(&mut harness)?;
    let mut other_challenge = issued.clone();
    other_challenge.tbs.server_challenge = [9; 32];
    let mut other_nonce = issued.clone();
    other_nonce.tbs.connection_nonce = [9; 32];
    let mut unsigned = issued.clone();
    unsigned.sequencer_signature = [0; 64];
    for (name, edited) in [
        ("another server challenge", other_challenge),
        ("another connection nonce", other_nonce),
        ("a forged sequencer signature", unsigned),
    ] {
        assert_eq!(
            code(harness.run(Op::AttachFinish, &DEVICE_ID, Some(&attach_bytes(edited)?))?),
            Some(E2eeReplyCode::DeviceRequired),
            "{name}"
        );
        assert_eq!(harness.device(), None, "{name}");
    }
    assert!(matches!(
        ok(harness.run(Op::AttachFinish, &DEVICE_ID, Some(&attach_bytes(issued)?))?)?.result,
        ResultBody::Attached(named, _) if named == DEVICE_ID
    ));
    Ok(())
}

/// A KeyPackage for `device` of the harness principal, with `extensions` on its leaf.
fn package_for(
    harness: &Harness,
    device: u8,
    leaf_extensions: Vec<(u16, Vec<u8>)>,
) -> TestResult<Vec<u8>> {
    let vectors = default_capabilities();
    let capabilities_hash = leaf_capabilities_digest(&encoded_capabilities(&vectors)?)?;
    let bundle = ArcCredentialBundle {
        root: harness.principal.root.clone(),
        device_certificate: certificate(
            &harness.principal.root_secret,
            &harness.principal.root,
            &DeviceSpec::new(device),
        )?,
        leaf_authorization: leaf_authorization(
            &harness.principal.roster,
            &LeafSpec {
                capabilities_hash,
                interval: LEAF_INTERVAL,
                ..LeafSpec::new(device, LEAF_SEED)
            },
        )?,
    };
    let identity = bundle.encode()?;
    let package = key_package(&KeyPackageSpec {
        identity: &identity,
        leaf_seed: LEAF_SEED,
        suite: 1,
        lifetime: LEAF_INTERVAL,
        capabilities: vectors,
        leaf_extensions,
    })?;
    wire_raw(ArcWireObjectKind::KeyPackageMls, package)
}

fn publish_params(device: [u8; 16], suite: u16) -> Vec<u8> {
    let mut params = device.to_vec();
    params.extend_from_slice(&suite.to_be_bytes());
    params.extend_from_slice(&50_000_u64.to_be_bytes());
    params
}

#[test]
fn a_key_package_names_the_attached_device_and_its_suite_without_last_resort() -> TestResult {
    let mut harness = Harness::with_devices(&[DEVICE, OTHER_DEVICE])?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let own = package_for(&harness, DEVICE, Vec::new())?;
    assert_eq!(
        code(harness.run(
            Op::PublishPackage,
            &publish_params([OTHER_DEVICE; 16], 1),
            Some(&own)
        )?),
        Some(E2eeReplyCode::DeviceRequired),
        "another device cannot publish while this one is attached"
    );
    assert_eq!(
        code(harness.run(
            Op::PublishPackage,
            &publish_params(DEVICE_ID, 2),
            Some(&own)
        )?),
        Some(E2eeReplyCode::BindingAuthInvalid),
        "the declared suite must be the package's suite"
    );
    let last_resort = package_for(
        &harness,
        DEVICE,
        vec![(LAST_RESORT_EXTENSION_TYPE, Vec::new())],
    )?;
    assert_eq!(
        code(harness.run(
            Op::PublishPackage,
            &publish_params(DEVICE_ID, 1),
            Some(&last_resort)
        )?),
        Some(E2eeReplyCode::BindingAuthInvalid),
        "a last-resort package is never published"
    );
    let other = package_for(&harness, OTHER_DEVICE, Vec::new())?;
    assert_eq!(
        code(harness.run(
            Op::PublishPackage,
            &publish_params(DEVICE_ID, 1),
            Some(&other)
        )?),
        Some(E2eeReplyCode::BindingAuthInvalid),
        "the credential must certify the attached device"
    );
    assert!(matches!(
        ok(harness.run(
            Op::PublishPackage,
            &publish_params(DEVICE_ID, 1),
            Some(&own)
        )?)?
        .result,
        ResultBody::Stored(StoreKind::Package, _)
    ));
    Ok(())
}
