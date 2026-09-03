#![forbid(unsafe_code)]

//! Independent identity vectors: every object written by
//! `scripts/generate-e2ee-vectors.py` decodes, verifies, and recomputes to
//! the identifiers the generator recorded.

use std::error::Error;
use std::fs;
use std::path::PathBuf;

use agenc_ircd_e2ee::identity::{
    AccountHeads, HeadObservation, ValidationTime, verify_capabilities, verify_credential_bundle,
    verify_device_certificate, verify_key_package_credential, verify_leaf_authorization,
    verify_root_chain, verify_root_identity, verify_roster,
};
use agenc_ircd_e2ee::mls_outer::{
    MlsOuterMessage, parse_mls_message, verify_key_package_signatures,
};
use agenc_ircd_e2ee::objects::identity::{
    IrcAccountRootChain, IrcCredentialBundle, IrcDeviceCapabilities, IrcDeviceCertificate,
    IrcDeviceRoster, IrcLeafAuthorization, IrcRootIdentity,
};
use agenc_ircd_e2ee::{DecodeBudget, TlsDecode};

type TestResult = Result<(), Box<dyn Error>>;

const NETWORK: [u8; 32] = [1; 32];

fn directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../test-data/vectors/e2ee/identity")
}

fn read(name: &str) -> Result<Vec<u8>, Box<dyn Error>> {
    Ok(fs::read(directory().join(name))?)
}

fn decode<T: TlsDecode>(name: &str) -> Result<T, Box<dyn Error>> {
    let mut budget = DecodeBudget::new(1 << 22, 1 << 16);
    Ok(T::decode_exact(&read(name)?, &mut budget)?)
}

fn manifest_id(key: &str) -> Result<[u8; 32], Box<dyn Error>> {
    let text = fs::read_to_string(directory().join("manifest.toml"))?;
    let line = text
        .lines()
        .find(|line| line.starts_with(&format!("{key} = ")))
        .ok_or("missing manifest id")?;
    let hex = line
        .trim_start_matches(&format!("{key} = "))
        .trim_matches('"');
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(hex.get(index..index + 2).unwrap_or("zz"), 16))
        .collect::<Result<Vec<u8>, _>>()?;
    Ok(bytes.as_slice().try_into()?)
}

#[test]
fn the_independent_identity_vectors_verify_and_recompute() -> TestResult {
    let root0: IrcRootIdentity = decode("root-generation-0.bin")?;
    let root1: IrcRootIdentity = decode("root-generation-1.bin")?;
    let verified_root = verify_root_identity(&NETWORK, &root0, None)?;
    assert_eq!(verified_root.fingerprint, manifest_id("root_fingerprint")?);
    let successor = verify_root_identity(&NETWORK, &root1, Some(&verified_root))?;
    assert_eq!(
        successor.fingerprint,
        manifest_id("successor_root_fingerprint")?
    );
    let chain: IrcAccountRootChain = decode("root-chain.bin")?;
    let verified_chain = verify_root_chain(&NETWORK, chain.roots.as_slice(), None)?;
    assert_eq!(verified_chain.len(), 2);

    let certificate: IrcDeviceCertificate = decode("certificate-7.bin")?;
    let verified_certificate = verify_device_certificate(&verified_root, &certificate)?;
    assert_eq!(
        verified_certificate.certificate_id,
        manifest_id("certificate_7_id")?
    );

    let roster: IrcDeviceRoster = decode("roster.bin")?;
    let verified_roster = verify_roster(&verified_root, &roster, None)?;
    assert_eq!(verified_roster.roster_id, manifest_id("roster_id")?);
    assert_eq!(verified_roster.devices.len(), 2);
    assert_eq!(
        verified_roster
            .device(&[8; 16])
            .map(|device| device.certificate_id),
        Some(manifest_id("certificate_8_id")?)
    );
    assert!(verified_roster.usable_for_add(ValidationTime(200)));

    let capabilities: IrcDeviceCapabilities = decode("capabilities-7.bin")?;
    let verified_capabilities = verify_capabilities(&verified_roster, &capabilities, None)?;
    assert_eq!(
        verified_capabilities.capability_id,
        manifest_id("capability_7_id")?
    );

    let leaf: IrcLeafAuthorization = decode("leaf-authorization-7.bin")?;
    let verified_leaf = verify_leaf_authorization(&verified_roster, &leaf)?;
    assert_eq!(
        verified_leaf.leaf_signature_key,
        manifest_id("leaf_7_signature_key")?.to_vec()
    );
    assert_eq!(
        verified_leaf.leaf_capabilities_hash,
        manifest_id("leaf_7_capabilities_hash")?
    );

    let bundle: IrcCredentialBundle = decode("credential-bundle-7.bin")?;
    let credential = verify_credential_bundle(&NETWORK, &verified_roster, &bundle)?;
    assert_eq!(credential.client.device_id, [7; 16]);

    let package_bytes = read("key-package-7.bin")?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 12);
    let MlsOuterMessage::KeyPackage(package) = parse_mls_message(&package_bytes, &mut budget)?
    else {
        return Err("expected a key package".into());
    };
    verify_key_package_signatures(&package)?;
    let from_package = verify_key_package_credential(&NETWORK, &verified_roster, &package)?;
    assert_eq!(from_package, credential);

    let mut heads = AccountHeads::new();
    assert_eq!(
        heads.observe_root(&verified_root),
        HeadObservation::Advanced
    );
    assert_eq!(heads.observe_root(&successor), HeadObservation::Advanced);
    assert_eq!(
        heads.observe_roster(&verified_roster),
        HeadObservation::Advanced
    );
    Ok(())
}
