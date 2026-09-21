#![forbid(unsafe_code)]

//! RFC 9420 outer framing: variable-length integers, private message and
//! Welcome headers, and the public KeyPackage with its signatures.

use std::error::Error;

use agenc_relay_crypto::{Ed25519SecretKey, SignatureDomain, sign_canonical};

use super::*;
use crate::limits::{MLS_VERSION_MLS10, SUITE_X25519_AES128GCM_SHA256_ED25519};

type TestResult = Result<(), Box<dyn Error>>;

fn opaque_v(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), E2eeError> {
    mls_varint_encode(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn budget() -> DecodeBudget {
    DecodeBudget::new(1 << 20, 1 << 12)
}

#[test]
fn varints_follow_the_rfc_examples() -> TestResult {
    let mut out = Vec::new();
    mls_varint_encode(&mut out, 37)?;
    assert_eq!(out, vec![0x25]);
    out.clear();
    mls_varint_encode(&mut out, 15_293)?;
    assert_eq!(out, vec![0x7b, 0xbd]);
    out.clear();
    mls_varint_encode(&mut out, 494_878_333)?;
    assert_eq!(out, vec![0x9d, 0x7f, 0x3e, 0x7d]);
    assert_eq!(
        mls_varint_encode(&mut out, 0x4000_0000),
        Err(E2eeError::LengthOutOfRange)
    );
    for (encoded, value) in [
        (vec![0x25_u8], 37_usize),
        (vec![0x7b, 0xbd], 15_293),
        (vec![0x9d, 0x7f, 0x3e, 0x7d], 494_878_333),
    ] {
        let mut budget = budget();
        let mut reader = MlsReader::new(&encoded, &mut budget);
        assert_eq!(reader.varint()?, value);
        reader.finish()?;
    }
    // Non-minimal encodings and the reserved prefix are refused.
    for bad in [vec![0x40_u8, 0x25], vec![0x80, 0, 0, 0x25], vec![0xc0]] {
        let mut budget = budget();
        let mut reader = MlsReader::new(&bad, &mut budget);
        assert_eq!(reader.varint(), Err(E2eeError::NonCanonical));
    }
    Ok(())
}

fn private_message(content_type: u8, aad: &[u8]) -> Result<Vec<u8>, E2eeError> {
    let mut out = vec![0, 1, 0, 2];
    opaque_v(&mut out, &[7; 32])?;
    out.extend_from_slice(&9_u64.to_be_bytes());
    out.push(content_type);
    opaque_v(&mut out, aad)?;
    opaque_v(&mut out, &[1; 40])?;
    opaque_v(&mut out, &[2; 300])?;
    Ok(out)
}

#[test]
fn a_private_message_header_is_read_and_the_rest_stays_opaque() -> TestResult {
    let bytes = private_message(1, b"aad")?;
    let parsed = parse_mls_message(&bytes, &mut budget())?;
    let MlsOuterMessage::Private(header) = parsed else {
        return Err("expected a private message".into());
    };
    assert_eq!(header.group_id, vec![7; 32]);
    assert_eq!(header.epoch, 9);
    assert_eq!(header.content_type, MlsContentType::Application);
    assert_eq!(header.authenticated_data, b"aad");
    assert_eq!(header.encrypted_sender_data_len, 40);
    assert_eq!(header.ciphertext_len, 300);
    let commit = private_message(3, b"")?;
    assert!(matches!(
        parse_mls_message(&commit, &mut budget())?,
        MlsOuterMessage::Private(PrivateMessageHeader {
            content_type: MlsContentType::Commit,
            ..
        })
    ));
    let proposal = private_message(2, b"")?;
    assert!(matches!(
        parse_mls_message(&proposal, &mut budget())?,
        MlsOuterMessage::Private(PrivateMessageHeader {
            content_type: MlsContentType::Proposal,
            ..
        })
    ));
    let unknown = private_message(4, b"")?;
    assert_eq!(
        parse_mls_message(&unknown, &mut budget()),
        Err(E2eeError::UnknownDiscriminant)
    );
    let mut trailing = bytes;
    trailing.push(0);
    assert_eq!(
        parse_mls_message(&trailing, &mut budget()),
        Err(E2eeError::TrailingBytes)
    );
    Ok(())
}

#[test]
fn public_messages_group_info_and_other_versions_are_refused() -> TestResult {
    let public = vec![0, 1, 0, 1, 0];
    assert_eq!(
        parse_mls_message(&public, &mut budget()),
        Err(E2eeError::WrongKind)
    );
    let group_info = vec![0, 1, 0, 4];
    assert_eq!(
        parse_mls_message(&group_info, &mut budget()),
        Err(E2eeError::WrongKind)
    );
    let version = vec![0, 2, 0, 2];
    assert_eq!(
        parse_mls_message(&version, &mut budget()),
        Err(E2eeError::ProfileMismatch)
    );
    let format = vec![0, 1, 0, 9];
    assert_eq!(
        parse_mls_message(&format, &mut budget()),
        Err(E2eeError::UnknownDiscriminant)
    );
    Ok(())
}

#[test]
fn a_welcome_header_lists_every_addressed_member() -> TestResult {
    let mut out = vec![0, 1, 0, 3, 0, 1];
    let mut secrets = Vec::new();
    for member in [[3_u8; 32], [4; 32]] {
        opaque_v(&mut secrets, &member)?;
        opaque_v(&mut secrets, &[5; 32])?;
        opaque_v(&mut secrets, &[6; 64])?;
    }
    opaque_v(&mut out, &secrets)?;
    opaque_v(&mut out, &[8; 500])?;
    let MlsOuterMessage::Welcome(header) = parse_mls_message(&out, &mut budget())? else {
        return Err("expected a welcome".into());
    };
    assert_eq!(header.cipher_suite, SUITE_X25519_AES128GCM_SHA256_ED25519);
    assert_eq!(header.new_member_refs, vec![vec![3; 32], vec![4; 32]]);
    assert_eq!(header.encrypted_group_info_len, 500);
    let mut wrong_suite = out;
    wrong_suite.splice(4..6, [0, 4]);
    assert_eq!(
        parse_mls_message(&wrong_suite, &mut budget()),
        Err(E2eeError::ProfileMismatch)
    );
    Ok(())
}

struct SampleKeyPackage {
    bytes: Vec<u8>,
    signature_key: [u8; 32],
}

fn key_package(
    secret: &Ed25519SecretKey,
    extra_extension: Option<u16>,
) -> Result<SampleKeyPackage, Box<dyn Error>> {
    let signature_key = *secret.public_key().as_bytes();
    let mut leaf = Vec::new();
    opaque_v(&mut leaf, &[11; 32])?;
    opaque_v(&mut leaf, &signature_key)?;
    leaf.extend_from_slice(&1_u16.to_be_bytes());
    opaque_v(&mut leaf, b"identity bundle bytes")?;
    let capability_vectors: [&[u8]; 5] = [&[0, 1], &[0, 1, 0, 3], &[], &[], &[0, 1]];
    for vector in capability_vectors {
        opaque_v(&mut leaf, vector)?;
    }
    leaf.push(1);
    leaf.extend_from_slice(&100_u64.to_be_bytes());
    leaf.extend_from_slice(&200_u64.to_be_bytes());
    let mut leaf_extensions = Vec::new();
    if let Some(extension_type) = extra_extension {
        leaf_extensions.extend_from_slice(&extension_type.to_be_bytes());
        opaque_v(&mut leaf_extensions, &[])?;
    }
    opaque_v(&mut leaf, &leaf_extensions)?;
    let leaf_signature = sign_canonical(secret, SignatureDomain::MlsLeafNodeTbs, &leaf)?;
    opaque_v(&mut leaf, leaf_signature.as_bytes())?;

    let mut tbs = Vec::new();
    tbs.extend_from_slice(&MLS_VERSION_MLS10.to_be_bytes());
    tbs.extend_from_slice(&SUITE_X25519_AES128GCM_SHA256_ED25519.to_be_bytes());
    opaque_v(&mut tbs, &[12; 32])?;
    tbs.extend_from_slice(&leaf);
    opaque_v(&mut tbs, &[])?;
    let signature = sign_canonical(secret, SignatureDomain::MlsKeyPackageTbs, &tbs)?;
    let mut bytes = vec![0, 1, 0, 5];
    bytes.extend_from_slice(&tbs);
    opaque_v(&mut bytes, signature.as_bytes())?;
    Ok(SampleKeyPackage {
        bytes,
        signature_key,
    })
}

#[test]
fn a_key_package_exposes_its_public_fields_reference_and_signatures() -> TestResult {
    let secret = Ed25519SecretKey::from_bytes([21; 32]);
    let sample = key_package(&secret, None)?;
    let MlsOuterMessage::KeyPackage(package) = parse_mls_message(&sample.bytes, &mut budget())?
    else {
        return Err("expected a key package".into());
    };
    assert_eq!(package.cipher_suite, SUITE_X25519_AES128GCM_SHA256_ED25519);
    assert_eq!(package.init_key, vec![12; 32]);
    assert_eq!(
        package.leaf_node.signature_key,
        sample.signature_key.to_vec()
    );
    assert_eq!(
        package.leaf_node.credential_identity,
        b"identity bundle bytes"
    );
    assert_eq!(
        package.leaf_node.lifetime,
        Lifetime {
            not_before: 100,
            not_after: 200
        }
    );
    assert!(package.leaf_node.encoded_credential.starts_with(&[0, 1]));
    assert_eq!(
        package.leaf_node.encoded_capabilities.len(),
        3 + 5 + 1 + 1 + 3
    );
    assert!(!package.has_last_resort_extension());
    verify_key_package_signatures(&package)?;
    // The reference is RefHash over the complete KeyPackage bytes.
    let complete = sample.bytes.get(4..).unwrap_or_default();
    assert_eq!(
        package.key_package_ref,
        ref_hash("MLS 1.0 KeyPackage Reference", complete)?
    );
    assert_eq!(leaf_signature_scheme(package.cipher_suite), Some(0x0807));
    assert_eq!(leaf_signature_scheme(0x0004), None);
    Ok(())
}

#[test]
fn last_resort_and_tampering_are_detected() -> TestResult {
    let secret = Ed25519SecretKey::from_bytes([22; 32]);
    let sample = key_package(&secret, Some(LAST_RESORT_EXTENSION_TYPE))?;
    let MlsOuterMessage::KeyPackage(package) = parse_mls_message(&sample.bytes, &mut budget())?
    else {
        return Err("expected a key package".into());
    };
    assert!(package.has_last_resort_extension());
    verify_key_package_signatures(&package)?;
    let mut tampered = package.clone();
    tampered.init_key = vec![13; 32];
    tampered.tbs.splice(4..37, {
        let mut init = Vec::new();
        opaque_v(&mut init, &[13; 32])?;
        init
    });
    assert_eq!(
        verify_key_package_signatures(&tampered),
        Err(E2eeError::SignatureInvalid)
    );
    let mut other_key = package;
    other_key.leaf_node.signature_key = vec![0; 32];
    assert_eq!(
        verify_key_package_signatures(&other_key),
        Err(E2eeError::SignatureInvalid)
    );
    Ok(())
}

#[test]
fn key_packages_outside_the_profile_are_refused() -> TestResult {
    let secret = Ed25519SecretKey::from_bytes([23; 32]);
    let sample = key_package(&secret, None)?;
    let mut wrong_suite = sample.bytes.clone();
    wrong_suite.splice(6..8, [0, 4]);
    assert_eq!(
        parse_mls_message(&wrong_suite, &mut budget()),
        Err(E2eeError::ProfileMismatch)
    );
    let mut wrong_credential = sample.bytes.clone();
    // credential type sits after version(2) format(2) version(2) suite(2) init(1+32) enc(1+32) sig(1+32)
    let offset = 4 + 4 + 33 + 33 + 33;
    wrong_credential.splice(offset..offset + 2, [0, 2]);
    assert_eq!(
        parse_mls_message(&wrong_credential, &mut budget()),
        Err(E2eeError::ProfileMismatch)
    );
    let mut small = DecodeBudget::new(64, 1 << 12);
    assert_eq!(
        parse_mls_message(&sample.bytes, &mut small),
        Err(E2eeError::BudgetExceeded)
    );
    Ok(())
}

#[test]
fn key_packages_of_another_version_or_leaf_source_are_refused() -> TestResult {
    let secret = Ed25519SecretKey::from_bytes([24; 32]);
    let sample = key_package(&secret, None)?;
    let mut wrong_version = sample.bytes.clone();
    wrong_version.splice(4..6, [0, 2]);
    assert_eq!(
        parse_mls_message(&wrong_version, &mut budget()),
        Err(E2eeError::ProfileMismatch)
    );
    // The leaf node source byte follows the key package header, the three
    // keys, the credential and the five capability vectors.
    let source_offset = 4 + 2 + 2 + 33 + 33 + 33 + 2 + 22 + 13;
    let mut wrong_source = sample.bytes.clone();
    assert_eq!(wrong_source.get(source_offset), Some(&1));
    *wrong_source.get_mut(source_offset).ok_or("source byte")? = 2;
    assert_eq!(
        parse_mls_message(&wrong_source, &mut budget()),
        Err(E2eeError::ProfileMismatch)
    );
    Ok(())
}
