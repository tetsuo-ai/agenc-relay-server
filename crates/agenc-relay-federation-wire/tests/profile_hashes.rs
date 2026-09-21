#![forbid(unsafe_code)]

//! Independent bindings between frozen source bytes and wire profile hashes.

use agenc_relay_federation_wire::{
    ARCHITECTURE_DOCUMENT_SHA256, BASE_FEDERATION_PROFILE_SHA256, BASE_FEDERATION_PROFILE_TOKEN,
    E2EE_DOCUMENT_SHA256, E2EE_PROFILE_SHA256, E2EE_PROFILE_TOKEN, FEDERATION_REGISTRY_SHA256,
    SOURCE_LEDGER_SHA256,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::{Digest, Sha256};

const ARCHITECTURE: &[u8] =
    include_bytes!("../../../docs/arc-architecture-and-implementation-spec.md");
const E2EE: &[u8] = include_bytes!("../../../docs/arc-mls-e2ee-extension.md");
const REGISTRY: &[u8] = include_bytes!("../../../docs/federation-v1-profile.registry");
const SOURCE_LEDGER: &[u8] = include_bytes!("../../../docs/protocol-sources-and-decisions.md");
const BASE_LABEL: &[u8] = b"agenc-chat base federation profile registry v1\0";
const E2EE_LABEL: &[u8] = b"agenc-chat ARC-MLS specification profile v1\0";

fn digest(parts: &[&[u8]]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update(part);
    }
    hasher.finalize().into()
}

#[test]
fn raw_documents_and_derived_profiles_match_frozen_constants() {
    assert_eq!(digest(&[ARCHITECTURE]), ARCHITECTURE_DOCUMENT_SHA256);
    assert_eq!(digest(&[E2EE]), E2EE_DOCUMENT_SHA256);
    assert_eq!(digest(&[REGISTRY]), FEDERATION_REGISTRY_SHA256);
    assert_eq!(digest(&[SOURCE_LEDGER]), SOURCE_LEDGER_SHA256);
    assert_eq!(
        digest(&[BASE_LABEL, REGISTRY]),
        BASE_FEDERATION_PROFILE_SHA256
    );
    assert_eq!(digest(&[E2EE_LABEL, E2EE]), E2EE_PROFILE_SHA256);
    assert_eq!(
        URL_SAFE_NO_PAD.encode(BASE_FEDERATION_PROFILE_SHA256),
        BASE_FEDERATION_PROFILE_TOKEN
    );
    assert_eq!(
        URL_SAFE_NO_PAD.encode(E2EE_PROFILE_SHA256),
        E2EE_PROFILE_TOKEN
    );
}

#[test]
fn one_changed_source_byte_changes_raw_and_profile_hashes() {
    let mut registry = REGISTRY.to_vec();
    if let Some(first) = registry.first_mut() {
        *first ^= 1;
    }
    assert_ne!(digest(&[&registry]), FEDERATION_REGISTRY_SHA256);
    assert_ne!(
        digest(&[BASE_LABEL, &registry]),
        BASE_FEDERATION_PROFILE_SHA256
    );

    let mut e2ee = E2EE.to_vec();
    if let Some(first) = e2ee.first_mut() {
        *first ^= 1;
    }
    assert_ne!(digest(&[&e2ee]), E2EE_DOCUMENT_SHA256);
    assert_ne!(digest(&[E2EE_LABEL, &e2ee]), E2EE_PROFILE_SHA256);
}
