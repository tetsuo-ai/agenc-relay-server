#![forbid(unsafe_code)]

//! Test-only builders that mint keys and sign companion objects, copied
//! from the e2ee crate's private test support (`tests/support.rs` there)
//! so the coordinator handlers can be driven with genuine signatures. The
//! workspace policy pins every dependency to the bare root entry, so the
//! builders cannot be shared through a feature.

use agenc_relay_crypto::{Ed25519SecretKey, SemanticHashDomain, SignatureDomain, sign_canonical};

use agenc_relay_e2ee::E2eeError;
use agenc_relay_e2ee::ids::{SemanticId, semantic_id_of};
use agenc_relay_e2ee::mls_outer::mls_varint_encode;
use agenc_relay_e2ee::objects::AccountIdField;
use agenc_relay_e2ee::objects::conversation::{
    ArcCommitApproval, ArcCommitApprovalEnvelope, ArcCommitAuthorization,
    ArcCommitAuthorizationRule, ArcCommitAuthorizationTbs, ArcConversationKind,
    ArcFinalityPrincipal, ArcMembershipPolicy, ArcPolicy, ArcPolicyApproval, ArcPolicyTbs,
    ArcSequencerCredential, ArcSequencerCredentialTbs,
};
use agenc_relay_e2ee::objects::identity::*;
use agenc_relay_e2ee::objects::sequencing::{ArcDispositionVoteTbs, ArcFinalityVote};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode, TlsVec};

pub(crate) const NETWORK: [u8; 32] = [1; 32];

pub(crate) fn key(seed: u8) -> Ed25519SecretKey {
    Ed25519SecretKey::from_bytes([seed; 32])
}

pub(crate) fn public(secret: &Ed25519SecretKey) -> [u8; 32] {
    *secret.public_key().as_bytes()
}

pub(crate) fn sign(
    secret: &Ed25519SecretKey,
    domain: SignatureDomain,
    tbs: &impl TlsEncode,
) -> Result<[u8; 64], E2eeError> {
    let encoded = tbs.encode()?;
    sign_canonical(secret, domain, &encoded)
        .map(|signature| *signature.as_bytes())
        .map_err(|_| E2eeError::SignatureInvalid)
}

pub(crate) fn account_field(account: &[u8; 24]) -> Result<AccountIdField, E2eeError> {
    Opaque::from_slice(account)
}

/// A root identity signed by `secret`, continuing `previous` when given.
pub(crate) fn root(
    secret: &Ed25519SecretKey,
    account: &[u8; 24],
    generation: u64,
    interval: (u64, u64),
    previous: Option<(&Ed25519SecretKey, &ArcRootIdentity)>,
) -> Result<ArcRootIdentity, E2eeError> {
    let previous_root_fingerprint = match previous {
        Some((_, previous_root)) => root_fingerprint(previous_root)?,
        None => [0; 32],
    };
    let tbs = ArcRootIdentityTbs {
        profile_version: 1,
        network_id: NETWORK,
        account_id: account_field(account)?,
        root_generation: generation,
        root_public_key: public(secret),
        not_before: interval.0,
        not_after: interval.1,
        previous_root_fingerprint,
    };
    let self_signature = sign(secret, SignatureDomain::RootIdentity, &tbs)?;
    let continuity = match previous {
        Some((previous_secret, _)) => {
            sign(previous_secret, SignatureDomain::RootContinuity, &tbs)?.to_vec()
        }
        None => Vec::new(),
    };
    Ok(ArcRootIdentity {
        tbs,
        self_signature,
        continuity_signature: Opaque::new(continuity)?,
    })
}

pub(crate) fn root_fingerprint(root: &ArcRootIdentity) -> Result<SemanticId, E2eeError> {
    semantic_id_of(SemanticHashDomain::RootFingerprint, &root.tbs)
}

pub(crate) struct DeviceSpec {
    pub(crate) seed: u8,
    pub(crate) device_id: [u8; 16],
    pub(crate) flags: u32,
    pub(crate) target_roster_generation: u64,
    pub(crate) interval: (u64, u64),
    pub(crate) enrollment: (u64, u64),
    pub(crate) serial: u64,
}

impl DeviceSpec {
    pub(crate) fn new(seed: u8) -> Self {
        Self {
            seed,
            device_id: [seed; 16],
            flags: 3,
            target_roster_generation: 0,
            interval: (0, 1_000_000),
            enrollment: (90, 100),
            serial: 1,
        }
    }
}

pub(crate) fn certificate(
    root_secret: &Ed25519SecretKey,
    root: &ArcRootIdentity,
    spec: &DeviceSpec,
) -> Result<ArcDeviceCertificate, E2eeError> {
    let device_secret = key(spec.seed);
    let enrollment_tbs = ArcDeviceEnrollmentTbs {
        profile_version: 1,
        network_id: NETWORK,
        account_id: root.tbs.account_id.clone(),
        root_generation: root.tbs.root_generation,
        root_fingerprint: root_fingerprint(root)?,
        target_roster_generation: spec.target_roster_generation,
        enrollment_challenge: [spec.seed.wrapping_add(100); 32],
        device_id: spec.device_id,
        device_authorization_key: public(&device_secret),
        issued_at: spec.enrollment.0,
        expires_at: spec.enrollment.1,
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
        network_id: NETWORK,
        account_id: root.tbs.account_id.clone(),
        root_generation: root.tbs.root_generation,
        root_fingerprint: root_fingerprint(root)?,
        device_id: spec.device_id,
        device_authorization_key: public(&device_secret),
        target_roster_generation: spec.target_roster_generation,
        enrollment_challenge: enrollment.tbs.enrollment_challenge,
        enrollment_id: semantic_id_of(SemanticHashDomain::EnrollmentId, &enrollment.tbs)?,
        certificate_serial: spec.serial,
        authorization_flags: spec.flags,
        not_before: spec.interval.0,
        not_after: spec.interval.1,
    };
    Ok(ArcDeviceCertificate {
        root_signature: sign(root_secret, SignatureDomain::DeviceCertificate, &tbs)?,
        tbs,
        enrollment_proof: enrollment,
    })
}

pub(crate) fn roster(
    root_secret: &Ed25519SecretKey,
    root: &ArcRootIdentity,
    generation: u64,
    previous_roster_id: [u8; 32],
    interval: (u64, u64),
    certificates: Vec<ArcDeviceCertificate>,
    revocations: Vec<ArcDeviceRevocation>,
) -> Result<ArcDeviceRoster, E2eeError> {
    let active = certificates
        .into_iter()
        .map(|certificate| ArcActiveDevice {
            device_id: certificate.tbs.device_id,
            certificate,
        })
        .collect();
    let tbs = ArcDeviceRosterTbs {
        profile_version: 1,
        network_id: NETWORK,
        account_id: root.tbs.account_id.clone(),
        root_generation: root.tbs.root_generation,
        root_fingerprint: root_fingerprint(root)?,
        roster_generation: generation,
        not_before: interval.0,
        not_after: interval.1,
        previous_roster_id,
        active_devices: TlsVec::new(active)?,
        revocations: TlsVec::new(revocations)?,
    };
    Ok(ArcDeviceRoster {
        root_signature: sign(root_secret, SignatureDomain::DeviceRoster, &tbs)?,
        tbs,
    })
}

pub(crate) fn roster_id(roster: &ArcDeviceRoster) -> Result<SemanticId, E2eeError> {
    semantic_id_of(SemanticHashDomain::RosterId, &roster.tbs)
}

pub(crate) fn capabilities(
    device_seed: u8,
    roster: &ArcDeviceRoster,
    generation: u64,
    previous_capability_id: [u8; 32],
    interval: (u64, u64),
    suites: Vec<u16>,
) -> Result<ArcDeviceCapabilities, E2eeError> {
    let tbs = ArcDeviceCapabilitiesTbs {
        profile_version: 1,
        network_id: NETWORK,
        account_id: roster.tbs.account_id.clone(),
        root_fingerprint: roster.tbs.root_fingerprint,
        roster_generation: roster.tbs.roster_generation,
        roster_id: roster_id(roster)?,
        device_id: [device_seed; 16],
        capability_generation: generation,
        previous_capability_id,
        not_before: interval.0,
        not_after: interval.1,
        versions: TlsVec::new(vec![1])?,
        cipher_suites: TlsVec::new(suites)?,
        extensions: TlsVec::new(vec![0xF1C1, 0xF1C3])?,
        proposals: TlsVec::new(vec![0xF1C2])?,
        credentials: TlsVec::new(vec![1])?,
    };
    Ok(ArcDeviceCapabilities {
        device_signature: sign(&key(device_seed), SignatureDomain::DeviceCapabilities, &tbs)?,
        tbs,
    })
}

pub(crate) struct LeafSpec {
    pub(crate) device_seed: u8,
    pub(crate) leaf_seed: u8,
    pub(crate) suite: u16,
    pub(crate) interval: (u64, u64),
    pub(crate) capabilities_hash: [u8; 32],
    pub(crate) last_resort: u8,
    pub(crate) credential_generation: u64,
}

impl LeafSpec {
    pub(crate) fn new(device_seed: u8, leaf_seed: u8) -> Self {
        Self {
            device_seed,
            leaf_seed,
            suite: 1,
            interval: (100, 1_000),
            capabilities_hash: [17; 32],
            last_resort: 0,
            credential_generation: 0,
        }
    }
}

pub(crate) fn leaf_authorization(
    roster: &ArcDeviceRoster,
    spec: &LeafSpec,
) -> Result<ArcLeafAuthorization, E2eeError> {
    let tbs = ArcLeafAuthorizationTbs {
        profile_version: 1,
        network_id: NETWORK,
        account_id: roster.tbs.account_id.clone(),
        root_generation: roster.tbs.root_generation,
        root_fingerprint: roster.tbs.root_fingerprint,
        roster_generation: roster.tbs.roster_generation,
        roster_id: roster_id(roster)?,
        device_id: [spec.device_seed; 16],
        credential_generation: spec.credential_generation,
        mls_version: 1,
        cipher_suite: spec.suite,
        leaf_signature_scheme: 0x0807,
        leaf_signature_key: Opaque::new(public(&key(spec.leaf_seed)).to_vec())?,
        leaf_capabilities_hash: spec.capabilities_hash,
        package_nonce: [spec.leaf_seed; 32],
        last_resort: spec.last_resort,
        not_before: spec.interval.0,
        not_after: spec.interval.1,
    };
    Ok(ArcLeafAuthorization {
        device_signature: sign(
            &key(spec.device_seed),
            SignatureDomain::LeafAuthorization,
            &tbs,
        )?,
        tbs,
    })
}

/// A public KeyPackage whose credential identity is `identity`, signed by
/// the leaf key `leaf_seed`, with the exact `capabilities` encoding.
pub(crate) struct KeyPackageSpec<'a> {
    pub(crate) identity: &'a [u8],
    pub(crate) leaf_seed: u8,
    pub(crate) suite: u16,
    pub(crate) lifetime: (u64, u64),
    pub(crate) capabilities: Vec<Vec<u8>>,
    pub(crate) leaf_extensions: Vec<(u16, Vec<u8>)>,
}

pub(crate) fn opaque_v(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), E2eeError> {
    mls_varint_encode(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

pub(crate) fn default_capabilities() -> Vec<Vec<u8>> {
    vec![
        vec![0, 1],
        vec![0, 1, 0, 3],
        Vec::new(),
        Vec::new(),
        vec![0, 1],
    ]
}

pub(crate) fn key_package(spec: &KeyPackageSpec<'_>) -> Result<Vec<u8>, E2eeError> {
    let leaf_secret = key(spec.leaf_seed);
    let mut leaf = Vec::new();
    opaque_v(&mut leaf, &[11; 32])?;
    opaque_v(&mut leaf, &public(&leaf_secret))?;
    leaf.extend_from_slice(&1_u16.to_be_bytes());
    opaque_v(&mut leaf, spec.identity)?;
    for vector in &spec.capabilities {
        opaque_v(&mut leaf, vector)?;
    }
    leaf.push(1);
    leaf.extend_from_slice(&spec.lifetime.0.to_be_bytes());
    leaf.extend_from_slice(&spec.lifetime.1.to_be_bytes());
    let mut extensions = Vec::new();
    for (extension_type, data) in &spec.leaf_extensions {
        extensions.extend_from_slice(&extension_type.to_be_bytes());
        opaque_v(&mut extensions, data)?;
    }
    opaque_v(&mut leaf, &extensions)?;
    let leaf_signature = sign_canonical(&leaf_secret, SignatureDomain::MlsLeafNodeTbs, &leaf)
        .map_err(|_| E2eeError::SignatureInvalid)?;
    opaque_v(&mut leaf, leaf_signature.as_bytes())?;
    let mut tbs = Vec::new();
    tbs.extend_from_slice(&1_u16.to_be_bytes());
    tbs.extend_from_slice(&spec.suite.to_be_bytes());
    opaque_v(&mut tbs, &[12; 32])?;
    tbs.extend_from_slice(&leaf);
    opaque_v(&mut tbs, &[])?;
    let signature = sign_canonical(&leaf_secret, SignatureDomain::MlsKeyPackageTbs, &tbs)
        .map_err(|_| E2eeError::SignatureInvalid)?;
    let mut bytes = vec![0, 1, 0, 5];
    bytes.extend_from_slice(&tbs);
    opaque_v(&mut bytes, signature.as_bytes())?;
    Ok(bytes)
}

/// The canonical capabilities encoding of `vectors` as the leaf carries it.
pub(crate) fn encoded_capabilities(vectors: &[Vec<u8>]) -> Result<Vec<u8>, E2eeError> {
    let mut out = Vec::new();
    for vector in vectors {
        opaque_v(&mut out, vector)?;
    }
    Ok(out)
}

/// A principal for a binding package: its root secret, root, and roster.
pub(crate) struct Principal {
    pub(crate) root_secret: Ed25519SecretKey,
    pub(crate) root: ArcRootIdentity,
    pub(crate) roster: ArcDeviceRoster,
    /// Device seeds active in the roster, all with binding authority.
    pub(crate) devices: Vec<u8>,
}

pub(crate) fn principal(
    root_seed: u8,
    account: &[u8; 24],
    devices: &[u8],
) -> Result<Principal, E2eeError> {
    let root_secret = key(root_seed);
    let root = root(&root_secret, account, 0, (0, 2_000_000), None)?;
    let mut certificates = devices
        .iter()
        .map(|seed| certificate(&root_secret, &root, &DeviceSpec::new(*seed)))
        .collect::<Result<Vec<_>, _>>()?;
    certificates.sort_by_key(|certificate| certificate.tbs.device_id);
    let roster = roster(
        &root_secret,
        &root,
        0,
        [0; 32],
        (100, 100 + 6 * 24 * 3600),
        certificates,
        Vec::new(),
    )?;
    Ok(Principal {
        root_secret,
        root,
        roster,
        devices: devices.to_vec(),
    })
}

pub(crate) struct BindingSpec<'a> {
    pub(crate) principals: &'a [Principal],
    pub(crate) route: agenc_relay_e2ee::objects::conversation::ArcSemanticRouteTbs,
    pub(crate) channel_instance_id: Option<[u8; 16]>,
    pub(crate) conversation_nonce: Option<[u8; 32]>,
    pub(crate) group_id: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) previous_binding_id: [u8; 32],
    pub(crate) lock_sequence: u64,
    pub(crate) plan_devices: Vec<(&'a [u8; 24], [u8; 32], u8)>,
    pub(crate) initial_policy_id: [u8; 32],
    pub(crate) required_operational_policy_id: [u8; 32],
    /// The sequencer credential the binding pins.
    pub(crate) sequencer_credential_id: [u8; 32],
}

/// A complete binding package signed by every binding-authorized device of
/// every principal, with one root lock per principal.
pub(crate) fn binding_package(
    spec: &BindingSpec<'_>,
) -> Result<agenc_relay_e2ee::objects::conversation::ArcConversationBindingPackage, E2eeError> {
    use agenc_relay_e2ee::objects::conversation::*;
    let lock_id = semantic_id_of(SemanticHashDomain::SemanticRouteLock, &spec.route)?;
    let route_binding = match (spec.channel_instance_id, spec.conversation_nonce) {
        (Some(instance), None) => {
            agenc_relay_e2ee::route::channel_route_binding(&NETWORK, &instance)?
        }
        (None, Some(nonce)) => {
            let a = spec.route.direct_account_a.exactly::<24>()?;
            let b = spec.route.direct_account_b.exactly::<24>()?;
            agenc_relay_e2ee::route::direct_route_binding(&NETWORK, &nonce, &a, &b)?
        }
        _ => return Err(E2eeError::InvalidValue),
    };
    let mut principals: Vec<ArcBindingPrincipal> = spec
        .principals
        .iter()
        .map(|principal| {
            Ok(ArcBindingPrincipal {
                account_id: principal.root.tbs.account_id.clone(),
                root_fingerprint: root_fingerprint(&principal.root)?,
                roster_generation: 0,
                roster_id: roster_id(&principal.roster)?,
            })
        })
        .collect::<Result<_, E2eeError>>()?;
    principals.sort_by_key(|principal| principal.account_id.clone());
    let mut entries: Vec<ArcInitialMemberPlanEntry> = spec
        .plan_devices
        .iter()
        .map(|(account, fingerprint, device)| {
            Ok(ArcInitialMemberPlanEntry {
                account_id: account_field(account)?,
                root_fingerprint: *fingerprint,
                device_id: [*device; 16],
                capability_id: [device.wrapping_add(200); 32],
            })
        })
        .collect::<Result<_, E2eeError>>()?;
    entries.sort_by_key(|entry| {
        (
            entry.account_id.clone(),
            entry.root_fingerprint,
            entry.device_id,
        )
    });
    let plan = ArcInitialMemberPlan {
        entries: TlsVec::new(entries)?,
    };
    let tbs = ArcConversationBindingTbs {
        profile_version: 1,
        network_id: NETWORK,
        kind: spec.route.kind,
        binding_generation: spec.generation,
        previous_binding_id: spec.previous_binding_id,
        semantic_route: spec.route.clone(),
        semantic_route_lock_id: lock_id,
        channel_instance_id: Opaque::new(
            spec.channel_instance_id
                .map(|id| id.to_vec())
                .unwrap_or_default(),
        )?,
        conversation_nonce: Opaque::new(
            spec.conversation_nonce
                .map(|nonce| nonce.to_vec())
                .unwrap_or_default(),
        )?,
        group_id: Opaque::new(spec.group_id.to_vec())?,
        conversation_id: agenc_relay_e2ee::ids::conversation_id(&NETWORK, &spec.group_id)?,
        route_binding,
        mls_version: 1,
        cipher_suite: 1,
        initial_policy_id: spec.initial_policy_id,
        required_operational_policy_id: spec.required_operational_policy_id,
        initial_member_plan_id: semantic_id_of(SemanticHashDomain::InitialMemberPlanId, &plan)?,
        context_core_id: [30; 32],
        sequencer_credential_id: spec.sequencer_credential_id,
        principals: TlsVec::new(principals)?,
    };
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &tbs)?;
    let mut approvals = Vec::new();
    let mut locks = Vec::new();
    if spec.generation == 0 {
        for principal in spec.principals {
            let fingerprint = root_fingerprint(&principal.root)?;
            for device in &principal.devices {
                let certificate = certificate(
                    &principal.root_secret,
                    &principal.root,
                    &DeviceSpec::new(*device),
                )?;
                approvals.push(ArcBindingApproval {
                    signer_root_fingerprint: fingerprint,
                    signer_device_id: [*device; 16],
                    signer_device_certificate_id: semantic_id_of(
                        SemanticHashDomain::DeviceCertificateId,
                        &certificate.tbs,
                    )?,
                    device_signature: sign(
                        &key(*device),
                        SignatureDomain::ConversationBinding,
                        &tbs,
                    )?,
                });
            }
            let lock_tbs = ArcRootBindingLockTbs {
                profile_version: 1,
                network_id: NETWORK,
                account_id: principal.root.tbs.account_id.clone(),
                root_fingerprint: fingerprint,
                root_binding_sequence: spec.lock_sequence,
                previous_root_binding_lock_id: if spec.lock_sequence == 0 {
                    [0; 32]
                } else {
                    [66; 32]
                },
                semantic_route_lock_id: lock_id,
                binding_id,
                roster_generation: 0,
                roster_id: roster_id(&principal.roster)?,
            };
            locks.push(ArcRootBindingLock {
                root_signature: sign(
                    &principal.root_secret,
                    SignatureDomain::RootBindingLock,
                    &lock_tbs,
                )?,
                tbs: lock_tbs,
            });
        }
    }
    approvals.sort_by_key(|approval| (approval.signer_root_fingerprint, approval.signer_device_id));
    locks.sort_by_key(|lock| lock.tbs.account_id.clone());
    Ok(ArcConversationBindingPackage {
        binding: ArcConversationBinding {
            tbs,
            approvals: TlsVec::new(approvals)?,
        },
        initial_member_plan: plan,
        root_binding_locks: TlsVec::new(locks)?,
    })
}

pub(crate) fn channel_route(
    name: &[u8],
    authority_root: [u8; 32],
) -> Result<agenc_relay_e2ee::objects::conversation::ArcSemanticRouteTbs, E2eeError> {
    Ok(
        agenc_relay_e2ee::objects::conversation::ArcSemanticRouteTbs {
            profile_version: 1,
            network_id: NETWORK,
            kind: agenc_relay_e2ee::objects::conversation::ArcConversationKind::Channel,
            direct_account_a: Opaque::new(Vec::new())?,
            direct_account_b: Opaque::new(Vec::new())?,
            canonical_channel_name: Opaque::from_slice(name)?,
            channel_authority_root_fingerprint: authority_root,
            semantic_incarnation: 0,
            predecessor_close_id: [0; 32],
        },
    )
}

pub(crate) fn sequencer_credential(
    secret: &Ed25519SecretKey,
    generation: u64,
    interval: (u64, u64),
    previous: Option<(&Ed25519SecretKey, &ArcSequencerCredential)>,
) -> Result<ArcSequencerCredential, E2eeError> {
    sequencer_credential_in(NETWORK, secret, generation, interval, previous)
}

/// A sequencer credential under `network_id`.
pub(crate) fn sequencer_credential_in(
    network_id: [u8; 32],
    secret: &Ed25519SecretKey,
    generation: u64,
    interval: (u64, u64),
    previous: Option<(&Ed25519SecretKey, &ArcSequencerCredential)>,
) -> Result<ArcSequencerCredential, E2eeError> {
    let previous_key_id = match previous {
        Some((_, credential)) => semantic_id_of(SemanticHashDomain::SequencerKey, &credential.tbs)?,
        None => [0; 32],
    };
    let tbs = ArcSequencerCredentialTbs {
        profile_version: 1,
        network_id,
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

/// An MLS `PrivateMessage` with the given content type and authenticated data.
pub(crate) fn private_message_bytes(
    group_id: &[u8],
    content_type: u8,
    aad: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    private_message_at_epoch(group_id, 9, content_type, aad)
}

/// An MLS `PrivateMessage` at `epoch` with the given content type and
/// authenticated data.
pub(crate) fn private_message_at_epoch(
    group_id: &[u8],
    epoch: u64,
    content_type: u8,
    aad: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let mut out = vec![0, 1, 0, 2];
    opaque_v(&mut out, group_id)?;
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(content_type);
    opaque_v(&mut out, aad)?;
    opaque_v(&mut out, &[1; 40])?;
    opaque_v(&mut out, &[2; 300])?;
    Ok(out)
}

pub(crate) fn certificate_id_of(
    principal: &Principal,
    device: u8,
) -> Result<SemanticId, E2eeError> {
    let certificate = certificate(
        &principal.root_secret,
        &principal.root,
        &DeviceSpec::new(device),
    )?;
    semantic_id_of(SemanticHashDomain::DeviceCertificateId, &certificate.tbs)
}

pub(crate) fn commit_approval(
    principal: &Principal,
    device: u8,
    tbs: &impl TlsEncode,
    domain: SignatureDomain,
) -> Result<ArcCommitApproval, E2eeError> {
    Ok(ArcCommitApproval {
        signer_root_fingerprint: root_fingerprint(&principal.root)?,
        signer_device_id: [device; 16],
        signer_device_certificate_id: certificate_id_of(principal, device)?,
        device_signature: sign(&key(device), domain, tbs)?,
    })
}

pub(crate) fn authorization_tbs(
    conversation_id: [u8; 32],
    old_policy_id: [u8; 32],
    rule: ArcCommitAuthorizationRule,
    bits: u32,
) -> ArcCommitAuthorizationTbs {
    ArcCommitAuthorizationTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id,
        prior_epoch: 0,
        prior_state_id: [50; 32],
        candidate_id: [52; 32],
        commit_object_id: [49; 32],
        canonical_validation_time: 7,
        old_policy_id,
        authorization_rule: rule,
        action_bits: bits,
        resulting_policy_id: old_policy_id,
        resulting_group_context_digest: [53; 32],
        resulting_ratchet_tree_digest: [54; 32],
        transition_target_digest: [0; 32],
    }
}

pub(crate) fn commit_authorization(
    tbs: ArcCommitAuthorizationTbs,
    approvers: &[(&Principal, u8)],
) -> Result<ArcCommitAuthorization, E2eeError> {
    let mut approvals: Vec<ArcCommitApproval> = approvers
        .iter()
        .map(|(principal, device)| {
            commit_approval(
                principal,
                *device,
                &tbs,
                SignatureDomain::CommitAuthorization,
            )
        })
        .collect::<Result<_, _>>()?;
    approvals.sort_by_key(|approval| (approval.signer_root_fingerprint, approval.signer_device_id));
    Ok(ArcCommitAuthorization {
        tbs,
        approvals: TlsVec::new(approvals)?,
    })
}

pub(crate) fn approval_envelope(
    tbs: ArcCommitAuthorizationTbs,
    principal: &Principal,
    device: u8,
) -> Result<ArcCommitApprovalEnvelope, E2eeError> {
    Ok(ArcCommitApprovalEnvelope {
        approval: commit_approval(
            principal,
            device,
            &tbs,
            SignatureDomain::CommitAuthorization,
        )?,
        tbs,
    })
}

/// One policy to sign: council, controllers, approvers, and lineage.
pub(crate) struct PolicySpec<'a> {
    pub(crate) principals: &'a [Principal],
    pub(crate) conversation_id: [u8; 32],
    pub(crate) generation: u64,
    pub(crate) previous_policy_id: [u8; 32],
    pub(crate) kind: ArcConversationKind,
    pub(crate) membership: ArcMembershipPolicy,
    /// Indices into `principals` whose roots are controllers.
    pub(crate) controllers: Vec<usize>,
    pub(crate) threshold: u16,
    /// `(principal index, device seed)` council members.
    pub(crate) council: Vec<(usize, u8)>,
    pub(crate) fault_bound: u16,
    /// `(principal index, device seed)` approvers.
    pub(crate) approvers: Vec<(usize, u8)>,
}

impl<'a> PolicySpec<'a> {
    /// The generation-zero policy of a bootstrap: every principal root is a
    /// controller at threshold one, every active device sits on the council
    /// with fault bound zero, and the first device of each root approves.
    pub(crate) fn bootstrap(
        principals: &'a [Principal],
        conversation_id: [u8; 32],
        kind: ArcConversationKind,
    ) -> Self {
        Self {
            principals,
            conversation_id,
            generation: 0,
            previous_policy_id: [0; 32],
            kind,
            membership: match kind {
                ArcConversationKind::Channel => ArcMembershipPolicy::Moderated,
                ArcConversationKind::Direct => ArcMembershipPolicy::FixedDirect,
            },
            controllers: (0..principals.len()).collect(),
            threshold: 1,
            council: principals
                .iter()
                .enumerate()
                .flat_map(|(index, principal)| {
                    principal.devices.iter().map(move |device| (index, *device))
                })
                .collect(),
            fault_bound: 0,
            approvers: principals
                .iter()
                .enumerate()
                .filter_map(|(index, principal)| {
                    principal.devices.first().map(|device| (index, *device))
                })
                .collect(),
        }
    }

    /// The next generation of this policy, otherwise unchanged.
    pub(crate) fn successor(&self, previous_policy_id: [u8; 32]) -> Self {
        Self {
            principals: self.principals,
            conversation_id: self.conversation_id,
            generation: self.generation.saturating_add(1),
            previous_policy_id,
            kind: self.kind,
            membership: self.membership,
            controllers: self.controllers.clone(),
            threshold: self.threshold,
            council: self.council.clone(),
            fault_bound: self.fault_bound,
            approvers: self.approvers.clone(),
        }
    }
}

fn principal_at(principals: &[Principal], index: usize) -> Result<&Principal, E2eeError> {
    principals.get(index).ok_or(E2eeError::InvalidValue)
}

pub(crate) fn policy_tbs(spec: &PolicySpec<'_>) -> Result<ArcPolicyTbs, E2eeError> {
    let mut controllers: Vec<[u8; 32]> = spec
        .controllers
        .iter()
        .map(|index| root_fingerprint(&principal_at(spec.principals, *index)?.root))
        .collect::<Result<_, _>>()?;
    controllers.sort_unstable();
    let mut council: Vec<ArcFinalityPrincipal> = spec
        .council
        .iter()
        .map(|(index, device)| {
            let principal = principal_at(spec.principals, *index)?;
            Ok(ArcFinalityPrincipal {
                root_fingerprint: root_fingerprint(&principal.root)?,
                device_id: [*device; 16],
                device_certificate_id: certificate_id_of(principal, *device)?,
            })
        })
        .collect::<Result<_, E2eeError>>()?;
    council.sort_by_key(|member| {
        (
            member.root_fingerprint,
            member.device_id,
            member.device_certificate_id,
        )
    });
    Ok(ArcPolicyTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: spec.conversation_id,
        policy_generation: spec.generation,
        previous_policy_id: spec.previous_policy_id,
        kind: spec.kind,
        membership_policy: spec.membership,
        mls_version: 1,
        selected_suite: 1,
        allowed_suites: TlsVec::new(vec![1, 3])?,
        controller_root_fingerprints: Opaque::new(controllers.concat())?,
        controller_threshold: spec.threshold,
        finality_principals: TlsVec::new(council)?,
        finality_fault_bound: spec.fault_bound,
        require_oob_verified_roots: 0,
        max_devices_per_account: 64,
        max_group_leaves: 512,
    })
}

/// A complete signed policy.
pub(crate) fn policy(spec: &PolicySpec<'_>) -> Result<ArcPolicy, E2eeError> {
    let tbs = policy_tbs(spec)?;
    let mut approvals: Vec<ArcPolicyApproval> = spec
        .approvers
        .iter()
        .map(|(index, device)| {
            let principal = principal_at(spec.principals, *index)?;
            Ok(ArcPolicyApproval {
                signer_root_fingerprint: root_fingerprint(&principal.root)?,
                signer_device_id: [*device; 16],
                signer_device_certificate_id: certificate_id_of(principal, *device)?,
                device_signature: sign(&key(*device), SignatureDomain::PolicyApproval, &tbs)?,
            })
        })
        .collect::<Result<_, E2eeError>>()?;
    approvals.sort_by_key(|approval| (approval.signer_root_fingerprint, approval.signer_device_id));
    Ok(ArcPolicy {
        tbs,
        approvals: TlsVec::new(approvals)?,
    })
}

/// The Section 2.2 identifier of a policy.
pub(crate) fn policy_id_of(policy: &ArcPolicy) -> Result<SemanticId, E2eeError> {
    semantic_id_of(SemanticHashDomain::PolicyId, &policy.tbs)
}

pub(crate) fn finality_vote(
    principal: &Principal,
    device: u8,
    tbs: &ArcDispositionVoteTbs,
) -> Result<ArcFinalityVote, E2eeError> {
    Ok(ArcFinalityVote {
        signer_root_fingerprint: root_fingerprint(&principal.root)?,
        signer_device_id: [device; 16],
        signer_device_certificate_id: certificate_id_of(principal, device)?,
        device_signature: sign(&key(device), SignatureDomain::DispositionVote, tbs)?,
    })
}

/// One old leaf a device attests to (companion 13.7.3).
pub(crate) struct MembershipSpec<'a> {
    pub(crate) principal: &'a Principal,
    pub(crate) conversation_id: [u8; 32],
    pub(crate) device: u8,
    pub(crate) leaf_seed: u8,
    pub(crate) leaf_index: u32,
    pub(crate) old_credential_hash: [u8; 32],
    pub(crate) epoch: u64,
    pub(crate) removed: Option<[u8; 32]>,
}

impl<'a> MembershipSpec<'a> {
    /// A continuing proof for `leaf_index` at epoch zero, whose credential
    /// hash repeats the leaf index so distinct leaves never collide.
    pub(crate) fn continuing(
        principal: &'a Principal,
        conversation_id: [u8; 32],
        device: u8,
        leaf_seed: u8,
        leaf_index: u32,
    ) -> Self {
        let tag = u8::try_from(leaf_index % 200).unwrap_or(0).wrapping_add(1);
        Self {
            principal,
            conversation_id,
            device,
            leaf_seed,
            leaf_index,
            old_credential_hash: [tag; 32],
            epoch: 0,
            removed: None,
        }
    }
}

/// A leaf-membership proof signed by the device and, for a continuing
/// leaf, by the old leaf key.
pub(crate) fn membership_proof(
    spec: &MembershipSpec<'_>,
) -> Result<agenc_relay_e2ee::objects::membership::ArcLeafMembershipProof, E2eeError> {
    use agenc_relay_e2ee::objects::membership::{
        ArcLeafDispositionKind, ArcLeafMembershipProof, ArcLeafMembershipProofTbs,
    };
    let principal = spec.principal;
    let tbs = ArcLeafMembershipProofTbs {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: spec.conversation_id,
        epoch: spec.epoch,
        leaf_index: spec.leaf_index,
        old_credential_hash: spec.old_credential_hash,
        leaf_signature_scheme: 0x0807,
        leaf_signature_key: Opaque::from_slice(&public(&key(spec.leaf_seed)))?,
        account_id: principal.root.tbs.account_id.clone(),
        device_id: [spec.device; 16],
        root_generation: principal.root.tbs.root_generation,
        root_fingerprint: root_fingerprint(&principal.root)?,
        roster_generation: principal.roster.tbs.roster_generation,
        roster_id: roster_id(&principal.roster)?,
        credential_generation: 0,
        disposition: if spec.removed.is_some() {
            ArcLeafDispositionKind::Removed
        } else {
            ArcLeafDispositionKind::Continuing
        },
        removal_finalization_id: spec.removed.unwrap_or([0; 32]),
    };
    let possession = if spec.removed.is_some() {
        Vec::new()
    } else {
        sign(
            &key(spec.leaf_seed),
            SignatureDomain::LeafMembershipPossession,
            &tbs,
        )?
        .to_vec()
    };
    Ok(ArcLeafMembershipProof {
        device_signature: sign(&key(spec.device), SignatureDomain::LeafMembership, &tbs)?,
        possession_signature: Opaque::new(possession)?,
        tbs,
    })
}

impl crate::e2ee::coordinator::CompanionCoordinator {
    /// Whether the request or payload object `object_id` of the request
    /// `correlation` names, from `peer`, keeps a recent tuple.
    pub(crate) fn holds_request_object(
        &self,
        peer: agenc_relay_types::ServerId,
        correlation: &agenc_relay_e2ee::federation::frames::Correlation,
        object_id: [u8; 32],
    ) -> bool {
        self.assembler.is_recent(&Self::assembly_key(
            peer,
            correlation,
            request_command(),
            object_id,
        ))
    }

    /// Completes `bytes` from `peer` at `now_millis` as an object of the
    /// request `correlation` names, the way its payload assembles.
    pub(crate) fn complete_request_object(
        &mut self,
        peer: agenc_relay_types::ServerId,
        correlation: &agenc_relay_e2ee::federation::frames::Correlation,
        bytes: &[u8],
        now_millis: u64,
    ) -> Result<(), crate::e2ee::coordinator::CompanionFault> {
        use crate::e2ee::coordinator::CompanionFault;
        let object_id = *agenc_relay_e2ee::ObjectId::compute(bytes).as_bytes();
        let key = Self::assembly_key(peer, correlation, request_command(), object_id);
        let fragments = agenc_relay_e2ee::wire::fragment::fragment_object(bytes)
            .map_err(|_| CompanionFault::Protocol)?;
        for fragment in fragments {
            let _progress = self.ingest(
                key.clone(),
                peer,
                agenc_relay_e2ee::wire::carrier::CarrierCommand::DeliverWelcome,
                &fragment,
                now_millis,
            )?;
        }
        Ok(())
    }
}

/// The carrier every request and payload object assembles under.
fn request_command() -> agenc_relay_e2ee::wire::carrier::CarrierCommand {
    agenc_relay_e2ee::wire::carrier::CarrierCommand::Federation(
        agenc_relay_e2ee::object::ArcWireObjectKind::FederationRequest,
    )
}
