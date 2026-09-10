//! Test-only builders that mint keys and sign every companion object a
//! client would (identities, device certificates, rosters, capabilities,
//! leaf authorizations, KeyPackages, binding packages, sequencer
//! credentials, commit authorizations, and finality votes). They sign for
//! [`NETWORK`] and hold every private key in memory; nothing here belongs in
//! a production crate.

// agenc-review: allow owner=testkit reviewed=2026-09-03 reason=the builders mirror the companion object fields one to one and their names are the specification's own
#![allow(missing_docs)]

use agenc_ircd_crypto::{Ed25519SecretKey, SemanticHashDomain, SignatureDomain, sign_canonical};

use agenc_ircd_e2ee::E2eeError;
use agenc_ircd_e2ee::ids::{SemanticId, semantic_id_of};
use agenc_ircd_e2ee::mls_outer::mls_varint_encode;
use agenc_ircd_e2ee::objects::AccountIdField;
use agenc_ircd_e2ee::objects::conversation::{
    IrcCommitApproval, IrcCommitApprovalEnvelope, IrcCommitAuthorization,
    IrcCommitAuthorizationRule, IrcCommitAuthorizationTbs, IrcConversationKind,
    IrcFinalityPrincipal, IrcMembershipPolicy, IrcPolicy, IrcPolicyApproval, IrcPolicyTbs,
    IrcSequencerCredential, IrcSequencerCredentialTbs,
};
use agenc_ircd_e2ee::objects::identity::*;
use agenc_ircd_e2ee::objects::sequencing::{IrcDispositionVoteTbs, IrcFinalityVote};
use agenc_ircd_e2ee::tls::{Opaque, TlsEncode, TlsVec};

/// The network every builder signs for; the three-process tests use it too.
pub const NETWORK: [u8; 32] = [1; 32];

pub fn key(seed: u8) -> Ed25519SecretKey {
    Ed25519SecretKey::from_bytes([seed; 32])
}

pub fn public(secret: &Ed25519SecretKey) -> [u8; 32] {
    *secret.public_key().as_bytes()
}

pub fn sign(
    secret: &Ed25519SecretKey,
    domain: SignatureDomain,
    tbs: &impl TlsEncode,
) -> Result<[u8; 64], E2eeError> {
    let encoded = tbs.encode()?;
    sign_canonical(secret, domain, &encoded)
        .map(|signature| *signature.as_bytes())
        .map_err(|_| E2eeError::SignatureInvalid)
}

pub fn account_field(account: &[u8; 24]) -> Result<AccountIdField, E2eeError> {
    Opaque::from_slice(account)
}

/// A root identity signed by `secret`, continuing `previous` when given.
pub fn root(
    secret: &Ed25519SecretKey,
    account: &[u8; 24],
    generation: u64,
    interval: (u64, u64),
    previous: Option<(&Ed25519SecretKey, &IrcRootIdentity)>,
) -> Result<IrcRootIdentity, E2eeError> {
    let previous_root_fingerprint = match previous {
        Some((_, previous_root)) => root_fingerprint(previous_root)?,
        None => [0; 32],
    };
    let tbs = IrcRootIdentityTbs {
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
    Ok(IrcRootIdentity {
        tbs,
        self_signature,
        continuity_signature: Opaque::new(continuity)?,
    })
}

/// Root binding lock identifiers by account.
pub type LockIds = Vec<([u8; 24], [u8; 32])>;

/// The lock identifier of each root binding lock of `package`, by account.
pub fn lock_ids(
    package: &agenc_ircd_e2ee::objects::conversation::IrcConversationBindingPackage,
) -> Result<LockIds, E2eeError> {
    package
        .root_binding_locks
        .as_slice()
        .iter()
        .map(|lock| {
            Ok((
                lock.tbs.account_id.exactly::<24>()?,
                semantic_id_of(SemanticHashDomain::RootBindingLockId, &lock.tbs)?,
            ))
        })
        .collect()
}

pub fn root_fingerprint(root: &IrcRootIdentity) -> Result<SemanticId, E2eeError> {
    semantic_id_of(SemanticHashDomain::RootFingerprint, &root.tbs)
}

pub struct DeviceSpec {
    pub seed: u8,
    pub device_id: [u8; 16],
    pub flags: u32,
    pub target_roster_generation: u64,
    pub interval: (u64, u64),
    pub enrollment: (u64, u64),
    pub serial: u64,
}

impl DeviceSpec {
    pub fn new(seed: u8) -> Self {
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

pub fn certificate(
    root_secret: &Ed25519SecretKey,
    root: &IrcRootIdentity,
    spec: &DeviceSpec,
) -> Result<IrcDeviceCertificate, E2eeError> {
    let device_secret = key(spec.seed);
    let enrollment_tbs = IrcDeviceEnrollmentTbs {
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
    let enrollment = IrcDeviceEnrollment {
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
    let tbs = IrcDeviceCertificateTbs {
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
    Ok(IrcDeviceCertificate {
        root_signature: sign(root_secret, SignatureDomain::DeviceCertificate, &tbs)?,
        tbs,
        enrollment_proof: enrollment,
    })
}

pub fn roster(
    root_secret: &Ed25519SecretKey,
    root: &IrcRootIdentity,
    generation: u64,
    previous_roster_id: [u8; 32],
    interval: (u64, u64),
    certificates: Vec<IrcDeviceCertificate>,
    revocations: Vec<IrcDeviceRevocation>,
) -> Result<IrcDeviceRoster, E2eeError> {
    let active = certificates
        .into_iter()
        .map(|certificate| IrcActiveDevice {
            device_id: certificate.tbs.device_id,
            certificate,
        })
        .collect();
    let tbs = IrcDeviceRosterTbs {
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
    Ok(IrcDeviceRoster {
        root_signature: sign(root_secret, SignatureDomain::DeviceRoster, &tbs)?,
        tbs,
    })
}

pub fn roster_id(roster: &IrcDeviceRoster) -> Result<SemanticId, E2eeError> {
    semantic_id_of(SemanticHashDomain::RosterId, &roster.tbs)
}

pub fn capabilities(
    device_seed: u8,
    roster: &IrcDeviceRoster,
    generation: u64,
    previous_capability_id: [u8; 32],
    interval: (u64, u64),
    suites: Vec<u16>,
) -> Result<IrcDeviceCapabilities, E2eeError> {
    let tbs = IrcDeviceCapabilitiesTbs {
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
    Ok(IrcDeviceCapabilities {
        device_signature: sign(&key(device_seed), SignatureDomain::DeviceCapabilities, &tbs)?,
        tbs,
    })
}

pub struct LeafSpec {
    pub device_seed: u8,
    pub leaf_seed: u8,
    pub suite: u16,
    pub interval: (u64, u64),
    pub capabilities_hash: [u8; 32],
    pub last_resort: u8,
    pub credential_generation: u64,
}

impl LeafSpec {
    pub fn new(device_seed: u8, leaf_seed: u8) -> Self {
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

pub fn leaf_authorization(
    roster: &IrcDeviceRoster,
    spec: &LeafSpec,
) -> Result<IrcLeafAuthorization, E2eeError> {
    leaf_authorization_for_key(roster, spec, &public(&key(spec.leaf_seed)))
}

/// A leaf authorization over `leaf_public_key`, the signature key an MLS
/// library generated, signed by the device of `spec`.
pub fn leaf_authorization_for_key(
    roster: &IrcDeviceRoster,
    spec: &LeafSpec,
    leaf_public_key: &[u8],
) -> Result<IrcLeafAuthorization, E2eeError> {
    let tbs = IrcLeafAuthorizationTbs {
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
        leaf_signature_key: Opaque::new(leaf_public_key.to_vec())?,
        leaf_capabilities_hash: spec.capabilities_hash,
        package_nonce: [spec.leaf_seed; 32],
        last_resort: spec.last_resort,
        not_before: spec.interval.0,
        not_after: spec.interval.1,
    };
    Ok(IrcLeafAuthorization {
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
pub struct KeyPackageSpec<'a> {
    pub identity: &'a [u8],
    pub leaf_seed: u8,
    pub suite: u16,
    pub lifetime: (u64, u64),
    pub capabilities: Vec<Vec<u8>>,
    pub leaf_extensions: Vec<(u16, Vec<u8>)>,
}

pub fn opaque_v(output: &mut Vec<u8>, bytes: &[u8]) -> Result<(), E2eeError> {
    mls_varint_encode(output, bytes.len())?;
    output.extend_from_slice(bytes);
    Ok(())
}

pub fn default_capabilities() -> Vec<Vec<u8>> {
    vec![
        vec![0, 1],
        vec![0, 1, 0, 3],
        Vec::new(),
        Vec::new(),
        vec![0, 1],
    ]
}

pub fn key_package(spec: &KeyPackageSpec<'_>) -> Result<Vec<u8>, E2eeError> {
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
pub fn encoded_capabilities(vectors: &[Vec<u8>]) -> Result<Vec<u8>, E2eeError> {
    let mut out = Vec::new();
    for vector in vectors {
        opaque_v(&mut out, vector)?;
    }
    Ok(out)
}

/// A principal for a binding package: its root secret, root, and roster.
pub struct Principal {
    pub root_secret: Ed25519SecretKey,
    pub root: IrcRootIdentity,
    pub roster: IrcDeviceRoster,
    /// Device seeds active in the roster, all with binding authority.
    pub devices: Vec<u8>,
}

pub fn principal(
    root_seed: u8,
    account: &[u8; 24],
    devices: &[u8],
) -> Result<Principal, E2eeError> {
    principal_with_intervals(
        root_seed,
        account,
        devices,
        (0, 2_000_000),
        (100, 100 + 6 * 24 * 3600),
    )
}

/// A principal whose root, certificates, and roster are valid around the
/// wall-clock second `now`, for MLS libraries that check leaf lifetimes
/// against their own clock: the roster spans six days from one hour ago.
pub fn principal_valid_at(
    root_seed: u8,
    account: &[u8; 24],
    devices: &[u8],
    now: u64,
) -> Result<Principal, E2eeError> {
    let start = now.saturating_sub(3_600);
    principal_with_intervals(
        root_seed,
        account,
        devices,
        (0, now.saturating_add(30 * 24 * 3_600)),
        (start, start.saturating_add(6 * 24 * 3_600)),
    )
}

fn principal_with_intervals(
    root_seed: u8,
    account: &[u8; 24],
    devices: &[u8],
    root_interval: (u64, u64),
    roster_interval: (u64, u64),
) -> Result<Principal, E2eeError> {
    let root_secret = key(root_seed);
    let root = root(&root_secret, account, 0, root_interval, None)?;
    let mut certificates = devices
        .iter()
        .map(|seed| {
            // The roster opens inside each certificate's enrollment window.
            let spec = DeviceSpec {
                interval: (0, root_interval.1),
                enrollment: (roster_interval.0.saturating_sub(10), roster_interval.0),
                ..DeviceSpec::new(*seed)
            };
            certificate(&root_secret, &root, &spec)
        })
        .collect::<Result<Vec<_>, _>>()?;
    certificates.sort_by_key(|certificate| certificate.tbs.device_id);
    let roster = roster(
        &root_secret,
        &root,
        0,
        [0; 32],
        roster_interval,
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

pub struct BindingSpec<'a> {
    pub principals: &'a [&'a Principal],
    pub route: agenc_ircd_e2ee::objects::conversation::IrcSemanticRouteTbs,
    pub channel_instance_id: Option<[u8; 16]>,
    pub conversation_nonce: Option<[u8; 32]>,
    pub group_id: [u8; 32],
    pub generation: u64,
    pub previous_binding_id: [u8; 32],
    pub lock_sequence: u64,
    /// The previous lock identifier per account when `lock_sequence` is
    /// not zero.
    pub previous_lock_ids: LockIds,
    pub plan_devices: Vec<(&'a [u8; 24], [u8; 32], u8)>,
    /// The binding's generation-zero policy identifier.
    pub initial_policy_id: [u8; 32],
    /// The binding's required operational policy identifier.
    pub required_operational_policy_id: [u8; 32],
}

/// A complete binding package signed by every binding-authorized device of
/// every principal, with one root lock per principal.
// agenc-review: focus owner=testkit reviewed=2026-09-03 reason=the binding package builder fills every field of the companion object in specification order so a reviewer can diff it against the table
pub fn binding_package(
    spec: &BindingSpec<'_>,
) -> Result<agenc_ircd_e2ee::objects::conversation::IrcConversationBindingPackage, E2eeError> {
    use agenc_ircd_e2ee::objects::conversation::*;
    let lock_id = semantic_id_of(SemanticHashDomain::SemanticRouteLock, &spec.route)?;
    let route_binding = match (spec.channel_instance_id, spec.conversation_nonce) {
        (Some(instance), None) => {
            agenc_ircd_e2ee::route::channel_route_binding(&NETWORK, &instance)?
        }
        (None, Some(nonce)) => {
            let a = spec.route.direct_account_a.exactly::<24>()?;
            let b = spec.route.direct_account_b.exactly::<24>()?;
            agenc_ircd_e2ee::route::direct_route_binding(&NETWORK, &nonce, &a, &b)?
        }
        _ => return Err(E2eeError::InvalidValue),
    };
    let mut principals: Vec<IrcBindingPrincipal> = spec
        .principals
        .iter()
        .map(|principal| {
            Ok(IrcBindingPrincipal {
                account_id: principal.root.tbs.account_id.clone(),
                root_fingerprint: root_fingerprint(&principal.root)?,
                roster_generation: 0,
                roster_id: roster_id(&principal.roster)?,
            })
        })
        .collect::<Result<_, E2eeError>>()?;
    principals.sort_by_key(|principal| principal.account_id.clone());
    let mut entries: Vec<IrcInitialMemberPlanEntry> = spec
        .plan_devices
        .iter()
        .map(|(account, fingerprint, device)| {
            Ok(IrcInitialMemberPlanEntry {
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
    let plan = IrcInitialMemberPlan {
        entries: TlsVec::new(entries)?,
    };
    let tbs = IrcConversationBindingTbs {
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
        conversation_id: agenc_ircd_e2ee::ids::conversation_id(&NETWORK, &spec.group_id)?,
        route_binding,
        mls_version: 1,
        cipher_suite: 1,
        initial_policy_id: spec.initial_policy_id,
        required_operational_policy_id: spec.required_operational_policy_id,
        initial_member_plan_id: semantic_id_of(SemanticHashDomain::InitialMemberPlanId, &plan)?,
        context_core_id: [30; 32],
        sequencer_credential_id: [31; 32],
        principals: TlsVec::new(principals)?,
    };
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &tbs)?;
    let mut approvals = Vec::new();
    let mut locks = Vec::new();
    if spec.generation == 0 {
        for principal in spec.principals {
            let fingerprint = root_fingerprint(&principal.root)?;
            for device in &principal.devices {
                approvals.push(IrcBindingApproval {
                    signer_root_fingerprint: fingerprint,
                    signer_device_id: [*device; 16],
                    signer_device_certificate_id: certificate_id_of(principal, *device)?,
                    device_signature: sign(
                        &key(*device),
                        SignatureDomain::ConversationBinding,
                        &tbs,
                    )?,
                });
            }
            let lock_tbs = IrcRootBindingLockTbs {
                profile_version: 1,
                network_id: NETWORK,
                account_id: principal.root.tbs.account_id.clone(),
                root_fingerprint: fingerprint,
                root_binding_sequence: spec.lock_sequence,
                previous_root_binding_lock_id: if spec.lock_sequence == 0 {
                    [0; 32]
                } else {
                    let account = principal.root.tbs.account_id.exactly::<24>()?;
                    spec.previous_lock_ids
                        .iter()
                        .find(|(previous, _)| *previous == account)
                        .map(|(_, id)| *id)
                        .ok_or(E2eeError::InvalidValue)?
                },
                semantic_route_lock_id: lock_id,
                binding_id,
                roster_generation: 0,
                roster_id: roster_id(&principal.roster)?,
            };
            locks.push(IrcRootBindingLock {
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
    Ok(IrcConversationBindingPackage {
        binding: IrcConversationBinding {
            tbs,
            approvals: TlsVec::new(approvals)?,
        },
        initial_member_plan: plan,
        root_binding_locks: TlsVec::new(locks)?,
    })
}

pub fn channel_route(
    name: &[u8],
    authority_root: [u8; 32],
) -> Result<agenc_ircd_e2ee::objects::conversation::IrcSemanticRouteTbs, E2eeError> {
    Ok(
        agenc_ircd_e2ee::objects::conversation::IrcSemanticRouteTbs {
            profile_version: 1,
            network_id: NETWORK,
            kind: agenc_ircd_e2ee::objects::conversation::IrcConversationKind::Channel,
            direct_account_a: Opaque::new(Vec::new())?,
            direct_account_b: Opaque::new(Vec::new())?,
            canonical_channel_name: Opaque::from_slice(name)?,
            channel_authority_root_fingerprint: authority_root,
            semantic_incarnation: 0,
            predecessor_close_id: [0; 32],
        },
    )
}

pub fn sequencer_credential(
    secret: &Ed25519SecretKey,
    generation: u64,
    interval: (u64, u64),
    previous: Option<(&Ed25519SecretKey, &IrcSequencerCredential)>,
) -> Result<IrcSequencerCredential, E2eeError> {
    sequencer_credential_in(NETWORK, secret, generation, interval, previous)
}

/// A sequencer credential under `network_id`.
pub fn sequencer_credential_in(
    network_id: [u8; 32],
    secret: &Ed25519SecretKey,
    generation: u64,
    interval: (u64, u64),
    previous: Option<(&Ed25519SecretKey, &IrcSequencerCredential)>,
) -> Result<IrcSequencerCredential, E2eeError> {
    let previous_key_id = match previous {
        Some((_, credential)) => semantic_id_of(SemanticHashDomain::SequencerKey, &credential.tbs)?,
        None => [0; 32],
    };
    let tbs = IrcSequencerCredentialTbs {
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
    Ok(IrcSequencerCredential {
        tbs,
        continuity_signature: Opaque::new(continuity)?,
    })
}

/// An MLS `PrivateMessage` with the given content type and authenticated data.
pub fn private_message_bytes(
    group_id: &[u8],
    content_type: u8,
    aad: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    private_message_at_epoch(group_id, 9, content_type, aad)
}

/// An MLS `PrivateMessage` at `epoch` with the given content type and
/// authenticated data.
pub fn private_message_at_epoch(
    group_id: &[u8],
    epoch: u64,
    content_type: u8,
    aad: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    private_message_with_ciphertext(group_id, epoch, content_type, aad, &[2; 300])
}

/// An MLS `PrivateMessage` at `epoch` whose opaque ciphertext is
/// `ciphertext`, so two messages of one test differ as real ones would.
pub fn private_message_with_ciphertext(
    group_id: &[u8],
    epoch: u64,
    content_type: u8,
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, E2eeError> {
    let mut out = vec![0, 1, 0, 2];
    opaque_v(&mut out, group_id)?;
    out.extend_from_slice(&epoch.to_be_bytes());
    out.push(content_type);
    opaque_v(&mut out, aad)?;
    opaque_v(&mut out, &[1; 40])?;
    opaque_v(&mut out, ciphertext)?;
    Ok(out)
}

/// The roster's active certificate of `device`.
pub fn active_certificate(
    principal: &Principal,
    device: u8,
) -> Result<IrcDeviceCertificate, E2eeError> {
    principal
        .roster
        .tbs
        .active_devices
        .as_slice()
        .iter()
        .find(|entry| entry.device_id == [device; 16])
        .map(|entry| entry.certificate.clone())
        .ok_or(E2eeError::InvalidValue)
}

/// The identifier of the roster's active certificate of `device`.
pub fn certificate_id_of(principal: &Principal, device: u8) -> Result<SemanticId, E2eeError> {
    let certificate = active_certificate(principal, device)?;
    semantic_id_of(SemanticHashDomain::DeviceCertificateId, &certificate.tbs)
}

pub fn commit_approval(
    principal: &Principal,
    device: u8,
    tbs: &impl TlsEncode,
    domain: SignatureDomain,
) -> Result<IrcCommitApproval, E2eeError> {
    Ok(IrcCommitApproval {
        signer_root_fingerprint: root_fingerprint(&principal.root)?,
        signer_device_id: [device; 16],
        signer_device_certificate_id: certificate_id_of(principal, device)?,
        device_signature: sign(&key(device), domain, tbs)?,
    })
}

pub fn authorization_tbs(
    conversation_id: [u8; 32],
    old_policy_id: [u8; 32],
    rule: IrcCommitAuthorizationRule,
    bits: u32,
) -> IrcCommitAuthorizationTbs {
    IrcCommitAuthorizationTbs {
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

pub fn commit_authorization(
    tbs: IrcCommitAuthorizationTbs,
    approvers: &[(&Principal, u8)],
) -> Result<IrcCommitAuthorization, E2eeError> {
    let mut approvals: Vec<IrcCommitApproval> = approvers
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
    Ok(IrcCommitAuthorization {
        tbs,
        approvals: TlsVec::new(approvals)?,
    })
}

pub fn approval_envelope(
    tbs: IrcCommitAuthorizationTbs,
    principal: &Principal,
    device: u8,
) -> Result<IrcCommitApprovalEnvelope, E2eeError> {
    Ok(IrcCommitApprovalEnvelope {
        approval: commit_approval(
            principal,
            device,
            &tbs,
            SignatureDomain::CommitAuthorization,
        )?,
        tbs,
    })
}

/// One policy to sign: council, controllers, approvers, and lineage
/// (companion 9.3).
pub struct PolicySpec<'a> {
    pub principals: &'a [&'a Principal],
    pub conversation_id: [u8; 32],
    pub generation: u64,
    pub previous_policy_id: [u8; 32],
    pub kind: IrcConversationKind,
    pub membership: IrcMembershipPolicy,
    /// Indices into `principals` whose roots are controllers.
    pub controllers: Vec<usize>,
    pub threshold: u16,
    /// `(principal index, device seed)` council members.
    pub council: Vec<(usize, u8)>,
    pub fault_bound: u16,
    /// `(principal index, device seed)` approvers.
    pub approvers: Vec<(usize, u8)>,
}

fn membership_of(kind: IrcConversationKind) -> IrcMembershipPolicy {
    match kind {
        IrcConversationKind::Channel => IrcMembershipPolicy::Moderated,
        IrcConversationKind::Direct => IrcMembershipPolicy::FixedDirect,
    }
}

impl<'a> PolicySpec<'a> {
    /// The creator-only bootstrap policy of generation zero (companion
    /// 13.2 step 4): the first principal's root is the sole controller and
    /// its first device the whole council, so `n = 1`, `f = 0`, `q = 1`.
    pub fn bootstrap(
        principals: &'a [&'a Principal],
        conversation_id: [u8; 32],
        kind: IrcConversationKind,
    ) -> Result<Self, E2eeError> {
        let creator = principals.first().ok_or(E2eeError::InvalidValue)?;
        let device = *creator.devices.first().ok_or(E2eeError::InvalidValue)?;
        Ok(Self {
            principals,
            conversation_id,
            generation: 0,
            previous_policy_id: [0; 32],
            kind,
            membership: IrcMembershipPolicy::Moderated,
            controllers: vec![0],
            threshold: 1,
            council: vec![(0, device)],
            fault_bound: 0,
            approvers: vec![(0, device)],
        })
    }

    /// The generation-one operational policy: every principal root is a
    /// controller, at threshold one for a channel and two for a fixed
    /// direct pair, and every device sits on the council with fault bound
    /// zero. The creator approves it under the bootstrap policy's
    /// controller set.
    pub fn operational(
        principals: &'a [&'a Principal],
        conversation_id: [u8; 32],
        kind: IrcConversationKind,
        previous_policy_id: [u8; 32],
    ) -> Result<Self, E2eeError> {
        let creator = principals.first().ok_or(E2eeError::InvalidValue)?;
        let device = *creator.devices.first().ok_or(E2eeError::InvalidValue)?;
        Ok(Self {
            principals,
            conversation_id,
            generation: 1,
            previous_policy_id,
            kind,
            membership: membership_of(kind),
            controllers: (0..principals.len()).collect(),
            threshold: match kind {
                IrcConversationKind::Channel => 1,
                IrcConversationKind::Direct => 2,
            },
            council: principals
                .iter()
                .enumerate()
                .flat_map(|(index, principal)| {
                    principal.devices.iter().map(move |device| (index, *device))
                })
                .collect(),
            fault_bound: 0,
            approvers: vec![(0, device)],
        })
    }
}

fn principal_at<'a>(
    principals: &'a [&'a Principal],
    index: usize,
) -> Result<&'a Principal, E2eeError> {
    principals
        .get(index)
        .copied()
        .ok_or(E2eeError::InvalidValue)
}

/// The signed fields of a policy.
pub fn policy_tbs(spec: &PolicySpec<'_>) -> Result<IrcPolicyTbs, E2eeError> {
    let mut controllers: Vec<[u8; 32]> = spec
        .controllers
        .iter()
        .map(|index| root_fingerprint(&principal_at(spec.principals, *index)?.root))
        .collect::<Result<_, _>>()?;
    controllers.sort_unstable();
    let mut council: Vec<IrcFinalityPrincipal> = spec
        .council
        .iter()
        .map(|(index, device)| {
            let principal = principal_at(spec.principals, *index)?;
            Ok(IrcFinalityPrincipal {
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
    Ok(IrcPolicyTbs {
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
pub fn policy(spec: &PolicySpec<'_>) -> Result<IrcPolicy, E2eeError> {
    let tbs = policy_tbs(spec)?;
    let mut approvals: Vec<IrcPolicyApproval> = spec
        .approvers
        .iter()
        .map(|(index, device)| {
            let principal = principal_at(spec.principals, *index)?;
            Ok(IrcPolicyApproval {
                signer_root_fingerprint: root_fingerprint(&principal.root)?,
                signer_device_id: [*device; 16],
                signer_device_certificate_id: certificate_id_of(principal, *device)?,
                device_signature: sign(&key(*device), SignatureDomain::PolicyApproval, &tbs)?,
            })
        })
        .collect::<Result<_, E2eeError>>()?;
    approvals.sort_by_key(|approval| (approval.signer_root_fingerprint, approval.signer_device_id));
    Ok(IrcPolicy {
        tbs,
        approvals: TlsVec::new(approvals)?,
    })
}

/// The credential bundle an MLS leaf of `device` carries as its basic
/// credential identity: the root, the device certificate, and the leaf
/// authorization over the library's signature key.
pub fn credential_bundle(
    principal: &Principal,
    device: u8,
    leaf_authorization: IrcLeafAuthorization,
) -> Result<IrcCredentialBundle, E2eeError> {
    let device_certificate = active_certificate(principal, device)?;
    Ok(IrcCredentialBundle {
        root: principal.root.clone(),
        device_certificate,
        leaf_authorization,
    })
}

/// The Section 2.2 identifier of a policy.
pub fn policy_id_of(policy: &IrcPolicy) -> Result<SemanticId, E2eeError> {
    semantic_id_of(SemanticHashDomain::PolicyId, &policy.tbs)
}

pub fn finality_vote(
    principal: &Principal,
    device: u8,
    tbs: &IrcDispositionVoteTbs,
) -> Result<IrcFinalityVote, E2eeError> {
    Ok(IrcFinalityVote {
        signer_root_fingerprint: root_fingerprint(&principal.root)?,
        signer_device_id: [device; 16],
        signer_device_certificate_id: certificate_id_of(principal, device)?,
        device_signature: sign(&key(device), SignatureDomain::DispositionVote, tbs)?,
    })
}

/// The `e2ee.sequencer_credentials_file` document for one sequencer key:
/// generation zero, a single credential valid over `interval`.
/// A credentials document for set generation 1 whose credential chains from
/// the generation-0 credential `previous` signed, so a rotated sequencer key
/// carries its signed continuity.
pub fn sequencer_rotation_document(
    network_id: [u8; 32],
    previous: &Ed25519SecretKey,
    next: &Ed25519SecretKey,
    interval: (u64, u64),
) -> Result<Vec<u8>, E2eeError> {
    use agenc_ircd_e2ee::sequencer::SequencerCredentialsFile;
    let previous_credential = sequencer_credential_in(network_id, previous, 0, interval, None)?;
    let credential = sequencer_credential_in(
        network_id,
        next,
        1,
        interval,
        Some((previous, &previous_credential)),
    )?;
    let document = SequencerCredentialsFile {
        set_generation: 1,
        credentials: TlsVec::new(vec![previous_credential, credential])?,
    };
    document.encode()
}

pub fn sequencer_credentials_document(
    network_id: [u8; 32],
    secret: &Ed25519SecretKey,
    interval: (u64, u64),
) -> Result<Vec<u8>, E2eeError> {
    use agenc_ircd_e2ee::sequencer::SequencerCredentialsFile;
    let credential = sequencer_credential_in(network_id, secret, 0, interval, None)?;
    let document = SequencerCredentialsFile {
        set_generation: 0,
        credentials: TlsVec::new(vec![credential])?,
    };
    document.encode()
}
