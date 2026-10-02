//! Identity, device, roster, capability, and leaf-authorization validation
//! (companion Section 8).
//!
//! Every function takes decoded objects plus the already verified context
//! they must agree with, and returns a verified view carrying only public
//! material. Time is a caller-supplied validation second; no clock is read.
//! Endpoint-only: trust-on-first-use pins, verified-mode policy, safety
//! numbers, and the stale-send grace, which need a client's local pin store.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use agenc_relay_crypto::{SemanticHashDomain, SignatureDomain};

use crate::error::E2eeError;
use crate::ids::{SemanticId, semantic_id_of};
use crate::limits::{
    ENROLLMENT_CHALLENGE_TIMEOUT_SECONDS, MAX_ACTIVE_DEVICES_PER_ACCOUNT,
    MAX_CAPABILITY_LIFETIME_SECONDS, MAX_CREDENTIAL_BUNDLE, MAX_KEY_PACKAGE_LIFETIME_SECONDS,
    MAX_ROSTER_AGE_AT_ADD_SECONDS, MAX_ROSTER_LIFETIME_SECONDS, MLS_VERSION_MLS10, PROFILE_VERSION,
    SIGNATURE_SCHEME_ED25519, suite_is_enabled,
};
use crate::mls_outer::PublicKeyPackage;
use crate::objects::identity::{
    ArcCredentialBundle, ArcDeviceCapabilities, ArcDeviceCertificate, ArcDeviceCertificateTbs,
    ArcDeviceEnrollmentTbs, ArcDeviceRoster, ArcDeviceRosterTbs, ArcLeafAuthorization,
    ArcLeafAuthorizationTbs, ArcRootIdentity, KNOWN_AUTHORIZATION_FLAGS,
};
use crate::objects::{ACCOUNT_ID_BYTES, account_id_bytes};
use crate::signature::{RoleKey, SignerRole};
use crate::tls::{TlsDecode, TlsEncode, ensure_canonical};

/// One canonical Account ID.
pub type AccountIdBytes = [u8; ACCOUNT_ID_BYTES];

/// The canonical validation second every time check uses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ValidationTime(pub u64);

/// A validity interval in seconds, `not_before < not_after`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Interval {
    /// Earliest valid second.
    pub not_before: u64,
    /// Latest valid second.
    pub not_after: u64,
}

impl Interval {
    fn ordered(not_before: u64, not_after: u64) -> Result<Self, E2eeError> {
        if not_before < not_after {
            Ok(Self {
                not_before,
                not_after,
            })
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// Whether `time` lies inside the interval, both ends inclusive.
    #[must_use]
    pub const fn covers(&self, time: ValidationTime) -> bool {
        self.not_before <= time.0 && time.0 <= self.not_after
    }

    /// Whether this interval lies inside `outer`.
    #[must_use]
    pub const fn within(&self, outer: &Self) -> bool {
        outer.not_before <= self.not_before && self.not_after <= outer.not_after
    }

    fn span(&self) -> u64 {
        self.not_after.saturating_sub(self.not_before)
    }
}

/// A verified root identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedRoot {
    /// Network identity.
    pub network_id: [u8; 32],
    /// Account ID.
    pub account_id: AccountIdBytes,
    /// Root generation.
    pub generation: u64,
    /// Root fingerprint.
    pub fingerprint: SemanticId,
    /// Root public key.
    pub key: RoleKey,
    /// Validity.
    pub interval: Interval,
}

/// Verifies one root identity against its optional continuous predecessor.
pub fn verify_root_identity(
    network_id: &[u8; 32],
    root: &ArcRootIdentity,
    predecessor: Option<&VerifiedRoot>,
) -> Result<VerifiedRoot, E2eeError> {
    let tbs = &root.tbs;
    if tbs.profile_version != PROFILE_VERSION || tbs.network_id != *network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    let account_id = account_id_bytes(&tbs.account_id)?;
    let interval = Interval::ordered(tbs.not_before, tbs.not_after)?;
    let key = RoleKey::new(SignerRole::Root, tbs.root_public_key)?;
    let encoded = tbs.encode()?;
    key.verify(
        SignatureDomain::RootIdentity,
        &encoded,
        &root.self_signature,
    )?;
    match predecessor {
        None => {
            if tbs.root_generation != 0
                || tbs.previous_root_fingerprint != [0; 32]
                || !root.continuity_signature.is_empty()
            {
                return Err(E2eeError::InvalidValue);
            }
        }
        Some(previous) => {
            let successor = previous
                .generation
                .checked_add(1)
                .ok_or(E2eeError::Overflow)?;
            if tbs.root_generation != successor
                || tbs.previous_root_fingerprint != previous.fingerprint
                || previous.account_id != account_id
                || !previous.interval.covers(ValidationTime(tbs.not_before))
            {
                return Err(E2eeError::InvalidValue);
            }
            let continuity = root.continuity_signature.exactly::<64>()?;
            previous
                .key
                .verify(SignatureDomain::RootContinuity, &encoded, &continuity)?;
        }
    }
    Ok(VerifiedRoot {
        network_id: *network_id,
        account_id,
        generation: tbs.root_generation,
        fingerprint: semantic_id_of(SemanticHashDomain::RootFingerprint, tbs)?,
        key,
        interval,
    })
}

/// Verifies a consecutive root chain, oldest first, optionally continuing
/// from an already verified head.
pub fn verify_root_chain(
    network_id: &[u8; 32],
    roots: &[ArcRootIdentity],
    head: Option<&VerifiedRoot>,
) -> Result<Vec<VerifiedRoot>, E2eeError> {
    let mut verified = Vec::new();
    verified
        .try_reserve(roots.len())
        .map_err(|_| E2eeError::BudgetExceeded)?;
    let mut previous = head.copied();
    for root in roots {
        let current = verify_root_identity(network_id, root, previous.as_ref())?;
        verified.push(current);
        previous = Some(current);
    }
    if verified.is_empty() {
        return Err(E2eeError::InvalidValue);
    }
    Ok(verified)
}

/// A verified device certificate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedCertificate {
    /// Device identity.
    pub device_id: [u8; 16],
    /// Device authorization key.
    pub key: RoleKey,
    /// Certificate serial.
    pub serial: u64,
    /// Authorization flags.
    pub flags: u32,
    /// Validity.
    pub interval: Interval,
    /// The certificate identifier.
    pub certificate_id: SemanticId,
    /// The roster generation the enrollment targeted.
    pub target_roster_generation: u64,
    /// The enrollment issuance interval.
    pub enrollment_interval: (u64, u64),
}

impl VerifiedCertificate {
    /// Whether bit 0, binding authority, is set.
    #[must_use]
    pub const fn may_bind(&self) -> bool {
        self.flags & 0x1 != 0
    }

    /// Whether bit 1, policy and controller authority, is set.
    #[must_use]
    pub const fn may_approve_policy(&self) -> bool {
        self.flags & 0x2 != 0
    }
}

/// Verifies one device certificate under its verified root.
pub fn verify_device_certificate(
    root: &VerifiedRoot,
    certificate: &ArcDeviceCertificate,
) -> Result<VerifiedCertificate, E2eeError> {
    let tbs = &certificate.tbs;
    let enrollment = &certificate.enrollment_proof.tbs;
    if tbs.profile_version != PROFILE_VERSION || enrollment.profile_version != PROFILE_VERSION {
        return Err(E2eeError::ProfileMismatch);
    }
    if !certificate_names_root(tbs, root)? || !certificate_repeats_enrollment(tbs, enrollment) {
        return Err(E2eeError::InvalidValue);
    }
    check_certificate_windows(tbs, enrollment, root)?;
    let enrollment_encoded = enrollment.encode()?;
    if tbs.enrollment_id != semantic_id_of(SemanticHashDomain::EnrollmentId, enrollment)? {
        return Err(E2eeError::InvalidValue);
    }
    let key = RoleKey::new(SignerRole::Device, tbs.device_authorization_key)?;
    key.verify(
        SignatureDomain::DeviceEnrollmentPossession,
        &enrollment_encoded,
        &certificate.enrollment_proof.new_device_signature,
    )?;
    root.key.verify(
        SignatureDomain::DeviceEnrollmentApproval,
        &enrollment_encoded,
        &certificate.enrollment_proof.root_signature,
    )?;
    root.key.verify(
        SignatureDomain::DeviceCertificate,
        &tbs.encode()?,
        &certificate.root_signature,
    )?;
    Ok(VerifiedCertificate {
        device_id: tbs.device_id,
        key,
        serial: tbs.certificate_serial,
        flags: tbs.authorization_flags,
        interval: Interval {
            not_before: tbs.not_before,
            not_after: tbs.not_after,
        },
        certificate_id: semantic_id_of(SemanticHashDomain::DeviceCertificateId, tbs)?,
        target_roster_generation: tbs.target_roster_generation,
        enrollment_interval: (enrollment.issued_at, enrollment.expires_at),
    })
}

fn certificate_names_root(
    tbs: &ArcDeviceCertificateTbs,
    root: &VerifiedRoot,
) -> Result<bool, E2eeError> {
    Ok(tbs.network_id == root.network_id
        && account_id_bytes(&tbs.account_id)? == root.account_id
        && tbs.root_generation == root.generation
        && tbs.root_fingerprint == root.fingerprint)
}

fn certificate_repeats_enrollment(
    tbs: &ArcDeviceCertificateTbs,
    enrollment: &ArcDeviceEnrollmentTbs,
) -> bool {
    enrollment.network_id == tbs.network_id
        && enrollment.account_id == tbs.account_id
        && enrollment.root_generation == tbs.root_generation
        && enrollment.root_fingerprint == tbs.root_fingerprint
        && enrollment.target_roster_generation == tbs.target_roster_generation
        && enrollment.enrollment_challenge == tbs.enrollment_challenge
        && enrollment.device_id == tbs.device_id
        && enrollment.device_authorization_key == tbs.device_authorization_key
}

/// Flags, the enrollment issuance window, and the certificate interval.
fn check_certificate_windows(
    tbs: &ArcDeviceCertificateTbs,
    enrollment: &ArcDeviceEnrollmentTbs,
    root: &VerifiedRoot,
) -> Result<(), E2eeError> {
    let window = enrollment.expires_at.saturating_sub(enrollment.issued_at);
    let acceptable = tbs.authorization_flags & !KNOWN_AUTHORIZATION_FLAGS == 0
        && enrollment.issued_at <= enrollment.expires_at
        && window <= ENROLLMENT_CHALLENGE_TIMEOUT_SECONDS
        && tbs.not_before <= tbs.not_after
        && tbs.not_after <= root.interval.not_after;
    if acceptable {
        Ok(())
    } else {
        Err(E2eeError::InvalidValue)
    }
}

/// A verified complete device roster.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRoster {
    /// Network identity of the root that signed the roster, which every
    /// device-signed statement naming the roster must carry.
    pub network_id: [u8; 32],
    /// Root fingerprint.
    pub root_fingerprint: SemanticId,
    /// Root generation.
    pub root_generation: u64,
    /// Account ID.
    pub account_id: AccountIdBytes,
    /// Roster generation.
    pub generation: u64,
    /// Roster identifier.
    pub roster_id: SemanticId,
    /// Validity.
    pub interval: Interval,
    /// Active devices by Device ID.
    pub devices: BTreeMap<[u8; 16], VerifiedCertificate>,
    /// Revocations as `(device_id, serial)`.
    pub revocations: Vec<([u8; 16], u64)>,
}

impl VerifiedRoster {
    /// The active certificate of `device_id`, if any.
    #[must_use]
    pub fn device(&self, device_id: &[u8; 16]) -> Option<&VerifiedCertificate> {
        self.devices.get(device_id)
    }

    /// Whether the roster may authorize an Add at `time`: it covers the
    /// time and is no older than `MAX_ROSTER_AGE_AT_ADD`.
    #[must_use]
    pub fn usable_for_add(&self, time: ValidationTime) -> bool {
        self.interval.covers(time)
            && time.0.saturating_sub(self.interval.not_before) <= MAX_ROSTER_AGE_AT_ADD_SECONDS
    }
}

/// How a statement's predecessor is treated during verification.
#[derive(Clone, Copy, Debug)]
pub enum Lineage<'a, T> {
    /// The predecessor is known (or known absent) and the lineage rules apply.
    Checked(Option<&'a T>),
    /// The statement was accepted before and is being reloaded from durable
    /// storage; its predecessor may no longer be retained, so the lineage
    /// rules are skipped while every other rule still applies.
    Restored,
}

/// How a roster is admitted: which lineage step applies, and where a
/// certificate enrolled for an earlier roster generation shows its issuance
/// (companion 8.3 and 8.4).
#[derive(Clone, Copy)]
enum RosterAdmission<'a> {
    /// Succession from the pinned head, or generation zero without one.
    Checked(Option<&'a VerifiedRoster>),
    /// No pinned head yet: earlier rosters of the same root this caller
    /// already verified.
    FirstContact(&'a [VerifiedRoster]),
    /// A roster this node accepted before, reloaded from durable storage.
    Restored,
}

/// Verifies one roster under its root and optional predecessor: generation
/// zero without one, otherwise the generation after it.
///
/// A certificate enrolled for this generation needs an enrollment interval
/// that covers the roster's `not_before`; one enrolled for an earlier
/// generation must be active, unchanged, in the predecessor, since absence
/// there means it was revoked; one enrolled for a later generation is
/// refused (companion 8.3).
pub fn verify_roster(
    root: &VerifiedRoot,
    roster: &ArcDeviceRoster,
    predecessor: Option<&VerifiedRoster>,
) -> Result<VerifiedRoster, E2eeError> {
    verify_roster_lineage(root, roster, RosterAdmission::Checked(predecessor))
}

/// Verifies a roster of a root whose roster lineage this caller has never
/// pinned (first contact), at any generation.
///
/// No predecessor is checked, so the result says nothing about whether a
/// newer roster exists or one was withheld; only the lineage shape applies,
/// generation zero alone naming the all-zero predecessor. A certificate
/// enrolled for an earlier generation is admitted only when it is active,
/// unchanged, in the roster of exactly that generation among `issuance`:
/// earlier rosters of the same root this caller already verified, such as a
/// Welcome's roster chain or imported roster proofs. Missing issuance refuses
/// the roster. The lookup is linear in `issuance`, which the caller bounds by
/// the rosters it already paid to verify. Every other rule of
/// [`verify_roster`] applies. Once a head is pinned, later rosters use
/// [`verify_roster`]; reloading one uses [`restore_roster`].
pub fn verify_first_contact_roster(
    root: &VerifiedRoot,
    roster: &ArcDeviceRoster,
    issuance: &[VerifiedRoster],
) -> Result<VerifiedRoster, E2eeError> {
    verify_roster_lineage(root, roster, RosterAdmission::FirstContact(issuance))
}

/// Re-verifies a roster this node accepted before, without its predecessor.
///
/// Its lineage, and the issuance of every certificate enrolled for an
/// earlier generation, were shown when it was accepted; every other rule
/// still applies, and a certificate enrolled for a later generation is
/// refused. It never admits a roster received from another party: that is
/// [`verify_roster`] or [`verify_first_contact_roster`].
pub fn restore_roster(
    root: &VerifiedRoot,
    roster: &ArcDeviceRoster,
) -> Result<VerifiedRoster, E2eeError> {
    verify_roster_lineage(root, roster, RosterAdmission::Restored)
}

// agenc-review: focus owner=e2ee reviewed=2026-10-02 reason=the roster rules of Sections 8.3 and 8.4 are one closed checklist whose ordering the reviewer reads top to bottom; the admission mode selects only the lineage step, the issuance evidence and the revocation carry-over
fn verify_roster_lineage(
    root: &VerifiedRoot,
    roster: &ArcDeviceRoster,
    admission: RosterAdmission<'_>,
) -> Result<VerifiedRoster, E2eeError> {
    let tbs = &roster.tbs;
    if tbs.profile_version != PROFILE_VERSION {
        return Err(E2eeError::ProfileMismatch);
    }
    if tbs.network_id != root.network_id
        || account_id_bytes(&tbs.account_id)? != root.account_id
        || tbs.root_generation != root.generation
        || tbs.root_fingerprint != root.fingerprint
    {
        return Err(E2eeError::InvalidValue);
    }
    let interval = Interval::ordered(tbs.not_before, tbs.not_after)?;
    if interval.span() > MAX_ROSTER_LIFETIME_SECONDS {
        return Err(E2eeError::LimitExceeded);
    }
    root.key.verify(
        SignatureDomain::DeviceRoster,
        &tbs.encode()?,
        &roster.root_signature,
    )?;
    match admission {
        RosterAdmission::Checked(predecessor) => {
            check_roster_lineage(tbs.roster_generation, &tbs.previous_roster_id, predecessor)?;
        }
        RosterAdmission::FirstContact(_) => {
            check_roster_shape(tbs.roster_generation, &tbs.previous_roster_id)?;
        }
        RosterAdmission::Restored => {}
    }
    let active = tbs.active_devices.as_slice();
    if active.len() > usize::from(MAX_ACTIVE_DEVICES_PER_ACCOUNT) {
        return Err(E2eeError::LimitExceeded);
    }
    ensure_canonical(active, |entry| entry.device_id)?;
    ensure_canonical(tbs.revocations.as_slice(), |entry| {
        (entry.device_id, entry.certificate_serial)
    })?;
    let mut devices = BTreeMap::new();
    let mut keys = BTreeSet::new();
    for entry in active {
        let certificate = verify_device_certificate(root, &entry.certificate)?;
        if entry.device_id != certificate.device_id
            || !interval.within(&certificate.interval)
            || !keys.insert(*certificate.key.as_bytes())
        {
            return Err(E2eeError::InvalidValue);
        }
        check_issuance(&certificate, tbs, root, admission)?;
        devices.insert(entry.device_id, certificate);
    }
    let revocations: Vec<([u8; 16], u64)> = tbs
        .revocations
        .as_slice()
        .iter()
        .map(|entry| (entry.device_id, entry.certificate_serial))
        .collect();
    // `(Device ID, certificate_serial)` is unique and absence means revoked
    // (companion 8.4): no active certificate is also listed as revoked.
    if devices
        .values()
        .any(|certificate| revocations.contains(&(certificate.device_id, certificate.serial)))
    {
        return Err(E2eeError::InvalidValue);
    }
    if let RosterAdmission::Checked(Some(previous)) = admission
        && !previous
            .revocations
            .iter()
            .all(|old| revocations.contains(old))
    {
        return Err(E2eeError::InvalidValue);
    }
    Ok(VerifiedRoster {
        network_id: root.network_id,
        root_fingerprint: root.fingerprint,
        root_generation: root.generation,
        account_id: root.account_id,
        generation: tbs.roster_generation,
        roster_id: semantic_id_of(SemanticHashDomain::RosterId, tbs)?,
        interval,
        devices,
        revocations,
    })
}

fn check_roster_lineage(
    generation: u64,
    previous_id: &[u8; 32],
    predecessor: Option<&VerifiedRoster>,
) -> Result<(), E2eeError> {
    match predecessor {
        None if generation == 0 && *previous_id == [0; 32] => Ok(()),
        Some(previous)
            if previous.generation.checked_add(1) == Some(generation)
                && *previous_id == previous.roster_id =>
        {
            Ok(())
        }
        _ => Err(E2eeError::InvalidValue),
    }
}

/// The lineage shape a roster keeps without its predecessor: generation zero,
/// and only it, names the all-zero predecessor.
fn check_roster_shape(generation: u64, previous_id: &[u8; 32]) -> Result<(), E2eeError> {
    if (generation == 0) == (*previous_id == [0; 32]) {
        Ok(())
    } else {
        Err(E2eeError::InvalidValue)
    }
}

/// Companion 8.3: a certificate is issued in exactly its target roster, whose
/// `not_before` lies in the enrollment interval, and then continues unchanged
/// in every later roster. One enrolled for a later generation than `roster`
/// was never issued; one enrolled for an earlier generation must show its
/// issuance as [`issued_before`] requires.
fn check_issuance(
    certificate: &VerifiedCertificate,
    roster: &ArcDeviceRosterTbs,
    root: &VerifiedRoot,
    admission: RosterAdmission<'_>,
) -> Result<(), E2eeError> {
    let issued = match certificate
        .target_roster_generation
        .cmp(&roster.roster_generation)
    {
        Ordering::Greater => false,
        Ordering::Equal => {
            let (issued_at, expires_at) = certificate.enrollment_interval;
            issued_at <= roster.not_before && roster.not_before <= expires_at
        }
        Ordering::Less => issued_before(certificate, root, admission),
    };
    if issued {
        Ok(())
    } else {
        Err(E2eeError::InvalidValue)
    }
}

/// Whether a certificate enrolled for an earlier generation shows the
/// issuance its admission requires: on succession it is active, unchanged,
/// in the predecessor; on first contact, in the supplied roster of the same
/// root at its target generation. A restored roster's continuing
/// certificates showed it when the roster was accepted.
fn issued_before(
    certificate: &VerifiedCertificate,
    root: &VerifiedRoot,
    admission: RosterAdmission<'_>,
) -> bool {
    let continues_in =
        |roster: &VerifiedRoster| roster.device(&certificate.device_id) == Some(certificate);
    match admission {
        RosterAdmission::Checked(predecessor) => predecessor.is_some_and(continues_in),
        RosterAdmission::FirstContact(issuance) => issuance.iter().any(|issued| {
            issued.root_fingerprint == root.fingerprint
                && issued.generation == certificate.target_roster_generation
                && continues_in(issued)
        }),
        RosterAdmission::Restored => true,
    }
}

/// Requires that the active authorization keys of several rosters are
/// pairwise distinct (Section 8.4 cross-root rule).
pub fn ensure_distinct_device_keys<'a>(
    rosters: impl IntoIterator<Item = &'a VerifiedRoster>,
) -> Result<(), E2eeError> {
    let mut seen = BTreeSet::new();
    for roster in rosters {
        for certificate in roster.devices.values() {
            if !seen.insert(*certificate.key.as_bytes()) {
                return Err(E2eeError::InvalidValue);
            }
        }
    }
    Ok(())
}

/// A verified device capability statement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCapabilities {
    /// Device identity.
    pub device_id: [u8; 16],
    /// Capability generation.
    pub generation: u64,
    /// Capability identifier.
    pub capability_id: SemanticId,
    /// Validity.
    pub interval: Interval,
    /// Supported suites in declared order.
    pub cipher_suites: Vec<u16>,
    /// Supported versions.
    pub versions: Vec<u16>,
}

/// Verifies a capability statement for a device active in `roster`. The
/// statement's signed network must be the roster's.
pub fn verify_capabilities(
    roster: &VerifiedRoster,
    capabilities: &ArcDeviceCapabilities,
    predecessor: Option<&VerifiedCapabilities>,
) -> Result<VerifiedCapabilities, E2eeError> {
    verify_capabilities_lineage(roster, capabilities, Lineage::Checked(predecessor))
}

/// Re-verifies a capability statement this node accepted before, without
/// its predecessor. Every other rule, the signed network included, still
/// applies.
pub fn restore_capabilities(
    roster: &VerifiedRoster,
    capabilities: &ArcDeviceCapabilities,
) -> Result<VerifiedCapabilities, E2eeError> {
    verify_capabilities_lineage(roster, capabilities, Lineage::Restored)
}

fn verify_capabilities_lineage(
    roster: &VerifiedRoster,
    capabilities: &ArcDeviceCapabilities,
    lineage: Lineage<'_, VerifiedCapabilities>,
) -> Result<VerifiedCapabilities, E2eeError> {
    let tbs = &capabilities.tbs;
    if tbs.profile_version != PROFILE_VERSION || tbs.network_id != roster.network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    if !statement_names_roster(
        &tbs.account_id,
        tbs.root_fingerprint,
        tbs.roster_generation,
        tbs.roster_id,
        roster,
    )? {
        return Err(E2eeError::InvalidValue);
    }
    let certificate = roster
        .device(&tbs.device_id)
        .ok_or(E2eeError::InvalidValue)?;
    let interval = Interval::ordered(tbs.not_before, tbs.not_after)?;
    if interval.span() > MAX_CAPABILITY_LIFETIME_SECONDS {
        return Err(E2eeError::LimitExceeded);
    }
    for vector in [
        tbs.versions.as_slice(),
        tbs.cipher_suites.as_slice(),
        tbs.extensions.as_slice(),
        tbs.proposals.as_slice(),
        tbs.credentials.as_slice(),
    ] {
        ensure_canonical(vector, |value| *value)?;
    }
    if let Lineage::Checked(predecessor) = lineage {
        check_capability_lineage(
            tbs.device_id,
            tbs.capability_generation,
            &tbs.previous_capability_id,
            predecessor,
        )?;
    }
    certificate.key.verify(
        SignatureDomain::DeviceCapabilities,
        &tbs.encode()?,
        &capabilities.device_signature,
    )?;
    Ok(VerifiedCapabilities {
        device_id: tbs.device_id,
        generation: tbs.capability_generation,
        capability_id: semantic_id_of(SemanticHashDomain::CapabilityId, tbs)?,
        interval,
        cipher_suites: tbs.cipher_suites.as_slice().to_vec(),
        versions: tbs.versions.as_slice().to_vec(),
    })
}

/// Whether a device-signed statement names exactly `roster`.
fn statement_names_roster(
    account_id: &crate::objects::AccountIdField,
    root_fingerprint: SemanticId,
    roster_generation: u64,
    roster_id: SemanticId,
    roster: &VerifiedRoster,
) -> Result<bool, E2eeError> {
    Ok(account_id_bytes(account_id)? == roster.account_id
        && root_fingerprint == roster.root_fingerprint
        && roster_generation == roster.generation
        && roster_id == roster.roster_id)
}

fn check_capability_lineage(
    device_id: [u8; 16],
    generation: u64,
    previous_id: &SemanticId,
    predecessor: Option<&VerifiedCapabilities>,
) -> Result<(), E2eeError> {
    match predecessor {
        None if generation == 0 && *previous_id == [0; 32] => Ok(()),
        Some(previous)
            if previous.device_id == device_id
                && previous.generation.checked_add(1) == Some(generation)
                && *previous_id == previous.capability_id =>
        {
            Ok(())
        }
        _ => Err(E2eeError::InvalidValue),
    }
}

/// A verified leaf authorization.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedLeafAuthorization {
    /// Device identity.
    pub device_id: [u8; 16],
    /// MLS version.
    pub mls_version: u16,
    /// Cipher suite.
    pub cipher_suite: u16,
    /// Leaf signature scheme.
    pub leaf_signature_scheme: u16,
    /// Leaf signature key.
    pub leaf_signature_key: Vec<u8>,
    /// Leaf capabilities digest.
    pub leaf_capabilities_hash: SemanticId,
    /// Package nonce.
    pub package_nonce: [u8; 32],
    /// Validity, which the KeyPackage lifetime must equal.
    pub interval: Interval,
}

/// Verifies a leaf authorization for a device active in `roster`. The
/// authorization's signed network must be the roster's; the credential
/// bundle and KeyPackage checks inherit this.
pub fn verify_leaf_authorization(
    roster: &VerifiedRoster,
    authorization: &ArcLeafAuthorization,
) -> Result<VerifiedLeafAuthorization, E2eeError> {
    let tbs = &authorization.tbs;
    if !leaf_profile_is_version_one(tbs) || tbs.network_id != roster.network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    let names_roster = statement_names_roster(
        &tbs.account_id,
        tbs.root_fingerprint,
        tbs.roster_generation,
        tbs.roster_id,
        roster,
    )?;
    if !names_roster || tbs.root_generation != roster.root_generation || !leaf_fields_are_fixed(tbs)
    {
        return Err(E2eeError::InvalidValue);
    }
    let certificate = roster
        .device(&tbs.device_id)
        .ok_or(E2eeError::InvalidValue)?;
    let interval = Interval::ordered(tbs.not_before, tbs.not_after)?;
    if interval.span() > MAX_KEY_PACKAGE_LIFETIME_SECONDS {
        return Err(E2eeError::LimitExceeded);
    }
    if !interval.within(&certificate.interval) || !interval.within(&roster.interval) {
        return Err(E2eeError::InvalidValue);
    }
    certificate.key.verify(
        SignatureDomain::LeafAuthorization,
        &tbs.encode()?,
        &authorization.device_signature,
    )?;
    Ok(VerifiedLeafAuthorization {
        device_id: tbs.device_id,
        mls_version: tbs.mls_version,
        cipher_suite: tbs.cipher_suite,
        leaf_signature_scheme: tbs.leaf_signature_scheme,
        leaf_signature_key: tbs.leaf_signature_key.as_slice().to_vec(),
        leaf_capabilities_hash: tbs.leaf_capabilities_hash,
        package_nonce: tbs.package_nonce,
        interval,
    })
}

/// Profile version, MLS version, suite, and signature scheme are fixed.
fn leaf_profile_is_version_one(tbs: &ArcLeafAuthorizationTbs) -> bool {
    tbs.profile_version == PROFILE_VERSION
        && tbs.mls_version == MLS_VERSION_MLS10
        && suite_is_enabled(tbs.cipher_suite)
        && tbs.leaf_signature_scheme == SIGNATURE_SCHEME_ED25519
}

/// Version 1 fixes the credential generation, the last-resort bit, and the
/// Ed25519 key length.
fn leaf_fields_are_fixed(tbs: &ArcLeafAuthorizationTbs) -> bool {
    tbs.credential_generation == 0 && tbs.last_resort == 0 && tbs.leaf_signature_key.len() == 32
}

/// The identity of one MLS client under the Section 8.5 equivalence rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ClientIdentity {
    /// Network identity.
    pub network_id: [u8; 32],
    /// Account ID.
    pub account_id: AccountIdBytes,
    /// The fingerprint of the root the credential resolves to.
    pub root_fingerprint: SemanticId,
    /// Device identity.
    pub device_id: [u8; 16],
}

impl ClientIdentity {
    /// Whether two credentials name the same client, given a predicate that
    /// says whether two root fingerprints belong to one continuous lineage.
    pub fn same_client(
        &self,
        other: &Self,
        roots_continuous: impl Fn(&SemanticId, &SemanticId) -> bool,
    ) -> bool {
        self.network_id == other.network_id
            && self.account_id == other.account_id
            && self.device_id == other.device_id
            && (self.root_fingerprint == other.root_fingerprint
                || roots_continuous(&self.root_fingerprint, &other.root_fingerprint))
    }
}

/// A verified credential bundle and the client it names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedCredential {
    /// The client identity.
    pub client: ClientIdentity,
    /// The certificate the bundle carries.
    pub certificate: VerifiedCertificate,
    /// The leaf authorization.
    pub leaf: VerifiedLeafAuthorization,
}

/// Verifies a credential bundle against the exact roster it names.
///
/// The root inside the bundle is checked as a self-signed identity whose
/// fingerprint equals the roster's root; continuity to earlier generations
/// is the chain verifier's job.
pub fn verify_credential_bundle(
    network_id: &[u8; 32],
    roster: &VerifiedRoster,
    bundle: &ArcCredentialBundle,
) -> Result<VerifiedCredential, E2eeError> {
    if bundle.encode()?.len() > MAX_CREDENTIAL_BUNDLE {
        return Err(E2eeError::LimitExceeded);
    }
    let root = verify_root_standalone(network_id, &bundle.root)?;
    if root.fingerprint != roster.root_fingerprint || root.account_id != roster.account_id {
        return Err(E2eeError::InvalidValue);
    }
    let certificate = verify_device_certificate(&root, &bundle.device_certificate)?;
    let active = roster
        .device(&certificate.device_id)
        .ok_or(E2eeError::InvalidValue)?;
    if *active != certificate {
        return Err(E2eeError::InvalidValue);
    }
    let leaf = verify_leaf_authorization(roster, &bundle.leaf_authorization)?;
    if leaf.device_id != certificate.device_id {
        return Err(E2eeError::InvalidValue);
    }
    Ok(VerifiedCredential {
        client: ClientIdentity {
            network_id: *network_id,
            account_id: root.account_id,
            root_fingerprint: root.fingerprint,
            device_id: certificate.device_id,
        },
        certificate,
        leaf,
    })
}

/// Verifies a root's own signature and shape without a predecessor, for a
/// root whose continuity is established elsewhere.
pub fn verify_root_standalone(
    network_id: &[u8; 32],
    root: &ArcRootIdentity,
) -> Result<VerifiedRoot, E2eeError> {
    let tbs = &root.tbs;
    if tbs.profile_version != PROFILE_VERSION || tbs.network_id != *network_id {
        return Err(E2eeError::ProfileMismatch);
    }
    let zero_generation = tbs.root_generation == 0;
    if zero_generation != (tbs.previous_root_fingerprint == [0; 32])
        || zero_generation != root.continuity_signature.is_empty()
    {
        return Err(E2eeError::InvalidValue);
    }
    let key = RoleKey::new(SignerRole::Root, tbs.root_public_key)?;
    key.verify(
        SignatureDomain::RootIdentity,
        &tbs.encode()?,
        &root.self_signature,
    )?;
    Ok(VerifiedRoot {
        network_id: *network_id,
        account_id: account_id_bytes(&tbs.account_id)?,
        generation: tbs.root_generation,
        fingerprint: semantic_id_of(SemanticHashDomain::RootFingerprint, tbs)?,
        key,
        interval: Interval::ordered(tbs.not_before, tbs.not_after)?,
    })
}

/// Verifies a public KeyPackage's credential bundle and the Section 8.5
/// agreement between the bundle and the MLS leaf.
pub fn verify_key_package_credential(
    network_id: &[u8; 32],
    roster: &VerifiedRoster,
    package: &PublicKeyPackage,
) -> Result<VerifiedCredential, E2eeError> {
    let mut budget = crate::tls::DecodeBudget::new(MAX_CREDENTIAL_BUNDLE, 1_024);
    let bundle =
        ArcCredentialBundle::decode_exact(&package.leaf_node.credential_identity, &mut budget)?;
    let credential = verify_credential_bundle(network_id, roster, &bundle)?;
    let leaf = &credential.leaf;
    let lifetime = package.leaf_node.lifetime;
    if package.version != leaf.mls_version
        || package.cipher_suite != leaf.cipher_suite
        || package.leaf_node.signature_key != leaf.leaf_signature_key
        || lifetime.not_before != leaf.interval.not_before
        || lifetime.not_after != leaf.interval.not_after
        || package.has_last_resort_extension()
    {
        return Err(E2eeError::InvalidValue);
    }
    let capabilities =
        crate::ids::leaf_capabilities_digest(&package.leaf_node.encoded_capabilities)?;
    if capabilities != leaf.leaf_capabilities_hash {
        return Err(E2eeError::InvalidValue);
    }
    Ok(credential)
}

/// What observing a new generation of a pinned object means.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HeadObservation {
    /// The exact pinned head again.
    Same,
    /// The next generation with the pinned predecessor.
    Advanced,
    /// A generation below the pinned head.
    Rollback,
    /// The pinned generation with a different identifier.
    Equivocation,
    /// A generation more than one above the pinned head.
    Gap,
}

/// One pinned `(generation, id)` head.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinnedHead {
    /// Highest accepted generation.
    pub generation: u64,
    /// Its identifier.
    pub id: SemanticId,
}

impl PinnedHead {
    /// Classifies `observed` against this pin.
    #[must_use]
    pub fn observe(&self, generation: u64, id: SemanticId) -> HeadObservation {
        if generation < self.generation {
            HeadObservation::Rollback
        } else if generation == self.generation {
            if id == self.id {
                HeadObservation::Same
            } else {
                HeadObservation::Equivocation
            }
        } else if generation == self.generation.saturating_add(1) {
            HeadObservation::Advanced
        } else {
            HeadObservation::Gap
        }
    }
}

/// The highest accepted heads per account, root, and device.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountHeads {
    roots: BTreeMap<AccountIdBytes, PinnedHead>,
    rosters: BTreeMap<SemanticId, PinnedHead>,
    capabilities: BTreeMap<(SemanticId, [u8; 16]), PinnedHead>,
    binding_locks: BTreeMap<SemanticId, PinnedHead>,
}

impl AccountHeads {
    /// Creates an empty head table.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records a verified root, returning how it relates to the pin.
    pub fn observe_root(&mut self, root: &VerifiedRoot) -> HeadObservation {
        observe(
            &mut self.roots,
            root.account_id,
            root.generation,
            root.fingerprint,
        )
    }

    /// Records a verified roster under its root.
    pub fn observe_roster(&mut self, roster: &VerifiedRoster) -> HeadObservation {
        observe(
            &mut self.rosters,
            roster.root_fingerprint,
            roster.generation,
            roster.roster_id,
        )
    }

    /// Records a verified capability statement under its root and device.
    pub fn observe_capabilities(
        &mut self,
        root_fingerprint: SemanticId,
        capabilities: &VerifiedCapabilities,
    ) -> HeadObservation {
        observe(
            &mut self.capabilities,
            (root_fingerprint, capabilities.device_id),
            capabilities.generation,
            capabilities.capability_id,
        )
    }

    /// Records a root binding lock head under its root.
    pub fn observe_binding_lock(
        &mut self,
        root_fingerprint: SemanticId,
        sequence: u64,
        lock_id: SemanticId,
    ) -> HeadObservation {
        observe(&mut self.binding_locks, root_fingerprint, sequence, lock_id)
    }

    /// The pinned roster head of a root, if any.
    #[must_use]
    pub fn roster_head(&self, root_fingerprint: &SemanticId) -> Option<PinnedHead> {
        self.rosters.get(root_fingerprint).copied()
    }

    /// The pinned root head of an account, if any.
    #[must_use]
    pub fn root_head(&self, account_id: &AccountIdBytes) -> Option<PinnedHead> {
        self.roots.get(account_id).copied()
    }
}

fn observe<K: Ord>(
    table: &mut BTreeMap<K, PinnedHead>,
    key: K,
    generation: u64,
    id: SemanticId,
) -> HeadObservation {
    let Some(pinned) = table.get(&key) else {
        table.insert(key, PinnedHead { generation, id });
        return HeadObservation::Advanced;
    };
    let observation = pinned.observe(generation, id);
    if observation == HeadObservation::Advanced {
        table.insert(key, PinnedHead { generation, id });
    }
    observation
}

#[cfg(test)]
#[path = "tests/identity.rs"]
mod tests;
