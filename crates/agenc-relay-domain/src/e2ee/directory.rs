//! The account directory (companion 8, 11.6, 13.1): root and roster heads,
//! device capability statements, binding-lock chains, device attachment
//! generations with compare-and-swap, and the one-use KeyPackage stock with
//! idempotent claims.
//!
//! Identifiers arrive already validated by the e2ee crate; this model owns
//! the state that relates them across time.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::ops::Bound::{Excluded, Unbounded};
use std::sync::Arc;

use super::limits::{
    ATTACH_CHALLENGE_TIMEOUT_SECONDS, KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS,
    MAX_ACTIVE_DEVICES_PER_ACCOUNT, MAX_KEY_PACKAGE_LIFETIME_SECONDS,
    MIN_KEY_PACKAGE_CLAIM_VALIDITY_SECONDS,
};

/// A 32-byte identifier or digest.
pub type Id = [u8; 32];
/// A 16-byte device or operation identifier.
pub type Id16 = [u8; 16];

/// Why a directory mutation was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DirectoryError {
    /// The generation is not the head plus one.
    GenerationGap,
    /// The object names a root or roster that is not the current head.
    HeadMismatch,
    /// The device is not active in the current roster.
    DeviceInactive,
    /// A KeyPackage reference is already published or was dispensed.
    DuplicatePackage,
    /// The package expiry exceeds the lifetime ceiling or is in the past.
    ExpiryOutOfRange,
    /// The stock has no acceptable package.
    KeyUnavailable,
    /// An operation identifier was reused with different parameters.
    OperationConflict,
    /// The attachment compare-and-swap failed.
    AttachConflict,
    /// The publisher does not own the package.
    NotOwner,
    /// Arithmetic overflow.
    Overflow,
}

impl fmt::Display for DirectoryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let text = match self {
            Self::GenerationGap => "generation is not the head plus one",
            Self::HeadMismatch => "the object names a stale head",
            Self::DeviceInactive => "the device is not active in the roster",
            Self::DuplicatePackage => "the key package was already published or dispensed",
            Self::ExpiryOutOfRange => "the package expiry is out of range",
            Self::KeyUnavailable => "no acceptable key package is available",
            Self::OperationConflict => "operation id reused with different parameters",
            Self::AttachConflict => "the attachment generation changed",
            Self::NotOwner => "the caller does not own the package",
            Self::Overflow => "counter overflow",
        };
        formatter.write_str(text)
    }
}

impl std::error::Error for DirectoryError {}

/// The root head of one account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RootHead {
    /// Root generation.
    pub generation: u64,
    /// Root fingerprint.
    pub fingerprint: Id,
    /// Object identifiers of every generation, oldest first.
    pub chain: Vec<Id>,
}

/// The roster head of one account.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RosterHead {
    /// Roster generation.
    pub generation: u64,
    /// Roster identifier.
    pub roster_id: Id,
    /// The root fingerprint the roster is signed under.
    pub root_fingerprint: Id,
    /// The retained object identifier.
    pub object_id: Id,
    /// Active devices in canonical order.
    pub active_devices: BTreeSet<Id16>,
}

/// One device's highest capability statement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CapabilityHead {
    /// Capability generation.
    pub generation: u64,
    /// Capability identifier.
    pub capability_id: Id,
    /// The roster identifier it names.
    pub roster_id: Id,
    /// The retained object identifier.
    pub object_id: Id,
}

/// An outstanding attach challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge {
    /// The connection it was issued to.
    pub connection_id: Id16,
    /// The reserved next session generation.
    pub reserved_generation: u64,
    /// Expiry second.
    pub expires_at: u64,
}

/// The attachment state of one device.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Attachment {
    /// The durable session generation, zero before any attachment.
    pub session_generation: u64,
    /// The outstanding challenge.
    pub challenge: Option<Challenge>,
}

/// One published KeyPackage.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Package {
    /// Publishing account digest.
    pub account_digest: Id,
    /// Publishing device.
    pub device_id: Id16,
    /// Cipher suite.
    pub suite: u16,
    /// Earliest valid second in the signed KeyPackage lifetime.
    pub not_before: u64,
    /// Expiry second.
    pub expires_at: u64,
    /// The retained object identifier.
    pub object_id: Id,
}

/// The parameters of one claim, pinned under its operation identifier.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ClaimParameters {
    /// Target account digest.
    pub target_account_digest: Id,
    /// Target device.
    pub target_device_id: Id16,
    /// Requested suite.
    pub suite: u16,
}

/// The stored outcome of one claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimOutcome {
    /// A package was dispensed.
    Claimed {
        /// The KeyPackage reference.
        key_package_ref: Vec<u8>,
        /// The dispensed object identifier.
        object_id: Id,
    },
    /// No acceptable package was available.
    Unavailable,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ClaimRecord {
    parameters: ClaimParameters,
    outcome: ClaimOutcome,
    retain_until: u64,
}

/// The exact result staged by the exclusive directory writer.
/// Dropping this plan leaves the stock and operation mappings unchanged.
pub struct PlannedClaim {
    key: (Id, Id16),
    record: ClaimRecord,
    fresh: bool,
}

impl PlannedClaim {
    /// Whether a new mapping and any stock removal must be committed.
    #[must_use]
    pub const fn is_fresh(&self) -> bool {
        self.fresh
    }

    /// The answer associated with this operation.
    #[must_use]
    pub const fn outcome(&self) -> &ClaimOutcome {
        &self.record.outcome
    }

    /// The persisted cutoff, including the dispensed package's lifetime.
    #[must_use]
    pub const fn retain_until(&self) -> u64 {
        self.record.retain_until
    }

    /// Replays the committed operation on its originating directory. As with
    /// `restore_claim`, the durable writer owns ordering. It holds off later
    /// directory work until this result has either committed or been discarded.
    pub fn apply_committed(self, directory: &mut Directory) -> ClaimOutcome {
        if self.fresh {
            let outcome = self.record.outcome.clone();
            directory.record_claim(self.key, self.record);
            outcome
        } else {
            self.record.outcome
        }
    }
}

/// The state of one account.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct AccountEntry {
    /// Root head.
    pub root: Option<RootHead>,
    /// Roster head.
    pub roster: Option<RosterHead>,
    /// Capability heads by device.
    pub capabilities: BTreeMap<Id16, CapabilityHead>,
    /// Binding lock chains: `(root fingerprint) -> next sequence`.
    pub lock_sequences: BTreeMap<Id, u64>,
    /// Attachment state by device.
    pub attachments: BTreeMap<Id16, Attachment>,
}

impl AccountEntry {
    /// Whether `device` is active in the current roster.
    #[must_use]
    pub fn device_active(&self, device: &Id16) -> bool {
        self.roster
            .as_ref()
            .is_some_and(|roster| roster.active_devices.contains(device))
    }
}

/// The directory.
#[derive(Clone, Debug, Default)]
pub struct Directory {
    accounts: BTreeMap<Id, AccountEntry>,
    packages: BTreeMap<Vec<u8>, Package>,
    // Other directory operations stage temporary copies. Their claim rows are immutable.
    claims: Arc<BTreeMap<(Id, Id16), ClaimRecord>>,
    // A successful claim holds its reference until retirement. An older
    // package row excluded from stock also withholds its named reference.
    spent: Arc<BTreeMap<Vec<u8>, usize>>,
}

impl Directory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Restores one account entry at startup, replacing any prior entry.
    pub fn restore_account(&mut self, account_digest: Id, entry: AccountEntry) {
        self.accounts.insert(account_digest, entry);
    }

    /// Installs the complete stock, claim and exclusion indexes after successful startup admission.
    pub fn replace_package_rows(&mut self, recovered: Self) {
        self.packages = recovered.packages;
        self.claims = recovered.claims;
        self.spent = recovered.spent;
    }

    /// Restores one published package at startup.
    pub fn restore_package(&mut self, reference: Vec<u8>, package: Package) {
        if !self.spent.contains_key(&reference) {
            self.packages.insert(reference, package);
        }
    }

    /// Withholds a reference named by a successful claim or by an existing
    /// package row that cannot be restored as valid stock.
    pub fn withhold_package(&mut self, reference: Vec<u8>) {
        self.packages.remove(&reference);
        *Arc::make_mut(&mut self.spent).entry(reference).or_default() += 1;
    }

    /// Restores one claim result at startup.
    pub fn restore_claim(
        &mut self,
        claimant_digest: Id,
        operation_id: Id16,
        parameters: ClaimParameters,
        outcome: ClaimOutcome,
        retain_until: u64,
    ) {
        self.record_claim(
            (claimant_digest, operation_id),
            ClaimRecord {
                parameters,
                outcome,
                retain_until,
            },
        );
    }

    fn record_claim(&mut self, key: (Id, Id16), record: ClaimRecord) {
        if let ClaimOutcome::Claimed {
            key_package_ref, ..
        } = &record.outcome
        {
            self.withhold_package(key_package_ref.clone());
        }
        if let Some(previous) = Arc::make_mut(&mut self.claims).insert(key, record) {
            Self::release_reference(&mut self.spent, &previous.outcome);
        }
    }

    fn release_reference(spent: &mut Arc<BTreeMap<Vec<u8>, usize>>, outcome: &ClaimOutcome) {
        if let ClaimOutcome::Claimed {
            key_package_ref, ..
        } = outcome
        {
            Self::release_withheld(spent, key_package_ref);
        }
    }

    /// Releases the separate exclusion owned by a deleted legacy stock row.
    pub fn release_withheld_package(&mut self, reference: &[u8]) {
        Self::release_withheld(&mut self.spent, reference);
    }

    fn release_withheld(spent: &mut Arc<BTreeMap<Vec<u8>, usize>>, reference: &[u8]) {
        let owners = Arc::make_mut(spent);
        if let Some(count) = owners.get_mut(reference) {
            *count -= 1;
            if *count == 0 {
                owners.remove(reference);
                if owners.is_empty() {
                    owners.clear();
                }
            }
        }
    }

    /// The number of stored directory entries: account heads and
    /// published packages.
    #[must_use]
    pub fn entry_count(&self) -> usize {
        self.accounts.len().saturating_add(self.packages.len())
    }

    /// The state of one account.
    #[must_use]
    pub fn account(&self, account_digest: &Id) -> Option<&AccountEntry> {
        self.accounts.get(account_digest)
    }

    /// Publishes a root at generation zero or the head plus one.
    pub fn publish_root(
        &mut self,
        account_digest: Id,
        generation: u64,
        fingerprint: Id,
        object_id: Id,
    ) -> Result<(), DirectoryError> {
        let entry = self.accounts.entry(account_digest).or_default();
        let next = entry.root.as_ref().map_or(Ok(0), |root| {
            root.generation
                .checked_add(1)
                .ok_or(DirectoryError::Overflow)
        })?;
        if generation != next {
            return Err(DirectoryError::GenerationGap);
        }
        let mut chain = entry.root.take().map(|root| root.chain).unwrap_or_default();
        chain.push(object_id);
        entry.root = Some(RootHead {
            generation,
            fingerprint,
            chain,
        });
        Ok(())
    }

    /// Publishes a roster under the current root; devices leaving the
    /// active set have their published packages burned, and the burned
    /// references are returned.
    ///
    /// Roster and capability generations are scoped to the root fingerprint
    /// (companion 14): a root's first roster has generation zero and every
    /// later one advances that root's head by exactly one, and a root's
    /// first roster keeps no capability head of an earlier root, while a
    /// later one keeps the heads of the devices it keeps active. Attachment
    /// counters are scoped to the account and device (companion 11.6 and 14)
    /// and outlive every roster.
    pub fn publish_roster(
        &mut self,
        account_digest: Id,
        generation: u64,
        roster_id: Id,
        root_fingerprint: Id,
        active_devices: BTreeSet<Id16>,
        object_id: Id,
    ) -> Result<Vec<Vec<u8>>, DirectoryError> {
        if active_devices.len() > MAX_ACTIVE_DEVICES_PER_ACCOUNT {
            return Err(DirectoryError::GenerationGap);
        }
        let entry = self.accounts.entry(account_digest).or_default();
        let root = entry.root.as_ref().ok_or(DirectoryError::HeadMismatch)?;
        if root.fingerprint != root_fingerprint {
            return Err(DirectoryError::HeadMismatch);
        }
        let continued = entry
            .roster
            .as_ref()
            .filter(|roster| roster.root_fingerprint == root_fingerprint);
        let next = continued.map_or(Ok(0), |roster| {
            roster
                .generation
                .checked_add(1)
                .ok_or(DirectoryError::Overflow)
        })?;
        if generation != next {
            return Err(DirectoryError::GenerationGap);
        }
        if continued.is_some() {
            entry
                .capabilities
                .retain(|device, _| active_devices.contains(device));
        } else {
            entry.capabilities.clear();
        }
        entry.roster = Some(RosterHead {
            generation,
            roster_id,
            root_fingerprint,
            object_id,
            active_devices: active_devices.clone(),
        });
        let burned: Vec<Vec<u8>> = self
            .packages
            .iter()
            .filter(|(_, package)| {
                package.account_digest == account_digest
                    && !active_devices.contains(&package.device_id)
            })
            .map(|(reference, _)| reference.clone())
            .collect();
        for reference in &burned {
            self.packages.remove(reference);
        }
        Ok(burned)
    }

    /// Publishes a capability statement for an active device under the
    /// current roster; the generation must exceed the retained one.
    pub fn publish_capability(
        &mut self,
        account_digest: Id,
        device_id: Id16,
        head: CapabilityHead,
    ) -> Result<(), DirectoryError> {
        let entry = self
            .accounts
            .get_mut(&account_digest)
            .ok_or(DirectoryError::HeadMismatch)?;
        let roster = entry.roster.as_ref().ok_or(DirectoryError::HeadMismatch)?;
        if roster.roster_id != head.roster_id {
            return Err(DirectoryError::HeadMismatch);
        }
        if !roster.active_devices.contains(&device_id) {
            return Err(DirectoryError::DeviceInactive);
        }
        if entry
            .capabilities
            .get(&device_id)
            .is_some_and(|current| head.generation <= current.generation)
        {
            return Err(DirectoryError::GenerationGap);
        }
        entry.capabilities.insert(device_id, head);
        Ok(())
    }

    /// The capability page of one account: every active device whose
    /// highest statement names the current roster, exactly once in Device ID
    /// order, with that statement's object. A statement is valid only for
    /// the highest roster in which its device is active (companion 8.5 and
    /// 11.6), so a device whose head names an earlier roster is left out
    /// until it publishes for the current one; the head itself is kept.
    #[must_use]
    pub fn capability_page(&self, account_digest: &Id) -> Vec<(Id16, Id)> {
        self.accounts
            .get(account_digest)
            .map(|entry| {
                let current = entry.roster.as_ref().map(|roster| roster.roster_id);
                entry
                    .capabilities
                    .iter()
                    .filter(|(device, head)| {
                        entry.device_active(device) && current == Some(head.roster_id)
                    })
                    .map(|(device, head)| (*device, head.object_id))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Records a binding lock at the next sequence of `root_fingerprint`.
    pub fn record_binding_lock(
        &mut self,
        account_digest: Id,
        root_fingerprint: Id,
        sequence: u64,
    ) -> Result<(), DirectoryError> {
        let entry = self
            .accounts
            .get_mut(&account_digest)
            .ok_or(DirectoryError::HeadMismatch)?;
        let next = entry.lock_sequences.entry(root_fingerprint).or_insert(0);
        if sequence != *next {
            return Err(DirectoryError::GenerationGap);
        }
        *next = next.checked_add(1).ok_or(DirectoryError::Overflow)?;
        Ok(())
    }

    /// Begins an attachment: reserves the next session generation and
    /// invalidates any earlier challenge for the connection and device.
    pub fn attach_begin(
        &mut self,
        account_digest: Id,
        device_id: Id16,
        connection_id: Id16,
        now: u64,
    ) -> Result<Challenge, DirectoryError> {
        let entry = self
            .accounts
            .get_mut(&account_digest)
            .ok_or(DirectoryError::HeadMismatch)?;
        if !entry.device_active(&device_id) {
            return Err(DirectoryError::DeviceInactive);
        }
        let attachment = entry.attachments.entry(device_id).or_default();
        let challenge = Challenge {
            connection_id,
            reserved_generation: attachment
                .session_generation
                .checked_add(1)
                .ok_or(DirectoryError::Overflow)?,
            expires_at: now
                .checked_add(ATTACH_CHALLENGE_TIMEOUT_SECONDS)
                .ok_or(DirectoryError::Overflow)?,
        };
        attachment.challenge = Some(challenge);
        Ok(challenge)
    }

    /// Finishes an attachment by compare-and-swap against the durable
    /// prior generation; returns the new session generation.
    pub fn attach_finish(
        &mut self,
        account_digest: Id,
        device_id: Id16,
        connection_id: Id16,
        reserved_generation: u64,
        now: u64,
    ) -> Result<u64, DirectoryError> {
        let entry = self
            .accounts
            .get_mut(&account_digest)
            .ok_or(DirectoryError::HeadMismatch)?;
        if !entry.device_active(&device_id) {
            return Err(DirectoryError::DeviceInactive);
        }
        let attachment = entry.attachments.entry(device_id).or_default();
        let challenge = attachment.challenge.ok_or(DirectoryError::AttachConflict)?;
        let matches = challenge.connection_id == connection_id
            && challenge.reserved_generation == reserved_generation
            && challenge.expires_at > now
            && reserved_generation
                == attachment
                    .session_generation
                    .checked_add(1)
                    .ok_or(DirectoryError::Overflow)?;
        if !matches {
            return Err(DirectoryError::AttachConflict);
        }
        attachment.session_generation = reserved_generation;
        attachment.challenge = None;
        Ok(reserved_generation)
    }

    /// The current session generation of a device, zero when unattached.
    #[must_use]
    pub fn session_generation(&self, account_digest: &Id, device_id: &Id16) -> u64 {
        self.accounts
            .get(account_digest)
            .and_then(|entry| entry.attachments.get(device_id))
            .map_or(0, |attachment| attachment.session_generation)
    }

    /// Publishes a one-use package for an active device.
    pub fn publish_package(
        &mut self,
        key_package_ref: Vec<u8>,
        package: Package,
        now: u64,
    ) -> Result<(), DirectoryError> {
        let entry = self
            .accounts
            .get(&package.account_digest)
            .ok_or(DirectoryError::HeadMismatch)?;
        if !entry.device_active(&package.device_id) {
            return Err(DirectoryError::DeviceInactive);
        }
        let ceiling = now
            .checked_add(MAX_KEY_PACKAGE_LIFETIME_SECONDS)
            .ok_or(DirectoryError::Overflow)?;
        if now < package.not_before || package.expires_at <= now || package.expires_at > ceiling {
            return Err(DirectoryError::ExpiryOutOfRange);
        }
        if self.packages.contains_key(&key_package_ref) || self.spent.contains_key(&key_package_ref)
        {
            return Err(DirectoryError::DuplicatePackage);
        }
        self.packages.insert(key_package_ref, package);
        Ok(())
    }

    /// Revokes a package published by `device_id`.
    pub fn revoke_package(
        &mut self,
        device_id: &Id16,
        key_package_ref: &[u8],
    ) -> Result<(), DirectoryError> {
        let package = self
            .packages
            .get(key_package_ref)
            .ok_or(DirectoryError::KeyUnavailable)?;
        if package.device_id != *device_id {
            return Err(DirectoryError::NotOwner);
        }
        self.packages.remove(key_package_ref);
        Ok(())
    }

    /// Claims one package for `(claimant, operation_id)`: an identical retry
    /// returns the stored outcome, a different retry is a conflict, and a
    /// fresh claim dispenses the acceptable package with the smallest
    /// reference and burns it.
    pub fn claim_package(
        &mut self,
        claimant_digest: Id,
        operation_id: Id16,
        parameters: ClaimParameters,
        now: u64,
    ) -> Result<ClaimOutcome, DirectoryError> {
        Ok(self
            .plan_claim(claimant_digest, operation_id, parameters, now)?
            .apply_committed(self))
    }

    /// Checks parameters, stock and the retention boundary without changing state.
    /// A service can reserve resources and persist this result before publishing its plan.
    pub fn plan_claim(
        &self,
        claimant_digest: Id,
        operation_id: Id16,
        parameters: ClaimParameters,
        now: u64,
    ) -> Result<PlannedClaim, DirectoryError> {
        let key = (claimant_digest, operation_id);
        if let Some(record) = self.claims.get(&key) {
            if record.parameters != parameters {
                return Err(DirectoryError::OperationConflict);
            }
            return Ok(PlannedClaim {
                key,
                record: record.clone(),
                fresh: false,
            });
        }
        let outcome = self.dispense(&parameters, now)?;
        let timeout = now
            .checked_add(KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS)
            .ok_or(DirectoryError::Overflow)?;
        let retain_until = match &outcome {
            ClaimOutcome::Claimed {
                key_package_ref, ..
            } => self
                .packages
                .get(key_package_ref)
                .map_or(timeout, |package| package.expires_at.max(timeout)),
            ClaimOutcome::Unavailable => timeout,
        };
        Ok(PlannedClaim {
            key,
            record: ClaimRecord {
                parameters,
                outcome,
                retain_until,
            },
            fresh: true,
        })
    }

    fn dispense(
        &self,
        parameters: &ClaimParameters,
        now: u64,
    ) -> Result<ClaimOutcome, DirectoryError> {
        let entry = self
            .accounts
            .get(&parameters.target_account_digest)
            .ok_or(DirectoryError::KeyUnavailable)?;
        if !entry.device_active(&parameters.target_device_id) {
            return Err(DirectoryError::DeviceInactive);
        }
        let floor = now
            .checked_add(MIN_KEY_PACKAGE_CLAIM_VALIDITY_SECONDS)
            .ok_or(DirectoryError::Overflow)?;
        let candidate = self.packages.iter().find(|(_, package)| {
            package.account_digest == parameters.target_account_digest
                && package.device_id == parameters.target_device_id
                && package.suite == parameters.suite
                && package.not_before <= now
                && package.expires_at >= floor
        });
        Ok(match candidate {
            Some((reference, package)) => ClaimOutcome::Claimed {
                key_package_ref: reference.clone(),
                object_id: package.object_id,
            },
            None => ClaimOutcome::Unavailable,
        })
    }

    /// The stored outcome of a claim operation.
    #[must_use]
    pub fn claim_status(&self, claimant_digest: &Id, operation_id: &Id16) -> Option<&ClaimOutcome> {
        self.claims
            .get(&(*claimant_digest, *operation_id))
            .map(|record| &record.outcome)
    }

    /// The parameters and outcome stored for a claim operation: the result
    /// `CLAIM STATUS` returns names the original claim's target, not the
    /// device that asks (companion 11.6).
    #[must_use]
    pub fn stored_claim(
        &self,
        claimant_digest: &Id,
        operation_id: &Id16,
    ) -> Option<(ClaimParameters, &ClaimOutcome)> {
        self.claims
            .get(&(*claimant_digest, *operation_id))
            .map(|record| (record.parameters, &record.outcome))
    }

    /// The deadline of the claim mapping. A caller persisting the result
    /// writes this value, including any longer published package lifetime.
    #[must_use]
    pub fn claim_retained_until(&self, claimant: &Id, operation: &Id16) -> Option<u64> {
        self.claims
            .get(&(*claimant, *operation))
            .map(|record| record.retain_until)
    }

    /// Visits claim mappings after a maintenance cursor, in key order. The
    /// caller limits how many entries it examines in one pass.
    pub fn claims_after(
        &self,
        after: Option<(Id, Id16)>,
    ) -> impl Iterator<Item = ((Id, Id16), u64, &ClaimOutcome)> {
        let start = after.map_or(Unbounded, Excluded);
        self.claims
            .range((start, Unbounded))
            .map(|(key, record)| (*key, record.retain_until, &record.outcome))
    }

    /// Removes a claim after its durable deletion has committed.
    pub fn forget_claim(&mut self, claimant: &Id, operation: &Id16) {
        let claims = Arc::make_mut(&mut self.claims);
        if let Some(record) = claims.remove(&(*claimant, *operation)) {
            Self::release_reference(&mut self.spent, &record.outcome);
        }
        if claims.is_empty() {
            claims.clear();
        }
    }

    /// Published packages of one device.
    #[must_use]
    pub fn stock(&self, account_digest: &Id, device_id: &Id16) -> usize {
        self.packages
            .values()
            .filter(|package| {
                package.account_digest == *account_digest && package.device_id == *device_id
            })
            .count()
    }

    /// Removes expired packages, claims, and challenges; returns the burned
    /// package references.
    pub fn expire(&mut self, now: u64) -> Vec<Vec<u8>> {
        let burned: Vec<Vec<u8>> = self
            .packages
            .iter()
            .filter(|(_, package)| package.expires_at <= now)
            .map(|(reference, _)| reference.clone())
            .collect();
        for reference in &burned {
            self.packages.remove(reference);
        }
        Arc::make_mut(&mut self.claims).retain(|_, record| {
            let keep = record.retain_until > now;
            if !keep {
                Self::release_reference(&mut self.spent, &record.outcome);
            }
            keep
        });
        for entry in self.accounts.values_mut() {
            for attachment in entry.attachments.values_mut() {
                if attachment
                    .challenge
                    .is_some_and(|challenge| challenge.expires_at <= now)
                {
                    attachment.challenge = None;
                }
            }
        }
        burned
    }
}

#[cfg(test)]
#[path = "tests/directory.rs"]
mod tests;
