//! The account directory (companion 8, 11.6, 13.1): root and roster heads,
//! device capability statements, binding-lock chains, device attachment
//! generations with compare-and-swap, and the one-use KeyPackage stock with
//! idempotent claims.
//!
//! Identifiers arrive already validated by the e2ee crate; this model owns
//! the state that relates them across time.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

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
    /// A KeyPackage reference is already published.
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
            Self::DuplicatePackage => "the key package is already published",
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
    pub connection_id: u64,
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
    claims: BTreeMap<(Id, Id16), ClaimRecord>,
}

impl Directory {
    /// An empty directory.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
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
        let next = entry.roster.as_ref().map_or(Ok(0), |roster| {
            roster
                .generation
                .checked_add(1)
                .ok_or(DirectoryError::Overflow)
        })?;
        if generation != next {
            return Err(DirectoryError::GenerationGap);
        }
        entry
            .capabilities
            .retain(|device, _| active_devices.contains(device));
        entry
            .attachments
            .retain(|device, _| active_devices.contains(device));
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

    /// The capability page of one account: every active device exactly
    /// once in Device ID order, with its highest object.
    #[must_use]
    pub fn capability_page(&self, account_digest: &Id) -> Vec<(Id16, Id)> {
        self.accounts
            .get(account_digest)
            .map(|entry| {
                entry
                    .capabilities
                    .iter()
                    .filter(|(device, _)| entry.device_active(device))
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
        connection_id: u64,
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
        connection_id: u64,
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
        if package.expires_at <= now || package.expires_at > ceiling {
            return Err(DirectoryError::ExpiryOutOfRange);
        }
        if self.packages.contains_key(&key_package_ref) {
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
        if let Some(record) = self.claims.get(&(claimant_digest, operation_id)) {
            if record.parameters != parameters {
                return Err(DirectoryError::OperationConflict);
            }
            return Ok(record.outcome.clone());
        }
        let outcome = self.dispense(&parameters, now)?;
        let retain_until = match &outcome {
            ClaimOutcome::Claimed {
                key_package_ref, ..
            } => self
                .packages
                .get(key_package_ref)
                .map_or(now, |package| package.expires_at)
                .max(now.saturating_add(KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS)),
            ClaimOutcome::Unavailable => now.saturating_add(KEY_PACKAGE_CLAIM_TIMEOUT_SECONDS),
        };
        if let ClaimOutcome::Claimed {
            key_package_ref, ..
        } = &outcome
        {
            self.packages.remove(key_package_ref);
        }
        self.claims.insert(
            (claimant_digest, operation_id),
            ClaimRecord {
                parameters,
                outcome: outcome.clone(),
                retain_until,
            },
        );
        Ok(outcome)
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
        self.claims.retain(|_, record| record.retain_until > now);
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
