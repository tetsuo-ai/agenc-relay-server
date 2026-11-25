//! Sealed directory usage of accounts admitted under the initial-root profile.
#![forbid(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use agenc_relay_e2ee::{ids::account_id_digest, limits::MAX_DIRECTORY_BYTES_PER_ACCOUNT};
use agenc_relay_storage::e2ee_records::ObjectOwnerRow;
use agenc_relay_storage::e2ee_records::initial_root::{RootClaimOwner, directory::*};
use agenc_relay_storage::{MIN_SEALED_RECORD_BYTES, StorageError, StoredKey, TableId};
use agenc_relay_types::{AccountId, NetworkId};

use super::{DurableIndex, IndexUpdate, IndexedRow, Projection};
use crate::RuntimeError;
use crate::budget::MemoryPermit;

mod restore;
mod stage;
pub(in crate::state_core) use stage::account;

type Digest = AccountDigest;

#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
enum Resource {
    Stock(StoredKey),
    Object(ObjectDigest),
}

#[derive(Clone)]
struct Holder {
    digest: Digest,
    _permit: Arc<MemoryPermit>,
}

impl PartialEq for Holder {
    fn eq(&self, other: &Self) -> bool {
        self.digest == other.digest
    }
}
impl Eq for Holder {}

const MEMBERSHIP_BYTES: usize = 1_024;

#[derive(Default)]
struct Usage {
    bytes: u64,
    /// Startup reads the authoritative account before its private owner row.
    /// Reserve their shared slot at the first retained allocation.
    restored_slot: Option<Arc<MemoryPermit>>,
    /// A removal only visits this account's resources, at most one per charged disk block.
    resources: BTreeSet<Resource>,
}

/// Installed only with the storage receipt for the matching mutation.
#[derive(Default, Eq, PartialEq)]
pub struct Updates {
    totals: BTreeMap<Digest, Option<u64>>,
    members: BTreeMap<Resource, Vec<Holder>>,
}

pub(in crate::state_core) struct Directory {
    limit: u64,
    users: BTreeMap<Digest, Usage>,
    members: BTreeMap<Resource, Vec<Holder>>,
}

impl Default for Directory {
    fn default() -> Self {
        Self {
            limit: MAX_DIRECTORY_BYTES_PER_ACCOUNT,
            users: BTreeMap::new(),
            members: BTreeMap::new(),
        }
    }
}

fn stale() -> RuntimeError {
    RuntimeError::Storage(StorageError::StaleState)
}

impl Directory {
    pub(super) fn restored_slot(&self, digest: &Digest) -> Option<&Arc<MemoryPermit>> {
        self.users.get(digest)?.restored_slot.as_ref()
    }
    pub(in crate::state_core) fn set_limit(&mut self, limit: u64) {
        self.limit = limit.min(MAX_DIRECTORY_BYTES_PER_ACCOUNT);
    }

    fn install_members(&mut self, resource: Resource, members: Vec<Holder>) {
        if let Some(previous) = self.members.remove(&resource) {
            for owner in previous {
                if let Some(usage) = self.users.get_mut(&owner.digest) {
                    usage.resources.remove(&resource);
                }
            }
        }
        for owner in &members {
            if let Some(usage) = self.users.get_mut(&owner.digest) {
                usage.resources.insert(resource.clone());
            }
        }
        if !members.is_empty() {
            self.members.insert(resource, members);
        }
    }

    fn remove_user(&mut self, digest: &Digest) {
        let Some(usage) = self.users.remove(digest) else {
            return;
        };
        for resource in usage.resources {
            let empty = self.members.get_mut(&resource).is_some_and(|members| {
                members.retain(|holder| holder.digest != *digest);
                members.is_empty()
            });
            if empty {
                self.members.remove(&resource);
            }
        }
    }

    pub(super) fn apply(&mut self, updates: &Updates) {
        for (digest, after) in &updates.totals {
            if let Some(bytes) = after {
                self.users.entry(*digest).or_default().bytes = *bytes;
            }
        }
        for (resource, members) in &updates.members {
            self.install_members(resource.clone(), members.clone());
        }
        for (digest, after) in &updates.totals {
            if after.is_none() {
                self.remove_user(digest);
            }
        }
    }
}

impl DurableIndex {
    pub(crate) fn with_guarded_directory_limit(mut self, limit: u64) -> Self {
        self.guarded_directory.set_limit(limit);
        self
    }
    fn current_charge(&self, table: TableId, key: &StoredKey) -> Result<u64, RuntimeError> {
        let size = match self.rows.get(&(table, key.clone())) {
            None => return Ok(0),
            Some(IndexedRow::Known(before)) => before.sealed_record_bytes() as usize,
            Some(IndexedRow::Pending { plaintext_bytes }) => plaintext_bytes
                .checked_add(MIN_SEALED_RECORD_BYTES)
                .ok_or(RuntimeError::Overflow)?,
        };
        Ok(sealed_charge(key, size)?)
    }

    fn holders(
        &self,
        resource: &Resource,
        digests: &BTreeSet<Digest>,
    ) -> Result<Vec<Holder>, RuntimeError> {
        let mut out = Vec::new();
        out.try_reserve_exact(digests.len())
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        for digest in digests {
            let previous = self
                .guarded_directory
                .members
                .get(resource)
                .and_then(|found| found.iter().find(|holder| holder.digest == *digest));
            let holder = match previous {
                Some(previous) => previous.clone(),
                None => Holder {
                    digest: *digest,
                    _permit: Arc::new(
                        self.initial_root_backing
                            .as_ref()
                            .ok_or(RuntimeError::MemoryExhausted)?
                            .reserve(MEMBERSHIP_BYTES)?,
                    ),
                },
            };
            out.push(holder);
        }
        Ok(out)
    }
}

impl Projection<'_> {
    pub(super) fn project_guarded_directory(&mut self, revision: u64) -> Result<(), RuntimeError> {
        let updates = stage::project(self).map_err(|error| match error {
            RuntimeError::MemoryExhausted => RuntimeError::Storage(StorageError::LimitExceeded),
            other => other,
        })?;
        for (digest, after) in &updates.totals {
            let subtotal = Subtotal {
                account: *digest,
                bytes: after.unwrap_or(4096),
            };
            let key = subtotal.key()?;
            if after.is_some() {
                self.put(TableId::E2eeState, key, subtotal.record(revision)?)?;
            } else {
                self.delete(TableId::E2eeState, key)?;
            }
        }
        if !updates.totals.is_empty() || !updates.members.is_empty() {
            self.updates
                .push(IndexUpdate::GuardedDirectory(Arc::new(updates)));
        }
        Ok(())
    }
}
