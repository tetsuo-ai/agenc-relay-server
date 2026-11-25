//! Rebuild all guarded subtotals from the authenticated rows before listeners open.
#![forbid(unsafe_code)]

use super::*;
use agenc_relay_storage::PersistentRecordValue;
use agenc_relay_storage::e2ee_records::initial_root::{self, InitialRootRow};

impl DurableIndex {
    pub(in crate::state_core) fn restore_guarded_account(
        &mut self,
        network: NetworkId,
        id: AccountId,
    ) -> Result<(), RuntimeError> {
        let slot = self
            .initial_root_backing
            .as_ref()
            .ok_or(RuntimeError::MemoryExhausted)?
            .reserve(super::super::initial_root::ROOT_SLOT_CAPACITY)?;
        if self
            .guarded_directory
            .users
            .insert(
                account(network, id)?,
                Usage {
                    restored_slot: Some(Arc::new(slot)),
                    ..Usage::default()
                },
            )
            .is_some()
        {
            return Err(stale());
        }
        Ok(())
    }

    fn observed(&mut self, digest: Digest, charge: u64) -> Result<(), RuntimeError> {
        if let Some(usage) = self.guarded_directory.users.get_mut(&digest) {
            usage.bytes = usage
                .bytes
                .checked_add(charge)
                .ok_or(RuntimeError::Overflow)?;
            if usage.bytes > self.guarded_directory.limit {
                return Err(StorageError::LimitExceeded.into());
            }
        }
        Ok(())
    }

    pub(in crate::state_core) fn restore_directory_row(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
        sealed: usize,
        expected: &mut BTreeMap<Digest, u64>,
    ) -> Result<(), RuntimeError> {
        let charge = sealed_charge(key, sealed)?;
        if value.record_kind() == initial_root::KIND {
            return match InitialRootRow::check_record(key, value)? {
                InitialRootRow::Format => Ok(()),
                InitialRootRow::Owner(owner) => {
                    self.observed(account(owner.network, owner.account)?, charge)
                }
                InitialRootRow::Directory(subtotal) => {
                    if !self.guarded_directory.users.contains_key(&subtotal.account)
                        || expected.insert(subtotal.account, subtotal.bytes).is_some()
                    {
                        return Err(stale());
                    }
                    self.observed(subtotal.account, charge)
                }
            };
        }
        if self.guarded_directory.users.is_empty()
            || key
                .as_bytes()
                .starts_with(agenc_relay_storage::e2ee_records::prefix::OWNER)
        {
            return Ok(());
        }
        match Allocation::stored(TableId::E2eeState, key, value)? {
            Some(Allocation::Account(digest)) => self.observed(digest, charge),
            Some(Allocation::Stock(Some(digest)))
                if self.guarded_directory.users.contains_key(&digest) =>
            {
                self.observed(digest, charge)?;
                let key = Resource::Stock(key.clone());
                let holders = self.holders(&key, &BTreeSet::from([digest]))?;
                self.guarded_directory.install_members(key, holders);
                Ok(())
            }
            _ => Ok(()),
        }
    }

    pub(in crate::state_core) fn needs_directory_scan(&self) -> bool {
        !self.guarded_directory.users.is_empty()
    }

    pub(in crate::state_core) fn restore_directory_ownership(
        &mut self,
        key: &StoredKey,
        value: &PersistentRecordValue,
    ) -> Result<(), RuntimeError> {
        let Some(Allocation::Ownership(id, owners)) =
            Allocation::stored(TableId::E2eeState, key, value)?
        else {
            return Err(stale());
        };
        let mut digests = BTreeSet::new();
        for owner in owners {
            match owner {
                Payer::Account(digest) if self.guarded_directory.users.contains_key(&digest) => {
                    digests.insert(digest);
                }
                Payer::Account(_) => {}
                Payer::Stock(key) => {
                    digests.extend(
                        self.guarded_directory
                            .members
                            .get(&Resource::Stock(key))
                            .into_iter()
                            .flatten()
                            .map(|holder| holder.digest),
                    );
                }
            }
        }
        if digests.is_empty() {
            return Ok(());
        }
        let obj = self.current_charge(TableId::E2eeObject, &StoredKey::new(id.to_vec())?)?;
        let charge = self
            .current_charge(TableId::E2eeState, key)?
            .checked_add(obj)
            .ok_or(RuntimeError::Overflow)?;
        for digest in &digests {
            self.observed(*digest, charge)?;
        }
        let resource = Resource::Object(id);
        let holders = self.holders(&resource, &digests)?;
        self.guarded_directory.install_members(resource, holders);
        Ok(())
    }

    pub(in crate::state_core) fn verify_directory_totals(
        &self,
        expected: &BTreeMap<Digest, u64>,
    ) -> Result<(), RuntimeError> {
        if self.guarded_directory.users.len() != expected.len()
            || self
                .guarded_directory
                .users
                .iter()
                .any(|(id, entry)| expected.get(id) != Some(&entry.bytes))
        {
            return Err(stale());
        }
        Ok(())
    }
}
