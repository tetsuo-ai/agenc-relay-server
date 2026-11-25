//! Validate guarded account ownership and its actual signed directory before startup.
#![forbid(unsafe_code)]

use agenc_relay_domain::{DurableAccount, InitialRootState};
use agenc_relay_e2ee::identity::{VerifiedRoot, verify_root_identity};
use agenc_relay_e2ee::ids::account_id_digest;
use agenc_relay_e2ee::limits::MAX_IDENTITY_OBJECT;
use agenc_relay_e2ee::object::{ArcWireObjectKind, ArcWireObjectRef};
use agenc_relay_e2ee::objects::identity::ArcRootIdentity;
use agenc_relay_e2ee::tls::{DecodeBudget, TlsDecode};
use agenc_relay_storage::e2ee_records::initial_root::FORMAT_KEY;
use agenc_relay_storage::e2ee_records::{DirectoryRow, MAX_ROOT_CHAIN_LENGTH, ObjectRow};
use agenc_relay_storage::{
    PersistentRecordValue, ReadPlan, SealedRecord, StorageError, StoragePort, StoredKey, TableId,
};
use agenc_relay_types::AccountId;

use super::{KeyDeriver, Scan};
use crate::RuntimeError;
use crate::bridge::storage::read_blocking;

fn stale() -> RuntimeError {
    RuntimeError::Storage(StorageError::StaleState)
}

impl Scan {
    pub(super) fn check_initial_roots(
        &self,
        keys: &KeyDeriver,
        port: &StoragePort,
    ) -> Result<(), RuntimeError> {
        let format = StoredKey::new(FORMAT_KEY.to_vec())?;
        let marked = self.index.holds(TableId::E2eeState, &format);
        for account in self.accounts.values().filter(|a| a.initial_root.is_some()) {
            if !marked
                || !self
                    .index
                    .initial_root_owners
                    .contains_key(&account.account_id)
            {
                return Err(stale());
            }
            self.check_initial_directory(keys, port, account)?;
        }
        Ok(())
    }

    fn check_initial_directory(
        &self,
        keys: &KeyDeriver,
        port: &StoragePort,
        account: &DurableAccount,
    ) -> Result<(), RuntimeError> {
        let network = keys.binding().network_id();
        let id = account.account_id.to_text();
        let id = id.as_bytes().try_into().map_err(|_| stale())?;
        let digest = account_id_digest(network.as_bytes(), id).map_err(|_| stale())?;
        let key = DirectoryRow::identity_key(&digest)?;
        let Some(InitialRootState::Published {
            fingerprint,
            object_id,
        }) = account.initial_root.as_deref()
        else {
            return if self.index.holds(TableId::E2eeState, &key) {
                Err(stale())
            } else {
                Ok(())
            };
        };
        let row = self.bounded_root_read(
            keys,
            port,
            TableId::E2eeState,
            key,
            MAX_ROOT_CHAIN_LENGTH * 32 + 512,
        )?;
        let DirectoryRow::Identity {
            root_generation,
            root_fingerprint,
            object_id: head,
            chain_object_ids,
        } = DirectoryRow::decode(row.body())?
        else {
            return Err(stale());
        };
        if chain_object_ids.first() != Some(object_id) || chain_object_ids.last() != Some(&head) {
            return Err(stale());
        }
        let mut previous = None;
        for id in chain_object_ids {
            let verified =
                self.read_signed_root(keys, port, account.account_id, id, previous.as_ref())?;
            if previous.is_none() && verified.fingerprint != *fingerprint {
                return Err(stale());
            }
            previous = Some(verified);
        }
        if !previous.is_some_and(|root| {
            root.generation == root_generation && root.fingerprint == root_fingerprint
        }) {
            return Err(stale());
        }
        Ok(())
    }

    fn read_signed_root(
        &self,
        keys: &KeyDeriver,
        port: &StoragePort,
        account: AccountId,
        id: [u8; 32],
        previous: Option<&VerifiedRoot>,
    ) -> Result<VerifiedRoot, RuntimeError> {
        let key = StoredKey::new(id.to_vec())?;
        let row = self.bounded_root_read(
            keys,
            port,
            TableId::E2eeObject,
            key.clone(),
            MAX_IDENTITY_OBJECT + 512,
        )?;
        let object = ObjectRow::decode(row.body())?;
        if object.key()? != key {
            return Err(stale());
        }
        let object = ArcWireObjectRef::parse(&object.bytes).map_err(|_| stale())?;
        if object.kind() != ArcWireObjectKind::RootIdentity {
            return Err(stale());
        }
        let root = ArcRootIdentity::decode_exact(
            object.body(),
            &mut DecodeBudget::new(MAX_IDENTITY_OBJECT, 1 << 16),
        )
        .map_err(|_| stale())?;
        let verified =
            verify_root_identity(keys.binding().network_id().as_bytes(), &root, previous)
                .map_err(|_| stale())?;
        if verified.account_id.as_slice() != account.to_text().as_bytes() {
            return Err(stale());
        }
        Ok(verified)
    }

    fn bounded_root_read(
        &self,
        keys: &KeyDeriver,
        port: &StoragePort,
        table: TableId,
        key: StoredKey,
        maximum: usize,
    ) -> Result<PersistentRecordValue, RuntimeError> {
        let before = self.index.existing(table, &key)?.ok_or_else(stale)?;
        if before.sealed_record_bytes()
            > u32::try_from(maximum).map_err(|_| RuntimeError::Overflow)?
        {
            return Err(stale());
        }
        let result = read_blocking(port, ReadPlan::exact(table, key.clone()))?;
        let [record] = result.records.as_slice() else {
            return Err(stale());
        };
        if record.table != table || record.key != key {
            return Err(stale());
        }
        let envelope = SealedRecord::decode(&record.sealed_record)?;
        let opened = keys.open(table, &key, &envelope)?;
        Ok(PersistentRecordValue::decode(
            table,
            opened.expose_for_storage_codec(),
        )?)
    }
}
