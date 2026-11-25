//! One serializable coordinator cut for protected claim reads, choices and signed genesis.
#![forbid(unsafe_code)]

use agenc_relay_auth::initial_root::{ClaimRecord, ClaimState};
use agenc_relay_domain::{AccountGenesisPolicy, MutationPlan};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::e2ee_records::initial_root::{
    FORMAT_KEY, InitialRootRow, KIND, RootClaimOwner, RootClaimState,
};
use agenc_relay_storage::{PersistentRecordValue, StorageError, StoredKey, TableId};
use agenc_relay_types::{AccountId, Generation, RecoveryEpoch, Revision};

use super::StateCoreContext;
use super::durable::AccountServiceDurableWrite;
use crate::RuntimeError;

/// An opaque exact snapshot taken before a private response was prepared.
pub(crate) struct InitialRootCut {
    account: AccountId,
    generation: Generation,
    revision: Revision,
}

impl StateCoreContext {
    pub(crate) fn stage_initial_root_creation(
        &self,
        claim: &agenc_relay_auth::CreatedRootClaim,
        epoch: RecoveryEpoch,
        revision: u64,
        writes: &mut Vec<AccountServiceDurableWrite>,
    ) -> Result<(), RuntimeError> {
        let binding = claim.binding();
        if binding.network_id() != self.keys.binding().network_id()
            || binding.recovery_epoch() != epoch
            || self.index.holds(
                TableId::Account,
                &super::durable::KeyDeriver::account_key(claim.account())?,
            )
        {
            return Err(inconsistent());
        }
        let row = RootClaimOwner {
            network: binding.network_id(),
            account: claim.account(),
            epoch,
            start: binding.client_request_id(),
            owner: agenc_relay_crypto::InitialRootClaimOwner::from_protected_bytes(
                *claim.owner().expose_for_storage(),
            ),
            state: RootClaimState::Reserved,
        };
        let marker = StoredKey::new(FORMAT_KEY.to_vec())?;
        writes
            .try_reserve_exact(2)
            .map_err(|_| RuntimeError::MemoryExhausted)?;
        if !self.index.holds(TableId::E2eeState, &marker) {
            writes.push(initial_root_write(
                revision,
                marker,
                InitialRootRow::format()?,
            )?);
        }
        writes.push(owned_write(revision, &row)?);
        Ok(())
    }

    fn root_owner(&self, account: AccountId) -> Result<Option<&RootClaimOwner>, RuntimeError> {
        let class = self
            .domain
            .account(account)
            .map(agenc_relay_domain::AccountState::genesis_policy);
        let row = self
            .index
            .initial_root_owners
            .get(&account)
            .map(|held| held.row());
        match (class, row) {
            (None | Some(AccountGenesisPolicy::Legacy), None) => Ok(None),
            (Some(AccountGenesisPolicy::Guarded), Some(row))
                if row.network == self.keys.binding().network_id() =>
            {
                Ok(Some(row))
            }
            _ => Err(inconsistent()),
        }
    }

    /// Reconciles the retained account after a durable receipt.
    pub(crate) fn initial_root_claim(
        &self,
        account: AccountId,
    ) -> Result<Option<ClaimRecord<'_>>, RuntimeError> {
        Ok(self.root_owner(account)?.map(|row| ClaimRecord {
            network: row.network,
            account,
            creation_epoch: row.epoch,
            creation_request: row.start,
            owner: &row.owner,
            state: match row.state {
                RootClaimState::Reserved => ClaimState::Reserved,
                RootClaimState::Chosen(fp) => ClaimState::Chosen(fp),
                RootClaimState::Published {
                    fingerprint,
                    object_id,
                } => ClaimState::Published {
                    fingerprint,
                    object_id,
                },
            },
        }))
    }

    /// Holds a checked revision and registration through the protected response preparation.
    pub(crate) fn initial_root_admission(
        &self,
        account: AccountId,
        generation: Generation,
    ) -> Result<(InitialRootCut, Option<ClaimRecord<'_>>), RuntimeError> {
        self.current_root_account(account, generation)?;
        let cut = InitialRootCut {
            account,
            generation,
            revision: self.domain.revision(),
        };
        Ok((cut, self.initial_root_claim(account)?))
    }

    fn current_root_account(
        &self,
        account: AccountId,
        generation: Generation,
    ) -> Result<(), RuntimeError> {
        if self.pending_len() != 0
            || self
                .domain
                .account(account)
                .is_none_or(|a| a.session_generation() != generation)
        {
            return Err(inconsistent());
        }
        Ok(())
    }

    /// Even a pure read is abandoned if the committed cut or live registration has moved.
    pub(crate) fn plan_initial_root_choice(
        &self,
        cut: InitialRootCut,
        choice: Option<[u8; 32]>,
        writes: &mut Vec<AccountServiceDurableWrite>,
    ) -> Result<MutationPlan, RuntimeError> {
        self.current_root_account(cut.account, cut.generation)?;
        if self.domain.revision() != cut.revision {
            return Err(inconsistent());
        }
        let row = self.root_owner(cut.account)?;
        let plan = self
            .domain
            .plan_account_service_checkpoint()
            .map_err(|_| RuntimeError::InvalidValue)?;
        if let Some(choice) = choice {
            let next = row
                .ok_or_else(inconsistent)?
                .transition(RootClaimState::Chosen(choice))?;
            writes.push(owned_write(plan.resulting_revision().get(), &next)?);
        }
        Ok(plan)
    }

    pub(crate) fn plan_signed_root(
        &self,
        account: AccountId,
        generation: Generation,
        root_generation: u64,
        fingerprint: [u8; 32],
        object_id: [u8; 32],
    ) -> Result<Option<AccountServiceDurableWrite>, E2eeReplyCode> {
        if self.pending_len() != 0 {
            return Err(E2eeReplyCode::RateLimited);
        }
        self.current_root_account(account, generation)
            .map_err(|_| E2eeReplyCode::AccountRequired)?;
        let Some(row) = self
            .root_owner(account)
            .map_err(|_| E2eeReplyCode::RateLimited)?
        else {
            return Ok(None);
        };
        match (root_generation, row.state) {
            (0, RootClaimState::Chosen(chosen)) if chosen == fingerprint => {
                let next = row
                    .transition(RootClaimState::Published {
                        fingerprint,
                        object_id,
                    })
                    .map_err(|_| E2eeReplyCode::BindingAuthInvalid)?;
                let revision = self
                    .domain
                    .revision()
                    .checked_add(1)
                    .map_err(|_| E2eeReplyCode::RateLimited)?;
                owned_write(revision.get(), &next)
                    .map(Some)
                    .map_err(|_| E2eeReplyCode::RateLimited)
            }
            (1.., RootClaimState::Published { .. }) => Ok(None),
            _ => Err(E2eeReplyCode::BindingAuthInvalid),
        }
    }
}

fn inconsistent() -> RuntimeError {
    RuntimeError::Storage(StorageError::StaleState)
}

fn owned_write(
    revision: u64,
    row: &RootClaimOwner,
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    initial_root_write(
        revision,
        RootClaimOwner::key(row.network, row.account)?,
        row.encode()?,
    )
}

fn initial_root_write(
    revision: u64,
    key: StoredKey,
    body: Vec<u8>,
) -> Result<AccountServiceDurableWrite, RuntimeError> {
    let value = PersistentRecordValue::new(
        TableId::E2eeState,
        KIND,
        revision,
        0,
        None,
        Vec::new(),
        body,
    )?;
    AccountServiceDurableWrite::put(TableId::E2eeState, key, value.encode()?)
}

#[cfg(test)]
mod tests;
