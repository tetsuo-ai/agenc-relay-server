//! The private claim and the public signed-directory publisher meet at this state owner.
#![forbid(unsafe_code)]

use agenc_relay_auth::initial_root::{ClaimRecord, ClaimState};
use agenc_relay_domain::{InitialRootState, MutationPlan};
use agenc_relay_e2ee::wire::reply::E2eeReplyCode;
use agenc_relay_storage::StorageError;
use agenc_relay_types::{AccountId, Generation};

use super::StateCoreContext;
use crate::RuntimeError;

impl StateCoreContext {
    /// Resolves the class independently of private row lookup, at one committed revision.
    pub(crate) fn initial_root_claim(
        &self,
        account: AccountId,
    ) -> Result<Option<ClaimRecord<'_>>, RuntimeError> {
        let state = self
            .domain
            .account(account)
            .and_then(agenc_relay_domain::AccountState::initial_root);
        match (state, self.index.initial_root_owners.get(&account)) {
            (None, None) => Ok(None),
            (Some(state), Some(owner)) if owner.network == self.keys.binding().network_id() => {
                let state = match state {
                    InitialRootState::Reserved => ClaimState::Reserved,
                    InitialRootState::Chosen(fingerprint) => ClaimState::Chosen(fingerprint),
                    InitialRootState::Published {
                        fingerprint,
                        object_id,
                    } => ClaimState::Published {
                        fingerprint,
                        object_id,
                    },
                };
                Ok(Some(ClaimRecord {
                    network: owner.network,
                    account,
                    creation_epoch: owner.epoch,
                    creation_request: owner.start,
                    owner: &owner.owner,
                    state,
                }))
            }
            _ => Err(RuntimeError::Storage(StorageError::StaleState)),
        }
    }

    /// Produces the stored-choice transition in the same revision as the authenticated reply.
    pub(crate) fn plan_initial_root_choice(
        &self,
        account: AccountId,
        generation: Generation,
        choice: Option<[u8; 32]>,
    ) -> Result<MutationPlan, RuntimeError> {
        self.initial_root_claim(account)?;
        self.domain
            .plan_initial_root_choice(account, generation, choice)
            .map_err(|_| RuntimeError::InvalidValue)
    }

    pub(crate) fn plan_signed_root(
        &self,
        account: AccountId,
        generation: Generation,
        root_generation: u64,
        fingerprint: [u8; 32],
        object_id: [u8; 32],
    ) -> Result<Option<MutationPlan>, E2eeReplyCode> {
        self.initial_root_claim(account)
            .map_err(|_| E2eeReplyCode::RateLimited)?;
        self.domain
            .plan_root_publication(account, generation, root_generation, fingerprint, object_id)
            .map_err(|_| E2eeReplyCode::BindingAuthInvalid)
    }
}
