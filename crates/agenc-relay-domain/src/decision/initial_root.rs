//! Revision-fenced transitions of one existing account's initial signed root.
#![forbid(unsafe_code)]

use agenc_relay_types::{AccountId, Generation};

use super::{
    DomainError, DomainState, Mutation, MutationPlan, PlanParts, RecipientSet, StorageClass,
};
use crate::{AccountState, InitialRootState};

impl DomainState {
    /// Plans the immutable choice from a freshly authorized private request.
    /// Reads and exact replays retain the same account disposition.
    pub fn plan_initial_root_choice(
        &self,
        account: AccountId,
        generation: Generation,
        fingerprint: Option<[u8; 32]>,
    ) -> Result<MutationPlan, DomainError> {
        let owner = self.root_account(account, generation)?;
        let Some(fingerprint) = fingerprint else {
            return self.plan_account_service_checkpoint();
        };
        if owner.initial_root() != Some(InitialRootState::Reserved) {
            return Err(DomainError::Forbidden);
        }
        self.set_initial_root(account, InitialRootState::Chosen(fingerprint))
    }

    /// Admits a fully verified signed root against the independently persisted
    /// genesis policy. The runtime joins any resulting transition to the
    /// signed directory, exact object and normal result in a single batch.
    pub fn plan_root_publication(
        &self,
        account: AccountId,
        session_generation: Generation,
        root_generation: u64,
        fingerprint: [u8; 32],
        object_id: [u8; 32],
    ) -> Result<Option<MutationPlan>, DomainError> {
        match (
            self.root_account(account, session_generation)?
                .initial_root(),
            root_generation,
        ) {
            (None, _) | (Some(InitialRootState::Published { .. }), 1..) => Ok(None),
            (Some(InitialRootState::Chosen(chosen)), 0) if chosen == fingerprint => self
                .set_initial_root(
                    account,
                    InitialRootState::Published {
                        fingerprint,
                        object_id,
                    },
                )
                .map(Some),
            _ => Err(DomainError::Forbidden),
        }
    }

    fn root_account(
        &self,
        account: AccountId,
        generation: Generation,
    ) -> Result<&AccountState, DomainError> {
        let owner = self.account(account).ok_or(DomainError::NotFound)?;
        if owner.session_generation() != generation {
            return Err(DomainError::StaleGeneration);
        }
        Ok(owner)
    }

    fn set_initial_root(
        &self,
        account: AccountId,
        next: InitialRootState,
    ) -> Result<MutationPlan, DomainError> {
        self.assemble_plan(PlanParts {
            mutations: vec![Mutation::SetInitialRoot(account, std::sync::Arc::new(next))],
            events: Vec::new(),
            recipients: RecipientSet::new(),
            failures: Vec::new(),
            message_batch: None,
            charges: Vec::new(),
            storage: StorageClass::Durable,
        })
    }
}
