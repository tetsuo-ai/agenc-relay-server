//! Opt-in account-service work executed in the existing bounded account pool.

use agenc_relay_auth::{
    AuthError, InitialRootServiceEnvelope,
    claimed_creation::{self, OpenedGuardedStart},
    initial_root::{self, ClaimRecord, ClaimState, OpenedClaim, PreparedClaim},
};
use agenc_relay_crypto::{AccountHpkePrivateKey, InitialRootClaimOwner, InitialRootExchange};
use agenc_relay_types::{AccountId, NetworkId, RecoveryEpoch, RequestId};
use std::sync::Arc;

/// A request whose profile and family were selected by the receiver before reading its body.
pub struct InitialRootOpenJob {
    private: Arc<AccountHpkePrivateKey>,
    network: NetworkId,
    epoch: RecoveryEpoch,
    envelope: InitialRootServiceEnvelope,
}

/// An exact, successfully opened guarded START or registered private request.
pub enum OpenedInitialRoot {
    /// Original OPAQUE registration, precommit and response authority.
    Creation(Box<OpenedGuardedStart>),
    /// The private registered operation and its one-use response authority.
    Claim(Box<OpenedClaim>),
}

impl InitialRootOpenJob {
    /// Binds the checked envelope to the service's actual current epoch and recipient.
    #[must_use]
    pub fn new(
        private: Arc<AccountHpkePrivateKey>,
        network: NetworkId,
        epoch: RecoveryEpoch,
        envelope: InitialRootServiceEnvelope,
    ) -> Self {
        Self {
            private,
            network,
            epoch,
            envelope,
        }
    }

    pub(super) fn execute(self) -> Result<OpenedInitialRoot, AuthError> {
        match self.envelope.message_kind() {
            InitialRootExchange::ClaimedCreateStart => claimed_creation::open_start(
                &self.private,
                self.network,
                self.epoch,
                &self.envelope,
            )
            .map(|opened| OpenedInitialRoot::Creation(Box::new(opened))),
            InitialRootExchange::Claim => {
                initial_root::open_claim(&self.private, self.network, self.epoch, &self.envelope)
                    .map(|opened| OpenedInitialRoot::Claim(Box::new(opened)))
            }
        }
    }
}

struct RetainedClaim {
    account: AccountId,
    network: NetworkId,
    creation_epoch: RecoveryEpoch,
    creation_request: RequestId,
    owner: InitialRootClaimOwner,
    state: ClaimState,
}

impl RetainedClaim {
    fn from_row(row: ClaimRecord<'_>) -> Self {
        Self {
            account: row.account,
            network: row.network,
            creation_epoch: row.creation_epoch,
            creation_request: row.creation_request,
            owner: InitialRootClaimOwner::from_protected_bytes(*row.owner.expose_for_storage()),
            state: row.state,
        }
    }

    fn row(&self) -> ClaimRecord<'_> {
        ClaimRecord {
            account: self.account,
            network: self.network,
            creation_epoch: self.creation_epoch,
            creation_request: self.creation_request,
            owner: &self.owner,
            state: self.state,
        }
    }
}

/// A bounded copy of the authorized current account cut and the opened private request.
pub struct InitialRootSealJob {
    request: OpenedClaim,
    registered: AccountId,
    record: Option<RetainedClaim>,
    response_count: u64,
}

impl InitialRootSealJob {
    /// The actor retains the exact cut to recheck when this ordered seal comes back.
    #[must_use]
    pub fn new(
        request: OpenedClaim,
        registered: AccountId,
        record: Option<ClaimRecord<'_>>,
        response_count: u64,
    ) -> Self {
        Self {
            request,
            registered,
            record: record.map(RetainedClaim::from_row),
            response_count,
        }
    }

    pub(super) fn execute(self) -> Result<PreparedClaim, AuthError> {
        let row = self.record.as_ref().map(RetainedClaim::row);
        self.request
            .prepare(Some(self.registered), row.as_ref(), self.response_count)
    }
}
