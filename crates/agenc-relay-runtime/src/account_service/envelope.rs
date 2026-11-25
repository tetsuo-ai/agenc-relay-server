//! The two disjoint account envelope profiles accepted by the actor.

use super::{
    ACCOUNT_SERVICE_ENVELOPE_BYTES, AccountOpenJob, AccountServiceConfig, AccountServiceEnvelope,
    AccountServiceMessageKind, RequestId, RuntimeCryptoJob, RuntimeError,
};
use crate::bridge::crypto::InitialRootOpenJob;
use agenc_relay_auth::InitialRootServiceEnvelope;
use agenc_relay_crypto::InitialRootExchange;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum RequestKind {
    Base(AccountServiceMessageKind),
    InitialRoot(InitialRootExchange),
}

pub(super) enum RoutedEnvelope {
    Base(AccountServiceEnvelope),
    InitialRoot(InitialRootServiceEnvelope),
}

impl From<AccountServiceEnvelope> for RoutedEnvelope {
    fn from(value: AccountServiceEnvelope) -> Self {
        Self::Base(value)
    }
}

impl RoutedEnvelope {
    pub(super) fn parse(
        bytes: [u8; ACCOUNT_SERVICE_ENVELOPE_BYTES],
        kind: RequestKind,
    ) -> Result<Self, RuntimeError> {
        match kind {
            RequestKind::Base(expected) => {
                let envelope =
                    AccountServiceEnvelope::parse(bytes).map_err(|_| RuntimeError::InvalidValue)?;
                if envelope.message_kind() != expected {
                    return Err(RuntimeError::InvalidValue);
                }
                Ok(Self::Base(envelope))
            }
            RequestKind::InitialRoot(expected) => {
                let envelope = InitialRootServiceEnvelope::parse(bytes)
                    .map_err(|_| RuntimeError::InvalidValue)?;
                if envelope.message_kind() != expected {
                    return Err(RuntimeError::InvalidValue);
                }
                Ok(Self::InitialRoot(envelope))
            }
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8; ACCOUNT_SERVICE_ENVELOPE_BYTES] {
        match self {
            Self::Base(e) => e.as_bytes(),
            Self::InitialRoot(e) => e.as_bytes(),
        }
    }

    pub(super) fn client_request_id(&self) -> RequestId {
        match self {
            Self::Base(e) => e.client_request_id(),
            Self::InitialRoot(e) => e.client_request_id(),
        }
    }

    pub(super) fn open_job(
        &self,
        config: &AccountServiceConfig,
    ) -> Result<RuntimeCryptoJob, RuntimeError> {
        let key = Arc::clone(&config.hpke_private_key);
        match self {
            Self::Base(e) => {
                let copy = AccountServiceEnvelope::parse(*e.as_bytes())
                    .map_err(|_| RuntimeError::InvalidValue)?;
                Ok(RuntimeCryptoJob::AccountOpen(Box::new(
                    AccountOpenJob::new(
                        key,
                        config.recovery_epoch,
                        config.network_id,
                        e.message_kind(),
                        copy,
                    ),
                )))
            }
            Self::InitialRoot(e) => {
                let copy = InitialRootServiceEnvelope::parse(*e.as_bytes())
                    .map_err(|_| RuntimeError::InvalidValue)?;
                Ok(RuntimeCryptoJob::InitialRootOpen(Box::new(
                    InitialRootOpenJob::new(key, config.network_id, config.recovery_epoch, copy),
                )))
            }
        }
    }
}
