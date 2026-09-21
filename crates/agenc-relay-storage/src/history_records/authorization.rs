//! Frozen authorization facts that prevent a later rejoin or policy enable from reviving a page.

use agenc_relay_types::AccountId;

use crate::StorageError;
use crate::codec::{Decoder, Encoder};

/// Exact principal, membership and history-policy generations used at query acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HistoryAuthorizationBinding {
    /// Session authenticated by the original origin.
    pub session_id: [u8; 16],
    /// User represented by that session.
    pub user_id: [u8; 16],
    /// Original session generation.
    pub session_generation: u64,
    /// Canonical 24-byte account identity, absent for a permitted guest.
    pub account_id: Option<[u8; 24]>,
    /// Zero exactly when no account is bound.
    pub account_session_generation: u64,
    /// Original channel-membership revision, distinguishing a later rejoin.
    pub membership_revision: u64,
    /// Original history authority epoch, unchanged by ordinary messages.
    pub history_authorization_generation: u64,
}

impl HistoryAuthorizationBinding {
    /// Validates the generation and account-presence invariants.
    pub fn validate(self) -> Result<(), StorageError> {
        if self.session_generation == 0
            || self.membership_revision == 0
            || self.history_authorization_generation == 0
            || self.account_id.is_none() != (self.account_session_generation == 0)
        {
            return Err(StorageError::InvalidEncoding);
        }
        if let Some(account) = self.account_id {
            AccountId::parse_wire_bytes(&account).map_err(|_| StorageError::InvalidEncoding)?;
        }
        Ok(())
    }

    pub(super) fn encode(self, encoder: &mut Encoder) -> Result<(), StorageError> {
        self.validate()?;
        encoder.put_fixed(&self.session_id)?;
        encoder.put_fixed(&self.user_id)?;
        encoder.put_u64(self.session_generation)?;
        match self.account_id {
            None => encoder.put_u16(0)?,
            Some(account) => {
                encoder.put_u16(1)?;
                encoder.put_fixed(&account)?;
            }
        }
        encoder.put_u64(self.account_session_generation)?;
        encoder.put_u64(self.membership_revision)?;
        encoder.put_u64(self.history_authorization_generation)
    }

    pub(super) fn decode(decoder: &mut Decoder<'_>) -> Result<Self, StorageError> {
        let record = Self {
            session_id: decoder.array()?,
            user_id: decoder.array()?,
            session_generation: decoder.u64()?,
            account_id: match decoder.u16()? {
                0 => None,
                1 => Some(decoder.array()?),
                _ => return Err(StorageError::InvalidEncoding),
            },
            account_session_generation: decoder.u64()?,
            membership_revision: decoder.u64()?,
            history_authorization_generation: decoder.u64()?,
        };
        record.validate()?;
        Ok(record)
    }
}
