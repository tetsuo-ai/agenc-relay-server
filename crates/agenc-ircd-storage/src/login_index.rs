//! Private login-index value codecs and two-generation transition state.

use agenc_ircd_crypto::{LoginIndexDigest, LoginIndexKey, LoginIndexKeyId, derive_login_index};
use agenc_ircd_types::{AccountId, NetworkId, NormalizedLogin, OpaqueCredentialId, TransactionId};
use subtle::ConstantTimeEq as _;

use crate::codec::{Decoder, Encoder};
use crate::{
    ExistingRecord, RecordMutation, StorageAccountingLimits, StorageError, StorageFaultSite,
    StorageMutationBatch, StorageMutationHead, StoredKey, TableId,
};

/// Fixed key of the single login-index key-state record.
pub const LOGIN_INDEX_KEY_STATE_KEY: &[u8] = b"agenc-chat/login-index-key-state/v1";
/// Exact redb key size: generation plus keyed digest.
pub const LOGIN_INDEX_STORED_KEY_BYTES: usize = 36;

/// Private generation/digest lookup key with no formatting surface.
pub struct LoginIndexStoredKey {
    generation: u32,
    digest: [u8; 32],
}

impl LoginIndexStoredKey {
    /// Binds one nonzero generation to a derived private digest.
    pub fn new(generation: u32, digest: LoginIndexDigest) -> Result<Self, StorageError> {
        if generation == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            generation,
            digest: *digest.expose_for_storage_key(),
        })
    }

    /// Parses the exact 36-byte private redb key.
    pub fn decode(bytes: &[u8]) -> Result<Self, StorageError> {
        if bytes.len() != LOGIN_INDEX_STORED_KEY_BYTES {
            return Err(StorageError::InvalidEncoding);
        }
        let mut decoder = Decoder::new(bytes);
        let generation = decoder.u32()?;
        let digest = decoder.array()?;
        decoder.finish()?;
        if generation == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self { generation, digest })
    }

    /// Encodes the exact private redb key.
    pub fn encode(&self) -> Result<StoredKey, StorageError> {
        let mut encoder =
            Encoder::with_capacity(LOGIN_INDEX_STORED_KEY_BYTES, LOGIN_INDEX_STORED_KEY_BYTES)?;
        encoder.put_u32(self.generation)?;
        encoder.put_fixed(&self.digest)?;
        StoredKey::new(encoder.finish())
    }

    /// Returns the registered nonzero generation.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    fn digest_matches(&self, candidate: &[u8; 32]) -> bool {
        bool::from(self.digest.ct_eq(candidate))
    }

    fn dummy(generation: u32) -> Result<Self, StorageError> {
        if generation == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            generation,
            digest: [0; 32],
        })
    }

    fn same_identity(&self, other: &Self) -> bool {
        self.generation == other.generation && self.digest_matches(&other.digest)
    }
}

/// Closed login-index ownership or conflict state.
pub enum LoginIndexValueKind {
    /// Live account and OPAQUE credential binding.
    Live {
        /// Canonical public account authority.
        account_id: AccountId,
        /// Private OPAQUE lookup identity.
        opaque_credential_id: OpaqueCredentialId,
    },
    /// In-progress account-creation reservation.
    CreationReservation {
        /// Owning account-service transaction.
        transaction_id: TransactionId,
        /// Exclusive expiration second.
        expires_at: u64,
    },
    /// Deleted-identity conflict tombstone.
    DeletionTombstone {
        /// Deleted account authority.
        deleted_account_id: AccountId,
        /// Exclusive release second.
        expires_at: u64,
    },
}

/// Plaintext that repeats its private stored-key generation and digest.
pub struct LoginIndexValue {
    generation: u32,
    digest: [u8; 32],
    kind: LoginIndexValueKind,
}

impl LoginIndexValue {
    /// Constructs a value that exactly repeats its private redb key.
    pub fn new(key: &LoginIndexStoredKey, kind: LoginIndexValueKind) -> Result<Self, StorageError> {
        match &kind {
            LoginIndexValueKind::CreationReservation { expires_at, .. }
            | LoginIndexValueKind::DeletionTombstone { expires_at, .. }
                if *expires_at == 0 =>
            {
                return Err(StorageError::InvalidEncoding);
            }
            _ => {}
        }
        Ok(Self {
            generation: key.generation,
            digest: key.digest,
            kind,
        })
    }

    /// Parses one full-consumption version-one value and checks its redb key.
    pub fn decode(encoded: &[u8], stored_key: &LoginIndexStoredKey) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let generation = decoder.u32()?;
        let digest: [u8; 32] = decoder.array()?;
        if generation != stored_key.generation || !stored_key.digest_matches(&digest) {
            return Err(StorageError::AuthenticationFailed);
        }
        let kind = match decoder.u16()? {
            1 => LoginIndexValueKind::Live {
                account_id: AccountId::parse_wire_bytes(decoder.take(24)?)
                    .map_err(|_| StorageError::InvalidEncoding)?,
                opaque_credential_id: OpaqueCredentialId::from_bytes(decoder.array()?),
            },
            2 => {
                let transaction_id = TransactionId::from_bytes(decoder.array()?);
                let expires_at = decoder.u64()?;
                if expires_at == 0 {
                    return Err(StorageError::InvalidEncoding);
                }
                LoginIndexValueKind::CreationReservation {
                    transaction_id,
                    expires_at,
                }
            }
            3 => {
                let deleted_account_id = AccountId::parse_wire_bytes(decoder.take(24)?)
                    .map_err(|_| StorageError::InvalidEncoding)?;
                let expires_at = decoder.u64()?;
                if expires_at == 0 {
                    return Err(StorageError::InvalidEncoding);
                }
                LoginIndexValueKind::DeletionTombstone {
                    deleted_account_id,
                    expires_at,
                }
            }
            _ => return Err(StorageError::UnsupportedVersion),
        };
        decoder.finish()?;
        Ok(Self {
            generation,
            digest,
            kind,
        })
    }

    /// Encodes one canonical version-one value.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(80, 104)?;
        encoder.put_u16(1)?;
        encoder.put_u32(self.generation)?;
        encoder.put_fixed(&self.digest)?;
        match &self.kind {
            LoginIndexValueKind::Live {
                account_id,
                opaque_credential_id,
            } => {
                encoder.put_u16(1)?;
                encoder.put_fixed(account_id.to_text().as_bytes())?;
                encoder.put_fixed(opaque_credential_id.expose_for_account_service())?;
            }
            LoginIndexValueKind::CreationReservation {
                transaction_id,
                expires_at,
            } => {
                if *expires_at == 0 {
                    return Err(StorageError::InvalidEncoding);
                }
                encoder.put_u16(2)?;
                encoder.put_fixed(transaction_id.as_bytes())?;
                encoder.put_u64(*expires_at)?;
            }
            LoginIndexValueKind::DeletionTombstone {
                deleted_account_id,
                expires_at,
            } => {
                if *expires_at == 0 {
                    return Err(StorageError::InvalidEncoding);
                }
                encoder.put_u16(3)?;
                encoder.put_fixed(deleted_account_id.to_text().as_bytes())?;
                encoder.put_u64(*expires_at)?;
            }
        }
        Ok(encoder.finish())
    }

    /// Returns the repeated generation.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Returns the closed value arm.
    #[must_use]
    pub const fn kind(&self) -> &LoginIndexValueKind {
        &self.kind
    }
}

/// Stable or one-previous-generation login-index key state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoginIndexKeyState {
    /// Only one current generation is registered.
    Stable {
        /// Nonzero current generation.
        current_generation: u32,
        /// Configured current-key ID.
        current_key_id: LoginIndexKeyId,
    },
    /// Exactly one consecutive previous generation remains.
    Transition {
        /// New current generation.
        current_generation: u32,
        /// New current-key ID.
        current_key_id: LoginIndexKeyId,
        /// Exact predecessor generation.
        previous_generation: u32,
        /// Previous-key ID.
        previous_key_id: LoginIndexKeyId,
        /// Number of remaining previous-generation entries.
        previous_entry_count: u64,
    },
}

impl LoginIndexKeyState {
    /// Creates the initial or finalized stable state.
    pub fn stable(
        current_generation: u32,
        current_key_id: LoginIndexKeyId,
    ) -> Result<Self, StorageError> {
        if current_generation == 0 {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self::Stable {
            current_generation,
            current_key_id,
        })
    }

    /// Starts exactly one consecutive transition.
    pub fn transition(
        previous_generation: u32,
        previous_key_id: LoginIndexKeyId,
        current_key_id: LoginIndexKeyId,
        previous_entry_count: u64,
    ) -> Result<Self, StorageError> {
        let current_generation = previous_generation
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        if previous_generation == 0 || previous_key_id == current_key_id {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self::Transition {
            current_generation,
            current_key_id,
            previous_generation,
            previous_key_id,
            previous_entry_count,
        })
    }

    /// Parses and validates the exact key-state union.
    pub fn decode(encoded: &[u8]) -> Result<Self, StorageError> {
        let mut decoder = Decoder::new(encoded);
        if decoder.u16()? != 1 {
            return Err(StorageError::UnsupportedVersion);
        }
        let kind = decoder.u16()?;
        let current_generation = decoder.u32()?;
        let current_key_id = LoginIndexKeyId::from_bytes(decoder.array()?);
        let previous_generation = decoder.u32()?;
        let previous_key_id_bytes = decoder.vector_u32(32)?;
        let previous_entry_count = decoder.u64()?;
        decoder.finish()?;
        match kind {
            1 if previous_generation == 0
                && previous_key_id_bytes.is_empty()
                && previous_entry_count == 0 =>
            {
                Self::stable(current_generation, current_key_id)
            }
            2 if previous_key_id_bytes.len() == 32 => Self::transition(
                previous_generation,
                LoginIndexKeyId::from_bytes(
                    previous_key_id_bytes
                        .try_into()
                        .map_err(|_| StorageError::InvalidEncoding)?,
                ),
                current_key_id,
                previous_entry_count,
            )
            .and_then(|state| {
                if state.current_generation() == current_generation {
                    Ok(state)
                } else {
                    Err(StorageError::InvalidEncoding)
                }
            }),
            _ => Err(StorageError::InvalidEncoding),
        }
    }

    /// Encodes the exact key-state union.
    pub fn encode(self) -> Result<Vec<u8>, StorageError> {
        let mut encoder = Encoder::with_capacity(88, 88)?;
        encoder.put_u16(1)?;
        match self {
            Self::Stable {
                current_generation,
                current_key_id,
            } => {
                encoder.put_u16(1)?;
                encoder.put_u32(current_generation)?;
                encoder.put_fixed(current_key_id.as_bytes())?;
                encoder.put_u32(0)?;
                encoder.put_vector_u32(&[])?;
                encoder.put_u64(0)?;
            }
            Self::Transition {
                current_generation,
                current_key_id,
                previous_generation,
                previous_key_id,
                previous_entry_count,
            } => {
                encoder.put_u16(2)?;
                encoder.put_u32(current_generation)?;
                encoder.put_fixed(current_key_id.as_bytes())?;
                encoder.put_u32(previous_generation)?;
                encoder.put_vector_u32(previous_key_id.as_bytes())?;
                encoder.put_u64(previous_entry_count)?;
            }
        }
        Ok(encoder.finish())
    }

    /// Requires exact agreement with the configured current and optional previous keys.
    pub fn validate_configured_keys(
        self,
        network_id: NetworkId,
        current_key: &LoginIndexKey,
        previous_key: Option<&LoginIndexKey>,
    ) -> Result<(), StorageError> {
        match (self, previous_key) {
            (Self::Stable { current_key_id, .. }, None)
                if current_key.key_id(network_id) == current_key_id =>
            {
                Ok(())
            }
            (
                Self::Transition {
                    current_key_id,
                    previous_key_id,
                    ..
                },
                Some(previous),
            ) if current_key.key_id(network_id) == current_key_id
                && previous.key_id(network_id) == previous_key_id =>
            {
                Ok(())
            }
            _ => Err(StorageError::AuthenticationFailed),
        }
    }

    /// Returns the current generation.
    #[must_use]
    pub const fn current_generation(self) -> u32 {
        match self {
            Self::Stable {
                current_generation, ..
            }
            | Self::Transition {
                current_generation, ..
            } => current_generation,
        }
    }

    /// Returns the optional previous generation and exact remaining count.
    #[must_use]
    pub const fn previous(self) -> Option<(u32, u64)> {
        match self {
            Self::Stable { .. } => None,
            Self::Transition {
                previous_generation,
                previous_entry_count,
                ..
            } => Some((previous_generation, previous_entry_count)),
        }
    }

    /// Returns the configured current key identifier.
    #[must_use]
    pub const fn current_key_id(self) -> LoginIndexKeyId {
        match self {
            Self::Stable { current_key_id, .. } | Self::Transition { current_key_id, .. } => {
                current_key_id
            }
        }
    }

    /// Starts an offline rotation from stable state after a complete old-generation scan.
    pub fn start_rotation(
        self,
        new_key_id: LoginIndexKeyId,
        scanned_previous_entries: u64,
    ) -> Result<Self, StorageError> {
        let Self::Stable {
            current_generation,
            current_key_id,
        } = self
        else {
            return Err(StorageError::StaleState);
        };
        Self::transition(
            current_generation,
            current_key_id,
            new_key_id,
            scanned_previous_entries,
        )
    }

    /// Decrements exactly one migrated or expired previous entry.
    pub fn decrement_previous(self) -> Result<Self, StorageError> {
        let Self::Transition {
            current_generation,
            current_key_id,
            previous_generation,
            previous_key_id,
            previous_entry_count,
        } = self
        else {
            return Err(StorageError::StaleState);
        };
        Ok(Self::Transition {
            current_generation,
            current_key_id,
            previous_generation,
            previous_key_id,
            previous_entry_count: previous_entry_count
                .checked_sub(1)
                .ok_or(StorageError::StaleState)?,
        })
    }

    /// Finalizes only an exact zero-count transition.
    pub fn finish(self) -> Result<Self, StorageError> {
        let Self::Transition {
            current_generation,
            current_key_id,
            previous_entry_count: 0,
            ..
        } = self
        else {
            return Err(StorageError::StaleState);
        };
        Self::stable(current_generation, current_key_id)
    }
}

/// Fixed current-then-previous lookup schedule for one normalized login.
pub struct LoginIndexLookupSchedule {
    current: LoginIndexStoredKey,
    previous_or_dummy: LoginIndexStoredKey,
    transition: bool,
}

impl LoginIndexLookupSchedule {
    /// Derives exactly two storage lookups and verifies configured key-state agreement.
    pub fn new(
        network_id: NetworkId,
        login: &NormalizedLogin,
        state: LoginIndexKeyState,
        current_key: &LoginIndexKey,
        previous_key: Option<&LoginIndexKey>,
    ) -> Result<Self, StorageError> {
        state.validate_configured_keys(network_id, current_key, previous_key)?;
        let current = LoginIndexStoredKey::new(
            state.current_generation(),
            derive_login_index(current_key, network_id, login)?,
        )?;
        let (previous_or_dummy, transition) = match (state.previous(), previous_key) {
            (Some((generation, _)), Some(previous_key)) => (
                LoginIndexStoredKey::new(
                    generation,
                    derive_login_index(previous_key, network_id, login)?,
                )?,
                true,
            ),
            (None, None) => {
                let dummy = LoginIndexStoredKey::dummy(state.current_generation())?;
                if current.same_identity(&dummy) {
                    return Err(StorageError::AuthenticationFailed);
                }
                (dummy, false)
            }
            _ => return Err(StorageError::AuthenticationFailed),
        };
        Ok(Self {
            current,
            previous_or_dummy,
            transition,
        })
    }

    /// Borrows the mandatory first lookup key.
    #[must_use]
    pub const fn current(&self) -> &LoginIndexStoredKey {
        &self.current
    }

    /// Borrows the mandatory second lookup key, which is a dummy in stable state.
    #[must_use]
    pub const fn previous_or_dummy(&self) -> &LoginIndexStoredKey {
        &self.previous_or_dummy
    }

    /// Reports whether the second key belongs to a registered previous generation.
    #[must_use]
    pub const fn is_transition(&self) -> bool {
        self.transition
    }
}

/// Exact previous-to-current mutations authorized only after successful OPAQUE completion.
pub struct LoginIndexLazyMigration {
    previous_key: StoredKey,
    current_key: StoredKey,
    current_value: LoginIndexValue,
    resulting_key_state: LoginIndexKeyState,
}

impl LoginIndexLazyMigration {
    /// Validates one live previous-generation owner and derives its idempotent successor.
    #[expect(
        clippy::too_many_arguments,
        reason = "the constructor binds the complete successful-login storage proof"
    )]
    pub fn new(
        network_id: NetworkId,
        login: &NormalizedLogin,
        key_state: LoginIndexKeyState,
        current_key: &LoginIndexKey,
        previous_key: &LoginIndexKey,
        authenticated_account_id: AccountId,
        authenticated_credential_id: OpaqueCredentialId,
        previous_value: &LoginIndexValue,
    ) -> Result<Self, StorageError> {
        key_state.validate_configured_keys(network_id, current_key, Some(previous_key))?;
        let Some((previous_generation, _)) = key_state.previous() else {
            return Err(StorageError::StaleState);
        };
        let schedule = LoginIndexLookupSchedule::new(
            network_id,
            login,
            key_state,
            current_key,
            Some(previous_key),
        )?;
        if previous_value.generation() != previous_generation {
            return Err(StorageError::StaleState);
        }
        let LoginIndexValueKind::Live {
            account_id,
            opaque_credential_id,
        } = previous_value.kind()
        else {
            return Err(StorageError::StaleState);
        };
        let credential_matches = bool::from(
            opaque_credential_id
                .expose_for_account_service()
                .ct_eq(authenticated_credential_id.expose_for_account_service()),
        );
        if *account_id != authenticated_account_id || !credential_matches {
            return Err(StorageError::AuthenticationFailed);
        }
        let current_value = LoginIndexValue::new(
            schedule.current(),
            LoginIndexValueKind::Live {
                account_id: authenticated_account_id,
                opaque_credential_id: authenticated_credential_id,
            },
        )?;
        Ok(Self {
            previous_key: schedule.previous_or_dummy().encode()?,
            current_key: schedule.current().encode()?,
            current_value,
            resulting_key_state: key_state.decrement_previous()?,
        })
    }

    /// Borrows the old row deleted by the atomic authentication-finish batch.
    #[must_use]
    pub const fn previous_key(&self) -> &StoredKey {
        &self.previous_key
    }

    /// Borrows the current row inserted by the same batch.
    #[must_use]
    pub const fn current_key(&self) -> &StoredKey {
        &self.current_key
    }

    /// Borrows the repeated current-generation live value.
    #[must_use]
    pub const fn current_value(&self) -> &LoginIndexValue {
        &self.current_value
    }

    /// Returns the exactly decremented transition state.
    #[must_use]
    pub const fn resulting_key_state(&self) -> LoginIndexKeyState {
        self.resulting_key_state
    }

    /// Builds the three exact mutations embedded in a successful authentication finish.
    pub fn into_mutations(
        self,
        previous_record: ExistingRecord,
        key_state_record: ExistingRecord,
    ) -> Result<[RecordMutation; 3], StorageError> {
        Ok([
            RecordMutation::delete(TableId::LoginIndex, self.previous_key, previous_record),
            RecordMutation::put(
                TableId::LoginIndex,
                self.current_key,
                1,
                None,
                self.current_value.encode()?,
            )?,
            RecordMutation::put(
                TableId::LoginIndexKeyState,
                StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
                1,
                Some(key_state_record),
                self.resulting_key_state.encode()?,
            )?,
        ])
    }
}

/// Atomic start/finalize constructors for the audited key-transition state machine.
pub struct LoginIndexTransitionBatch;

impl LoginIndexTransitionBatch {
    /// Starts exactly one previous/current overlap after a complete old-generation scan.
    pub fn start(
        head: StorageMutationHead,
        accounting: StorageAccountingLimits,
        stable_state: LoginIndexKeyState,
        new_key_id: LoginIndexKeyId,
        previous_entry_count: u64,
        key_state_record: ExistingRecord,
        audit_mutation: RecordMutation,
    ) -> Result<StorageMutationBatch, StorageError> {
        let transition = stable_state.start_rotation(new_key_id, previous_entry_count)?;
        Self::build(
            head,
            accounting,
            transition,
            key_state_record,
            audit_mutation,
            StorageFaultSite::LoginIndexRotationStart,
        )
    }

    /// Finalizes only a zero-count transition and removes configured previous-key authority.
    pub fn finalize(
        head: StorageMutationHead,
        accounting: StorageAccountingLimits,
        transition_state: LoginIndexKeyState,
        key_state_record: ExistingRecord,
        audit_mutation: RecordMutation,
    ) -> Result<StorageMutationBatch, StorageError> {
        let stable = transition_state.finish()?;
        Self::build(
            head,
            accounting,
            stable,
            key_state_record,
            audit_mutation,
            StorageFaultSite::LoginIndexRotationFinish,
        )
    }

    fn build(
        head: StorageMutationHead,
        accounting: StorageAccountingLimits,
        resulting_state: LoginIndexKeyState,
        key_state_record: ExistingRecord,
        audit_mutation: RecordMutation,
        fault_site: StorageFaultSite,
    ) -> Result<StorageMutationBatch, StorageError> {
        let expected_state_generation = head
            .expected_state_generation
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        if (
            audit_mutation.table(),
            audit_mutation.is_deletion(),
            head.state_advancing_plan_count,
            head.resulting_state_generation,
            head.resulting_account_service_response_count,
        ) != (
            TableId::Audit,
            false,
            1,
            expected_state_generation,
            head.expected_account_service_response_count,
        ) {
            return Err(StorageError::InvalidEncoding);
        }
        let key_state_mutation = RecordMutation::put(
            TableId::LoginIndexKeyState,
            StoredKey::new(LOGIN_INDEX_KEY_STATE_KEY.to_vec())?,
            1,
            Some(key_state_record),
            resulting_state.encode()?,
        )?;
        StorageMutationBatch::new(
            head,
            1,
            accounting,
            vec![key_state_mutation, audit_mutation],
        )
        .map(|batch| batch.with_fault_site(fault_site))
    }
}

/// Complete old-generation scan required before starting an offline key rotation.
pub struct LoginIndexTransitionPreflight {
    stable_state: LoginIndexKeyState,
    new_key_id: LoginIndexKeyId,
    previous_entry_count: u64,
}

impl LoginIndexTransitionPreflight {
    /// Starts a bounded scan only from stable state and a distinct new key ID.
    pub fn new(
        stable_state: LoginIndexKeyState,
        new_key_id: LoginIndexKeyId,
    ) -> Result<Self, StorageError> {
        let LoginIndexKeyState::Stable { current_key_id, .. } = stable_state else {
            return Err(StorageError::StaleState);
        };
        if current_key_id == new_key_id {
            return Err(StorageError::InvalidEncoding);
        }
        Ok(Self {
            stable_state,
            new_key_id,
            previous_entry_count: 0,
        })
    }

    /// Validates one row from the complete old-generation scan.
    pub fn observe(
        &mut self,
        key: &LoginIndexStoredKey,
        value: &LoginIndexValue,
    ) -> Result<(), StorageError> {
        if key.generation() != self.stable_state.current_generation()
            || value.generation() != key.generation()
        {
            return Err(StorageError::StaleState);
        }
        if matches!(
            value.kind(),
            LoginIndexValueKind::CreationReservation { .. }
        ) {
            return Err(StorageError::StaleState);
        }
        self.previous_entry_count = self
            .previous_entry_count
            .checked_add(1)
            .ok_or(StorageError::Overflow)?;
        Ok(())
    }

    /// Produces the exact two-generation state after the complete scan succeeds.
    pub fn finish(self) -> Result<LoginIndexKeyState, StorageError> {
        self.stable_state
            .start_rotation(self.new_key_id, self.previous_entry_count)
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_types::AccountRandomId;

    use super::*;

    fn credential() -> OpaqueCredentialId {
        OpaqueCredentialId::from_bytes([5; 32])
    }

    struct LoginIndexFixture {
        network: NetworkId,
        login: NormalizedLogin,
        previous_key: LoginIndexKey,
        current_key: LoginIndexKey,
        transition: LoginIndexKeyState,
        stored: LoginIndexStoredKey,
        value: LoginIndexValue,
        account: AccountId,
    }

    fn fixture() -> Result<LoginIndexFixture, StorageError> {
        let network = NetworkId::from_bytes([1; 32]);
        let login =
            NormalizedLogin::prepare("branch-login").map_err(|_| StorageError::InvalidEncoding)?;
        let previous_key = LoginIndexKey::from_bytes([2; 32]);
        let current_key = LoginIndexKey::from_bytes([3; 32]);
        let state = LoginIndexKeyState::transition(
            1,
            previous_key.key_id(network),
            current_key.key_id(network),
            1,
        )?;
        let stored =
            LoginIndexStoredKey::new(1, derive_login_index(&previous_key, network, &login)?)?;
        let account = AccountRandomId::from_bytes([4; 16]).to_account_id();
        let value = LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::Live {
                account_id: account,
                opaque_credential_id: credential(),
            },
        )?;
        Ok(LoginIndexFixture {
            network,
            login,
            previous_key,
            current_key,
            transition: state,
            stored,
            value,
            account,
        })
    }

    #[test]
    fn private_key_and_value_helpers_reject_unreachable_internal_states() -> Result<(), StorageError>
    {
        assert!(matches!(
            LoginIndexStoredKey::dummy(0),
            Err(StorageError::InvalidEncoding)
        ));
        let dummy = LoginIndexStoredKey::dummy(1)?;
        let same = LoginIndexStoredKey {
            generation: 1,
            digest: [0; 32],
        };
        assert!(dummy.same_identity(&same));
        let different = LoginIndexStoredKey {
            generation: 2,
            digest: [0; 32],
        };
        assert!(!dummy.same_identity(&different));

        let creation = LoginIndexValue {
            generation: 1,
            digest: [0; 32],
            kind: LoginIndexValueKind::CreationReservation {
                transaction_id: TransactionId::from_bytes([6; 16]),
                expires_at: 0,
            },
        };
        assert_eq!(creation.encode(), Err(StorageError::InvalidEncoding));
        let deletion = LoginIndexValue {
            generation: 1,
            digest: [0; 32],
            kind: LoginIndexValueKind::DeletionTombstone {
                deleted_account_id: AccountRandomId::from_bytes([7; 16]).to_account_id(),
                expires_at: 0,
            },
        };
        assert_eq!(deletion.encode(), Err(StorageError::InvalidEncoding));
        Ok(())
    }

    #[test]
    fn lazy_migration_rejects_every_previous_owner_mismatch() -> Result<(), StorageError> {
        let LoginIndexFixture {
            network,
            login,
            previous_key,
            current_key,
            transition,
            stored,
            value,
            account,
        } = fixture()?;

        let stable = LoginIndexKeyState::stable(1, current_key.key_id(network))?;
        assert_eq!(
            LoginIndexLazyMigration::new(
                network,
                &login,
                stable,
                &current_key,
                &previous_key,
                account,
                credential(),
                &value,
            )
            .map(|_| ()),
            Err(StorageError::AuthenticationFailed)
        );

        let wrong_generation = LoginIndexValue {
            generation: 2,
            digest: stored.digest,
            kind: LoginIndexValueKind::Live {
                account_id: account,
                opaque_credential_id: credential(),
            },
        };
        assert_eq!(
            LoginIndexLazyMigration::new(
                network,
                &login,
                transition,
                &current_key,
                &previous_key,
                account,
                credential(),
                &wrong_generation,
            )
            .map(|_| ()),
            Err(StorageError::StaleState)
        );

        let reservation = LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::CreationReservation {
                transaction_id: TransactionId::from_bytes([8; 16]),
                expires_at: 1,
            },
        )?;
        assert_eq!(
            LoginIndexLazyMigration::new(
                network,
                &login,
                transition,
                &current_key,
                &previous_key,
                account,
                credential(),
                &reservation,
            )
            .map(|_| ()),
            Err(StorageError::StaleState)
        );

        for (candidate_account, candidate_credential) in [
            (
                AccountRandomId::from_bytes([9; 16]).to_account_id(),
                credential(),
            ),
            (account, OpaqueCredentialId::from_bytes([10; 32])),
        ] {
            assert_eq!(
                LoginIndexLazyMigration::new(
                    network,
                    &login,
                    transition,
                    &current_key,
                    &previous_key,
                    candidate_account,
                    candidate_credential,
                    &value,
                )
                .map(|_| ()),
                Err(StorageError::AuthenticationFailed)
            );
        }
        Ok(())
    }

    #[test]
    fn transition_preflight_rejects_generation_reservation_and_overflow() -> Result<(), StorageError>
    {
        let LoginIndexFixture {
            network,
            login: _,
            previous_key,
            current_key,
            transition,
            stored,
            value,
            account: _,
        } = fixture()?;
        assert_eq!(
            LoginIndexTransitionPreflight::new(transition, previous_key.key_id(network))
                .map(|_| ()),
            Err(StorageError::StaleState)
        );

        let stable = LoginIndexKeyState::stable(1, previous_key.key_id(network))?;
        assert_eq!(
            LoginIndexTransitionPreflight::new(stable, previous_key.key_id(network)).map(|_| ()),
            Err(StorageError::InvalidEncoding)
        );
        let mut preflight =
            LoginIndexTransitionPreflight::new(stable, current_key.key_id(network))?;
        let wrong_key = LoginIndexStoredKey {
            generation: 2,
            digest: stored.digest,
        };
        assert_eq!(
            preflight.observe(&wrong_key, &value),
            Err(StorageError::StaleState)
        );
        let wrong_value = LoginIndexValue {
            generation: 2,
            digest: stored.digest,
            kind: LoginIndexValueKind::Live {
                account_id: AccountRandomId::from_bytes([11; 16]).to_account_id(),
                opaque_credential_id: OpaqueCredentialId::from_bytes([12; 32]),
            },
        };
        assert_eq!(
            preflight.observe(&stored, &wrong_value),
            Err(StorageError::StaleState)
        );
        let reservation = LoginIndexValue::new(
            &stored,
            LoginIndexValueKind::CreationReservation {
                transaction_id: TransactionId::from_bytes([13; 16]),
                expires_at: 1,
            },
        )?;
        assert_eq!(
            preflight.observe(&stored, &reservation),
            Err(StorageError::StaleState)
        );
        preflight.previous_entry_count = u64::MAX;
        assert_eq!(
            preflight.observe(&stored, &value),
            Err(StorageError::Overflow)
        );
        Ok(())
    }

    #[test]
    fn transition_key_validation_rejects_a_wrong_previous_key_after_current_matches()
    -> Result<(), StorageError> {
        let LoginIndexFixture {
            network,
            previous_key: _,
            current_key,
            transition,
            ..
        } = fixture()?;
        let wrong_previous = LoginIndexKey::from_bytes([14; 32]);
        assert_eq!(
            transition.validate_configured_keys(network, &current_key, Some(&wrong_previous),),
            Err(StorageError::AuthenticationFailed),
        );
        Ok(())
    }
}
