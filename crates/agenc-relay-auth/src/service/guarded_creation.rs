//! Opt-in creation binds the claimant before a newly allocated account can become visible.

use agenc_relay_crypto::{
    AccountHpkeExchange, AccountRequestBinding, AccountResponseSealToken, Digest32,
    InitialRootClaimOwner, InitialRootExchange, InitialRootPrecommit, LoginIndexDigest,
    LoginIndexKey, OsEntropy, Sha256Stream,
};
use agenc_relay_types::{AccountId, AccountServiceMessageKind, OpaqueCredentialId, TransactionId};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use super::{
    AccountCreationStartParameters, AccountCreationState, AccountTransaction, AuthError,
    AuthenticationRecordReader, AuthenticationRecordWriter, CREATION_TRANSACTION_CLASS,
    CREATION_TRANSACTION_RECORD_BYTES, CreationTransactionRestartMetadata, MonotonicTick,
    OpaqueProfile, TransactionClass, UtcSecond, durable_transaction_expiry, prepare_creation,
    put_request_binding, put_start_disposition, put_transaction_record_header,
    put_validated_invitation, read_request_binding_profile, read_start_disposition,
    read_transaction_record_header, read_validated_invitation, validate_finish_lineage,
};
use crate::claimed_creation::{OpenedGuardedStart, seal_challenge};
use crate::{InitialRootServiceEnvelope, InitialRootServiceResponse, OpaqueRegistrationResponse};

pub(super) enum CreationOrigin {
    Legacy(AccountRequestBinding),
    Guarded {
        binding: AccountRequestBinding<InitialRootExchange>,
        precommit: InitialRootPrecommit,
    },
}

impl CreationOrigin {
    pub(super) fn accepts(&self, finish: AccountRequestBinding) -> bool {
        match self {
            Self::Legacy(start) => validate_finish_lineage(*start, finish).is_ok(),
            Self::Guarded { binding, .. } => {
                binding.message_kind() == InitialRootExchange::ClaimedCreateStart
                    && finish.message_kind() == AccountServiceMessageKind::AccountCreateFinish
                    && binding.network_id() == finish.network_id()
                    && binding.recovery_epoch() == finish.recovery_epoch()
                    && binding.recipient_key_id() == finish.recipient_key_id()
                    && binding.client_request_id() != finish.client_request_id()
            }
        }
    }

    pub(super) fn complete(self, account: AccountId) -> Option<CreatedRootClaim> {
        let Self::Guarded { binding, precommit } = self else {
            return None;
        };
        let owner = precommit.bind(
            binding.network_id(),
            binding.recovery_epoch(),
            account,
            binding.client_request_id(),
        );
        Some(CreatedRootClaim {
            binding,
            account,
            owner,
        })
    }
}

/// A newly allocated account's private creator, available only from the successful guarded FINISH.
pub struct CreatedRootClaim {
    binding: AccountRequestBinding<InitialRootExchange>,
    account: AccountId,
    owner: InitialRootClaimOwner,
}

impl CreatedRootClaim {
    /// The original guarded request and independently authenticated network, recipient and epoch.
    #[must_use]
    pub const fn binding(&self) -> AccountRequestBinding<InitialRootExchange> {
        self.binding
    }

    /// The fresh immutable account allocated by this FINISH.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// The verifier for the private, account-bound reservation row.
    #[must_use]
    pub const fn owner(&self) -> &InitialRootClaimOwner {
        &self.owner
    }
}

/// The version-two 393-byte encrypted creation transaction, including its private precommit.
pub struct GuardedCreationTransactionRecord(
    Zeroizing<[u8; CREATION_TRANSACTION_RECORD_BYTES + 32]>,
);

impl GuardedCreationTransactionRecord {
    fn capture(
        transaction: &AccountTransaction<AccountCreationState>,
        now: MonotonicTick,
        now_utc: UtcSecond,
    ) -> Result<Self, AuthError> {
        let current = transaction.binding();
        let expires =
            durable_transaction_expiry(current, TransactionClass::AccountCreation, now, now_utc)?;
        let state = transaction.state_ref().ok_or(AuthError::Consumed)?;
        let CreationOrigin::Guarded { binding, precommit } = &state.origin else {
            return Err(AuthError::ContextMismatch);
        };
        let mut bytes = Zeroizing::new([0; CREATION_TRANSACTION_RECORD_BYTES + 32]);
        let mut writer = AuthenticationRecordWriter::new(bytes.as_mut());
        put_transaction_record_header(
            &mut writer,
            current,
            InitialRootExchange::VERSION,
            CREATION_TRANSACTION_CLASS,
            expires,
        )?;
        put_request_binding(&mut writer, *binding)?;
        put_start_disposition(&mut writer, state.disposition)?;
        writer.put(state.login_digest.expose_for_storage_key())?;
        writer.put(state.credential_id.expose_for_account_service())?;
        put_validated_invitation(&mut writer, state.invitation.as_ref())?;
        writer.put(precommit.expose_for_protection())?;
        writer.finish()?;
        Ok(Self(bytes))
    }

    /// Copies the exact protected record. Recovery then validates its request and transaction.
    pub fn parse(bytes: &[u8]) -> Result<Self, AuthError> {
        let mut saved = Zeroizing::new([0; CREATION_TRANSACTION_RECORD_BYTES + 32]);
        if saved.len() != bytes.len() {
            return Err(AuthError::InvalidEncoding);
        }
        saved.copy_from_slice(bytes);
        Ok(Self(saved))
    }

    /// Borrows the exact private row for authenticated persistence.
    #[must_use]
    pub fn expose_for_persistence(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Recovers the original login and invitation cleanup facts after loss of the live connection.
    /// Restart never turns this retained row into fresh account-creation authority.
    pub fn into_restart_cleanup_metadata(
        self,
    ) -> Result<CreationTransactionRestartMetadata, AuthError> {
        let mut reader = AuthenticationRecordReader::new(self.0.as_slice());
        let (transaction_id, network, _, durable_expires_at_utc) = read_transaction_record_header(
            &mut reader,
            InitialRootExchange::VERSION,
            CREATION_TRANSACTION_CLASS,
        )?;
        let binding = read_request_binding_profile::<InitialRootExchange>(&mut reader)?;
        if binding.network_id() != network
            || binding.message_kind() != InitialRootExchange::ClaimedCreateStart
        {
            return Err(AuthError::ContextMismatch);
        }
        let admitted = read_start_disposition(&mut reader)?.rejection().is_none();
        let digest = LoginIndexDigest::from_storage_key(reader.read_array()?);
        let _credential = super::OpaqueCredentialId::from_bytes(reader.read_array()?);
        let invitation = read_validated_invitation(&mut reader)?;
        let _commitment = InitialRootPrecommit::from_protected_bytes(reader.read_array()?);
        reader.finish()?;
        Ok(CreationTransactionRestartMetadata {
            transaction_id,
            durable_expires_at_utc,
            reservation_login_digest: admitted.then_some(digest),
            reservation_invitation: invitation
                .filter(|_| admitted)
                .map(|invitation| (invitation.invite_id, invitation.expires_at)),
        })
    }
}

/// The guarded challenge, transaction and durable replay fields before their ordered START commit.
#[must_use = "persist a guarded creation START before sending its challenge or accepting FINISH"]
pub struct GuardedAccountStart {
    transaction: AccountTransaction<AccountCreationState>,
    record: GuardedCreationTransactionRecord,
    response: InitialRootServiceResponse,
    request_digest: Digest32,
    next_response_count: u64,
}

impl GuardedAccountStart {
    /// Identifies the generated transaction used as the encrypted row key.
    #[must_use]
    pub fn transaction_id(&self) -> TransactionId {
        self.transaction.binding().transaction_id()
    }

    /// Borrows the exact retained private transaction, including its guarded origin.
    #[must_use]
    pub const fn record(&self) -> &GuardedCreationTransactionRecord {
        &self.record
    }

    /// Borrows the sealed response for the ordered replay row.
    #[must_use]
    pub const fn response_for_commit(&self) -> &InitialRootServiceResponse {
        &self.response
    }

    /// Returns the epoch-scoped response counter to commit with the transaction.
    #[must_use]
    pub const fn next_response_count(&self) -> u64 {
        self.next_response_count
    }

    /// Gives a successful candidate's already validated lookup fields to the durable stage.
    #[must_use]
    pub fn reserved_login(&self) -> Option<&LoginIndexDigest> {
        let state = self.transaction.state_ref()?;
        state
            .disposition
            .rejection()
            .is_none()
            .then_some(&state.login_digest)
    }

    /// Gives the admitted invitation to the same durable START stage, if one was required.
    #[must_use]
    pub fn reserved_invitation(&self) -> Option<(super::InviteId, UtcSecond)> {
        let state = self.transaction.state_ref()?;
        state
            .invitation
            .as_ref()
            .filter(|_| state.disposition.rejection().is_none())
            .map(|invitation| (invitation.invite_id, invitation.expires_at))
    }

    /// Opens the exact staged continuation after the ordered original request/response and transaction commit.
    pub fn into_committed(
        self,
        request: &InitialRootServiceEnvelope,
        response: &InitialRootServiceResponse,
        record: &GuardedCreationTransactionRecord,
        response_count: u64,
    ) -> Result<AccountTransaction<AccountCreationState>, AuthError> {
        let mut digest = Sha256Stream::new();
        digest.update(request.as_bytes());
        if response_count < self.next_response_count
            || digest.finish() != self.request_digest
            || self.response.as_bytes() != response.as_bytes()
            || !bool::from(
                self.record
                    .expose_for_persistence()
                    .ct_eq(record.expose_for_persistence()),
            )
        {
            return Err(AuthError::ContextMismatch);
        }
        Ok(self.transaction)
    }
}

/// Prepares the actual OPAQUE registration under an authenticated guarded START.
pub fn begin_guarded_account_creation(
    profile: &OpaqueProfile,
    login_index_key: &LoginIndexKey,
    parameters: AccountCreationStartParameters<OpenedGuardedStart>,
    response_count: u64,
) -> Result<GuardedAccountStart, AuthError> {
    prepare_guarded_account_creation(profile, login_index_key, parameters)?.seal(response_count)
}

/// An authenticated OPAQUE challenge waiting for the coordinator's ordered response count.
#[must_use = "seal this challenge only after the service reserves its response-count successor"]
pub struct GuardedCreationChallenge {
    transaction: AccountTransaction<AccountCreationState>,
    record: GuardedCreationTransactionRecord,
    credential: OpaqueCredentialId,
    challenge: OpaqueRegistrationResponse,
    token: AccountResponseSealToken<InitialRootExchange>,
    request_digest: Digest32,
}

impl GuardedCreationChallenge {
    /// Consumes the original response authority and binds this challenge to the durable successor.
    pub fn seal(self, response_count: u64) -> Result<GuardedAccountStart, AuthError> {
        let (response, next_response_count) = seal_challenge(
            self.token,
            self.transaction.binding().transaction_id(),
            &self.credential,
            &self.challenge,
            response_count,
        )?;
        Ok(GuardedAccountStart {
            transaction: self.transaction,
            record: self.record,
            response,
            request_digest: self.request_digest,
            next_response_count,
        })
    }
}

/// Completes the OPAQUE computation without taking a shared response-count slot.
pub fn prepare_guarded_account_creation(
    profile: &OpaqueProfile,
    login_index_key: &LoginIndexKey,
    parameters: AccountCreationStartParameters<OpenedGuardedStart>,
) -> Result<GuardedCreationChallenge, AuthError> {
    let AccountCreationStartParameters {
        context,
        request,
        admission,
        login_is_available,
        invitation_is_available,
    } = parameters;
    let OpenedGuardedStart {
        binding,
        request,
        precommit,
        token,
        request_digest,
    } = request;
    let inputs = AccountCreationStartParameters {
        context,
        request,
        admission,
        login_is_available,
        invitation_is_available,
    };
    let (transaction, credential, challenge) = prepare_creation(
        profile,
        login_index_key,
        inputs,
        CreationOrigin::Guarded { binding, precommit },
        &mut OsEntropy,
    )?;
    let record =
        GuardedCreationTransactionRecord::capture(&transaction, context.now, context.now_utc)?;
    Ok(GuardedCreationChallenge {
        transaction,
        record,
        credential,
        challenge,
        token,
        request_digest,
    })
}
