//! Authenticated, fixed-width initial-root claim reads and exact choices.

use agenc_relay_crypto::{
    AccountHpkeExchange, AccountHpkePrivateKey, AccountHpkePublicKey, AccountRequestBinding,
    AccountResponseOpenToken, AccountResponseSealToken, InitialRootClaimOwner, InitialRootExchange,
    InitialRootSecret, seal_account_request,
};
use agenc_relay_types::{AccountId, NetworkId, RecoveryEpoch, RequestId};
use zeroize::Zeroizing;

use super::{
    AuthError, Cursor, InitialRootServiceEnvelope, InitialRootServiceResponse, Writer, padding,
};

#[cfg(test)]
mod tests;

const REQUEST_BYTES: usize = 139;
const STATE_BYTES: usize = 107;

/// Private operation requested by the account creator.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ClaimAction {
    /// Read the currently retained reservation or choice.
    Read,
    /// Permanently bind the exact fingerprint of an independently protected root.
    Choose([u8; 32]),
}

/// Account authority recognized by a verified coordinator response.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum ClaimState {
    /// A prospective guarded account still holds its original reservation.
    Reserved,
    /// The exact immutable generation-zero root fingerprint has been selected.
    Chosen([u8; 32]),
    /// The signed generation-zero object has been committed.
    Published {
        /// Original root fingerprint, retained across rotations.
        fingerprint: [u8; 32],
        /// Standalone object ID in the account's directory chain.
        object_id: [u8; 32],
    },
}

/// A client request bound to its sole HPKE exporter and private expected operation.
pub struct ClaimOpenToken {
    token: AccountResponseOpenToken<InitialRootExchange>,
    account: AccountId,
    start: RequestId,
    action: ClaimAction,
}

/// A private observation that can only be constructed by authenticating the exact response.
pub struct AuthenticatedClaimState {
    binding: AccountRequestBinding<InitialRootExchange>,
    account: AccountId,
    start: RequestId,
    action: ClaimAction,
    state: Option<ClaimState>,
}

impl AuthenticatedClaimState {
    /// Identifies the authenticated recipient, epoch, network and fresh client request.
    #[must_use]
    pub const fn binding(&self) -> AccountRequestBinding<InitialRootExchange> {
        self.binding
    }

    /// The immutable target of the verified private request.
    #[must_use]
    pub const fn account(&self) -> AccountId {
        self.account
    }

    /// The account creator's original guarded start request.
    #[must_use]
    pub const fn creation_request(&self) -> RequestId {
        self.start
    }

    /// The operation whose exporter authenticated this result.
    #[must_use]
    pub const fn action(&self) -> ClaimAction {
        self.action
    }

    /// The coordinator's retained result, or a private denial with no disclosed cause.
    #[must_use]
    pub const fn state(&self) -> Option<ClaimState> {
        self.state
    }
}

/// Seals the caller's private operation to the independently pinned account service.
pub fn seal_claim(
    recipient: AccountHpkePublicKey,
    binding: AccountRequestBinding<InitialRootExchange>,
    account: AccountId,
    start: RequestId,
    secret: &InitialRootSecret,
    action: ClaimAction,
) -> Result<(InitialRootServiceEnvelope, ClaimOpenToken), AuthError> {
    if binding.message_kind() != InitialRootExchange::Claim {
        return Err(AuthError::ContextMismatch);
    }
    let mut fields = Zeroizing::new([0; REQUEST_BYTES]);
    let mut writer = Writer::new(fields.as_mut());
    writer.write(&InitialRootExchange::VERSION.to_be_bytes())?;
    writer.write(binding.network_id().as_bytes())?;
    writer.write(account.to_text().as_bytes())?;
    writer.write(start.as_bytes())?;
    writer.write(secret.expose_for_protection())?;
    match action {
        ClaimAction::Read => {
            writer.write(&[1])?;
            writer.write_zeros(32)?;
        }
        ClaimAction::Choose(root) => {
            writer.write(&[2])?;
            writer.write(&root)?;
        }
    }
    let plaintext = padding::encode(fields.as_ref(), REQUEST_BYTES..=REQUEST_BYTES)?;
    let (sealed, token) = seal_account_request(recipient, binding, &plaintext)?;
    Ok((
        InitialRootServiceEnvelope::from_sealed(sealed)?,
        ClaimOpenToken {
            token,
            account,
            start,
            action,
        },
    ))
}

impl ClaimOpenToken {
    /// Opens this one reply and checks the exact creation, account and requested choice.
    pub fn open(
        self,
        response: &InitialRootServiceResponse,
    ) -> Result<AuthenticatedClaimState, AuthError> {
        let binding = self.token.request_binding();
        let plaintext = response.open(self.token)?;
        let fields = padding::decode(
            plaintext.expose_for_account_parser(),
            STATE_BYTES..=STATE_BYTES,
        )?;
        let mut cursor = Cursor::new(fields);
        if cursor.read_u16()? != InitialRootExchange::VERSION {
            return Err(AuthError::InvalidEncoding);
        }
        let account: [u8; 24] = cursor.read_array()?;
        let start: [u8; 16] = cursor.read_array()?;
        let tag = cursor.read_u8()?;
        let fingerprint = cursor.read_array()?;
        let object_id = cursor.read_array()?;
        let state = match tag {
            1 if account == [0; 24]
                && start == [0; 16]
                && fingerprint == [0; 32]
                && object_id == [0; 32] =>
            {
                None
            }
            2..=4 => {
                if AccountId::parse_wire_bytes(&account).map_err(|_| AuthError::InvalidEncoding)?
                    != self.account
                    || start != *self.start.as_bytes()
                {
                    return Err(AuthError::ContextMismatch);
                }
                Some(match (tag, self.action) {
                    (2, ClaimAction::Read) if fingerprint == [0; 32] && object_id == [0; 32] => {
                        ClaimState::Reserved
                    }
                    (3 | 4, ClaimAction::Choose(expected)) if fingerprint != expected => {
                        return Err(AuthError::ContextMismatch);
                    }
                    (3, _) if object_id == [0; 32] => ClaimState::Chosen(fingerprint),
                    (4, _) => ClaimState::Published {
                        fingerprint,
                        object_id,
                    },
                    _ => return Err(AuthError::InvalidEncoding),
                })
            }
            _ => return Err(AuthError::InvalidEncoding),
        };
        Ok(AuthenticatedClaimState {
            binding,
            account: self.account,
            start: self.start,
            action: self.action,
            state,
        })
    }
}

/// The request and its response authority stay together through coordinator admission.
pub struct OpenedClaim {
    binding: AccountRequestBinding<InitialRootExchange>,
    token: AccountResponseSealToken<InitialRootExchange>,
    account: AccountId,
    start: RequestId,
    secret: InitialRootSecret,
    action: ClaimAction,
}

/// Opens a registered claim using its current pinned network and recovery epoch.
pub fn open_claim(
    recipient: &AccountHpkePrivateKey,
    network: NetworkId,
    epoch: RecoveryEpoch,
    envelope: &InitialRootServiceEnvelope,
) -> Result<OpenedClaim, AuthError> {
    let (plaintext, token) =
        envelope.open(recipient, epoch, network, InitialRootExchange::Claim)?;
    let fields = padding::decode(
        plaintext.expose_for_account_parser(),
        REQUEST_BYTES..=REQUEST_BYTES,
    )?;
    let mut cursor = Cursor::new(fields);
    if cursor.read_u16()? != InitialRootExchange::VERSION {
        return Err(AuthError::InvalidEncoding);
    }
    if NetworkId::from_bytes(cursor.read_array()?) != network {
        return Err(AuthError::ContextMismatch);
    }
    let account = AccountId::parse_wire_bytes(cursor.read_slice(24)?)
        .map_err(|_| AuthError::InvalidEncoding)?;
    let start = RequestId::from_bytes(cursor.read_array()?);
    let mut secret_bytes = Zeroizing::new([0; 32]);
    secret_bytes.copy_from_slice(cursor.read_slice(32)?);
    let secret = InitialRootSecret::from_protected_bytes(secret_bytes);
    let tag = cursor.read_u8()?;
    let fingerprint = cursor.read_array()?;
    let action = match tag {
        1 if fingerprint == [0; 32] => ClaimAction::Read,
        2 => ClaimAction::Choose(fingerprint),
        _ => return Err(AuthError::InvalidEncoding),
    };
    Ok(OpenedClaim {
        binding: envelope.binding(epoch),
        token,
        account,
        start,
        secret,
        action,
    })
}

/// Immutable private row supplied by the authenticated coordinator account store.
pub struct ClaimRecord<'a> {
    /// The account whose independently classified Guarded row was loaded.
    pub account: AccountId,
    /// Network of the authenticated account.
    pub network: NetworkId,
    /// Original recovery epoch that the creator's secret committed to.
    pub creation_epoch: RecoveryEpoch,
    /// Original guarded create request ID.
    pub creation_request: RequestId,
    /// Private stored account-bound verifier.
    pub owner: &'a InitialRootClaimOwner,
    /// Current durable position. Users cannot set a position using the wire protocol.
    pub state: ClaimState,
}

/// A sealed outcome for the existing ordered durable-admission stage.
pub struct PreparedClaim {
    response: InitialRootServiceResponse,
    next_response_count: u64,
    new_choice: Option<[u8; 32]>,
}

impl PreparedClaim {
    /// Borrows the exact ciphertext for the ordered batch's durable replay row.
    #[must_use]
    pub fn bytes_for_commit(&self) -> &[u8; super::ACCOUNT_SERVICE_RESPONSE_BYTES] {
        self.response.as_bytes()
    }

    /// Returns the response counter to persist atomically with the ordered batch.
    #[must_use]
    pub const fn next_response_count(&self) -> u64 {
        self.next_response_count
    }

    /// Returns the only new choice, to be staged after rechecking the exact Reserved row.
    #[must_use]
    pub const fn new_choice(&self) -> Option<[u8; 32]> {
        self.new_choice
    }

    /// Delivers the protected reply after the ordered sealing counter is known durable.
    pub fn into_committed(
        self,
        response_count: u64,
    ) -> Result<InitialRootServiceResponse, AuthError> {
        if response_count < self.next_response_count {
            return Err(AuthError::ContextMismatch);
        }
        Ok(self.response)
    }
}

impl OpenedClaim {
    /// Validates a current registered account and its protected row before selecting a response.
    /// The caller must serialize the row, registration generation and subsequent commit with publication.
    pub fn prepare(
        self,
        registered: Option<AccountId>,
        record: Option<&ClaimRecord<'_>>,
        response_count: u64,
    ) -> Result<PreparedClaim, AuthError> {
        let (state, new_choice) = match record {
            Some(row)
                if registered == Some(self.account)
                    && row.account == self.account
                    && row.network == self.binding.network_id()
                    && row.creation_request == self.start
                    && row.owner.matches(
                        &self
                            .secret
                            .precommit(row.network, row.creation_epoch, self.start)
                            .bind(row.network, row.creation_epoch, self.account, self.start),
                    ) =>
            {
                self.resolve(row)
            }
            _ => (None, None),
        };
        let fields = encode_state(self.account, self.start, state)?;
        let wrapped = padding::encode(fields.as_ref(), STATE_BYTES..=STATE_BYTES)?;
        let sealed =
            self.token
                .seal_response(response_count, InitialRootExchange::Claim, &wrapped)?;
        let next_response_count = sealed.next_response_count();
        Ok(PreparedClaim {
            response: InitialRootServiceResponse::from_sealed(sealed)?,
            next_response_count,
            new_choice,
        })
    }

    fn resolve(&self, row: &ClaimRecord<'_>) -> (Option<ClaimState>, Option<[u8; 32]>) {
        let same_epoch = self.binding.recovery_epoch() == row.creation_epoch;
        match (self.action, row.state) {
            (ClaimAction::Read, ClaimState::Chosen(_) | ClaimState::Published { .. }) => {
                (Some(row.state), None)
            }
            (ClaimAction::Read, ClaimState::Reserved) if same_epoch => (Some(row.state), None),
            (ClaimAction::Choose(root), ClaimState::Reserved) if same_epoch => {
                (Some(ClaimState::Chosen(root)), Some(root))
            }
            (
                ClaimAction::Choose(root),
                ClaimState::Chosen(current)
                | ClaimState::Published {
                    fingerprint: current,
                    ..
                },
            ) if same_epoch && root == current => (Some(row.state), None),
            _ => (None, None),
        }
    }
}

fn encode_state(
    account: AccountId,
    start: RequestId,
    state: Option<ClaimState>,
) -> Result<Zeroizing<[u8; STATE_BYTES]>, AuthError> {
    let mut output = Zeroizing::new([0; STATE_BYTES]);
    let mut writer = Writer::new(output.as_mut());
    writer.write(&InitialRootExchange::VERSION.to_be_bytes())?;
    let Some(state) = state else {
        writer.write_zeros(40)?;
        writer.write(&[1])?;
        writer.write_zeros(64)?;
        return Ok(output);
    };
    writer.write(account.to_text().as_bytes())?;
    writer.write(start.as_bytes())?;
    let (tag, fingerprint, object) = match state {
        ClaimState::Reserved => (2, [0; 32], [0; 32]),
        ClaimState::Chosen(root) => (3, root, [0; 32]),
        ClaimState::Published {
            fingerprint,
            object_id,
        } => (4, fingerprint, object_id),
    };
    writer.write(&[tag])?;
    writer.write(&fingerprint)?;
    writer.write(&object)?;
    Ok(output)
}
