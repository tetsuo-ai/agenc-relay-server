//! Connection-bound, expiring, one-use account transactions.

use agenc_ircd_types::{
    ConnectionId, Generation, MonotonicTick, NetworkId, OriginId, ServerId, ServerIncarnation,
    TransactionId,
};
use subtle::ConstantTimeEq as _;

use crate::AuthError;

/// Account-creation transaction lifetime in monotonic milliseconds.
pub const ACCOUNT_CREATION_TIMEOUT_TICKS: u64 = 60_000;
/// OPAQUE authentication transaction lifetime in monotonic milliseconds.
pub const AUTHENTICATION_TIMEOUT_TICKS: u64 = 30_000;
/// One-use authentication-grant lifetime in monotonic milliseconds.
pub const AUTHENTICATION_GRANT_TIMEOUT_TICKS: u64 = 30_000;
/// Durable authentication-grant lifetime in UTC seconds.
pub const AUTHENTICATION_GRANT_TIMEOUT_SECONDS: u64 = 30;
/// Credential-change registration transaction lifetime in monotonic milliseconds.
pub const CREDENTIAL_CHANGE_TIMEOUT_TICKS: u64 = 60_000;
/// Fresh same-account proof lifetime in monotonic milliseconds.
pub const FRESH_AUTH_TIMEOUT_TICKS: u64 = 300_000;
/// Account-deletion confirmation lifetime in monotonic milliseconds.
pub const DELETION_CONFIRMATION_TIMEOUT_TICKS: u64 = 60_000;

/// Closed account-service transaction classes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransactionClass {
    /// Account creation registration.
    AccountCreation,
    /// OPAQUE authentication.
    Authentication,
    /// Credential replacement registration.
    CredentialChange,
    /// Fresh same-account authorization proof.
    FreshAuthentication,
    /// Revision-bound account-deletion confirmation.
    AccountDeletion,
}

/// Exact edge, origin, and connection identity for an account operation.
///
/// The connection nonce is deliberately private, has no formatting surface,
/// and is exposed only through the final authentication-grant boundary.
///
/// ```compile_fail
/// use agenc_ircd_auth::AccountRouteBinding;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<AccountRouteBinding>();
/// ```
#[derive(Clone, Copy)]
pub struct AccountRouteBinding {
    edge_server_id: ServerId,
    edge_incarnation: ServerIncarnation,
    origin_id: OriginId,
    origin_generation: Generation,
    connection_id: ConnectionId,
    connection_nonce: [u8; 32],
}

impl AccountRouteBinding {
    /// Constructs the complete coordinator-validated route identity.
    #[must_use]
    pub const fn new(
        edge_server_id: ServerId,
        edge_incarnation: ServerIncarnation,
        origin_id: OriginId,
        origin_generation: Generation,
        connection_id: ConnectionId,
        connection_nonce: [u8; 32],
    ) -> Self {
        Self {
            edge_server_id,
            edge_incarnation,
            origin_id,
            origin_generation,
            connection_id,
            connection_nonce,
        }
    }

    pub(crate) const fn edge_server_id(self) -> ServerId {
        self.edge_server_id
    }

    pub(crate) const fn edge_incarnation(self) -> ServerIncarnation {
        self.edge_incarnation
    }

    pub(crate) const fn origin_id(self) -> OriginId {
        self.origin_id
    }

    pub(crate) const fn origin_generation(self) -> Generation {
        self.origin_generation
    }

    pub(crate) const fn connection_id(self) -> ConnectionId {
        self.connection_id
    }

    pub(crate) const fn connection_nonce(&self) -> &[u8; 32] {
        &self.connection_nonce
    }

    pub(crate) fn validate_match(self, candidate: Self) -> Result<(), AuthError> {
        if self.edge_server_id != candidate.edge_server_id
            || self.edge_incarnation != candidate.edge_incarnation
        {
            return Err(AuthError::ContextMismatch);
        }
        if self.origin_id != candidate.origin_id
            || self.origin_generation != candidate.origin_generation
        {
            return Err(AuthError::WrongOrigin);
        }
        if self.connection_id != candidate.connection_id
            || !bool::from(self.connection_nonce.ct_eq(&candidate.connection_nonce))
        {
            return Err(AuthError::WrongConnection);
        }
        Ok(())
    }
}

impl TransactionClass {
    const fn timeout_ticks(self) -> u64 {
        match self {
            Self::AccountCreation => ACCOUNT_CREATION_TIMEOUT_TICKS,
            Self::Authentication => AUTHENTICATION_TIMEOUT_TICKS,
            Self::CredentialChange => CREDENTIAL_CHANGE_TIMEOUT_TICKS,
            Self::FreshAuthentication => FRESH_AUTH_TIMEOUT_TICKS,
            Self::AccountDeletion => DELETION_CONFIRMATION_TIMEOUT_TICKS,
        }
    }
}

/// Complete private route and deadline binding for one account transaction.
#[derive(Clone, Copy)]
pub struct AccountTransactionBinding {
    transaction_id: TransactionId,
    class: TransactionClass,
    network_id: NetworkId,
    route: AccountRouteBinding,
    expires_at: MonotonicTick,
}

impl AccountTransactionBinding {
    /// Constructs a binding with the exact class-specific exclusive deadline.
    pub fn new(
        transaction_id: TransactionId,
        class: TransactionClass,
        network_id: NetworkId,
        route: AccountRouteBinding,
        now: MonotonicTick,
    ) -> Result<Self, AuthError> {
        let expires_at = now
            .get()
            .checked_add(class.timeout_ticks())
            .ok_or(AuthError::Overflow)?;
        Ok(Self {
            transaction_id,
            class,
            network_id,
            route,
            expires_at: MonotonicTick::from_ticks(expires_at),
        })
    }

    /// Returns the transaction identity.
    #[must_use]
    pub const fn transaction_id(self) -> TransactionId {
        self.transaction_id
    }

    /// Returns the exclusive monotonic deadline.
    #[must_use]
    pub const fn expires_at(self) -> MonotonicTick {
        self.expires_at
    }
}

/// Secret-capable state consumed exactly once on success or failure.
pub struct AccountTransaction<T> {
    binding: AccountTransactionBinding,
    state: Option<T>,
}

impl<T> AccountTransaction<T> {
    /// Takes ownership of one transaction state.
    #[must_use]
    pub const fn new(binding: AccountTransactionBinding, state: T) -> Self {
        Self {
            binding,
            state: Some(state),
        }
    }

    /// Returns the non-secret transaction binding.
    #[must_use]
    pub const fn binding(&self) -> AccountTransactionBinding {
        self.binding
    }

    pub(crate) const fn state_ref(&self) -> Option<&T> {
        self.state.as_ref()
    }

    /// Consumes the state before checking every terminal outcome.
    pub fn consume(
        &mut self,
        class: TransactionClass,
        network_id: NetworkId,
        route: AccountRouteBinding,
        now: MonotonicTick,
    ) -> Result<T, AuthError> {
        let state = self.state.take().ok_or(AuthError::Consumed)?;
        if self.binding.class != class || self.binding.network_id != network_id {
            return Err(AuthError::ContextMismatch);
        }
        self.binding.route.validate_match(route)?;
        if now >= self.binding.expires_at {
            return Err(AuthError::Expired);
        }
        Ok(state)
    }

    /// Terminally consumes state when its owning connection closes.
    pub fn consume_on_disconnect(&mut self) {
        let _state = self.state.take();
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_types::{
        ConnectionId, Generation, MonotonicTick, NetworkId, OriginId, ServerId, ServerIncarnation,
        TransactionId,
    };

    use super::{
        AccountRouteBinding, AccountTransaction, AccountTransactionBinding, AuthError,
        TransactionClass,
    };

    fn route(seed: u8) -> Result<AccountRouteBinding, agenc_ircd_types::ValidationError> {
        Ok(AccountRouteBinding::new(
            ServerId::from_bytes([seed; 16]),
            ServerIncarnation::from_bytes([seed.wrapping_add(1); 16]),
            OriginId::from_bytes([seed.wrapping_add(2); 16]),
            Generation::new(u64::from(seed).saturating_add(3))?,
            ConnectionId::from_bytes([seed.wrapping_add(4); 16]),
            [seed.wrapping_add(5); 32],
        ))
    }

    fn route_substitutions(
        expected: AccountRouteBinding,
    ) -> Result<[(AccountRouteBinding, AuthError); 6], agenc_ircd_types::ValidationError> {
        Ok([
            (
                AccountRouteBinding::new(
                    ServerId::from_bytes([40_u8; 16]),
                    expected.edge_incarnation(),
                    expected.origin_id(),
                    expected.origin_generation(),
                    expected.connection_id(),
                    *expected.connection_nonce(),
                ),
                AuthError::ContextMismatch,
            ),
            (
                AccountRouteBinding::new(
                    expected.edge_server_id(),
                    ServerIncarnation::from_bytes([41_u8; 16]),
                    expected.origin_id(),
                    expected.origin_generation(),
                    expected.connection_id(),
                    *expected.connection_nonce(),
                ),
                AuthError::ContextMismatch,
            ),
            (
                AccountRouteBinding::new(
                    expected.edge_server_id(),
                    expected.edge_incarnation(),
                    OriginId::from_bytes([42_u8; 16]),
                    expected.origin_generation(),
                    expected.connection_id(),
                    *expected.connection_nonce(),
                ),
                AuthError::WrongOrigin,
            ),
            (
                AccountRouteBinding::new(
                    expected.edge_server_id(),
                    expected.edge_incarnation(),
                    expected.origin_id(),
                    Generation::new(43)?,
                    expected.connection_id(),
                    *expected.connection_nonce(),
                ),
                AuthError::WrongOrigin,
            ),
            (
                AccountRouteBinding::new(
                    expected.edge_server_id(),
                    expected.edge_incarnation(),
                    expected.origin_id(),
                    expected.origin_generation(),
                    ConnectionId::from_bytes([44_u8; 16]),
                    *expected.connection_nonce(),
                ),
                AuthError::WrongConnection,
            ),
            (
                AccountRouteBinding::new(
                    expected.edge_server_id(),
                    expected.edge_incarnation(),
                    expected.origin_id(),
                    expected.origin_generation(),
                    expected.connection_id(),
                    [45_u8; 32],
                ),
                AuthError::WrongConnection,
            ),
        ])
    }

    #[test]
    fn terminal_failure_still_consumes_transaction() -> Result<(), Box<dyn core::error::Error>> {
        let network = NetworkId::from_bytes([1_u8; 32]);
        let expected_route = route(2)?;
        let binding = AccountTransactionBinding::new(
            TransactionId::from_bytes([4_u8; 16]),
            TransactionClass::Authentication,
            network,
            expected_route,
            MonotonicTick::from_ticks(0),
        )?;
        let mut transaction = AccountTransaction::new(binding, 7_u8);
        assert!(
            transaction
                .consume(
                    TransactionClass::Authentication,
                    network,
                    route(9)?,
                    MonotonicTick::from_ticks(1),
                )
                .is_err()
        );
        assert!(
            transaction
                .consume(
                    TransactionClass::Authentication,
                    network,
                    expected_route,
                    MonotonicTick::from_ticks(1),
                )
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn matching_live_transaction_returns_its_owned_state() -> Result<(), Box<dyn core::error::Error>>
    {
        let network = NetworkId::from_bytes([10_u8; 32]);
        let expected_route = route(11)?;
        let binding = AccountTransactionBinding::new(
            TransactionId::from_bytes([13_u8; 16]),
            TransactionClass::CredentialChange,
            network,
            expected_route,
            MonotonicTick::from_ticks(100),
        )?;
        let mut transaction = AccountTransaction::new(binding, 14_u8);
        assert_eq!(
            transaction.consume(
                TransactionClass::CredentialChange,
                network,
                expected_route,
                MonotonicTick::from_ticks(101),
            )?,
            14
        );
        Ok(())
    }

    #[test]
    fn every_transaction_context_substitution_is_terminal()
    -> Result<(), Box<dyn core::error::Error>> {
        let network = NetworkId::from_bytes([20_u8; 32]);
        let expected_route = route(21)?;
        let make_transaction = |seed| {
            AccountTransactionBinding::new(
                TransactionId::from_bytes([seed; 16]),
                TransactionClass::Authentication,
                network,
                expected_route,
                MonotonicTick::from_ticks(100),
            )
            .map(|binding| AccountTransaction::new(binding, seed))
        };

        let mut wrong_class = make_transaction(23)?;
        assert_eq!(
            wrong_class
                .consume(
                    TransactionClass::CredentialChange,
                    network,
                    expected_route,
                    MonotonicTick::from_ticks(1),
                )
                .err(),
            Some(super::AuthError::ContextMismatch)
        );
        let mut wrong_network = make_transaction(24)?;
        assert_eq!(
            wrong_network
                .consume(
                    TransactionClass::Authentication,
                    NetworkId::from_bytes([25_u8; 32]),
                    expected_route,
                    MonotonicTick::from_ticks(1),
                )
                .err(),
            Some(super::AuthError::ContextMismatch)
        );
        for (index, (candidate, expected_error)) in
            route_substitutions(expected_route)?.into_iter().enumerate()
        {
            let seed = u8::try_from(index)?.saturating_add(26);
            let mut substituted = make_transaction(seed)?;
            assert_eq!(
                substituted
                    .consume(
                        TransactionClass::Authentication,
                        network,
                        candidate,
                        MonotonicTick::from_ticks(1),
                    )
                    .err(),
                Some(expected_error)
            );
        }
        let mut expired = make_transaction(28)?;
        assert_eq!(
            expired
                .consume(
                    TransactionClass::Authentication,
                    network,
                    expected_route,
                    MonotonicTick::from_ticks(30_100),
                )
                .err(),
            Some(super::AuthError::Expired)
        );
        Ok(())
    }
}
