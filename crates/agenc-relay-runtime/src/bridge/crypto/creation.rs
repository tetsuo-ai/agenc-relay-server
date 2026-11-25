//! The original and guarded creation use the same admission lookups, rate policy and bounded workers.

use super::*;
use agenc_relay_auth::{
    GuardedAccountStart, GuardedCreationChallenge, claimed_creation::OpenedGuardedStart,
};

/// The opened registration and response authority before the ordinary admission lookups.
pub enum CreationInput {
    /// The original mode in profile one.
    Base(AuthenticatedAccountRequest<CreationStart>),
    /// The negotiated guarded START with the creator's precommit.
    Guarded(OpenedGuardedStart),
}

impl From<AuthenticatedAccountRequest<CreationStart>> for CreationInput {
    fn from(opened: AuthenticatedAccountRequest<CreationStart>) -> Self {
        Self::Base(opened)
    }
}

impl From<OpenedGuardedStart> for CreationInput {
    fn from(opened: OpenedGuardedStart) -> Self {
        Self::Guarded(opened)
    }
}

impl CreationInput {
    pub(crate) fn payload(&self) -> &CreationStart {
        match self {
            Self::Base(opened) => opened.payload(),
            Self::Guarded(opened) => opened.request(),
        }
    }
}

/// The correctly profiled challenge produced before the response counter is reserved.
pub enum CreationPlan {
    /// A base OPAQUE challenge.
    Base(Box<AccountStartOutcome<AccountCreationState>>),
    /// A guarded OPAQUE challenge with the private creation lineage.
    Guarded(Box<GuardedCreationChallenge>),
}

impl CreationPlan {
    pub(super) fn prepare(
        profile: &OpaqueProfile,
        lookup: &LoginIndexKey,
        parameters: AccountCreationStartParameters<CreationInput>,
    ) -> Result<Self, AuthError> {
        let AccountCreationStartParameters {
            context,
            request,
            admission,
            login_is_available,
            invitation_is_available,
        } = parameters;
        match request {
            CreationInput::Base(request) => begin_account_creation(
                profile,
                lookup,
                AccountCreationStartParameters {
                    context,
                    request,
                    admission,
                    login_is_available,
                    invitation_is_available,
                },
            )
            .map(|value| Self::Base(Box::new(value))),
            CreationInput::Guarded(request) => agenc_relay_auth::prepare_guarded_account_creation(
                profile,
                lookup,
                AccountCreationStartParameters {
                    context,
                    request,
                    admission,
                    login_is_available,
                    invitation_is_available,
                },
            )
            .map(|value| Self::Guarded(Box::new(value))),
        }
    }

    pub(super) fn seal(self, count: u64) -> Result<SealedCreation, AuthError> {
        match self {
            Self::Base(plan) => plan.seal(count).map(SealedCreation::from),
            Self::Guarded(plan) => plan
                .seal(count)
                .map(|value| SealedCreation::Guarded(Box::new(value))),
        }
    }
}

/// A sealed challenge whose transaction remains unavailable until its durable commit.
pub enum SealedCreation {
    /// A base START release.
    Base(Box<SealedAccountStart<AccountCreationState>>),
    /// An exact guarded request, challenge and protected transaction.
    Guarded(Box<GuardedAccountStart>),
}

impl From<SealedAccountStart<AccountCreationState>> for SealedCreation {
    fn from(sealed: SealedAccountStart<AccountCreationState>) -> Self {
        Self::Base(Box::new(sealed))
    }
}

impl SealedCreation {
    pub(crate) fn transaction_id(&self) -> agenc_relay_types::TransactionId {
        match self {
            Self::Base(s) => s.transaction_id(),
            Self::Guarded(s) => s.transaction_id(),
        }
    }

    pub(crate) fn response(&self) -> &[u8; agenc_relay_auth::ACCOUNT_SERVICE_RESPONSE_BYTES] {
        match self {
            Self::Base(s) => s.response_intent().response().as_bytes(),
            Self::Guarded(s) => s.response_for_commit().as_bytes(),
        }
    }

    pub(crate) fn next_response_count(&self) -> u64 {
        match self {
            Self::Base(s) => s.response_intent().next_response_count(),
            Self::Guarded(s) => s.next_response_count(),
        }
    }

    pub(crate) fn retained_record(
        &self,
        now: agenc_relay_types::MonotonicTick,
        utc: UtcSecond,
    ) -> Result<(UtcSecond, Vec<u8>), AuthError> {
        match self {
            Self::Base(s) => {
                let record = s.creation_transaction_record(now, utc)?;
                Ok((
                    record.durable_expires_at_utc()?,
                    record.expose_for_persistence().to_vec(),
                ))
            }
            Self::Guarded(s) => Ok((
                s.live_record_expiry(now, utc)?,
                s.record().expose_for_persistence().to_vec(),
            )),
        }
    }

    pub(crate) fn reservation_login(&self) -> Option<&agenc_relay_crypto::LoginIndexDigest> {
        match self {
            Self::Base(s) => s.creation_reservation_login_digest(),
            Self::Guarded(s) => s.reserved_login(),
        }
    }

    pub(crate) fn reservation_invitation(&self) -> Option<InviteId> {
        match self {
            Self::Base(s) => s.creation_reservation_invitation(),
            Self::Guarded(s) => s.reserved_invitation(),
        }
        .map(|(id, _)| id)
    }
}
