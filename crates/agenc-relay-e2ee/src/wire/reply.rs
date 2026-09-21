//! The closed `FAIL` reply code registry (companion Section 11.9).

use std::fmt;

/// One of the twenty-two extension reply codes.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum E2eeReplyCode {
    /// Required capability was not negotiated.
    CapRequired,
    /// Connection lacks an authenticated account.
    AccountRequired,
    /// Connection lacks a current roster-active device attachment.
    DeviceRequired,
    /// Fragment grammar, encoding, or consistency failed.
    InvalidFragment,
    /// Declared or decoded object exceeds its limit.
    ObjectTooLarge,
    /// Memory, object-count, or timeout limit reached.
    ReassemblyLimit,
    /// Reassembled bytes do not match the object ID.
    HashMismatch,
    /// Route is unknown or does not match the sender.
    RouteInvalid,
    /// A binding already exists.
    GroupConflict,
    /// Binding or transition authorization is missing or malformed.
    BindingAuthInvalid,
    /// The epoch already has an unfinalized candidate.
    CandidateActive,
    /// Operation named a candidate without a valid finalization.
    FinalityRequired,
    /// A published policy failed route, chain, or approval validation.
    PolicyInvalid,
    /// A terminal request named a policy the server has not retained.
    PolicyRequired,
    /// A Commit references an epoch outside the bounded window.
    EpochStale,
    /// Requested retained object or record is unavailable.
    ObjectNotFound,
    /// Operation exceeded an authenticated quota.
    RateLimited,
    /// No acceptable KeyPackage is available.
    KeyUnavailable,
    /// A stable operation ID was reused with different parameters.
    OperationConflict,
    /// Coordinator accepted the request but ingress lost its result.
    DeliveryUncertain,
    /// Federation route state has not crossed the READY/ACTIVE barrier.
    Syncing,
    /// Plaintext is forbidden for the target.
    Required,
}

impl E2eeReplyCode {
    /// Every code in registry order.
    pub const ALL: [Self; 22] = [
        Self::CapRequired,
        Self::AccountRequired,
        Self::DeviceRequired,
        Self::InvalidFragment,
        Self::ObjectTooLarge,
        Self::ReassemblyLimit,
        Self::HashMismatch,
        Self::RouteInvalid,
        Self::GroupConflict,
        Self::BindingAuthInvalid,
        Self::CandidateActive,
        Self::FinalityRequired,
        Self::PolicyInvalid,
        Self::PolicyRequired,
        Self::EpochStale,
        Self::ObjectNotFound,
        Self::RateLimited,
        Self::KeyUnavailable,
        Self::OperationConflict,
        Self::DeliveryUncertain,
        Self::Syncing,
        Self::Required,
    ];

    /// The wire token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::CapRequired => "E2EE_CAP_REQUIRED",
            Self::AccountRequired => "E2EE_ACCOUNT_REQUIRED",
            Self::DeviceRequired => "E2EE_DEVICE_REQUIRED",
            Self::InvalidFragment => "E2EE_INVALID_FRAGMENT",
            Self::ObjectTooLarge => "E2EE_OBJECT_TOO_LARGE",
            Self::ReassemblyLimit => "E2EE_REASSEMBLY_LIMIT",
            Self::HashMismatch => "E2EE_HASH_MISMATCH",
            Self::RouteInvalid => "E2EE_ROUTE_INVALID",
            Self::GroupConflict => "E2EE_GROUP_CONFLICT",
            Self::BindingAuthInvalid => "E2EE_BINDING_AUTH_INVALID",
            Self::CandidateActive => "E2EE_CANDIDATE_ACTIVE",
            Self::FinalityRequired => "E2EE_FINALITY_REQUIRED",
            Self::PolicyInvalid => "E2EE_POLICY_INVALID",
            Self::PolicyRequired => "E2EE_POLICY_REQUIRED",
            Self::EpochStale => "E2EE_EPOCH_STALE",
            Self::ObjectNotFound => "E2EE_OBJECT_NOT_FOUND",
            Self::RateLimited => "E2EE_RATE_LIMITED",
            Self::KeyUnavailable => "E2EE_KEY_UNAVAILABLE",
            Self::OperationConflict => "E2EE_OPERATION_CONFLICT",
            Self::DeliveryUncertain => "E2EE_DELIVERY_UNCERTAIN",
            Self::Syncing => "E2EE_SYNCING",
            Self::Required => "E2EE_REQUIRED",
        }
    }

    /// The fixed description; never carries object bytes or identities.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::CapRequired => "required capability was not negotiated",
            Self::AccountRequired => "an authenticated account is required",
            Self::DeviceRequired => "a roster-active device attachment is required",
            Self::InvalidFragment => "fragment grammar, encoding, or consistency failed",
            Self::ObjectTooLarge => "object exceeds its limit",
            Self::ReassemblyLimit => "reassembly limit reached",
            Self::HashMismatch => "reassembled bytes do not match the object id",
            Self::RouteInvalid => "route is unknown or does not match the sender",
            Self::GroupConflict => "a binding already exists",
            Self::BindingAuthInvalid => "binding or transition authorization is invalid",
            Self::CandidateActive => "the epoch already has an unfinalized candidate",
            Self::FinalityRequired => "operation requires a valid finalization",
            Self::PolicyInvalid => "published policy failed validation",
            Self::PolicyRequired => "the named policy has not been published",
            Self::EpochStale => "commit references an epoch outside the window",
            Self::ObjectNotFound => "requested object is unavailable",
            Self::RateLimited => "operation exceeded a quota",
            Self::KeyUnavailable => "no acceptable key package is available",
            Self::OperationConflict => "operation id reused with different parameters",
            Self::DeliveryUncertain => "request result was lost after acceptance",
            Self::Syncing => "federation route state is not active",
            Self::Required => "plaintext is forbidden for the target",
        }
    }

    /// Looks a token up.
    #[must_use]
    pub fn from_token(token: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|code| code.token() == token)
    }

    /// Renders `FAIL <command> <code> [context] :<description>` without the
    /// server prefix. `command` is the triggering command or `*`.
    #[must_use]
    pub fn render_fail(self, command: &str, context: Option<&str>) -> String {
        match context {
            Some(context) => format!(
                "FAIL {command} {} {context} :{}",
                self.token(),
                self.description()
            ),
            None => format!("FAIL {command} {} :{}", self.token(), self.description()),
        }
    }
}

impl fmt::Display for E2eeReplyCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.token())
    }
}

#[cfg(test)]
#[path = "../tests/reply.rs"]
mod tests;
