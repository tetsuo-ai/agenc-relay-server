//! Pure verification of the authenticated hello tuple and recovery-epoch
//! transitions (spec 20.3).
//!
//! Signature and TLS identity checks belong to the runtime adapters. These
//! functions decide only what the decoded fields must equal.

use std::error::Error;
use std::fmt;

use agenc_relay_types::{FederationRole, NetworkId, RecoveryEpoch, ServerId, ServerIncarnation};

use crate::objects::HelloTbs;

/// Everything the receiver already knows before reading a peer hello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloExpectation {
    /// The receiver's configured role.
    pub local_role: FederationRole,
    /// The configured network identity.
    pub network_id: NetworkId,
    /// The receiver's Server ID.
    pub local_server_id: ServerId,
    /// The authenticated peer's configured Server ID.
    pub peer_server_id: ServerId,
    /// The peer's configured recovery-epoch pin.
    pub pinned_recovery_epoch: RecoveryEpoch,
    /// The receiver's own exporter output for this connection.
    pub tls_exporter: [u8; 32],
    /// The frozen base profile hash.
    pub profile_hash: [u8; 32],
}

/// The one field that disqualified a peer hello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloRejection {
    /// The peer did not claim the inverse of the local role.
    Role,
    /// The network identity differs.
    Network,
    /// The sender is not the authenticated peer.
    SenderId,
    /// The sender expected a different receiver.
    ExpectedPeerId,
    /// The recovery epoch differs from the static pin.
    RecoveryEpochPin,
    /// The nonce was already seen for this peer.
    NonceReuse,
    /// The exporter outputs differ.
    Exporter,
    /// The profile hash differs.
    ProfileHash,
}

impl fmt::Display for HelloRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::Role => "federation hello role mismatch",
            Self::Network => "federation hello network mismatch",
            Self::SenderId => "federation hello sender mismatch",
            Self::ExpectedPeerId => "federation hello expected-peer mismatch",
            Self::RecoveryEpochPin => "federation hello recovery-epoch pin mismatch",
            Self::NonceReuse => "federation hello nonce reuse",
            Self::Exporter => "federation hello exporter mismatch",
            Self::ProfileHash => "federation hello profile-hash mismatch",
        };
        formatter.write_str(message)
    }
}

impl Error for HelloRejection {}

/// Checks every hello field against the receiver's expectation.
///
/// `nonce_fresh` is the caller's statement that the nonce was not previously
/// accepted from this peer; the crate keeps no nonce history.
pub fn verify_hello_tuple(
    tbs: &HelloTbs,
    expectation: &HelloExpectation,
    nonce_fresh: bool,
) -> Result<(), HelloRejection> {
    let expected_role = match expectation.local_role {
        FederationRole::Coordinator => FederationRole::Edge,
        FederationRole::Edge => FederationRole::Coordinator,
    };
    if tbs.role != expected_role {
        return Err(HelloRejection::Role);
    }
    if tbs.network_id != expectation.network_id {
        return Err(HelloRejection::Network);
    }
    if tbs.sender_server_id != expectation.peer_server_id {
        return Err(HelloRejection::SenderId);
    }
    if tbs.expected_peer_server_id != expectation.local_server_id {
        return Err(HelloRejection::ExpectedPeerId);
    }
    if tbs.recovery_epoch != expectation.pinned_recovery_epoch {
        return Err(HelloRejection::RecoveryEpochPin);
    }
    if !nonce_fresh {
        return Err(HelloRejection::NonceReuse);
    }
    if tbs.tls_exporter != expectation.tls_exporter {
        return Err(HelloRejection::Exporter);
    }
    if tbs.profile_hash != expectation.profile_hash {
        return Err(HelloRejection::ProfileHash);
    }
    Ok(())
}

/// What the receiver durably remembers about a peer's last accepted hello.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerContinuity {
    /// The last accepted recovery epoch and incarnation, if any.
    pub last_accepted: Option<(RecoveryEpoch, ServerIncarnation)>,
}

/// How an accepted hello relates to the peer's durable history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochTransition {
    /// First contact with this peer; nothing to fence.
    Initial,
    /// The same recovery epoch as last accepted.
    Continuing,
    /// A new pinned epoch with a fresh incarnation: fence every old origin and
    /// cursor and require a complete snapshot.
    NewEpoch,
}

/// A recovery-epoch change that is a fatal rollback or configuration error.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EpochRejection {
    /// The epoch changed but the incarnation did not.
    SameIncarnationEpochChange,
    /// The epoch was already accepted once and cannot be reused.
    ReusedEpoch,
}

impl fmt::Display for EpochRejection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::SameIncarnationEpochChange => {
                "federation recovery epoch changed without a new incarnation"
            }
            Self::ReusedEpoch => "federation recovery epoch was already accepted",
        };
        formatter.write_str(message)
    }
}

impl Error for EpochRejection {}

/// Classifies a hello that already passed [`verify_hello_tuple`] against the
/// peer's durable continuity and the set of every previously accepted epoch.
pub fn classify_epoch_transition(
    hello_epoch: RecoveryEpoch,
    hello_incarnation: ServerIncarnation,
    continuity: PeerContinuity,
    previously_accepted_epochs: &[RecoveryEpoch],
) -> Result<EpochTransition, EpochRejection> {
    let Some((last_epoch, last_incarnation)) = continuity.last_accepted else {
        return Ok(EpochTransition::Initial);
    };
    if hello_epoch == last_epoch {
        return Ok(EpochTransition::Continuing);
    }
    if hello_incarnation == last_incarnation {
        return Err(EpochRejection::SameIncarnationEpochChange);
    }
    if previously_accepted_epochs.contains(&hello_epoch) {
        return Err(EpochRejection::ReusedEpoch);
    }
    Ok(EpochTransition::NewEpoch)
}

#[cfg(test)]
#[path = "tests/hello.rs"]
mod tests;
