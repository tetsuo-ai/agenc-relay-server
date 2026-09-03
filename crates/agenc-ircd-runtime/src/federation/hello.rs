//! The authenticated FHELLO and FREADY exchange (spec 20.3).
//!
//! Both peers send one signed hello, verify the other's tuple, exporter,
//! profile hash, and signature, then echo the peer nonce in FREADY. Either
//! side may see FHELLO or FREADY first; each waits at most five seconds per
//! message and closes on any other frame.

use std::error::Error;
use std::fmt;
use std::time::Duration;

use agenc_ircd_crypto::{Ed25519Signature, SignatureDomain, sign_canonical, verify_canonical};
use agenc_ircd_federation_wire::{
    BASE_FEDERATION_PROFILE_SHA256, EpochRejection, EpochTransition, FederationFrame,
    FederationHello, HelloExpectation, HelloRejection, HelloTbs, PeerContinuity,
    classify_epoch_transition, verify_hello_tuple,
};
use agenc_ircd_types::{EntropySource, FHELLO_TIMEOUT_SECONDS, RecoveryEpoch, ServerIncarnation};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::federation::link::{FrameReader, ReadFailure, write_line};
use crate::federation::{LocalIdentity, PeerIdentity};

/// The one deadline applied to each hello message.
/// The fixed hello and READY deadline (spec 20.3).
pub const HELLO_DEADLINE: Duration = Duration::from_secs(FHELLO_TIMEOUT_SECONDS);

/// Why the hello exchange failed; every value is safe to log.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HelloFailure {
    /// A message did not arrive within five seconds.
    Timeout,
    /// The transport failed or the peer closed.
    Transport,
    /// A line violated the framing or federation grammar.
    Framing,
    /// A frame other than the expected FHELLO or FREADY arrived.
    UnexpectedFrame,
    /// The peer hello named a different peer for this receiver.
    WrongAddressee,
    /// The hello signature did not verify under the configured key.
    Signature,
    /// One hello tuple field disqualified the peer.
    Tuple(HelloRejection),
    /// The recovery epoch transition is a fatal rollback or configuration error.
    Epoch(EpochRejection),
    /// The FREADY nonce did not echo ours.
    NonceMismatch,
    /// Encoding or entropy failed locally.
    Local,
}

impl fmt::Display for HelloFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("hello timed out"),
            Self::Transport => formatter.write_str("hello transport failed"),
            Self::Framing => formatter.write_str("hello framing violation"),
            Self::UnexpectedFrame => formatter.write_str("unexpected frame before READY"),
            Self::WrongAddressee => formatter.write_str("hello addressed to another server"),
            Self::Signature => formatter.write_str("hello signature rejected"),
            Self::Tuple(rejection) => rejection.fmt(formatter),
            Self::Epoch(rejection) => rejection.fmt(formatter),
            Self::NonceMismatch => formatter.write_str("READY nonce mismatch"),
            Self::Local => formatter.write_str("hello could not be produced"),
        }
    }
}

impl Error for HelloFailure {}

impl From<ReadFailure> for HelloFailure {
    fn from(failure: ReadFailure) -> Self {
        match failure {
            ReadFailure::Io | ReadFailure::PeerClosed => Self::Transport,
            ReadFailure::Framing | ReadFailure::Frame(_) => Self::Framing,
        }
    }
}

/// The authenticated facts learned from a completed exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HelloOutcome {
    /// The peer's incarnation.
    pub peer_incarnation: ServerIncarnation,
    /// The peer's recovery epoch.
    pub peer_recovery_epoch: RecoveryEpoch,
    /// How the epoch relates to the durable peer history.
    pub transition: EpochTransition,
    /// The nonce we sent, echoed by the peer's READY.
    pub local_nonce: [u8; 32],
    /// The nonce the peer sent, echoed by our READY.
    pub peer_nonce: [u8; 32],
}

/// The durable peer facts the exchange checks the hello against.
#[derive(Clone, Copy, Debug)]
pub struct PeerHistory<'a> {
    /// The last accepted epoch and incarnation.
    pub continuity: PeerContinuity,
    /// Every epoch ever accepted from the peer.
    pub accepted_epochs: &'a [RecoveryEpoch],
}

/// Builds and signs this node's hello for one connection.
pub fn build_hello(
    local: &LocalIdentity,
    peer: &PeerIdentity,
    exporter: [u8; 32],
    nonce: [u8; 32],
) -> Result<FederationHello, HelloFailure> {
    let tbs = HelloTbs {
        network_id: local.network_id(),
        sender_server_id: local.server_id(),
        expected_peer_server_id: peer.server_id(),
        server_incarnation: local.incarnation(),
        recovery_epoch: local.recovery_epoch(),
        role: local.role(),
        hello_nonce: nonce,
        profile_hash: BASE_FEDERATION_PROFILE_SHA256,
        tls_exporter: exporter,
    };
    let encoded = tbs.encode().map_err(|_| HelloFailure::Local)?;
    let signature = sign_canonical(
        local.signing_key(),
        SignatureDomain::FederationHello,
        encoded.as_slice(),
    )
    .map_err(|_| HelloFailure::Local)?;
    Ok(FederationHello {
        tbs,
        signature: *signature.as_bytes(),
    })
}

/// Verifies one received peer hello against the local expectation.
pub fn verify_hello(
    hello: &FederationHello,
    local: &LocalIdentity,
    peer: &PeerIdentity,
    exporter: [u8; 32],
    history: PeerHistory<'_>,
) -> Result<EpochTransition, HelloFailure> {
    let encoded = hello.tbs.encode().map_err(|_| HelloFailure::Local)?;
    verify_canonical(
        peer.signing_key(),
        SignatureDomain::FederationHello,
        encoded.as_slice(),
        Ed25519Signature::from_bytes(hello.signature),
    )
    .map_err(|_| HelloFailure::Signature)?;
    let expectation = HelloExpectation {
        local_role: local.role(),
        network_id: local.network_id(),
        local_server_id: local.server_id(),
        peer_server_id: peer.server_id(),
        pinned_recovery_epoch: peer.recovery_epoch_pin(),
        tls_exporter: exporter,
        profile_hash: BASE_FEDERATION_PROFILE_SHA256,
    };
    verify_hello_tuple(&hello.tbs, &expectation, true).map_err(HelloFailure::Tuple)?;
    classify_epoch_transition(
        hello.tbs.recovery_epoch,
        hello.tbs.server_incarnation,
        history.continuity,
        history.accepted_epochs,
    )
    .map_err(HelloFailure::Epoch)
}

/// Runs the complete exchange over one authenticated transport.
pub async fn exchange_hello<S>(
    reader: &mut FrameReader<S>,
    local: &LocalIdentity,
    peer: &PeerIdentity,
    exporter: [u8; 32],
    history: PeerHistory<'_>,
    entropy: &mut (dyn EntropySource + Send),
) -> Result<HelloOutcome, HelloFailure>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut local_nonce = [0_u8; 32];
    entropy
        .fill_exact(&mut local_nonce)
        .map_err(|_| HelloFailure::Local)?;
    let hello = build_hello(local, peer, exporter, local_nonce)?;
    let line = FederationFrame::Hello {
        peer_server_id: peer.server_id(),
        hello,
    }
    .render(local.server_name())
    .map_err(|_| HelloFailure::Local)?;
    write_line(reader.stream_mut(), &line)
        .await
        .map_err(|_| HelloFailure::Transport)?;

    let mut verified: Option<(HelloOutcome, bool)> = None;
    loop {
        let frame = tokio::time::timeout(HELLO_DEADLINE, reader.next_frame())
            .await
            .map_err(|_| HelloFailure::Timeout)??;
        match (frame, &mut verified) {
            (
                FederationFrame::Hello {
                    peer_server_id,
                    hello,
                },
                None,
            ) => {
                if peer_server_id != local.server_id() {
                    return Err(HelloFailure::WrongAddressee);
                }
                let transition = verify_hello(&hello, local, peer, exporter, history)?;
                let ready = FederationFrame::Ready {
                    peer_server_id: peer.server_id(),
                    hello_nonce: hello.tbs.hello_nonce,
                }
                .render(local.server_name())
                .map_err(|_| HelloFailure::Local)?;
                write_line(reader.stream_mut(), &ready)
                    .await
                    .map_err(|_| HelloFailure::Transport)?;
                let outcome = HelloOutcome {
                    peer_incarnation: hello.tbs.server_incarnation,
                    peer_recovery_epoch: hello.tbs.recovery_epoch,
                    transition,
                    local_nonce,
                    peer_nonce: hello.tbs.hello_nonce,
                };
                verified = Some((outcome, false));
            }
            (
                FederationFrame::Ready {
                    peer_server_id,
                    hello_nonce,
                },
                Some((outcome, ready_seen)),
            ) if !*ready_seen => {
                if peer_server_id != local.server_id() {
                    return Err(HelloFailure::WrongAddressee);
                }
                if hello_nonce != outcome.local_nonce {
                    return Err(HelloFailure::NonceMismatch);
                }
                return Ok(*outcome);
            }
            _ => return Err(HelloFailure::UnexpectedFrame),
        }
    }
}
