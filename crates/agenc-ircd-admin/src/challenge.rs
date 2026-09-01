//! Section 22.4 administrative session challenge and operator proof.

use agenc_ircd_crypto::{
    CryptoError, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, SignatureDomain,
    sign_canonical, verify_canonical,
};
use agenc_ircd_types::{NetworkId, ServerId};

use crate::AdminError;
use crate::base64::{decode_fixed_base64url, encode_base64url};
use crate::codec::Writer;

/// Random administrative session identifier width (spec 4380).
pub const ADMIN_SESSION_ID_BYTES: usize = 16;
/// Random challenge width (spec 4380).
pub const ADMIN_CHALLENGE_BYTES: usize = 32;
/// Transport binding width: RFC 9846 exporter or fresh random bytes (spec 4380-4384).
pub const ADMIN_TRANSPORT_BINDING_BYTES: usize = 32;

/// Session proof profile version (spec 4391).
const SESSION_PROOF_VERSION: u16 = 1;
/// Exact encoded proof length: version, network, server, session, challenge,
/// kind, binding.
const SESSION_PROOF_BYTES: usize = 2 + 32 + 16 + 16 + 32 + 2 + 32;

/// A fresh random administrative session identity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminSessionId([u8; ADMIN_SESSION_ID_BYTES]);

impl AdminSessionId {
    /// Wraps fresh random bytes drawn by the runtime.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ADMIN_SESSION_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADMIN_SESSION_ID_BYTES] {
        &self.0
    }

    /// Encodes the 22-character canonical token.
    #[must_use]
    pub fn to_base64url(&self) -> String {
        encode_base64url(&self.0)
    }
}

/// A fresh random challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Challenge([u8; ADMIN_CHALLENGE_BYTES]);

impl Challenge {
    /// Wraps fresh random bytes drawn by the runtime.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ADMIN_CHALLENGE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw challenge bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADMIN_CHALLENGE_BYTES] {
        &self.0
    }
}

/// The transport binding: an exporter value on TLS, random bytes locally.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TransportBinding([u8; ADMIN_TRANSPORT_BINDING_BYTES]);

impl TransportBinding {
    /// Wraps the exporter output or the fresh local binding.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; ADMIN_TRANSPORT_BINDING_BYTES]) -> Self {
        Self(bytes)
    }

    /// Returns the raw binding bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; ADMIN_TRANSPORT_BINDING_BYTES] {
        &self.0
    }
}

/// Which administrative transport carried the session (spec 4394).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TransportKind {
    /// Unix socket admitted by peer credentials.
    Local = 1,
    /// Remote TLS listener with the admin ALPN and client certificate pin.
    Tls = 2,
}

impl TransportKind {
    /// Returns the `uint16(transport_kind)` value.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::Local => 1,
            Self::Tls => 2,
        }
    }

    /// Returns the challenge-line token.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::Tls => "tls",
        }
    }
}

/// The challenge the server issues before OPER and the proof it later checks.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AdminChallenge {
    session_id: AdminSessionId,
    challenge: Challenge,
    kind: TransportKind,
    binding: TransportBinding,
}

impl AdminChallenge {
    /// Binds the four session facts the runtime established.
    #[must_use]
    pub const fn new(
        session_id: AdminSessionId,
        challenge: Challenge,
        kind: TransportKind,
        binding: TransportBinding,
    ) -> Self {
        Self {
            session_id,
            challenge,
            kind,
            binding,
        }
    }

    /// Returns the session identity.
    #[must_use]
    pub const fn session_id(&self) -> AdminSessionId {
        self.session_id
    }

    /// Returns the transport kind.
    #[must_use]
    pub const fn kind(&self) -> TransportKind {
        self.kind
    }

    /// Renders the exact pre-authentication challenge line (spec 4377-4380).
    #[must_use]
    pub fn render_note(&self) -> String {
        format!(
            "NOTE OPER CHALLENGE {} {} {} {} :Authenticate this administrative session",
            self.session_id.to_base64url(),
            encode_base64url(&self.challenge.0),
            self.kind.token(),
            encode_base64url(&self.binding.0),
        )
    }

    /// Encodes the signed content after the domain label (spec 4389-4394).
    pub fn session_proof_bytes(
        &self,
        network_id: NetworkId,
        server_id: ServerId,
    ) -> Result<Vec<u8>, AdminError> {
        let mut writer = Writer::with_ceiling(SESSION_PROOF_BYTES);
        writer.put_u16(SESSION_PROOF_VERSION)?;
        writer.put_fixed(network_id.as_bytes())?;
        writer.put_fixed(server_id.as_bytes())?;
        writer.put_fixed(&self.session_id.0)?;
        writer.put_fixed(&self.challenge.0)?;
        writer.put_u16(self.kind.as_u16())?;
        writer.put_fixed(&self.binding.0)?;
        Ok(writer.finish())
    }

    /// Produces the operator proof a client sends in `OPER` (used by tests
    /// and client tooling; the server only verifies).
    pub fn sign_oper(
        &self,
        network_id: NetworkId,
        server_id: ServerId,
        operator_key: &Ed25519SecretKey,
    ) -> Result<Ed25519Signature, AdminError> {
        let content = self.session_proof_bytes(network_id, server_id)?;
        sign_canonical(operator_key, SignatureDomain::AdminSession, &content).map_err(map_crypto)
    }

    /// Strictly verifies an `OPER` proof under the enrolled operator key.
    pub fn verify_oper(
        &self,
        network_id: NetworkId,
        server_id: ServerId,
        operator_key: Ed25519PublicKey,
        signature: Ed25519Signature,
    ) -> Result<(), AdminError> {
        let content = self.session_proof_bytes(network_id, server_id)?;
        verify_canonical(
            operator_key,
            SignatureDomain::AdminSession,
            &content,
            signature,
        )
        .map_err(map_crypto)
    }
}

/// Parses the 86-character canonical signature token of an `OPER` line.
pub(crate) fn parse_signature_token(text: &[u8]) -> Result<Ed25519Signature, AdminError> {
    decode_fixed_base64url::<64>(text).map(Ed25519Signature::from_bytes)
}

fn map_crypto(error: CryptoError) -> AdminError {
    match error {
        CryptoError::AuthenticationFailed => AdminError::Signature,
        CryptoError::LimitExceeded => AdminError::Limit,
        CryptoError::Overflow => AdminError::Overflow,
        _ => AdminError::Token,
    }
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::{Ed25519SecretKey, Ed25519Signature};
    use agenc_ircd_types::{NetworkId, ServerId};

    use super::{
        AdminChallenge, AdminSessionId, Challenge, TransportBinding, TransportKind,
        parse_signature_token,
    };
    use crate::{AdminError, encode_base64url};

    fn challenge(kind: TransportKind) -> AdminChallenge {
        AdminChallenge::new(
            AdminSessionId::from_bytes([1; 16]),
            Challenge::from_bytes([2; 32]),
            kind,
            TransportBinding::from_bytes([3; 32]),
        )
    }

    #[test]
    fn challenge_note_has_exact_tokens_and_kinds() {
        let note = challenge(TransportKind::Local).render_note();
        let parts: Vec<&str> = note.split(' ').collect();
        assert_eq!(parts.len(), 11);
        assert_eq!(parts.first().copied(), Some("NOTE"));
        assert_eq!(parts.get(3).map(|token| token.len()), Some(22));
        assert_eq!(parts.get(4).map(|token| token.len()), Some(43));
        assert_eq!(parts.get(5).copied(), Some("local"));
        assert_eq!(parts.get(6).map(|token| token.len()), Some(43));
        assert!(note.ends_with(" :Authenticate this administrative session"));
        assert!(
            challenge(TransportKind::Tls)
                .render_note()
                .contains(" tls ")
        );
        assert_eq!(TransportKind::Local.as_u16(), 1);
        assert_eq!(TransportKind::Tls.as_u16(), 2);
    }

    #[test]
    fn proof_layout_binds_every_field_and_verifies_strictly() -> Result<(), AdminError> {
        let network = NetworkId::from_bytes([9; 32]);
        let server = ServerId::from_bytes([8; 16]);
        let subject = challenge(TransportKind::Tls);
        let bytes = subject.session_proof_bytes(network, server)?;
        assert_eq!(bytes.len(), 132);
        assert_eq!(bytes.get(..2), Some(&[0, 1][..]));
        assert_eq!(bytes.get(2..34), Some(&[9_u8; 32][..]));
        assert_eq!(bytes.get(34..50), Some(&[8_u8; 16][..]));
        assert_eq!(bytes.get(50..66), Some(&[1_u8; 16][..]));
        assert_eq!(bytes.get(66..98), Some(&[2_u8; 32][..]));
        assert_eq!(bytes.get(98..100), Some(&[0, 2][..]));
        assert_eq!(bytes.get(100..132), Some(&[3_u8; 32][..]));

        let key = Ed25519SecretKey::from_bytes([5; 32]);
        let signature = subject.sign_oper(network, server, &key)?;
        subject.verify_oper(network, server, key.public_key(), signature)?;
        let other = challenge(TransportKind::Local);
        assert_eq!(
            other.verify_oper(network, server, key.public_key(), signature),
            Err(AdminError::Signature)
        );
        let wrong_key = Ed25519SecretKey::from_bytes([6; 32]);
        assert_eq!(
            subject.verify_oper(network, server, wrong_key.public_key(), signature),
            Err(AdminError::Signature)
        );
        let text = encode_base64url(signature.as_bytes());
        assert_eq!(text.len(), 86);
        assert_eq!(parse_signature_token(text.as_bytes())?, signature);
        assert_eq!(parse_signature_token(b"short"), Err(AdminError::Token));
        assert_ne!(
            Ed25519Signature::from_bytes([0; 64]).as_bytes(),
            signature.as_bytes()
        );
        Ok(())
    }
}
