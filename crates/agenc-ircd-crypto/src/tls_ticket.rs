//! Bounded ChaCha20-Poly1305 protection for opaque TLS session tickets.

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;
use crate::{CryptoError, OsEntropy};

const TLS_TICKET_FORMAT_VERSION: u8 = 1;
const TLS_TICKET_KEY_BYTES: usize = 32;
const TLS_TICKET_KEY_ID_BYTES: usize = 16;
const TLS_TICKET_NONCE_BYTES: usize = 12;
const TLS_TICKET_TAG_BYTES: usize = 16;
const TLS_TICKET_HEADER_BYTES: usize = 1 + TLS_TICKET_KEY_ID_BYTES + TLS_TICKET_NONCE_BYTES;
const MIN_TLS_TICKET_BYTES: usize = TLS_TICKET_HEADER_BYTES + TLS_TICKET_TAG_BYTES;

/// Largest plaintext that leaves room for the version, key ID, nonce, and
/// authentication tag in TLS's 65,535-byte ticket vector.
pub const MAX_TLS_TICKET_PLAINTEXT_BYTES: usize = 65_535 - MIN_TLS_TICKET_BYTES;
/// Largest encoded ticket accepted from the network.
pub const MAX_TLS_TICKET_BYTES: usize = 65_535;

/// Random, non-secret identifier for one ephemeral ticket key.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TlsTicketKeyId([u8; TLS_TICKET_KEY_ID_BYTES]);

/// One process-local TLS ticket key, zeroized when its generation is dropped.
///
/// ```compile_fail
/// use agenc_ircd_crypto::TlsTicketKey;
/// fn require_clone<T: Clone>() {}
/// require_clone::<TlsTicketKey>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_crypto::TlsTicketKey;
/// fn require_debug<T: core::fmt::Debug>() {}
/// require_debug::<TlsTicketKey>();
/// ```
pub struct TlsTicketKey {
    id: TlsTicketKeyId,
    bytes: SecretBytes<TLS_TICKET_KEY_BYTES>,
}

impl TlsTicketKey {
    /// Generates a fresh, nonpersisted key ID and ChaCha20-Poly1305 key from
    /// the operating-system entropy authority.
    pub fn generate() -> Result<Self, CryptoError> {
        Self::generate_with(OsEntropy::fill)
    }

    /// Returns the non-secret identifier carried by tickets for this key.
    #[must_use]
    pub const fn key_id(&self) -> TlsTicketKeyId {
        self.id
    }

    /// Seals one bounded rustls session value with a fresh random nonce.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>, CryptoError> {
        self.seal_with(plaintext, OsEntropy::fill)
    }

    /// Authenticates and opens one bounded version-one ticket for this key.
    pub fn open(&self, encoded: &[u8]) -> Result<OpenedTlsTicket, CryptoError> {
        let parts = parse_ticket(encoded)?;
        if parts.key_id != self.id {
            return Err(CryptoError::AuthenticationFailed);
        }
        let cipher = ChaCha20Poly1305::new_from_slice(self.bytes.as_bytes())
            .map_err(|_| CryptoError::InvalidEncoding)?;
        let nonce = Nonce::try_from(parts.nonce).map_err(|_| CryptoError::InvalidEncoding)?;
        let plaintext = cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: parts.ciphertext,
                    aad: parts.header,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        if plaintext.len() > MAX_TLS_TICKET_PLAINTEXT_BYTES {
            return Err(CryptoError::LimitExceeded);
        }
        Ok(OpenedTlsTicket(Zeroizing::new(plaintext)))
    }

    fn generate_with<F>(mut fill: F) -> Result<Self, CryptoError>
    where
        F: FnMut(&mut [u8]) -> Result<(), CryptoError>,
    {
        let mut id = [0_u8; TLS_TICKET_KEY_ID_BYTES];
        if let Err(error) = fill(&mut id) {
            id.fill(0);
            return Err(error);
        }
        let mut bytes = SecretBytes::new([0_u8; TLS_TICKET_KEY_BYTES]);
        if let Err(error) = fill(bytes.as_mut_bytes()) {
            id.fill(0);
            bytes.as_mut_bytes().fill(0);
            return Err(error);
        }
        Ok(Self {
            id: TlsTicketKeyId(id),
            bytes,
        })
    }

    fn seal_with<F>(&self, plaintext: &[u8], mut fill: F) -> Result<Vec<u8>, CryptoError>
    where
        F: FnMut(&mut [u8]) -> Result<(), CryptoError>,
    {
        if plaintext.len() > MAX_TLS_TICKET_PLAINTEXT_BYTES {
            return Err(CryptoError::LimitExceeded);
        }
        let mut nonce_bytes = [0_u8; TLS_TICKET_NONCE_BYTES];
        if let Err(error) = fill(&mut nonce_bytes) {
            nonce_bytes.fill(0);
            return Err(error);
        }
        let header = encode_header(self.id, nonce_bytes)?;
        let nonce =
            Nonce::try_from(nonce_bytes.as_slice()).map_err(|_| CryptoError::InvalidEncoding)?;
        let cipher = ChaCha20Poly1305::new_from_slice(self.bytes.as_bytes())
            .map_err(|_| CryptoError::InvalidEncoding)?;
        let ciphertext = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: plaintext,
                    aad: &header,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let encoded_len = TLS_TICKET_HEADER_BYTES
            .checked_add(ciphertext.len())
            .ok_or(CryptoError::Overflow)?;
        if encoded_len > MAX_TLS_TICKET_BYTES {
            return Err(CryptoError::LimitExceeded);
        }
        let mut encoded = Vec::new();
        encoded
            .try_reserve_exact(encoded_len)
            .map_err(|_| CryptoError::AllocationFailed)?;
        encoded.extend_from_slice(&header);
        encoded.extend_from_slice(&ciphertext);
        Ok(encoded)
    }
}

/// One authenticated rustls ticket plaintext, zeroized unless ownership is
/// explicitly transferred to rustls.
pub struct OpenedTlsTicket(Zeroizing<Vec<u8>>);

impl OpenedTlsTicket {
    /// Transfers the plaintext to rustls, which owns its session-secret
    /// lifetime after this boundary.
    #[must_use]
    pub fn into_rustls_plaintext(mut self) -> Vec<u8> {
        std::mem::take(&mut self.0)
    }
}

/// Parses only the bounded version and key ID needed to select a retained
/// generation. Full authentication still happens in [`TlsTicketKey::open`].
pub fn tls_ticket_key_id(encoded: &[u8]) -> Result<TlsTicketKeyId, CryptoError> {
    parse_ticket(encoded).map(|parts| parts.key_id)
}

struct TicketParts<'a> {
    header: &'a [u8],
    key_id: TlsTicketKeyId,
    nonce: &'a [u8],
    ciphertext: &'a [u8],
}

fn parse_ticket(encoded: &[u8]) -> Result<TicketParts<'_>, CryptoError> {
    if !(MIN_TLS_TICKET_BYTES..=MAX_TLS_TICKET_BYTES).contains(&encoded.len()) {
        return Err(CryptoError::InvalidEncoding);
    }
    let header = encoded
        .get(..TLS_TICKET_HEADER_BYTES)
        .ok_or(CryptoError::InvalidEncoding)?;
    if header.first().copied() != Some(TLS_TICKET_FORMAT_VERSION) {
        return Err(CryptoError::InvalidEncoding);
    }
    let key_id_start = 1_usize;
    let key_id_end = key_id_start
        .checked_add(TLS_TICKET_KEY_ID_BYTES)
        .ok_or(CryptoError::Overflow)?;
    let key_id_bytes = header
        .get(key_id_start..key_id_end)
        .ok_or(CryptoError::InvalidEncoding)?;
    let mut key_id = [0_u8; TLS_TICKET_KEY_ID_BYTES];
    key_id.copy_from_slice(key_id_bytes);
    let nonce = header
        .get(key_id_end..TLS_TICKET_HEADER_BYTES)
        .ok_or(CryptoError::InvalidEncoding)?;
    let ciphertext = encoded
        .get(TLS_TICKET_HEADER_BYTES..)
        .ok_or(CryptoError::InvalidEncoding)?;
    if ciphertext.len() < TLS_TICKET_TAG_BYTES {
        return Err(CryptoError::InvalidEncoding);
    }
    Ok(TicketParts {
        header,
        key_id: TlsTicketKeyId(key_id),
        nonce,
        ciphertext,
    })
}

fn encode_header(
    key_id: TlsTicketKeyId,
    nonce: [u8; TLS_TICKET_NONCE_BYTES],
) -> Result<[u8; TLS_TICKET_HEADER_BYTES], CryptoError> {
    let mut header = [0_u8; TLS_TICKET_HEADER_BYTES];
    let version = header.first_mut().ok_or(CryptoError::InvalidEncoding)?;
    *version = TLS_TICKET_FORMAT_VERSION;
    let key_id_start = 1_usize;
    let key_id_end = key_id_start
        .checked_add(TLS_TICKET_KEY_ID_BYTES)
        .ok_or(CryptoError::Overflow)?;
    header
        .get_mut(key_id_start..key_id_end)
        .ok_or(CryptoError::InvalidEncoding)?
        .copy_from_slice(&key_id.0);
    header
        .get_mut(key_id_end..TLS_TICKET_HEADER_BYTES)
        .ok_or(CryptoError::InvalidEncoding)?
        .copy_from_slice(&nonce);
    Ok(header)
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn fixed_key(id: u8, key: u8) -> TlsTicketKey {
        TlsTicketKey {
            id: TlsTicketKeyId([id; TLS_TICKET_KEY_ID_BYTES]),
            bytes: SecretBytes::new([key; TLS_TICKET_KEY_BYTES]),
        }
    }

    fn deterministic_nonce(output: &mut [u8]) -> Result<(), CryptoError> {
        for (index, byte) in output.iter_mut().enumerate() {
            *byte = u8::try_from(index).map_err(|_| CryptoError::Overflow)?;
        }
        Ok(())
    }

    #[test]
    fn versioned_ticket_round_trips_and_random_nonces_change_ciphertext() -> TestResult {
        let key = TlsTicketKey::generate()?;
        let first = key.seal(b"bounded rustls session")?;
        let second = key.seal(b"bounded rustls session")?;
        assert_ne!(first, second);
        assert_eq!(tls_ticket_key_id(&first)?, key.key_id());
        assert_eq!(
            key.open(&first)?.into_rustls_plaintext(),
            b"bounded rustls session"
        );
        assert_eq!(
            key.open(&second)?.into_rustls_plaintext(),
            b"bounded rustls session"
        );
        Ok(())
    }

    #[test]
    fn exact_ticket_bound_is_enforced_before_network_allocation() -> TestResult {
        let key = fixed_key(3, 7);
        let plaintext = vec![0x5a; MAX_TLS_TICKET_PLAINTEXT_BYTES];
        let encoded = key.seal_with(&plaintext, deterministic_nonce)?;
        assert_eq!(encoded.len(), MAX_TLS_TICKET_BYTES);
        assert_eq!(key.open(&encoded)?.into_rustls_plaintext(), plaintext);
        assert_eq!(
            key.seal(&vec![0_u8; MAX_TLS_TICKET_PLAINTEXT_BYTES + 1])
                .err(),
            Some(CryptoError::LimitExceeded)
        );
        Ok(())
    }

    #[test]
    fn malformed_and_tampered_attacker_tickets_fail_closed() -> TestResult {
        let key = fixed_key(4, 8);
        let valid = key.seal_with(b"session", deterministic_nonce)?;
        for length in 0..MIN_TLS_TICKET_BYTES {
            assert!(key.open(&vec![0_u8; length]).is_err());
        }
        assert!(key.open(&vec![0_u8; MAX_TLS_TICKET_BYTES + 1]).is_err());
        for index in 0..valid.len() {
            let mut changed = valid.clone();
            let byte = changed.get_mut(index).ok_or(CryptoError::InvalidEncoding)?;
            *byte ^= 1;
            assert!(key.open(&changed).is_err());
        }
        let mut maximum_attacker_input = vec![0_u8; MAX_TLS_TICKET_BYTES];
        let header = encode_header(key.key_id(), [0_u8; TLS_TICKET_NONCE_BYTES])?;
        maximum_attacker_input
            .get_mut(..TLS_TICKET_HEADER_BYTES)
            .ok_or(CryptoError::InvalidEncoding)?
            .copy_from_slice(&header);
        assert!(key.open(&maximum_attacker_input).is_err());
        Ok(())
    }

    #[test]
    fn wrong_generation_and_entropy_failures_return_closed_errors() -> TestResult {
        let first = fixed_key(5, 9);
        let second = fixed_key(6, 10);
        let encoded = first.seal_with(b"session", deterministic_nonce)?;
        assert_eq!(
            second.open(&encoded).err(),
            Some(CryptoError::AuthenticationFailed)
        );

        let generated = TlsTicketKey::generate_with(|output| {
            output.fill(0xa5);
            Err(CryptoError::EntropyUnavailable)
        });
        assert_eq!(generated.err(), Some(CryptoError::EntropyUnavailable));
        assert_eq!(
            first
                .seal_with(b"session", |output| {
                    output.fill(0xa5);
                    Err(CryptoError::EntropyUnavailable)
                })
                .err(),
            Some(CryptoError::EntropyUnavailable)
        );
        Ok(())
    }
}
