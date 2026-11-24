//! Ephemeral authenticated encryption for separately charged companion spool extents.

use chacha20poly1305::aead::{Aead as _, KeyInit as _, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::secret::SecretBytes;
use crate::{CryptoError, OsEntropy};

const DOMAIN: &[u8; 24] = b"agenc-chat spool part v1";
const NONCE_BYTES: usize = 24;
/// Encoded bytes added to a spool fragment by its nonce and authentication tag.
pub const SPOOL_PART_OVERHEAD: usize = NONCE_BYTES + 16;
/// A spool record carries exactly one companion fragment.
const MAX_PART: usize = 2_940;

/// A fresh key for one open object. The file carries no recoverable key.
/// Its object identifier, declared total and byte offset authenticate each part.
pub struct SpoolCipher {
    key: SecretBytes<32>,
    object_id: [u8; 32],
    total: u32,
}

impl SpoolCipher {
    /// Creates an independent, nonpersisted key.
    pub fn generate(object_id: [u8; 32], total: u32) -> Result<Self, CryptoError> {
        let mut key = SecretBytes::new([0; 32]);
        OsEntropy::fill(key.as_mut_bytes())?;
        Ok(Self {
            key,
            object_id,
            total,
        })
    }

    /// Seals one bounded part with a fresh XChaCha20-Poly1305 nonce.
    pub fn seal(&self, offset: u32, bytes: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let aad = self.aad(offset, bytes.len())?;
        let mut nonce = [0; NONCE_BYTES];
        OsEntropy::fill(&mut nonce)?;
        let cipher = XChaCha20Poly1305::new(self.key.as_bytes().into());
        let ciphertext = cipher
            .encrypt(
                &XNonce::from(nonce),
                Payload {
                    msg: bytes,
                    aad: &aad,
                },
            )
            .map_err(|_| CryptoError::AuthenticationFailed)?;
        let mut record = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        record.extend_from_slice(&nonce);
        record.extend_from_slice(&ciphertext);
        Ok(record)
    }

    /// Opens the part only at its original byte offset in the original object.
    pub fn open(&self, offset: u32, record: &[u8]) -> Result<Zeroizing<Vec<u8>>, CryptoError> {
        let length = record
            .len()
            .checked_sub(SPOOL_PART_OVERHEAD)
            .ok_or(CryptoError::InvalidEncoding)?;
        let aad = self.aad(offset, length)?;
        let (nonce, ciphertext) = record
            .split_at_checked(NONCE_BYTES)
            .ok_or(CryptoError::InvalidEncoding)?;
        let nonce = XNonce::try_from(nonce).map_err(|_| CryptoError::InvalidEncoding)?;
        let cipher = XChaCha20Poly1305::new(self.key.as_bytes().into());
        cipher
            .decrypt(
                &nonce,
                Payload {
                    msg: ciphertext,
                    aad: &aad,
                },
            )
            .map(Zeroizing::new)
            .map_err(|_| CryptoError::AuthenticationFailed)
    }

    fn aad(&self, offset: u32, length: usize) -> Result<[u8; 64], CryptoError> {
        if !(1..=MAX_PART).contains(&length)
            || offset
                .checked_add(u32::try_from(length).map_err(|_| CryptoError::Overflow)?)
                .is_none_or(|end| end > self.total)
        {
            return Err(CryptoError::LimitExceeded);
        }
        let mut aad = [0; 64];
        let (label, rest) = aad.split_at_mut(DOMAIN.len());
        label.copy_from_slice(DOMAIN);
        let (object, suffix) = rest.split_at_mut(self.object_id.len());
        object.copy_from_slice(&self.object_id);
        let (total, position) = suffix.split_at_mut(4);
        total.copy_from_slice(&self.total.to_be_bytes());
        position.copy_from_slice(&offset.to_be_bytes());
        Ok(aad)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extents_authenticate_their_position_key_and_complete_bytes() -> Result<(), CryptoError> {
        let key = SpoolCipher::generate([9; 32], 6000)?;
        let other = SpoolCipher::generate([9; 32], 6000)?;
        let mut sealed = key.seal(2940, b"encrypted control fragment")?;
        assert_eq!(
            key.open(2940, &sealed)?.as_slice(),
            b"encrypted control fragment"
        );
        assert_ne!(sealed, key.seal(2940, b"encrypted control fragment")?);
        assert!(key.open(0, &sealed).is_err());
        assert!(other.open(2940, &sealed).is_err());
        *sealed.last_mut().ok_or(CryptoError::InvalidEncoding)? ^= 1;
        assert!(key.open(2940, &sealed).is_err());
        assert!(key.seal(5999, b"xx").is_err());
        Ok(())
    }
}
