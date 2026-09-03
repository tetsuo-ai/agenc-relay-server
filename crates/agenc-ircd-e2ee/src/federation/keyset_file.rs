//! The sequencer credentials file (`e2ee.sequencer_credentials_file`).
//!
//! Interpretation recorded for the completion notes: the architecture names
//! the file as "canonical public active/overlap credentials" without a byte
//! layout, so this profile fixes one: the TLS encoding of
//! `struct { uint16 file_version; uint64 key_set_generation;
//! IrcSequencerCredential credentials<1..2 items> }` with a `uint8` item
//! count, `file_version` one. The set digest is recomputed from the
//! verified credentials, never read from the file.

use crate::error::E2eeError;
use crate::identity::ValidationTime;
use crate::objects::conversation::IrcSequencerCredential;
use crate::sequencer::{SequencerKeySet, VerifiedSequencerCredential};
use crate::tls::{DecodeBudget, Reader, TlsDecode, TlsEncode, Writer};

/// `file_version`.
pub const FILE_VERSION: u16 = 1;
/// The most credentials a file holds: the current one and its successor.
pub const MAX_FILE_CREDENTIALS: usize = 2;
/// The largest file the daemon reads.
pub const MAX_FILE_BYTES: usize = 8_192;

/// The parsed file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SequencerCredentialsFile {
    /// Key set generation.
    pub key_set_generation: u64,
    /// Credentials, current first.
    pub credentials: Vec<IrcSequencerCredential>,
}

impl SequencerCredentialsFile {
    /// Encodes the file.
    pub fn encode(&self) -> Result<Vec<u8>, E2eeError> {
        if self.credentials.is_empty() || self.credentials.len() > MAX_FILE_CREDENTIALS {
            return Err(E2eeError::InvalidValue);
        }
        let mut writer = Writer::new();
        writer.u16(FILE_VERSION)?;
        writer.u64(self.key_set_generation)?;
        writer.u8(u8::try_from(self.credentials.len()).map_err(|_| E2eeError::Overflow)?)?;
        for credential in &self.credentials {
            credential.encode_into(&mut writer)?;
        }
        Ok(writer.into_bytes())
    }

    /// Decodes the file exactly.
    pub fn decode(bytes: &[u8]) -> Result<Self, E2eeError> {
        if bytes.len() > MAX_FILE_BYTES {
            return Err(E2eeError::LimitExceeded);
        }
        let mut budget = DecodeBudget::new(MAX_FILE_BYTES, 4_096);
        let mut reader = Reader::new(bytes, &mut budget);
        if reader.u16()? != FILE_VERSION {
            return Err(E2eeError::ProfileMismatch);
        }
        let key_set_generation = reader.u64()?;
        let count = usize::from(reader.u8()?);
        if count == 0 || count > MAX_FILE_CREDENTIALS {
            return Err(E2eeError::InvalidValue);
        }
        let mut credentials = Vec::with_capacity(count);
        for _ in 0..count {
            credentials.push(IrcSequencerCredential::decode_from(&mut reader)?);
        }
        reader.finish()?;
        Ok(Self {
            key_set_generation,
            credentials,
        })
    }

    /// Verifies the file as a key set for `network_id` at `now`, requiring
    /// the current credential to cover `now`; `head` is the accepted
    /// predecessor when the file opens above generation zero.
    pub fn verify(
        &self,
        network_id: &[u8; 32],
        now: ValidationTime,
        head: Option<&VerifiedSequencerCredential>,
    ) -> Result<SequencerKeySet, E2eeError> {
        let set =
            SequencerKeySet::verify(network_id, &self.credentials, self.key_set_generation, head)?;
        let covered = set
            .current()
            .is_some_and(|credential| credential.covers(now));
        if !covered {
            return Err(E2eeError::InvalidValue);
        }
        Ok(set)
    }
}

#[cfg(test)]
#[path = "../tests/keyset_file.rs"]
mod tests;
