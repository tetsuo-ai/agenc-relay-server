//! `AdminCommandTBS` (spec 4413-4424): the signed content of every
//! post-authentication administrative command.

use agenc_relay_crypto::{
    CryptoError, Ed25519PublicKey, Ed25519SecretKey, Ed25519Signature, SignatureDomain,
    sign_canonical, verify_canonical,
};
use agenc_relay_types::{NetworkId, ServerId};

use crate::codec::{Reader, Writer};
use crate::{AdminError, AdminSessionId, MAX_ADMIN_COMMAND_BYTES};

/// `profile_version` (spec 4414).
const TBS_VERSION: u16 = 1;
/// Fixed bytes: version, network, server, session, counter, one-byte hash
/// length, two-byte command length.
const TBS_FIXED_BYTES: usize = 2 + 32 + 16 + 16 + 8 + 1 + 2;
/// Largest encoding: fixed bytes plus a 32-byte hash and a 4,096-byte command.
pub(crate) const MAX_TBS_BYTES: usize = TBS_FIXED_BYTES + 32 + MAX_ADMIN_COMMAND_BYTES;

/// The to-be-signed command structure.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminCommandTbs {
    network_id: NetworkId,
    server_id: ServerId,
    admin_session_id: AdminSessionId,
    command_counter: u64,
    confirmation_token_hash: Option<[u8; 32]>,
    canonical_command: Vec<u8>,
}

impl AdminCommandTbs {
    /// Builds the structure for one canonical command (1..4096 bytes).
    pub fn new(
        network_id: NetworkId,
        server_id: ServerId,
        admin_session_id: AdminSessionId,
        command_counter: u64,
        confirmation_token_hash: Option<[u8; 32]>,
        canonical_command: &[u8],
    ) -> Result<Self, AdminError> {
        if canonical_command.is_empty() || canonical_command.len() > MAX_ADMIN_COMMAND_BYTES {
            return Err(AdminError::Framing);
        }
        Ok(Self {
            network_id,
            server_id,
            admin_session_id,
            command_counter,
            confirmation_token_hash,
            canonical_command: canonical_command.to_vec(),
        })
    }

    /// Returns the command counter.
    #[must_use]
    pub const fn command_counter(&self) -> u64 {
        self.command_counter
    }

    /// Returns the network identity bound into the operator signature.
    #[must_use]
    pub const fn network_id(&self) -> NetworkId {
        self.network_id
    }

    /// Returns the server identity bound into the operator signature.
    #[must_use]
    pub const fn server_id(&self) -> ServerId {
        self.server_id
    }

    /// Returns the exact canonical command bytes.
    #[must_use]
    pub fn canonical_command(&self) -> &[u8] {
        &self.canonical_command
    }

    /// Returns the confirmation token hash when the command carried one.
    #[must_use]
    pub const fn confirmation_token_hash(&self) -> Option<[u8; 32]> {
        self.confirmation_token_hash
    }

    /// Returns the session identity the command was signed under.
    #[must_use]
    pub const fn admin_session_id(&self) -> AdminSessionId {
        self.admin_session_id
    }

    /// TLS-encodes the structure in field order (spec 4413-4422).
    pub fn encode(&self) -> Result<Vec<u8>, AdminError> {
        let mut writer = Writer::with_ceiling(MAX_TBS_BYTES);
        writer.put_u16(TBS_VERSION)?;
        writer.put_fixed(self.network_id.as_bytes())?;
        writer.put_fixed(self.server_id.as_bytes())?;
        writer.put_fixed(self.admin_session_id.as_bytes())?;
        writer.put_u64(self.command_counter)?;
        match self.confirmation_token_hash {
            Some(hash) => writer.put_vector_u8(&hash)?,
            None => writer.put_vector_u8(&[])?,
        }
        writer.put_vector_u16(&self.canonical_command)?;
        Ok(writer.finish())
    }

    /// Decodes one structure from a reader positioned at its first byte.
    pub(crate) fn decode_from(reader: &mut Reader<'_>) -> Result<Self, AdminError> {
        if reader.u16()? != TBS_VERSION {
            return Err(AdminError::Audit);
        }
        let network_id = NetworkId::from_bytes(reader.fixed::<32>()?);
        let server_id = ServerId::from_bytes(reader.fixed::<16>()?);
        let admin_session_id = AdminSessionId::from_bytes(reader.fixed::<16>()?);
        let command_counter = reader.u64()?;
        let hash_bytes = reader.vector_u8(32)?;
        let confirmation_token_hash = match hash_bytes.len() {
            0 => None,
            32 => {
                let mut hash = [0_u8; 32];
                hash.copy_from_slice(hash_bytes);
                Some(hash)
            }
            _ => return Err(AdminError::Audit),
        };
        let command = reader.vector_u16(MAX_ADMIN_COMMAND_BYTES)?;
        Self::new(
            network_id,
            server_id,
            admin_session_id,
            command_counter,
            confirmation_token_hash,
            command,
        )
        .map_err(|_| AdminError::Audit)
    }

    /// Decodes exactly one complete structure with no trailing bytes.
    pub fn decode_exact(bytes: &[u8]) -> Result<Self, AdminError> {
        let mut reader = Reader::new(bytes);
        let tbs = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(tbs)
    }

    /// Signs the structure (client tooling and tests).
    pub fn sign(&self, key: &Ed25519SecretKey) -> Result<Ed25519Signature, AdminError> {
        let encoded = self.encode()?;
        sign_canonical(key, SignatureDomain::AdminCommand, &encoded).map_err(map_crypto)
    }

    /// Strictly verifies the operator signature over this structure.
    pub fn verify(
        &self,
        key: Ed25519PublicKey,
        signature: Ed25519Signature,
    ) -> Result<(), AdminError> {
        let encoded = self.encode()?;
        verify_canonical(key, SignatureDomain::AdminCommand, &encoded, signature)
            .map_err(map_crypto)
    }
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
    use agenc_relay_crypto::Ed25519SecretKey;
    use agenc_relay_types::{NetworkId, ServerId};

    use super::{AdminCommandTbs, MAX_TBS_BYTES};
    use crate::{AdminError, AdminSessionId};

    fn sample(hash: Option<[u8; 32]>, command: &[u8]) -> Result<AdminCommandTbs, AdminError> {
        AdminCommandTbs::new(
            NetworkId::from_bytes([1; 32]),
            ServerId::from_bytes([2; 16]),
            AdminSessionId::from_bytes([3; 16]),
            5,
            hash,
            command,
        )
    }

    #[test]
    fn encoding_matches_the_spec_layout_byte_for_byte() -> Result<(), AdminError> {
        let tbs = sample(None, b"STATS RUNTIME")?;
        let encoded = tbs.encode()?;
        let mut expected = vec![0, 1];
        expected.extend_from_slice(&[1; 32]);
        expected.extend_from_slice(&[2; 16]);
        expected.extend_from_slice(&[3; 16]);
        expected.extend_from_slice(&5_u64.to_be_bytes());
        expected.push(0);
        expected.extend_from_slice(&[0, 13]);
        expected.extend_from_slice(b"STATS RUNTIME");
        assert_eq!(encoded, expected);
        assert_eq!(AdminCommandTbs::decode_exact(&encoded)?, tbs);

        let with_hash = sample(Some([7; 32]), b"DIE :now")?;
        let encoded = with_hash.encode()?;
        assert_eq!(encoded.get(74), Some(&32));
        assert_eq!(AdminCommandTbs::decode_exact(&encoded)?, with_hash);
        assert_eq!(with_hash.confirmation_token_hash(), Some([7; 32]));
        assert_eq!(with_hash.command_counter(), 5);
        assert_eq!(with_hash.canonical_command(), b"DIE :now");

        let longest = vec![b'A'; 4_096];
        assert_eq!(
            sample(Some([0; 32]), &longest)?.encode()?.len(),
            MAX_TBS_BYTES
        );
        assert_eq!(sample(None, &[]), Err(AdminError::Framing));
        assert_eq!(sample(None, &vec![b'A'; 4_097]), Err(AdminError::Framing));
        Ok(())
    }

    #[test]
    fn decoding_rejects_every_malformed_shape() -> Result<(), AdminError> {
        let encoded = sample(None, b"QUIT")?.encode()?;
        let mut wrong_version = encoded.clone();
        if let Some(byte) = wrong_version.get_mut(1) {
            *byte = 2;
        }
        assert_eq!(
            AdminCommandTbs::decode_exact(&wrong_version),
            Err(AdminError::Audit)
        );
        let mut trailing = encoded.clone();
        trailing.push(0);
        assert_eq!(
            AdminCommandTbs::decode_exact(&trailing),
            Err(AdminError::Audit)
        );
        let truncated = encoded.get(..encoded.len() - 1).unwrap_or(&[]);
        assert_eq!(
            AdminCommandTbs::decode_exact(truncated),
            Err(AdminError::Audit)
        );
        let mut bad_hash_length = encoded.clone();
        if let Some(byte) = bad_hash_length.get_mut(74) {
            *byte = 1;
        }
        bad_hash_length.insert(75, 0xaa);
        assert_eq!(
            AdminCommandTbs::decode_exact(&bad_hash_length),
            Err(AdminError::Audit)
        );
        let mut empty_command = encoded.clone();
        empty_command.truncate(75);
        empty_command.extend_from_slice(&[0, 0]);
        assert_eq!(
            AdminCommandTbs::decode_exact(&empty_command),
            Err(AdminError::Audit)
        );
        Ok(())
    }

    #[test]
    fn signatures_verify_only_for_the_exact_structure() -> Result<(), AdminError> {
        let key = Ed25519SecretKey::from_bytes([4; 32]);
        let tbs = sample(None, b"REHASH :reason")?;
        let signature = tbs.sign(&key)?;
        tbs.verify(key.public_key(), signature)?;
        let changed = sample(None, b"REHASH :reasoN")?;
        assert_eq!(
            changed.verify(key.public_key(), signature),
            Err(AdminError::Signature)
        );
        assert_eq!(tbs.admin_session_id(), AdminSessionId::from_bytes([3; 16]));
        Ok(())
    }
}
