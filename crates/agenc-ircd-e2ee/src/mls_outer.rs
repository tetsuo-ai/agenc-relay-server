//! Bounded RFC 9420 outer framing for the objects a server handles.
//!
//! The daemon reads the `MLSMessage` wire format, the public `PrivateMessage`
//! header (group ID, epoch, content type, authenticated data), the `Welcome`
//! header (suite and recipient references), and the complete public
//! `KeyPackage`. Ciphertext, encrypted sender data, encrypted group info,
//! proposals, and every secret are never interpreted. Endpoint-only: content
//! decryption, tree and path validation, confirmation tags, exporters.

use agenc_ircd_crypto::SignatureDomain;
use sha2::{Digest as _, Sha256};

use crate::error::E2eeError;
use crate::limits::{MLS_VERSION_MLS10, SIGNATURE_SCHEME_ED25519, suite_is_enabled};
use crate::signature::RoleKey;
use crate::tls::DecodeBudget;

/// RFC 9420 wire formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsWireFormat {
    /// `mls_public_message`, never accepted by this profile.
    PublicMessage,
    /// `mls_private_message`.
    PrivateMessage,
    /// `mls_welcome`.
    Welcome,
    /// `mls_group_info`, never accepted by this profile.
    GroupInfo,
    /// `mls_key_package`.
    KeyPackage,
}

impl MlsWireFormat {
    const fn from_value(value: u16) -> Result<Self, E2eeError> {
        match value {
            1 => Ok(Self::PublicMessage),
            2 => Ok(Self::PrivateMessage),
            3 => Ok(Self::Welcome),
            4 => Ok(Self::GroupInfo),
            5 => Ok(Self::KeyPackage),
            _ => Err(E2eeError::UnknownDiscriminant),
        }
    }
}

/// RFC 9420 content types.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlsContentType {
    /// `application`.
    Application,
    /// `proposal`, never accepted by this profile.
    Proposal,
    /// `commit`.
    Commit,
}

impl MlsContentType {
    const fn from_value(value: u8) -> Result<Self, E2eeError> {
        match value {
            1 => Ok(Self::Application),
            2 => Ok(Self::Proposal),
            3 => Ok(Self::Commit),
            _ => Err(E2eeError::UnknownDiscriminant),
        }
    }
}

/// `LeafNodeSource` values.
const LEAF_NODE_SOURCE_KEY_PACKAGE: u8 = 1;
/// `CredentialType::basic`.
const CREDENTIAL_TYPE_BASIC: u16 = 1;
/// The `last_resort` KeyPackage extension type from the MLS extensions
/// registry; profile version 1 requires it to be absent.
pub const LAST_RESORT_EXTENSION_TYPE: u16 = 0x000a;

/// The public `PrivateMessage` header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PrivateMessageHeader {
    /// The MLS group identifier.
    pub group_id: Vec<u8>,
    /// The epoch the message was created in.
    pub epoch: u64,
    /// The content type.
    pub content_type: MlsContentType,
    /// The exact `authenticated_data` bytes.
    pub authenticated_data: Vec<u8>,
    /// Length of the opaque encrypted sender data.
    pub encrypted_sender_data_len: usize,
    /// Length of the opaque ciphertext.
    pub ciphertext_len: usize,
}

/// The public `Welcome` header.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WelcomeHeader {
    /// The suite of the group being joined.
    pub cipher_suite: u16,
    /// The `KeyPackageRef` of every addressed member, in order.
    pub new_member_refs: Vec<Vec<u8>>,
    /// Length of the opaque encrypted group info.
    pub encrypted_group_info_len: usize,
}

/// One RFC 9420 extension.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MlsExtension {
    /// The extension type.
    pub extension_type: u16,
    /// The extension data.
    pub extension_data: Vec<u8>,
}

/// The RFC 9420 `Lifetime` of a KeyPackage leaf.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Lifetime {
    /// Earliest valid second.
    pub not_before: u64,
    /// Latest valid second.
    pub not_after: u64,
}

/// The public fields of a KeyPackage leaf node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicLeafNode {
    /// HPKE encryption key encoding.
    pub encryption_key: Vec<u8>,
    /// Signature public key encoding.
    pub signature_key: Vec<u8>,
    /// The `BasicCredential.identity` bytes.
    pub credential_identity: Vec<u8>,
    /// The complete canonical `BasicCredential` encoding.
    pub encoded_credential: Vec<u8>,
    /// The complete canonical `Capabilities` encoding.
    pub encoded_capabilities: Vec<u8>,
    /// The leaf lifetime.
    pub lifetime: Lifetime,
    /// Leaf extensions.
    pub extensions: Vec<MlsExtension>,
    /// The leaf signature.
    pub signature: Vec<u8>,
    /// The `LeafNodeTBS` encoding for a `key_package` source.
    pub tbs: Vec<u8>,
}

/// The complete public KeyPackage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicKeyPackage {
    /// Protocol version.
    pub version: u16,
    /// Cipher suite.
    pub cipher_suite: u16,
    /// HPKE init key encoding.
    pub init_key: Vec<u8>,
    /// The leaf node.
    pub leaf_node: PublicLeafNode,
    /// KeyPackage extensions.
    pub extensions: Vec<MlsExtension>,
    /// The KeyPackage signature.
    pub signature: Vec<u8>,
    /// The `KeyPackageTBS` encoding.
    pub tbs: Vec<u8>,
    /// The RFC 9420 `KeyPackageRef` over the complete KeyPackage.
    pub key_package_ref: [u8; 32],
}

impl PublicKeyPackage {
    /// Returns whether a `last_resort` extension is present anywhere.
    #[must_use]
    pub fn has_last_resort_extension(&self) -> bool {
        self.extensions
            .iter()
            .chain(self.leaf_node.extensions.iter())
            .any(|extension| extension.extension_type == LAST_RESORT_EXTENSION_TYPE)
    }
}

/// One parsed outer message.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MlsOuterMessage {
    /// A `PrivateMessage` with its public header.
    Private(PrivateMessageHeader),
    /// A `Welcome` with its public header.
    Welcome(WelcomeHeader),
    /// A public `KeyPackage`.
    KeyPackage(Box<PublicKeyPackage>),
}

/// Parses one complete `MLSMessage`, refusing public messages, group info,
/// unknown formats, and trailing bytes.
pub fn parse_mls_message(
    bytes: &[u8],
    budget: &mut DecodeBudget,
) -> Result<MlsOuterMessage, E2eeError> {
    let mut reader = MlsReader::new(bytes, budget);
    if reader.u16()? != MLS_VERSION_MLS10 {
        return Err(E2eeError::ProfileMismatch);
    }
    let message = match MlsWireFormat::from_value(reader.u16()?)? {
        MlsWireFormat::PrivateMessage => {
            MlsOuterMessage::Private(parse_private_message(&mut reader)?)
        }
        MlsWireFormat::Welcome => MlsOuterMessage::Welcome(parse_welcome(&mut reader)?),
        MlsWireFormat::KeyPackage => {
            let start = reader.position;
            let package = parse_key_package(&mut reader)?;
            let complete = reader.slice(start, reader.position)?;
            MlsOuterMessage::KeyPackage(Box::new(with_reference(package, complete)?))
        }
        MlsWireFormat::PublicMessage | MlsWireFormat::GroupInfo => {
            return Err(E2eeError::WrongKind);
        }
    };
    reader.finish()?;
    Ok(message)
}

fn parse_private_message(reader: &mut MlsReader<'_>) -> Result<PrivateMessageHeader, E2eeError> {
    let group_id = reader.opaque_v()?.to_vec();
    let epoch = reader.u64()?;
    let content_type = MlsContentType::from_value(reader.u8()?)?;
    let authenticated_data = reader.opaque_v()?.to_vec();
    let encrypted_sender_data_len = reader.opaque_v()?.len();
    let ciphertext_len = reader.opaque_v()?.len();
    Ok(PrivateMessageHeader {
        group_id,
        epoch,
        content_type,
        authenticated_data,
        encrypted_sender_data_len,
        ciphertext_len,
    })
}

fn parse_welcome(reader: &mut MlsReader<'_>) -> Result<WelcomeHeader, E2eeError> {
    let cipher_suite = reader.u16()?;
    if !suite_is_enabled(cipher_suite) {
        return Err(E2eeError::ProfileMismatch);
    }
    let secrets = reader.opaque_v()?;
    let mut inner = MlsReader::new(secrets, reader.budget);
    let mut new_member_refs = Vec::new();
    while inner.remaining() > 0 {
        inner.budget.claim_item()?;
        let reference = inner.opaque_v()?.to_vec();
        // HPKECiphertext { kem_output<V>, ciphertext<V> } stays opaque.
        let _kem_output = inner.opaque_v()?;
        let _ciphertext = inner.opaque_v()?;
        new_member_refs
            .try_reserve(1)
            .map_err(|_| E2eeError::BudgetExceeded)?;
        new_member_refs.push(reference);
    }
    let encrypted_group_info_len = reader.opaque_v()?.len();
    Ok(WelcomeHeader {
        cipher_suite,
        new_member_refs,
        encrypted_group_info_len,
    })
}

fn parse_key_package(reader: &mut MlsReader<'_>) -> Result<PublicKeyPackage, E2eeError> {
    let tbs_start = reader.position;
    let version = reader.u16()?;
    if version != MLS_VERSION_MLS10 {
        return Err(E2eeError::ProfileMismatch);
    }
    let cipher_suite = reader.u16()?;
    if !suite_is_enabled(cipher_suite) {
        return Err(E2eeError::ProfileMismatch);
    }
    let init_key = reader.opaque_v()?.to_vec();
    let leaf_node = parse_leaf_node(reader)?;
    let extensions = parse_extensions(reader)?;
    let tbs = reader.slice(tbs_start, reader.position)?.to_vec();
    let signature = reader.opaque_v()?.to_vec();
    Ok(PublicKeyPackage {
        version,
        cipher_suite,
        init_key,
        leaf_node,
        extensions,
        signature,
        tbs,
        key_package_ref: [0; 32],
    })
}

fn parse_leaf_node(reader: &mut MlsReader<'_>) -> Result<PublicLeafNode, E2eeError> {
    let tbs_start = reader.position;
    let encryption_key = reader.opaque_v()?.to_vec();
    let signature_key = reader.opaque_v()?.to_vec();
    let credential_start = reader.position;
    if reader.u16()? != CREDENTIAL_TYPE_BASIC {
        return Err(E2eeError::ProfileMismatch);
    }
    let credential_identity = reader.opaque_v()?.to_vec();
    let encoded_credential = reader.slice(credential_start, reader.position)?.to_vec();
    let capabilities_start = reader.position;
    for _ in 0..5 {
        let _ = reader.opaque_v()?;
    }
    let encoded_capabilities = reader.slice(capabilities_start, reader.position)?.to_vec();
    if reader.u8()? != LEAF_NODE_SOURCE_KEY_PACKAGE {
        return Err(E2eeError::ProfileMismatch);
    }
    let lifetime = Lifetime {
        not_before: reader.u64()?,
        not_after: reader.u64()?,
    };
    let extensions = parse_extensions(reader)?;
    let tbs = reader.slice(tbs_start, reader.position)?.to_vec();
    let signature = reader.opaque_v()?.to_vec();
    Ok(PublicLeafNode {
        encryption_key,
        signature_key,
        credential_identity,
        encoded_credential,
        encoded_capabilities,
        lifetime,
        extensions,
        signature,
        tbs,
    })
}

fn parse_extensions(reader: &mut MlsReader<'_>) -> Result<Vec<MlsExtension>, E2eeError> {
    let body = reader.opaque_v()?;
    let mut inner = MlsReader::new(body, reader.budget);
    let mut extensions = Vec::new();
    while inner.remaining() > 0 {
        inner.budget.claim_item()?;
        let extension_type = inner.u16()?;
        let extension_data = inner.opaque_v()?.to_vec();
        extensions
            .try_reserve(1)
            .map_err(|_| E2eeError::BudgetExceeded)?;
        extensions.push(MlsExtension {
            extension_type,
            extension_data,
        });
    }
    Ok(extensions)
}

fn with_reference(
    mut package: PublicKeyPackage,
    complete: &[u8],
) -> Result<PublicKeyPackage, E2eeError> {
    package.key_package_ref = ref_hash("MLS 1.0 KeyPackage Reference", complete)?;
    Ok(package)
}

/// RFC 9420 `RefHash(label, value)` with SHA-256, the hash of both enabled
/// suites.
pub fn ref_hash(label: &str, value: &[u8]) -> Result<[u8; 32], E2eeError> {
    let mut input = Vec::new();
    mls_varint_encode(&mut input, label.len())?;
    input.extend_from_slice(label.as_bytes());
    mls_varint_encode(&mut input, value.len())?;
    input
        .try_reserve(value.len())
        .map_err(|_| E2eeError::BudgetExceeded)?;
    input.extend_from_slice(value);
    Ok(Sha256::digest(&input).into())
}

/// Verifies the LeafNode and KeyPackage signatures with the leaf signature
/// key carried in the leaf, under the RFC 9420 labels.
pub fn verify_key_package_signatures(package: &PublicKeyPackage) -> Result<(), E2eeError> {
    let key = RoleKey::leaf(&package.leaf_node.signature_key)?;
    key.verify_suite_encoded(
        SignatureDomain::MlsLeafNodeTbs,
        &package.leaf_node.tbs,
        &package.leaf_node.signature,
    )?;
    key.verify_suite_encoded(
        SignatureDomain::MlsKeyPackageTbs,
        &package.tbs,
        &package.signature,
    )
}

/// Returns the leaf signature scheme this profile expects for a suite.
#[must_use]
pub const fn leaf_signature_scheme(cipher_suite: u16) -> Option<u16> {
    if suite_is_enabled(cipher_suite) {
        Some(SIGNATURE_SCHEME_ED25519)
    } else {
        None
    }
}

/// Appends the minimal RFC 9420 Section 2.1.3 variable-length integer.
pub fn mls_varint_encode(output: &mut Vec<u8>, value: usize) -> Result<(), E2eeError> {
    let value = u32::try_from(value).map_err(|_| E2eeError::LengthOutOfRange)?;
    output
        .try_reserve(4)
        .map_err(|_| E2eeError::BudgetExceeded)?;
    if value < 0x40 {
        output.push(u8::try_from(value).map_err(|_| E2eeError::Overflow)?);
    } else if value < 0x4000 {
        let bytes = (value | 0x4000).to_be_bytes();
        output.extend_from_slice(bytes.get(2..).ok_or(E2eeError::Overflow)?);
    } else if value < 0x4000_0000 {
        output.extend_from_slice(&(value | 0x8000_0000).to_be_bytes());
    } else {
        return Err(E2eeError::LengthOutOfRange);
    }
    Ok(())
}

/// A cursor over RFC 9420 encodings, whose vectors use variable-length
/// integer prefixes rather than the companion's fixed widths.
pub struct MlsReader<'a> {
    bytes: &'a [u8],
    position: usize,
    budget: &'a mut DecodeBudget,
}

impl<'a> MlsReader<'a> {
    /// Starts reading at the first byte.
    pub fn new(bytes: &'a [u8], budget: &'a mut DecodeBudget) -> Self {
        Self {
            bytes,
            position: 0,
            budget,
        }
    }

    /// Returns the bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        self.bytes.len().saturating_sub(self.position)
    }

    /// Fails unless every byte was consumed.
    pub fn finish(&self) -> Result<(), E2eeError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(E2eeError::TrailingBytes)
        }
    }

    fn slice(&self, start: usize, end: usize) -> Result<&'a [u8], E2eeError> {
        self.bytes.get(start..end).ok_or(E2eeError::Truncated)
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], E2eeError> {
        let end = self
            .position
            .checked_add(length)
            .ok_or(E2eeError::Overflow)?;
        let slice = self
            .bytes
            .get(self.position..end)
            .ok_or(E2eeError::Truncated)?;
        self.position = end;
        Ok(slice)
    }

    /// Reads one byte.
    pub fn u8(&mut self) -> Result<u8, E2eeError> {
        self.take(1)?.first().copied().ok_or(E2eeError::Truncated)
    }

    /// Reads one big-endian 16-bit value.
    pub fn u16(&mut self) -> Result<u16, E2eeError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| E2eeError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Reads one big-endian 64-bit value.
    pub fn u64(&mut self) -> Result<u64, E2eeError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| E2eeError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Reads one minimal variable-length integer.
    pub fn varint(&mut self) -> Result<usize, E2eeError> {
        let first = self.u8()?;
        let (length, value) = match first >> 6 {
            0 => (1_usize, usize::from(first & 0x3f)),
            1 => (
                2,
                (usize::from(first & 0x3f) << 8) | usize::from(self.u8()?),
            ),
            2 => {
                let rest = self.take(3)?;
                let value = rest.iter().fold(usize::from(first & 0x3f), |total, byte| {
                    (total << 8) | usize::from(*byte)
                });
                (4, value)
            }
            _ => return Err(E2eeError::NonCanonical),
        };
        let minimal = match length {
            1 => true,
            2 => value >= 0x40,
            _ => value >= 0x4000,
        };
        if minimal {
            Ok(value)
        } else {
            Err(E2eeError::NonCanonical)
        }
    }

    /// Reads one `opaque<V>` field.
    pub fn opaque_v(&mut self) -> Result<&'a [u8], E2eeError> {
        let length = self.varint()?;
        self.budget.claim_item()?;
        self.budget.claim_copy(length)?;
        self.take(length)
    }
}

impl DecodeBudget {
    fn claim_item(&mut self) -> Result<(), E2eeError> {
        self.claim_value_public()
    }

    fn claim_copy(&mut self, amount: usize) -> Result<(), E2eeError> {
        self.claim_bytes_public(amount)
    }
}

#[cfg(test)]
#[path = "tests/mls_outer.rs"]
mod tests;
