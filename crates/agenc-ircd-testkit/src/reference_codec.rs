//! Independent federation-vector parsing and primitive reference encoding.

use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

/// Maximum records accepted from one checked-in vector manifest.
pub const MAX_REFERENCE_VECTORS: usize = 4_096;
/// Maximum decoded bytes accepted across one vector manifest.
pub const MAX_REFERENCE_VECTOR_BYTES: usize = 64 * 1024 * 1024;

/// Failures from the independent reference codec and vector loader.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReferenceCodecError {
    /// A primitive does not fit its selected wire width.
    IntegerOutOfRange,
    /// A byte vector is outside its declared bounds.
    VectorLength,
    /// The caller's output ceiling would be exceeded.
    OutputLimit,
    /// A manifest line does not have the closed five-field shape.
    ManifestShape,
    /// A manifest identifier, name, hex value, or hash is malformed.
    ManifestValue,
    /// A vector's decoded SHA-256 does not match its manifest.
    HashMismatch,
    /// A checked size calculation overflowed.
    Overflow,
    /// A bounded allocation failed.
    AllocationFailed,
}

impl fmt::Display for ReferenceCodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::IntegerOutOfRange => "reference integer is outside its wire width",
            Self::VectorLength => "reference vector is outside its bounds",
            Self::OutputLimit => "reference output limit exceeded",
            Self::ManifestShape => "reference vector manifest shape is invalid",
            Self::ManifestValue => "reference vector manifest value is invalid",
            Self::HashMismatch => "reference vector hash mismatch",
            Self::Overflow => "reference codec calculation overflowed",
            Self::AllocationFailed => "reference codec allocation failed",
        };
        formatter.write_str(message)
    }
}

impl Error for ReferenceCodecError {}

/// A small encoder independent of production codec traits and helpers.
pub struct ReferenceEncoder {
    output: Vec<u8>,
    output_limit: usize,
}

impl ReferenceEncoder {
    /// Creates an empty encoder with an exact output ceiling.
    #[must_use]
    pub const fn new(output_limit: usize) -> Self {
        Self {
            output: Vec::new(),
            output_limit,
        }
    }

    fn admit(&mut self, additional: usize) -> Result<(), ReferenceCodecError> {
        let total = self
            .output
            .len()
            .checked_add(additional)
            .ok_or(ReferenceCodecError::Overflow)?;
        if total > self.output_limit {
            return Err(ReferenceCodecError::OutputLimit);
        }
        self.output
            .try_reserve_exact(additional)
            .map_err(|_| ReferenceCodecError::AllocationFailed)
    }

    /// Writes one network-order `u8`.
    pub fn write_u8(&mut self, value: u64) -> Result<(), ReferenceCodecError> {
        let value = u8::try_from(value).map_err(|_| ReferenceCodecError::IntegerOutOfRange)?;
        self.admit(1)?;
        self.output.push(value);
        Ok(())
    }

    /// Writes one network-order `u16`.
    pub fn write_u16(&mut self, value: u64) -> Result<(), ReferenceCodecError> {
        let value = u16::try_from(value).map_err(|_| ReferenceCodecError::IntegerOutOfRange)?;
        self.admit(2)?;
        self.output.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Writes one network-order `u24`.
    pub fn write_u24(&mut self, value: u64) -> Result<(), ReferenceCodecError> {
        if value > 0x00ff_ffff {
            return Err(ReferenceCodecError::IntegerOutOfRange);
        }
        self.admit(3)?;
        let bytes = u32::try_from(value)
            .map_err(|_| ReferenceCodecError::IntegerOutOfRange)?
            .to_be_bytes();
        let Some(encoded) = bytes.get(1..) else {
            return Err(ReferenceCodecError::Overflow);
        };
        self.output.extend_from_slice(encoded);
        Ok(())
    }

    /// Writes one network-order `u32`.
    pub fn write_u32(&mut self, value: u64) -> Result<(), ReferenceCodecError> {
        let value = u32::try_from(value).map_err(|_| ReferenceCodecError::IntegerOutOfRange)?;
        self.admit(4)?;
        self.output.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Writes one network-order `u64`.
    pub fn write_u64(&mut self, value: u64) -> Result<(), ReferenceCodecError> {
        self.admit(8)?;
        self.output.extend_from_slice(&value.to_be_bytes());
        Ok(())
    }

    /// Writes fixed opaque bytes without a prefix.
    pub fn write_fixed(&mut self, bytes: &[u8]) -> Result<(), ReferenceCodecError> {
        self.admit(bytes.len())?;
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    /// Writes bounded opaque bytes with the minimal width derived from `maximum`.
    pub fn write_opaque(
        &mut self,
        bytes: &[u8],
        minimum: usize,
        maximum: usize,
    ) -> Result<(), ReferenceCodecError> {
        if bytes.len() < minimum || bytes.len() > maximum {
            return Err(ReferenceCodecError::VectorLength);
        }
        self.write_length(bytes.len(), maximum)?;
        self.write_fixed(bytes)
    }

    /// Writes an element-count prefix with the minimal derived width.
    pub fn write_length(
        &mut self,
        length: usize,
        maximum: usize,
    ) -> Result<(), ReferenceCodecError> {
        if length > maximum {
            return Err(ReferenceCodecError::VectorLength);
        }
        let value = u64::try_from(length).map_err(|_| ReferenceCodecError::Overflow)?;
        if maximum <= u8::MAX.into() {
            return self.write_u8(value);
        }
        if maximum <= u16::MAX.into() {
            return self.write_u16(value);
        }
        if maximum <= 0x00ff_ffff {
            return self.write_u24(value);
        }
        self.write_u32(value)
    }

    /// Transfers the complete encoded bytes.
    #[must_use]
    pub fn finish(self) -> Vec<u8> {
        self.output
    }
}

/// One checked independent golden-vector record.
pub struct ReferenceVector {
    identifier: String,
    schema: String,
    bytes: Vec<u8>,
    sha256: String,
    provenance: String,
}

impl ReferenceVector {
    /// Borrows the stable vector identifier.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// Borrows the exact schema or arm name.
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// Borrows the independently decoded bytes.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Borrows the lowercase decoded-byte SHA-256.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Borrows the generation provenance label.
    #[must_use]
    pub fn provenance(&self) -> &str {
        &self.provenance
    }
}

/// Parses and verifies a complete checked-in vector manifest.
pub fn parse_reference_vectors(input: &str) -> Result<Vec<ReferenceVector>, ReferenceCodecError> {
    let mut vectors = Vec::new();
    let mut decoded_bytes = 0_usize;
    for line in input.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        if vectors.len() == MAX_REFERENCE_VECTORS {
            return Err(ReferenceCodecError::OutputLimit);
        }
        let fields: Vec<&str> = line.split('|').collect();
        let [identifier, schema, encoded, expected_hash, provenance] = fields.as_slice() else {
            return Err(ReferenceCodecError::ManifestShape);
        };
        validate_manifest_strings(identifier, schema, expected_hash, provenance)?;
        let bytes = decode_hex(encoded)?;
        decoded_bytes = decoded_bytes
            .checked_add(bytes.len())
            .ok_or(ReferenceCodecError::Overflow)?;
        if decoded_bytes > MAX_REFERENCE_VECTOR_BYTES {
            return Err(ReferenceCodecError::OutputLimit);
        }
        let actual_hash = hex_digest(&bytes);
        if actual_hash != *expected_hash {
            return Err(ReferenceCodecError::HashMismatch);
        }
        vectors.push(ReferenceVector {
            identifier: (*identifier).to_owned(),
            schema: (*schema).to_owned(),
            bytes,
            sha256: (*expected_hash).to_owned(),
            provenance: (*provenance).to_owned(),
        });
    }
    Ok(vectors)
}

fn validate_manifest_strings(
    identifier: &str,
    schema: &str,
    hash: &str,
    provenance: &str,
) -> Result<(), ReferenceCodecError> {
    if !identifier.starts_with("VEC-B-")
        || schema.is_empty()
        || provenance != "frozen-registry-minimum"
        || hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ReferenceCodecError::ManifestValue);
    }
    Ok(())
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ReferenceCodecError> {
    if !input.len().is_multiple_of(2) {
        return Err(ReferenceCodecError::ManifestValue);
    }
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(input.len() / 2)
        .map_err(|_| ReferenceCodecError::AllocationFailed)?;
    let (pairs, remainder) = input.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(ReferenceCodecError::ManifestValue);
    }
    for [high, low] in pairs {
        let Some(high) = hex_nibble(*high) else {
            return Err(ReferenceCodecError::ManifestValue);
        };
        let Some(low) = hex_nibble(*low) else {
            return Err(ReferenceCodecError::ManifestValue);
        };
        bytes.push((high << 4) | low);
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut output = String::with_capacity(64);
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for byte in digest {
        let high = usize::from(byte >> 4);
        let low = usize::from(byte & 0x0f);
        if let (Some(high), Some(low)) = (HEX.get(high), HEX.get(low)) {
            output.push(char::from(*high));
            output.push(char::from(*low));
        }
    }
    output
}
