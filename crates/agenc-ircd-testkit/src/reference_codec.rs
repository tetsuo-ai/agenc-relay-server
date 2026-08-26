//! Independent federation-vector parsing and primitive reference encoding.

use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

/// Maximum records accepted from one checked-in vector manifest.
pub const MAX_REFERENCE_VECTORS: usize = 4_096;
/// Maximum decoded bytes accepted across one vector manifest.
pub const MAX_REFERENCE_VECTOR_BYTES: usize = 64 * 1024 * 1024;
/// Maximum retained metadata bytes in one manifest record.
const MAX_REFERENCE_RECORD_METADATA_BYTES: usize = 256;
/// Maximum retained identifier, schema, hash, and provenance bytes.
const MAX_REFERENCE_METADATA_BYTES: usize =
    MAX_REFERENCE_VECTORS * MAX_REFERENCE_RECORD_METADATA_BYTES;
/// Maximum borrowed manifest bytes, including hex expansion and line syntax.
const MAX_REFERENCE_MANIFEST_BYTES: usize =
    MAX_REFERENCE_VECTOR_BYTES * 2 + MAX_REFERENCE_METADATA_BYTES + 64 * 1024;

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

fn encode_length_prefix(
    length: usize,
    maximum: usize,
) -> Result<([u8; 4], usize), ReferenceCodecError> {
    if length > maximum {
        return Err(ReferenceCodecError::VectorLength);
    }
    let value = u64::try_from(length).map_err(|_| ReferenceCodecError::Overflow)?;
    if maximum <= u8::MAX.into() {
        let value = u8::try_from(value).map_err(|_| ReferenceCodecError::IntegerOutOfRange)?;
        return Ok(([value, 0, 0, 0], 1));
    }
    if maximum <= u16::MAX.into() {
        let value = u16::try_from(value).map_err(|_| ReferenceCodecError::IntegerOutOfRange)?;
        let [high, low] = value.to_be_bytes();
        return Ok(([high, low, 0, 0], 2));
    }
    if maximum <= 0x00ff_ffff {
        let value = u32::try_from(value).map_err(|_| ReferenceCodecError::IntegerOutOfRange)?;
        let [_, high, middle, low] = value.to_be_bytes();
        return Ok(([high, middle, low, 0], 3));
    }
    let value = u32::try_from(value).map_err(|_| ReferenceCodecError::IntegerOutOfRange)?;
    Ok((value.to_be_bytes(), 4))
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
        let (prefix, prefix_len) = encode_length_prefix(bytes.len(), maximum)?;
        let prefix = prefix
            .get(..prefix_len)
            .ok_or(ReferenceCodecError::Overflow)?;
        let additional = prefix
            .len()
            .checked_add(bytes.len())
            .ok_or(ReferenceCodecError::Overflow)?;
        self.admit(additional)?;
        self.output.extend_from_slice(prefix);
        self.output.extend_from_slice(bytes);
        Ok(())
    }

    /// Writes an element-count prefix with the minimal derived width.
    pub fn write_length(
        &mut self,
        length: usize,
        maximum: usize,
    ) -> Result<(), ReferenceCodecError> {
        let (prefix, prefix_len) = encode_length_prefix(length, maximum)?;
        let prefix = prefix
            .get(..prefix_len)
            .ok_or(ReferenceCodecError::Overflow)?;
        self.write_fixed(prefix)
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
    parse_reference_vectors_with_limit(input, MAX_REFERENCE_VECTOR_BYTES)
}

fn parse_reference_vectors_with_limit(
    input: &str,
    decoded_byte_limit: usize,
) -> Result<Vec<ReferenceVector>, ReferenceCodecError> {
    parse_reference_vectors_with_limits(
        input,
        decoded_byte_limit,
        MAX_REFERENCE_MANIFEST_BYTES,
        MAX_REFERENCE_METADATA_BYTES,
    )
}

fn parse_reference_vectors_with_limits(
    input: &str,
    decoded_byte_limit: usize,
    manifest_byte_limit: usize,
    metadata_byte_limit: usize,
) -> Result<Vec<ReferenceVector>, ReferenceCodecError> {
    if input.len() > manifest_byte_limit {
        return Err(ReferenceCodecError::OutputLimit);
    }
    let mut vectors = Vec::new();
    let mut decoded_bytes = 0_usize;
    let mut metadata_bytes = 0_usize;
    for line in input
        .lines()
        .filter(|line| !line.starts_with('#') && !line.is_empty())
    {
        if vectors.len() == MAX_REFERENCE_VECTORS {
            return Err(ReferenceCodecError::OutputLimit);
        }
        let fields = parse_manifest_fields(line)?;
        let record_metadata = manifest_metadata_len(
            fields.identifier,
            fields.schema,
            fields.expected_hash,
            fields.provenance,
        )?;
        if record_metadata > MAX_REFERENCE_RECORD_METADATA_BYTES {
            return Err(ReferenceCodecError::OutputLimit);
        }
        claim_total(&mut metadata_bytes, record_metadata, metadata_byte_limit)?;
        validate_manifest_strings(
            fields.identifier,
            fields.schema,
            fields.expected_hash,
            fields.provenance,
        )?;
        let decoded_length = checked_decoded_hex_len(fields.encoded)?;
        claim_total(&mut decoded_bytes, decoded_length, decoded_byte_limit)?;
        validate_hex_alphabet(fields.encoded)?;
        vectors
            .try_reserve(1)
            .map_err(|_| ReferenceCodecError::AllocationFailed)?;
        vectors.push(reference_vector_from_fields(fields)?);
    }
    Ok(vectors)
}

#[derive(Clone, Copy)]
struct ManifestFields<'a> {
    identifier: &'a str,
    schema: &'a str,
    encoded: &'a str,
    expected_hash: &'a str,
    provenance: &'a str,
}

fn parse_manifest_fields(line: &str) -> Result<ManifestFields<'_>, ReferenceCodecError> {
    let mut fields = line.split('|');
    let parsed = ManifestFields {
        identifier: fields.next().ok_or(ReferenceCodecError::ManifestShape)?,
        schema: fields.next().ok_or(ReferenceCodecError::ManifestShape)?,
        encoded: fields.next().ok_or(ReferenceCodecError::ManifestShape)?,
        expected_hash: fields.next().ok_or(ReferenceCodecError::ManifestShape)?,
        provenance: fields.next().ok_or(ReferenceCodecError::ManifestShape)?,
    };
    if fields.next().is_some() {
        return Err(ReferenceCodecError::ManifestShape);
    }
    Ok(parsed)
}

fn claim_total(total: &mut usize, amount: usize, limit: usize) -> Result<(), ReferenceCodecError> {
    let next = total
        .checked_add(amount)
        .ok_or(ReferenceCodecError::Overflow)?;
    if next > limit {
        return Err(ReferenceCodecError::OutputLimit);
    }
    *total = next;
    Ok(())
}

fn reference_vector_from_fields(
    fields: ManifestFields<'_>,
) -> Result<ReferenceVector, ReferenceCodecError> {
    let bytes = decode_hex(fields.encoded)?;
    if hex_digest(&bytes) != fields.expected_hash {
        return Err(ReferenceCodecError::HashMismatch);
    }
    Ok(ReferenceVector {
        identifier: copy_manifest_string(fields.identifier)?,
        schema: copy_manifest_string(fields.schema)?,
        bytes,
        sha256: copy_manifest_string(fields.expected_hash)?,
        provenance: copy_manifest_string(fields.provenance)?,
    })
}

fn manifest_metadata_len(
    identifier: &str,
    schema: &str,
    hash: &str,
    provenance: &str,
) -> Result<usize, ReferenceCodecError> {
    [identifier, schema, hash, provenance]
        .into_iter()
        .try_fold(0_usize, |total, value| {
            total
                .checked_add(value.len())
                .ok_or(ReferenceCodecError::Overflow)
        })
}

fn copy_manifest_string(input: &str) -> Result<String, ReferenceCodecError> {
    let mut output = String::new();
    output
        .try_reserve_exact(input.len())
        .map_err(|_| ReferenceCodecError::AllocationFailed)?;
    output.push_str(input);
    Ok(output)
}

fn checked_decoded_hex_len(input: &str) -> Result<usize, ReferenceCodecError> {
    if !input.len().is_multiple_of(2) {
        return Err(ReferenceCodecError::ManifestValue);
    }
    Ok(input.len() / 2)
}

fn validate_manifest_strings(
    identifier: &str,
    schema: &str,
    hash: &str,
    provenance: &str,
) -> Result<(), ReferenceCodecError> {
    if !is_reference_identifier(identifier)
        || !is_reference_schema(schema)
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

fn is_reference_identifier(identifier: &str) -> bool {
    let Some(sequence) = identifier.strip_prefix("VEC-B-") else {
        return false;
    };
    if !(3..=4).contains(&sequence.len())
        || !sequence.bytes().all(|byte| byte.is_ascii_digit())
        || (sequence.len() == 4 && sequence.starts_with('0'))
    {
        return false;
    }
    sequence
        .parse::<usize>()
        .is_ok_and(|value| (1..=MAX_REFERENCE_VECTORS).contains(&value))
}

fn is_reference_schema(schema: &str) -> bool {
    let Some((&first, remaining)) = schema.as_bytes().split_first() else {
        return false;
    };
    first.is_ascii_alphabetic()
        && remaining
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.'))
}

fn decode_hex(input: &str) -> Result<Vec<u8>, ReferenceCodecError> {
    if !input.len().is_multiple_of(2) {
        return Err(ReferenceCodecError::ManifestValue);
    }
    validate_hex_alphabet(input)?;
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

fn validate_hex_alphabet(input: &str) -> Result<(), ReferenceCodecError> {
    if input.bytes().all(|byte| hex_nibble(byte).is_some()) {
        return Ok(());
    }
    Err(ReferenceCodecError::ManifestValue)
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

#[cfg(test)]
mod tests {
    use super::{
        MAX_REFERENCE_METADATA_BYTES, MAX_REFERENCE_RECORD_METADATA_BYTES, ReferenceCodecError,
        parse_reference_vectors_with_limit, parse_reference_vectors_with_limits,
    };

    #[test]
    fn decoded_byte_limit_is_checked_before_hex_decode() {
        let manifest = concat!(
            "VEC-B-001|x|gg|",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "|frozen-registry-minimum"
        );
        assert_eq!(
            parse_reference_vectors_with_limit(manifest, 0).err(),
            Some(ReferenceCodecError::OutputLimit)
        );
    }

    #[test]
    fn manifest_and_metadata_limits_precede_record_allocation() {
        let manifest = concat!(
            "VEC-B-001|x|gg|",
            "0000000000000000000000000000000000000000000000000000000000000000",
            "|frozen-registry-minimum"
        );
        assert_eq!(
            parse_reference_vectors_with_limits(
                manifest,
                usize::MAX,
                manifest.len() - 1,
                MAX_REFERENCE_METADATA_BYTES,
            )
            .err(),
            Some(ReferenceCodecError::OutputLimit)
        );
        assert_eq!(
            parse_reference_vectors_with_limits(manifest, usize::MAX, manifest.len(), 0).err(),
            Some(ReferenceCodecError::OutputLimit)
        );
        let oversized_schema = "a".repeat(MAX_REFERENCE_RECORD_METADATA_BYTES);
        let oversized_record = format!(
            "VEC-B-001|{oversized_schema}||\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855|\
             frozen-registry-minimum"
        );
        assert_eq!(
            parse_reference_vectors_with_limits(
                &oversized_record,
                usize::MAX,
                usize::MAX,
                MAX_REFERENCE_METADATA_BYTES,
            )
            .err(),
            Some(ReferenceCodecError::OutputLimit)
        );
    }

    #[test]
    fn manifest_names_follow_the_generator_grammar() {
        const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        for identifier in ["VEC-B-", "VEC-B-000", "VEC-B-0001", "VEC-B-4097"] {
            let manifest = format!("{identifier}|x||{EMPTY_HASH}|frozen-registry-minimum");
            assert_eq!(
                parse_reference_vectors_with_limit(&manifest, 0).err(),
                Some(ReferenceCodecError::ManifestValue)
            );
        }
        for schema in ["", ".leading", "bad/schema", "bad-name"] {
            let manifest = format!("VEC-B-001|{schema}||{EMPTY_HASH}|frozen-registry-minimum");
            assert_eq!(
                parse_reference_vectors_with_limit(&manifest, 0).err(),
                Some(ReferenceCodecError::ManifestValue)
            );
        }
    }
}
