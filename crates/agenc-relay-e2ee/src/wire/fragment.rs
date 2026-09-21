//! The fragment and receipt tag values (companion Section 11.2).
//!
//! Everything here is bounded string work: a fragment value is at most a
//! few thousand ASCII bytes and decodes to at most one 2,940-byte segment.
//! The object limit for the carrying command is applied by the assembler,
//! after the grammar and before any reservation.

use crate::error::E2eeError;
use crate::limits::MAX_FRAGMENT_RAW;
use crate::object::ObjectId;
use crate::wire::tokens::{
    base64url_decode, base64url_encode, is_base64url_byte, parse_hash, parse_u32,
};

/// The client-only fragment tag key.
pub const CLIENT_FRAGMENT_TAG: &str = "+agenc.ag/e2ee";
/// The server-originated fragment tag key.
pub const SERVER_FRAGMENT_TAG: &str = "agenc.ag/e2ee";
/// The candidate receipt tag key.
pub const RECEIPT_TAG: &str = "agenc.ag/e2ee-receipt";
/// Base64url characters of a full raw segment.
pub const MAX_SEGMENT_CHARS: usize = 3_920;
/// Most decimal digits in `part` and `count`.
pub const MAX_INDEX_DIGITS: usize = 4;
/// Most decimal digits in `total`.
pub const MAX_TOTAL_DIGITS: usize = 7;

/// One decoded fragment tag value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FragmentTag {
    /// SHA-256 of the complete object.
    pub object_id: ObjectId,
    /// Zero-based fragment index.
    pub part: u32,
    /// Total fragment count.
    pub count: u32,
    /// Complete object length in bytes.
    pub total: u32,
    /// This fragment's raw bytes.
    pub segment: Vec<u8>,
}

/// The fragment count implied by a total: `ceil(total / 2940)`.
pub fn fragment_count(total: u32) -> Result<u32, E2eeError> {
    if total == 0 {
        return Err(E2eeError::InvalidValue);
    }
    let raw = u32::try_from(MAX_FRAGMENT_RAW).map_err(|_| E2eeError::Overflow)?;
    Ok(total.div_ceil(raw))
}

/// The exact raw length fragment `part` of `count` must carry.
pub fn segment_length(part: u32, count: u32, total: u32) -> Result<usize, E2eeError> {
    if part >= count {
        return Err(E2eeError::InvalidValue);
    }
    let raw = u32::try_from(MAX_FRAGMENT_RAW).map_err(|_| E2eeError::Overflow)?;
    let offset = part.checked_mul(raw).ok_or(E2eeError::Overflow)?;
    let length = if part + 1 == count {
        total.checked_sub(offset).ok_or(E2eeError::InvalidValue)?
    } else {
        raw
    };
    usize::try_from(length).map_err(|_| E2eeError::Overflow)
}

impl FragmentTag {
    /// Parses the raw tag value after `=`; the value must contain no
    /// backslash and match the grammar exactly.
    pub fn parse(raw: &str) -> Result<Self, E2eeError> {
        let mut fields = raw.split('.');
        let version = fields.next().ok_or(E2eeError::InvalidValue)?;
        let object_id = fields.next().ok_or(E2eeError::InvalidValue)?;
        let part = fields.next().ok_or(E2eeError::InvalidValue)?;
        let count = fields.next().ok_or(E2eeError::InvalidValue)?;
        let total = fields.next().ok_or(E2eeError::InvalidValue)?;
        let segment = fields.next().ok_or(E2eeError::InvalidValue)?;
        if fields.next().is_some() || version != "v1" {
            return Err(E2eeError::InvalidValue);
        }
        if part.len() > MAX_INDEX_DIGITS
            || count.len() > MAX_INDEX_DIGITS
            || total.len() > MAX_TOTAL_DIGITS
        {
            return Err(E2eeError::InvalidValue);
        }
        let tag = Self {
            object_id: ObjectId::from_bytes(parse_hash(object_id)?),
            part: parse_u32(part)?,
            count: parse_u32(count)?,
            total: parse_u32(total)?,
            segment: decode_segment(segment)?,
        };
        tag.check_consistency()?;
        Ok(tag)
    }

    fn check_consistency(&self) -> Result<(), E2eeError> {
        if self.count == 0 || self.part >= self.count || self.total == 0 {
            return Err(E2eeError::InvalidValue);
        }
        if fragment_count(self.total)? != self.count {
            return Err(E2eeError::InvalidValue);
        }
        if self.segment.len() != segment_length(self.part, self.count, self.total)? {
            return Err(E2eeError::InvalidValue);
        }
        Ok(())
    }

    /// Whether this is the last fragment.
    #[must_use]
    pub const fn is_final(&self) -> bool {
        self.part + 1 == self.count
    }

    /// The byte offset of this fragment in the complete object.
    pub fn offset(&self) -> Result<usize, E2eeError> {
        usize::try_from(self.part)
            .ok()
            .and_then(|part| part.checked_mul(MAX_FRAGMENT_RAW))
            .ok_or(E2eeError::Overflow)
    }

    /// Renders the tag value.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "v1.{}.{}.{}.{}.{}",
            base64url_encode(self.object_id.as_bytes()),
            self.part,
            self.count,
            self.total,
            base64url_encode(&self.segment)
        )
    }
}

fn decode_segment(text: &str) -> Result<Vec<u8>, E2eeError> {
    if text.is_empty() || text.len() > MAX_SEGMENT_CHARS || !text.bytes().all(is_base64url_byte) {
        return Err(E2eeError::InvalidValue);
    }
    base64url_decode(text)
}

/// Splits a complete encoded object into its fragment tags.
pub fn fragment_object(object: &[u8]) -> Result<Vec<FragmentTag>, E2eeError> {
    let total = u32::try_from(object.len()).map_err(|_| E2eeError::Overflow)?;
    let count = fragment_count(total)?;
    let object_id = ObjectId::compute(object);
    object
        .chunks(MAX_FRAGMENT_RAW)
        .enumerate()
        .map(|(index, segment)| {
            Ok(FragmentTag {
                object_id,
                part: u32::try_from(index).map_err(|_| E2eeError::Overflow)?,
                count,
                total,
                segment: segment.to_vec(),
            })
        })
        .collect()
}

/// The candidate receipt tag value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReceiptTag {
    /// The candidate identifier.
    pub candidate_id: [u8; 32],
    /// The exact encoded `ArcCandidateReceipt`.
    pub receipt: Vec<u8>,
}

impl ReceiptTag {
    /// Parses the raw tag value.
    pub fn parse(raw: &str) -> Result<Self, E2eeError> {
        let mut fields = raw.split('.');
        let version = fields.next().ok_or(E2eeError::InvalidValue)?;
        let candidate = fields.next().ok_or(E2eeError::InvalidValue)?;
        let receipt = fields.next().ok_or(E2eeError::InvalidValue)?;
        if fields.next().is_some() || version != "v1" || receipt.is_empty() {
            return Err(E2eeError::InvalidValue);
        }
        if !receipt.bytes().all(is_base64url_byte) {
            return Err(E2eeError::InvalidValue);
        }
        Ok(Self {
            candidate_id: parse_hash(candidate)?,
            receipt: base64url_decode(receipt)?,
        })
    }

    /// Renders the tag value.
    #[must_use]
    pub fn render(&self) -> String {
        format!(
            "v1.{}.{}",
            base64url_encode(&self.candidate_id),
            base64url_encode(&self.receipt)
        )
    }
}

/// Which fragment tag keys a frame carries, and whether that is legal: a
/// frame carrying both names, or the same name twice, is invalid.
pub fn fragment_tag_of<'a>(
    keys_and_raw_values: &[(&'a str, &'a str)],
) -> Result<Option<(&'a str, &'a str)>, E2eeError> {
    let mut found = None;
    for (key, raw) in keys_and_raw_values {
        if *key != CLIENT_FRAGMENT_TAG && *key != SERVER_FRAGMENT_TAG {
            continue;
        }
        if found.is_some() || raw.contains('\\') || !raw.is_ascii() {
            return Err(E2eeError::InvalidValue);
        }
        found = Some((*key, *raw));
    }
    Ok(found)
}

#[cfg(test)]
#[path = "../tests/fragment.rs"]
mod tests;
