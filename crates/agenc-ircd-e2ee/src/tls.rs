//! A bounded TLS presentation-language codec for the companion structures.
//!
//! Every structure in `docs/irc-mls-e2ee-extension.md` uses the RFC 9420
//! conventions: network byte order, one fixed-width length prefix implied by
//! a vector's declared bound, closed enumerations, and complete consumption.
//! This module implements exactly those rules over borrowed input with a
//! caller-owned allocation budget. It has no knowledge of any structure;
//! the typed declarations live in [`crate::objects`].

use std::marker::PhantomData;

use crate::error::E2eeError;

/// A caller-owned allocation budget for one complete decode.
///
/// `bytes` bounds the total bytes copied into owned vectors; `values` bounds
/// the number of vector items and variable fields materialized. Both are
/// charged before allocation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeBudget {
    remaining_bytes: usize,
    remaining_values: usize,
}

impl DecodeBudget {
    /// Creates explicit byte-copy and value-count ceilings.
    #[must_use]
    pub const fn new(bytes: usize, values: usize) -> Self {
        Self {
            remaining_bytes: bytes,
            remaining_values: values,
        }
    }

    /// Returns the unspent byte-copy allowance.
    #[must_use]
    pub const fn remaining_bytes(&self) -> usize {
        self.remaining_bytes
    }

    /// Returns the unspent value-count allowance.
    #[must_use]
    pub const fn remaining_values(&self) -> usize {
        self.remaining_values
    }

    /// Charges one materialized value; shared by every reader in the crate.
    pub(crate) fn claim_value_public(&mut self) -> Result<(), E2eeError> {
        self.claim_value()
    }

    /// Charges copied bytes; shared by every reader in the crate.
    pub(crate) fn claim_bytes_public(&mut self, amount: usize) -> Result<(), E2eeError> {
        self.claim_bytes(amount)
    }

    fn claim_bytes(&mut self, amount: usize) -> Result<(), E2eeError> {
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(amount)
            .ok_or(E2eeError::BudgetExceeded)?;
        Ok(())
    }

    fn claim_value(&mut self) -> Result<(), E2eeError> {
        self.remaining_values = self
            .remaining_values
            .checked_sub(1)
            .ok_or(E2eeError::BudgetExceeded)?;
        Ok(())
    }
}

/// The one length-prefix width implied by a declared vector bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthWidth {
    /// Bounds up to 255.
    U8,
    /// Bounds up to 65,535.
    U16,
    /// Bounds up to 16,777,215.
    U24,
    /// Larger bounds.
    U32,
}

impl LengthWidth {
    /// Selects the width for a declared maximum byte length.
    #[must_use]
    pub const fn for_maximum(maximum: usize) -> Self {
        if maximum <= 0xff {
            Self::U8
        } else if maximum <= 0xffff {
            Self::U16
        } else if maximum <= 0xff_ffff {
            Self::U24
        } else {
            Self::U32
        }
    }
}

/// A cursor over one borrowed encoding.
pub struct Reader<'a> {
    bytes: &'a [u8],
    position: usize,
    budget: &'a mut DecodeBudget,
}

impl<'a> Reader<'a> {
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

    /// Reads one unsigned byte.
    pub fn u8(&mut self) -> Result<u8, E2eeError> {
        let slice = self.take(1)?;
        slice.first().copied().ok_or(E2eeError::Truncated)
    }

    /// Reads one big-endian 16-bit value.
    pub fn u16(&mut self) -> Result<u16, E2eeError> {
        let bytes: [u8; 2] = self.take(2)?.try_into().map_err(|_| E2eeError::Truncated)?;
        Ok(u16::from_be_bytes(bytes))
    }

    /// Reads one big-endian 32-bit value.
    pub fn u32(&mut self) -> Result<u32, E2eeError> {
        let bytes: [u8; 4] = self.take(4)?.try_into().map_err(|_| E2eeError::Truncated)?;
        Ok(u32::from_be_bytes(bytes))
    }

    /// Reads one big-endian 64-bit value.
    pub fn u64(&mut self) -> Result<u64, E2eeError> {
        let bytes: [u8; 8] = self.take(8)?.try_into().map_err(|_| E2eeError::Truncated)?;
        Ok(u64::from_be_bytes(bytes))
    }

    /// Reads exactly `N` bytes.
    pub fn fixed<const N: usize>(&mut self) -> Result<[u8; N], E2eeError> {
        self.take(N)?.try_into().map_err(|_| E2eeError::Truncated)
    }

    fn length(&mut self, width: LengthWidth) -> Result<usize, E2eeError> {
        let value = match width {
            LengthWidth::U8 => usize::from(self.u8()?),
            LengthWidth::U16 => usize::from(self.u16()?),
            LengthWidth::U24 => {
                let bytes = self.take(3)?;
                bytes
                    .iter()
                    .fold(0_usize, |total, byte| (total << 8) | usize::from(*byte))
            }
            LengthWidth::U32 => {
                usize::try_from(self.u32()?).map_err(|_| E2eeError::LengthOutOfRange)?
            }
        };
        Ok(value)
    }

    /// Reads one length-prefixed opaque field declared as `opaque<min..max>`.
    pub fn opaque(&mut self, minimum: usize, maximum: usize) -> Result<Vec<u8>, E2eeError> {
        let length = self.length(LengthWidth::for_maximum(maximum))?;
        if length < minimum || length > maximum {
            return Err(E2eeError::LengthOutOfRange);
        }
        self.budget.claim_value()?;
        self.budget.claim_bytes(length)?;
        Ok(self.take(length)?.to_vec())
    }

    /// Reads one length-prefixed vector declared as `T items<min..max>` by
    /// decoding items until the declared byte length is exactly consumed.
    pub fn vector<T: TlsDecode>(
        &mut self,
        minimum: usize,
        maximum: usize,
    ) -> Result<Vec<T>, E2eeError> {
        let length = self.length(LengthWidth::for_maximum(maximum))?;
        if length < minimum || length > maximum {
            return Err(E2eeError::LengthOutOfRange);
        }
        let body = self.take(length)?;
        let mut inner = Reader {
            bytes: body,
            position: 0,
            budget: self.budget,
        };
        let mut items = Vec::new();
        while inner.remaining() > 0 {
            inner.budget.claim_value()?;
            items
                .try_reserve(1)
                .map_err(|_| E2eeError::BudgetExceeded)?;
            items.push(T::decode_from(&mut inner)?);
        }
        Ok(items)
    }
}

/// An append-only encoder.
#[derive(Default)]
pub struct Writer {
    bytes: Vec<u8>,
}

impl Writer {
    /// Starts an empty encoding.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Returns the bytes written so far.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }

    /// Returns the current length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Returns whether nothing was written.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn put(&mut self, bytes: &[u8]) -> Result<(), E2eeError> {
        self.bytes
            .try_reserve(bytes.len())
            .map_err(|_| E2eeError::BudgetExceeded)?;
        self.bytes.extend_from_slice(bytes);
        Ok(())
    }

    /// Writes one byte.
    pub fn u8(&mut self, value: u8) -> Result<(), E2eeError> {
        self.put(&[value])
    }

    /// Writes one big-endian 16-bit value.
    pub fn u16(&mut self, value: u16) -> Result<(), E2eeError> {
        self.put(&value.to_be_bytes())
    }

    /// Writes one big-endian 32-bit value.
    pub fn u32(&mut self, value: u32) -> Result<(), E2eeError> {
        self.put(&value.to_be_bytes())
    }

    /// Writes one big-endian 64-bit value.
    pub fn u64(&mut self, value: u64) -> Result<(), E2eeError> {
        self.put(&value.to_be_bytes())
    }

    /// Writes exactly the given bytes.
    pub fn fixed(&mut self, bytes: &[u8]) -> Result<(), E2eeError> {
        self.put(bytes)
    }

    fn length(&mut self, width: LengthWidth, length: usize) -> Result<(), E2eeError> {
        match width {
            LengthWidth::U8 => {
                self.u8(u8::try_from(length).map_err(|_| E2eeError::LengthOutOfRange)?)
            }
            LengthWidth::U16 => {
                self.u16(u16::try_from(length).map_err(|_| E2eeError::LengthOutOfRange)?)
            }
            LengthWidth::U24 => {
                let value = u32::try_from(length).map_err(|_| E2eeError::LengthOutOfRange)?;
                if value > 0xff_ffff {
                    return Err(E2eeError::LengthOutOfRange);
                }
                let bytes = value.to_be_bytes();
                self.put(bytes.get(1..).ok_or(E2eeError::Overflow)?)
            }
            LengthWidth::U32 => {
                self.u32(u32::try_from(length).map_err(|_| E2eeError::LengthOutOfRange)?)
            }
        }
    }

    /// Writes one `opaque<min..max>` field.
    pub fn opaque(
        &mut self,
        bytes: &[u8],
        minimum: usize,
        maximum: usize,
    ) -> Result<(), E2eeError> {
        if bytes.len() < minimum || bytes.len() > maximum {
            return Err(E2eeError::LengthOutOfRange);
        }
        self.length(LengthWidth::for_maximum(maximum), bytes.len())?;
        self.put(bytes)
    }

    /// Writes one `T items<min..max>` vector.
    pub fn vector<T: TlsEncode>(
        &mut self,
        items: &[T],
        minimum: usize,
        maximum: usize,
    ) -> Result<(), E2eeError> {
        let mut body = Writer::new();
        for item in items {
            item.encode_into(&mut body)?;
        }
        self.opaque(&body.bytes, minimum, maximum)
    }
}

/// Canonical encoding of one value.
pub trait TlsEncode {
    /// Appends the canonical encoding.
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError>;

    /// Returns the complete canonical encoding.
    fn encode(&self) -> Result<Vec<u8>, E2eeError> {
        let mut writer = Writer::new();
        self.encode_into(&mut writer)?;
        Ok(writer.into_bytes())
    }
}

/// Bounded decoding of one value.
pub trait TlsDecode: Sized {
    /// Reads one value from the cursor.
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError>;

    /// Decodes a complete encoding, refusing trailing bytes.
    fn decode_exact(bytes: &[u8], budget: &mut DecodeBudget) -> Result<Self, E2eeError> {
        let mut reader = Reader::new(bytes, budget);
        let value = Self::decode_from(&mut reader)?;
        reader.finish()?;
        Ok(value)
    }
}

impl TlsEncode for u8 {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        writer.u8(*self)
    }
}

impl TlsDecode for u8 {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        reader.u8()
    }
}

impl TlsEncode for u16 {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        writer.u16(*self)
    }
}

impl TlsDecode for u16 {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        reader.u16()
    }
}

impl TlsEncode for u32 {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        writer.u32(*self)
    }
}

impl TlsDecode for u32 {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        reader.u32()
    }
}

impl TlsEncode for u64 {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        writer.u64(*self)
    }
}

impl TlsDecode for u64 {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        reader.u64()
    }
}

impl<const N: usize> TlsEncode for [u8; N] {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        writer.fixed(self)
    }
}

impl<const N: usize> TlsDecode for [u8; N] {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        reader.fixed::<N>()
    }
}

/// One `opaque<MIN..MAX>` field.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Opaque<const MIN: usize, const MAX: usize>(Vec<u8>);

impl<const MIN: usize, const MAX: usize> Opaque<MIN, MAX> {
    /// Wraps bytes whose length is inside the declared bound.
    pub fn new(bytes: Vec<u8>) -> Result<Self, E2eeError> {
        if bytes.len() < MIN || bytes.len() > MAX {
            return Err(E2eeError::LengthOutOfRange);
        }
        Ok(Self(bytes))
    }

    /// Wraps a copy of a slice whose length is inside the declared bound.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, E2eeError> {
        Self::new(bytes.to_vec())
    }

    /// Returns the field bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Returns the byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns whether the field is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Requires the field to be empty or exactly `N` bytes and returns it.
    pub fn empty_or_fixed<const N: usize>(&self) -> Result<Option<[u8; N]>, E2eeError> {
        if self.0.is_empty() {
            return Ok(None);
        }
        let bytes: [u8; N] = self
            .0
            .as_slice()
            .try_into()
            .map_err(|_| E2eeError::InvalidValue)?;
        Ok(Some(bytes))
    }

    /// Requires exactly `N` bytes and returns them.
    pub fn exactly<const N: usize>(&self) -> Result<[u8; N], E2eeError> {
        self.0
            .as_slice()
            .try_into()
            .map_err(|_| E2eeError::InvalidValue)
    }
}

impl<const MIN: usize, const MAX: usize> TlsEncode for Opaque<MIN, MAX> {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        writer.opaque(&self.0, MIN, MAX)
    }
}

impl<const MIN: usize, const MAX: usize> TlsDecode for Opaque<MIN, MAX> {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        Ok(Self(reader.opaque(MIN, MAX)?))
    }
}

/// One `T items<MIN..MAX>` vector; the bound is in encoded bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsVec<T, const MIN: usize, const MAX: usize> {
    items: Vec<T>,
    _bound: PhantomData<[(); MIN]>,
}

impl<T: TlsEncode, const MIN: usize, const MAX: usize> TlsVec<T, MIN, MAX> {
    /// Wraps items whose encoded length is inside the declared bound.
    pub fn new(items: Vec<T>) -> Result<Self, E2eeError> {
        let mut body = Writer::new();
        for item in &items {
            item.encode_into(&mut body)?;
        }
        if body.len() < MIN || body.len() > MAX {
            return Err(E2eeError::LengthOutOfRange);
        }
        Ok(Self {
            items,
            _bound: PhantomData,
        })
    }
}

impl<T, const MIN: usize, const MAX: usize> TlsVec<T, MIN, MAX> {
    /// Returns the items.
    #[must_use]
    pub fn as_slice(&self) -> &[T] {
        &self.items
    }

    /// Returns the item count.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns whether there are no items.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Returns the items, consuming the vector.
    #[must_use]
    pub fn into_items(self) -> Vec<T> {
        self.items
    }
}

impl<T: TlsEncode, const MIN: usize, const MAX: usize> TlsEncode for TlsVec<T, MIN, MAX> {
    fn encode_into(&self, writer: &mut Writer) -> Result<(), E2eeError> {
        writer.vector(&self.items, MIN, MAX)
    }
}

impl<T: TlsDecode, const MIN: usize, const MAX: usize> TlsDecode for TlsVec<T, MIN, MAX> {
    fn decode_from(reader: &mut Reader<'_>) -> Result<Self, E2eeError> {
        Ok(Self {
            items: reader.vector(MIN, MAX)?,
            _bound: PhantomData,
        })
    }
}

/// Fails unless `items` are strictly increasing under `key`, which is the
/// profile's definition of a canonical, duplicate-free vector.
pub fn ensure_canonical<T, K: Ord>(items: &[T], key: impl Fn(&T) -> K) -> Result<(), E2eeError> {
    let strictly_increasing = items
        .windows(2)
        .all(|pair| matches!(pair, [left, right] if key(left) < key(right)));
    if strictly_increasing {
        Ok(())
    } else {
        Err(E2eeError::NonCanonical)
    }
}

/// Declares one profile structure whose canonical encoding is the
/// field-by-field concatenation shown in the specification.
macro_rules! tls_struct {
    (
        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$field_meta:meta])*
                $field_vis:vis $field:ident : $field_type:ty
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Eq, PartialEq)]
        $vis struct $name {
            $(
                $(#[$field_meta])*
                $field_vis $field: $field_type,
            )*
        }

        impl $crate::tls::TlsEncode for $name {
            fn encode_into(
                &self,
                writer: &mut $crate::tls::Writer,
            ) -> Result<(), $crate::error::E2eeError> {
                $( self.$field.encode_into(writer)?; )*
                Ok(())
            }
        }

        impl $crate::tls::TlsDecode for $name {
            fn decode_from(
                reader: &mut $crate::tls::Reader<'_>,
            ) -> Result<Self, $crate::error::E2eeError> {
                Ok(Self {
                    $( $field: <$field_type as $crate::tls::TlsDecode>::decode_from(reader)?, )*
                })
            }
        }
    };
}

/// Declares one closed enumeration with the width implied by its values.
macro_rules! tls_enum {
    (
        $(#[$meta:meta])*
        $vis:vis enum $name:ident : $repr:ident {
            $(
                $(#[$variant_meta:meta])*
                $variant:ident = $value:literal
            ),* $(,)?
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
        $vis enum $name {
            $(
                $(#[$variant_meta])*
                $variant = $value,
            )*
        }

        impl $name {
            /// Every registered value in ascending order.
            $vis const ALL: &'static [Self] = &[ $( Self::$variant, )* ];

            /// Returns the registered wire value.
            #[must_use]
            $vis const fn value(self) -> $repr {
                self as $repr
            }

            /// Maps one wire value to its registered variant.
            $vis const fn from_value(value: $repr) -> Result<Self, $crate::error::E2eeError> {
                match value {
                    $( $value => Ok(Self::$variant), )*
                    _ => Err($crate::error::E2eeError::UnknownDiscriminant),
                }
            }
        }

        impl $crate::tls::TlsEncode for $name {
            fn encode_into(
                &self,
                writer: &mut $crate::tls::Writer,
            ) -> Result<(), $crate::error::E2eeError> {
                self.value().encode_into(writer)
            }
        }

        impl $crate::tls::TlsDecode for $name {
            fn decode_from(
                reader: &mut $crate::tls::Reader<'_>,
            ) -> Result<Self, $crate::error::E2eeError> {
                Self::from_value(<$repr as $crate::tls::TlsDecode>::decode_from(reader)?)
            }
        }
    };
}

pub(crate) use {tls_enum, tls_struct};

#[cfg(test)]
#[path = "tests/tls.rs"]
mod tests;
