//! Allocation-bounded canonical Appendix-B encoding and decoding.

use std::error::Error;
use std::fmt;
use std::mem::size_of;

use agenc_ircd_types::{BASE_OBJECT_BYTES, ChannelName, ENUM_REGISTRY};
use zeroize::Zeroize as _;

use crate::schema::{FieldKind, LengthWidth, SchemaDescriptor, schema_by_name};
use crate::semantics::{validate_embedded_semantics, validate_schema_semantics};

pub(crate) const MAX_STATIC_SCHEMA_DEPTH: usize = 16;
const UINT24_MAX: u64 = 0x00ff_ffff;

/// Closed failures from canonical wire construction or decoding.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodecError {
    /// A requested schema is not in the frozen registry.
    UnknownSchema,
    /// A structure has the wrong number of fields.
    FieldCount,
    /// A value does not match its field grammar.
    TypeMismatch,
    /// Input ended before the selected schema completed.
    UnexpectedEof,
    /// Bytes remained after one complete top-level object.
    TrailingBytes,
    /// A bounded byte or element vector is shorter than its minimum.
    LengthBelowMinimum,
    /// A bounded byte or element vector exceeds its maximum.
    LengthAboveMaximum,
    /// A numeric value does not fit its exact wire width.
    IntegerOutOfRange,
    /// A closed enum discriminant is unregistered.
    UnknownDiscriminant,
    /// A decoded allocation would exceed the caller's budget.
    AllocationBudgetExceeded,
    /// A checked size or cursor calculation overflowed.
    Overflow,
    /// A bounded allocation failed.
    AllocationFailed,
    /// A nested value names a different static schema.
    SchemaMismatch,
    /// Static schema nesting exceeded the reviewed closed maximum.
    SchemaDepth,
    /// A repeated canonical key was found.
    DuplicateValue,
    /// A canonical collection was not in required order.
    NonCanonicalOrder,
    /// A presence, fixed-optional, or cross-field rule was violated.
    CrossReference,
    /// A zero-padding field contained a nonzero byte.
    NonzeroPadding,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::UnknownSchema => "unknown federation schema",
            Self::FieldCount => "federation field count mismatch",
            Self::TypeMismatch => "federation field type mismatch",
            Self::UnexpectedEof => "truncated federation object",
            Self::TrailingBytes => "trailing federation object bytes",
            Self::LengthBelowMinimum => "federation vector is below its minimum",
            Self::LengthAboveMaximum => "federation vector exceeds its maximum",
            Self::IntegerOutOfRange => "federation integer is outside its wire width",
            Self::UnknownDiscriminant => "unknown federation enum discriminant",
            Self::AllocationBudgetExceeded => "federation decode allocation budget exhausted",
            Self::Overflow => "federation codec calculation overflowed",
            Self::AllocationFailed => "federation codec allocation failed",
            Self::SchemaMismatch => "nested federation schema mismatch",
            Self::SchemaDepth => "federation schema nesting limit exceeded",
            Self::DuplicateValue => "duplicate canonical federation value",
            Self::NonCanonicalOrder => "federation values are not canonically ordered",
            Self::CrossReference => "federation field presence or cross-reference mismatch",
            Self::NonzeroPadding => "federation padding is not all zero",
        };
        formatter.write_str(message)
    }
}

impl Error for CodecError {}

/// A caller-owned allocation budget for one complete decode operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DecodeBudget {
    remaining_bytes: usize,
    remaining_values: usize,
}

impl DecodeBudget {
    /// Creates explicit byte-copy and value-count ceilings.
    #[must_use]
    pub const fn new(byte_limit: usize, value_limit: usize) -> Self {
        Self {
            remaining_bytes: byte_limit,
            remaining_values: value_limit,
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

    fn claim_bytes(&mut self, amount: usize) -> Result<(), CodecError> {
        self.remaining_bytes = self
            .remaining_bytes
            .checked_sub(amount)
            .ok_or(CodecError::AllocationBudgetExceeded)?;
        Ok(())
    }

    fn claim_values(&mut self, amount: usize) -> Result<(), CodecError> {
        self.remaining_values = self
            .remaining_values
            .checked_sub(amount)
            .ok_or(CodecError::AllocationBudgetExceeded)?;
        Ok(())
    }
}

/// Move-only canonical bytes that erase their complete backing capacity on drop.
///
/// The encoded bytes may contain credentials or other protocol secrets. The
/// private field prevents accidentally extracting a non-zeroizing `Vec<u8>`.
/// Borrow the result explicitly with [`CanonicalBytes::as_slice`].
///
/// This type intentionally does not implement `Clone` or `Debug`:
///
/// ```compile_fail
/// use agenc_ircd_federation_wire::CanonicalBytes;
///
/// fn requires_clone<T: Clone>() {}
/// requires_clone::<CanonicalBytes>();
/// ```
///
/// ```compile_fail
/// use agenc_ircd_federation_wire::CanonicalBytes;
///
/// fn requires_debug<T: core::fmt::Debug>() {}
/// requires_debug::<CanonicalBytes>();
/// ```
#[must_use = "canonical encoded bytes must be consumed or explicitly dropped"]
pub struct CanonicalBytes {
    bytes: Vec<u8>,
}

impl CanonicalBytes {
    fn try_with_capacity(capacity: usize) -> Result<Self, CodecError> {
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(capacity)
            .map_err(|_| CodecError::AllocationFailed)?;
        Ok(Self { bytes })
    }

    /// Borrows the canonical byte representation.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact encoded byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether the canonical representation is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    fn zeroize_storage(&mut self) {
        zeroize_vec_capacity(&mut self.bytes);
    }
}

impl AsRef<[u8]> for CanonicalBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl Drop for CanonicalBytes {
    fn drop(&mut self) {
        self.zeroize_storage();
    }
}

fn zeroize_vec_capacity(bytes: &mut Vec<u8>) {
    bytes.resize(bytes.capacity(), 0);
    bytes.as_mut_slice().zeroize();
}

/// One field value whose validity is established by [`SchemaObject::new`].
pub enum WireValue {
    /// Unsigned integer or closed enum value.
    Unsigned(u64),
    /// Fixed or length-prefixed opaque bytes.
    Opaque(Vec<u8>),
    /// One nested structure, owned without a separate peer-triggered allocation.
    Structure(SchemaObject),
    /// One bounded vector of nested structures.
    Vector(Vec<SchemaObject>),
    /// One projection union arm and its explicit discriminant.
    ProjectionUnion {
        /// Encoded `FederationProjectionKind` discriminant.
        discriminant: u16,
        /// Validated selected arm, owned without a separate peer-triggered allocation.
        value: SchemaObject,
    },
}

impl WireValue {
    fn zeroize_opaque_storage(&mut self) {
        if let Self::Opaque(bytes) = self {
            zeroize_vec_capacity(bytes);
        }
    }
}

impl Drop for WireValue {
    fn drop(&mut self) {
        self.zeroize_opaque_storage();
    }
}

/// A complete value validated against one frozen Appendix-B schema.
pub struct SchemaObject {
    pub(crate) schema: &'static SchemaDescriptor,
    pub(crate) fields: Vec<WireValue>,
    backing_capacity_bytes: usize,
}

impl SchemaObject {
    /// Validates a complete field vector against one exact schema.
    pub fn new(schema_name: &str, fields: Vec<WireValue>) -> Result<Self, CodecError> {
        let schema = schema_by_name(schema_name).ok_or(CodecError::UnknownSchema)?;
        validate_fields(schema, &fields)?;
        let object = Self::from_validated_fields(schema, fields)?;
        if object.encoded_len()? > base_object_limit()? {
            return Err(CodecError::LengthAboveMaximum);
        }
        let semantic_byte_limit = base_object_limit()?
            .checked_mul(2)
            .ok_or(CodecError::Overflow)?;
        let mut semantic_budget = DecodeBudget::new(semantic_byte_limit, 1_000_000);
        validate_embedded_tree(&object, &mut semantic_budget)?;
        Ok(object)
    }

    fn from_validated_fields(
        schema: &'static SchemaDescriptor,
        fields: Vec<WireValue>,
    ) -> Result<Self, CodecError> {
        validate_storage_capacities(schema, &fields, fields.capacity())?;
        let backing_capacity_bytes = calculate_backing_capacity_bytes(&fields, fields.capacity())?;
        Ok(Self {
            schema,
            fields,
            backing_capacity_bytes,
        })
    }

    #[cfg(test)]
    pub(crate) fn raw_for_test(schema: &'static SchemaDescriptor, fields: Vec<WireValue>) -> Self {
        let backing_capacity_bytes = calculate_backing_capacity_bytes(&fields, fields.capacity());
        // agenc-review: internal-assert owner=stage01-codec reviewed=2026-08-26 reason=cfg(test)-only constructor must preserve the exact cache invariant
        assert!(
            backing_capacity_bytes.is_ok(),
            "test-owned schema storage capacity must fit usize"
        );
        Self {
            schema,
            fields,
            backing_capacity_bytes: backing_capacity_bytes.unwrap_or_default(),
        }
    }

    /// Decodes exactly one complete object under an explicit allocation budget.
    pub fn decode_exact(
        schema_name: &str,
        input: &[u8],
        budget: &mut DecodeBudget,
    ) -> Result<Self, CodecError> {
        let object = decode_one_without_embedded(schema_name, input, budget, 0)?;
        validate_embedded_tree(&object, budget)?;
        Ok(object)
    }

    /// Returns the exact schema descriptor used for validation.
    #[must_use]
    pub const fn schema(&self) -> &'static SchemaDescriptor {
        self.schema
    }

    /// Borrows fields in canonical schema order.
    #[must_use]
    pub fn fields(&self) -> &[WireValue] {
        &self.fields
    }

    /// Returns the exact bytes reserved by every object-owned backing vector.
    ///
    /// This includes field tables, opaque byte buffers, vector element tables,
    /// and all nested objects. It excludes inline object size and allocator
    /// bookkeeping, which admission control charges separately.
    #[must_use]
    pub const fn backing_capacity_bytes(&self) -> usize {
        self.backing_capacity_bytes
    }

    /// Returns the exact canonical encoded length without writing output.
    pub fn encoded_len(&self) -> Result<usize, CodecError> {
        encoded_fields_len(self.schema, &self.fields)
    }
}

mod private {
    pub trait Sealed {}
}

/// Sealed canonical encoding contract for validated federation values.
pub trait CanonicalEncode: private::Sealed {
    /// Encodes one unique Appendix-B representation.
    fn encode_canonical(&self) -> Result<CanonicalBytes, CodecError>;
}

impl private::Sealed for SchemaObject {}

impl CanonicalEncode for SchemaObject {
    fn encode_canonical(&self) -> Result<CanonicalBytes, CodecError> {
        let length = self.encoded_len()?;
        let mut output = CanonicalBytes::try_with_capacity(length)?;
        encode_fields(self.schema, &self.fields, &mut output.bytes)?;
        if output.bytes.len() != length {
            return Err(CodecError::Overflow);
        }
        Ok(output)
    }
}

fn base_object_limit() -> Result<usize, CodecError> {
    usize::try_from(BASE_OBJECT_BYTES).map_err(|_| CodecError::Overflow)
}

fn validate_storage_capacities(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    fields_capacity: usize,
) -> Result<(), CodecError> {
    if fields_capacity > schema.fields.len() {
        return Err(CodecError::LengthAboveMaximum);
    }
    for (descriptor, value) in schema.fields.iter().zip(fields) {
        validate_value_storage_capacity(descriptor.kind, value)?;
    }
    Ok(())
}

fn validate_value_storage_capacity(kind: FieldKind, value: &WireValue) -> Result<(), CodecError> {
    match (kind, value) {
        (
            FieldKind::Uint8
            | FieldKind::Uint16
            | FieldKind::Uint24
            | FieldKind::Uint32
            | FieldKind::Uint64
            | FieldKind::Enumeration { .. },
            WireValue::Unsigned(_),
        ) => Ok(()),
        (FieldKind::FixedOpaque { length }, WireValue::Opaque(bytes)) => {
            validate_capacity(bytes.capacity(), length)
        }
        (FieldKind::VariableOpaque { maximum, .. }, WireValue::Opaque(bytes)) => {
            validate_capacity(bytes.capacity(), maximum)
        }
        (FieldKind::Structure { schema }, WireValue::Structure(value)) => {
            validate_nested_schema_name(schema, value)?;
            validate_storage_capacities(value.schema, &value.fields, value.fields.capacity())
        }
        (
            FieldKind::Vector {
                schema, maximum, ..
            },
            WireValue::Vector(values),
        ) => {
            validate_capacity(values.capacity(), maximum)?;
            for value in values {
                validate_nested_schema_name(schema, value)?;
                validate_storage_capacities(value.schema, &value.fields, value.fields.capacity())?;
            }
            Ok(())
        }
        (
            FieldKind::ProjectionUnion {
                discriminant,
                schema,
            },
            WireValue::ProjectionUnion {
                discriminant: actual,
                value,
            },
        ) if discriminant == *actual => {
            validate_nested_schema_name(schema, value)?;
            validate_storage_capacities(value.schema, &value.fields, value.fields.capacity())
        }
        _ => Err(CodecError::TypeMismatch),
    }
}

fn validate_capacity(capacity: usize, maximum: usize) -> Result<(), CodecError> {
    if capacity > maximum {
        return Err(CodecError::LengthAboveMaximum);
    }
    Ok(())
}

fn calculate_backing_capacity_bytes(
    fields: &[WireValue],
    fields_capacity: usize,
) -> Result<usize, CodecError> {
    let mut total = fields_capacity
        .checked_mul(size_of::<WireValue>())
        .ok_or(CodecError::Overflow)?;
    for value in fields {
        total = total
            .checked_add(value_backing_capacity_bytes(value)?)
            .ok_or(CodecError::Overflow)?;
    }
    Ok(total)
}

fn value_backing_capacity_bytes(value: &WireValue) -> Result<usize, CodecError> {
    match value {
        WireValue::Unsigned(_) => Ok(0),
        WireValue::Opaque(bytes) => Ok(bytes.capacity()),
        WireValue::Structure(value) | WireValue::ProjectionUnion { value, .. } => {
            Ok(value.backing_capacity_bytes)
        }
        WireValue::Vector(values) => {
            let mut total = values
                .capacity()
                .checked_mul(size_of::<SchemaObject>())
                .ok_or(CodecError::Overflow)?;
            for value in values {
                total = total
                    .checked_add(value.backing_capacity_bytes)
                    .ok_or(CodecError::Overflow)?;
            }
            Ok(total)
        }
    }
}

fn validate_fields(schema: &SchemaDescriptor, fields: &[WireValue]) -> Result<(), CodecError> {
    if fields.len() != schema.fields.len() {
        return Err(CodecError::FieldCount);
    }
    for (descriptor, value) in schema.fields.iter().zip(fields) {
        validate_value(descriptor.kind, value)?;
        validate_field_semantics(schema.name, descriptor.name, value)?;
    }
    validate_collection_semantics(schema, fields)?;
    validate_schema_semantics(schema, fields)
}

fn validate_decoded_fields(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    if fields.len() != schema.fields.len() {
        return Err(CodecError::FieldCount);
    }
    for (descriptor, value) in schema.fields.iter().zip(fields) {
        validate_decoded_value(descriptor.kind, value)?;
        validate_field_semantics(schema.name, descriptor.name, value)?;
    }
    validate_collection_semantics(schema, fields)?;
    validate_schema_semantics(schema, fields)
}

fn validate_decoded_value(kind: FieldKind, value: &WireValue) -> Result<(), CodecError> {
    match (kind, value) {
        (FieldKind::Structure { schema }, WireValue::Structure(value)) => {
            validate_nested_schema_name(schema, value)
        }
        (
            FieldKind::Vector {
                schema,
                minimum,
                maximum,
                ..
            },
            WireValue::Vector(values),
        ) => {
            validate_bounds(values.len(), minimum, maximum)?;
            for value in values {
                validate_nested_schema_name(schema, value)?;
            }
            Ok(())
        }
        (
            FieldKind::ProjectionUnion {
                discriminant,
                schema,
            },
            WireValue::ProjectionUnion {
                discriminant: actual,
                value,
            },
        ) if discriminant == *actual => validate_nested_schema_name(schema, value),
        _ => validate_value(kind, value),
    }
}

fn validate_value(kind: FieldKind, value: &WireValue) -> Result<(), CodecError> {
    match (kind, value) {
        (FieldKind::Uint8, WireValue::Unsigned(value)) if *value <= u8::MAX.into() => Ok(()),
        (FieldKind::Uint16, WireValue::Unsigned(value)) if *value <= u16::MAX.into() => Ok(()),
        (FieldKind::Uint24, WireValue::Unsigned(value)) if *value <= UINT24_MAX => Ok(()),
        (FieldKind::Uint32, WireValue::Unsigned(value)) if *value <= u32::MAX.into() => Ok(()),
        (FieldKind::Uint64, WireValue::Unsigned(_)) => Ok(()),
        (FieldKind::FixedOpaque { length }, WireValue::Opaque(bytes)) if bytes.len() == length => {
            Ok(())
        }
        (
            FieldKind::VariableOpaque {
                minimum, maximum, ..
            },
            WireValue::Opaque(bytes),
        ) => validate_bounds(bytes.len(), minimum, maximum),
        (FieldKind::Enumeration { registry }, WireValue::Unsigned(value)) => {
            validate_enum(registry, *value)
        }
        (FieldKind::Structure { schema }, WireValue::Structure(value)) => {
            validate_nested_schema(schema, value)
        }
        (
            FieldKind::Vector {
                schema,
                minimum,
                maximum,
                ..
            },
            WireValue::Vector(values),
        ) => {
            validate_bounds(values.len(), minimum, maximum)?;
            for value in values {
                validate_nested_schema(schema, value)?;
            }
            Ok(())
        }
        (
            FieldKind::ProjectionUnion {
                discriminant,
                schema,
            },
            WireValue::ProjectionUnion {
                discriminant: actual,
                value,
            },
        ) if discriminant == *actual => validate_nested_schema(schema, value),
        _ => Err(CodecError::TypeMismatch),
    }
}

fn validate_bounds(length: usize, minimum: usize, maximum: usize) -> Result<(), CodecError> {
    if length < minimum {
        return Err(CodecError::LengthBelowMinimum);
    }
    if length > maximum {
        return Err(CodecError::LengthAboveMaximum);
    }
    Ok(())
}

fn validate_enum(registry: &str, value: u64) -> Result<(), CodecError> {
    let descriptor = ENUM_REGISTRY
        .iter()
        .find(|descriptor| descriptor.name == registry)
        .ok_or(CodecError::UnknownSchema)?;
    let value = u16::try_from(value).map_err(|_| CodecError::IntegerOutOfRange)?;
    if descriptor.entries.iter().any(|entry| entry.value == value) {
        return Ok(());
    }
    Err(CodecError::UnknownDiscriminant)
}

fn validate_nested_schema(expected: &str, value: &SchemaObject) -> Result<(), CodecError> {
    validate_nested_schema_name(expected, value)?;
    validate_fields(value.schema, &value.fields)
}

fn validate_nested_schema_name(expected: &str, value: &SchemaObject) -> Result<(), CodecError> {
    if value.schema.name == expected {
        return Ok(());
    }
    Err(CodecError::SchemaMismatch)
}

fn is_optional_fixed(schema: &str, field: &str, maximum: usize) -> bool {
    matches!(
        (schema, field, maximum),
        ("FederationOrigin", "session_id" | "user_id", 16)
            | ("FederationOrigin", "account_id", 24)
            | ("FederationResult", "completion_event_id", 16)
            | ("FederationEvent", "cross_profile_mutation_id", 16)
            | ("FederationEvent", "request_home_server_id", 16)
            | ("FederationEvent", "request_server_incarnation", 16)
            | ("FederationEvent", "request_origin_id", 16)
            | ("FederationEvent", "request_id", 16)
            | ("operation.session_open", "auth_grant_id", 32)
            | ("result.session_registered", "account_id", 24)
            | ("event.topic_changed", "message_id", 16)
            | ("result.reply_page", "next_cursor", 32)
    )
}

fn validate_field_semantics(
    schema: &str,
    field: &str,
    value: &WireValue,
) -> Result<(), CodecError> {
    validate_version_field(field, value)?;
    validate_padding_field(field, value)?;
    validate_optional_fixed_field(schema, field, value)
}

fn validate_version_field(field: &str, value: &WireValue) -> Result<(), CodecError> {
    if matches!(field, "profile_version" | "padding_version")
        && !matches!(value, WireValue::Unsigned(1))
    {
        return Err(CodecError::CrossReference);
    }
    Ok(())
}

fn validate_padding_field(field: &str, value: &WireValue) -> Result<(), CodecError> {
    if field == "zero_padding"
        && matches!(value, WireValue::Opaque(bytes) if bytes.iter().any(|byte| *byte != 0))
    {
        return Err(CodecError::NonzeroPadding);
    }
    Ok(())
}

fn validate_optional_fixed_field(
    schema: &str,
    field: &str,
    value: &WireValue,
) -> Result<(), CodecError> {
    let Some(descriptor) = schema_by_name(schema) else {
        return Err(CodecError::UnknownSchema);
    };
    let Some(field_descriptor) = descriptor
        .fields
        .iter()
        .find(|candidate| candidate.name == field)
    else {
        return Err(CodecError::SchemaMismatch);
    };
    if let (FieldKind::VariableOpaque { maximum, .. }, WireValue::Opaque(bytes)) =
        (field_descriptor.kind, value)
        && is_optional_fixed(schema, field, maximum)
        && !bytes.is_empty()
        && bytes.len() != maximum
    {
        return Err(CodecError::CrossReference);
    }
    Ok(())
}

fn validate_collection_semantics(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<(), CodecError> {
    for (descriptor, value) in schema.fields.iter().zip(fields) {
        let WireValue::Vector(values) = value else {
            continue;
        };
        if !matches!(
            (schema.name, descriptor.name),
            ("operation.join", "targets")
                | ("operation.message", "targets" | "tags")
                | ("FederationDeliveredMessage", "tags")
                | ("operation.part", "channels")
                | ("event.session_hidden", "channels")
                | ("event.channel_memberships_recomputed", "memberships")
        ) {
            continue;
        }
        validate_ordered_unique(schema.name, descriptor.name, values)?;
    }
    Ok(())
}

fn validate_ordered_unique(
    owner_schema: &str,
    field_name: &str,
    values: &[SchemaObject],
) -> Result<(), CodecError> {
    let mut previous: Option<Vec<u8>> = None;
    for value in values {
        let encoded = collection_key(owner_schema, field_name, value)?;
        if let Some(prior) = &previous {
            if prior == &encoded {
                return Err(CodecError::DuplicateValue);
            }
            if prior > &encoded {
                return Err(CodecError::NonCanonicalOrder);
            }
        }
        previous = Some(encoded);
    }
    Ok(())
}

fn collection_key(
    owner_schema: &str,
    field_name: &str,
    value: &SchemaObject,
) -> Result<Vec<u8>, CodecError> {
    match (owner_schema, field_name) {
        ("operation.join", "targets") => join_target_key(value),
        ("operation.message", "targets") => message_target_key(value),
        ("operation.message" | "FederationDeliveredMessage", "tags") => {
            opaque_value(value, "key").and_then(copy_key)
        }
        ("operation.part", "channels") => opaque_value(value, "value").and_then(copy_key),
        ("event.session_hidden", "channels") => {
            opaque_value(value, "channel_instance_id").and_then(copy_key)
        }
        ("event.channel_memberships_recomputed", "memberships") => {
            let membership = structure_value(value, "membership")?;
            opaque_value(membership, "user_id").and_then(copy_key)
        }
        _ => Err(CodecError::SchemaMismatch),
    }
}

fn join_target_key(value: &SchemaObject) -> Result<Vec<u8>, CodecError> {
    let channel = structure_value(value, "channel_name")?;
    let bytes = opaque_value(channel, "value")?;
    let text = std::str::from_utf8(bytes).map_err(|_| CodecError::CrossReference)?;
    let name = ChannelName::parse(text).map_err(|_| CodecError::CrossReference)?;
    copy_key(name.canonical().as_bytes())
}

fn object_value<'a>(
    value: &'a SchemaObject,
    field_name: &str,
) -> Result<&'a WireValue, CodecError> {
    value
        .schema
        .fields
        .iter()
        .zip(&value.fields)
        .find_map(|(descriptor, field)| (descriptor.name == field_name).then_some(field))
        .ok_or(CodecError::SchemaMismatch)
}

fn opaque_value<'a>(value: &'a SchemaObject, field_name: &str) -> Result<&'a [u8], CodecError> {
    match object_value(value, field_name)? {
        WireValue::Opaque(bytes) => Ok(bytes),
        _ => Err(CodecError::TypeMismatch),
    }
}

fn structure_value<'a>(
    value: &'a SchemaObject,
    field_name: &str,
) -> Result<&'a SchemaObject, CodecError> {
    match object_value(value, field_name)? {
        WireValue::Structure(nested) => Ok(nested),
        _ => Err(CodecError::TypeMismatch),
    }
}

fn unsigned_value(value: &SchemaObject, field_name: &str) -> Result<u64, CodecError> {
    match object_value(value, field_name)? {
        WireValue::Unsigned(number) => Ok(*number),
        _ => Err(CodecError::TypeMismatch),
    }
}

fn copy_key(bytes: &[u8]) -> Result<Vec<u8>, CodecError> {
    let mut key = Vec::new();
    key.try_reserve_exact(bytes.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    key.extend_from_slice(bytes);
    Ok(key)
}

fn message_target_key(value: &SchemaObject) -> Result<Vec<u8>, CodecError> {
    let kind = u16::try_from(unsigned_value(value, "target_kind")?)
        .map_err(|_| CodecError::IntegerOutOfRange)?;
    let target = opaque_value(value, "value")?;
    let length = target.len().checked_add(2).ok_or(CodecError::Overflow)?;
    let mut key = Vec::new();
    key.try_reserve_exact(length)
        .map_err(|_| CodecError::AllocationFailed)?;
    key.extend_from_slice(&kind.to_be_bytes());
    key.extend_from_slice(target);
    Ok(key)
}

fn encoded_fields_len(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<usize, CodecError> {
    validate_fields(schema, fields)?;
    measured_fields_len(schema, fields)
}

pub(crate) fn measured_fields_len(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
) -> Result<usize, CodecError> {
    if fields.len() != schema.fields.len() {
        return Err(CodecError::FieldCount);
    }
    let mut total = 0_usize;
    for (descriptor, value) in schema.fields.iter().zip(fields) {
        total = total
            .checked_add(encoded_value_len(descriptor.kind, value)?)
            .ok_or(CodecError::Overflow)?;
    }
    Ok(total)
}

fn encoded_value_len(kind: FieldKind, value: &WireValue) -> Result<usize, CodecError> {
    validate_value(kind, value)?;
    measured_value_len(kind, value)
}

fn measured_value_len(kind: FieldKind, value: &WireValue) -> Result<usize, CodecError> {
    match (kind, value) {
        (FieldKind::Uint8, _) => Ok(1),
        (FieldKind::Uint16 | FieldKind::Enumeration { .. }, _) => Ok(2),
        (FieldKind::Uint24, _) => Ok(3),
        (FieldKind::Uint32, _) => Ok(4),
        (FieldKind::Uint64, _) => Ok(8),
        (FieldKind::FixedOpaque { .. }, WireValue::Opaque(bytes)) => Ok(bytes.len()),
        (FieldKind::VariableOpaque { width, .. }, WireValue::Opaque(bytes)) => width
            .bytes()
            .checked_add(bytes.len())
            .ok_or(CodecError::Overflow),
        (FieldKind::Structure { .. }, WireValue::Structure(value)) => {
            measured_fields_len(value.schema, &value.fields)
        }
        (FieldKind::Vector { width, .. }, WireValue::Vector(values)) => {
            let mut total = width.bytes();
            for value in values {
                total = total
                    .checked_add(measured_fields_len(value.schema, &value.fields)?)
                    .ok_or(CodecError::Overflow)?;
            }
            Ok(total)
        }
        (FieldKind::ProjectionUnion { .. }, WireValue::ProjectionUnion { value, .. }) => {
            measured_fields_len(value.schema, &value.fields)?
                .checked_add(2)
                .ok_or(CodecError::Overflow)
        }
        _ => Err(CodecError::TypeMismatch),
    }
}

fn encode_fields(
    schema: &SchemaDescriptor,
    fields: &[WireValue],
    output: &mut Vec<u8>,
) -> Result<(), CodecError> {
    validate_fields(schema, fields)?;
    for (descriptor, value) in schema.fields.iter().zip(fields) {
        encode_value(descriptor.kind, value, output)?;
    }
    Ok(())
}

fn encode_value(
    kind: FieldKind,
    value: &WireValue,
    output: &mut Vec<u8>,
) -> Result<(), CodecError> {
    validate_value(kind, value)?;
    match (kind, value) {
        (FieldKind::Uint8, WireValue::Unsigned(value)) => {
            output.push(u8::try_from(*value).map_err(|_| CodecError::IntegerOutOfRange)?)
        }
        (FieldKind::Uint16 | FieldKind::Enumeration { .. }, WireValue::Unsigned(value)) => output
            .extend_from_slice(
                &u16::try_from(*value)
                    .map_err(|_| CodecError::IntegerOutOfRange)?
                    .to_be_bytes(),
            ),
        (FieldKind::Uint24, WireValue::Unsigned(value)) => {
            let bytes = u32::try_from(*value)
                .map_err(|_| CodecError::IntegerOutOfRange)?
                .to_be_bytes();
            let Some(encoded) = bytes.get(1..) else {
                return Err(CodecError::Overflow);
            };
            output.extend_from_slice(encoded);
        }
        (FieldKind::Uint32, WireValue::Unsigned(value)) => output.extend_from_slice(
            &u32::try_from(*value)
                .map_err(|_| CodecError::IntegerOutOfRange)?
                .to_be_bytes(),
        ),
        (FieldKind::Uint64, WireValue::Unsigned(value)) => {
            output.extend_from_slice(&value.to_be_bytes())
        }
        (FieldKind::FixedOpaque { .. }, WireValue::Opaque(bytes)) => {
            output.extend_from_slice(bytes)
        }
        (FieldKind::VariableOpaque { width, .. }, WireValue::Opaque(bytes)) => {
            encode_length(width, bytes.len(), output)?;
            output.extend_from_slice(bytes);
        }
        (FieldKind::Structure { .. }, WireValue::Structure(value)) => {
            encode_fields(value.schema, &value.fields, output)?
        }
        (FieldKind::Vector { width, .. }, WireValue::Vector(values)) => {
            encode_length(width, values.len(), output)?;
            for value in values {
                encode_fields(value.schema, &value.fields, output)?;
            }
        }
        (
            FieldKind::ProjectionUnion { .. },
            WireValue::ProjectionUnion {
                discriminant,
                value,
            },
        ) => {
            output.extend_from_slice(&discriminant.to_be_bytes());
            encode_fields(value.schema, &value.fields, output)?;
        }
        _ => return Err(CodecError::TypeMismatch),
    }
    Ok(())
}

fn encode_length(
    width: LengthWidth,
    length: usize,
    output: &mut Vec<u8>,
) -> Result<(), CodecError> {
    let value = u64::try_from(length).map_err(|_| CodecError::Overflow)?;
    match width {
        LengthWidth::U8 => {
            output.push(u8::try_from(value).map_err(|_| CodecError::IntegerOutOfRange)?)
        }
        LengthWidth::U16 => output.extend_from_slice(
            &u16::try_from(value)
                .map_err(|_| CodecError::IntegerOutOfRange)?
                .to_be_bytes(),
        ),
        LengthWidth::U24 => encode_value(FieldKind::Uint24, &WireValue::Unsigned(value), output)?,
        LengthWidth::U32 => output.extend_from_slice(
            &u32::try_from(value)
                .map_err(|_| CodecError::IntegerOutOfRange)?
                .to_be_bytes(),
        ),
    }
    Ok(())
}

struct Decoder<'a> {
    input: &'a [u8],
    cursor: usize,
}

impl<'a> Decoder<'a> {
    const fn new(input: &'a [u8]) -> Self {
        Self { input, cursor: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.cursor)
    }

    fn read(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let end = self
            .cursor
            .checked_add(length)
            .ok_or(CodecError::Overflow)?;
        let Some(bytes) = self.input.get(self.cursor..end) else {
            return Err(CodecError::UnexpectedEof);
        };
        self.cursor = end;
        Ok(bytes)
    }

    fn read_unsigned(&mut self, width: LengthWidth) -> Result<u64, CodecError> {
        let bytes = self.read(width.bytes())?;
        let mut value = 0_u64;
        for byte in bytes {
            value = value.checked_shl(8).ok_or(CodecError::Overflow)? | u64::from(*byte);
        }
        Ok(value)
    }
}

#[derive(Clone, Copy)]
enum SchemaCompletion {
    Root,
    Structure,
    Projection(u16),
}

struct SchemaFrame {
    schema: &'static SchemaDescriptor,
    fields: Vec<WireValue>,
    next_field: usize,
    depth: usize,
    completion: SchemaCompletion,
}

struct VectorFrame {
    schema: &'static SchemaDescriptor,
    values: Vec<SchemaObject>,
    remaining: usize,
    element_depth: usize,
}

enum DecodeFrame {
    Schema(SchemaFrame),
    Vector(VectorFrame),
}

enum DecodeStep {
    Value(WireValue),
    Schema(SchemaFrame),
    Vector(VectorFrame),
}

enum CompletedValue {
    Wire(WireValue),
    Structure(SchemaObject),
    Projection {
        discriminant: u16,
        value: SchemaObject,
    },
}

impl CompletedValue {
    fn into_wire(self) -> WireValue {
        match self {
            Self::Wire(value) => value,
            Self::Structure(value) => WireValue::Structure(value),
            Self::Projection {
                discriminant,
                value,
            } => WireValue::ProjectionUnion {
                discriminant,
                value,
            },
        }
    }
}

enum DecodeProgress {
    Waiting,
    Value(CompletedValue),
    Root(SchemaObject),
}

pub(crate) fn decode_one_without_embedded(
    schema_name: &str,
    input: &[u8],
    budget: &mut DecodeBudget,
    initial_depth: usize,
) -> Result<SchemaObject, CodecError> {
    if input.len() > base_object_limit()? {
        return Err(CodecError::LengthAboveMaximum);
    }
    let schema = schema_by_name(schema_name).ok_or(CodecError::UnknownSchema)?;
    let mut decoder = Decoder::new(input);
    let object = decode_schema_iterative(schema, &mut decoder, budget, initial_depth)?;
    if decoder.remaining() != 0 {
        return Err(CodecError::TrailingBytes);
    }
    Ok(object)
}

fn decode_schema_iterative(
    schema: &'static SchemaDescriptor,
    decoder: &mut Decoder<'_>,
    budget: &mut DecodeBudget,
    initial_depth: usize,
) -> Result<SchemaObject, CodecError> {
    let root = new_schema_frame(schema, initial_depth, SchemaCompletion::Root, budget)?;
    let mut frames = Vec::new();
    push_decode_frame(&mut frames, DecodeFrame::Schema(root))?;
    loop {
        let frame = frames.pop().ok_or(CodecError::Overflow)?;
        match process_decode_frame(frame, decoder, budget, &mut frames)? {
            DecodeProgress::Waiting => {}
            DecodeProgress::Value(value) => deliver_completed_value(&mut frames, value)?,
            DecodeProgress::Root(object) => return Ok(object),
        }
    }
}

fn process_decode_frame(
    frame: DecodeFrame,
    decoder: &mut Decoder<'_>,
    budget: &mut DecodeBudget,
    frames: &mut Vec<DecodeFrame>,
) -> Result<DecodeProgress, CodecError> {
    match frame {
        DecodeFrame::Schema(frame) => process_schema_frame(frame, decoder, budget, frames),
        DecodeFrame::Vector(frame) => process_vector_frame(frame, budget, frames),
    }
}

fn process_schema_frame(
    frame: SchemaFrame,
    decoder: &mut Decoder<'_>,
    budget: &mut DecodeBudget,
    frames: &mut Vec<DecodeFrame>,
) -> Result<DecodeProgress, CodecError> {
    let Some(descriptor) = frame.schema.fields.get(frame.next_field).copied() else {
        return complete_schema_frame(frame, frames);
    };
    advance_schema_frame(frame, descriptor.kind, decoder, budget, frames)
}

fn complete_schema_frame(
    frame: SchemaFrame,
    frames: &[DecodeFrame],
) -> Result<DecodeProgress, CodecError> {
    validate_decoded_fields(frame.schema, &frame.fields)?;
    let object = SchemaObject::from_validated_fields(frame.schema, frame.fields)?;
    match frame.completion {
        SchemaCompletion::Root if frames.is_empty() => Ok(DecodeProgress::Root(object)),
        SchemaCompletion::Root => Err(CodecError::Overflow),
        SchemaCompletion::Structure => Ok(DecodeProgress::Value(CompletedValue::Structure(object))),
        SchemaCompletion::Projection(discriminant) => {
            Ok(DecodeProgress::Value(CompletedValue::Projection {
                discriminant,
                value: object,
            }))
        }
    }
}

fn advance_schema_frame(
    mut frame: SchemaFrame,
    kind: FieldKind,
    decoder: &mut Decoder<'_>,
    budget: &mut DecodeBudget,
    frames: &mut Vec<DecodeFrame>,
) -> Result<DecodeProgress, CodecError> {
    frame.next_field = frame
        .next_field
        .checked_add(1)
        .ok_or(CodecError::Overflow)?;
    let child_depth = frame.depth.checked_add(1).ok_or(CodecError::Overflow)?;
    push_decode_frame(frames, DecodeFrame::Schema(frame))?;
    match begin_decode_value(kind, decoder, budget, child_depth)? {
        DecodeStep::Value(value) => Ok(DecodeProgress::Value(CompletedValue::Wire(value))),
        DecodeStep::Schema(nested) => {
            push_decode_frame(frames, DecodeFrame::Schema(nested))?;
            Ok(DecodeProgress::Waiting)
        }
        DecodeStep::Vector(vector) => {
            push_decode_frame(frames, DecodeFrame::Vector(vector))?;
            Ok(DecodeProgress::Waiting)
        }
    }
}

fn process_vector_frame(
    mut frame: VectorFrame,
    budget: &mut DecodeBudget,
    frames: &mut Vec<DecodeFrame>,
) -> Result<DecodeProgress, CodecError> {
    if frame.remaining == 0 {
        return Ok(DecodeProgress::Value(CompletedValue::Wire(
            WireValue::Vector(frame.values),
        )));
    }
    frame.remaining = frame.remaining.checked_sub(1).ok_or(CodecError::Overflow)?;
    let nested = new_schema_frame(
        frame.schema,
        frame.element_depth,
        SchemaCompletion::Structure,
        budget,
    )?;
    push_decode_frame(frames, DecodeFrame::Vector(frame))?;
    push_decode_frame(frames, DecodeFrame::Schema(nested))?;
    Ok(DecodeProgress::Waiting)
}

fn new_schema_frame(
    schema: &'static SchemaDescriptor,
    depth: usize,
    completion: SchemaCompletion,
    budget: &mut DecodeBudget,
) -> Result<SchemaFrame, CodecError> {
    if depth > MAX_STATIC_SCHEMA_DEPTH {
        return Err(CodecError::SchemaDepth);
    }
    budget.claim_values(schema.fields.len())?;
    let mut fields = Vec::new();
    fields
        .try_reserve_exact(schema.fields.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    Ok(SchemaFrame {
        schema,
        fields,
        next_field: 0,
        depth,
        completion,
    })
}

fn push_decode_frame(frames: &mut Vec<DecodeFrame>, frame: DecodeFrame) -> Result<(), CodecError> {
    frames
        .try_reserve(1)
        .map_err(|_| CodecError::AllocationFailed)?;
    frames.push(frame);
    Ok(())
}

fn deliver_completed_value(
    frames: &mut Vec<DecodeFrame>,
    value: CompletedValue,
) -> Result<(), CodecError> {
    let parent = frames.pop().ok_or(CodecError::Overflow)?;
    match parent {
        DecodeFrame::Schema(mut frame) => {
            frame.fields.push(value.into_wire());
            push_decode_frame(frames, DecodeFrame::Schema(frame))
        }
        DecodeFrame::Vector(mut frame) => {
            let CompletedValue::Structure(value) = value else {
                return Err(CodecError::TypeMismatch);
            };
            frame.values.push(value);
            push_decode_frame(frames, DecodeFrame::Vector(frame))
        }
    }
}

fn begin_decode_value(
    kind: FieldKind,
    decoder: &mut Decoder<'_>,
    budget: &mut DecodeBudget,
    child_depth: usize,
) -> Result<DecodeStep, CodecError> {
    let value = match kind {
        FieldKind::Uint8 => WireValue::Unsigned(decoder.read_unsigned(LengthWidth::U8)?),
        FieldKind::Uint16 => WireValue::Unsigned(decoder.read_unsigned(LengthWidth::U16)?),
        FieldKind::Uint24 => WireValue::Unsigned(decoder.read_unsigned(LengthWidth::U24)?),
        FieldKind::Uint32 => WireValue::Unsigned(decoder.read_unsigned(LengthWidth::U32)?),
        FieldKind::Uint64 => WireValue::Unsigned(read_u64(decoder)?),
        FieldKind::FixedOpaque { length } => decode_opaque(length, decoder, budget)?,
        FieldKind::VariableOpaque {
            minimum,
            maximum,
            width,
        } => {
            let length = decode_length(width, decoder)?;
            validate_bounds(length, minimum, maximum)?;
            decode_opaque(length, decoder, budget)?
        }
        FieldKind::Enumeration { registry } => {
            let value = decoder.read_unsigned(LengthWidth::U16)?;
            validate_enum(registry, value)?;
            WireValue::Unsigned(value)
        }
        FieldKind::Structure { schema } => {
            let nested = schema_by_name(schema).ok_or(CodecError::UnknownSchema)?;
            return new_schema_frame(nested, child_depth, SchemaCompletion::Structure, budget)
                .map(DecodeStep::Schema);
        }
        FieldKind::Vector {
            schema,
            minimum,
            maximum,
            width,
        } => {
            let count = decode_length(width, decoder)?;
            validate_bounds(count, minimum, maximum)?;
            budget.claim_values(count)?;
            let nested = schema_by_name(schema).ok_or(CodecError::UnknownSchema)?;
            let mut values = Vec::new();
            values
                .try_reserve_exact(count)
                .map_err(|_| CodecError::AllocationFailed)?;
            return Ok(DecodeStep::Vector(VectorFrame {
                schema: nested,
                values,
                remaining: count,
                element_depth: child_depth,
            }));
        }
        FieldKind::ProjectionUnion {
            discriminant,
            schema,
        } => {
            let actual = decoder.read_unsigned(LengthWidth::U16)?;
            if actual != u64::from(discriminant) {
                return Err(CodecError::UnknownDiscriminant);
            }
            let nested = schema_by_name(schema).ok_or(CodecError::UnknownSchema)?;
            return new_schema_frame(
                nested,
                child_depth,
                SchemaCompletion::Projection(discriminant),
                budget,
            )
            .map(DecodeStep::Schema);
        }
    };
    Ok(DecodeStep::Value(value))
}

fn read_u64(decoder: &mut Decoder<'_>) -> Result<u64, CodecError> {
    let bytes = decoder.read(8)?;
    let mut value = 0_u64;
    for byte in bytes {
        value = value.checked_shl(8).ok_or(CodecError::Overflow)? | u64::from(*byte);
    }
    Ok(value)
}

fn decode_length(width: LengthWidth, decoder: &mut Decoder<'_>) -> Result<usize, CodecError> {
    let value = decoder.read_unsigned(width)?;
    usize::try_from(value).map_err(|_| CodecError::Overflow)
}

fn decode_opaque(
    length: usize,
    decoder: &mut Decoder<'_>,
    budget: &mut DecodeBudget,
) -> Result<WireValue, CodecError> {
    let input = decoder.read(length)?;
    budget.claim_bytes(length)?;
    let mut bytes = Vec::new();
    bytes
        .try_reserve_exact(length)
        .map_err(|_| CodecError::AllocationFailed)?;
    bytes.extend_from_slice(input);
    Ok(WireValue::Opaque(bytes))
}

enum ObjectWalkFrame<'a> {
    Object {
        object: &'a SchemaObject,
        next_field: usize,
        depth: usize,
    },
    Vector {
        values: &'a [SchemaObject],
        next_value: usize,
        element_depth: usize,
    },
}

fn validate_embedded_tree(
    root: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<(), CodecError> {
    let mut pending = Vec::new();
    validate_embedded_in_object_graph(root, 0, budget, &mut pending)?;
    while let Some((object, depth)) = pending.pop() {
        validate_embedded_in_object_graph(&object, depth, budget, &mut pending)?;
    }
    Ok(())
}

fn validate_embedded_in_object_graph(
    root: &SchemaObject,
    initial_depth: usize,
    budget: &mut DecodeBudget,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    let mut frames = Vec::new();
    push_walk_frame(
        &mut frames,
        ObjectWalkFrame::Object {
            object: root,
            next_field: 0,
            depth: initial_depth,
        },
    )?;

    while let Some(frame) = frames.pop() {
        process_walk_frame(frame, &mut frames, budget, pending)?;
    }
    Ok(())
}

fn process_walk_frame<'a>(
    frame: ObjectWalkFrame<'a>,
    frames: &mut Vec<ObjectWalkFrame<'a>>,
    budget: &mut DecodeBudget,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    match frame {
        ObjectWalkFrame::Object {
            object,
            next_field,
            depth,
        } => process_object_walk(object, next_field, depth, frames, budget, pending),
        ObjectWalkFrame::Vector {
            values,
            next_value,
            element_depth,
        } => process_vector_walk(values, next_value, element_depth, frames),
    }
}

fn process_object_walk<'a>(
    object: &'a SchemaObject,
    next_field: usize,
    depth: usize,
    frames: &mut Vec<ObjectWalkFrame<'a>>,
    budget: &mut DecodeBudget,
    pending: &mut Vec<(SchemaObject, usize)>,
) -> Result<(), CodecError> {
    if next_field == 0 {
        validate_embedded_semantics(object.schema, &object.fields, budget, depth, pending)?;
    }
    let Some(value) = object.fields.get(next_field) else {
        return Ok(());
    };
    let following = next_field.checked_add(1).ok_or(CodecError::Overflow)?;
    push_walk_frame(
        frames,
        ObjectWalkFrame::Object {
            object,
            next_field: following,
            depth,
        },
    )?;
    let child_depth = depth.checked_add(1).ok_or(CodecError::Overflow)?;
    push_nested_value_for_walk(frames, value, child_depth)
}

fn process_vector_walk<'a>(
    values: &'a [SchemaObject],
    next_value: usize,
    element_depth: usize,
    frames: &mut Vec<ObjectWalkFrame<'a>>,
) -> Result<(), CodecError> {
    let Some(value) = values.get(next_value) else {
        return Ok(());
    };
    let following = next_value.checked_add(1).ok_or(CodecError::Overflow)?;
    push_walk_frame(
        frames,
        ObjectWalkFrame::Vector {
            values,
            next_value: following,
            element_depth,
        },
    )?;
    push_object_for_walk(frames, value, element_depth)
}

fn push_nested_value_for_walk<'a>(
    frames: &mut Vec<ObjectWalkFrame<'a>>,
    value: &'a WireValue,
    child_depth: usize,
) -> Result<(), CodecError> {
    match value {
        WireValue::Structure(value) | WireValue::ProjectionUnion { value, .. } => {
            push_object_for_walk(frames, value, child_depth)
        }
        WireValue::Vector(values) if !values.is_empty() => push_walk_frame(
            frames,
            ObjectWalkFrame::Vector {
                values,
                next_value: 0,
                element_depth: child_depth,
            },
        ),
        WireValue::Unsigned(_) | WireValue::Opaque(_) | WireValue::Vector(_) => Ok(()),
    }
}

fn push_object_for_walk<'a>(
    frames: &mut Vec<ObjectWalkFrame<'a>>,
    object: &'a SchemaObject,
    depth: usize,
) -> Result<(), CodecError> {
    if depth > MAX_STATIC_SCHEMA_DEPTH {
        return Err(CodecError::SchemaDepth);
    }
    push_walk_frame(
        frames,
        ObjectWalkFrame::Object {
            object,
            next_field: 0,
            depth,
        },
    )
}

fn push_walk_frame<'a>(
    frames: &mut Vec<ObjectWalkFrame<'a>>,
    frame: ObjectWalkFrame<'a>,
) -> Result<(), CodecError> {
    frames
        .try_reserve(1)
        .map_err(|_| CodecError::AllocationFailed)?;
    frames.push(frame);
    Ok(())
}

#[cfg(test)]
#[path = "tests/codec.rs"]
mod tests;
