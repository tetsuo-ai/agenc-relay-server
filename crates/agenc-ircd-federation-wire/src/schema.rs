//! Static Appendix-B schema descriptors.

/// Minimal fixed-width prefix used by one bounded vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LengthWidth {
    /// One-byte unsigned prefix.
    U8,
    /// Two-byte unsigned prefix.
    U16,
    /// Three-byte unsigned prefix.
    U24,
    /// Four-byte unsigned prefix.
    U32,
}

impl LengthWidth {
    /// Returns the encoded prefix width in bytes.
    #[must_use]
    pub const fn bytes(self) -> usize {
        match self {
            Self::U8 => 1,
            Self::U16 => 2,
            Self::U24 => 3,
            Self::U32 => 4,
        }
    }
}

/// One static field grammar in a frozen Appendix-B schema.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldKind {
    /// Exact unsigned 8-bit integer.
    Uint8,
    /// Exact unsigned 16-bit integer.
    Uint16,
    /// Exact unsigned 24-bit integer.
    Uint24,
    /// Exact unsigned 32-bit integer.
    Uint32,
    /// Exact unsigned 64-bit integer.
    Uint64,
    /// Fixed bytes without a length prefix.
    FixedOpaque {
        /// Exact byte length.
        length: usize,
    },
    /// Bounded opaque bytes with a minimal fixed-width prefix.
    VariableOpaque {
        /// Inclusive minimum byte length.
        minimum: usize,
        /// Inclusive maximum byte length.
        maximum: usize,
        /// Prefix width derived from the maximum.
        width: LengthWidth,
    },
    /// A closed `u16` enum registry.
    Enumeration {
        /// Frozen registry type name.
        registry: &'static str,
    },
    /// One nested static structure.
    Structure {
        /// Required nested schema name.
        schema: &'static str,
    },
    /// A bounded element-count vector of nested structures.
    Vector {
        /// Element schema name.
        schema: &'static str,
        /// Inclusive minimum element count.
        minimum: usize,
        /// Inclusive maximum element count.
        maximum: usize,
        /// Prefix width derived from the maximum.
        width: LengthWidth,
    },
    /// One fixed projection union arm including its explicit discriminant.
    ProjectionUnion {
        /// Required `FederationProjectionKind` value.
        discriminant: u16,
        /// Required arm schema.
        schema: &'static str,
    },
}

/// One named field in an Appendix-B structure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldDescriptor {
    /// Exact field name from the frozen registry.
    pub name: &'static str,
    /// Exact field encoding grammar.
    pub kind: FieldKind,
}

/// One complete Appendix-B structure or registered union arm.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaDescriptor {
    /// Exact schema or arm name.
    pub name: &'static str,
    /// Fields in canonical encoding order.
    pub fields: &'static [FieldDescriptor],
}

include!("generated_schema.rs");

/// Finds one schema by its exact registry name.
#[must_use]
pub fn schema_by_name(name: &str) -> Option<&'static SchemaDescriptor> {
    SCHEMA_REGISTRY.iter().find(|schema| schema.name == name)
}
