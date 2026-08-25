//! Frozen client and federation registries.

use std::error::Error;
use std::fmt;

/// One named value in a closed federation enum.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumEntry {
    /// Registry spelling.
    pub name: &'static str,
    /// Explicit `u16` network value.
    pub value: u16,
}

/// A complete closed federation enum descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EnumDescriptor {
    /// Rust/protocol type name.
    pub name: &'static str,
    /// Registered entries in source order.
    pub entries: &'static [EnumEntry],
}

/// One named unsigned federation constant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConstantDescriptor {
    /// Registry spelling.
    pub name: &'static str,
    /// Frozen unsigned value.
    pub value: u64,
}

/// One named frozen textual registry descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TextDescriptor {
    /// Registry key.
    pub name: &'static str,
    /// Exact registry payload following the key.
    pub value: &'static str,
}

/// One explicit federation mode descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ModeDescriptor {
    /// Stable numeric mode code.
    pub code: u16,
    /// Case-sensitive client mode letter.
    pub letter: &'static str,
    /// Mode behavior class.
    pub kind: &'static str,
    /// Canonical argument description.
    pub argument: &'static str,
}

/// Failure to resolve a value in a frozen registry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RegistryValueError {
    /// A binary discriminant is not registered.
    UnknownDiscriminant,
    /// A text token is not registered with exact case.
    UnknownToken,
}

impl fmt::Display for RegistryValueError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownDiscriminant => formatter.write_str("unknown registry discriminant"),
            Self::UnknownToken => formatter.write_str("unknown registry token"),
        }
    }
}

impl Error for RegistryValueError {}

include!("generated_registry.rs");
