//! Closed configuration failures and the ordered validation report.

use std::fmt;

/// Stable failures returned while parsing and validating configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ConfigError {
    /// The file could not be opened, was not a protected regular file, or exceeded its limit.
    FileRejected,
    /// TOML syntax or the closed table shape was invalid.
    InvalidDocument,
    /// A required value was absent or had the wrong TOML type.
    MissingValue,
    /// A scalar or cross-field storage constraint was invalid.
    InvalidValue,
    /// A table or array element carried a key outside the closed schema.
    UnknownKey,
    /// A checked arithmetic step overflowed.
    Overflow,
    /// A role, peer, listener, or operator relationship was inconsistent.
    Topology,
    /// A host control, permission, or process hardening step failed.
    HostControl,
    /// A configured transport requires an optional Cargo feature.
    DeferredTransport,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::FileRejected => "configuration file rejected",
            Self::InvalidDocument => "configuration document rejected",
            Self::MissingValue => "required configuration value missing",
            Self::InvalidValue => "configuration value rejected",
            Self::UnknownKey => "configuration key is outside the closed schema",
            Self::Overflow => "configuration arithmetic overflowed",
            Self::Topology => "configuration topology is inconsistent",
            Self::HostControl => "host control unavailable",
            Self::DeferredTransport => "listener transport is not compiled into this binary",
        })
    }
}

impl std::error::Error for ConfigError {}

/// The ordered startup validation stages from Appendix C.8 (spec 9280-9285).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ValidationStage {
    /// Root document and closed table shape.
    RootSchema,
    /// Canonical scalar syntax and table-local ranges.
    Scalars,
    /// Path existence, file types, and directory permissions.
    PathsAndFileTypes,
    /// Secret and public key parsing.
    KeyParsing,
    /// Local identity consistency.
    LocalIdentity,
    /// Listener union constraints.
    ListenerUnion,
    /// Role and peer topology.
    Topology,
    /// Resource arithmetic.
    ResourceArithmetic,
    /// Database header comparison, filled by the composition layer.
    DatabaseHeader,
    /// E2EE and base state compatibility, filled by the composition layer.
    E2eeCompatibility,
}

impl ValidationStage {
    /// Returns whether a failure at this stage stops validation before any secret,
    /// database, socket, or network connection is opened (spec 9283-9285).
    #[must_use]
    pub const fn is_structural(self) -> bool {
        matches!(self, Self::RootSchema | Self::Scalars)
    }

    /// Returns the fixed lowercase stage label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::RootSchema => "root-schema",
            Self::Scalars => "scalars",
            Self::PathsAndFileTypes => "paths-and-file-types",
            Self::KeyParsing => "key-parsing",
            Self::LocalIdentity => "local-identity",
            Self::ListenerUnion => "listener-union",
            Self::Topology => "topology",
            Self::ResourceArithmetic => "resource-arithmetic",
            Self::DatabaseHeader => "database-header",
            Self::E2eeCompatibility => "e2ee-compatibility",
        }
    }
}

/// A static dotted schema path naming the key an issue is about.
///
/// The key never carries an operator-supplied value, so a report is safe to print.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct SchemaKey {
    table: &'static str,
    index: Option<u16>,
    field: &'static str,
}

impl SchemaKey {
    /// Names one key of one table.
    #[must_use]
    pub const fn new(table: &'static str, field: &'static str) -> Self {
        Self {
            table,
            index: None,
            field,
        }
    }

    /// Names one key of one array element.
    #[must_use]
    pub const fn indexed(table: &'static str, index: u16, field: &'static str) -> Self {
        Self {
            table,
            index: Some(index),
            field,
        }
    }

    /// Returns the owning table path.
    #[must_use]
    pub const fn table(self) -> &'static str {
        self.table
    }

    /// Returns the array element index when the key belongs to an array element.
    #[must_use]
    pub const fn index(self) -> Option<u16> {
        self.index
    }

    /// Returns the field name, or an empty string for a whole-table issue.
    #[must_use]
    pub const fn field(self) -> &'static str {
        self.field
    }
}

impl fmt::Display for SchemaKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.table)?;
        if let Some(index) = self.index {
            write!(formatter, "[{index}]")?;
        }
        if !self.field.is_empty() {
            formatter.write_str(".")?;
            formatter.write_str(self.field)?;
        }
        Ok(())
    }
}

/// One safe configuration issue: stage, static key, and closed error.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct ConfigIssue {
    /// The validation stage that found the issue.
    pub stage: ValidationStage,
    /// The static schema key the issue is about.
    pub key: SchemaKey,
    /// The closed error class.
    pub error: ConfigError,
}

impl fmt::Display for ConfigIssue {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{}: {}: {}",
            self.stage.as_str(),
            self.key,
            self.error
        )
    }
}

/// Maximum issues one report accumulates (spec 9283).
pub const MAX_REPORTED_ISSUES: usize = 100;

/// The complete ordered set of safe issues from one validation run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigReport {
    issues: Vec<ConfigIssue>,
    truncated: bool,
}

impl ConfigReport {
    /// Borrows the issues in discovery order.
    #[must_use]
    pub fn issues(&self) -> &[ConfigIssue] {
        &self.issues
    }

    /// Returns whether more issues existed than the report retains.
    #[must_use]
    pub const fn is_truncated(&self) -> bool {
        self.truncated
    }

    /// Returns the first issue's error, which maintenance callers use as the
    /// single closed failure.
    #[must_use]
    pub fn first_error(&self) -> ConfigError {
        self.issues
            .first()
            .map_or(ConfigError::InvalidDocument, |issue| issue.error)
    }

    /// Returns whether any issue belongs to a structural stage.
    #[must_use]
    pub fn has_structural_issue(&self) -> bool {
        self.issues.iter().any(|issue| issue.stage.is_structural())
    }

    /// Returns whether every issue matches the given predicate.
    #[must_use]
    pub fn all(&self, predicate: impl Fn(&ConfigIssue) -> bool) -> bool {
        self.issues.iter().all(predicate)
    }
}

impl fmt::Display for ConfigReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (position, issue) in self.issues.iter().enumerate() {
            if position > 0 {
                formatter.write_str("; ")?;
            }
            write!(formatter, "{issue}")?;
        }
        if self.truncated {
            formatter.write_str("; further issues omitted")?;
        }
        Ok(())
    }
}

impl std::error::Error for ConfigReport {}

/// Bounded issue accumulator shared by every validation stage.
#[derive(Debug, Default)]
pub(crate) struct IssueSink {
    issues: Vec<ConfigIssue>,
    truncated: bool,
}

impl IssueSink {
    pub(crate) fn push(&mut self, stage: ValidationStage, key: SchemaKey, error: ConfigError) {
        if self.issues.len() >= MAX_REPORTED_ISSUES {
            self.truncated = true;
            return;
        }
        self.issues.push(ConfigIssue { stage, key, error });
    }

    /// Records a failed field result and returns the success value otherwise.
    pub(crate) fn field<T>(&mut self, key: SchemaKey, result: Result<T, ConfigError>) -> Option<T> {
        match result {
            Ok(value) => Some(value),
            Err(error) => {
                self.push(stage_for(error), key, error);
                None
            }
        }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.issues.is_empty()
    }

    pub(crate) fn has_structural_issue(&self) -> bool {
        self.issues.iter().any(|issue| issue.stage.is_structural())
    }

    pub(crate) fn into_report(self) -> ConfigReport {
        ConfigReport {
            issues: self.issues,
            truncated: self.truncated,
        }
    }

    pub(crate) fn into_result<T>(self, value: T) -> Result<T, ConfigReport> {
        if self.is_empty() {
            Ok(value)
        } else {
            Err(self.into_report())
        }
    }
}

/// Maps a table-local error to its C.8 stage.
pub(crate) const fn stage_for(error: ConfigError) -> ValidationStage {
    match error {
        ConfigError::InvalidDocument | ConfigError::MissingValue | ConfigError::UnknownKey => {
            ValidationStage::RootSchema
        }
        ConfigError::InvalidValue | ConfigError::Overflow | ConfigError::DeferredTransport => {
            ValidationStage::Scalars
        }
        ConfigError::FileRejected | ConfigError::HostControl => ValidationStage::PathsAndFileTypes,
        ConfigError::Topology => ValidationStage::Topology,
    }
}
