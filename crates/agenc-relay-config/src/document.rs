//! Untrusted TOML intermediate and closed-key accessors.
//!
//! `toml` 1.1.4 rejects duplicate keys, redefined tables, and duplicate
//! inline-table keys at parse time; the crate tests pin all four shapes.
//! TOML has no include or environment-interpolation syntax, and every value
//! accessor below refuses implicit type conversion by using the exact `as_*`
//! projection for the expected type (spec 4274-4277).

use toml::{Table, Value};

use crate::error::ConfigError;

/// Parses one untrusted document into the closed root table.
pub(crate) fn parse_document(text: &str) -> Result<Table, ConfigError> {
    text.parse::<Table>()
        .map_err(|_| ConfigError::InvalidDocument)
}

/// Rejects any key outside the closed allowed set.
pub(crate) fn check_keys(table: &Table, allowed: &[&str]) -> Result<(), ConfigError> {
    if table.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(ConfigError::UnknownKey);
    }
    Ok(())
}

/// Requires every listed key to be present and no other key (used by manifests).
pub(crate) fn require_exact_keys(table: &Table, expected: &[&str]) -> Result<(), ConfigError> {
    check_keys(table, expected)?;
    if table.len() != expected.len() {
        return Err(ConfigError::MissingValue);
    }
    Ok(())
}

/// Borrows one required sub-table.
pub(crate) fn table<'a>(parent: &'a Table, name: &str) -> Result<&'a Table, ConfigError> {
    match parent.get(name) {
        None => Err(ConfigError::MissingValue),
        Some(Value::Table(inner)) => Ok(inner),
        Some(_) => Err(ConfigError::InvalidDocument),
    }
}

/// Borrows one array of tables, requiring the element count to sit in a range.
pub(crate) fn table_array<'a>(
    parent: &'a Table,
    name: &str,
    minimum: usize,
    maximum: usize,
) -> Result<Vec<&'a Table>, ConfigError> {
    let rows = match parent.get(name) {
        None if minimum == 0 => return Ok(Vec::new()),
        None => return Err(ConfigError::MissingValue),
        Some(Value::Array(rows)) => rows,
        Some(_) => return Err(ConfigError::InvalidDocument),
    };
    if !(minimum..=maximum).contains(&rows.len()) {
        return Err(ConfigError::InvalidValue);
    }
    let mut tables = Vec::new();
    tables
        .try_reserve_exact(rows.len())
        .map_err(|_| ConfigError::InvalidValue)?;
    for row in rows {
        tables.push(row.as_table().ok_or(ConfigError::InvalidDocument)?);
    }
    Ok(tables)
}

/// Borrows one required non-empty string.
pub(crate) fn string<'a>(table: &'a Table, name: &str) -> Result<&'a str, ConfigError> {
    optional_string(table, name)?.ok_or(ConfigError::MissingValue)
}

/// Borrows one optional string; an empty string is invalid (spec 8885).
pub(crate) fn optional_string<'a>(
    table: &'a Table,
    name: &str,
) -> Result<Option<&'a str>, ConfigError> {
    match table.get(name) {
        None => Ok(None),
        Some(Value::String(text)) if text.is_empty() => Err(ConfigError::InvalidValue),
        Some(Value::String(text)) => Ok(Some(text.as_str())),
        Some(_) => Err(ConfigError::MissingValue),
    }
}

/// Reads one required unsigned integer.
pub(crate) fn unsigned(table: &Table, name: &str) -> Result<u64, ConfigError> {
    optional_unsigned(table, name)?.ok_or(ConfigError::MissingValue)
}

/// Reads one optional unsigned integer; a negative value is invalid (spec 8881).
pub(crate) fn optional_unsigned(table: &Table, name: &str) -> Result<Option<u64>, ConfigError> {
    match table.get(name) {
        None => Ok(None),
        Some(Value::Integer(value)) => u64::try_from(*value)
            .map(Some)
            .map_err(|_| ConfigError::InvalidValue),
        Some(_) => Err(ConfigError::MissingValue),
    }
}

/// Reads one required boolean.
pub(crate) fn boolean(table: &Table, name: &str) -> Result<bool, ConfigError> {
    optional_boolean(table, name)?.ok_or(ConfigError::MissingValue)
}

/// Reads one optional boolean.
pub(crate) fn optional_boolean(table: &Table, name: &str) -> Result<Option<bool>, ConfigError> {
    match table.get(name) {
        None => Ok(None),
        Some(Value::Boolean(value)) => Ok(Some(*value)),
        Some(_) => Err(ConfigError::MissingValue),
    }
}

/// Reads an optional array of non-empty strings, bounded by `maximum` elements.
pub(crate) fn string_array<'a>(
    table: &'a Table,
    name: &str,
    maximum: usize,
) -> Result<Vec<&'a str>, ConfigError> {
    let rows = match table.get(name) {
        None => return Ok(Vec::new()),
        Some(Value::Array(rows)) => rows,
        Some(_) => return Err(ConfigError::MissingValue),
    };
    if rows.len() > maximum {
        return Err(ConfigError::InvalidValue);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(rows.len())
        .map_err(|_| ConfigError::InvalidValue)?;
    for row in rows {
        let text = row.as_str().ok_or(ConfigError::MissingValue)?;
        if text.is_empty() {
            return Err(ConfigError::InvalidValue);
        }
        values.push(text);
    }
    Ok(values)
}

/// Reads an optional array of unsigned integers, bounded by `maximum` elements.
pub(crate) fn unsigned_array(
    table: &Table,
    name: &str,
    maximum: usize,
) -> Result<Vec<u64>, ConfigError> {
    let rows = match table.get(name) {
        None => return Ok(Vec::new()),
        Some(Value::Array(rows)) => rows,
        Some(_) => return Err(ConfigError::MissingValue),
    };
    if rows.len() > maximum {
        return Err(ConfigError::InvalidValue);
    }
    let mut values = Vec::new();
    values
        .try_reserve_exact(rows.len())
        .map_err(|_| ConfigError::InvalidValue)?;
    for row in rows {
        let value = row.as_integer().ok_or(ConfigError::MissingValue)?;
        values.push(u64::try_from(value).map_err(|_| ConfigError::InvalidValue)?);
    }
    Ok(values)
}
