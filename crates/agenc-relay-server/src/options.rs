//! Closed table-driven command option parsing.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{OsStr, OsString};
use std::path::PathBuf;

/// Whether one option consumes a following value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OptionKind {
    /// The option consumes one nonempty value.
    Value,
    /// The option is a presence flag.
    Flag,
}

/// One accepted option spelling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OptionSpec {
    /// Exact long option.
    pub name: &'static str,
    /// Value or flag behavior.
    pub kind: OptionKind,
}

impl OptionSpec {
    /// Declares a valued option.
    pub(crate) const fn value(name: &'static str) -> Self {
        Self {
            name,
            kind: OptionKind::Value,
        }
    }

    /// Declares a flag.
    pub(crate) const fn flag(name: &'static str) -> Self {
        Self {
            name,
            kind: OptionKind::Flag,
        }
    }
}

/// Validated option values keyed by their static specification names.
pub(crate) struct ParsedOptions {
    values: BTreeMap<&'static str, OsString>,
    flags: BTreeSet<&'static str>,
}

impl ParsedOptions {
    /// Parses a complete option vector, rejecting unknowns and duplicates.
    pub(crate) fn parse(arguments: &[OsString], specs: &[OptionSpec]) -> Result<Self, ()> {
        let mut parsed = Self {
            values: BTreeMap::new(),
            flags: BTreeSet::new(),
        };
        let mut cursor = 0_usize;
        while let Some(argument) = arguments.get(cursor) {
            let name = argument.to_str().ok_or(())?;
            let spec = specs.iter().find(|spec| spec.name == name).ok_or(())?;
            cursor = cursor.checked_add(1).ok_or(())?;
            parsed.admit(*spec, arguments.get(cursor))?;
            if spec.kind == OptionKind::Value {
                cursor = cursor.checked_add(1).ok_or(())?;
            }
        }
        Ok(parsed)
    }

    fn admit(&mut self, spec: OptionSpec, next: Option<&OsString>) -> Result<(), ()> {
        match spec.kind {
            OptionKind::Flag if self.flags.insert(spec.name) => Ok(()),
            OptionKind::Flag => Err(()),
            OptionKind::Value => {
                let value = next.ok_or(())?;
                if invalid_value(value) || self.values.insert(spec.name, value.clone()).is_some() {
                    return Err(());
                }
                Ok(())
            }
        }
    }

    /// Takes one required path.
    pub(crate) fn required_path(&mut self, name: &'static str) -> Result<PathBuf, ()> {
        self.values.remove(name).map(PathBuf::from).ok_or(())
    }

    /// Takes one optional path.
    pub(crate) fn optional_path(&mut self, name: &'static str) -> Option<PathBuf> {
        self.values.remove(name).map(PathBuf::from)
    }

    /// Takes one required UTF-8 value.
    pub(crate) fn required_text(&mut self, name: &'static str) -> Result<String, ()> {
        self.values
            .remove(name)
            .and_then(|value| value.into_string().ok())
            .ok_or(())
    }

    /// Takes one optional UTF-8 value.
    pub(crate) fn optional_text(&mut self, name: &'static str) -> Result<Option<String>, ()> {
        self.values
            .remove(name)
            .map(|value| value.into_string().map_err(|_| ()))
            .transpose()
    }

    /// Returns whether a flag occurred.
    pub(crate) fn flag(&self, name: &'static str) -> bool {
        self.flags.contains(name)
    }
}

fn invalid_value(value: &OsStr) -> bool {
    value.is_empty() || value.to_str().is_some_and(|text| text.starts_with("--"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn arguments(values: &[&str]) -> Vec<OsString> {
        values.iter().map(OsString::from).collect()
    }

    #[test]
    fn parser_accepts_any_pair_order_and_rejects_every_ambiguous_shape() -> Result<(), ()> {
        let specs = [OptionSpec::value("--one"), OptionSpec::flag("--flag")];
        let mut parsed = ParsedOptions::parse(&arguments(&["--flag", "--one", "value"]), &specs)?;
        assert!(parsed.flag("--flag"));
        assert_eq!(parsed.required_text("--one")?, "value");
        for invalid in [
            arguments(&["--one"]),
            arguments(&["--one", ""]),
            arguments(&["--one", "--flag"]),
            arguments(&["--unknown"]),
            arguments(&["--flag", "--flag"]),
            arguments(&["--one", "a", "--one", "b"]),
        ] {
            assert!(ParsedOptions::parse(&invalid, &specs).is_err());
        }
        Ok(())
    }
}
