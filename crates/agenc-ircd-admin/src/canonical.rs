//! Canonical command-line form and canonical decimal parsing (spec 4408-4412).

use crate::{AdminError, MAX_ADMIN_COMMAND_BYTES};

/// Section 9.1 accepts at most 15 parameters after the command (spec 603).
pub const MAX_COMMAND_PARAMETERS: usize = 15;

/// Longest canonical decimal a `u64` can hold: `18446744073709551615`.
const MAX_DECIMAL_DIGITS: usize = 20;

/// Parses a canonical unsigned decimal: digits only, no sign, no leading
/// zero except the single digit `0`, fitting `u64` (spec 4406-4407).
pub fn parse_canonical_u64(text: &[u8]) -> Result<u64, AdminError> {
    if text.is_empty() || text.len() > MAX_DECIMAL_DIGITS {
        return Err(AdminError::Counter);
    }
    if text.len() > 1 && text.first() == Some(&b'0') {
        return Err(AdminError::Counter);
    }
    let mut value: u64 = 0;
    for byte in text {
        let digit = match byte {
            b'0'..=b'9' => u64::from(byte - b'0'),
            _ => return Err(AdminError::Counter),
        };
        value = value
            .checked_mul(10)
            .and_then(|shifted| shifted.checked_add(digit))
            .ok_or(AdminError::Counter)?;
    }
    Ok(value)
}

/// A command line proven canonical: uppercase verb, exactly one SPACE between
/// parameters, no unnecessary trailing-parameter form, no CR, LF, NUL, or
/// other control byte, valid UTF-8, and at most fifteen parameters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CanonicalCommand<'a> {
    line: &'a str,
    verb: &'a str,
}

impl<'a> CanonicalCommand<'a> {
    /// Proves that `bytes` is the one canonical rendering of its command.
    pub fn check(bytes: &'a [u8]) -> Result<Self, AdminError> {
        if bytes.is_empty() || bytes.len() > MAX_ADMIN_COMMAND_BYTES {
            return Err(AdminError::Framing);
        }
        let line = std::str::from_utf8(bytes).map_err(|_| AdminError::Canonical)?;
        if line.chars().any(char::is_control) {
            return Err(AdminError::Canonical);
        }
        if line.starts_with(' ') || line.ends_with(' ') || line.contains("  ") {
            return Err(AdminError::Canonical);
        }
        let verb = line.split(' ').next().ok_or(AdminError::Canonical)?;
        if verb.is_empty() || !verb.bytes().all(|byte| byte.is_ascii_uppercase()) {
            return Err(AdminError::Canonical);
        }
        let command = Self { line, verb };
        command.check_parameter_forms()?;
        Ok(command)
    }

    /// Rejects a middle parameter that would need the trailing form and a
    /// trailing form that was not necessary (spec 4409-4411).
    fn check_parameter_forms(self) -> Result<(), AdminError> {
        let mut middles = self.line.split(' ').skip(1);
        let mut count = 0_usize;
        while let Some(parameter) = middles.next() {
            count = count.checked_add(1).ok_or(AdminError::Overflow)?;
            if count > MAX_COMMAND_PARAMETERS {
                return Err(AdminError::Canonical);
            }
            if let Some(trailing) = parameter.strip_prefix(':') {
                let rest: Vec<&str> = middles.collect();
                return Self::check_trailing(trailing, &rest);
            }
        }
        Ok(())
    }

    fn check_trailing(first_word: &str, rest: &[&str]) -> Result<(), AdminError> {
        // The trailing form is necessary only when the value is empty,
        // contains a SPACE (so it spans several words), or begins with ':'.
        let necessary = first_word.is_empty() || !rest.is_empty() || first_word.starts_with(':');
        if necessary {
            Ok(())
        } else {
            Err(AdminError::Canonical)
        }
    }

    /// Returns the uppercase verb.
    #[must_use]
    pub const fn verb(self) -> &'a str {
        self.verb
    }

    /// Returns the exact canonical bytes without CRLF.
    #[must_use]
    pub const fn as_bytes(self) -> &'a [u8] {
        self.line.as_bytes()
    }

    /// Returns the parameters after the verb, with the trailing value joined
    /// and stripped of its leading colon.
    #[must_use]
    pub fn parameters(self) -> Vec<&'a str> {
        let mut parameters = Vec::new();
        let after_verb = self.line.get(self.verb.len()..).unwrap_or("");
        let after_verb = after_verb.strip_prefix(' ').unwrap_or(after_verb);
        if after_verb.is_empty() {
            return parameters;
        }
        let mut cursor = after_verb;
        loop {
            if let Some(trailing) = cursor.strip_prefix(':') {
                parameters.push(trailing);
                return parameters;
            }
            match cursor.split_once(' ') {
                Some((middle, rest)) => {
                    parameters.push(middle);
                    cursor = rest;
                }
                None => {
                    parameters.push(cursor);
                    return parameters;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CanonicalCommand, parse_canonical_u64};
    use crate::AdminError;

    #[test]
    fn canonical_decimal_accepts_only_one_form_per_value() {
        assert_eq!(parse_canonical_u64(b"0"), Ok(0));
        assert_eq!(parse_canonical_u64(b"7"), Ok(7));
        assert_eq!(parse_canonical_u64(b"18446744073709551615"), Ok(u64::MAX));
        for rejected in [
            &b""[..],
            b"00",
            b"01",
            b"+1",
            b"-1",
            b"1a",
            b" 1",
            b"18446744073709551616",
            b"184467440737095516150",
        ] {
            assert_eq!(parse_canonical_u64(rejected), Err(AdminError::Counter));
        }
    }

    #[test]
    fn canonical_form_rejects_every_noncanonical_shape() -> Result<(), AdminError> {
        let accepted = CanonicalCommand::check(b"KILL abc :reason text")?;
        assert_eq!(accepted.verb(), "KILL");
        assert_eq!(accepted.parameters(), vec!["abc", "reason text"]);
        assert_eq!(CanonicalCommand::check(b"REHASH :")?.parameters(), vec![""]);
        assert_eq!(
            CanonicalCommand::check(b"REHASH ::x")?.parameters(),
            vec![":x"]
        );
        assert_eq!(CanonicalCommand::check(b"QUIT")?.parameters().len(), 0);
        assert_eq!(
            CanonicalCommand::check(b"").err(),
            Some(AdminError::Framing)
        );
        for rejected in [
            &b" QUIT"[..],
            b"QUIT ",
            b"QUIT  x",
            b"quit",
            b"KILL abc :single",
            b"KILL\tabc",
            b"KILL abc\r",
            b"KILL abc\n",
            b"KILL a\0b",
            b"1ABC x",
            b"K1LL x",
            b"A 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16",
            &[0xff, b'A'],
        ] {
            assert_eq!(
                CanonicalCommand::check(rejected).err(),
                Some(AdminError::Canonical),
                "{rejected:?}"
            );
        }
        let long = vec![b'A'; 4_097];
        assert_eq!(CanonicalCommand::check(&long), Err(AdminError::Framing));
        let exact = vec![b'A'; 4_096];
        assert!(CanonicalCommand::check(&exact).is_ok());
        Ok(())
    }
}
