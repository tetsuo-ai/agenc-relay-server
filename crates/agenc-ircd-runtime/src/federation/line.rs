//! Bounded splitting of one federation line into its tag, prefix, command,
//! and parameters (spec 20.2, B.8).
//!
//! Federation lines are a narrow subset of the IRC line grammar: at most one
//! `@agenc.ag/fed=` tag, a mandatory server prefix, an uppercase command, and
//! space-separated parameters that never start with a colon. The client
//! parser deliberately rejects prefixed lines, so this splitter exists
//! instead of widening it.

use agenc_ircd_federation_wire::FEDERATION_FRAGMENT_TAG_NAME;

/// The most parameters any registered form carries, plus its subcommand.
pub const MAX_LINE_PARAMETERS: usize = 8;

/// Closed reasons a line cannot be split.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LineError {
    /// The line was empty or had no command.
    Empty,
    /// A forbidden control byte or double space was present.
    Syntax,
    /// A tag other than the one fragment tag, or a malformed one, was present.
    Tag,
    /// The line had no server prefix.
    MissingPrefix,
    /// A parameter began with a colon or more than the maximum were present.
    Parameters,
}

/// The borrowed parts of one line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LineParts<'a> {
    /// The fragment tag value, when present.
    pub tag_value: Option<&'a str>,
    /// The server prefix without its leading colon.
    pub prefix: &'a str,
    /// The command token.
    pub command: &'a str,
    /// The parameters in order, subcommand included.
    pub parameters: Vec<&'a str>,
}

/// Splits one complete line without its CRLF.
pub fn split_line(line: &str) -> Result<LineParts<'_>, LineError> {
    validate_line_bytes(line)?;
    let mut tokens = line.split(' ');
    let mut first = tokens.next().ok_or(LineError::Empty)?;
    let mut tag_value = None;
    if let Some(tag) = first.strip_prefix('@') {
        tag_value = Some(split_tag(tag)?);
        first = tokens.next().ok_or(LineError::MissingPrefix)?;
    }
    let prefix = first.strip_prefix(':').ok_or(LineError::MissingPrefix)?;
    if prefix.is_empty() {
        return Err(LineError::MissingPrefix);
    }
    let command = tokens
        .next()
        .filter(|command| !command.is_empty())
        .ok_or(LineError::Empty)?;
    let mut parameters = Vec::new();
    for token in tokens {
        if token.starts_with(':') || parameters.len() >= MAX_LINE_PARAMETERS {
            return Err(LineError::Parameters);
        }
        parameters.push(token);
    }
    Ok(LineParts {
        tag_value,
        prefix,
        command,
        parameters,
    })
}

fn validate_line_bytes(line: &str) -> Result<(), LineError> {
    if line.is_empty() {
        return Err(LineError::Empty);
    }
    let control = line
        .bytes()
        .any(|byte| byte == 0 || byte == b'\r' || byte == b'\n');
    if control || line.contains("  ") || line.starts_with(' ') || line.ends_with(' ') {
        return Err(LineError::Syntax);
    }
    Ok(())
}

fn split_tag(tag: &str) -> Result<&str, LineError> {
    let (name, value) = tag.split_once('=').ok_or(LineError::Tag)?;
    if name != FEDERATION_FRAGMENT_TAG_NAME || value.is_empty() || value.contains(';') {
        return Err(LineError::Tag);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splits_tagged_and_untagged_lines() -> Result<(), LineError> {
        let parts = split_line(":core.example FACK a 1 b")?;
        assert_eq!(parts.tag_value, None);
        assert_eq!(parts.prefix, "core.example");
        assert_eq!(parts.command, "FACK");
        assert_eq!(parts.parameters, vec!["a", "1", "b"]);
        let parts = split_line("@agenc.ag/fed=v1.x.0.1.3.YWJj :edge.example FREQUEST a b")?;
        assert_eq!(parts.tag_value, Some("v1.x.0.1.3.YWJj"));
        assert_eq!(parts.command, "FREQUEST");
        assert_eq!(parts.parameters.len(), 2);
        let bare = split_line(":edge.example FORIGIN READY")?;
        assert_eq!(bare.parameters, vec!["READY"]);
        Ok(())
    }

    #[test]
    fn rejects_every_grammar_violation() {
        assert_eq!(split_line(""), Err(LineError::Empty));
        assert_eq!(split_line(":a"), Err(LineError::Empty));
        assert_eq!(split_line(":a FACK  x"), Err(LineError::Syntax));
        assert_eq!(split_line(" :a FACK"), Err(LineError::Syntax));
        assert_eq!(split_line(":a FACK "), Err(LineError::Syntax));
        assert_eq!(split_line(":a FACK\u{0}"), Err(LineError::Syntax));
        assert_eq!(split_line("FACK a"), Err(LineError::MissingPrefix));
        assert_eq!(split_line(": FACK a"), Err(LineError::MissingPrefix));
        assert_eq!(split_line("@x=y :a FACK"), Err(LineError::Tag));
        assert_eq!(split_line("@agenc.ag/fed :a FACK"), Err(LineError::Tag));
        assert_eq!(split_line("@agenc.ag/fed= :a FACK"), Err(LineError::Tag));
        assert_eq!(split_line("@agenc.ag/fed=a;b :a FACK"), Err(LineError::Tag));
        assert_eq!(split_line("@agenc.ag/fed=v"), Err(LineError::MissingPrefix));
        assert_eq!(split_line(":a FACK :trailing"), Err(LineError::Parameters));
        assert_eq!(
            split_line(":a FACK 1 2 3 4 5 6 7 8 9"),
            Err(LineError::Parameters)
        );
    }
}
