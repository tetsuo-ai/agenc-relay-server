//! Bounded splitting of one federation line into its tag, prefix, command,
//! and parameters (spec 20.2, B.8).
//!
//! Federation lines are a narrow subset of the IRC line grammar: at most one
//! `@agenc.ag/fed=` tag, a mandatory server prefix, an uppercase command, and
//! space-separated parameters that never start with a colon. The client
//! parser deliberately rejects prefixed lines, so this splitter exists
//! instead of widening it.

use agenc_ircd_e2ee::federation::frames::is_companion_command;
use agenc_ircd_e2ee::wire::fragment::SERVER_FRAGMENT_TAG as COMPANION_FRAGMENT_TAG_NAME;
use agenc_ircd_federation_wire::FEDERATION_FRAGMENT_TAG_NAME;

/// The most parameters any registered base form carries, plus its
/// subcommand.
pub const MAX_LINE_PARAMETERS: usize = 8;
/// The most parameters any companion form carries: `ECAP IRCMLS OFFER`
/// with its fourteen-value tuple.
pub const MAX_COMPANION_LINE_PARAMETERS: usize = 16;

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
    /// Whether the tag is the companion `agenc.ag/e2ee` key rather than
    /// the base fragment key.
    pub companion_tag: bool,
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
    let mut companion_tag = false;
    if let Some(tag) = first.strip_prefix('@') {
        let (companion, value) = split_tag(tag)?;
        tag_value = Some(value);
        companion_tag = companion;
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
    let limit = if is_companion_command(command) {
        MAX_COMPANION_LINE_PARAMETERS
    } else {
        MAX_LINE_PARAMETERS
    };
    let mut parameters = Vec::new();
    for token in tokens {
        if token.starts_with(':') || parameters.len() >= limit {
            return Err(LineError::Parameters);
        }
        parameters.push(token);
    }
    Ok(LineParts {
        tag_value,
        companion_tag,
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

/// Splits the one tag: the base fragment key or the companion key.
fn split_tag(tag: &str) -> Result<(bool, &str), LineError> {
    let (name, value) = tag.split_once('=').ok_or(LineError::Tag)?;
    let companion = name == COMPANION_FRAGMENT_TAG_NAME;
    if (name != FEDERATION_FRAGMENT_TAG_NAME && !companion)
        || value.is_empty()
        || value.contains(';')
    {
        return Err(LineError::Tag);
    }
    Ok((companion, value))
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

    #[test]
    fn companion_lines_carry_the_ecap_arity() -> Result<(), LineError> {
        let sixteen = ":a ECAP IRCMLS OFFER 3 4 5 6 7 8 9 10 11 12 13 14 15 16";
        assert_eq!(split_line(sixteen)?.parameters.len(), 16);
        assert_eq!(
            split_line(":a ECAP IRCMLS OFFER 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17"),
            Err(LineError::Parameters)
        );
        assert_eq!(
            split_line(":a ESTATE BEGIN 1 2 3 4 5 6 7 8")?
                .parameters
                .len(),
            9
        );
        assert_eq!(
            split_line(":a FSTATE BEGIN 1 2 3 4 5 6 7 8"),
            Err(LineError::Parameters)
        );
        Ok(())
    }
}

#[cfg(test)]
mod companion_tests {
    use super::*;

    #[test]
    fn splits_the_companion_tag_and_marks_it() -> Result<(), LineError> {
        let parts = split_line("@agenc.ag/e2ee=v1.x.0.1.3.YWJj :edge.example EREQUEST a b")?;
        assert_eq!(parts.tag_value, Some("v1.x.0.1.3.YWJj"));
        assert!(parts.companion_tag);
        let base = split_line("@agenc.ag/fed=v1.x.0.1.3.YWJj :edge.example FREQUEST a b")?;
        assert!(!base.companion_tag);
        assert_eq!(split_line("@agenc.ag/e2ee= :a EACK"), Err(LineError::Tag));
        Ok(())
    }
}
