//! The post-authentication admin tag line (spec 4402-4432).

use agenc_ircd_crypto::Ed25519Signature;

use crate::base64::{decode_fixed_base64url, encode_base64url};
use crate::canonical::parse_canonical_u64;
use crate::{
    AdminError, ConfirmationToken, MAX_ADMIN_COMMAND_BYTES, MAX_ADMIN_LINE_BYTES,
    MAX_ADMIN_TAG_PREFIX_BYTES,
};

const ADMIN_TAG_KEY: &[u8] = b"+agenc.ag/admin";
const CONFIRM_TAG_KEY: &[u8] = b"+agenc.ag/confirm";
const ADMIN_TAG_VERSION_PREFIX: &[u8] = b"v1.";
/// 86 characters of canonical base64url for a 64-byte signature.
const SIGNATURE_TEXT_BYTES: usize = 86;

/// One parsed administrative line: the signed tag facts and the command bytes.
pub struct AdminLine<'a> {
    counter: u64,
    signature: Ed25519Signature,
    confirmation: Option<ConfirmationToken>,
    command: &'a [u8],
}

impl<'a> AdminLine<'a> {
    /// Returns the canonical command counter from the tag.
    #[must_use]
    pub const fn counter(&self) -> u64 {
        self.counter
    }

    /// Returns the operator signature from the tag.
    #[must_use]
    pub const fn signature(&self) -> Ed25519Signature {
        self.signature
    }

    /// Returns the confirmation token when the confirm tag was present.
    #[must_use]
    pub const fn confirmation(&self) -> Option<&ConfirmationToken> {
        self.confirmation.as_ref()
    }

    /// Takes the confirmation token out of the line.
    #[must_use]
    pub fn take_confirmation(&mut self) -> Option<ConfirmationToken> {
        self.confirmation.take()
    }

    /// Returns the command bytes after the tag section, without CRLF.
    #[must_use]
    pub const fn command(&self) -> &'a [u8] {
        self.command
    }
}

/// Parses one CRLF-terminated administrative line into its tag facts.
///
/// The line must be at most 4,610 bytes including CRLF, start with `@`, keep
/// the tag section within 512 bytes through the separating SPACE, carry
/// exactly one `+agenc.ag/admin=v1.<counter>.<signature>` tag and at most one
/// `+agenc.ag/confirm=<token>` tag in bytewise key order, and leave 1..4096
/// command bytes (spec 4402-4432). Nothing is interpreted beyond that.
pub fn parse_admin_line(line: &[u8]) -> Result<AdminLine<'_>, AdminError> {
    if line.len() > MAX_ADMIN_LINE_BYTES {
        return Err(AdminError::Framing);
    }
    let content = line.strip_suffix(b"\r\n").ok_or(AdminError::Framing)?;
    if content.iter().any(|byte| matches!(byte, b'\r' | b'\n' | 0)) {
        return Err(AdminError::Framing);
    }
    std::str::from_utf8(content).map_err(|_| AdminError::Framing)?;
    let tags = content.strip_prefix(b"@").ok_or(AdminError::Tag)?;
    let space = tags
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(AdminError::Tag)?;
    // The prefix bound counts '@' and the separating SPACE (spec 4429).
    if space.checked_add(2).ok_or(AdminError::Overflow)? > MAX_ADMIN_TAG_PREFIX_BYTES {
        return Err(AdminError::Framing);
    }
    let (tag_section, rest) = tags.split_at_checked(space).ok_or(AdminError::Tag)?;
    let command = rest.get(1..).ok_or(AdminError::Tag)?;
    if command.is_empty() || command.len() > MAX_ADMIN_COMMAND_BYTES {
        return Err(AdminError::Framing);
    }
    let (counter, signature, confirmation) = parse_tag_section(tag_section)?;
    Ok(AdminLine {
        counter,
        signature,
        confirmation,
        command,
    })
}

type TagFacts = (u64, Ed25519Signature, Option<ConfirmationToken>);

fn parse_tag_section(section: &[u8]) -> Result<TagFacts, AdminError> {
    let mut tags = section.split(|byte| *byte == b';');
    let first = tags.next().ok_or(AdminError::Tag)?;
    let (key, value) = split_tag(first)?;
    if key != ADMIN_TAG_KEY {
        return Err(AdminError::Tag);
    }
    let (counter, signature) = parse_admin_value(value)?;
    let confirmation = match tags.next() {
        None => None,
        Some(second) => {
            let (key, value) = split_tag(second)?;
            if key != CONFIRM_TAG_KEY {
                return Err(AdminError::Tag);
            }
            Some(ConfirmationToken::parse(value)?)
        }
    };
    if tags.next().is_some() {
        return Err(AdminError::Tag);
    }
    Ok((counter, signature, confirmation))
}

fn split_tag(tag: &[u8]) -> Result<(&[u8], &[u8]), AdminError> {
    let equals = tag
        .iter()
        .position(|byte| *byte == b'=')
        .ok_or(AdminError::Tag)?;
    let (key, rest) = tag.split_at_checked(equals).ok_or(AdminError::Tag)?;
    let value = rest.get(1..).ok_or(AdminError::Tag)?;
    Ok((key, value))
}

fn parse_admin_value(value: &[u8]) -> Result<(u64, Ed25519Signature), AdminError> {
    let body = value
        .strip_prefix(ADMIN_TAG_VERSION_PREFIX)
        .ok_or(AdminError::Tag)?;
    let dot = body
        .iter()
        .position(|byte| *byte == b'.')
        .ok_or(AdminError::Tag)?;
    let (counter_text, rest) = body.split_at_checked(dot).ok_or(AdminError::Tag)?;
    let signature_text = rest.get(1..).ok_or(AdminError::Tag)?;
    if signature_text.len() != SIGNATURE_TEXT_BYTES {
        return Err(AdminError::Tag);
    }
    let counter = parse_canonical_u64(counter_text)?;
    let signature =
        decode_fixed_base64url::<64>(signature_text).map(Ed25519Signature::from_bytes)?;
    Ok((counter, signature))
}

/// Renders the exact tag section a client sends (used by tests and tooling).
#[must_use]
pub fn render_admin_tag(
    counter: u64,
    signature: &Ed25519Signature,
    confirmation: Option<&ConfirmationToken>,
) -> String {
    let mut tag = format!(
        "@+agenc.ag/admin=v1.{counter}.{}",
        encode_base64url(signature.as_bytes())
    );
    if let Some(token) = confirmation {
        tag.push_str(";+agenc.ag/confirm=");
        tag.push_str(&token.to_base64url());
    }
    tag
}

#[cfg(test)]
mod tests {
    use agenc_ircd_crypto::Ed25519Signature;

    use super::{parse_admin_line, render_admin_tag};
    use crate::{AdminError, ConfirmationToken, MAX_ADMIN_LINE_BYTES};

    fn signature() -> Ed25519Signature {
        Ed25519Signature::from_bytes([0x41; 64])
    }

    fn line(counter: u64, confirm: bool, command: &str) -> Vec<u8> {
        let token = ConfirmationToken::from_bytes([5; 16]);
        let tag = render_admin_tag(counter, &signature(), confirm.then_some(&token));
        format!("{tag} {command}\r\n").into_bytes()
    }

    #[test]
    fn valid_lines_expose_counter_signature_token_and_command() -> Result<(), AdminError> {
        let plain = line(0, false, "STATS RUNTIME");
        let parsed = parse_admin_line(&plain)?;
        assert_eq!(parsed.counter(), 0);
        assert_eq!(parsed.signature(), signature());
        assert!(parsed.confirmation().is_none());
        assert_eq!(parsed.command(), b"STATS RUNTIME");

        let with_token = line(18_446_744_073_709_551_615, true, "DIE :x");
        let mut confirmed = parse_admin_line(&with_token)?;
        assert_eq!(confirmed.counter(), u64::MAX);
        let token = confirmed
            .take_confirmation()
            .ok_or(AdminError::Confirmation)?;
        assert!(token.matches(&ConfirmationToken::from_bytes([5; 16])));
        assert!(confirmed.take_confirmation().is_none());
        Ok(())
    }

    #[test]
    fn framing_bounds_are_exact() {
        let tag = render_admin_tag(7, &signature(), None);
        // A tag section of exactly 512 bytes including '@' and the SPACE.
        let padding = 512 - tag.len() - 1;
        let mut confirm_padded = format!("{tag};+agenc.ag/confirm=");
        // Fill the confirm value to reach the bound; the value is then an
        // invalid token, which must be reported as a token error, not framing.
        confirm_padded.push_str(&"A".repeat(padding - ";+agenc.ag/confirm=".len()));
        let at_bound = format!("{confirm_padded} QUIT\r\n");
        assert_eq!(at_bound.find(' '), Some(511));
        assert_eq!(
            parse_admin_line(at_bound.as_bytes()).err(),
            Some(AdminError::Token)
        );
        let over = format!("{confirm_padded}A QUIT\r\n");
        assert_eq!(
            parse_admin_line(over.as_bytes()).err(),
            Some(AdminError::Framing)
        );

        let command_max = "A".repeat(4_096);
        let exact = format!("{tag} {command_max}\r\n");
        assert!(parse_admin_line(exact.as_bytes()).is_ok());
        let command_over = "A".repeat(4_097);
        let too_long = format!("{tag} {command_over}\r\n");
        assert_eq!(
            parse_admin_line(too_long.as_bytes()).err(),
            Some(AdminError::Framing)
        );

        let full_tag = format!("{confirm_padded} {}\r\n", "B".repeat(4_096));
        assert_eq!(full_tag.len(), MAX_ADMIN_LINE_BYTES);
        assert_eq!(
            parse_admin_line(full_tag.as_bytes()).err(),
            Some(AdminError::Token)
        );
        let mut longer = full_tag.clone().into_bytes();
        longer.insert(600, b'B');
        assert_eq!(longer.len(), MAX_ADMIN_LINE_BYTES + 1);
        assert_eq!(parse_admin_line(&longer).err(), Some(AdminError::Framing));
        let mut shorter = full_tag.into_bytes();
        shorter.remove(600);
        assert_eq!(shorter.len(), MAX_ADMIN_LINE_BYTES - 1);
        assert_eq!(parse_admin_line(&shorter).err(), Some(AdminError::Token));
    }

    #[test]
    fn malformed_tag_shapes_are_rejected() {
        let sig = "A".repeat(86);
        let baseline = "@+agenc.ag/admin=v1.0.SIG QUIT\r\n".replace("SIG", &sig);
        assert!(parse_admin_line(baseline.as_bytes()).is_ok());
        let cases: [(&str, AdminError); 13] = [
            ("QUIT\r\n", AdminError::Tag),
            ("@+agenc.ag/admin=v1.0.", AdminError::Framing),
            ("@+agenc.ag/admin=v1.0.SIG QUIT\n", AdminError::Framing),
            ("@+agenc.ag/admin=v1.0.SIG QUIT\r\r\n", AdminError::Framing),
            ("@+agenc.ag/admin=v1.0.SIG\r\n", AdminError::Tag),
            ("@+agenc.ag/admin=v1.0.SIG \r\n", AdminError::Framing),
            ("@+agenc.ag/other=v1.0.SIG QUIT\r\n", AdminError::Tag),
            ("@+agenc.ag/admin QUIT\r\n", AdminError::Tag),
            ("@+agenc.ag/admin=v2.0.SIG QUIT\r\n", AdminError::Tag),
            ("@+agenc.ag/admin=v1.0 QUIT\r\n", AdminError::Tag),
            ("@+agenc.ag/admin=v1.01.SIG QUIT\r\n", AdminError::Counter),
            (
                "@+agenc.ag/admin=v1.0.SIG;+agenc.ag/admin=v1.1.SIG QUIT\r\n",
                AdminError::Tag,
            ),
            (
                "@+agenc.ag/confirm=AAAAAAAAAAAAAAAAAAAAAA;+agenc.ag/admin=v1.0.SIG QUIT\r\n",
                AdminError::Tag,
            ),
        ];
        for (template, expected) in cases {
            let text = template.replace("SIG", &sig);
            assert_eq!(
                parse_admin_line(text.as_bytes()).err(),
                Some(expected),
                "{template:?}"
            );
        }
        let three = format!(
            "@+agenc.ag/admin=v1.0.{sig};+agenc.ag/confirm=AAAAAAAAAAAAAAAAAAAAAA;+agenc.ag/confirm=AAAAAAAAAAAAAAAAAAAAAA QUIT\r\n"
        );
        assert_eq!(
            parse_admin_line(three.as_bytes()).err(),
            Some(AdminError::Tag)
        );
        let bad_token = format!("@+agenc.ag/admin=v1.0.{sig};+agenc.ag/confirm=short QUIT\r\n");
        assert_eq!(
            parse_admin_line(bad_token.as_bytes()).err(),
            Some(AdminError::Token)
        );
        let short_signature = format!("@+agenc.ag/admin=v1.0.{} QUIT\r\n", "A".repeat(85));
        assert_eq!(
            parse_admin_line(short_signature.as_bytes()).err(),
            Some(AdminError::Tag)
        );
        let noncanonical_signature = format!("@+agenc.ag/admin=v1.0.{}B QUIT\r\n", "A".repeat(85));
        assert_eq!(
            parse_admin_line(noncanonical_signature.as_bytes()).err(),
            Some(AdminError::Token)
        );
        let invalid_utf8 = [
            b"@+agenc.ag/admin=v1.0.".as_slice(),
            sig.as_bytes(),
            b" QU\xffIT\r\n",
        ]
        .concat();
        assert_eq!(
            parse_admin_line(&invalid_utf8).err(),
            Some(AdminError::Framing)
        );
        let nul = format!("@+agenc.ag/admin=v1.0.{sig} QU\0IT\r\n");
        assert_eq!(
            parse_admin_line(nul.as_bytes()).err(),
            Some(AdminError::Framing)
        );
    }
}
