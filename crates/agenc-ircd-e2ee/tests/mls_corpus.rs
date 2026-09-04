#![forbid(unsafe_code)]
//! The pinned MLS WG interoperability corpus subset parses under the
//! production outer parser (companion Section 21 gates 1 and 3): messages
//! of an enabled suite are accepted with their public fields, messages of
//! any other suite are refused as a profile mismatch, and no line panics
//! or escapes its budget.

use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use agenc_ircd_e2ee::limits::{ENABLED_SUITES, MAX_KEY_PACKAGE_OBJECT, MAX_WELCOME_MAILBOX_OBJECT};
use agenc_ircd_e2ee::mls_outer::{
    MlsOuterMessage, MlsReader, parse_mls_message, verify_key_package_signatures,
};
use agenc_ircd_e2ee::{DecodeBudget, E2eeError};

type TestResult<T = ()> = Result<T, Box<dyn Error>>;

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-data/interoperability/mls")
        .join(name)
}

fn hex(text: &str) -> TestResult<Vec<u8>> {
    let digits: Vec<u8> = text
        .trim()
        .bytes()
        .map(|byte| match byte {
            b'0'..=b'9' => Ok(byte - b'0'),
            b'a'..=b'f' => Ok(byte - b'a' + 10),
            b'A'..=b'F' => Ok(byte - b'A' + 10),
            _ => Err("not a hex digit"),
        })
        .collect::<Result<_, _>>()?;
    if !digits.len().is_multiple_of(2) {
        return Err("odd hex length".into());
    }
    Ok(digits
        .chunks(2)
        .map(|pair| pair.iter().fold(0, |acc, digit| acc << 4 | digit))
        .collect())
}

fn lines(name: &str) -> TestResult<Vec<Vec<u8>>> {
    fs::read_to_string(corpus(name))?
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(hex)
        .collect()
}

fn suite_at(bytes: &[u8], offset: usize) -> Option<u16> {
    let pair = bytes.get(offset..offset.checked_add(2)?)?;
    Some(u16::from_be_bytes([*pair.first()?, *pair.get(1)?]))
}

fn budget(limit: usize) -> DecodeBudget {
    DecodeBudget::new(limit, 1 << 14)
}

#[test]
fn the_pinned_mls_corpus_messages_parse_under_the_outer_parser() -> TestResult {
    let mut accepted = 0_usize;
    for bytes in lines("key-packages.hex")? {
        // MLSMessage { version, wire_format = 5, KeyPackage { version, suite, ... } }
        let suite = suite_at(&bytes, 6).ok_or("short key package")?;
        let parsed = parse_mls_message(&bytes, &mut budget(MAX_KEY_PACKAGE_OBJECT));
        if ENABLED_SUITES.contains(&suite) {
            let MlsOuterMessage::KeyPackage(package) = parsed? else {
                return Err("key package parsed as another shape".into());
            };
            assert_eq!(package.cipher_suite, suite);
            assert!(!package.init_key.is_empty());
            verify_key_package_signatures(&package)?;
            accepted += 1;
        } else {
            assert!(parsed.is_err(), "suite {suite:#06x} must be refused");
        }
    }
    for bytes in lines("welcomes.hex")? {
        // MLSMessage { version, wire_format = 3, Welcome { suite, ... } }
        let suite = suite_at(&bytes, 4).ok_or("short welcome")?;
        let parsed = parse_mls_message(&bytes, &mut budget(MAX_WELCOME_MAILBOX_OBJECT));
        if ENABLED_SUITES.contains(&suite) {
            let MlsOuterMessage::Welcome(header) = parsed? else {
                return Err("welcome parsed as another shape".into());
            };
            assert_eq!(header.cipher_suite, suite);
            assert!(!header.new_member_refs.is_empty());
            accepted += 1;
        } else {
            assert!(parsed.is_err(), "suite {suite:#06x} must be refused");
        }
    }
    for bytes in lines("private-messages.hex")? {
        match parse_mls_message(&bytes, &mut budget(MAX_KEY_PACKAGE_OBJECT)) {
            Ok(MlsOuterMessage::Private(header)) => {
                assert!(!header.group_id.is_empty());
                assert!(header.ciphertext_len > 0);
                accepted += 1;
            }
            Ok(_) => return Err("private message parsed as another shape".into()),
            Err(E2eeError::InvalidValue | E2eeError::ProfileMismatch) => {}
            Err(error) => return Err(format!("unexpected refusal {error:?}").into()),
        }
    }
    for name in ["public-messages.hex", "group-infos.hex"] {
        for bytes in lines(name)? {
            assert!(
                parse_mls_message(&bytes, &mut budget(MAX_KEY_PACKAGE_OBJECT)).is_err(),
                "{name}: the daemon never accepts public messages or group info"
            );
        }
    }
    assert!(
        accepted >= 24,
        "the enabled suites must be represented: {accepted}"
    );
    Ok(())
}

#[test]
fn the_pinned_welcome_joins_split_by_suite() -> TestResult {
    let text = fs::read_to_string(corpus("welcome-joins.hex"))?;
    let mut enabled = 0_usize;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let suite: u16 = fields.next().ok_or("suite")?.parse()?;
        let package = hex(fields.next().ok_or("key package")?)?;
        let welcome = hex(fields.next().ok_or("welcome")?)?;
        let package_parsed = parse_mls_message(&package, &mut budget(MAX_KEY_PACKAGE_OBJECT));
        let welcome_parsed = parse_mls_message(&welcome, &mut budget(MAX_WELCOME_MAILBOX_OBJECT));
        if ENABLED_SUITES.contains(&suite) {
            assert!(matches!(package_parsed, Ok(MlsOuterMessage::KeyPackage(_))));
            assert!(matches!(welcome_parsed, Ok(MlsOuterMessage::Welcome(_))));
            enabled += 1;
        } else {
            assert!(package_parsed.is_err() && welcome_parsed.is_err());
        }
    }
    assert_eq!(enabled, 2);
    Ok(())
}

#[test]
fn the_pinned_variable_length_headers_decode_to_their_lengths() -> TestResult {
    let text = fs::read_to_string(corpus("varint.hex"))?;
    let mut count = 0_usize;
    for line in text.lines().filter(|line| !line.trim().is_empty()) {
        let mut fields = line.split_whitespace();
        let header = hex(fields.next().ok_or("header")?)?;
        let length: usize = fields.next().ok_or("length")?.parse()?;
        let mut budget = DecodeBudget::new(1 << 16, 16);
        let mut reader = MlsReader::new(&header, &mut budget);
        assert_eq!(reader.varint()?, length, "header {line}");
        reader.finish()?;
        count += 1;
    }
    assert_eq!(count, 14);
    Ok(())
}
