//! The detached release decision document and its PEM trust anchor.
//!
//! `scripts/qualify-release.py close` writes `release.json` as canonical
//! JSON: sorted keys, no whitespace, ASCII only, one trailing line feed. The
//! reader here accepts exactly that grammar under fixed bounds, so a document
//! the release signer never produced is rejected before its content is
//! examined. Signature verification and the executable comparison belong to
//! the runtime crate; this module only validates shape and content.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

/// Maximum accepted bytes in one `release.json`.
pub const MAX_RELEASE_DECISION_BYTES: usize = 65_536;
/// Maximum accepted bytes in one PEM trust anchor.
pub const MAX_RELEASE_PUBLIC_KEY_BYTES: usize = 4_096;
const MAX_STRING_BYTES: usize = 256;
const MAX_DEPTH: usize = 4;
const MAX_MEMBERS: usize = 16;
const MAX_ELEMENTS: usize = 16;
const MAX_INTEGER_DIGITS: usize = 16;
const MAX_TARGET_BYTES: usize = 64;
const MAX_TARGETS: usize = 8;
const PEM_HEADER: &str = "-----BEGIN PUBLIC KEY-----";
const PEM_FOOTER: &str = "-----END PUBLIC KEY-----";
const MAX_PEM_LINE_BYTES: usize = 76;
/// The RFC 8410 SubjectPublicKeyInfo prefix of an Ed25519 public key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
// Structural bytes are spelled as values: the repository's source scanner does
// not recognise byte-character literals, so a bare quote or brace literal
// would unbalance its string and block matching.
const QUOTE: u8 = 0x22;
const OPEN_BRACE: u8 = 0x7b;
const CLOSE_BRACE: u8 = 0x7d;
const DECISION_FIELDS: [&str; 9] = [
    "artifacts",
    "candidate_sha256",
    "claims",
    "decided_at",
    "public_key_sha256",
    "qualification_sha256",
    "schema_version",
    "source",
    "targets",
];
const SOURCE_FIELDS: [&str; 3] = ["commit", "lock_sha256", "source_sha256"];
const ARTIFACT_FIELDS: [&str; 5] = [
    "build_record",
    "build_record_sha256",
    "path",
    "sha256",
    "target",
];

/// Closed failures while reading a release decision or its trust anchor.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum ReleaseDecisionError {
    /// The input exceeded its fixed byte limit.
    TooLarge,
    /// The bytes were not canonical JSON within the reader's bounds.
    InvalidJson,
    /// The JSON did not carry exactly the release decision schema.
    InvalidSchema,
    /// The trust anchor was not a PEM-encoded Ed25519 public key.
    InvalidPublicKey,
}

impl fmt::Display for ReleaseDecisionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::TooLarge => "release decision input exceeds its size limit",
            Self::InvalidJson => "release decision is not canonical JSON",
            Self::InvalidSchema => "release decision does not match the decision schema",
            Self::InvalidPublicKey => "trust anchor is not a PEM Ed25519 public key",
        })
    }
}

impl std::error::Error for ReleaseDecisionError {}

/// The closed set of release claims a signed decision may grant, declared in
/// canonical name order so the derived ordering matches the document order.
#[derive(Clone, Copy, Debug, Eq, PartialEq, PartialOrd, Ord, Hash)]
pub enum ReleaseClaim {
    /// The base client profile.
    CoreV1,
    /// The E2EE companion profile.
    EncryptedV1,
    /// The base federation profile.
    FederatedV1,
    /// The optional history service.
    History,
    /// The optional WebSocket transport.
    Wss,
}

impl ReleaseClaim {
    /// Every claim in canonical name order.
    pub const ALL: [Self; 5] = [
        Self::CoreV1,
        Self::EncryptedV1,
        Self::FederatedV1,
        Self::History,
        Self::Wss,
    ];

    /// The fixed claim name used by the decision and the metadata output.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::CoreV1 => "core-v1",
            Self::EncryptedV1 => "encrypted-v1",
            Self::FederatedV1 => "federated-v1",
            Self::History => "history",
            Self::Wss => "wss",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|claim| claim.name() == name)
    }
}

/// One release artifact identity named by a decision.
#[derive(Clone, Eq, PartialEq)]
pub struct ReleaseArtifact {
    /// The Rust target triple the artifact was built for.
    pub target: String,
    /// SHA-256 of the artifact binary.
    pub sha256: [u8; 32],
}

/// A fully validated release decision document.
///
/// Every string field is limited to a closed ASCII alphabet, so composing it
/// into JSON output cannot inject structure.
#[derive(Clone, Eq, PartialEq)]
pub struct ReleaseDecisionDocument {
    /// SHA-256 of the canonical candidate record.
    pub candidate_sha256: [u8; 32],
    /// The qualified source commit.
    pub source_commit: [u8; 20],
    /// SHA-256 of the canonical source tree.
    pub source_sha256: [u8; 32],
    /// SHA-256 of the committed `Cargo.lock`.
    pub lock_sha256: [u8; 32],
    /// Granted claims in canonical order without repetition.
    pub claims: Vec<ReleaseClaim>,
    /// Covered targets in byte order without repetition.
    pub targets: Vec<String>,
    /// One artifact per covered target, in target order.
    pub artifacts: Vec<ReleaseArtifact>,
    /// The UTC decision time in the runner's `Z` notation.
    pub decided_at: String,
    /// SHA-256 of the qualification summary the decision binds.
    pub qualification_sha256: [u8; 32],
    /// SHA-256 of the PEM public key that signed the decision.
    pub public_key_sha256: [u8; 32],
}

impl ReleaseDecisionDocument {
    /// Parses one canonical `release.json`.
    pub fn parse(bytes: &[u8]) -> Result<Self, ReleaseDecisionError> {
        if bytes.len() > MAX_RELEASE_DECISION_BYTES {
            return Err(ReleaseDecisionError::TooLarge);
        }
        let mut reader = Reader { bytes, cursor: 0 };
        let root = reader.value(0)?;
        if reader.next() != Some(b'\n') || reader.cursor != bytes.len() {
            return Err(ReleaseDecisionError::InvalidJson);
        }
        let members = object_with_fields(&root, &DECISION_FIELDS)?;
        if integer(field(members, "schema_version")?)? != 1 {
            return Err(ReleaseDecisionError::InvalidSchema);
        }
        let source = object_with_fields(field(members, "source")?, &SOURCE_FIELDS)?;
        let claims = claims(field(members, "claims")?)?;
        let targets = targets(field(members, "targets")?)?;
        let artifacts = artifacts(field(members, "artifacts")?, &targets)?;
        Ok(Self {
            candidate_sha256: hash(field(members, "candidate_sha256")?)?,
            source_commit: hex_bytes(text(field(source, "commit")?)?)?,
            source_sha256: hash(field(source, "source_sha256")?)?,
            lock_sha256: hash(field(source, "lock_sha256")?)?,
            claims,
            targets,
            artifacts,
            decided_at: timestamp(text(field(members, "decided_at")?)?)?,
            qualification_sha256: hash(field(members, "qualification_sha256")?)?,
            public_key_sha256: hash(field(members, "public_key_sha256")?)?,
        })
    }

    /// Returns the artifact digest recorded for one target, if covered.
    #[must_use]
    pub fn artifact_digest(&self, target: &str) -> Option<&[u8; 32]> {
        self.artifacts
            .iter()
            .find(|artifact| artifact.target == target)
            .map(|artifact| &artifact.sha256)
    }
}

/// Parses a PEM `PUBLIC KEY` block holding exactly one Ed25519 key and
/// returns its 32 raw bytes. Point validation belongs to the crypto crate.
pub fn parse_release_public_key_pem(bytes: &[u8]) -> Result<[u8; 32], ReleaseDecisionError> {
    if bytes.len() > MAX_RELEASE_PUBLIC_KEY_BYTES {
        return Err(ReleaseDecisionError::TooLarge);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| ReleaseDecisionError::InvalidPublicKey)?;
    let mut lines = text.split('\n');
    if lines.next() != Some(PEM_HEADER) {
        return Err(ReleaseDecisionError::InvalidPublicKey);
    }
    let mut encoded = String::new();
    let mut footer_seen = false;
    for line in lines {
        if footer_seen {
            if !line.is_empty() {
                return Err(ReleaseDecisionError::InvalidPublicKey);
            }
            continue;
        }
        if line == PEM_FOOTER {
            footer_seen = true;
            continue;
        }
        if line.is_empty()
            || line.len() > MAX_PEM_LINE_BYTES
            || !line
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/' | b'='))
        {
            return Err(ReleaseDecisionError::InvalidPublicKey);
        }
        encoded.push_str(line);
    }
    if !footer_seen {
        return Err(ReleaseDecisionError::InvalidPublicKey);
    }
    let der = STANDARD
        .decode(encoded)
        .map_err(|_| ReleaseDecisionError::InvalidPublicKey)?;
    let (prefix, key) = der
        .split_at_checked(ED25519_SPKI_PREFIX.len())
        .ok_or(ReleaseDecisionError::InvalidPublicKey)?;
    if prefix != ED25519_SPKI_PREFIX {
        return Err(ReleaseDecisionError::InvalidPublicKey);
    }
    <[u8; 32]>::try_from(key).map_err(|_| ReleaseDecisionError::InvalidPublicKey)
}

enum Value {
    Null,
    Integer(u64),
    Text(String),
    Array(Vec<Value>),
    Object(Vec<(String, Value)>),
}

struct Reader<'a> {
    bytes: &'a [u8],
    cursor: usize,
}

impl Reader<'_> {
    fn peek(&self) -> Option<u8> {
        self.bytes.get(self.cursor).copied()
    }

    fn next(&mut self) -> Option<u8> {
        let byte = self.peek()?;
        self.cursor = self.cursor.checked_add(1)?;
        Some(byte)
    }

    fn consume(&mut self, byte: u8) -> Result<(), ReleaseDecisionError> {
        if self.next() == Some(byte) {
            Ok(())
        } else {
            Err(ReleaseDecisionError::InvalidJson)
        }
    }

    fn value(&mut self, depth: usize) -> Result<Value, ReleaseDecisionError> {
        if depth > MAX_DEPTH {
            return Err(ReleaseDecisionError::InvalidJson);
        }
        match self.peek().ok_or(ReleaseDecisionError::InvalidJson)? {
            OPEN_BRACE => self.object(depth),
            b'[' => self.array(depth),
            QUOTE => self.string().map(Value::Text),
            b'0'..=b'9' => self.integer(),
            b'n' => {
                self.literal(b"null")?;
                Ok(Value::Null)
            }
            _ => Err(ReleaseDecisionError::InvalidJson),
        }
    }

    fn literal(&mut self, expected: &[u8]) -> Result<(), ReleaseDecisionError> {
        for byte in expected {
            self.consume(*byte)?;
        }
        Ok(())
    }

    fn object(&mut self, depth: usize) -> Result<Value, ReleaseDecisionError> {
        self.consume(OPEN_BRACE)?;
        let mut members: Vec<(String, Value)> = Vec::new();
        if self.peek() == Some(CLOSE_BRACE) {
            self.consume(CLOSE_BRACE)?;
            return Ok(Value::Object(members));
        }
        loop {
            if members.len() >= MAX_MEMBERS {
                return Err(ReleaseDecisionError::InvalidJson);
            }
            let key = self.string()?;
            if members.last().is_some_and(|(previous, _)| *previous >= key) {
                return Err(ReleaseDecisionError::InvalidJson);
            }
            self.consume(b':')?;
            let value = self.value(depth.saturating_add(1))?;
            members.push((key, value));
            match self.next() {
                Some(b',') => continue,
                Some(CLOSE_BRACE) => return Ok(Value::Object(members)),
                _ => return Err(ReleaseDecisionError::InvalidJson),
            }
        }
    }

    fn array(&mut self, depth: usize) -> Result<Value, ReleaseDecisionError> {
        self.consume(b'[')?;
        let mut elements = Vec::new();
        if self.peek() == Some(b']') {
            self.consume(b']')?;
            return Ok(Value::Array(elements));
        }
        loop {
            if elements.len() >= MAX_ELEMENTS {
                return Err(ReleaseDecisionError::InvalidJson);
            }
            elements.push(self.value(depth.saturating_add(1))?);
            match self.next() {
                Some(b',') => continue,
                Some(b']') => return Ok(Value::Array(elements)),
                _ => return Err(ReleaseDecisionError::InvalidJson),
            }
        }
    }

    /// Reads a quoted string of printable ASCII without escapes.
    fn string(&mut self) -> Result<String, ReleaseDecisionError> {
        self.consume(QUOTE)?;
        let mut text = String::new();
        loop {
            let byte = self.next().ok_or(ReleaseDecisionError::InvalidJson)?;
            if byte == QUOTE {
                return Ok(text);
            }
            let printable = (0x20..=0x7e).contains(&byte) && byte != b'\\';
            if !printable || text.len() >= MAX_STRING_BYTES {
                return Err(ReleaseDecisionError::InvalidJson);
            }
            text.push(char::from(byte));
        }
    }

    /// Reads a non-negative integer without a leading zero, sign, fraction,
    /// or exponent.
    fn integer(&mut self) -> Result<Value, ReleaseDecisionError> {
        let start = self.cursor;
        while self.peek().is_some_and(|byte| byte.is_ascii_digit()) {
            self.next();
        }
        let digits = self
            .bytes
            .get(start..self.cursor)
            .and_then(|digits| std::str::from_utf8(digits).ok())
            .ok_or(ReleaseDecisionError::InvalidJson)?;
        if digits.is_empty()
            || digits.len() > MAX_INTEGER_DIGITS
            || (digits.len() > 1 && digits.starts_with('0'))
        {
            return Err(ReleaseDecisionError::InvalidJson);
        }
        digits
            .parse()
            .map(Value::Integer)
            .map_err(|_| ReleaseDecisionError::InvalidJson)
    }
}

fn object_with_fields<'a>(
    value: &'a Value,
    fields: &[&str],
) -> Result<&'a [(String, Value)], ReleaseDecisionError> {
    let Value::Object(members) = value else {
        return Err(ReleaseDecisionError::InvalidSchema);
    };
    if members.len() != fields.len()
        || members
            .iter()
            .zip(fields)
            .any(|((name, _), expected)| name != expected)
    {
        return Err(ReleaseDecisionError::InvalidSchema);
    }
    Ok(members)
}

fn field<'a>(
    members: &'a [(String, Value)],
    name: &str,
) -> Result<&'a Value, ReleaseDecisionError> {
    members
        .iter()
        .find(|(member, _)| member == name)
        .map(|(_, value)| value)
        .ok_or(ReleaseDecisionError::InvalidSchema)
}

fn integer(value: &Value) -> Result<u64, ReleaseDecisionError> {
    match value {
        Value::Integer(number) => Ok(*number),
        _ => Err(ReleaseDecisionError::InvalidSchema),
    }
}

fn text(value: &Value) -> Result<&str, ReleaseDecisionError> {
    match value {
        Value::Text(text) => Ok(text),
        _ => Err(ReleaseDecisionError::InvalidSchema),
    }
}

fn hash(value: &Value) -> Result<[u8; 32], ReleaseDecisionError> {
    hex_bytes(text(value)?)
}

fn hex_bytes<const N: usize>(text: &str) -> Result<[u8; N], ReleaseDecisionError> {
    let mut bytes = [0_u8; N];
    if text.len() != N.saturating_mul(2) {
        return Err(ReleaseDecisionError::InvalidSchema);
    }
    for (index, [first, second]) in text.as_bytes().as_chunks::<2>().0.iter().enumerate() {
        let (Some(high), Some(low)) = (hex_nibble(*first), hex_nibble(*second)) else {
            return Err(ReleaseDecisionError::InvalidSchema);
        };
        let Some(slot) = bytes.get_mut(index) else {
            return Err(ReleaseDecisionError::InvalidSchema);
        };
        *slot = (high << 4) | low;
    }
    Ok(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        _ => None,
    }
}

fn claims(value: &Value) -> Result<Vec<ReleaseClaim>, ReleaseDecisionError> {
    let Value::Array(elements) = value else {
        return Err(ReleaseDecisionError::InvalidSchema);
    };
    let mut claims = Vec::new();
    for element in elements {
        let claim =
            ReleaseClaim::parse(text(element)?).ok_or(ReleaseDecisionError::InvalidSchema)?;
        if claims.last().is_some_and(|previous| *previous >= claim) {
            return Err(ReleaseDecisionError::InvalidSchema);
        }
        claims.push(claim);
    }
    if claims.is_empty() {
        return Err(ReleaseDecisionError::InvalidSchema);
    }
    Ok(claims)
}

fn target(value: &Value) -> Result<String, ReleaseDecisionError> {
    let name = text(value)?;
    if name.is_empty()
        || name.len() > MAX_TARGET_BYTES
        || !name.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
    {
        return Err(ReleaseDecisionError::InvalidSchema);
    }
    Ok(name.to_owned())
}

fn targets(value: &Value) -> Result<Vec<String>, ReleaseDecisionError> {
    let Value::Array(elements) = value else {
        return Err(ReleaseDecisionError::InvalidSchema);
    };
    if elements.is_empty() || elements.len() > MAX_TARGETS {
        return Err(ReleaseDecisionError::InvalidSchema);
    }
    let mut targets: Vec<String> = Vec::new();
    for element in elements {
        let name = target(element)?;
        if targets.last().is_some_and(|previous| *previous >= name) {
            return Err(ReleaseDecisionError::InvalidSchema);
        }
        targets.push(name);
    }
    Ok(targets)
}

fn artifacts(
    value: &Value,
    targets: &[String],
) -> Result<Vec<ReleaseArtifact>, ReleaseDecisionError> {
    let Value::Array(elements) = value else {
        return Err(ReleaseDecisionError::InvalidSchema);
    };
    if elements.len() != targets.len() {
        return Err(ReleaseDecisionError::InvalidSchema);
    }
    let mut artifacts = Vec::new();
    for (element, expected) in elements.iter().zip(targets) {
        let members = object_with_fields(element, &ARTIFACT_FIELDS)?;
        let name = target(field(members, "target")?)?;
        if name != *expected
            || text(field(members, "path")?)? != format!("artifacts/{name}/agenc-ircd")
            || text(field(members, "build_record")?)? != format!("artifacts/{name}/build.json")
        {
            return Err(ReleaseDecisionError::InvalidSchema);
        }
        hash(field(members, "build_record_sha256")?)?;
        artifacts.push(ReleaseArtifact {
            target: name,
            sha256: hash(field(members, "sha256")?)?,
        });
    }
    Ok(artifacts)
}

/// Accepts the runner's `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` spelling.
fn timestamp(text: &str) -> Result<String, ReleaseDecisionError> {
    let bytes = text.as_bytes();
    let fixed = b"0000-00-00T00:00:00";
    let valid_head = bytes.len() >= fixed.len()
        && bytes
            .iter()
            .zip(fixed)
            .all(|(byte, pattern)| match pattern {
                b'0' => byte.is_ascii_digit(),
                _ => byte == pattern,
            });
    let tail = bytes.get(fixed.len()..).unwrap_or_default();
    let valid_tail = match tail {
        b"Z" => true,
        [b'.', fraction @ .., b'Z'] => {
            (1..=6).contains(&fraction.len()) && fraction.iter().all(u8::is_ascii_digit)
        }
        _ => false,
    };
    if !valid_head || !valid_tail {
        return Err(ReleaseDecisionError::InvalidSchema);
    }
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        MAX_RELEASE_DECISION_BYTES, ReleaseClaim, ReleaseDecisionDocument, ReleaseDecisionError,
        parse_release_public_key_pem,
    };

    const HEX64: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const HEX40: &str = "0123456789abcdef0123456789abcdef01234567";
    const X86: &str = "x86_64-unknown-linux-gnu";
    const ARM: &str = "aarch64-unknown-linux-gnu";
    const STAMP: &str = "2026-09-05T12:00:00.123456Z";

    fn artifact(target: &str) -> String {
        let mut text = format!("{{\"build_record\":\"artifacts/{target}/build.json\",");
        text.push_str(&format!("\"build_record_sha256\":\"{HEX64}\","));
        text.push_str(&format!("\"path\":\"artifacts/{target}/agenc-ircd\","));
        text.push_str(&format!("\"sha256\":\"{HEX64}\",\"target\":\"{target}\"}}"));
        text
    }

    fn document(claims: &str, targets: &[&str]) -> String {
        let artifacts = targets
            .iter()
            .map(|target| artifact(target))
            .collect::<Vec<_>>()
            .join(",");
        let names = targets
            .iter()
            .map(|target| format!("\"{target}\""))
            .collect::<Vec<_>>()
            .join(",");
        let mut text = format!("{{\"artifacts\":[{artifacts}],");
        text.push_str(&format!(
            "\"candidate_sha256\":\"{HEX64}\",\"claims\":[{claims}],"
        ));
        text.push_str(&format!("\"decided_at\":\"{STAMP}\","));
        text.push_str(&format!("\"public_key_sha256\":\"{HEX64}\","));
        text.push_str(&format!(
            "\"qualification_sha256\":\"{HEX64}\",\"schema_version\":1,"
        ));
        text.push_str(&format!("\"source\":{{\"commit\":\"{HEX40}\","));
        text.push_str(&format!(
            "\"lock_sha256\":\"{HEX64}\",\"source_sha256\":\"{HEX64}\"}},"
        ));
        text.push_str(&format!("\"targets\":[{names}]}}\n"));
        text
    }

    fn canonical() -> String {
        document("\"core-v1\",\"wss\"", &[ARM, X86])
    }

    fn rejects(cases: &[(String, ReleaseDecisionError)]) {
        for (input, expected) in cases {
            assert_eq!(
                ReleaseDecisionDocument::parse(input.as_bytes()).err(),
                Some(*expected),
                "{}",
                input.chars().take(120).collect::<String>()
            );
        }
    }

    #[test]
    fn canonical_document_parses_into_typed_fields() -> Result<(), ReleaseDecisionError> {
        let parsed = ReleaseDecisionDocument::parse(canonical().as_bytes())?;
        assert_eq!(parsed.claims, vec![ReleaseClaim::CoreV1, ReleaseClaim::Wss]);
        assert_eq!(parsed.targets, vec![ARM.to_owned(), X86.to_owned()]);
        assert_eq!(parsed.decided_at, STAMP);
        assert_eq!(parsed.source_commit[0], 0x01);
        assert!(parsed.artifact_digest(X86).is_some());
        assert!(
            parsed
                .artifact_digest("riscv64gc-unknown-linux-gnu")
                .is_none()
        );
        let every = "\"core-v1\",\"encrypted-v1\",\"federated-v1\",\"history\",\"wss\"";
        let complete = document(every, &[X86]);
        let parsed = ReleaseDecisionDocument::parse(complete.as_bytes())?;
        assert_eq!(parsed.claims, ReleaseClaim::ALL.to_vec());
        Ok(())
    }

    #[test]
    fn grammar_outside_the_canonical_form_is_rejected() {
        let good = canonical();
        let json = ReleaseDecisionError::InvalidJson;
        rejects(&[
            (good.replace(":[", ": ["), json),
            (good.trim_end().to_owned(), json),
            (format!("{good}\n"), json),
            (good.replace("\"claims\"", "\"claim\\s\""), json),
            (
                good.replace("\"schema_version\":1", "\"schema_version\":01"),
                json,
            ),
            (
                good.replace("\"schema_version\":1", "\"schema_version\":true"),
                json,
            ),
            (
                good.replace("\"decided_at\":\"2026", "\"decided_at\":\"2026\u{e9}"),
                json,
            ),
            ("{\"b\":1,\"a\":2}\n".to_owned(), json),
            ("{\"a\":1,\"a\":2}\n".to_owned(), json),
            ("{\"a\":[[[[[1]]]]]}\n".to_owned(), json),
            ("{\"a\":-1}\n".to_owned(), json),
            ("{\"a\":1.5}\n".to_owned(), json),
            ("{\"a\":99999999999999999}\n".to_owned(), json),
            (String::new(), json),
            (
                "x".repeat(MAX_RELEASE_DECISION_BYTES + 1),
                ReleaseDecisionError::TooLarge,
            ),
        ]);
    }

    #[test]
    fn documents_outside_the_schema_are_rejected() {
        let good = canonical();
        let schema = ReleaseDecisionError::InvalidSchema;
        let commit = format!("\"commit\":\"{HEX40}\"");
        rejects(&[
            (
                good.replace("\"schema_version\":1", "\"schema_version\":2"),
                schema,
            ),
            (
                good.replace("\"core-v1\",\"wss\"", "\"wss\",\"core-v1\""),
                schema,
            ),
            (
                good.replace("\"core-v1\",\"wss\"", "\"core-v1\",\"core-v1\""),
                schema,
            ),
            (good.replace("\"core-v1\",\"wss\"", "\"core-v2\""), schema),
            (good.replace("\"core-v1\",\"wss\"", ""), schema),
            (good.replace("00.123456Z", "00.1234567Z"), schema),
            (good.replace("00.123456Z", "00.123456+00:00"), schema),
            (
                good.replace(&commit, &format!("\"commit\":\"{HEX64}\"")),
                schema,
            ),
            (
                good.replace("\"targets\":[", "\"targets\":[\"Zeta\","),
                schema,
            ),
            (good.replacen(ARM, X86, 1), schema),
            (
                good.replace("\"public_key_sha256\"", "\"public_key_sha255\""),
                schema,
            ),
            (
                good.replace("\"qualification_sha256\"", "\"qualification_sha255\""),
                schema,
            ),
            ("{}\n".to_owned(), schema),
            ("[]\n".to_owned(), schema),
        ]);
    }

    #[test]
    fn every_error_discriminant_renders_a_distinct_message() {
        let variants = [
            ReleaseDecisionError::TooLarge,
            ReleaseDecisionError::InvalidJson,
            ReleaseDecisionError::InvalidSchema,
            ReleaseDecisionError::InvalidPublicKey,
        ];
        let rendered: Vec<String> = variants.iter().map(ToString::to_string).collect();
        assert!(rendered.iter().all(|text| !text.is_empty()));
        let mut unique = rendered.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), rendered.len(), "{rendered:?}");
    }

    #[test]
    fn pem_reader_accepts_only_one_ed25519_public_key() -> Result<(), ReleaseDecisionError> {
        let body = "MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=";
        let pem = format!("-----BEGIN PUBLIC KEY-----\n{body}\n-----END PUBLIC KEY-----\n");
        let key = parse_release_public_key_pem(pem.as_bytes())?;
        assert_eq!(key[0], 0x19);
        assert_eq!(
            parse_release_public_key_pem(pem.trim_end().as_bytes())?,
            key
        );
        for hostile in [
            pem.replace("BEGIN PUBLIC KEY", "BEGIN PRIVATE KEY"),
            pem.replace("MCowBQYDK2Vw", "MC4CAQAwBQYD"),
            pem.replace("-----END PUBLIC KEY-----\n", ""),
            pem.replace("\n-----END", "\n\n-----END"),
            format!("{pem}trailing"),
            pem.replace("AyEAGb9", "AyEA Gb9"),
            String::from("\u{e9}"),
            "x".repeat(5000),
        ] {
            assert!(
                parse_release_public_key_pem(hostile.as_bytes()).is_err(),
                "{hostile}"
            );
        }
        Ok(())
    }

    #[test]
    fn json_grammar_limits_and_consume_mismatches_are_rejected() {
        let members = (0..40)
            .map(|index| format!("\"k{index:03}\":1"))
            .collect::<Vec<_>>()
            .join(",");
        let elements = vec!["1"; 40].join(",");
        let long_text = "a".repeat(300);
        rejects(&[
            ("{\"a\" 1}".to_owned(), ReleaseDecisionError::InvalidJson),
            (format!("{{{members}}}"), ReleaseDecisionError::InvalidJson),
            (
                format!("{{\"a\":[{elements}]}}"),
                ReleaseDecisionError::InvalidJson,
            ),
            (
                format!("{{\"a\":\"{long_text}\"}}"),
                ReleaseDecisionError::InvalidJson,
            ),
            ("{\"a\":-x}".to_owned(), ReleaseDecisionError::InvalidJson),
        ]);
    }

    #[test]
    fn schema_fields_are_checked_one_rule_at_a_time() {
        let base = canonical();
        let swap = |from: &str, to: &str| base.replacen(from, to, 1);
        let claims_field = "\"claims\":[\"core-v1\",\"wss\"]";
        let targets_field = format!("\"targets\":[\"{ARM}\",\"{X86}\"]");
        let stamp_field = format!("\"decided_at\":\"{STAMP}\"");
        let candidate_field = format!("\"candidate_sha256\":\"{HEX64}\"");
        let bad_hex = format!("\"candidate_sha256\":\"{}\"", "zz".repeat(32));
        let long_target = "t".repeat(200);
        rejects(&[
            (
                swap("\"schema_version\":1", "\"schema_version\":12"),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(&candidate_field, &bad_hex),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(claims_field, "\"claims\":1"),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(&targets_field, "\"targets\":1"),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(&targets_field, "\"targets\":[]"),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(
                    &targets_field,
                    &format!("\"targets\":[\"{X86}\",\"{ARM}\"]"),
                ),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(&targets_field, &format!("\"targets\":[\"{ARM}\",\"\"]")),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(
                    &targets_field,
                    &format!("\"targets\":[\"{ARM}\",\"{long_target}\"]"),
                ),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(&targets_field, &format!("\"targets\":[\"{ARM}\"]")),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(
                    &format!("\"artifacts\":[{},{}]", artifact(ARM), artifact(X86)),
                    "\"artifacts\":1",
                ),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(
                    &format!("\"target\":\"{ARM}\""),
                    &format!("\"target\":\"{X86}\""),
                ),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(
                    &format!("\"path\":\"artifacts/{ARM}/agenc-ircd\""),
                    &format!("\"path\":\"artifacts/{ARM}/other\""),
                ),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(&stamp_field, "\"decided_at\":\"2026-09-05T12:00:00\""),
                ReleaseDecisionError::InvalidSchema,
            ),
            (
                swap(&stamp_field, "\"decided_at\":\"abcd-09-05T12:00:00Z\""),
                ReleaseDecisionError::InvalidSchema,
            ),
        ]);
        let many = (0..9)
            .map(|index| format!("\"t{index:02}\""))
            .collect::<Vec<_>>()
            .join(",");
        rejects(&[(
            swap(&targets_field, &format!("\"targets\":[{many}]")),
            ReleaseDecisionError::InvalidSchema,
        )]);
    }

    #[test]
    fn pem_lines_are_bounded_and_the_footer_is_required() {
        let long_line = "A".repeat(1_000);
        let unbounded =
            format!("-----BEGIN PUBLIC KEY-----\n{long_line}\n-----END PUBLIC KEY-----\n");
        assert_eq!(
            parse_release_public_key_pem(unbounded.as_bytes()).err(),
            Some(ReleaseDecisionError::InvalidPublicKey)
        );
        let unterminated = "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n";
        assert_eq!(
            parse_release_public_key_pem(unterminated.as_bytes()).err(),
            Some(ReleaseDecisionError::InvalidPublicKey)
        );
    }
}
