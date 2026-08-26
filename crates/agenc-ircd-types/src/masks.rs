//! Typed masks and bounded nonrecursive glob matching.

use crate::{AccountRandomId, Nickname, UserId, ValidationError};

/// Maximum bytes in a nickname or cloak glob.
pub const MAX_GLOB_BYTES: usize = 96;
/// Maximum bytes in one complete typed-mask text form.
pub const MAX_TYPED_MASK_BYTES: usize = 128;

#[derive(Clone, Copy, Eq, PartialEq)]
enum GlobCase {
    AsciiInsensitive,
    Exact,
}

/// A validated glob evaluated with a fixed `u128` NFA-state bitset.
pub struct CompiledGlob {
    pattern: String,
    case: GlobCase,
}

impl CompiledGlob {
    fn compile(input: &str, case: GlobCase) -> Result<Self, ValidationError> {
        if !(1..=MAX_GLOB_BYTES).contains(&input.len()) {
            return Err(if input.is_empty() {
                ValidationError::Empty
            } else {
                ValidationError::TooLong
            });
        }
        if !input.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'*' | b'?')
        }) {
            return Err(ValidationError::InvalidCharacter);
        }
        let mut pattern = String::new();
        pattern
            .try_reserve_exact(input.len())
            .map_err(|_| ValidationError::AllocationFailed)?;
        let mut previous_star = false;
        for byte in input.bytes() {
            if byte == b'*' && previous_star {
                continue;
            }
            let canonical = if case == GlobCase::AsciiInsensitive {
                byte.to_ascii_lowercase()
            } else {
                byte
            };
            pattern.push(char::from(canonical));
            previous_star = byte == b'*';
        }
        Ok(Self { pattern, case })
    }

    fn epsilon_closure(&self, mut states: u128) -> u128 {
        loop {
            let mut expanded = states;
            for (position, token) in self.pattern.bytes().enumerate() {
                let active = states & (1_u128 << position) != 0;
                if active && token == b'*' {
                    expanded |= 1_u128 << (position + 1);
                }
            }
            if expanded == states {
                return states;
            }
            states = expanded;
        }
    }

    /// Matches in work linear in input length under the fixed 96-byte pattern cap.
    #[must_use]
    pub fn is_match(&self, input: &str) -> bool {
        if !input.is_ascii() {
            return false;
        }
        let mut states = self.epsilon_closure(1);
        for input_byte in input.bytes() {
            let candidate = if self.case == GlobCase::AsciiInsensitive {
                input_byte.to_ascii_lowercase()
            } else {
                input_byte
            };
            let mut next = 0_u128;
            for (position, token) in self.pattern.bytes().enumerate() {
                if states & (1_u128 << position) == 0 {
                    continue;
                }
                if token == b'*' {
                    next |= 1_u128 << position;
                    continue;
                }
                if token == b'?' || token == candidate {
                    next |= 1_u128 << (position + 1);
                }
            }
            states = self.epsilon_closure(next);
        }
        states & (1_u128 << self.pattern.len()) != 0
    }

    /// Borrows the canonical pattern with redundant stars removed.
    #[must_use]
    pub fn pattern(&self) -> &str {
        &self.pattern
    }
}

/// The domain selected by one typed mask.
pub enum MaskSubject {
    /// An immutable authenticated account.
    Account(AccountRandomId),
    /// One live user session.
    User(UserId),
    /// A case-insensitive nickname glob.
    Nickname(CompiledGlob),
    /// An exact-case public cloak glob.
    Cloak(CompiledGlob),
}

/// A canonical nonrecursive typed mask.
pub struct TypedMask {
    quiet: bool,
    subject: MaskSubject,
}

impl TypedMask {
    /// Parses one complete `$a`, `$u`, `$n`, `$c`, or single `$q` mask.
    pub fn parse(input: &str) -> Result<Self, ValidationError> {
        if input.len() > MAX_TYPED_MASK_BYTES {
            return Err(ValidationError::TooLong);
        }
        if let Some(inner) = input.strip_prefix("$q:") {
            let mut mask = Self::parse_subject(inner)?;
            mask.quiet = true;
            return Ok(mask);
        }
        Self::parse_subject(input)
    }

    fn parse_subject(input: &str) -> Result<Self, ValidationError> {
        if input.starts_with("$q:") {
            return Err(ValidationError::InvalidMask);
        }
        let subject = if let Some(value) = input.strip_prefix("$a:") {
            MaskSubject::Account(AccountRandomId::parse(value)?)
        } else if let Some(value) = input.strip_prefix("$u:") {
            MaskSubject::User(UserId::parse(value)?)
        } else if let Some(value) = input.strip_prefix("$n:") {
            MaskSubject::Nickname(CompiledGlob::compile(value, GlobCase::AsciiInsensitive)?)
        } else if let Some(value) = input.strip_prefix("$c:") {
            MaskSubject::Cloak(CompiledGlob::compile(value, GlobCase::Exact)?)
        } else {
            return Err(ValidationError::InvalidPrefix);
        };
        Ok(Self {
            quiet: false,
            subject,
        })
    }

    /// Reports whether this mask is the one permitted quiet wrapper.
    #[must_use]
    pub const fn is_quiet(&self) -> bool {
        self.quiet
    }

    /// Borrows the typed subject.
    #[must_use]
    pub const fn subject(&self) -> &MaskSubject {
        &self.subject
    }

    /// Matches a routing nickname only when this is a nickname-glob mask.
    #[must_use]
    pub fn matches_nickname(&self, nickname: &Nickname) -> bool {
        match &self.subject {
            MaskSubject::Nickname(glob) => glob.is_match(nickname.canonical()),
            _ => false,
        }
    }

    /// Matches a visible cloak string only when this is a cloak-glob mask.
    #[must_use]
    pub fn matches_cloak(&self, cloak: &str) -> bool {
        match &self.subject {
            MaskSubject::Cloak(glob) => glob.is_match(cloak),
            _ => false,
        }
    }
}
