//! Allocation-bounded byte strings and validated UTF-8.

use crate::ValidationError;

fn validate_length<const MIN: usize, const MAX: usize>(
    length: usize,
) -> Result<(), ValidationError> {
    if MIN > MAX {
        return Err(ValidationError::OutOfRange);
    }
    if length < MIN {
        return Err(if length == 0 {
            ValidationError::Empty
        } else {
            ValidationError::TooShort
        });
    }
    if length > MAX {
        return Err(ValidationError::TooLong);
    }
    Ok(())
}

/// A byte vector whose inclusive length bounds are retained by construction.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedBytes<const MIN: usize, const MAX: usize> {
    bytes: Vec<u8>,
}

impl<const MIN: usize, const MAX: usize> BoundedBytes<MIN, MAX> {
    /// Copies a borrowed slice only after validating its complete length.
    pub fn try_from_slice(input: &[u8]) -> Result<Self, ValidationError> {
        validate_length::<MIN, MAX>(input.len())?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(input.len())
            .map_err(|_| ValidationError::AllocationFailed)?;
        bytes.extend_from_slice(input);
        Ok(Self { bytes })
    }

    /// Validates an already-owned vector without another allocation.
    pub fn try_from_vec(bytes: Vec<u8>) -> Result<Self, ValidationError> {
        validate_length::<MIN, MAX>(bytes.len())?;
        Ok(Self { bytes })
    }

    /// Borrows the validated bytes.
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    /// Returns the exact validated byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Reports whether this domain permits and contains an empty value.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Transfers ownership of the validated bytes.
    #[must_use]
    pub fn into_vec(self) -> Vec<u8> {
        self.bytes
    }
}

/// Field-level control-character policy for bounded UTF-8.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ControlPolicy {
    /// Reject every Unicode control character.
    RejectAll,
    /// Permit horizontal tab while rejecting every other control character.
    PermitHorizontalTab,
}

/// UTF-8 whose byte bounds, NUL rule, and control policy are retained.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct BoundedUtf8<const MIN: usize, const MAX: usize> {
    text: String,
}

impl<const MIN: usize, const MAX: usize> BoundedUtf8<MIN, MAX> {
    /// Validates bytes before performing a bounded copy.
    pub fn try_from_bytes(input: &[u8], controls: ControlPolicy) -> Result<Self, ValidationError> {
        validate_length::<MIN, MAX>(input.len())?;
        let text = std::str::from_utf8(input).map_err(|_| ValidationError::InvalidUtf8)?;
        Self::try_from_str(text, controls)
    }

    /// Validates text before performing a bounded copy.
    pub fn try_from_str(input: &str, controls: ControlPolicy) -> Result<Self, ValidationError> {
        validate_length::<MIN, MAX>(input.len())?;
        for character in input.chars() {
            if character == '\0' {
                return Err(ValidationError::Nul);
            }
            if character.is_control()
                && !(controls == ControlPolicy::PermitHorizontalTab && character == '\t')
            {
                return Err(ValidationError::Control);
            }
        }
        let mut text = String::new();
        text.try_reserve_exact(input.len())
            .map_err(|_| ValidationError::AllocationFailed)?;
        text.push_str(input);
        Ok(Self { text })
    }

    /// Borrows the validated text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// Returns the exact validated UTF-8 byte length.
    #[must_use]
    pub fn len(&self) -> usize {
        self.text.len()
    }

    /// Reports whether this domain permits and contains an empty value.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.text.is_empty()
    }

    /// Transfers ownership of the validated UTF-8.
    #[must_use]
    pub fn into_string(self) -> String {
        self.text
    }
}
