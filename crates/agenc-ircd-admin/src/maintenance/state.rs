//! Closed public facts for a login-index key transition, independent of storage.
#![forbid(unsafe_code)]

use crate::AdminError;
use crate::codec::{Reader, Writer};

/// The two stopped maintenance operations admitted by encoding two.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MaintenanceOperation {
    /// Stable state becomes an exact two-generation transition.
    LoginIndexRotateStart,
    /// A zero-count transition becomes stable under the same current key.
    LoginIndexRotateFinish,
}

impl MaintenanceOperation {
    /// Returns the closed wire discriminator.
    #[must_use]
    pub const fn as_u16(self) -> u16 {
        match self {
            Self::LoginIndexRotateStart => 1,
            Self::LoginIndexRotateFinish => 2,
        }
    }

    /// Rejects every unassigned discriminator.
    pub const fn from_u16(value: u16) -> Result<Self, AdminError> {
        match value {
            1 => Ok(Self::LoginIndexRotateStart),
            2 => Ok(Self::LoginIndexRotateFinish),
            _ => Err(AdminError::Audit),
        }
    }
}

/// The exact public key-state tuple before or after maintenance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceKeyState {
    current_generation: u32,
    current_key_id: [u8; 32],
    previous_generation: u32,
    previous_key_id: [u8; 32],
    previous_entry_count: u64,
}

impl MaintenanceKeyState {
    /// Validates stable absence or one exact consecutive previous generation.
    pub fn new(
        current_generation: u32,
        current_key_id: [u8; 32],
        previous_generation: u32,
        previous_key_id: [u8; 32],
        previous_entry_count: u64,
    ) -> Result<Self, AdminError> {
        let value = Self {
            current_generation,
            current_key_id,
            previous_generation,
            previous_key_id,
            previous_entry_count,
        };
        value.validate()?;
        Ok(value)
    }

    fn validate(self) -> Result<(), AdminError> {
        if self.current_generation == 0 {
            return Err(AdminError::Audit);
        }
        if self.previous_generation == 0 {
            return if self.previous_key_id == [0; 32] && self.previous_entry_count == 0 {
                Ok(())
            } else {
                Err(AdminError::Audit)
            };
        }
        if self.previous_generation.checked_add(1) != Some(self.current_generation)
            || self.previous_key_id == self.current_key_id
        {
            return Err(AdminError::Audit);
        }
        Ok(())
    }

    /// Returns the nonzero current generation.
    #[must_use]
    pub const fn current_generation(self) -> u32 {
        self.current_generation
    }
    /// Returns the public identifier of the current key.
    #[must_use]
    pub const fn current_key_id(self) -> [u8; 32] {
        self.current_key_id
    }
    /// Returns the previous generation, public key ID, and exact count if present.
    #[must_use]
    pub const fn previous(self) -> Option<(u32, [u8; 32], u64)> {
        if self.previous_generation == 0 {
            None
        } else {
            Some((
                self.previous_generation,
                self.previous_key_id,
                self.previous_entry_count,
            ))
        }
    }

    pub(super) fn put(self, writer: &mut Writer) -> Result<(), AdminError> {
        self.validate()?;
        writer.put_fixed(&self.current_generation.to_be_bytes())?;
        writer.put_fixed(&self.current_key_id)?;
        writer.put_fixed(&self.previous_generation.to_be_bytes())?;
        writer.put_fixed(&self.previous_key_id)?;
        writer.put_u64(self.previous_entry_count)
    }

    pub(super) fn take(reader: &mut Reader<'_>) -> Result<Self, AdminError> {
        Self::new(
            u32::from_be_bytes(reader.fixed()?),
            reader.fixed()?,
            u32::from_be_bytes(reader.fixed()?),
            reader.fixed()?,
            reader.u64()?,
        )
    }
}

/// Validated before/after facts for exactly one stopped key transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MaintenanceTransition {
    operation: MaintenanceOperation,
    preceding: MaintenanceKeyState,
    resulting: MaintenanceKeyState,
}

impl MaintenanceTransition {
    /// Checks the operation against both complete key-state tuples.
    pub fn new(
        operation: MaintenanceOperation,
        preceding: MaintenanceKeyState,
        resulting: MaintenanceKeyState,
    ) -> Result<Self, AdminError> {
        let value = Self {
            operation,
            preceding,
            resulting,
        };
        value.validate()?;
        Ok(value)
    }

    pub(super) fn validate(self) -> Result<(), AdminError> {
        self.preceding.validate()?;
        self.resulting.validate()?;
        match self.operation {
            MaintenanceOperation::LoginIndexRotateStart => self.validate_start(),
            MaintenanceOperation::LoginIndexRotateFinish => self.validate_finish(),
        }
    }

    fn validate_start(self) -> Result<(), AdminError> {
        let before = self.preceding;
        let after = self.resulting;
        if before.previous_generation != 0
            || before.current_generation.checked_add(1) != Some(after.current_generation)
            || after.previous_generation != before.current_generation
            || after.previous_key_id != before.current_key_id
            || after.current_key_id == before.current_key_id
        {
            return Err(AdminError::Audit);
        }
        Ok(())
    }

    fn validate_finish(self) -> Result<(), AdminError> {
        let before = self.preceding;
        let after = self.resulting;
        if before.previous_generation == 0
            || before.previous_entry_count != 0
            || after.previous_generation != 0
            || after.current_generation != before.current_generation
            || after.current_key_id != before.current_key_id
        {
            return Err(AdminError::Audit);
        }
        Ok(())
    }

    /// Returns the maintenance discriminator.
    #[must_use]
    pub const fn operation(self) -> MaintenanceOperation {
        self.operation
    }
    /// Returns the authenticated preceding key state.
    #[must_use]
    pub const fn preceding(self) -> MaintenanceKeyState {
        self.preceding
    }
    /// Returns the exact resulting key state.
    #[must_use]
    pub const fn resulting(self) -> MaintenanceKeyState {
        self.resulting
    }

    pub(super) fn put(self, writer: &mut Writer) -> Result<(), AdminError> {
        self.validate()?;
        writer.put_u16(self.operation.as_u16())?;
        self.preceding.put(writer)?;
        self.resulting.put(writer)
    }

    pub(super) fn take(reader: &mut Reader<'_>) -> Result<Self, AdminError> {
        Self::new(
            MaintenanceOperation::from_u16(reader.u16()?)?,
            MaintenanceKeyState::take(reader)?,
            MaintenanceKeyState::take(reader)?,
        )
    }
}
