//! Operating-system entropy authority.

use agenc_relay_types::{EntropyError, EntropySource};

use crate::CryptoError;

/// Production entropy sourced directly from the operating system.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsEntropy;

impl OsEntropy {
    /// Fills the complete destination or returns a closed failure.
    ///
    /// On failure, callers must discard the destination; no partial result is
    /// ever returned as successful output.
    pub fn fill(destination: &mut [u8]) -> Result<(), CryptoError> {
        fill_from(destination, |output| {
            getrandom::fill(output).map_err(|_| CryptoError::EntropyUnavailable)
        })
    }
}

fn fill_from<F>(destination: &mut [u8], source: F) -> Result<(), CryptoError>
where
    F: FnOnce(&mut [u8]) -> Result<(), CryptoError>,
{
    match source(destination) {
        Ok(()) => Ok(()),
        Err(error) => {
            destination.fill(0);
            Err(error)
        }
    }
}

impl EntropySource for OsEntropy {
    fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        Self::fill(destination).map_err(|_| EntropyError::Unavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::{OsEntropy, fill_from};
    use crate::CryptoError;

    fn write_prefix_then_fail(output: &mut [u8]) -> Result<(), CryptoError> {
        let Some(prefix) = output.get_mut(..8) else {
            return Err(CryptoError::EntropyUnavailable);
        };
        prefix.fill(7);
        Err(CryptoError::EntropyUnavailable)
    }

    #[test]
    fn fills_the_complete_destination() {
        let mut bytes = [0_u8; 64];
        assert!(OsEntropy::fill(&mut bytes).is_ok());
        assert_ne!(bytes, [0_u8; 64]);
    }

    #[test]
    fn erases_partial_output_when_the_source_fails() {
        let mut bytes = [9_u8; 16];
        let result = fill_from(&mut bytes, write_prefix_then_fail);
        assert_eq!(result, Err(CryptoError::EntropyUnavailable));
        assert_eq!(bytes, [0_u8; 16]);

        let mut empty = [];
        assert_eq!(
            fill_from(&mut empty, write_prefix_then_fail),
            Err(CryptoError::EntropyUnavailable)
        );
    }
}
