//! Internal move-only secret storage.

use zeroize::Zeroizing;

/// Fixed-size secret storage with no formatting or cloning surface.
pub(crate) struct SecretBytes<const SIZE: usize>(Zeroizing<[u8; SIZE]>);

impl<const SIZE: usize> SecretBytes<SIZE> {
    pub(crate) fn new(bytes: [u8; SIZE]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub(crate) fn as_bytes(&self) -> &[u8; SIZE] {
        &self.0
    }

    pub(crate) fn as_mut_bytes(&mut self) -> &mut [u8; SIZE] {
        &mut self.0
    }
}
