//! The explicitly configured optional federation profile. Its hello uses the
//! original fixed layout and signs the selected wire version and profile hash.

mod transfer;
pub use transfer::{InitialRootOperation, InitialRootRequest, InitialRootResult};

use crate::{BASE_FEDERATION_PROFILE_SHA256, CodecError, FederationHello, HelloTbs};
pub use agenc_relay_types::{INITIAL_ROOT_PROFILE_SHA256, INITIAL_ROOT_PROFILE_TOKEN};

/// The exact base-federation grammar configured for one authenticated peer.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum FederationProfile {
    /// The original Appendix B registry.
    #[default]
    Base,
    /// Appendix B plus prospective root creation and the private claim exchange.
    InitialRoot,
}

impl FederationProfile {
    /// Hash the peer must authenticate on this link.
    #[must_use]
    pub const fn hash(self) -> [u8; 32] {
        match self {
            Self::Base => BASE_FEDERATION_PROFILE_SHA256,
            Self::InitialRoot => INITIAL_ROOT_PROFILE_SHA256,
        }
    }

    fn hello_bytes<const N: usize>(
        self,
        base: &[u8],
        hash: [u8; 32],
    ) -> Result<[u8; N], CodecError> {
        let mut wire: [u8; N] = base.try_into().map_err(|_| CodecError::TypeMismatch)?;
        if self == Self::InitialRoot {
            if hash != self.hash() {
                return Err(CodecError::CrossReference);
            }
            // Both profiles use exactly the same validated fields. Only the
            // leading version changes, including in the input to Ed25519.
            let version = wire.get_mut(..2).ok_or(CodecError::UnexpectedEof)?;
            version.copy_from_slice(&2_u16.to_be_bytes());
        }
        Ok(wire)
    }

    /// Canonical signature input before the ordinary federation domain label.
    pub fn hello_tbs(self, tbs: &HelloTbs) -> Result<[u8; 196], CodecError> {
        self.hello_bytes(tbs.encode()?.as_slice(), tbs.profile_hash)
    }

    pub(crate) fn encode_hello(self, hello: &FederationHello) -> Result<[u8; 260], CodecError> {
        self.hello_bytes(hello.encode()?.as_slice(), hello.tbs.profile_hash)
    }

    pub(crate) fn decode_hello(self, mut wire: [u8; 260]) -> Result<FederationHello, CodecError> {
        if self == Self::Base {
            return FederationHello::decode(&wire);
        }
        let version = wire.get_mut(..2).ok_or(CodecError::UnexpectedEof)?;
        if version != 2_u16.to_be_bytes() {
            return Err(CodecError::CrossReference);
        }
        version.copy_from_slice(&1_u16.to_be_bytes());
        let hello = FederationHello::decode(&wire)?;
        if hello.tbs.profile_hash != self.hash() {
            return Err(CodecError::CrossReference);
        }
        Ok(hello)
    }
}
