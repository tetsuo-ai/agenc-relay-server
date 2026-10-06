//! The exact RFC 9807 OPAQUE profile of Architecture Section 11.2.
//!
//! The coordinator's server calls in this crate and the client calls in
//! [`crate::client`] both take the suite, key-stretching function, context and
//! identities from here, so a client that names these items derives exactly
//! the bytes the coordinator verifies.

use agenc_relay_types::{EntropySource, NetworkId, OpaqueCredentialId};
use argon2::{Algorithm, Argon2, Params, Version};
use opaque_ke::errors::InternalError;
use opaque_ke::generic_array::{ArrayLength, GenericArray};
use opaque_ke::ksf::Ksf;
use opaque_ke::rand::{CryptoRng, Error as RandError, RngCore};
use opaque_ke::{CipherSuite, Identifiers, Ristretto255, TripleDh};
use zeroize::Zeroizing;

/// Argon2id memory cost in KiB.
pub const OPAQUE_ARGON2_MEMORY_KIB: u32 = 65_536;
/// Argon2id passes.
pub const OPAQUE_ARGON2_ITERATIONS: u32 = 3;
/// Argon2id lanes.
pub const OPAQUE_ARGON2_LANES: u32 = 4;
/// Argon2id output bytes, the suite's SHA-512 width.
pub const OPAQUE_ARGON2_OUTPUT_BYTES: usize = 64;
/// Argon2id salt: sixteen zero bytes.
pub const OPAQUE_ARGON2_SALT: [u8; 16] = [0_u8; 16];
/// Exact byte length of the context label.
pub const OPAQUE_CONTEXT_LABEL_BYTES: usize = 36;
/// The context label; the 32 Network-ID bytes follow it with no separator.
pub const OPAQUE_CONTEXT_LABEL: &[u8; OPAQUE_CONTEXT_LABEL_BYTES] =
    b"agenc-chat account authentication v1";
/// Exact byte length of one complete context: the label and the Network ID.
pub const OPAQUE_CONTEXT_BYTES: usize = OPAQUE_CONTEXT_LABEL_BYTES + 32;
/// Exact byte length of the login session key, the suite's SHA-512 width.
pub const OPAQUE_SESSION_KEY_BYTES: usize = 64;
/// Exact byte length of the client export key, the suite's SHA-512 width.
pub const OPAQUE_EXPORT_KEY_BYTES: usize = 64;

/// The fixed suite: ristretto255-SHA512 OPRF, TripleDH over ristretto255 with
/// SHA-512, and [`FixedArgon2id`].
pub struct AgencOpaqueSuite;

impl CipherSuite for AgencOpaqueSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, opaque_sha2::Sha512>;
    type Ksf = FixedArgon2id;
}

/// The fixed Argon2id v1.3 key-stretching function: 65,536 KiB, three passes,
/// four lanes, a 64-byte output and sixteen zero salt bytes. It refuses any
/// other input width.
pub struct FixedArgon2id;

impl Default for FixedArgon2id {
    fn default() -> Self {
        Self
    }
}

impl Ksf for FixedArgon2id {
    fn hash<L: ArrayLength<u8>>(
        &self,
        input: GenericArray<u8, L>,
    ) -> Result<GenericArray<u8, L>, InternalError> {
        let input = Zeroizing::new(input);
        if input.len() != OPAQUE_ARGON2_OUTPUT_BYTES {
            return Err(InternalError::KsfError);
        }
        let parameters = Params::new(
            OPAQUE_ARGON2_MEMORY_KIB,
            OPAQUE_ARGON2_ITERATIONS,
            OPAQUE_ARGON2_LANES,
            Some(OPAQUE_ARGON2_OUTPUT_BYTES),
        )
        .map_err(|_| InternalError::KsfError)?;
        let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
        let mut output: Zeroizing<GenericArray<u8, L>> = Zeroizing::new(GenericArray::default());
        argon2
            .hash_password_into(input.as_ref(), &OPAQUE_ARGON2_SALT, output.as_mut())
            .map_err(|_| InternalError::KsfError)?;
        Ok(GenericArray::clone_from_slice(output.as_ref()))
    }
}

/// The random-number adapter the OPAQUE library draws through, over one
/// entropy source, latching the first failure.
///
/// The library draws through the infallible `RngCore` interface. On the first
/// draw the source cannot fill, the adapter writes a nonzero sentinel and
/// stays failed; every caller checks [`succeeded`](Self::succeeded) after the
/// library returns and discards the library's result. The adapter is as
/// unpredictable as its source: production callers pass the operating-system
/// source, and only deterministic tests pass anything else.
pub struct FallibleOpaqueRng<E> {
    entropy: E,
    failed: bool,
}

impl<E: EntropySource> FallibleOpaqueRng<E> {
    /// Wraps one entropy source; no draw has failed yet.
    pub const fn new(entropy: E) -> Self {
        Self {
            entropy,
            failed: false,
        }
    }

    /// Whether every draw so far filled its destination from the source.
    #[must_use]
    pub const fn succeeded(&self) -> bool {
        !self.failed
    }

    fn fill_or_latch(&mut self, destination: &mut [u8]) {
        if self.failed || self.entropy.fill_exact(destination).is_err() {
            destination.fill(0);
            // The pinned Ristretto generators reject an all-zero scalar and
            // retry through this infallible `RngCore` interface. Supply a
            // nonzero sentinel so that failed entropy cannot trap the worker
            // in that rejection loop. `failed` remains latched, and every
            // caller discards the library result before it can become state.
            if let Some(first) = destination.first_mut() {
                *first = 1;
            }
            self.failed = true;
        }
    }
}

impl<E: EntropySource> RngCore for FallibleOpaqueRng<E> {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0_u8; 4];
        self.fill_or_latch(&mut bytes);
        u32::from_be_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0_u8; 8];
        self.fill_or_latch(&mut bytes);
        u64::from_be_bytes(bytes)
    }

    fn fill_bytes(&mut self, destination: &mut [u8]) {
        self.fill_or_latch(destination);
    }

    fn try_fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), RandError> {
        self.fill_or_latch(destination);
        Ok(())
    }
}

impl<E: EntropySource> CryptoRng for FallibleOpaqueRng<E> {}

/// The exact context: the label immediately followed by the 32 Network-ID
/// bytes, with no NUL or length prefix.
#[must_use]
pub fn opaque_context(network_id: &NetworkId) -> [u8; OPAQUE_CONTEXT_BYTES] {
    let mut context = [0_u8; OPAQUE_CONTEXT_BYTES];
    let source = OPAQUE_CONTEXT_LABEL.iter().chain(network_id.as_bytes());
    for (slot, byte) in context.iter_mut().zip(source) {
        *slot = *byte;
    }
    context
}

/// The exact identities: the 32-byte credential ID is the client identity and
/// the Network ID is the server identity.
#[must_use]
pub fn opaque_identifiers<'a>(
    network_id: &'a NetworkId,
    credential_id: &'a OpaqueCredentialId,
) -> Identifiers<'a> {
    Identifiers {
        client: Some(credential_id.expose_for_account_service()),
        server: Some(network_id.as_bytes()),
    }
}

#[cfg(test)]
mod tests {
    use agenc_relay_types::{
        CRYPTO_DESCRIPTORS, EntropyError, EntropySource, NetworkId, OpaqueCredentialId,
    };
    use opaque_ke::generic_array::GenericArray;
    use opaque_ke::generic_array::typenum::{U32, U64};
    use opaque_ke::ksf::Ksf as _;
    use opaque_ke::rand::RngCore as _;

    use super::{
        AgencOpaqueSuite, FallibleOpaqueRng, FixedArgon2id, OPAQUE_ARGON2_ITERATIONS,
        OPAQUE_ARGON2_LANES, OPAQUE_ARGON2_MEMORY_KIB, OPAQUE_ARGON2_OUTPUT_BYTES,
        OPAQUE_ARGON2_SALT, OPAQUE_CONTEXT_BYTES, OPAQUE_CONTEXT_LABEL, opaque_context,
        opaque_identifiers,
    };

    /// Fills from a counter until its budget of successful fills runs out.
    struct Budgeted {
        next: u8,
        successes: usize,
    }

    impl EntropySource for Budgeted {
        fn fill_exact(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
            let Some(remaining) = self.successes.checked_sub(1) else {
                return Err(EntropyError::Unavailable);
            };
            self.successes = remaining;
            for byte in destination {
                *byte = self.next;
                self.next = self.next.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn fixed_ksf_accepts_only_the_profile_width() {
        assert!(
            FixedArgon2id
                .hash(GenericArray::<u8, U32>::default())
                .is_err()
        );
        assert!(
            FixedArgon2id
                .hash(GenericArray::<u8, U64>::default())
                .is_ok()
        );
    }

    #[test]
    fn the_profile_constants_are_the_frozen_registry_profile() {
        let registered = CRYPTO_DESCRIPTORS
            .iter()
            .find(|descriptor| descriptor.name == "opaque_profile")
            .map(|descriptor| descriptor.value)
            .unwrap_or_default();
        assert!(registered.starts_with("RFC9807;"), "{registered}");
        assert_eq!(OPAQUE_ARGON2_SALT, [0_u8; 16]);
        let ksf = format!(
            "ksf=Argon2id(v=19,m={OPAQUE_ARGON2_MEMORY_KIB}KiB,t={OPAQUE_ARGON2_ITERATIONS},\
             p={OPAQUE_ARGON2_LANES},out={OPAQUE_ARGON2_OUTPUT_BYTES},salt=16zero)"
        );
        assert!(registered.contains(&ksf), "{registered}");
        let label = core::str::from_utf8(OPAQUE_CONTEXT_LABEL).unwrap_or_default();
        let context = format!("context=\"{label}\"+network_id;");
        assert!(registered.contains(&context), "{registered}");
        assert!(registered.contains("oprf=ristretto255-SHA512;"));
        assert!(registered.contains("ake=TripleDh(ristretto255);"));
        assert!(registered.contains("client_identity=opaque_credential_id[32];"));
        assert!(registered.ends_with("server_identity=network_id"));
    }

    #[test]
    fn context_is_the_label_then_the_network_id() {
        let network = NetworkId::from_bytes([0x5a; 32]);
        let context = opaque_context(&network);
        assert_eq!(context.len(), OPAQUE_CONTEXT_BYTES);
        assert_eq!(&context[..36], OPAQUE_CONTEXT_LABEL);
        assert_eq!(&context[36..], network.as_bytes());
        assert_eq!(
            &context[..],
            b"agenc-chat account authentication v1ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ"
        );
    }

    #[test]
    fn identities_are_the_credential_id_and_the_network_id() {
        let network = NetworkId::from_bytes([0x11; 32]);
        let credential = OpaqueCredentialId::from_bytes([0x22; 32]);
        let identifiers = opaque_identifiers(&network, &credential);
        assert_eq!(identifiers.client, Some(&[0x22_u8; 32][..]));
        assert_eq!(identifiers.server, Some(&[0x11_u8; 32][..]));
    }

    #[test]
    fn rng_passes_source_bytes_until_the_first_failure_then_latches() {
        let mut rng = FallibleOpaqueRng::new(Budgeted {
            next: 7,
            successes: 2,
        });
        let mut bytes = [0_u8; 4];
        rng.fill_bytes(&mut bytes);
        assert_eq!(bytes, [7, 8, 9, 10]);
        assert_eq!(rng.next_u32(), u32::from_be_bytes([11, 12, 13, 14]));
        assert!(rng.succeeded());

        let mut bytes = [9_u8; 8];
        rng.fill_bytes(&mut bytes);
        assert_eq!(bytes, [1, 0, 0, 0, 0, 0, 0, 0]);
        assert!(!rng.succeeded());
        assert_eq!(rng.next_u32(), u32::from_be_bytes([1, 0, 0, 0]));
        assert_eq!(rng.next_u64(), u64::from_be_bytes([1, 0, 0, 0, 0, 0, 0, 0]));
        assert!(rng.try_fill_bytes(&mut bytes).is_ok());
        assert_eq!(bytes, [1, 0, 0, 0, 0, 0, 0, 0]);
        let mut empty: [u8; 0] = [];
        rng.fill_bytes(&mut empty);
        assert!(!rng.succeeded());
    }

    #[test]
    fn a_failed_source_cannot_trap_server_setup_in_scalar_rejection() {
        let mut rng = FallibleOpaqueRng::new(Budgeted {
            next: 0,
            successes: 0,
        });
        let _discarded_setup = opaque_ke::ServerSetup::<AgencOpaqueSuite>::new(&mut rng);
        assert!(!rng.succeeded());
    }
}
