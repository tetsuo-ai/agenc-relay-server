//! Reviewed Argon2id adapter for IRC channel-key verifiers.

use argon2::{Algorithm, Argon2, Params, Version};

use crate::AuthError;

/// Argon2id memory cost for channel secrets, in KiB.
pub const CHANNEL_KEY_MEMORY_KIB: u32 = 65_536;
/// Argon2id iteration count for channel secrets.
pub const CHANNEL_KEY_ITERATIONS: u32 = 3;
/// Argon2id parallelism for channel secrets.
pub const CHANNEL_KEY_LANES: u32 = 4;
/// Salt bytes stored beside one channel-key verifier.
pub const CHANNEL_KEY_SALT_BYTES: usize = 16;
/// Bytes in one derived channel-key verifier.
pub const CHANNEL_KEY_HASH_BYTES: usize = 32;

/// Derives one fixed-profile channel-key verifier.
///
/// The caller owns input length validation and moves this blocking operation
/// onto the bounded cryptographic worker pool.
pub fn derive_channel_key_verifier(
    secret: &[u8],
    salt: &[u8; CHANNEL_KEY_SALT_BYTES],
) -> Result<[u8; CHANNEL_KEY_HASH_BYTES], AuthError> {
    let parameters = Params::new(
        CHANNEL_KEY_MEMORY_KIB,
        CHANNEL_KEY_ITERATIONS,
        CHANNEL_KEY_LANES,
        Some(CHANNEL_KEY_HASH_BYTES),
    )
    .map_err(|_| AuthError::InvalidEncoding)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, parameters);
    let mut output = [0_u8; CHANNEL_KEY_HASH_BYTES];
    argon2
        .hash_password_into(secret, salt, &mut output)
        .map_err(|_| AuthError::AuthenticationFailed)?;
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_key_profile_is_fixed_and_domain_separates_inputs() -> Result<(), AuthError> {
        assert_eq!(CHANNEL_KEY_MEMORY_KIB, 65_536);
        assert_eq!(CHANNEL_KEY_ITERATIONS, 3);
        assert_eq!(CHANNEL_KEY_LANES, 4);
        let first = derive_channel_key_verifier(b"agenc-channel-test", &[3; 16])?;
        let second = derive_channel_key_verifier(b"agenc-channel-test-2", &[3; 16])?;
        assert_ne!(first, second);
        assert_ne!(first, [0; CHANNEL_KEY_HASH_BYTES]);
        Ok(())
    }
}
