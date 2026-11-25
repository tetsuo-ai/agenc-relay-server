//! Shared constants of the optional prospective initial-root profile.

/// The client capability name independently negotiated on the active connection.
pub const INITIAL_ROOT_CAPABILITY: &str = "agenc.ag/initial-root";

/// Digest of the pinned base, ARC-MLS and prospective initial-root specification.
pub const INITIAL_ROOT_PROFILE_SHA256: [u8; 32] = [
    0x55, 0x0b, 0x56, 0x94, 0x3d, 0xc9, 0x03, 0x98, 0xda, 0xb5, 0x24, 0xb1, 0xe5, 0xc3, 0x3c, 0xd3,
    0x61, 0x8c, 0xfd, 0xfe, 0x7a, 0x30, 0x9a, 0xce, 0x3f, 0xc7, 0x85, 0xb1, 0xd6, 0x7e, 0x84, 0x4d,
];

/// Unpadded base64url encoding of the prospective initial-root profile digest.
pub const INITIAL_ROOT_PROFILE_TOKEN: &str = "VQtWlD3JA5jatSSx5cM802GM_f56MJrOP8eFsdZ-hE0";
