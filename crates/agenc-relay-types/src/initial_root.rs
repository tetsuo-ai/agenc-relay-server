//! Shared constants of the optional prospective initial-root profile.

/// The client capability name independently negotiated on the active connection.
pub const INITIAL_ROOT_CAPABILITY: &str = "agenc.ag/initial-root";

/// Digest of the pinned base, ARC-MLS and prospective initial-root specification.
pub const INITIAL_ROOT_PROFILE_SHA256: [u8; 32] = [
    0x98, 0x82, 0xc6, 0xd6, 0x7a, 0x79, 0x8a, 0x85, 0xf6, 0x13, 0x61, 0x03, 0x2d, 0x78, 0xef, 0xa8,
    0xfe, 0x80, 0x2d, 0x70, 0x8f, 0x43, 0xc3, 0x96, 0xf2, 0xe4, 0x0d, 0xa4, 0x82, 0xd7, 0xe4, 0xa1,
];

/// Unpadded base64url encoding of the prospective initial-root profile digest.
pub const INITIAL_ROOT_PROFILE_TOKEN: &str = "mILG1np5ioX2E2EDLXjvqP6ALXCPQ8OW8uQNpILX5KE";

/// Independently negotiated current-root directory read.
pub const TERMINAL_ROOT_CAPABILITY: &str = "agenc.ag/root-head";

/// Hash over the optional version 2 profile and the exact terminal-head specification.
pub const TERMINAL_ROOT_PROFILE_SHA256: [u8; 32] = [
    0x42, 0x73, 0x7e, 0xfb, 0x2d, 0x11, 0xd1, 0xd6, 0xf7, 0x96, 0x71, 0xf0, 0x69, 0x4c, 0x27, 0x3a,
    0x9b, 0x57, 0xb3, 0x3e, 0x7b, 0x38, 0x1a, 0xed, 0xd7, 0xd0, 0x2e, 0xa0, 0xb3, 0x60, 0xab, 0xcf,
];

/// Unpadded base64url of the terminal-head profile.
pub const TERMINAL_ROOT_PROFILE_TOKEN: &str = "QnN--y0R0db3lnHwaUwnOptXsz57OBrt19AuoLNgq88";
