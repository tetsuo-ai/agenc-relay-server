#![forbid(unsafe_code)]

//! Public-object validation for the IRC-MLS companion profile.
//!
//! The daemon is an untrusted MLS Delivery Service. This crate knows only the
//! public objects and checks the companion specification assigns to servers:
//! canonical TLS encodings, semantic identifiers, registered-label signatures,
//! identity and roster chains, route bindings, policy and quorum arithmetic,
//! sequencer records, MLS outer framing, and the federation objects. It never
//! contains an MLS client, never derives or accepts an epoch secret or
//! plaintext, and never takes a root or device private key. Every check an
//! endpoint must perform over private MLS state is named in the module docs
//! as endpoint-only so that absence here is deliberate, not an omission.
//!
//! # Public validation surfaces
//!
//! - [`tls`]: the bounded presentation-language codec and decode budget.
//! - [`objects`]: every companion structure, the typed body dispatch, and
//!   the shape helpers for fixed-size identifiers.
//! - [`object`]: the `IrcWireObject` envelope, per-kind maxima, and the
//!   transport object identifier.
//! - [`ids`]: semantic identifiers and digests over TBS encodings.
//! - [`identity`]: root chains, device certificates, rosters, capability
//!   statements, leaf authorizations, credential bundles, and pinned heads.
//! - [`signature`]: registered-label verification with role-bound public
//!   keys; there is no signing entry point.
//! - [`mls_outer`]: RFC 9420 outer framing, the public KeyPackage, and its
//!   reference and signatures.
//! - [`route`]: canonical channel names, concrete and semantic routes,
//!   binding packages with unanimous approvals and root locks, and close
//!   authorization identifiers.
//! - [`policy`]: conversation policies, controller sets, councils, and the
//!   finality quorum arithmetic.
//! - [`sequencer`]: sequencer credential chains and the federation key set.
//! - [`authorization`]: candidate-specific commit authorizations, the action
//!   bit table, and approval envelopes.
//! - [`close`]: controller approvals under the last finalized policy.
//! - [`finality`]: disposition votes, sign-once slots, and quorum ledgers.
//! - [`context`]: the required MLS context extension and the context core.
//! - [`envelope`]: application and Commit outer objects and the padding
//!   arithmetic.
//! - [`welcome`]: Welcome and staged ReInit wrappers and proof bundles.
//! - [`wire`]: tokens, fragment tags, the carrier matrix, reassembly,
//!   command and response productions, and reply codes.
//! - [`federation`]: the `E*` frame grammar, the ECAP negotiation, and the
//!   sequencer credentials file.
//! - [`profile`]: the exact capability value and ECAP tuple.
//! - [`limits`]: the Section 16 constants.
//!
//! # Separation guarantees
//!
//! The workspace policy (`scripts/check-workspace.py`) rejects any MLS
//! client engine in a production crate, and the source policy
//! (`scripts/check-source.py`) rejects any secret-bearing or signing
//! identifier in this crate. The API itself accepts no secret wrapper:
//!
//! ```compile_fail
//! use agenc_ircd_crypto::Ed25519SecretKey;
//! use agenc_ircd_e2ee::signature::{RoleKey, SignerRole};
//! let secret = Ed25519SecretKey::from_bytes([1; 32]);
//! let _ = RoleKey::new(SignerRole::Root, secret);
//! ```
//!
//! ```compile_fail
//! use agenc_ircd_crypto::Ed25519SecretKey;
//! use agenc_ircd_e2ee::object::{IrcWireObject, IrcWireObjectKind};
//! let secret = Ed25519SecretKey::from_bytes([1; 32]);
//! let _ = IrcWireObject::new(IrcWireObjectKind::RootIdentity, secret);
//! ```

pub mod authorization;
pub mod close;
pub mod context;
pub mod envelope;
pub mod error;
pub mod federation;
pub mod finality;
pub mod identity;
pub mod ids;
pub mod limits;
pub mod mls_outer;
pub mod object;
pub mod objects;
pub mod policy;
pub mod profile;
pub mod record_authentication;
pub mod reinit_authorization;
pub mod route;
pub mod sequencer;
pub mod signature;
pub mod tls;
pub mod welcome;
pub mod wire;

pub use error::E2eeError;
pub use object::{IrcWireObject, IrcWireObjectKind, ObjectId};
pub use tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};

#[cfg(test)]
#[path = "tests/support.rs"]
pub(crate) mod test_support;
