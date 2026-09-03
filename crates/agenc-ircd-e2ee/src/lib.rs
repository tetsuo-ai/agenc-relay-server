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

pub mod error;
pub mod ids;
pub mod limits;
pub mod mls_outer;
pub mod object;
pub mod objects;
pub mod profile;
pub mod signature;
pub mod tls;

pub use error::E2eeError;
pub use object::{IrcWireObject, IrcWireObjectKind, ObjectId};
pub use tls::{DecodeBudget, Opaque, TlsDecode, TlsEncode, TlsVec};
