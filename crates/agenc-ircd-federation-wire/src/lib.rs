#![forbid(unsafe_code)]

//! Canonical federation codecs and frozen Appendix-B schemas.
//!
//! This crate validates complete borrowed objects before dispatch. It does not
//! implement connection state, fragment assembly, or peer authorization yet.

mod codec;
mod hashes;
mod schema;
mod semantics;
mod text;

pub use codec::{CanonicalEncode, CodecError, DecodeBudget, SchemaObject, WireValue};
pub use hashes::{
    ARCHITECTURE_DOCUMENT_SHA256, BASE_FEDERATION_PROFILE_SHA256, BASE_FEDERATION_PROFILE_TOKEN,
    E2EE_DOCUMENT_SHA256, E2EE_PROFILE_SHA256, E2EE_PROFILE_TOKEN, FEDERATION_REGISTRY_SHA256,
    SOURCE_LEDGER_SHA256,
};
pub use schema::{
    FieldDescriptor, FieldKind, LengthWidth, SCHEMA_REGISTRY, SchemaDescriptor, schema_by_name,
};
pub use text::{
    FEDERATION_COMMAND_FORMS, FederationCommandDescriptor, FederationFragment, FederationHash32,
    FederationId16, FederationTextError, FragmentTagPolicy, StarCursor, StarId,
    parse_federation_u32, parse_federation_u64, validate_federation_command,
};
