#![forbid(unsafe_code)]

//! Canonical federation codecs and frozen Appendix-B schemas.
//!
//! This crate validates complete borrowed objects before dispatch, types the
//! Section-20 line forms, reassembles fragmented objects under the fixed link
//! ceilings, and checks the hello tuple. It holds no sockets, clocks, keys,
//! or policy; the runtime supplies those.

mod assembly;
mod codec;
mod frames;
mod hashes;
mod hello;
mod objects;
mod schema;
mod semantics;
mod text;

pub use assembly::{
    AssembledObject, AssemblyError, AssemblyProgress, FragmentAssembler, FragmentDescriptorKey,
    split_fragments,
};

pub use codec::{
    CanonicalBytes, CanonicalEncode, CodecError, DecodeBudget, SchemaObject, WireValue,
};
pub use frames::{
    DeliveryCursor, EventDescriptor, FHELLO_LINE_BYTES, FederationFrame, FederationFrameKind,
    FederationLine, FederationLineText, FrameError, OperationDescriptor, OriginDescriptor,
    SnapshotIdentity,
};
pub use hashes::{
    ARCHITECTURE_DOCUMENT_SHA256, BASE_FEDERATION_PROFILE_SHA256, BASE_FEDERATION_PROFILE_TOKEN,
    E2EE_DOCUMENT_SHA256, E2EE_PROFILE_SHA256, E2EE_PROFILE_TOKEN, FEDERATION_REGISTRY_SHA256,
    SOURCE_LEDGER_SHA256,
};
pub use hello::{
    EpochRejection, EpochTransition, HelloExpectation, HelloRejection, PeerContinuity,
    classify_epoch_transition, verify_hello_tuple,
};
pub use objects::{
    CrossProfilePart, EventHeader, FEDERATION_EXPORTER_CONTEXT_BYTES, FEDERATION_EXPORTER_LABEL,
    FEDERATION_HELLO_SIGNATURE_LABEL, FEDERATION_OBJECT_HASH_LABEL, FEDERATION_PROFILE_VERSION,
    FEDERATION_SNAPSHOT_HASH_LABEL, FederationHello, HelloTbs, OriginAccount, OriginRecord,
    OriginSession, ProjectionEntryHeader, ProjectionPrimaryKey, ReplayKey, RequestCorrelation,
    RequestHeader, ResultHeader, decode_event_arm, decode_projection_arm, decode_request_operation,
    decode_result_arm, event_schema_name, exporter_context, federation_object_id,
    hello_signature_input, opcode_registry_name, operation_schema_name, permitted_success_results,
    projection_schema_name, result_kind_permitted, result_kind_registry_name, result_mapping_value,
    result_schema_name, snapshot_digest,
};
/// Field accessors and builders over validated schema objects.
pub mod access {
    pub use crate::objects::{
        expect_schema, field, fixed, opaque, opaque_field, optional_fixed, projection_union,
        structure, text, unsigned, unsigned_u16, unsigned_u32, vector,
    };
}
pub use schema::{
    FieldDescriptor, FieldKind, LengthWidth, SCHEMA_REGISTRY, SchemaDescriptor, schema_by_name,
};
pub use text::{
    FEDERATION_COMMAND_FORMS, FEDERATION_FRAGMENT_TAG_NAME, FederationCommandDescriptor,
    FederationCommandTag, FederationCommandTags, FederationFragment, FederationFragmentText,
    FederationHash32, FederationId16, FederationTextError, FragmentTagPolicy, StarCursor, StarId,
    parse_federation_u32, parse_federation_u64, validate_federation_command,
};
