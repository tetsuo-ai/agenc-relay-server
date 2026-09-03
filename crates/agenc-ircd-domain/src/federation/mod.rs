//! Pure base-federation state logic (spec 20, Appendix B).
//!
//! Everything here is deterministic and free of I/O: origin lifecycle and
//! replay classification, least-information projection derivation, the
//! edge's committed replica, and query-cursor bindings. The runtime supplies
//! clocks, entropy, storage, and wire encoding.

pub mod origin;
pub mod projection;
pub mod query_cursor;
pub mod record;
pub mod replica;

pub use origin::{
    EdgeLink, EdgePhase, OperationKey, OriginBinding, OriginDeclaration, OriginEntry, OriginError,
    OriginKey, OriginPrincipal, OriginStatus, OriginTable, ReplayDecision, RetainedRequest,
};
pub use projection::{
    CoordinatorProjection, EdgeDelta, EdgeStanding, MutationContext, MutationProjection,
    channel_detail_from, session_record_from, simple_mode_bits, user_mode_bits,
};
pub use query_cursor::{
    ContinuationRequest, CursorCollision, CursorCounter, CursorRejection, LiveCursor,
    QueryCursorBinding, QueryCursorTable,
};
pub use record::{
    AccountRecord, ActorView, ChannelDetailRecord, DeliveredMessageRecord, DeliveryTarget,
    EventPhase, InviteRecord, InviteRemovalKind, MembershipRecord, MembershipView, ModeDirection,
    ModeListEntryRecord, ProjectedEvent, ProjectedModeChange, ProjectionKey, ProjectionRecord,
    SessionEventView, SessionHideKind, SessionRecord, SourceView, role_level,
};
pub use replica::{ApplyOutcome, EdgeReplica, ReplicaError};
