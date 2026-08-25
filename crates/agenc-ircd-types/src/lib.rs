#![forbid(unsafe_code)]

//! Validated shared types and frozen protocol registries.
//!
//! Constructors validate hostile input before allocation. Domain-separated
//! identifiers, units, names, and masks do not provide implicit cross-domain
//! conversions.

mod bounded;
mod errors;
mod identifiers;
mod masks;
mod names;
mod quantities;
mod registries;

pub use bounded::{BoundedBytes, BoundedUtf8, ControlPolicy};
pub use errors::{SafeContext, ValidationError};
pub use identifiers::{
    AccountId, AccountRandomId, AuthGrantId, ChannelInstanceId, ConnectionId, DatabaseId, EntryId,
    EventId, InviteId, MessageId, NetworkId, OpaqueCredentialId, OriginId, RecoveryEpoch,
    RequestId, ServerId, ServerIncarnation, SessionId, TransactionId, UserId,
};
pub use masks::{CompiledGlob, MAX_GLOB_BYTES, MAX_TYPED_MASK_BYTES, MaskSubject, TypedMask};
pub use names::{
    AccountLabel, ChannelName, DisplayName, MAX_DISPLAY_NAME_BYTES, MAX_PRECIS_INPUT_BYTES,
    Nickname, NormalizedLogin, PublicCloak, ServerName,
};
pub use quantities::{
    ByteCount, DurationMilliseconds, EntropySource, Generation, MonotonicClock, MonotonicTick,
    ObjectCount, QueueDemand, Quota, Revision, SequenceNumber, UnixMilliseconds, WallClock,
};
pub use registries::*;
