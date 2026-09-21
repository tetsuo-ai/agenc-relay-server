//! Typed views of canonical history selectors, authorization, messages, and pages.

use agenc_relay_types::{AccountId, ChannelInstanceId, MessageId, SessionId, UserId};

use crate::access::{
    expect_schema, fixed, opaque_field, optional_fixed, structure, unsigned, unsigned_u32, vector,
};
use crate::{CodecError, SchemaObject};

/// A validated selector preserving the canonical reference bytes and their direction.
#[derive(Eq, PartialEq)]
pub struct HistorySelectorObject(SchemaObject);

impl HistorySelectorObject {
    /// Accepts only an already validated HistorySelector object.
    pub fn new(object: SchemaObject) -> Result<Self, CodecError> {
        expect_schema(&object, "HistorySelector")?;
        Ok(Self(object))
    }

    /// Borrows the canonical selector for domain conversion or request encoding.
    #[must_use]
    pub const fn as_object(&self) -> &SchemaObject {
        &self.0
    }

    /// Copies the bounded selector without changing its references.
    pub fn try_clone(&self) -> Result<Self, CodecError> {
        Self::new(self.0.try_clone()?)
    }
}

/// A validated authorization tuple, whose authority requires the authenticated coordinator.
#[derive(Eq, PartialEq)]
pub struct HistoryAuthorizationObject(SchemaObject);

impl HistoryAuthorizationObject {
    /// Accepts the exact session/account/membership/history-generation schema.
    pub fn new(object: SchemaObject) -> Result<Self, CodecError> {
        expect_schema(&object, "FederationHistoryAuthorization")?;
        Ok(Self(object))
    }

    /// Borrows the canonical tuple.
    #[must_use]
    pub const fn as_object(&self) -> &SchemaObject {
        &self.0
    }

    /// Returns the originating session.
    pub fn session_id(&self) -> Result<SessionId, CodecError> {
        fixed(&self.0, "session_id").map(SessionId::from_bytes)
    }

    /// Returns the originating user.
    pub fn user_id(&self) -> Result<UserId, CodecError> {
        fixed(&self.0, "user_id").map(UserId::from_bytes)
    }

    /// Returns the captured session fence.
    pub fn session_generation(&self) -> Result<u64, CodecError> {
        unsigned(&self.0, "session_generation")
    }

    /// Returns the optional authenticated account and its session fence.
    pub fn account(&self) -> Result<Option<(AccountId, u64)>, CodecError> {
        let account = opaque_field(&self.0, "account_id")?;
        if account.is_empty() {
            return Ok(None);
        }
        let account =
            AccountId::parse_wire_bytes(account).map_err(|_| CodecError::CrossReference)?;
        Ok(Some((
            account,
            unsigned(&self.0, "account_session_generation")?,
        )))
    }

    /// Returns the captured membership revision.
    pub fn membership_revision(&self) -> Result<u64, CodecError> {
        unsigned(&self.0, "membership_revision")
    }

    /// Returns the coordinator's durable history authorization generation.
    pub fn history_generation(&self) -> Result<u64, CodecError> {
        unsigned(&self.0, "history_authorization_generation")
    }
}

/// A validated immutable history message. Bodies deliberately have no Debug rendering.
#[derive(Eq, PartialEq)]
pub struct HistoryMessageObject(SchemaObject);

impl HistoryMessageObject {
    /// Accepts only the validated history message schema.
    pub fn new(object: SchemaObject) -> Result<Self, CodecError> {
        expect_schema(&object, "FederationHistoryMessage")?;
        Ok(Self(object))
    }

    /// Borrows the original message for capability-aware rendering.
    #[must_use]
    pub const fn as_object(&self) -> &SchemaObject {
        &self.0
    }

    /// Returns the immutable message identity.
    pub fn message_id(&self) -> Result<MessageId, CodecError> {
        fixed(&self.0, "message_id").map(MessageId::from_bytes)
    }

    /// Returns the immutable channel event position.
    pub fn channel_sequence(&self) -> Result<u64, CodecError> {
        unsigned(&self.0, "channel_event_sequence")
    }

    /// Returns the original acceptance timestamp.
    pub fn received_unix_milliseconds(&self) -> Result<u64, CodecError> {
        unsigned(&self.0, "received_unix_milliseconds")
    }

    /// Returns the immutable expiry timestamp.
    pub fn expires_unix_milliseconds(&self) -> Result<u64, CodecError> {
        unsigned(&self.0, "expires_unix_milliseconds")
    }
}

/// One typed history result page, without mutation-completion or outer semantic replies.
#[derive(Eq, PartialEq)]
pub struct HistoryPage(SchemaObject);

impl HistoryPage {
    /// Accepts the validated page schema; its enclosing result enforces the 64-KiB bound.
    pub fn new(object: SchemaObject) -> Result<Self, CodecError> {
        expect_schema(&object, "result.history_page")?;
        Ok(Self(object))
    }

    /// Borrows the canonical result arm.
    #[must_use]
    pub const fn as_object(&self) -> &SchemaObject {
        &self.0
    }

    /// Copies the bounded arm for result encoding.
    pub fn to_object(&self) -> Result<SchemaObject, CodecError> {
        self.0.try_clone()
    }

    /// Returns the original session, repeated by the authorization tuple.
    pub fn session_id(&self) -> Result<SessionId, CodecError> {
        fixed(&self.0, "session_id").map(SessionId::from_bytes)
    }

    /// Returns the exact channel instance.
    pub fn channel_id(&self) -> Result<ChannelInstanceId, CodecError> {
        fixed(&self.0, "channel_instance_id").map(ChannelInstanceId::from_bytes)
    }

    /// Returns the immutable snapshot identity.
    pub fn snapshot_token(&self) -> Result<[u8; 32], CodecError> {
        fixed(&self.0, "snapshot_token")
    }

    /// Returns this page's zero-based sequence.
    pub fn page_sequence(&self) -> Result<u32, CodecError> {
        unsigned_u32(&self.0, "page_sequence")
    }

    /// Returns the one-use continuation cursor, when rows remain.
    pub fn next_cursor(&self) -> Result<Option<[u8; 32]>, CodecError> {
        optional_fixed(&self.0, "next_cursor")
    }

    /// Copies the bounded authorization tuple without message bodies.
    pub fn authorization(&self) -> Result<HistoryAuthorizationObject, CodecError> {
        HistoryAuthorizationObject::new(structure(&self.0, "authorization")?.try_clone()?)
    }

    /// Borrows the already validated, ordered messages without copying their bodies.
    pub fn messages(&self) -> Result<&[SchemaObject], CodecError> {
        vector(&self.0, "messages")
    }
}
