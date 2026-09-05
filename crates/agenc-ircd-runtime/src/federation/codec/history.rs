//! Lossless conversion of the history selector and immutable page contract.

#[cfg(test)]
#[path = "history/tests/history.rs"]
mod tests;

use agenc_ircd_domain::{HistoryQuery, HistoryReference, HistorySelector, HistoryTimestamp};
use agenc_ircd_federation_wire::access::{fixed, opaque, opaque_field, structure, unsigned};
use agenc_ircd_federation_wire::{
    CodecError, HistoryPage, HistorySelectorObject, SchemaObject, WireValue,
};
use agenc_ircd_storage::history_records::{
    HistoryAuthorizationBinding, HistoryMessageRecord, HistoryPageMetadata,
};
use agenc_ircd_types::MessageId;

pub(crate) fn selector_object(
    selector: HistorySelector,
) -> Result<HistorySelectorObject, CodecError> {
    let (kind, first, second) = match selector {
        HistorySelector::Latest(first) => (1, first, None),
        HistorySelector::Before(first) => (2, Some(first), None),
        HistorySelector::After(first) => (3, Some(first), None),
        HistorySelector::Around(first) => (4, Some(first), None),
        HistorySelector::Between(first, second) => (5, Some(first), Some(second)),
    };
    HistorySelectorObject::new(SchemaObject::new(
        "HistorySelector",
        vec![
            WireValue::Unsigned(kind),
            WireValue::Structure(reference_object(first)?),
            WireValue::Structure(reference_object(second)?),
        ],
    )?)
}

fn reference_object(reference: Option<HistoryReference>) -> Result<SchemaObject, CodecError> {
    let (kind, bytes, milliseconds) = match reference {
        None => (0, Vec::new(), 0),
        Some(HistoryReference::Message(id)) => (1, id.as_bytes().to_vec(), 0),
        Some(HistoryReference::Timestamp(time)) => (2, Vec::new(), time.milliseconds()),
    };
    SchemaObject::new(
        "FederationHistoryReference",
        vec![
            WireValue::Unsigned(kind),
            opaque(&bytes)?,
            WireValue::Unsigned(milliseconds),
        ],
    )
}

pub(crate) fn query_of(
    selector: &HistorySelectorObject,
    limit: u16,
) -> Result<HistoryQuery, CodecError> {
    let object = selector.as_object();
    let first = reference_of(structure(object, "first")?)?;
    let selector = match unsigned(object, "selector_kind")? {
        1 => HistorySelector::Latest(first),
        2 => HistorySelector::Before(first.ok_or(CodecError::CrossReference)?),
        3 => HistorySelector::After(first.ok_or(CodecError::CrossReference)?),
        4 => HistorySelector::Around(first.ok_or(CodecError::CrossReference)?),
        5 => HistorySelector::Between(
            first.ok_or(CodecError::CrossReference)?,
            reference_of(structure(object, "second")?)?.ok_or(CodecError::CrossReference)?,
        ),
        _ => return Err(CodecError::UnknownDiscriminant),
    };
    HistoryQuery::new(selector, limit).map_err(|_| CodecError::CrossReference)
}

fn reference_of(object: &SchemaObject) -> Result<Option<HistoryReference>, CodecError> {
    match unsigned(object, "reference_kind")? {
        0 => Ok(None),
        1 => Ok(Some(HistoryReference::Message(MessageId::from_bytes(
            fixed(object, "message_id")?,
        )))),
        2 => Ok(Some(HistoryReference::Timestamp(
            HistoryTimestamp::new(unsigned(object, "unix_milliseconds")?)
                .map_err(|_| CodecError::CrossReference)?,
        ))),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

pub(crate) fn authorization_object(
    binding: HistoryAuthorizationBinding,
) -> Result<SchemaObject, CodecError> {
    binding.validate().map_err(|_| CodecError::CrossReference)?;
    SchemaObject::new(
        "FederationHistoryAuthorization",
        vec![
            opaque(&binding.session_id)?,
            opaque(&binding.user_id)?,
            WireValue::Unsigned(binding.session_generation),
            opaque(
                binding
                    .account_id
                    .as_ref()
                    .map_or(&[][..], |id| id.as_slice()),
            )?,
            WireValue::Unsigned(binding.account_session_generation),
            WireValue::Unsigned(binding.membership_revision),
            WireValue::Unsigned(binding.history_authorization_generation),
        ],
    )
}

pub(crate) fn authorization_of(
    object: &SchemaObject,
) -> Result<HistoryAuthorizationBinding, CodecError> {
    let account = opaque_field(object, "account_id")?;
    let binding = HistoryAuthorizationBinding {
        session_id: fixed(object, "session_id")?,
        user_id: fixed(object, "user_id")?,
        session_generation: unsigned(object, "session_generation")?,
        account_id: if account.is_empty() {
            None
        } else {
            Some(account.try_into().map_err(|_| CodecError::CrossReference)?)
        },
        account_session_generation: unsigned(object, "account_session_generation")?,
        membership_revision: unsigned(object, "membership_revision")?,
        history_authorization_generation: unsigned(object, "history_authorization_generation")?,
    };
    binding.validate().map_err(|_| CodecError::CrossReference)?;
    Ok(binding)
}

pub(crate) fn page_object(
    metadata: &HistoryPageMetadata,
    messages: &[HistoryMessageRecord],
) -> Result<HistoryPage, CodecError> {
    if messages.len() != metadata.selected.len() {
        return Err(CodecError::CrossReference);
    }
    let mut objects = Vec::new();
    objects
        .try_reserve_exact(messages.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for message in messages {
        objects.push(message_object(message)?);
    }
    HistoryPage::new(SchemaObject::new(
        "result.history_page",
        vec![
            opaque(&metadata.authorization.session_id)?,
            opaque(&metadata.channel_id)?,
            WireValue::Structure(super::channel_name_object(&metadata.channel_name)?),
            WireValue::Structure(authorization_object(metadata.authorization)?),
            opaque(&metadata.snapshot_token)?,
            WireValue::Unsigned(metadata.state_cut),
            WireValue::Unsigned(u64::from(metadata.page_sequence)),
            opaque(
                metadata
                    .next_cursor
                    .as_ref()
                    .map_or(&[][..], |cursor| cursor.as_slice()),
            )?,
            WireValue::Vector(objects),
        ],
    )?)
}

fn message_object(message: &HistoryMessageRecord) -> Result<SchemaObject, CodecError> {
    let tags = message
        .tags
        .iter()
        .map(|(key, value)| super::client_tag_object(key, value))
        .collect::<Result<Vec<_>, _>>()?;
    SchemaObject::new(
        "FederationHistoryMessage",
        vec![
            opaque(message.message_id.as_bytes())?,
            WireValue::Unsigned(message.channel_sequence),
            WireValue::Unsigned(message.received_unix_milliseconds),
            WireValue::Unsigned(message.expires_unix_milliseconds),
            WireValue::Unsigned(super::message_kind_value(message.kind)),
            WireValue::Structure(super::source_view_object(&message.sender)?),
            WireValue::Vector(tags),
            opaque(message.body.as_bytes())?,
        ],
    )
}

pub(crate) fn messages_of(
    page: &HistoryPage,
    channel_name: &agenc_ircd_domain::ChannelNameValue,
) -> Result<Vec<HistoryMessageRecord>, CodecError> {
    let channel_id = page.channel_id()?;
    let objects = page.messages()?;
    if objects.len() > crate::state_core::history::HISTORY_PAGE_MESSAGES {
        return Err(CodecError::CrossReference);
    }
    let mut messages = Vec::new();
    messages
        .try_reserve_exact(objects.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for object in objects {
        let received = unsigned(object, "received_unix_milliseconds")?;
        let expires = unsigned(object, "expires_unix_milliseconds")?;
        let duration = expires
            .checked_sub(received)
            .filter(|duration| duration % 1_000 == 0)
            .ok_or(CodecError::CrossReference)?;
        let message = HistoryMessageRecord {
            channel_id,
            channel_name: channel_name.clone(),
            channel_sequence: unsigned(object, "channel_event_sequence")?,
            message_id: MessageId::from_bytes(fixed(object, "message_id")?),
            received_unix_milliseconds: received,
            expires_unix_milliseconds: expires,
            retention_seconds: u32::try_from(duration / 1_000)
                .map_err(|_| CodecError::CrossReference)?,
            sender: super::source_view_of(structure(object, "sender")?)?,
            kind: super::message_kind_of_value(unsigned(object, "message_kind")?)
                .ok_or(CodecError::UnknownDiscriminant)?,
            tags: super::client_tags_of(agenc_ircd_federation_wire::access::vector(
                object, "tags",
            )?)?,
            body: agenc_ircd_federation_wire::access::text(object, "body")?.to_owned(),
        };
        message.validate().map_err(|_| CodecError::CrossReference)?;
        messages.push(message);
    }
    Ok(messages)
}
