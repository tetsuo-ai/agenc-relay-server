//! Original public message identities rendered inside one bounded history batch.

use agenc_ircd_client_wire::{BatchStack, CapabilityState, WireMessage, labeled_response};
use agenc_ircd_domain::{ChannelNameValue, MessageKind};
use agenc_ircd_storage::history_records::HistoryMessageRecord;
use agenc_ircd_types::UtcSecond;

use crate::RuntimeError;

pub(crate) struct PageInput<'a> {
    pub(crate) prefix: &'a str,
    pub(crate) capabilities: &'a CapabilityState,
    pub(crate) batch_id: &'a str,
    pub(crate) channel: &'a ChannelNameValue,
    pub(crate) messages: &'a [HistoryMessageRecord],
    pub(crate) first: bool,
    pub(crate) last: bool,
    pub(crate) label: Option<&'a str>,
}

pub(crate) fn page(input: PageInput<'_>) -> Result<Vec<WireMessage>, RuntimeError> {
    if !input.capabilities.enabled("draft/chathistory")
        || !input.capabilities.enabled("batch")
        || input.messages.len() > crate::state_core::history::HISTORY_PAGE_MESSAGES
    {
        return Err(RuntimeError::InvalidValue);
    }
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(input.messages.len() + 2)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    let mut batches = BatchStack::default();
    let start = batches
        .open_history(
            input.capabilities,
            input.prefix,
            input.batch_id,
            input.channel.presentation(),
        )
        .map_err(|_| RuntimeError::InvalidValue)?;
    if input.first {
        frames.extend(
            labeled_response(
                input.capabilities,
                input.prefix,
                input.label,
                None,
                vec![start],
            )
            .map_err(|_| RuntimeError::InvalidValue)?
            .into_messages(),
        );
    }
    for message in input.messages {
        if &message.channel_name != input.channel {
            return Err(RuntimeError::InvalidValue);
        }
        let mut frame = message_frame(input.capabilities, message)?;
        batches
            .attach(input.batch_id, &mut frame)
            .map_err(|_| RuntimeError::InvalidValue)?;
        frames.push(frame);
    }
    let close = batches
        .close(input.prefix, input.batch_id)
        .map_err(|_| RuntimeError::InvalidValue)?;
    if input.last {
        frames.push(close);
    }
    let bytes = frames.iter().try_fold(0_usize, |sum, frame| {
        sum.checked_add(
            frame
                .measure()
                .map_err(|_| RuntimeError::InvalidValue)?
                .bytes(),
        )
        .ok_or(RuntimeError::Overflow)
    })?;
    if bytes > 65_536 {
        return Err(RuntimeError::LimitExceeded);
    }
    Ok(frames)
}

fn message_frame(
    capabilities: &CapabilityState,
    message: &HistoryMessageRecord,
) -> Result<WireMessage, RuntimeError> {
    message.validate()?;
    let source = &message.sender;
    let prefix = format!(
        "{}!{}@{}",
        source.nickname.presentation(),
        std::str::from_utf8(source.public_cloak.user_component())
            .map_err(|_| RuntimeError::InvalidValue)?,
        std::str::from_utf8(source.public_cloak.host_component())
            .map_err(|_| RuntimeError::InvalidValue)?
    );
    let command = match message.kind {
        MessageKind::Privmsg => "PRIVMSG",
        MessageKind::Notice => "NOTICE",
        MessageKind::Tagmsg => return Err(RuntimeError::InvalidValue),
    };
    let mut frame = WireMessage::new(
        &prefix,
        command,
        &[message.channel_name.presentation()],
        Some(&message.body),
    )
    .map_err(|_| RuntimeError::InvalidValue)?;
    frame
        .add_server_tag("msgid", Some(&message.message_id.to_base64url()))
        .map_err(|_| RuntimeError::InvalidValue)?;
    let milliseconds = message.received_unix_milliseconds;
    let whole =
        crate::mutation_render::server_time(UtcSecond::from_unix_seconds(milliseconds / 1_000))?;
    let timestamp = format!(
        "{}.{:03}Z",
        whole.get(..19).ok_or(RuntimeError::InvalidValue)?,
        milliseconds % 1_000
    );
    frame
        .add_server_tag("time", Some(&timestamp))
        .map_err(|_| RuntimeError::InvalidValue)?;
    if capabilities.enabled("account-tag")
        && let Some(label) = &source.account_label
    {
        frame
            .add_server_tag("account", Some(label.as_str()))
            .map_err(|_| RuntimeError::InvalidValue)?;
    }
    for (key, value) in &message.tags {
        frame
            .add_client_only_tag(capabilities, key, Some(value))
            .map_err(|_| RuntimeError::InvalidValue)?;
    }
    Ok(frame)
}
