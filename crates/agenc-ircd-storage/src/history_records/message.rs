//! Immutable public message facts admitted under explicit plaintext retention.

use agenc_ircd_domain::federation::SourceView;
use agenc_ircd_domain::{
    AccountLabelValue, ChannelNameValue, ChannelScope, MessageKind, NicknameValue,
};
use agenc_ircd_types::{ChannelInstanceId, MessageId, PublicCloak, UserId};

use crate::StorageError;
use crate::codec::{Decoder, Encoder};

use super::{HISTORY_BODY_VERSION, MAX_HISTORY_RECORD_BYTES, text, version};

const MAX_TAGS: usize = 16;
const MAX_TAG_KEY_BYTES: usize = 255;
const MAX_TAG_VALUE_BYTES: usize = 256;
const MAX_MESSAGE_BYTES: usize = 512;

/// One immutable plaintext history message. Debug intentionally omits this body-bearing type.
#[derive(Clone, Eq, PartialEq)]
pub struct HistoryMessageRecord {
    /// Exact channel instance whose policy admitted the write.
    pub channel_id: ChannelInstanceId,
    /// Positive authoritative accepting state generation.
    pub channel_sequence: u64,
    /// Message identity from the original delivery.
    pub message_id: MessageId,
    /// Original authoritative receive time, never recomputed during replay.
    pub received_unix_milliseconds: u64,
    /// Original receive time plus the chosen policy duration.
    pub expires_unix_milliseconds: u64,
    /// One of 3,600, 86,400, or 604,800 seconds.
    pub retention_seconds: u32,
    /// Exact public channel spelling at acceptance.
    pub channel_name: ChannelNameValue,
    /// Public source view at acceptance, including the then-current account label.
    pub sender: SourceView,
    /// Only channel-wide PRIVMSG and NOTICE are retained.
    pub kind: MessageKind,
    /// Sorted, unique ordinary transferable client tags; no server correlation tags.
    pub tags: Vec<(String, String)>,
    /// Original bounded message text.
    pub body: String,
}

impl HistoryMessageRecord {
    /// Checks immutable retention arithmetic and the closed plaintext message shape.
    pub fn validate(&self) -> Result<(), StorageError> {
        if self.channel_sequence == 0
            || self.channel_name.scope() != ChannelScope::Global
            || !matches!(self.retention_seconds, 3_600 | 86_400 | 604_800)
            || !matches!(self.kind, MessageKind::Privmsg | MessageKind::Notice)
            || !self.valid_body()
            || self.tags.len() > MAX_TAGS
        {
            return Err(StorageError::InvalidEncoding);
        }
        let expected = self
            .received_unix_milliseconds
            .checked_add(u64::from(self.retention_seconds) * 1_000)
            .ok_or(StorageError::Overflow)?;
        if self.expires_unix_milliseconds != expected {
            return Err(StorageError::InvalidEncoding);
        }
        validate_tags(&self.tags)
    }

    fn valid_body(&self) -> bool {
        !(self.kind == MessageKind::Privmsg && self.body.is_empty())
            && self.body.len() <= MAX_MESSAGE_BYTES
            && !self
                .body
                .bytes()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n'))
    }

    /// Encodes the version-one body; key and expiry-envelope binding are checked separately.
    pub fn encode(&self) -> Result<Vec<u8>, StorageError> {
        self.validate()?;
        let mut encoder =
            Encoder::with_capacity(MAX_HISTORY_RECORD_BYTES, MAX_HISTORY_RECORD_BYTES)?;
        encoder.put_u16(HISTORY_BODY_VERSION)?;
        encoder.put_fixed(self.channel_id.as_bytes())?;
        encoder.put_u64(self.channel_sequence)?;
        encoder.put_fixed(self.message_id.as_bytes())?;
        encoder.put_u64(self.received_unix_milliseconds)?;
        encoder.put_u64(self.expires_unix_milliseconds)?;
        encoder.put_u32(self.retention_seconds)?;
        encoder.put_vector_u32(self.channel_name.presentation().as_bytes())?;
        encode_source(&mut encoder, &self.sender)?;
        encoder.put_u16(match self.kind {
            MessageKind::Privmsg => 1,
            MessageKind::Notice => 2,
            MessageKind::Tagmsg => return Err(StorageError::InvalidEncoding),
        })?;
        encoder.put_u16(u16::try_from(self.tags.len()).map_err(|_| StorageError::Overflow)?)?;
        for (key, value) in &self.tags {
            encoder.put_vector_u32(key.as_bytes())?;
            encoder.put_vector_u32(value.as_bytes())?;
        }
        encoder.put_vector_u32(self.body.as_bytes())?;
        Ok(encoder.finish())
    }

    /// Decodes one complete body, rejecting oversized vectors before allocation.
    pub fn decode(body: &[u8]) -> Result<Self, StorageError> {
        if body.len() > MAX_HISTORY_RECORD_BYTES {
            return Err(StorageError::LimitExceeded);
        }
        let mut decoder = Decoder::new(body);
        version(&mut decoder)?;
        let mut record = Self {
            channel_id: ChannelInstanceId::from_bytes(decoder.array()?),
            channel_sequence: decoder.u64()?,
            message_id: MessageId::from_bytes(decoder.array()?),
            received_unix_milliseconds: decoder.u64()?,
            expires_unix_milliseconds: decoder.u64()?,
            retention_seconds: decoder.u32()?,
            channel_name: ChannelNameValue::parse(&text(&mut decoder, 64)?)
                .map_err(|_| StorageError::InvalidEncoding)?,
            sender: decode_source(&mut decoder)?,
            kind: match decoder.u16()? {
                1 => MessageKind::Privmsg,
                2 => MessageKind::Notice,
                _ => return Err(StorageError::InvalidEncoding),
            },
            tags: decode_tags(&mut decoder)?,
            body: String::new(),
        };
        record.body = text(&mut decoder, MAX_MESSAGE_BYTES)?;
        decoder.finish()?;
        record.validate()?;
        Ok(record)
    }
}

fn validate_tags(tags: &[(String, String)]) -> Result<(), StorageError> {
    let mut previous: Option<&str> = None;
    for (key, value) in tags {
        if !key.starts_with('+')
            || key.len() > MAX_TAG_KEY_BYTES
            || key
                .bytes()
                .any(|byte| matches!(byte, 0 | b'\r' | b'\n' | b' ' | b';' | b'='))
            || key.starts_with("+agenc.ag/")
            || value.len() > MAX_TAG_VALUE_BYTES
            || value.contains('\0')
            || previous.is_some_and(|previous| previous >= key.as_str())
        {
            return Err(StorageError::InvalidEncoding);
        }
        previous = Some(key);
    }
    Ok(())
}

fn decode_tags(decoder: &mut Decoder<'_>) -> Result<Vec<(String, String)>, StorageError> {
    let count = usize::from(decoder.u16()?);
    if count > MAX_TAGS {
        return Err(StorageError::LimitExceeded);
    }
    let mut tags = Vec::new();
    tags.try_reserve_exact(count)
        .map_err(|_| StorageError::AllocationFailed)?;
    for _ in 0..count {
        tags.push((
            text(decoder, MAX_TAG_KEY_BYTES)?,
            text(decoder, MAX_TAG_VALUE_BYTES)?,
        ));
    }
    Ok(tags)
}

fn encode_source(encoder: &mut Encoder, source: &SourceView) -> Result<(), StorageError> {
    encoder.put_fixed(source.user_id.as_bytes())?;
    encoder.put_vector_u32(source.nickname.presentation().as_bytes())?;
    encoder.put_fixed(source.public_cloak.user_component())?;
    encoder.put_fixed(source.public_cloak.host_component())?;
    encoder.put_vector_u32(
        source
            .account_label
            .as_ref()
            .map_or(&[], |value| value.as_str().as_bytes()),
    )
}

fn decode_source(decoder: &mut Decoder<'_>) -> Result<SourceView, StorageError> {
    let user_id = UserId::from_bytes(decoder.array()?);
    let nickname =
        NicknameValue::parse(&text(decoder, 32)?).map_err(|_| StorageError::InvalidEncoding)?;
    let public_cloak = PublicCloak::from_components(decoder.array()?, decoder.array()?)
        .map_err(|_| StorageError::InvalidEncoding)?;
    let label = text(decoder, 32)?;
    let account_label = if label.is_empty() {
        None
    } else {
        Some(AccountLabelValue::parse(&label).map_err(|_| StorageError::InvalidEncoding)?)
    };
    Ok(SourceView {
        user_id,
        nickname,
        public_cloak,
        account_label,
    })
}
