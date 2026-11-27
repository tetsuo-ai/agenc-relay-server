//! The physical client's nickname and reply dialect captured at request admission.
use super::Violation;
use agenc_relay_client_wire::{CapabilityState, StandardReplies};
use agenc_relay_domain::DomainError;

pub(super) struct ReplyRequester {
    nickname: [u8; 32],
    nickname_len: usize,
    pub(super) dialect: StandardReplies,
}

impl ReplyRequester {
    pub(super) fn new(nick: &str, caps: &CapabilityState) -> Result<Self, DomainError> {
        // The registered IRC nickname is at most 32 ASCII bytes.
        let mut nickname = [0; 32];
        nickname
            .get_mut(..nick.len())
            .ok_or(DomainError::InvariantViolation)?
            .copy_from_slice(nick.as_bytes());
        Ok(Self {
            nickname,
            nickname_len: nick.len(),
            dialect: StandardReplies::negotiated(caps),
        })
    }

    pub(super) fn nickname(&self) -> Result<&str, Violation> {
        self.nickname
            .get(..self.nickname_len)
            .and_then(|bytes| str::from_utf8(bytes).ok())
            .ok_or(Violation::Consistency)
    }
}
