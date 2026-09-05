//! Bounded, connection-local replies to already completed object submissions.

use std::collections::BTreeMap;

use agenc_ircd_client_wire::WireMessage;
use agenc_ircd_e2ee::limits::RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS;
use agenc_ircd_e2ee::wire::reply::E2eeReplyCode;

use super::router::{Refusal, Resolved};
use super::{ClientOutput, PendingRequest};
use crate::connection::ConnectionGeneration;

/// Connection, attached session, content address, and canonical command scope.
pub(super) type ReplyKey = (u64, u64, [u8; 32], [u8; 32]);
const MAX_REPLIES: usize = 1_024;
const MAX_REPLY_BYTES: usize = 16 * 1024 * 1024;
const MAX_RETAINED_BYTES: usize = 128 * 1024 * 1024;

struct Reply {
    command: Resolved,
    lines: Vec<String>,
    bytes: usize,
    until: u64,
}

#[derive(Default)]
pub(super) struct Replies {
    entries: BTreeMap<ReplyKey, Reply>,
}

impl Replies {
    pub(super) fn expire(&mut self, now: u64) {
        self.entries.retain(|_, reply| reply.until > now);
    }

    pub(super) fn disconnect(&mut self, generation: ConnectionGeneration) {
        self.entries.retain(|key, _| key.0 != generation.get());
    }

    /// Reserve the maximum encoded reply size for every outstanding submission.
    pub(super) fn admits(&self, pending: usize) -> bool {
        let bytes = self
            .entries
            .values()
            .fold(0usize, |sum, reply| sum.saturating_add(reply.bytes));
        self.entries.len().saturating_add(pending) < MAX_REPLIES
            && bytes.saturating_add(pending.saturating_add(1).saturating_mul(MAX_REPLY_BYTES))
                <= MAX_RETAINED_BYTES
    }

    pub(super) fn remember(
        &mut self,
        pending: &PendingRequest,
        lines: Vec<String>,
        now: u64,
    ) -> Result<(), Refusal> {
        let Some(key) = pending.reply_key else {
            return Ok(());
        };
        let bytes = lines
            .iter()
            .try_fold(0usize, |sum, line| sum.checked_add(line.len()))
            .filter(|bytes| *bytes <= MAX_REPLY_BYTES)
            .ok_or(E2eeReplyCode::ObjectTooLarge)?;
        self.entries.insert(
            key,
            Reply {
                command: pending.command.clone(),
                lines,
                bytes,
                until: now.saturating_add(RECENT_OBJECT_IDEMPOTENCY_RETENTION_SECONDS),
            },
        );
        Ok(())
    }

    pub(super) fn replay(
        &self,
        key: ReplyKey,
        command: &Resolved,
        label: Option<&str>,
    ) -> Result<Option<ClientOutput>, Refusal> {
        let Some(reply) = self.entries.get(&key) else {
            return Ok(None);
        };
        if &reply.command != command {
            return Err(E2eeReplyCode::InvalidFragment.into());
        }
        let frames = reply
            .lines
            .iter()
            .enumerate()
            .map(|(index, line)| {
                WireMessage::extension_line(&relabel(line, label, index == 0))
                    .map_err(|_| Refusal::from(E2eeReplyCode::InvalidFragment))
            })
            .collect::<Result<_, _>>()?;
        Ok(Some(ClientOutput {
            generation: ConnectionGeneration::new(key.0),
            frames,
        }))
    }
}

/// Preserve fragment and batch tags, replacing only the request label.
fn relabel(line: &str, label: Option<&str>, first: bool) -> String {
    let (tags, body) = line
        .strip_prefix('@')
        .and_then(|rest| rest.split_once(' '))
        .map_or((Vec::new(), line), |(tags, body)| {
            (tags.split(';').collect::<Vec<_>>(), body)
        });
    let had_label = tags.iter().any(|tag| tag.starts_with("label="));
    let mut tags: Vec<String> = tags
        .into_iter()
        .filter(|tag| !tag.starts_with("label="))
        .map(str::to_owned)
        .collect();
    if (first || had_label)
        && let Some(label) = label
    {
        tags.insert(0, format!("label={label}"));
    }
    if tags.is_empty() {
        body.to_owned()
    } else {
        format!("@{} {body}", tags.join(";"))
    }
}
