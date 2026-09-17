//! The exact success, broadcast, batch, and live-forwarding productions
//! (companion Section 11.7). Every renderer measures the non-tag portion
//! against the 512-byte traditional line and refuses to exceed it; tags are
//! measured against the 4,094-byte server budget by the caller.

use crate::error::E2eeError;
use crate::limits::MAX_E2EE_SERVER_PREFIX_BYTES;
use crate::object::IrcWireObjectKind;
use crate::wire::fragment::{
    CLIENT_FRAGMENT_TAG, FragmentTag, RECEIPT_TAG, ReceiptTag, SERVER_FRAGMENT_TAG,
};
use crate::wire::tokens::{base64url_encode, is_batch_id, is_safe_label, render_cursor};

/// The traditional line budget, including CRLF.
pub const MAX_NON_TAG_LINE_BYTES: usize = 512;

/// `PENDING` operation kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PendingKind {
    /// `FINALIZATION`.
    Finalization,
    /// `ABORT`.
    Abort,
    /// `REINIT-ATTEMPT`.
    ReinitAttempt,
    /// `REINIT-ACTIVATE`.
    ReinitActivate,
    /// `REINIT-ABORT`.
    ReinitAbort,
}

impl PendingKind {
    /// The wire literal.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Finalization => "FINALIZATION",
            Self::Abort => "ABORT",
            Self::ReinitAttempt => "REINIT-ATTEMPT",
            Self::ReinitActivate => "REINIT-ACTIVATE",
            Self::ReinitAbort => "REINIT-ABORT",
        }
    }
}

/// `EGROUP EMPTY` kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EmptyGroupKind {
    /// `AUTHORIZATIONS`.
    Authorizations,
    /// `ACKS`.
    Acks,
    /// `RECEIPTS`.
    Receipts,
    /// `OBJECTS`.
    Objects,
}

impl EmptyGroupKind {
    /// The wire literal.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Authorizations => "AUTHORIZATIONS",
            Self::Acks => "ACKS",
            Self::Receipts => "RECEIPTS",
            Self::Objects => "OBJECTS",
        }
    }
}

/// `EKEY STORED` and `EKEY EMPTY` store kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StoreKind {
    /// `IDENTITY`.
    Identity,
    /// `ROOT-CHAIN` (empty only).
    RootChain,
    /// `ROSTER`.
    Roster,
    /// `CAPABILITIES`.
    Capabilities,
    /// `PACKAGE`.
    Package,
    /// `APPLICATION`.
    Application,
    /// `BINDING`.
    Binding,
    /// `BINDING-LOCK` (empty only).
    BindingLock,
    /// `WELCOME`.
    Welcome,
    /// `STAGED-REINIT`.
    StagedReinit,
}

impl StoreKind {
    /// The wire literal.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Identity => "IDENTITY",
            Self::RootChain => "ROOT-CHAIN",
            Self::Roster => "ROSTER",
            Self::Capabilities => "CAPABILITIES",
            Self::Package => "PACKAGE",
            Self::Application => "APPLICATION",
            Self::Binding => "BINDING",
            Self::BindingLock => "BINDING-LOCK",
            Self::Welcome => "WELCOME",
            Self::StagedReinit => "STAGED-REINIT",
        }
    }

    /// Whether the kind may appear in `EKEY STORED`.
    #[must_use]
    pub const fn storable(self) -> bool {
        !matches!(self, Self::RootChain | Self::BindingLock)
    }
}

/// One scalar success or broadcast line body (after the server prefix).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SuccessLine {
    /// `EGROUP BOUND <conversation-id> <binding-id>`.
    Bound([u8; 32], [u8; 32]),
    /// `EGROUP CLOSED <conversation-id> <close-id>`.
    Closed([u8; 32], [u8; 32]),
    /// `EGROUP STORED AUTHORIZATION <conversation-id> <candidate-id> <approval-object-id>`.
    StoredAuthorization([u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP STORED POLICY <conversation-id> <policy-id> <policy-object-id>`.
    StoredPolicy([u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP STORED MEMBERSHIP <conversation-id> <leaf-membership-id> <membership-object-id>`.
    StoredMembership([u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP RECOVERY-ACCEPTED <conversation-id> <submission-id>`.
    RecoveryAccepted([u8; 32], [u8; 32]),
    /// `EGROUP RECOVERY-EXTENDED <conversation-id> <route-sequence> <record-id>`.
    RecoveryExtended([u8; 32], u64, [u8; 32]),
    /// `EGROUP RECOVERY-CLOSED <conversation-id> <close-id>`.
    RecoveryClosed([u8; 32], [u8; 32]),
    /// `EGROUP RECOVERY-CONFLICT <conversation-id> <route-sequence> <first-record-id> <second-record-id>`.
    RecoveryConflict([u8; 32], u64, [u8; 32], [u8; 32]),
    /// `EGROUP ACKED <conversation-id> <candidate-id> <ack-object-id>`.
    Acked([u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP PENDING <conversation-id> <kind> <object-id>`.
    Pending([u8; 32], PendingKind, [u8; 32]),
    /// `EGROUP FINALIZED <conversation-id> <resulting-epoch> <finalization-id> <certificate-object-id>`.
    Finalized([u8; 32], u64, [u8; 32], [u8; 32]),
    /// `EGROUP ABORTED <conversation-id> <candidate-id> <abort-id> <certificate-object-id>`.
    Aborted([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP REINIT-STAGED <old-conversation-id> <reinit-attempt-id> <attempt-object-id>`.
    ReinitStaged([u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP REINIT-ACKED <old-conversation-id> <reinit-attempt-id> <ack-object-id>`.
    ReinitAcked([u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP REINIT-ACTIVATED <old> <new> <activation-id> <certificate-object-id>`.
    ReinitActivated([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP REINIT-ABORTED <old> <reinit-attempt-id> <abort-id> <certificate-object-id>`.
    ReinitAborted([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP EMPTY <kind>`.
    EmptyGroup(EmptyGroupKind),
    /// `EKEY ACCOUNT <account-token> <session-generation>`.
    Account([u8; 24], u64),
    /// `EKEY ATTACHED <device-id> <session-generation>`.
    Attached([u8; 16], u64),
    /// `EKEY STORED <kind> <object-id>`.
    Stored(StoreKind, [u8; 32]),
    /// `EKEY REVOKED <key-package-ref>`.
    Revoked(Vec<u8>),
    /// `EKEY ACKED <delivery-token> <object-id>`.
    MailboxAcked([u8; 32], [u8; 32]),
    /// `EKEY EMPTY <kind>`.
    EmptyKey(StoreKind),
}

fn hash(bytes: &[u8]) -> String {
    base64url_encode(bytes)
}

impl SuccessLine {
    /// The bodies of the companion 13.7.4 recovery replies.
    fn recovery_body(&self) -> Option<String> {
        Some(match self {
            Self::RecoveryAccepted(a, b) => {
                format!("EGROUP RECOVERY-ACCEPTED {} {}", hash(a), hash(b))
            }
            Self::RecoveryExtended(a, sequence, c) => {
                format!(
                    "EGROUP RECOVERY-EXTENDED {} {sequence} {}",
                    hash(a),
                    hash(c)
                )
            }
            Self::RecoveryClosed(a, b) => {
                format!("EGROUP RECOVERY-CLOSED {} {}", hash(a), hash(b))
            }
            Self::RecoveryConflict(a, sequence, c, d) => {
                format!(
                    "EGROUP RECOVERY-CONFLICT {} {sequence} {} {}",
                    hash(a),
                    hash(c),
                    hash(d)
                )
            }
            _ => return None,
        })
    }

    /// The line body without prefix, tags, or CRLF.
    pub fn body(&self) -> Result<String, E2eeError> {
        self.recovery_body()
            .map_or_else(|| self.ordinary_body(), Ok)
    }

    fn ordinary_body(&self) -> Result<String, E2eeError> {
        Ok(match self {
            Self::RecoveryAccepted(..)
            | Self::RecoveryExtended(..)
            | Self::RecoveryClosed(..)
            | Self::RecoveryConflict(..) => return Err(E2eeError::InvalidValue),
            Self::Bound(a, b) | Self::Closed(a, b) => {
                format!("EGROUP {} {} {}", self.verb(), hash(a), hash(b))
            }
            Self::StoredAuthorization(a, b, c) => {
                format!(
                    "EGROUP STORED AUTHORIZATION {} {} {}",
                    hash(a),
                    hash(b),
                    hash(c)
                )
            }
            Self::StoredPolicy(a, b, c) => {
                format!("EGROUP STORED POLICY {} {} {}", hash(a), hash(b), hash(c))
            }
            Self::StoredMembership(a, b, c) => {
                format!(
                    "EGROUP STORED MEMBERSHIP {} {} {}",
                    hash(a),
                    hash(b),
                    hash(c)
                )
            }
            Self::Acked(a, b, c) | Self::ReinitStaged(a, b, c) | Self::ReinitAcked(a, b, c) => {
                format!("EGROUP {} {} {} {}", self.verb(), hash(a), hash(b), hash(c))
            }
            Self::Pending(a, kind, c) => {
                format!("EGROUP PENDING {} {} {}", hash(a), kind.token(), hash(c))
            }
            Self::Finalized(a, epoch, c, d) => {
                format!(
                    "EGROUP FINALIZED {} {epoch} {} {}",
                    hash(a),
                    hash(c),
                    hash(d)
                )
            }
            Self::Aborted(a, b, c, d)
            | Self::ReinitActivated(a, b, c, d)
            | Self::ReinitAborted(a, b, c, d) => format!(
                "EGROUP {} {} {} {} {}",
                self.verb(),
                hash(a),
                hash(b),
                hash(c),
                hash(d)
            ),
            Self::EmptyGroup(kind) => format!("EGROUP EMPTY {}", kind.token()),
            Self::Account(account, generation) => {
                format!("EKEY ACCOUNT {} {generation}", hash(account))
            }
            Self::Attached(device, generation) => {
                format!("EKEY ATTACHED {} {generation}", hash(device))
            }
            Self::Stored(kind, object) => {
                if !kind.storable() {
                    return Err(E2eeError::InvalidValue);
                }
                format!("EKEY STORED {} {}", kind.token(), hash(object))
            }
            Self::Revoked(reference) => format!("EKEY REVOKED {}", hash(reference)),
            Self::MailboxAcked(token, object) => {
                format!("EKEY ACKED {} {}", hash(token), hash(object))
            }
            Self::EmptyKey(kind) => format!("EKEY EMPTY {}", kind.token()),
        })
    }

    const fn verb(&self) -> &'static str {
        match self {
            Self::Bound(..) => "BOUND",
            Self::Closed(..) => "CLOSED",
            Self::Acked(..) => "ACKED",
            Self::Aborted(..) => "ABORTED",
            Self::ReinitStaged(..) => "REINIT-STAGED",
            Self::ReinitAcked(..) => "REINIT-ACKED",
            Self::ReinitActivated(..) => "REINIT-ACTIVATED",
            Self::ReinitAborted(..) => "REINIT-ABORTED",
            _ => "",
        }
    }

    /// Whether this form is one of the six untagged state broadcasts.
    #[must_use]
    pub const fn is_broadcast(&self) -> bool {
        matches!(
            self,
            Self::Finalized(..)
                | Self::Aborted(..)
                | Self::Closed(..)
                | Self::ReinitStaged(..)
                | Self::ReinitActivated(..)
                | Self::ReinitAborted(..)
        )
    }
}

/// Checks a server prefix (without the leading colon) against the profile
/// bound, which counts the serialized prefix with its colon.
pub fn check_server_prefix(server: &str) -> Result<(), E2eeError> {
    if server.is_empty()
        || server.len() >= MAX_E2EE_SERVER_PREFIX_BYTES
        || server.bytes().any(|byte| byte == b' ' || byte < 0x21)
    {
        return Err(E2eeError::LimitExceeded);
    }
    Ok(())
}

/// Finishes a line: prefix, body, CRLF, and the traditional budget.
fn finish_line(tags: Option<&str>, server: &str, body: &str) -> Result<String, E2eeError> {
    check_server_prefix(server)?;
    let non_tag = format!(":{server} {body}\r\n");
    if non_tag.len() > MAX_NON_TAG_LINE_BYTES {
        return Err(E2eeError::LimitExceeded);
    }
    Ok(match tags {
        Some(tags) => format!("@{tags} {non_tag}"),
        None => non_tag,
    })
}

/// Renders the labeled response copy for the requesting connection.
pub fn render_labeled(label: &str, server: &str, line: &SuccessLine) -> Result<String, E2eeError> {
    if !is_safe_label(label) {
        return Err(E2eeError::InvalidValue);
    }
    finish_line(Some(&format!("label={label}")), server, &line.body()?)
}

/// Renders one of the six untagged broadcasts.
pub fn render_broadcast(server: &str, line: &SuccessLine) -> Result<String, E2eeError> {
    if !line.is_broadcast() {
        return Err(E2eeError::InvalidValue);
    }
    finish_line(None, server, &line.body()?)
}

/// Renders a `FAIL` line with the server prefix.
pub fn render_fail(server: &str, fail_body: &str) -> Result<String, E2eeError> {
    finish_line(None, server, fail_body)
}

/// Renders the labeled `FAIL` line a failed result earns on the requesting
/// connection (11.7: failure gets one labeled `FAIL`).
pub fn render_labeled_fail(
    label: &str,
    server: &str,
    fail_body: &str,
) -> Result<String, E2eeError> {
    if !is_safe_label(label) {
        return Err(E2eeError::InvalidValue);
    }
    finish_line(Some(&format!("label={label}")), server, fail_body)
}

/// The object batch opener.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchOpener {
    /// The request label.
    pub label: String,
    /// The batch identifier.
    pub batch_id: String,
    /// `EGROUP` or `EKEY`.
    pub request_command: &'static str,
    /// The object kind.
    pub object_kind: IrcWireObjectKind,
    /// The response scope token.
    pub scope: [u8; 16],
    /// The snapshot token.
    pub snapshot: [u8; 32],
    /// The next cursor.
    pub next_cursor: Option<[u8; 32]>,
}

impl BatchOpener {
    fn check(&self) -> Result<(), E2eeError> {
        let request_ok = matches!(self.request_command, "EGROUP" | "EKEY");
        if !is_safe_label(&self.label) || !is_batch_id(&self.batch_id) || !request_ok {
            return Err(E2eeError::InvalidValue);
        }
        Ok(())
    }

    /// Renders the opener.
    pub fn render(&self, server: &str) -> Result<String, E2eeError> {
        self.check()?;
        let body = format!(
            "BATCH +{} agenc.ag/e2ee-objects {} {} {} {} {}",
            self.batch_id,
            self.request_command,
            self.object_kind.token(),
            hash(&self.scope),
            hash(&self.snapshot),
            render_cursor(self.next_cursor.as_ref())
        );
        finish_line(Some(&format!("label={}", self.label)), server, &body)
    }

    /// Renders the batch close.
    pub fn render_close(&self, server: &str) -> Result<String, E2eeError> {
        self.check()?;
        finish_line(None, server, &format!("BATCH -{}", self.batch_id))
    }
}

/// The operation-result metadata children.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchChild {
    /// `EGROUP RESERVED <reservation-id> <reservation-object-id>`.
    Reserved([u8; 16], [u8; 32]),
    /// `EGROUP BOUND <conversation-id> <binding-id> <binding-object-id>`.
    Bound([u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP CANDIDATE <conversation-id> <candidate-object-id> <candidate-id>`.
    Candidate([u8; 32], [u8; 32], [u8; 32]),
    /// `EGROUP FINALIZED <conversation-id> <resulting-epoch> <finalization-id> <certificate-object-id>`.
    Finalized([u8; 32], u64, [u8; 32], [u8; 32]),
    /// `EGROUP ABORTED <conversation-id> <candidate-id> <abort-id> <certificate-object-id>`.
    Aborted([u8; 32], [u8; 32], [u8; 32], [u8; 32]),
    /// `EKEY ATTACH-CHALLENGE <device-id> <challenge-object-id>`.
    AttachChallenge([u8; 16], [u8; 32]),
    /// `EKEY CLAIMED <device-id> NORMAL <key-package-ref> <object-id>`.
    Claimed([u8; 16], Vec<u8>, [u8; 32]),
    /// `EKEY MAILBOX <delivery-token> <device-id> <object-id>`.
    Mailbox([u8; 32], [u8; 16], [u8; 32]),
}

impl BatchChild {
    fn body(&self) -> String {
        match self {
            Self::Reserved(a, b) => format!("EGROUP RESERVED {} {}", hash(a), hash(b)),
            Self::Bound(a, b, c) => format!("EGROUP BOUND {} {} {}", hash(a), hash(b), hash(c)),
            Self::Candidate(a, b, c) => {
                format!("EGROUP CANDIDATE {} {} {}", hash(a), hash(b), hash(c))
            }
            Self::Finalized(a, epoch, c, d) => {
                format!(
                    "EGROUP FINALIZED {} {epoch} {} {}",
                    hash(a),
                    hash(c),
                    hash(d)
                )
            }
            Self::Aborted(a, b, c, d) => {
                format!(
                    "EGROUP ABORTED {} {} {} {}",
                    hash(a),
                    hash(b),
                    hash(c),
                    hash(d)
                )
            }
            Self::AttachChallenge(a, b) => {
                format!("EKEY ATTACH-CHALLENGE {} {}", hash(a), hash(b))
            }
            Self::Claimed(a, reference, c) => {
                format!(
                    "EKEY CLAIMED {} NORMAL {} {}",
                    hash(a),
                    hash(reference),
                    hash(c)
                )
            }
            Self::Mailbox(a, b, c) => format!("EKEY MAILBOX {} {} {}", hash(a), hash(b), hash(c)),
        }
    }

    /// Renders the child inside `batch_id`.
    pub fn render(&self, server: &str, batch_id: &str) -> Result<String, E2eeError> {
        if !is_batch_id(batch_id) {
            return Err(E2eeError::InvalidValue);
        }
        finish_line(Some(&format!("batch={batch_id}")), server, &self.body())
    }
}

/// Renders one `EOBJECT` fragment line inside a batch.
pub fn render_eobject(
    server: &str,
    batch_id: &str,
    fragment: &FragmentTag,
    kind: IrcWireObjectKind,
    scope: &[u8; 16],
) -> Result<String, E2eeError> {
    if !is_batch_id(batch_id) {
        return Err(E2eeError::InvalidValue);
    }
    let tags = format!(
        "batch={batch_id};{SERVER_FRAGMENT_TAG}={}",
        fragment.render()
    );
    let body = format!(
        "EOBJECT {} {} {}",
        kind.token(),
        hash(scope),
        hash(fragment.object_id.as_bytes())
    );
    finish_line(Some(&tags), server, &body)
}

/// The live-forwarded productions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum LiveLine {
    /// `TAGMSG #channel`.
    Tagmsg(Vec<u8>),
    /// `EDIRECT <conversation-id>`.
    Edirect([u8; 32]),
    /// `EGROUP CANDIDATE <conversation-id> <object-id> <candidate-id>`.
    Candidate([u8; 32], [u8; 32], [u8; 32]),
}

/// Server-added metadata on a live line.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LiveTags<'a> {
    /// The requester label, on fragment zero of the echo only.
    pub label: Option<&'a str>,
    /// The mutable `account` tag value.
    pub account: Option<&'a str>,
    /// The candidate receipt, on candidate fragment zero only.
    pub receipt: Option<&'a ReceiptTag>,
}

/// Renders a live forwarded or echoed frame: server tags first, then the
/// preserved client-only fragment tag.
pub fn render_live(
    source: &str,
    tags: &LiveTags<'_>,
    fragment: &FragmentTag,
    line: &LiveLine,
) -> Result<String, E2eeError> {
    if tags.label.is_some_and(|label| !is_safe_label(label)) {
        return Err(E2eeError::InvalidValue);
    }
    let candidate = matches!(line, LiveLine::Candidate(..));
    let fragment_zero = fragment.part == 0;
    if (tags.label.is_some() && !fragment_zero)
        || (tags.receipt.is_some() != (candidate && fragment_zero))
    {
        return Err(E2eeError::InvalidValue);
    }
    let mut rendered = Vec::new();
    if let Some(label) = tags.label {
        rendered.push(format!("label={label}"));
    }
    if let Some(account) = tags.account {
        rendered.push(format!("account={account}"));
    }
    if let Some(receipt) = tags.receipt {
        rendered.push(format!("{RECEIPT_TAG}={}", receipt.render()));
    }
    rendered.push(format!("{CLIENT_FRAGMENT_TAG}={}", fragment.render()));
    let body = match line {
        LiveLine::Tagmsg(channel) => format!("TAGMSG {}", String::from_utf8_lossy(channel)),
        LiveLine::Edirect(conversation) => format!("EDIRECT {}", hash(conversation)),
        LiveLine::Candidate(a, b, c) => {
            format!("EGROUP CANDIDATE {} {} {}", hash(a), hash(b), hash(c))
        }
    };
    finish_line(Some(&rendered.join(";")), source, &body)
}

/// Renders the untagged ACK notification lines.
pub fn render_ack_notice(
    source: &str,
    reinit: bool,
    conversation_id: &[u8; 32],
    selector: &[u8; 32],
    ack_object_id: &[u8; 32],
) -> Result<String, E2eeError> {
    let verb = if reinit { "REINIT-ACK" } else { "ACK" };
    finish_line(
        None,
        source,
        &format!(
            "EGROUP {verb} {} {} {}",
            hash(conversation_id),
            hash(selector),
            hash(ack_object_id)
        ),
    )
}

#[cfg(test)]
#[path = "../tests/response.rs"]
mod tests;
