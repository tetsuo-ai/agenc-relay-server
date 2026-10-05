//! The inverse of [`response`](super::response): the exact companion
//! Section 11.7 productions and the Section 11.9 `FAIL` line, read as a
//! client receives them, and the charge of an object batch's fragments to
//! the batch's bounds.
//!
//! A line is read without its CRLF. Its tags may come in any order, because
//! the daemon's base renderer sorts them by key, so the order on the wire is
//! not the order the productions are written in; each production still has
//! its exact tag set, no other tag, and no tag twice. Every production keeps
//! the 512-byte non-tag budget, the source check of
//! [`check_server_prefix`], and its registry tokens: result verbs, the
//! [`PendingKind`], [`EmptyGroupKind`] and [`StoreKind`] literals,
//! [`ArcWireObjectKind`] tokens and [`E2eeReplyCode`] codes.

use crate::error::E2eeError;
use crate::limits::{MAX_BATCH_DECODED_BYTES, MAX_BATCH_FRAGMENTS, MAX_BATCH_OBJECTS};
use crate::object::{ArcWireObjectKind, ObjectId};
use crate::route::canonical_channel_name;
use crate::wire::carrier::{CarrierCommand, ObjectLimit};
use crate::wire::fragment::{
    CLIENT_FRAGMENT_TAG, FragmentTag, RECEIPT_TAG, ReceiptTag, SERVER_FRAGMENT_TAG,
};
use crate::wire::reply::E2eeReplyCode;
use crate::wire::response::{
    BatchChild, BatchOpener, EmptyGroupKind, LiveLine, MAX_NON_TAG_LINE_BYTES, PendingKind,
    StoreKind, SuccessLine, check_server_prefix,
};
use crate::wire::tokens::{
    is_batch_id, is_safe_label, parse_account, parse_cursor, parse_hash, parse_id16,
    parse_key_package_ref, parse_u64,
};

const LABEL_TAG: &str = "label";
const BATCH_TAG: &str = "batch";
const ACCOUNT_TAG: &str = "account";
/// The batch type of every object batch (companion 11.7).
const OBJECT_BATCH_TYPE: &str = "agenc.ag/e2ee-objects";
/// The CRLF the non-tag budget counts.
const CRLF_BYTES: usize = 2;

/// One received companion line, read into its production.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ReceivedLine {
    /// The labeled scalar result sent to the requesting connection.
    Labeled {
        /// The request's safe label.
        label: String,
        /// The result.
        success: SuccessLine,
    },
    /// One of the six untagged state broadcasts.
    Broadcast(SuccessLine),
    /// The opener of an object batch.
    BatchOpen(BatchOpener),
    /// An operation-result or mailbox child of an object batch.
    BatchChild {
        /// The batch the child belongs to.
        batch_id: String,
        /// The child.
        child: BatchChild,
    },
    /// One `EOBJECT` fragment of an object batch.
    Object(ObjectFragment),
    /// The close of an object batch.
    BatchClose {
        /// The batch closed.
        batch_id: String,
    },
    /// A live forwarded or echoed frame.
    Live(LiveFrame),
    /// An untagged ACK notification.
    AckNotice(AckNotice),
    /// A companion `FAIL`.
    Fail(FailLine),
}

/// One received line and the source that sent it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Received {
    /// The source prefix without its colon: the server, or for a live frame
    /// the sending user.
    pub source: String,
    /// The production.
    pub line: ReceivedLine,
}

/// One `EOBJECT` fragment line:
/// `@batch=<batch-id>;agenc.ag/e2ee=<fragment> :server EOBJECT <object-kind> <scope-token> <object-id>`.
/// The explicit object ID equals the fragment tag's.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectFragment {
    /// The batch the fragment belongs to.
    pub batch_id: String,
    /// The object kind.
    pub kind: ArcWireObjectKind,
    /// The response scope token.
    pub scope: [u8; 16],
    /// The fragment, whose object ID the line names.
    pub fragment: FragmentTag,
}

/// A live forwarded or echoed frame (companion 11.7): a requester echo of
/// fragment zero carries the label, and a candidate's fragment zero, and no
/// other fragment, carries the receipt.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LiveFrame {
    /// The requester's label, on fragment zero of the echo only.
    pub label: Option<String>,
    /// The raw `account` tag value.
    pub account: Option<String>,
    /// The candidate receipt.
    pub receipt: Option<ReceiptTag>,
    /// The preserved client-only fragment.
    pub fragment: FragmentTag,
    /// The forwarded command.
    pub line: LiveLine,
}

/// An untagged `EGROUP ACK` or `EGROUP REINIT-ACK` notification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AckNotice {
    /// Whether this is the ReInit ACK literal.
    pub reinit: bool,
    /// The conversation, or the old conversation of a ReInit.
    pub conversation_id: [u8; 32],
    /// The candidate, or the ReInit attempt.
    pub selector: [u8; 32],
    /// The stored ACK object.
    pub ack_object_id: [u8; 32],
}

/// A companion `FAIL <command|*> <code> [context] :<description>` line,
/// labeled on the requesting connection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FailLine {
    /// The request's safe label, if the line carries one.
    pub label: Option<String>,
    /// The triggering command, or `*`.
    pub command: String,
    /// The companion reply code.
    pub code: E2eeReplyCode,
    /// The optional context token.
    pub context: Option<String>,
    /// The human-readable description, which a client does not parse.
    pub description: String,
}

/// Reads one received companion line, without its CRLF, into its
/// production.
///
/// The tag set selects the production: a client-only fragment tag makes a
/// live frame, `batch` with the server fragment tag an `EOBJECT` fragment,
/// `batch` alone a batch child, `label` a labeled result, batch opener or
/// `FAIL`, and no tag a broadcast, batch close, ACK notification or `FAIL`.
pub fn parse_received_line(line: &str) -> Result<Received, E2eeError> {
    let parts = LineParts::split(line)?;
    let received = if parts.tag(CLIENT_FRAGMENT_TAG).is_some() {
        ReceivedLine::Live(live_frame(&parts)?)
    } else if parts.body.starts_with("FAIL ") {
        ReceivedLine::Fail(fail_line(&parts)?)
    } else if parts.tag(SERVER_FRAGMENT_TAG).is_some() {
        ReceivedLine::Object(object_fragment(&parts)?)
    } else if parts.tag(BATCH_TAG).is_some() {
        batch_child(&parts)?
    } else if parts.tag(LABEL_TAG).is_some() {
        labeled(&parts)?
    } else {
        untagged(&parts)?
    };
    Ok(Received {
        source: parts.source.to_owned(),
        line: received,
    })
}

/// One line split into its raw tags, its source and its body.
struct LineParts<'a> {
    tags: Vec<(&'a str, &'a str)>,
    source: &'a str,
    body: &'a str,
}

impl<'a> LineParts<'a> {
    fn split(line: &'a str) -> Result<Self, E2eeError> {
        let (tags, rest) = match line.strip_prefix('@') {
            Some(tagged) => {
                let (raw, rest) = tagged.split_once(' ').ok_or(E2eeError::InvalidValue)?;
                (split_tags(raw)?, rest)
            }
            None => (Vec::new(), line),
        };
        if rest.len() + CRLF_BYTES > MAX_NON_TAG_LINE_BYTES {
            return Err(E2eeError::LimitExceeded);
        }
        let rest = rest.strip_prefix(':').ok_or(E2eeError::InvalidValue)?;
        let (source, body) = rest.split_once(' ').ok_or(E2eeError::InvalidValue)?;
        check_server_prefix(source)?;
        Ok(Self { tags, source, body })
    }

    fn tag(&self, key: &str) -> Option<&'a str> {
        self.tags
            .iter()
            .find(|(seen, _)| *seen == key)
            .map(|(_, value)| *value)
    }

    /// Whether the line carries exactly these tags, in any order.
    fn has_exactly(&self, keys: &[&str]) -> bool {
        self.tags.len() == keys.len() && keys.iter().all(|key| self.tag(key).is_some())
    }

    fn words(&self) -> Vec<&'a str> {
        self.body.split(' ').collect()
    }
}

/// Splits a tag section into keys and raw values; every companion tag has a
/// value and none repeats.
fn split_tags(raw: &str) -> Result<Vec<(&str, &str)>, E2eeError> {
    let mut tags: Vec<(&str, &str)> = Vec::new();
    for field in raw.split(';') {
        let (key, value) = field.split_once('=').ok_or(E2eeError::InvalidValue)?;
        if key.is_empty() || value.is_empty() || tags.iter().any(|(seen, _)| *seen == key) {
            return Err(E2eeError::InvalidValue);
        }
        tags.push((key, value));
    }
    Ok(tags)
}

/// A label tag value, which must be a `safe-label`.
fn safe_label(raw: &str) -> Result<String, E2eeError> {
    if is_safe_label(raw) {
        Ok(raw.to_owned())
    } else {
        Err(E2eeError::InvalidValue)
    }
}

fn labeled(parts: &LineParts<'_>) -> Result<ReceivedLine, E2eeError> {
    if !parts.has_exactly(&[LABEL_TAG]) {
        return Err(E2eeError::InvalidValue);
    }
    let label = safe_label(parts.tag(LABEL_TAG).unwrap_or_default())?;
    if parts.body.starts_with("BATCH ") {
        return BatchOpener::parse_body(&label, parts.body).map(ReceivedLine::BatchOpen);
    }
    let success = SuccessLine::parse_body(parts.body)?;
    Ok(ReceivedLine::Labeled { label, success })
}

fn untagged(parts: &LineParts<'_>) -> Result<ReceivedLine, E2eeError> {
    if !parts.has_exactly(&[]) {
        return Err(E2eeError::InvalidValue);
    }
    match parts.words().as_slice() {
        ["BATCH", reference] => {
            let batch_id = reference.strip_prefix('-').ok_or(E2eeError::InvalidValue)?;
            if !is_batch_id(batch_id) {
                return Err(E2eeError::InvalidValue);
            }
            Ok(ReceivedLine::BatchClose {
                batch_id: batch_id.to_owned(),
            })
        }
        [
            "EGROUP",
            verb @ ("ACK" | "REINIT-ACK"),
            conversation,
            selector,
            object,
        ] => Ok(ReceivedLine::AckNotice(AckNotice {
            reinit: *verb == "REINIT-ACK",
            conversation_id: parse_hash(conversation)?,
            selector: parse_hash(selector)?,
            ack_object_id: parse_hash(object)?,
        })),
        _ => {
            let success = SuccessLine::parse_body(parts.body)?;
            if !success.is_broadcast() {
                return Err(E2eeError::InvalidValue);
            }
            Ok(ReceivedLine::Broadcast(success))
        }
    }
}

fn batch_child(parts: &LineParts<'_>) -> Result<ReceivedLine, E2eeError> {
    let batch_id = parts.tag(BATCH_TAG).unwrap_or_default();
    if !parts.has_exactly(&[BATCH_TAG]) || !is_batch_id(batch_id) {
        return Err(E2eeError::InvalidValue);
    }
    Ok(ReceivedLine::BatchChild {
        batch_id: batch_id.to_owned(),
        child: BatchChild::parse_body(parts.body)?,
    })
}

fn object_fragment(parts: &LineParts<'_>) -> Result<ObjectFragment, E2eeError> {
    let batch_id = parts.tag(BATCH_TAG).unwrap_or_default();
    if !parts.has_exactly(&[BATCH_TAG, SERVER_FRAGMENT_TAG]) || !is_batch_id(batch_id) {
        return Err(E2eeError::InvalidValue);
    }
    let words = parts.words();
    let ["EOBJECT", kind, scope, object_id] = words.as_slice() else {
        return Err(E2eeError::InvalidValue);
    };
    let fragment = FragmentTag::parse(parts.tag(SERVER_FRAGMENT_TAG).unwrap_or_default())?;
    if fragment.object_id != ObjectId::from_bytes(parse_hash(object_id)?) {
        return Err(E2eeError::ObjectIdMismatch);
    }
    Ok(ObjectFragment {
        batch_id: batch_id.to_owned(),
        kind: ArcWireObjectKind::from_token(kind)?,
        scope: parse_id16(scope)?,
        fragment,
    })
}

fn live_frame(parts: &LineParts<'_>) -> Result<LiveFrame, E2eeError> {
    let known = [CLIENT_FRAGMENT_TAG, LABEL_TAG, ACCOUNT_TAG, RECEIPT_TAG];
    if parts.tags.iter().any(|(key, _)| !known.contains(key)) {
        return Err(E2eeError::InvalidValue);
    }
    let fragment = FragmentTag::parse(parts.tag(CLIENT_FRAGMENT_TAG).unwrap_or_default())?;
    let line = LiveLine::parse_body(parts.body)?;
    let label = parts.tag(LABEL_TAG).map(safe_label).transpose()?;
    let receipt = parts.tag(RECEIPT_TAG).map(ReceiptTag::parse).transpose()?;
    let candidate = matches!(line, LiveLine::Candidate(..));
    let fragment_zero = fragment.part == 0;
    if (label.is_some() && !fragment_zero) || (receipt.is_some() != (candidate && fragment_zero)) {
        return Err(E2eeError::InvalidValue);
    }
    Ok(LiveFrame {
        label,
        account: parts.tag(ACCOUNT_TAG).map(str::to_owned),
        receipt,
        fragment,
        line,
    })
}

fn fail_line(parts: &LineParts<'_>) -> Result<FailLine, E2eeError> {
    let label = match parts.tags.as_slice() {
        [] => None,
        [(LABEL_TAG, raw)] => Some(safe_label(raw)?),
        _ => return Err(E2eeError::InvalidValue),
    };
    let (head, description) = parts.body.split_once(" :").ok_or(E2eeError::InvalidValue)?;
    let words: Vec<&str> = head.split(' ').collect();
    let (command, code, context) = match words.as_slice() {
        ["FAIL", command, code] => (command, code, None),
        ["FAIL", command, code, context] if !context.is_empty() => {
            (command, code, Some((*context).to_owned()))
        }
        _ => return Err(E2eeError::InvalidValue),
    };
    let named_command = *command == "*"
        || (!command.is_empty() && command.bytes().all(|byte| byte.is_ascii_uppercase()));
    if !named_command {
        return Err(E2eeError::InvalidValue);
    }
    Ok(FailLine {
        label,
        command: (*command).to_owned(),
        code: E2eeReplyCode::from_token(code).ok_or(E2eeError::UnknownDiscriminant)?,
        context,
        description: description.to_owned(),
    })
}

impl SuccessLine {
    /// Reads a line body, as [`SuccessLine::body`] writes it, into its
    /// result.
    pub fn parse_body(body: &str) -> Result<Self, E2eeError> {
        let words: Vec<&str> = body.split(' ').collect();
        match words.as_slice() {
            ["EGROUP", rest @ ..] => group_success(rest),
            ["EKEY", rest @ ..] => key_success(rest),
            _ => Err(E2eeError::InvalidValue),
        }
    }
}

// agenc-review: focus owner=e2ee reviewed=2026-10-04 reason=one arm per companion 11.7 EGROUP result production, each reading its fixed tokens in order
fn group_success(words: &[&str]) -> Result<SuccessLine, E2eeError> {
    let hash = |text: &str| parse_hash(text);
    Ok(match words {
        ["BOUND", a, b] => SuccessLine::Bound(hash(a)?, hash(b)?),
        ["CLOSED", a, b] => SuccessLine::Closed(hash(a)?, hash(b)?),
        ["STORED", "AUTHORIZATION", a, b, c] => {
            SuccessLine::StoredAuthorization(hash(a)?, hash(b)?, hash(c)?)
        }
        ["STORED", "POLICY", a, b, c] => SuccessLine::StoredPolicy(hash(a)?, hash(b)?, hash(c)?),
        ["STORED", "MEMBERSHIP", a, b, c] => {
            SuccessLine::StoredMembership(hash(a)?, hash(b)?, hash(c)?)
        }
        ["RECOVERY-ACCEPTED", a, b] => SuccessLine::RecoveryAccepted(hash(a)?, hash(b)?),
        ["RECOVERY-EXTENDED", a, sequence, c] => {
            SuccessLine::RecoveryExtended(hash(a)?, parse_u64(sequence)?, hash(c)?)
        }
        ["RECOVERY-CLOSED", a, b] => SuccessLine::RecoveryClosed(hash(a)?, hash(b)?),
        ["RECOVERY-CONFLICT", a, sequence, c, d] => {
            SuccessLine::RecoveryConflict(hash(a)?, parse_u64(sequence)?, hash(c)?, hash(d)?)
        }
        ["ACKED", a, b, c] => SuccessLine::Acked(hash(a)?, hash(b)?, hash(c)?),
        ["PENDING", a, kind, c] => SuccessLine::Pending(
            hash(a)?,
            PendingKind::from_token(kind).ok_or(E2eeError::UnknownDiscriminant)?,
            hash(c)?,
        ),
        ["FINALIZED", a, epoch, c, d] => {
            SuccessLine::Finalized(hash(a)?, parse_u64(epoch)?, hash(c)?, hash(d)?)
        }
        ["ABORTED", a, b, c, d] => SuccessLine::Aborted(hash(a)?, hash(b)?, hash(c)?, hash(d)?),
        ["REINIT-STAGED", a, b, c] => SuccessLine::ReinitStaged(hash(a)?, hash(b)?, hash(c)?),
        ["REINIT-ACKED", a, b, c] => SuccessLine::ReinitAcked(hash(a)?, hash(b)?, hash(c)?),
        ["REINIT-ACTIVATED", a, b, c, d] => {
            SuccessLine::ReinitActivated(hash(a)?, hash(b)?, hash(c)?, hash(d)?)
        }
        ["REINIT-ABORTED", a, b, c, d] => {
            SuccessLine::ReinitAborted(hash(a)?, hash(b)?, hash(c)?, hash(d)?)
        }
        ["EMPTY", kind] => SuccessLine::EmptyGroup(
            EmptyGroupKind::from_token(kind).ok_or(E2eeError::UnknownDiscriminant)?,
        ),
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn key_success(words: &[&str]) -> Result<SuccessLine, E2eeError> {
    Ok(match words {
        ["ACCOUNT", account, generation] => {
            SuccessLine::Account(parse_account(account)?, parse_u64(generation)?)
        }
        ["ATTACHED", device, generation] => {
            SuccessLine::Attached(parse_id16(device)?, parse_u64(generation)?)
        }
        ["STORED", kind, object] => {
            let kind = StoreKind::from_token(kind)
                .filter(|kind| kind.storable())
                .ok_or(E2eeError::UnknownDiscriminant)?;
            SuccessLine::Stored(kind, parse_hash(object)?)
        }
        ["REVOKED", reference] => SuccessLine::Revoked(parse_key_package_ref(reference)?),
        ["ACKED", token, object] => {
            SuccessLine::MailboxAcked(parse_hash(token)?, parse_hash(object)?)
        }
        ["EMPTY", kind] => SuccessLine::EmptyKey(
            StoreKind::from_token(kind).ok_or(E2eeError::UnknownDiscriminant)?,
        ),
        _ => return Err(E2eeError::InvalidValue),
    })
}

impl BatchOpener {
    /// Reads an opener's body, as [`BatchOpener::render`] writes it, under
    /// the label its line carries.
    pub fn parse_body(label: &str, body: &str) -> Result<Self, E2eeError> {
        let words: Vec<&str> = body.split(' ').collect();
        let [
            "BATCH",
            reference,
            OBJECT_BATCH_TYPE,
            command,
            kind,
            scope,
            snapshot,
            cursor,
        ] = words.as_slice()
        else {
            return Err(E2eeError::InvalidValue);
        };
        let batch_id = reference.strip_prefix('+').ok_or(E2eeError::InvalidValue)?;
        let request_command = match *command {
            "EGROUP" => "EGROUP",
            "EKEY" => "EKEY",
            _ => return Err(E2eeError::InvalidValue),
        };
        if !is_safe_label(label) || !is_batch_id(batch_id) {
            return Err(E2eeError::InvalidValue);
        }
        Ok(Self {
            label: label.to_owned(),
            batch_id: batch_id.to_owned(),
            request_command,
            object_kind: ArcWireObjectKind::from_token(kind)?,
            scope: parse_id16(scope)?,
            snapshot: parse_hash(snapshot)?,
            next_cursor: parse_cursor(cursor)?,
        })
    }
}

impl BatchChild {
    /// Reads a child's body, as [`BatchChild::render`] writes it.
    pub fn parse_body(body: &str) -> Result<Self, E2eeError> {
        let words: Vec<&str> = body.split(' ').collect();
        Ok(match words.as_slice() {
            ["EGROUP", "RESERVED", a, b] => Self::Reserved(parse_id16(a)?, parse_hash(b)?),
            ["EGROUP", "BOUND", a, b, c] => {
                Self::Bound(parse_hash(a)?, parse_hash(b)?, parse_hash(c)?)
            }
            ["EGROUP", "CANDIDATE", a, b, c] => {
                Self::Candidate(parse_hash(a)?, parse_hash(b)?, parse_hash(c)?)
            }
            ["EGROUP", "FINALIZED", a, epoch, c, d] => Self::Finalized(
                parse_hash(a)?,
                parse_u64(epoch)?,
                parse_hash(c)?,
                parse_hash(d)?,
            ),
            ["EGROUP", "ABORTED", a, b, c, d] => Self::Aborted(
                parse_hash(a)?,
                parse_hash(b)?,
                parse_hash(c)?,
                parse_hash(d)?,
            ),
            ["EKEY", "ATTACH-CHALLENGE", device, object] => {
                Self::AttachChallenge(parse_id16(device)?, parse_hash(object)?)
            }
            ["EKEY", "CLAIMED", device, "NORMAL", reference, object] => Self::Claimed(
                parse_id16(device)?,
                parse_key_package_ref(reference)?,
                parse_hash(object)?,
            ),
            ["EKEY", "MAILBOX", token, device, object] => {
                Self::Mailbox(parse_hash(token)?, parse_id16(device)?, parse_hash(object)?)
            }
            _ => return Err(E2eeError::InvalidValue),
        })
    }
}

impl LiveLine {
    /// Reads a live frame's body: `TAGMSG <channel>`, `EDIRECT
    /// <conversation-id>` or `EGROUP CANDIDATE <conversation-id> <object-id>
    /// <candidate-id>`. The channel is an encrypted channel name (companion
    /// Section 9.1), kept as received.
    pub fn parse_body(body: &str) -> Result<Self, E2eeError> {
        let words: Vec<&str> = body.split(' ').collect();
        Ok(match words.as_slice() {
            ["TAGMSG", channel] => {
                canonical_channel_name(channel.as_bytes())?;
                Self::Tagmsg(channel.as_bytes().to_vec())
            }
            ["EDIRECT", conversation] => Self::Edirect(parse_hash(conversation)?),
            ["EGROUP", "CANDIDATE", a, b, c] => {
                Self::Candidate(parse_hash(a)?, parse_hash(b)?, parse_hash(c)?)
            }
            _ => return Err(E2eeError::InvalidValue),
        })
    }
}

/// What one fragment did to its batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FragmentCharge {
    /// The fragment began an object, which is now charged to the batch.
    NewObject,
    /// The fragment belongs to an object already charged.
    KnownObject,
}

/// One object charged to a batch: its identifier, fragment count and size,
/// pinned by its first fragment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ChargedObject {
    object_id: ObjectId,
    count: u32,
    total: u32,
}

/// One object batch a client reads (companion 11.7), from its opener to its
/// close.
///
/// The opener's object kind fixes the class every object of the batch is
/// held to: the response carrier's complete-object size and fragment ceiling
/// ([`CarrierCommand::Response`]). Response fragments may arrive in any
/// order (Section 11.8), so the first fragment seen of each object charges
/// the object, its declared fragment count and its declared size to the
/// batch's bounds (`MAX_BATCH_OBJECTS`, `MAX_BATCH_FRAGMENTS`,
/// `MAX_BATCH_DECODED_BYTES`) before a client reserves memory to reassemble
/// it; every later fragment must repeat that count and size. The batch's
/// lines keep their production order: at most one operation-result child,
/// before the first object, and in a mailbox fetch one `MAILBOX` child
/// immediately before each object's first fragment, naming that object.
/// Reassembly and the per-connection quotas stay with
/// [`E2eeAssembler`](crate::wire::assembly::E2eeAssembler).
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResponseBatch {
    opener: BatchOpener,
    limit: ObjectLimit,
    objects: Vec<ChargedObject>,
    fragments: usize,
    decoded_bytes: usize,
    result_child: bool,
    mailbox_fetch: Option<bool>,
    pending_mailbox: Option<ObjectId>,
}

impl ResponseBatch {
    /// Opens the batch its opener names.
    #[must_use]
    pub fn open(opener: BatchOpener) -> Self {
        let limit = CarrierCommand::Response(opener.object_kind).limit();
        Self {
            opener,
            limit,
            objects: Vec::new(),
            fragments: 0,
            decoded_bytes: 0,
            result_child: false,
            mailbox_fetch: None,
            pending_mailbox: None,
        }
    }

    /// The opener.
    #[must_use]
    pub const fn opener(&self) -> &BatchOpener {
        &self.opener
    }

    /// Objects charged so far.
    #[must_use]
    pub fn object_count(&self) -> usize {
        self.objects.len()
    }

    /// Declared fragments charged so far.
    #[must_use]
    pub const fn fragment_count(&self) -> usize {
        self.fragments
    }

    /// Declared object bytes charged so far.
    #[must_use]
    pub const fn decoded_bytes(&self) -> usize {
        self.decoded_bytes
    }

    fn check_batch(&self, batch_id: &str) -> Result<(), E2eeError> {
        if batch_id == self.opener.batch_id {
            Ok(())
        } else {
            Err(E2eeError::InvalidValue)
        }
    }

    /// Admits one child of this batch.
    pub fn child(&mut self, batch_id: &str, child: &BatchChild) -> Result<(), E2eeError> {
        self.check_batch(batch_id)?;
        if self.pending_mailbox.is_some() {
            return Err(E2eeError::InvalidValue);
        }
        if let BatchChild::Mailbox(_, _, object_id) = child {
            if self.mailbox_fetch == Some(false) {
                return Err(E2eeError::InvalidValue);
            }
            self.pending_mailbox = Some(ObjectId::from_bytes(*object_id));
            return Ok(());
        }
        if self.result_child || !self.objects.is_empty() {
            return Err(E2eeError::InvalidValue);
        }
        self.result_child = true;
        Ok(())
    }

    /// Charges one `EOBJECT` fragment of this batch.
    pub fn charge(&mut self, fragment: &ObjectFragment) -> Result<FragmentCharge, E2eeError> {
        self.check_batch(&fragment.batch_id)?;
        if fragment.kind != self.opener.object_kind {
            return Err(E2eeError::WrongKind);
        }
        if fragment.scope != self.opener.scope {
            return Err(E2eeError::InvalidValue);
        }
        let tag = &fragment.fragment;
        let known = self
            .objects
            .iter()
            .find(|object| object.object_id == tag.object_id);
        if let Some(object) = known {
            if self.pending_mailbox.is_some()
                || object.count != tag.count
                || object.total != tag.total
            {
                return Err(E2eeError::InvalidValue);
            }
            return Ok(FragmentCharge::KnownObject);
        }
        self.pair_mailbox(tag.object_id)?;
        self.admit_object(tag)?;
        Ok(FragmentCharge::NewObject)
    }

    /// Checks a new object against the mailbox pairing: the batch's first
    /// object decides whether it is a mailbox fetch, and in one each object
    /// follows the `MAILBOX` child that names it.
    fn pair_mailbox(&mut self, object_id: ObjectId) -> Result<(), E2eeError> {
        let named = self.pending_mailbox.take();
        if named.is_some_and(|named| named != object_id) {
            return Err(E2eeError::InvalidValue);
        }
        let mailbox = named.is_some();
        match self.mailbox_fetch {
            None => {
                self.mailbox_fetch = Some(mailbox);
                Ok(())
            }
            Some(fetch) if fetch == mailbox => Ok(()),
            Some(_) => Err(E2eeError::InvalidValue),
        }
    }

    fn admit_object(&mut self, tag: &FragmentTag) -> Result<(), E2eeError> {
        let total = usize::try_from(tag.total).map_err(|_| E2eeError::Overflow)?;
        let count = usize::try_from(tag.count).map_err(|_| E2eeError::Overflow)?;
        if total > self.limit.max_bytes || tag.count > self.limit.max_fragments {
            return Err(E2eeError::LimitExceeded);
        }
        let fragments = self
            .fragments
            .checked_add(count)
            .ok_or(E2eeError::Overflow)?;
        let decoded_bytes = self
            .decoded_bytes
            .checked_add(total)
            .ok_or(E2eeError::Overflow)?;
        if self.objects.len() >= MAX_BATCH_OBJECTS
            || fragments > MAX_BATCH_FRAGMENTS
            || decoded_bytes > MAX_BATCH_DECODED_BYTES
        {
            return Err(E2eeError::LimitExceeded);
        }
        self.objects.push(ChargedObject {
            object_id: tag.object_id,
            count: tag.count,
            total: tag.total,
        });
        self.fragments = fragments;
        self.decoded_bytes = decoded_bytes;
        Ok(())
    }

    /// Accepts the batch close: the same batch, at least one object (an
    /// empty page is the `EMPTY` result, never a batch), and no `MAILBOX`
    /// child left without its object.
    pub fn close(&self, batch_id: &str) -> Result<(), E2eeError> {
        self.check_batch(batch_id)?;
        if self.objects.is_empty() || self.pending_mailbox.is_some() {
            return Err(E2eeError::InvalidValue);
        }
        Ok(())
    }
}
