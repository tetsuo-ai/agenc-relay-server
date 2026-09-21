//! The `EGROUP`, `EKEY`, and `EDIRECT` client productions (companion
//! Sections 11.3 to 11.6) with exact parameter counts and the Section 11.10
//! token grammar. Parsing is pure: the caller supplies the command name and
//! its middle parameters as already split by the IRC framing layer.

use crate::error::E2eeError;
use crate::route::canonical_channel_name;
use crate::wire::carrier::CarrierCommand;
use crate::wire::tokens::{
    parse_account, parse_cursor, parse_hash, parse_id16, parse_key_package_ref, parse_u16,
    parse_u64,
};

/// `EGROUP SUBMIT` kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubmitKind {
    /// `CANDIDATE`.
    Candidate,
    /// `AUTHORIZATION`.
    Authorization,
    /// `ACK`.
    Ack,
    /// `FINALIZATION`.
    Finalization,
    /// `ABORT`.
    Abort,
    /// `REINIT ATTEMPT`.
    ReinitAttempt,
    /// `REINIT ACK`.
    ReinitAck,
    /// `REINIT ACTIVATE`.
    ReinitActivate,
    /// `REINIT ABORT`.
    ReinitAbort,
    /// `POLICY`.
    Policy,
    /// `MEMBERSHIP`.
    Membership,
    /// `RECOVERY`.
    Recovery,
}

impl SubmitKind {
    /// The carrier this submission uses.
    #[must_use]
    pub const fn carrier(self) -> CarrierCommand {
        match self {
            Self::Candidate => CarrierCommand::SubmitCandidate,
            Self::Authorization => CarrierCommand::SubmitAuthorization,
            Self::Ack => CarrierCommand::SubmitAck,
            Self::Finalization => CarrierCommand::SubmitFinalization,
            Self::Abort => CarrierCommand::SubmitAbort,
            Self::ReinitAttempt => CarrierCommand::SubmitReinitAttempt,
            Self::ReinitAck => CarrierCommand::SubmitReinitAck,
            Self::ReinitActivate => CarrierCommand::SubmitReinitActivate,
            Self::ReinitAbort => CarrierCommand::SubmitReinitAbort,
            Self::Policy => CarrierCommand::SubmitPolicy,
            Self::Membership => CarrierCommand::SubmitMembership,
            Self::Recovery => CarrierCommand::SubmitRecovery,
        }
    }
}

/// Mailbox kinds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MailboxKind {
    /// `APPLICATION`.
    Application,
    /// `BINDING`.
    Binding,
    /// `WELCOME`.
    Welcome,
    /// `STAGED-REINIT`.
    StagedReinit,
}

impl MailboxKind {
    /// The wire literal.
    #[must_use]
    pub const fn token(self) -> &'static str {
        match self {
            Self::Application => "APPLICATION",
            Self::Binding => "BINDING",
            Self::Welcome => "WELCOME",
            Self::StagedReinit => "STAGED-REINIT",
        }
    }

    fn parse(token: &str) -> Result<Self, E2eeError> {
        match token {
            "APPLICATION" => Ok(Self::Application),
            "BINDING" => Ok(Self::Binding),
            "WELCOME" => Ok(Self::Welcome),
            "STAGED-REINIT" => Ok(Self::StagedReinit),
            _ => Err(E2eeError::InvalidValue),
        }
    }
}

/// One `EGROUP` production.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EgroupCommand {
    /// `RESERVE CHANNEL <channel>` with the canonical name.
    ReserveChannel(Vec<u8>),
    /// `RESERVE DIRECT <peer-account-token>`.
    ReserveDirect([u8; 24]),
    /// `BIND <reservation-id> <conversation-id> <context-digest>`.
    Bind {
        /// Reservation identifier.
        reservation_id: [u8; 16],
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// Context digest.
        context_digest: [u8; 32],
    },
    /// `QUERY CHANNEL <channel>`.
    QueryChannel(Vec<u8>),
    /// `QUERY DIRECT <peer-account-token>`.
    QueryDirect([u8; 24]),
    /// `CLOSE <conversation-id> <reason-code>`.
    Close {
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// Reason code.
        reason_code: u16,
    },
    /// `SUBMIT <kind> <conversation-id>`.
    Submit {
        /// Submission kind.
        kind: SubmitKind,
        /// Conversation identifier.
        conversation_id: [u8; 32],
    },
    /// `SUBMIT RECOVERY-ELEMENT <conversation-id> <submission-id>`.
    SubmitRecoveryElement {
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// The accepted submission the element completes.
        submission_id: [u8; 32],
    },
    /// `FETCH OBJECT <conversation-id> <object-id>`.
    FetchObject {
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// Object identifier.
        object_id: [u8; 32],
    },
    /// `FETCH AUTHORIZATIONS <conversation-id> <candidate-id> <cursor>`.
    FetchAuthorizations {
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// Candidate identifier.
        candidate_id: [u8; 32],
        /// Cursor.
        cursor: Option<[u8; 32]>,
    },
    /// `FETCH ACKS <conversation-id> <selector> <cursor>`.
    FetchAcks {
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// Candidate or ReInit attempt identifier.
        selector: [u8; 32],
        /// Cursor.
        cursor: Option<[u8; 32]>,
    },
    /// `FETCH RECEIPTS <conversation-id> <first-route-sequence> <cursor>`.
    FetchReceipts {
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// First route sequence.
        first_route_sequence: u64,
        /// Cursor.
        cursor: Option<[u8; 32]>,
    },
}

/// One `EKEY` production.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EkeyCommand {
    /// `FETCH IDENTITY <account-token>`.
    FetchIdentity([u8; 24]),
    /// `FETCH ROOT-CHAIN <account-token> <first-generation> <cursor>`.
    FetchRootChain {
        /// Account.
        account: [u8; 24],
        /// First generation.
        first_generation: u64,
        /// Cursor.
        cursor: Option<[u8; 32]>,
    },
    /// `PUBLISH IDENTITY`.
    PublishIdentity,
    /// `FETCH ROSTER <account-token>`.
    FetchRoster([u8; 24]),
    /// `PUBLISH ROSTER`.
    PublishRoster,
    /// `FETCH CAPABILITIES <account-token> <cursor>`.
    FetchCapabilities {
        /// Account.
        account: [u8; 24],
        /// Cursor.
        cursor: Option<[u8; 32]>,
    },
    /// `PUBLISH CAPABILITIES <device-id>`.
    PublishCapabilities([u8; 16]),
    /// `FETCH BINDING-LOCKS <account-token> <root-fingerprint> <first-sequence> <cursor>`.
    FetchBindingLocks {
        /// Account.
        account: [u8; 24],
        /// Root fingerprint.
        root_fingerprint: [u8; 32],
        /// First sequence.
        first_sequence: u64,
        /// Cursor.
        cursor: Option<[u8; 32]>,
    },
    /// `WHOAMI`.
    Whoami,
    /// `ATTACH BEGIN <device-id>`.
    AttachBegin([u8; 16]),
    /// `ATTACH FINISH <device-id>`.
    AttachFinish([u8; 16]),
    /// `CLAIM PACKAGE <account-token> <device-id> <mls-suite> <operation-id>`.
    ClaimPackage {
        /// Target account.
        account: [u8; 24],
        /// Target device.
        device_id: [u8; 16],
        /// Cipher suite.
        suite: u16,
        /// Operation identifier.
        operation_id: [u8; 16],
    },
    /// `CLAIM STATUS <operation-id>`.
    ClaimStatus([u8; 16]),
    /// `PUBLISH PACKAGE <device-id> <mls-suite> NORMAL <expires-at>`.
    PublishPackage {
        /// Publishing device.
        device_id: [u8; 16],
        /// Cipher suite.
        suite: u16,
        /// Expiry second.
        expires_at: u64,
    },
    /// `REVOKE PACKAGE <key-package-ref>`.
    RevokePackage(Vec<u8>),
    /// `DELIVER BINDING <account-token> <device-id>`.
    DeliverBinding {
        /// Target account.
        account: [u8; 24],
        /// Target device.
        device_id: [u8; 16],
    },
    /// `DELIVER WELCOME <account-token> <device-id> <conversation-id> <authorization-id>`.
    DeliverWelcome {
        /// Target account.
        account: [u8; 24],
        /// Target device.
        device_id: [u8; 16],
        /// Conversation identifier.
        conversation_id: [u8; 32],
        /// Finalization or ReInit attempt identifier.
        authorization_id: [u8; 32],
    },
    /// `FETCH MAILBOX <kind> <cursor>`.
    FetchMailbox {
        /// Mailbox kind.
        kind: MailboxKind,
        /// Cursor.
        cursor: Option<[u8; 32]>,
    },
    /// `ACK MAILBOX <delivery-token> <object-id>`.
    AckMailbox {
        /// Delivery token.
        delivery_token: [u8; 32],
        /// Object identifier.
        object_id: [u8; 32],
    },
}

/// One extension command.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClientCommand {
    /// `EGROUP`.
    Egroup(EgroupCommand),
    /// `EKEY`.
    Ekey(EkeyCommand),
    /// `EDIRECT <conversation-id>`.
    Edirect([u8; 32]),
}

impl ClientCommand {
    /// The carrier for a command that must carry an object, if any.
    #[must_use]
    pub fn carrier(&self) -> Option<CarrierCommand> {
        match self {
            Self::Edirect(_) => Some(CarrierCommand::Edirect),
            Self::Egroup(command) => command.carrier(),
            Self::Ekey(command) => command.carrier(),
        }
    }

    /// The top-level command literal.
    #[must_use]
    pub const fn request_command(&self) -> &'static str {
        match self {
            Self::Egroup(_) => "EGROUP",
            Self::Ekey(_) => "EKEY",
            Self::Edirect(_) => "EDIRECT",
        }
    }
}

impl EgroupCommand {
    /// The carrier for an object-carrying production.
    #[must_use]
    pub const fn carrier(&self) -> Option<CarrierCommand> {
        match self {
            Self::Submit { kind, .. } => Some(kind.carrier()),
            Self::SubmitRecoveryElement { .. } => Some(CarrierCommand::SubmitRecoveryElement),
            Self::Bind { .. } => Some(CarrierCommand::Bind),
            Self::Close { .. } => Some(CarrierCommand::Close),
            _ => None,
        }
    }
}

impl EkeyCommand {
    /// The carrier for an object-carrying production.
    #[must_use]
    pub const fn carrier(&self) -> Option<CarrierCommand> {
        match self {
            Self::PublishIdentity => Some(CarrierCommand::PublishIdentity),
            Self::PublishRoster => Some(CarrierCommand::PublishRoster),
            Self::PublishCapabilities(_) => Some(CarrierCommand::PublishCapabilities),
            Self::PublishPackage { .. } => Some(CarrierCommand::PublishPackage),
            Self::DeliverBinding { .. } => Some(CarrierCommand::DeliverBinding),
            Self::DeliverWelcome { .. } => Some(CarrierCommand::DeliverWelcome),
            Self::AttachFinish(_) => Some(CarrierCommand::AttachFinish),
            _ => None,
        }
    }
}

/// Parses one extension command from its name and middle parameters.
pub fn parse_command(command: &str, params: &[&str]) -> Result<ClientCommand, E2eeError> {
    match command {
        "EGROUP" => parse_egroup(params).map(ClientCommand::Egroup),
        "EKEY" => parse_ekey(params).map(ClientCommand::Ekey),
        "EDIRECT" => match params {
            [conversation] => parse_hash(conversation).map(ClientCommand::Edirect),
            _ => Err(E2eeError::InvalidValue),
        },
        _ => Err(E2eeError::UnknownDiscriminant),
    }
}

/// Whether `command` names an extension command.
#[must_use]
pub fn is_extension_command(command: &str) -> bool {
    matches!(command, "EGROUP" | "EKEY" | "EDIRECT")
}

fn channel(name: &str) -> Result<Vec<u8>, E2eeError> {
    canonical_channel_name(name.as_bytes())
}

fn parse_egroup(params: &[&str]) -> Result<EgroupCommand, E2eeError> {
    use EgroupCommand::*;
    Ok(match params {
        ["RESERVE", "CHANNEL", name] => ReserveChannel(channel(name)?),
        ["RESERVE", "DIRECT", peer] => ReserveDirect(parse_account(peer)?),
        ["BIND", reservation, conversation, digest] => Bind {
            reservation_id: parse_id16(reservation)?,
            conversation_id: parse_hash(conversation)?,
            context_digest: parse_hash(digest)?,
        },
        ["QUERY", "CHANNEL", name] => QueryChannel(channel(name)?),
        ["QUERY", "DIRECT", peer] => QueryDirect(parse_account(peer)?),
        ["CLOSE", conversation, reason] => Close {
            conversation_id: parse_hash(conversation)?,
            reason_code: parse_u16(reason)?,
        },
        ["SUBMIT", rest @ ..] => parse_submit(rest)?,
        ["FETCH", rest @ ..] => parse_egroup_fetch(rest)?,
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn parse_submit(params: &[&str]) -> Result<EgroupCommand, E2eeError> {
    let (kind, conversation) = match params {
        ["CANDIDATE", id] => (SubmitKind::Candidate, id),
        ["AUTHORIZATION", id] => (SubmitKind::Authorization, id),
        ["ACK", id] => (SubmitKind::Ack, id),
        ["FINALIZATION", id] => (SubmitKind::Finalization, id),
        ["ABORT", id] => (SubmitKind::Abort, id),
        ["REINIT", "ATTEMPT", id] => (SubmitKind::ReinitAttempt, id),
        ["REINIT", "ACK", id] => (SubmitKind::ReinitAck, id),
        ["REINIT", "ACTIVATE", id] => (SubmitKind::ReinitActivate, id),
        ["REINIT", "ABORT", id] => (SubmitKind::ReinitAbort, id),
        ["POLICY", id] => (SubmitKind::Policy, id),
        ["MEMBERSHIP", id] => (SubmitKind::Membership, id),
        ["RECOVERY", id] => (SubmitKind::Recovery, id),
        ["RECOVERY-ELEMENT", id, submission] => {
            return Ok(EgroupCommand::SubmitRecoveryElement {
                conversation_id: parse_hash(id)?,
                submission_id: parse_hash(submission)?,
            });
        }
        _ => return Err(E2eeError::InvalidValue),
    };
    Ok(EgroupCommand::Submit {
        kind,
        conversation_id: parse_hash(conversation)?,
    })
}

fn parse_egroup_fetch(params: &[&str]) -> Result<EgroupCommand, E2eeError> {
    use EgroupCommand::*;
    Ok(match params {
        ["OBJECT", conversation, object] => FetchObject {
            conversation_id: parse_hash(conversation)?,
            object_id: parse_hash(object)?,
        },
        ["AUTHORIZATIONS", conversation, candidate, cursor] => FetchAuthorizations {
            conversation_id: parse_hash(conversation)?,
            candidate_id: parse_hash(candidate)?,
            cursor: parse_cursor(cursor)?,
        },
        ["ACKS", conversation, selector, cursor] => FetchAcks {
            conversation_id: parse_hash(conversation)?,
            selector: parse_hash(selector)?,
            cursor: parse_cursor(cursor)?,
        },
        ["RECEIPTS", conversation, first, cursor] => FetchReceipts {
            conversation_id: parse_hash(conversation)?,
            first_route_sequence: parse_u64(first)?,
            cursor: parse_cursor(cursor)?,
        },
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn parse_ekey(params: &[&str]) -> Result<EkeyCommand, E2eeError> {
    use EkeyCommand::*;
    Ok(match params {
        ["FETCH", rest @ ..] => parse_ekey_fetch(rest)?,
        ["PUBLISH", "IDENTITY"] => PublishIdentity,
        ["PUBLISH", "ROSTER"] => PublishRoster,
        ["PUBLISH", "CAPABILITIES", device] => PublishCapabilities(parse_id16(device)?),
        ["PUBLISH", "PACKAGE", device, suite, "NORMAL", expires] => PublishPackage {
            device_id: parse_id16(device)?,
            suite: parse_u16(suite)?,
            expires_at: parse_u64(expires)?,
        },
        ["WHOAMI"] => Whoami,
        ["ATTACH", "BEGIN", device] => AttachBegin(parse_id16(device)?),
        ["ATTACH", "FINISH", device] => AttachFinish(parse_id16(device)?),
        ["CLAIM", "PACKAGE", account, device, suite, operation] => ClaimPackage {
            account: parse_account(account)?,
            device_id: parse_id16(device)?,
            suite: parse_u16(suite)?,
            operation_id: parse_id16(operation)?,
        },
        ["CLAIM", "STATUS", operation] => ClaimStatus(parse_id16(operation)?),
        ["REVOKE", "PACKAGE", reference] => RevokePackage(parse_key_package_ref(reference)?),
        ["DELIVER", rest @ ..] => parse_deliver(rest)?,
        ["ACK", "MAILBOX", token, object] => AckMailbox {
            delivery_token: parse_hash(token)?,
            object_id: parse_hash(object)?,
        },
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn parse_ekey_fetch(params: &[&str]) -> Result<EkeyCommand, E2eeError> {
    use EkeyCommand::*;
    Ok(match params {
        ["IDENTITY", account] => FetchIdentity(parse_account(account)?),
        ["ROOT-CHAIN", account, first, cursor] => FetchRootChain {
            account: parse_account(account)?,
            first_generation: parse_u64(first)?,
            cursor: parse_cursor(cursor)?,
        },
        ["ROSTER", account] => FetchRoster(parse_account(account)?),
        ["CAPABILITIES", account, cursor] => FetchCapabilities {
            account: parse_account(account)?,
            cursor: parse_cursor(cursor)?,
        },
        ["BINDING-LOCKS", account, fingerprint, first, cursor] => FetchBindingLocks {
            account: parse_account(account)?,
            root_fingerprint: parse_hash(fingerprint)?,
            first_sequence: parse_u64(first)?,
            cursor: parse_cursor(cursor)?,
        },
        ["MAILBOX", kind, cursor] => FetchMailbox {
            kind: MailboxKind::parse(kind)?,
            cursor: parse_cursor(cursor)?,
        },
        _ => return Err(E2eeError::InvalidValue),
    })
}

fn parse_deliver(params: &[&str]) -> Result<EkeyCommand, E2eeError> {
    use EkeyCommand::*;
    Ok(match params {
        ["BINDING", account, device] => DeliverBinding {
            account: parse_account(account)?,
            device_id: parse_id16(device)?,
        },
        ["WELCOME", account, device, conversation, authorization] => DeliverWelcome {
            account: parse_account(account)?,
            device_id: parse_id16(device)?,
            conversation_id: parse_hash(conversation)?,
            authorization_id: parse_hash(authorization)?,
        },
        _ => return Err(E2eeError::InvalidValue),
    })
}

#[cfg(test)]
#[path = "../tests/command.rs"]
mod tests;
