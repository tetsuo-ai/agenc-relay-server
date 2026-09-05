//! `result.<kind>` arms and `FederationReply` values (spec 20.4, B.6).

use agenc_ircd_client_wire::WireMessage;
use agenc_ircd_domain::DomainError;
use agenc_ircd_federation_wire::access::{
    expect_schema, fixed, opaque, opaque_field, optional_fixed, text, unsigned, unsigned_u32,
    vector,
};
use agenc_ircd_federation_wire::{
    CodecError, HistoryPage, SchemaObject, WireValue, result_schema_name,
};
use agenc_ircd_types::{AccountId, FederationResultKind, SessionId, UserId};

use super::{account_text, optional_account_id, presence, presence_of, unsigned_value};

/// The typed content of one result arm.
#[derive(Eq, PartialEq)]
pub(crate) enum ResultArm {
    /// `failed`: a closed Appendix-A code plus a validated identifier context.
    Failed { code: String, context: String },
    /// `committed`.
    Committed { resulting_state_generation: u64 },
    /// `session_registered`.
    SessionRegistered(SessionRegistered),
    /// `auth_challenge`: the sealed account-service response object.
    AuthChallenge(SchemaObject),
    /// `authenticated`.
    Authenticated {
        account_id: AccountId,
        account_session_generation: u64,
        auth_grant_id: [u8; 32],
    },
    /// `account_created`.
    AccountCreated {
        account_id: AccountId,
        account_revision: u64,
    },
    /// `reply_page`.
    ReplyPage {
        snapshot_token: [u8; 32],
        page_sequence: u32,
        next_cursor: Option<[u8; 32]>,
    },
    /// `no_content`.
    NoContent,
    /// An immutable bounded history page, with no outer replies or completion event.
    HistoryPage(HistoryPage),
    /// Terminal invalidation of one exact original successful history result.
    HistoryExpired { original_result_object_id: [u8; 32] },
}

/// The `session_registered` arm fields.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SessionRegistered {
    pub session_id: SessionId,
    pub user_id: UserId,
    pub session_revision: u64,
    pub account: Option<(AccountId, u64, u64)>,
    pub resulting_state_generation: u64,
}

impl ResultArm {
    /// Returns the registered result kind.
    pub(crate) const fn kind(&self) -> FederationResultKind {
        match self {
            Self::Failed { .. } => FederationResultKind::Failed,
            Self::Committed { .. } => FederationResultKind::Committed,
            Self::SessionRegistered(_) => FederationResultKind::SessionRegistered,
            Self::AuthChallenge(_) => FederationResultKind::AuthChallenge,
            Self::Authenticated { .. } => FederationResultKind::Authenticated,
            Self::AccountCreated { .. } => FederationResultKind::AccountCreated,
            Self::ReplyPage { .. } => FederationResultKind::ReplyPage,
            Self::NoContent => FederationResultKind::NoContent,
            Self::HistoryPage(_) => FederationResultKind::HistoryPage,
            Self::HistoryExpired { .. } => FederationResultKind::HistoryExpired,
        }
    }

    /// Encodes the arm as its `result.<kind>` object.
    // agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match encodes every result arm in schema field order
    pub(crate) fn to_object(&self) -> Result<SchemaObject, CodecError> {
        let name = result_schema_name(self.kind());
        match self {
            Self::Failed { code, context } => SchemaObject::new(
                name,
                vec![opaque(code.as_bytes())?, opaque(context.as_bytes())?],
            ),
            Self::Committed {
                resulting_state_generation,
            } => SchemaObject::new(name, vec![unsigned_value(*resulting_state_generation)]),
            Self::SessionRegistered(registered) => {
                let (account, generation, revision) = match registered.account {
                    Some((account, generation, revision)) => {
                        (account_text(account)?, generation, revision)
                    }
                    None => (opaque(&[])?, 0, 0),
                };
                SchemaObject::new(
                    name,
                    vec![
                        opaque(registered.session_id.as_bytes())?,
                        opaque(registered.user_id.as_bytes())?,
                        unsigned_value(registered.session_revision),
                        account,
                        unsigned_value(generation),
                        unsigned_value(revision),
                        unsigned_value(registered.resulting_state_generation),
                    ],
                )
            }
            Self::AuthChallenge(response) => {
                SchemaObject::new(name, vec![WireValue::Structure(response.try_clone()?)])
            }
            Self::Authenticated {
                account_id,
                account_session_generation,
                auth_grant_id,
            } => SchemaObject::new(
                name,
                vec![
                    account_text(*account_id)?,
                    unsigned_value(*account_session_generation),
                    opaque(auth_grant_id)?,
                ],
            ),
            Self::AccountCreated {
                account_id,
                account_revision,
            } => SchemaObject::new(
                name,
                vec![
                    account_text(*account_id)?,
                    unsigned_value(*account_revision),
                ],
            ),
            Self::ReplyPage {
                snapshot_token,
                page_sequence,
                next_cursor,
            } => {
                let cursor: &[u8] = next_cursor.as_ref().map_or(&[], |cursor| cursor);
                SchemaObject::new(
                    name,
                    vec![
                        opaque(snapshot_token)?,
                        unsigned_value(u64::from(*page_sequence)),
                        opaque(cursor)?,
                    ],
                )
            }
            Self::NoContent => SchemaObject::new(name, Vec::new()),
            Self::HistoryPage(page) => page.to_object(),
            Self::HistoryExpired {
                original_result_object_id,
            } => SchemaObject::new(name, vec![opaque(original_result_object_id)?]),
        }
    }

    /// Decodes one `result.<kind>` object.
    pub(crate) fn from_object(
        kind: FederationResultKind,
        object: &SchemaObject,
    ) -> Result<Self, CodecError> {
        expect_schema(object, result_schema_name(kind))?;
        Ok(match kind {
            FederationResultKind::Failed => Self::Failed {
                code: super::owned_text(object, "reply_code")?,
                context: super::owned_text(object, "safe_context")?,
            },
            FederationResultKind::Committed => Self::Committed {
                resulting_state_generation: unsigned(object, "resulting_state_generation")?,
            },
            FederationResultKind::SessionRegistered => {
                let account = optional_account_id(object, "account_id")?;
                let generation = unsigned(object, "account_session_generation")?;
                let revision = unsigned(object, "account_revision")?;
                if account.is_some() != (generation != 0 && revision != 0) {
                    return Err(CodecError::CrossReference);
                }
                Self::SessionRegistered(SessionRegistered {
                    session_id: SessionId::from_bytes(fixed(object, "session_id")?),
                    user_id: UserId::from_bytes(fixed(object, "user_id")?),
                    session_revision: unsigned(object, "session_revision")?,
                    account: account.map(|account| (account, generation, revision)),
                    resulting_state_generation: unsigned(object, "resulting_state_generation")?,
                })
            }
            FederationResultKind::AuthChallenge => Self::AuthChallenge(
                agenc_ircd_federation_wire::access::structure(object, "account_service_response")?
                    .try_clone()?,
            ),
            FederationResultKind::Authenticated => Self::Authenticated {
                account_id: super::account_id_of(object, "account_id")?,
                account_session_generation: unsigned(object, "account_session_generation")?,
                auth_grant_id: fixed(object, "auth_grant_id")?,
            },
            FederationResultKind::AccountCreated => Self::AccountCreated {
                account_id: super::account_id_of(object, "account_id")?,
                account_revision: unsigned(object, "account_revision")?,
            },
            FederationResultKind::ReplyPage => Self::ReplyPage {
                snapshot_token: fixed(object, "snapshot_token")?,
                page_sequence: unsigned_u32(object, "page_sequence")?,
                next_cursor: optional_fixed(object, "next_cursor")?,
            },
            FederationResultKind::NoContent => Self::NoContent,
            FederationResultKind::HistoryPage => {
                Self::HistoryPage(HistoryPage::new(object.try_clone()?)?)
            }
            FederationResultKind::HistoryExpired => Self::HistoryExpired {
                original_result_object_id: fixed(object, "original_result_object_id")?,
            },
        })
    }
}

/// The closed base failure codes carried by `result.failed`, keyed by the
/// domain error the coordinator observed. Every code is in the registered
/// `federation-failed-reply-codes` list; the edge maps a code back to the
/// nearest domain error and renders it with the client's own capabilities
/// and the request's target text.
const FAILURE_CODES: [(DomainError, &str); 20] = [
    (DomainError::InvalidArgument, "INVALID_ARGUMENT"),
    (DomainError::DuplicateTarget, "INVALID_ARGUMENT"),
    (DomainError::MixedAuthority, "INVALID_ARGUMENT"),
    (DomainError::NotFound, "STALE_STATE"),
    (DomainError::SecretUnavailable, "SECRET_UNAVAILABLE"),
    (DomainError::Forbidden, "NOT_ALLOWED"),
    (DomainError::RegistrationRequired, "REGISTRATION_REQUIRED"),
    (DomainError::StaleGeneration, "STALE_STATE"),
    (DomainError::StaleRevision, "STALE_STATE"),
    (DomainError::LimitExceeded, "TOO_LARGE"),
    (DomainError::ServerBusy, "SERVER_BUSY"),
    (DomainError::BadState, "BAD_STATE"),
    (DomainError::EncryptedRoute, "E2EE_REQUIRED"),
    (DomainError::PlaintextRoute, "NOT_ALLOWED"),
    (DomainError::UnsafeCtcp, "NOT_ALLOWED"),
    (DomainError::WallClockUnavailable, "SERVER_BUSY"),
    (DomainError::ExternalInputMismatch, "SERVER_BUSY"),
    (DomainError::Overflow, "SERVER_BUSY"),
    (DomainError::AllocationFailed, "SERVER_BUSY"),
    (DomainError::InvariantViolation, "SERVER_BUSY"),
];

/// The domain error the edge renders for each registered code.
const CODE_ERRORS: [(&str, DomainError); 20] = [
    ("ALREADY_AUTHENTICATED", DomainError::BadState),
    ("AUTH_REQUIRED", DomainError::RegistrationRequired),
    ("BAD_SEQUENCE", DomainError::BadState),
    ("BAD_STATE", DomainError::BadState),
    ("CHANNEL_FULL", DomainError::Forbidden),
    ("E2EE_REQUIRED", DomainError::EncryptedRoute),
    ("E2EE_SYNCING", DomainError::ServerBusy),
    ("INVALID_ARGUMENT", DomainError::InvalidArgument),
    ("NOT_ALLOWED", DomainError::Forbidden),
    ("ORIGIN_EXPIRED", DomainError::BadState),
    ("ORIGIN_GAP", DomainError::BadState),
    ("QUERY_EXPIRED", DomainError::ServerBusy),
    ("RATE_LIMITED", DomainError::ServerBusy),
    ("REGISTRATION_REQUIRED", DomainError::RegistrationRequired),
    ("SECRET_UNAVAILABLE", DomainError::SecretUnavailable),
    ("SERVER_BUSY", DomainError::ServerBusy),
    ("STALE_STATE", DomainError::StaleRevision),
    ("STORAGE_UNAVAILABLE", DomainError::ServerBusy),
    ("TOO_LARGE", DomainError::LimitExceeded),
    ("UNAVAILABLE", DomainError::ServerBusy),
];

/// Maps a domain error onto its registered failure code.
pub(crate) fn failure_code(error: DomainError) -> &'static str {
    FAILURE_CODES
        .iter()
        .find_map(|(candidate, code)| (*candidate == error).then_some(*code))
        .unwrap_or("SERVER_BUSY")
}

/// Maps a registered failure code onto the domain error the edge renders.
pub(crate) fn failure_error(code: &str) -> Option<DomainError> {
    CODE_ERRORS
        .iter()
        .find_map(|(candidate, error)| (*candidate == code).then_some(*error))
}

/// Encodes one already rendered reply line as a `FederationReply`.
pub(crate) fn reply_object(message: &WireMessage) -> Result<SchemaObject, CodecError> {
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(message.middle().len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for parameter in message.middle() {
        parameters.push(SchemaObject::new(
            "FederationParameter",
            vec![opaque(parameter.as_bytes())?],
        )?);
    }
    let trailing = message.trailing();
    SchemaObject::new(
        "FederationReply",
        vec![
            opaque(message.command().as_bytes())?,
            WireValue::Vector(parameters),
            presence(trailing.is_some()),
            opaque(trailing.unwrap_or("").as_bytes())?,
        ],
    )
}

/// The decoded parts of one `FederationReply`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ReplyParts {
    pub command: String,
    pub parameters: Vec<String>,
    pub trailing: Option<String>,
}

/// Decodes one `FederationReply`.
pub(crate) fn reply_parts_of(object: &SchemaObject) -> Result<ReplyParts, CodecError> {
    expect_schema(object, "FederationReply")?;
    let items = vector(object, "parameters")?;
    let mut parameters = Vec::new();
    parameters
        .try_reserve_exact(items.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for item in items {
        expect_schema(item, "FederationParameter")?;
        parameters.push(super::owned_text(item, "value")?);
    }
    let present = presence_of(object, "trailing_presence")?;
    let trailing = text(object, "trailing")?;
    if !present && !trailing.is_empty() {
        return Err(CodecError::CrossReference);
    }
    let _ = opaque_field(object, "command")?;
    Ok(ReplyParts {
        command: super::owned_text(object, "command")?,
        parameters,
        trailing: present.then(|| trailing.to_owned()),
    })
}
