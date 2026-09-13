//! Typed `operation.<opcode>` arms (spec 20.5.2).
//!
//! The edge encodes a typed operation from its client's command and the
//! coordinator decodes the same shape before it converts the operation into
//! a domain command. Query arms and account-service envelopes stay as
//! validated schema objects because their content is interpreted by other
//! owners.

use agenc_ircd_domain::MessageKind;
use agenc_ircd_domain::federation::ModeDirection;
use agenc_ircd_federation_wire::access::{
    expect_schema, fixed, opaque, opaque_field, optional_fixed, structure, text, unsigned,
    unsigned_u16, vector,
};
use agenc_ircd_federation_wire::{
    CanonicalEncode, CodecError, DecodeBudget, SchemaObject, WireValue, operation_schema_name,
};
use agenc_ircd_types::{ChannelInstanceId, ConnectionId, FederationOpcode, SessionId, UserId};
use zeroize::Zeroizing;

use super::{
    channel_name_object, client_tag_object, client_tags_of, direction_of_value,
    message_kind_of_value, nickname_object, owned_text, presence, presence_of, unsigned_value,
};

const TARGET_CHANNEL: u64 = 1;
const TARGET_USER: u64 = 2;
const MAX_KICK_TARGETS: usize = 4;
/// The fixed B.4 user-mode code for operator notices.
pub(crate) const USER_MODE_CODE_WALLOPS: u16 = 18;

/// One join target with its optional key, zeroized on drop.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct JoinTarget {
    pub channel_name: String,
    pub join_key: Zeroizing<Vec<u8>>,
}

/// One requested mode change: the registered code plus its raw argument.
/// Mask arguments are canonical client text here and typed objects on the wire.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct ModeChangeArg {
    pub direction: ModeDirection,
    pub mode_code: u16,
    pub argument: Zeroizing<Vec<u8>>,
}

/// One message target as the edge named it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum MessageTargetArg {
    /// A channel by instance ID with its expected revision.
    Channel {
        channel_id: ChannelInstanceId,
        expected_revision: u64,
    },
    /// A user by canonical nickname.
    User { nickname: String },
}

/// The typed content of one operation arm.
#[derive(Eq, PartialEq)]
pub(crate) enum FederatedOperation {
    SessionOpen {
        connection_id: ConnectionId,
        auth_grant_id: Option<[u8; 32]>,
        nickname: String,
        realname: String,
        capability_hash: [u8; 32],
        connection_nonce: [u8; 32],
    },
    SessionClose {
        session_id: SessionId,
        reason_code: u16,
    },
    NickChange {
        session_id: SessionId,
        expected_session_revision: u64,
        nickname: String,
    },
    Join {
        session_id: SessionId,
        expected_session_revision: u64,
        targets: Vec<JoinTarget>,
    },
    Part {
        session_id: SessionId,
        expected_session_revision: u64,
        all_channels: bool,
        channels: Vec<ChannelInstanceId>,
        reason: String,
    },
    ChannelMode {
        session_id: SessionId,
        channel_id: ChannelInstanceId,
        expected_channel_revision: u64,
        changes: Vec<ModeChangeArg>,
    },
    UserMode {
        session_id: SessionId,
        expected_session_revision: u64,
        changes: Vec<ModeChangeArg>,
    },
    Topic {
        session_id: SessionId,
        channel_id: ChannelInstanceId,
        expected_channel_revision: u64,
        topic: String,
    },
    Invite {
        session_id: SessionId,
        channel_id: ChannelInstanceId,
        target_nickname: String,
        expected_channel_revision: u64,
    },
    Kick {
        session_id: SessionId,
        channel_id: ChannelInstanceId,
        targets: Vec<UserId>,
        expected_channel_revision: u64,
        reason: String,
    },
    Message {
        session_id: SessionId,
        kind: MessageKind,
        targets: Vec<MessageTargetArg>,
        tags: Vec<(String, String)>,
        body: String,
    },
    Away {
        session_id: SessionId,
        expected_session_revision: u64,
        away_text: String,
    },
    Setname {
        session_id: SessionId,
        expected_session_revision: u64,
        display_name: String,
    },
    ChannelRegister {
        session_id: SessionId,
        channel_id: ChannelInstanceId,
        expected_channel_revision: u64,
    },
    ChannelUnregister {
        session_id: SessionId,
        channel_id: ChannelInstanceId,
        expected_channel_revision: u64,
    },
    ChannelSettings {
        session_id: SessionId,
        channel_id: ChannelInstanceId,
        expected_channel_revision: u64,
        setting_kind: u16,
    },
    AccountSettings {
        session_id: SessionId,
        expected_account_revision: u64,
        setting_kind: u16,
        value: Vec<u8>,
    },
    HistoryQuery {
        session_id: SessionId,
        channel_id: ChannelInstanceId,
        selector: agenc_ircd_federation_wire::HistorySelectorObject,
        limit: u16,
        cursor: Option<[u8; 32]>,
    },
    DirectoryQuery {
        session_id: SessionId,
        query: SchemaObject,
    },
    /// The four account and two credential envelopes, with the session the
    /// credential operations bind to.
    AccountService {
        opcode: FederationOpcode,
        session_id: Option<SessionId>,
        envelope: SchemaObject,
    },
}

impl FederatedOperation {
    /// Returns the operation's registered opcode.
    pub(crate) const fn opcode(&self) -> FederationOpcode {
        match self {
            Self::SessionOpen { .. } => FederationOpcode::SessionOpen,
            Self::SessionClose { .. } => FederationOpcode::SessionClose,
            Self::NickChange { .. } => FederationOpcode::NickChange,
            Self::Join { .. } => FederationOpcode::Join,
            Self::Part { .. } => FederationOpcode::Part,
            Self::ChannelMode { .. } => FederationOpcode::ChannelMode,
            Self::UserMode { .. } => FederationOpcode::UserMode,
            Self::Topic { .. } => FederationOpcode::Topic,
            Self::Invite { .. } => FederationOpcode::Invite,
            Self::Kick { .. } => FederationOpcode::Kick,
            Self::Message { .. } => FederationOpcode::Message,
            Self::Away { .. } => FederationOpcode::Away,
            Self::Setname { .. } => FederationOpcode::Setname,
            Self::ChannelRegister { .. } => FederationOpcode::ChannelRegister,
            Self::ChannelUnregister { .. } => FederationOpcode::ChannelUnregister,
            Self::ChannelSettings { .. } => FederationOpcode::ChannelSettings,
            Self::AccountSettings { .. } => FederationOpcode::AccountSettings,
            Self::HistoryQuery { .. } => FederationOpcode::HistoryQuery,
            Self::DirectoryQuery { .. } => FederationOpcode::DirectoryQuery,
            Self::AccountService { opcode, .. } => *opcode,
        }
    }

    /// Returns the acting session, absent for session open and the
    /// account-creation and authentication envelopes.
    pub(crate) const fn session_id(&self) -> Option<SessionId> {
        match self {
            Self::SessionOpen { .. } => None,
            Self::SessionClose { session_id, .. }
            | Self::NickChange { session_id, .. }
            | Self::Join { session_id, .. }
            | Self::Part { session_id, .. }
            | Self::ChannelMode { session_id, .. }
            | Self::UserMode { session_id, .. }
            | Self::Topic { session_id, .. }
            | Self::Invite { session_id, .. }
            | Self::Kick { session_id, .. }
            | Self::Message { session_id, .. }
            | Self::Away { session_id, .. }
            | Self::Setname { session_id, .. }
            | Self::ChannelRegister { session_id, .. }
            | Self::ChannelUnregister { session_id, .. }
            | Self::ChannelSettings { session_id, .. }
            | Self::AccountSettings { session_id, .. }
            | Self::HistoryQuery { session_id, .. }
            | Self::DirectoryQuery { session_id, .. } => Some(*session_id),
            Self::AccountService { session_id, .. } => *session_id,
        }
    }

    /// Encodes the operation as its `operation.<opcode>` object.
    // agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match encodes every opcode arm in table order
    pub(crate) fn to_object(&self) -> Result<SchemaObject, CodecError> {
        let name = operation_schema_name(self.opcode());
        let fields = match self {
            Self::SessionOpen {
                connection_id,
                auth_grant_id,
                nickname,
                realname,
                capability_hash,
                connection_nonce,
            } => {
                let grant: &[u8] = auth_grant_id.as_ref().map_or(&[], |grant| grant);
                vec![
                    opaque(connection_id.as_bytes())?,
                    opaque(grant)?,
                    opaque(nickname.as_bytes())?,
                    opaque(realname.as_bytes())?,
                    opaque(capability_hash)?,
                    opaque(connection_nonce)?,
                ]
            }
            Self::SessionClose {
                session_id,
                reason_code,
            } => vec![
                opaque(session_id.as_bytes())?,
                unsigned_value(u64::from(*reason_code)),
            ],
            Self::NickChange {
                session_id,
                expected_session_revision,
                nickname,
            } => vec![
                opaque(session_id.as_bytes())?,
                unsigned_value(*expected_session_revision),
                opaque(nickname.as_bytes())?,
            ],
            Self::Join {
                session_id,
                expected_session_revision,
                targets,
            } => {
                let mut encoded = Vec::new();
                encoded
                    .try_reserve_exact(targets.len())
                    .map_err(|_| CodecError::AllocationFailed)?;
                for target in targets {
                    encoded.push(SchemaObject::new(
                        "FederationJoinTarget",
                        vec![
                            WireValue::Structure(channel_name_object(&target.channel_name)?),
                            opaque(&target.join_key)?,
                        ],
                    )?);
                }
                vec![
                    opaque(session_id.as_bytes())?,
                    unsigned_value(*expected_session_revision),
                    WireValue::Vector(encoded),
                ]
            }
            Self::Part {
                session_id,
                expected_session_revision,
                all_channels,
                channels,
                reason,
            } => {
                let mut encoded = Vec::new();
                encoded
                    .try_reserve_exact(channels.len())
                    .map_err(|_| CodecError::AllocationFailed)?;
                for channel in channels {
                    encoded.push(SchemaObject::new(
                        "FederationChannelId",
                        vec![opaque(channel.as_bytes())?],
                    )?);
                }
                vec![
                    opaque(session_id.as_bytes())?,
                    unsigned_value(*expected_session_revision),
                    presence(*all_channels),
                    WireValue::Vector(encoded),
                    opaque(reason.as_bytes())?,
                ]
            }
            Self::ChannelMode {
                session_id,
                channel_id,
                expected_channel_revision,
                changes,
            } => vec![
                opaque(session_id.as_bytes())?,
                opaque(channel_id.as_bytes())?,
                unsigned_value(*expected_channel_revision),
                WireValue::Vector(mode_change_objects(changes)?),
            ],
            Self::UserMode {
                session_id,
                expected_session_revision,
                changes,
            } => vec![
                opaque(session_id.as_bytes())?,
                unsigned_value(*expected_session_revision),
                WireValue::Vector(mode_change_objects(changes)?),
            ],
            Self::Topic {
                session_id,
                channel_id,
                expected_channel_revision,
                topic,
            } => vec![
                opaque(session_id.as_bytes())?,
                opaque(channel_id.as_bytes())?,
                unsigned_value(*expected_channel_revision),
                opaque(topic.as_bytes())?,
            ],
            Self::Invite {
                session_id,
                channel_id,
                target_nickname,
                expected_channel_revision,
            } => vec![
                opaque(session_id.as_bytes())?,
                opaque(channel_id.as_bytes())?,
                WireValue::Structure(SchemaObject::new(
                    "FederationNickname",
                    vec![opaque(target_nickname.as_bytes())?],
                )?),
                unsigned_value(*expected_channel_revision),
            ],
            Self::Kick {
                session_id,
                channel_id,
                targets,
                expected_channel_revision,
                reason,
            } => {
                let mut ids = Vec::new();
                ids.try_reserve_exact(targets.len().saturating_mul(16))
                    .map_err(|_| CodecError::AllocationFailed)?;
                for target in targets {
                    ids.extend_from_slice(target.as_bytes());
                }
                vec![
                    opaque(session_id.as_bytes())?,
                    opaque(channel_id.as_bytes())?,
                    opaque(&ids)?,
                    unsigned_value(*expected_channel_revision),
                    opaque(reason.as_bytes())?,
                ]
            }
            Self::Message {
                session_id,
                kind,
                targets,
                tags,
                body,
            } => {
                let mut encoded_targets = Vec::new();
                encoded_targets
                    .try_reserve_exact(targets.len())
                    .map_err(|_| CodecError::AllocationFailed)?;
                for target in targets {
                    let (target_kind, value, revision): (u64, &[u8], u64) = match target {
                        MessageTargetArg::Channel {
                            channel_id,
                            expected_revision,
                        } => (TARGET_CHANNEL, channel_id.as_bytes(), *expected_revision),
                        MessageTargetArg::User { nickname } => {
                            (TARGET_USER, nickname.as_bytes(), 0)
                        }
                    };
                    encoded_targets.push(SchemaObject::new(
                        "FederationMessageTarget",
                        vec![
                            unsigned_value(target_kind),
                            opaque(value)?,
                            unsigned_value(revision),
                        ],
                    )?);
                }
                let mut encoded_tags = Vec::new();
                encoded_tags
                    .try_reserve_exact(tags.len())
                    .map_err(|_| CodecError::AllocationFailed)?;
                for (key, value) in tags {
                    encoded_tags.push(client_tag_object(key, value)?);
                }
                vec![
                    opaque(session_id.as_bytes())?,
                    unsigned_value(match kind {
                        MessageKind::Privmsg => 1,
                        MessageKind::Notice => 2,
                        MessageKind::Tagmsg => 3,
                    }),
                    WireValue::Vector(encoded_targets),
                    WireValue::Vector(encoded_tags),
                    opaque(body.as_bytes())?,
                ]
            }
            Self::Away {
                session_id,
                expected_session_revision,
                away_text,
            } => vec![
                opaque(session_id.as_bytes())?,
                unsigned_value(*expected_session_revision),
                opaque(away_text.as_bytes())?,
            ],
            Self::Setname {
                session_id,
                expected_session_revision,
                display_name,
            } => vec![
                opaque(session_id.as_bytes())?,
                unsigned_value(*expected_session_revision),
                opaque(display_name.as_bytes())?,
            ],
            Self::ChannelRegister {
                session_id,
                channel_id,
                expected_channel_revision,
            }
            | Self::ChannelUnregister {
                session_id,
                channel_id,
                expected_channel_revision,
            } => vec![
                opaque(session_id.as_bytes())?,
                opaque(channel_id.as_bytes())?,
                unsigned_value(*expected_channel_revision),
            ],
            Self::ChannelSettings {
                session_id,
                channel_id,
                expected_channel_revision,
                setting_kind,
            } => vec![
                opaque(session_id.as_bytes())?,
                opaque(channel_id.as_bytes())?,
                unsigned_value(*expected_channel_revision),
                WireValue::Structure(SchemaObject::new(
                    "ChannelSettingsChange",
                    vec![unsigned_value(u64::from(*setting_kind))],
                )?),
            ],
            Self::AccountSettings {
                session_id,
                expected_account_revision,
                setting_kind,
                value,
            } => vec![
                opaque(session_id.as_bytes())?,
                unsigned_value(*expected_account_revision),
                WireValue::Structure(SchemaObject::new(
                    "AccountSettingsChange",
                    vec![unsigned_value(u64::from(*setting_kind)), opaque(value)?],
                )?),
            ],
            Self::HistoryQuery {
                session_id,
                channel_id,
                selector,
                limit,
                cursor,
            } => vec![
                opaque(session_id.as_bytes())?,
                opaque(channel_id.as_bytes())?,
                WireValue::Structure(selector.as_object().try_clone()?),
                unsigned_value(u64::from(*limit)),
                opaque(cursor.as_ref().map_or(&[], |cursor| cursor.as_slice()))?,
            ],
            Self::DirectoryQuery { session_id, query } => vec![
                opaque(session_id.as_bytes())?,
                WireValue::Structure(query.try_clone()?),
            ],
            Self::AccountService {
                session_id,
                envelope,
                ..
            } => {
                // The codec checks exact vector capacities, so the field
                // vector is sized for the arm it encodes.
                let mut fields = Vec::new();
                fields
                    .try_reserve_exact(1 + usize::from(session_id.is_some()))
                    .map_err(|_| CodecError::AllocationFailed)?;
                if let Some(session_id) = session_id {
                    fields.push(opaque(session_id.as_bytes())?);
                }
                fields.push(WireValue::Structure(envelope.try_clone()?));
                fields
            }
        };
        SchemaObject::new(name, fields)
    }

    /// Decodes one validated `operation.<opcode>` object.
    // agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match decodes every opcode arm and its cross-field rules
    pub(crate) fn from_object(
        opcode: FederationOpcode,
        object: &SchemaObject,
    ) -> Result<Self, CodecError> {
        expect_schema(object, operation_schema_name(opcode))?;
        let operation = match opcode {
            FederationOpcode::SessionOpen => Self::SessionOpen {
                connection_id: ConnectionId::from_bytes(fixed(object, "connection_id")?),
                auth_grant_id: optional_fixed(object, "auth_grant_id")?,
                nickname: owned_text(object, "nickname")?,
                realname: owned_text(object, "realname")?,
                capability_hash: fixed(object, "capability_hash")?,
                connection_nonce: fixed(object, "connection_nonce")?,
            },
            FederationOpcode::SessionClose => Self::SessionClose {
                session_id: session_of(object)?,
                reason_code: unsigned_u16(object, "reason_code")?,
            },
            FederationOpcode::NickChange => Self::NickChange {
                session_id: session_of(object)?,
                expected_session_revision: unsigned(object, "expected_session_revision")?,
                nickname: owned_text(object, "nickname")?,
            },
            FederationOpcode::Join => Self::Join {
                session_id: session_of(object)?,
                expected_session_revision: unsigned(object, "expected_session_revision")?,
                targets: join_targets_of(vector(object, "targets")?)?,
            },
            FederationOpcode::Part => part_of(object)?,
            FederationOpcode::ChannelMode => Self::ChannelMode {
                session_id: session_of(object)?,
                channel_id: channel_of(object)?,
                expected_channel_revision: unsigned(object, "expected_channel_revision")?,
                changes: mode_changes_of(vector(object, "changes")?)?,
            },
            FederationOpcode::UserMode => Self::UserMode {
                session_id: session_of(object)?,
                expected_session_revision: unsigned(object, "expected_session_revision")?,
                changes: mode_changes_of(vector(object, "changes")?)?,
            },
            FederationOpcode::Topic => Self::Topic {
                session_id: session_of(object)?,
                channel_id: channel_of(object)?,
                expected_channel_revision: unsigned(object, "expected_channel_revision")?,
                topic: owned_text(object, "topic")?,
            },
            FederationOpcode::Invite => {
                let target = structure(object, "target_nickname")?;
                expect_schema(target, "FederationNickname")?;
                Self::Invite {
                    session_id: session_of(object)?,
                    channel_id: channel_of(object)?,
                    target_nickname: owned_text(target, "value")?,
                    expected_channel_revision: unsigned(object, "expected_channel_revision")?,
                }
            }
            FederationOpcode::Kick => Self::Kick {
                session_id: session_of(object)?,
                channel_id: channel_of(object)?,
                targets: kick_targets_of(opaque_field(object, "target_user_ids")?)?,
                expected_channel_revision: unsigned(object, "expected_channel_revision")?,
                reason: owned_text(object, "reason")?,
            },
            FederationOpcode::Message => Self::Message {
                session_id: session_of(object)?,
                kind: message_kind_of_value(unsigned(object, "message_kind")?)
                    .ok_or(CodecError::UnknownDiscriminant)?,
                targets: message_targets_of(vector(object, "targets")?)?,
                tags: client_tags_of(vector(object, "tags")?)?,
                body: owned_text(object, "body")?,
            },
            FederationOpcode::Away => Self::Away {
                session_id: session_of(object)?,
                expected_session_revision: unsigned(object, "expected_session_revision")?,
                away_text: owned_text(object, "away_text")?,
            },
            FederationOpcode::Setname => Self::Setname {
                session_id: session_of(object)?,
                expected_session_revision: unsigned(object, "expected_session_revision")?,
                display_name: owned_text(object, "display_name")?,
            },
            FederationOpcode::ChannelRegister => Self::ChannelRegister {
                session_id: session_of(object)?,
                channel_id: channel_of(object)?,
                expected_channel_revision: unsigned(object, "expected_channel_revision")?,
            },
            FederationOpcode::ChannelUnregister => Self::ChannelUnregister {
                session_id: session_of(object)?,
                channel_id: channel_of(object)?,
                expected_channel_revision: unsigned(object, "expected_channel_revision")?,
            },
            FederationOpcode::ChannelSettings => {
                let change = structure(object, "change")?;
                expect_schema(change, "ChannelSettingsChange")?;
                Self::ChannelSettings {
                    session_id: session_of(object)?,
                    channel_id: channel_of(object)?,
                    expected_channel_revision: unsigned(object, "expected_channel_revision")?,
                    setting_kind: unsigned_u16(change, "setting_kind")?,
                }
            }
            FederationOpcode::AccountSettings => {
                let change = structure(object, "change")?;
                expect_schema(change, "AccountSettingsChange")?;
                Self::AccountSettings {
                    session_id: session_of(object)?,
                    expected_account_revision: unsigned(object, "expected_account_revision")?,
                    setting_kind: unsigned_u16(change, "setting_kind")?,
                    value: opaque_field(change, "value")?.to_vec(),
                }
            }
            FederationOpcode::HistoryQuery => Self::HistoryQuery {
                session_id: session_of(object)?,
                channel_id: channel_of(object)?,
                selector: agenc_ircd_federation_wire::HistorySelectorObject::new(
                    structure(object, "selector")?.try_clone()?,
                )?,
                limit: unsigned_u16(object, "limit")?,
                cursor: agenc_ircd_federation_wire::access::optional_fixed(object, "cursor")?,
            },
            FederationOpcode::DirectoryQuery => Self::DirectoryQuery {
                session_id: session_of(object)?,
                query: structure(object, "query")?.try_clone()?,
            },
            FederationOpcode::AccountCreateStart
            | FederationOpcode::AccountCreateFinish
            | FederationOpcode::OpaqueAuthStart
            | FederationOpcode::OpaqueAuthFinish => Self::AccountService {
                opcode,
                session_id: None,
                envelope: structure(object, "account_service_envelope")?.try_clone()?,
            },
            FederationOpcode::CredentialChangeStart | FederationOpcode::CredentialChangeFinish => {
                Self::AccountService {
                    opcode,
                    session_id: Some(session_of(object)?),
                    envelope: structure(object, "account_service_envelope")?.try_clone()?,
                }
            }
        };
        Ok(operation)
    }
}

fn session_of(object: &SchemaObject) -> Result<SessionId, CodecError> {
    Ok(SessionId::from_bytes(fixed(object, "session_id")?))
}

fn channel_of(object: &SchemaObject) -> Result<ChannelInstanceId, CodecError> {
    Ok(ChannelInstanceId::from_bytes(fixed(
        object,
        "channel_instance_id",
    )?))
}

fn mode_change_objects(changes: &[ModeChangeArg]) -> Result<Vec<SchemaObject>, CodecError> {
    let mut encoded = Vec::new();
    encoded
        .try_reserve_exact(changes.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for change in changes {
        encoded.push(SchemaObject::new(
            "FederationModeChange",
            vec![
                unsigned_value(match change.direction {
                    ModeDirection::Add => 1,
                    ModeDirection::Remove => 2,
                }),
                unsigned_value(u64::from(change.mode_code)),
                mode_argument_object(change)?,
            ],
        )?);
    }
    Ok(encoded)
}

fn mode_changes_of(items: &[SchemaObject]) -> Result<Vec<ModeChangeArg>, CodecError> {
    let mut changes = Vec::new();
    changes
        .try_reserve_exact(items.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for item in items {
        expect_schema(item, "FederationModeChange")?;
        let mode_code = unsigned_u16(item, "mode_code")?;
        changes.push(ModeChangeArg {
            direction: direction_of_value(unsigned(item, "direction")?)
                .ok_or(CodecError::UnknownDiscriminant)?,
            mode_code,
            argument: Zeroizing::new(mode_argument_of(item, mode_code)?),
        });
    }
    Ok(changes)
}

fn mode_argument_object(change: &ModeChangeArg) -> Result<WireValue, CodecError> {
    if (1..=3).contains(&change.mode_code) {
        let mask = std::str::from_utf8(&change.argument).map_err(|_| CodecError::CrossReference)?;
        let encoded = super::typed_mask_object(mask)?.encode_canonical()?;
        opaque(encoded.as_slice())
    } else {
        opaque(&change.argument)
    }
}

fn mode_argument_of(item: &SchemaObject, mode_code: u16) -> Result<Vec<u8>, CodecError> {
    let argument = opaque_field(item, "argument")?;
    if (1..=3).contains(&mode_code) {
        let mut budget = DecodeBudget::new(4096, 16);
        let mask = SchemaObject::decode_exact("FederationTypedMask", argument, &mut budget)?;
        Ok(super::typed_mask_of(&mask)?.into_bytes())
    } else {
        Ok(argument.to_vec())
    }
}

fn join_targets_of(items: &[SchemaObject]) -> Result<Vec<JoinTarget>, CodecError> {
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(items.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut previous: Option<String> = None;
    for item in items {
        expect_schema(item, "FederationJoinTarget")?;
        let name = structure(item, "channel_name")?;
        expect_schema(name, "FederationChannelName")?;
        let channel_name = owned_text(name, "value")?;
        if previous.as_ref().is_some_and(|last| *last >= channel_name) {
            return Err(CodecError::CrossReference);
        }
        previous = Some(channel_name.clone());
        targets.push(JoinTarget {
            channel_name,
            join_key: Zeroizing::new(opaque_field(item, "join_key")?.to_vec()),
        });
    }
    Ok(targets)
}

fn part_of(object: &SchemaObject) -> Result<FederatedOperation, CodecError> {
    let all_channels = presence_of(object, "all_channels")?;
    let items = vector(object, "channels")?;
    let reason = owned_text(object, "reason")?;
    if all_channels && !reason.is_empty() {
        return Err(CodecError::CrossReference);
    }
    if !all_channels && (items.is_empty() || items.len() > 20) {
        return Err(CodecError::CrossReference);
    }
    let mut channels = Vec::new();
    channels
        .try_reserve_exact(items.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut previous: Option<[u8; 16]> = None;
    for item in items {
        expect_schema(item, "FederationChannelId")?;
        let value: [u8; 16] = fixed(item, "value")?;
        if previous.is_some_and(|last| last >= value) {
            return Err(CodecError::CrossReference);
        }
        previous = Some(value);
        channels.push(ChannelInstanceId::from_bytes(value));
    }
    Ok(FederatedOperation::Part {
        session_id: session_of(object)?,
        expected_session_revision: unsigned(object, "expected_session_revision")?,
        all_channels,
        channels,
        reason,
    })
}

fn kick_targets_of(bytes: &[u8]) -> Result<Vec<UserId>, CodecError> {
    let (chunks, remainder) = bytes.as_chunks::<16>();
    if chunks.is_empty() || !remainder.is_empty() || chunks.len() > MAX_KICK_TARGETS {
        return Err(CodecError::CrossReference);
    }
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(chunks.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for chunk in chunks {
        targets.push(UserId::from_bytes(*chunk));
    }
    Ok(targets)
}

fn message_targets_of(items: &[SchemaObject]) -> Result<Vec<MessageTargetArg>, CodecError> {
    let mut targets = Vec::new();
    targets
        .try_reserve_exact(items.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    let mut previous: Option<(u64, Vec<u8>)> = None;
    for item in items {
        expect_schema(item, "FederationMessageTarget")?;
        let kind = unsigned(item, "target_kind")?;
        let ordering = (kind, opaque_field(item, "value")?.to_vec());
        if previous.as_ref().is_some_and(|last| *last >= ordering) {
            return Err(CodecError::CrossReference);
        }
        previous = Some(ordering);
        targets.push(message_target_of(item, kind)?);
    }
    Ok(targets)
}

fn message_target_of(item: &SchemaObject, kind: u64) -> Result<MessageTargetArg, CodecError> {
    let value = opaque_field(item, "value")?;
    let revision = unsigned(item, "expected_target_revision")?;
    match kind {
        TARGET_CHANNEL => {
            let id: [u8; 16] = value.try_into().map_err(|_| CodecError::CrossReference)?;
            if revision == 0 {
                return Err(CodecError::CrossReference);
            }
            Ok(MessageTargetArg::Channel {
                channel_id: ChannelInstanceId::from_bytes(id),
                expected_revision: revision,
            })
        }
        TARGET_USER => {
            if revision != 0 {
                return Err(CodecError::CrossReference);
            }
            Ok(MessageTargetArg::User {
                nickname: text(item, "value")?.to_owned(),
            })
        }
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

/// Builds the operation object for one `FederationNickname` value.
pub(crate) fn nickname_value_object(
    nickname: &agenc_ircd_domain::NicknameValue,
) -> Result<SchemaObject, CodecError> {
    nickname_object(nickname)
}
