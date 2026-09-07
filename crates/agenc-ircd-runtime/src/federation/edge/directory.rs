#![forbid(unsafe_code)]

//! Registered directory commands encoded for the coordinator (spec 20.4).

use agenc_ircd_domain::{
    CanonicalCommand, CanonicalCommandView, ChannelNameValue, DomainError, InformationQuery,
    MaskList, ModeCommand, NicknameValue, PresenceCommand, UserQuery, WhoTarget,
};
use agenc_ircd_federation_wire::access::opaque;
use agenc_ircd_federation_wire::{CanonicalEncode, CodecError, SchemaObject, WireValue};
use agenc_ircd_types::{FederationDirectoryQueryKind as QueryKind, SessionId};

use crate::federation::codec::operations::FederatedOperation;
use crate::federation::codec::{channel_name_object, nickname_object};

type QueryArm = (QueryKind, SchemaObject);

pub(super) fn operation(
    session_id: SessionId,
    command: &CanonicalCommand,
    cursor: Option<[u8; 32]>,
) -> Result<FederatedOperation, DomainError> {
    let (kind, arm) = command_arm(command.view())?;
    let encoded = arm.encode_canonical().map_err(invalid)?;
    let cursor = cursor.as_ref().map_or(&[][..], |cursor| &cursor[..]);
    let query = SchemaObject::new(
        "DirectoryQuery",
        vec![
            WireValue::Unsigned(u64::from(kind.wire_value())),
            opaque(encoded.as_slice()).map_err(invalid)?,
            opaque(cursor).map_err(invalid)?,
        ],
    )
    .map_err(invalid)?;
    Ok(FederatedOperation::DirectoryQuery { session_id, query })
}

fn command_arm(command: CanonicalCommandView<'_>) -> Result<QueryArm, DomainError> {
    match command {
        CanonicalCommandView::Names(channels) => arm(
            QueryKind::Names,
            "directory.names",
            vec![channel_names(channels)?],
        ),
        CanonicalCommandView::List(channels) => arm(
            QueryKind::List,
            "directory.list",
            vec![channel_names(channels)?],
        ),
        CanonicalCommandView::TopicQuery(channel) => arm(
            QueryKind::ChannelTopic,
            "directory.channel_topic",
            vec![channel_name(channel)?],
        ),
        CanonicalCommandView::UserQuery(query) => user_arm(query),
        CanonicalCommandView::Presence(query) => monitor_arm(query),
        CanonicalCommandView::Mode(query) => mode_arm(query),
        CanonicalCommandView::Information(InformationQuery::Links) => {
            arm(QueryKind::Links, "directory.links", Vec::new())
        }
        _ => Err(DomainError::BadState),
    }
}

fn user_arm(query: &UserQuery) -> Result<QueryArm, DomainError> {
    match query {
        UserQuery::Who(target) => arm(
            QueryKind::Who,
            "directory.who",
            vec![who_target(target.as_ref())?],
        ),
        UserQuery::Whois(name) => arm(QueryKind::Whois, "directory.whois", vec![nickname(name)?]),
        UserQuery::Whowas(name, count) => arm(
            QueryKind::Whowas,
            "directory.whowas",
            vec![nickname(name)?, WireValue::Unsigned(u64::from(*count))],
        ),
        UserQuery::Ison(names) => arm(QueryKind::Ison, "directory.ison", vec![nicknames(names)?]),
        UserQuery::Userhost(names) => arm(
            QueryKind::Userhost,
            "directory.userhost",
            vec![nicknames(names)?],
        ),
    }
}

fn monitor_arm(query: &PresenceCommand) -> Result<QueryArm, DomainError> {
    match query {
        PresenceCommand::MonitorAdd(names) => arm(
            QueryKind::MonitorAdd,
            "directory.monitor_add",
            vec![nicknames(names)?],
        ),
        PresenceCommand::MonitorRemove(names) => arm(
            QueryKind::MonitorRemove,
            "directory.monitor_remove",
            vec![nicknames(names)?],
        ),
        PresenceCommand::MonitorClear => arm(
            QueryKind::MonitorClear,
            "directory.monitor_clear",
            Vec::new(),
        ),
        PresenceCommand::MonitorList => {
            arm(QueryKind::MonitorList, "directory.monitor_list", Vec::new())
        }
        PresenceCommand::MonitorStatus => arm(
            QueryKind::MonitorStatus,
            "directory.monitor_status",
            Vec::new(),
        ),
        PresenceCommand::Away(_) => Err(DomainError::BadState),
    }
}

fn mode_arm(query: &ModeCommand) -> Result<QueryArm, DomainError> {
    match query {
        ModeCommand::ChannelQuery(channel) => arm(
            QueryKind::ChannelModes,
            "directory.channel_modes",
            vec![channel_name(channel)?],
        ),
        ModeCommand::ChannelList(channel, list) => {
            let code = match list {
                MaskList::Ban => 1,
                MaskList::Exception => 2,
                MaskList::InviteException => 3,
            };
            arm(
                QueryKind::ChannelModeList,
                "directory.channel_mode_list",
                vec![channel_name(channel)?, WireValue::Unsigned(code)],
            )
        }
        _ => Err(DomainError::BadState),
    }
}

fn arm(
    kind: QueryKind,
    schema: &'static str,
    fields: Vec<WireValue>,
) -> Result<QueryArm, DomainError> {
    Ok((kind, SchemaObject::new(schema, fields).map_err(invalid)?))
}

fn channel_names(channels: &[ChannelNameValue]) -> Result<WireValue, DomainError> {
    channels
        .iter()
        .map(|channel| channel_name_object(channel.canonical()))
        .collect::<Result<Vec<_>, _>>()
        .map(WireValue::Vector)
        .map_err(invalid)
}

fn channel_name(channel: &ChannelNameValue) -> Result<WireValue, DomainError> {
    channel_name_object(channel.canonical())
        .map(WireValue::Structure)
        .map_err(invalid)
}

fn nicknames(names: &[NicknameValue]) -> Result<WireValue, DomainError> {
    names
        .iter()
        .map(nickname_object)
        .collect::<Result<Vec<_>, _>>()
        .map(WireValue::Vector)
        .map_err(invalid)
}

fn nickname(name: &NicknameValue) -> Result<WireValue, DomainError> {
    nickname_object(name)
        .map(WireValue::Structure)
        .map_err(invalid)
}

fn who_target(target: Option<&WhoTarget>) -> Result<WireValue, DomainError> {
    let (kind, value) = match target {
        None => (0, ""),
        Some(WhoTarget::Nickname(name)) => (1, name.canonical()),
        Some(WhoTarget::Channel(channel)) => (2, channel.canonical()),
    };
    SchemaObject::new(
        "FederationQueryTarget",
        vec![
            WireValue::Unsigned(kind),
            opaque(value.as_bytes()).map_err(invalid)?,
        ],
    )
    .map(WireValue::Structure)
    .map_err(invalid)
}

fn invalid(_: CodecError) -> DomainError {
    DomainError::InvalidArgument
}
