//! Mapping between domain federation values and Appendix-B schema objects.
//!
//! Both roles use this module: the coordinator encodes projection events,
//! standing entries, and results, and the edge decodes them into the same
//! domain types before applying them to its replica. Every decoder validates
//! the closed enumerations and identifier shapes it reads; the generic codec
//! already enforced lengths, so the checks here are semantic only.

pub(crate) mod events;
pub(crate) mod history;
pub(crate) mod operations;
pub(crate) mod projection;
pub(crate) mod results;

use agenc_ircd_domain::federation::{
    AccountRecord, ActorView, ChannelDetailRecord, DeliveredMessageRecord, DeliveryTarget,
    InviteRecord, MembershipRecord, MembershipView, ModeDirection, ModeListEntryRecord,
    ProjectedModeChange, SessionEventView, SessionRecord, SourceView, role_level,
};
use agenc_ircd_domain::{
    AccountLabelValue, ChannelNameValue, ContentPolicy, DisplayNameValue, HistoryPolicy,
    MessageKind, NicknameValue, PersistencePolicy, Principal, Role, Visibility,
};
use agenc_ircd_federation_wire::access::{
    expect_schema, fixed, opaque, opaque_field, structure, text, unsigned, unsigned_u16, vector,
};
use agenc_ircd_federation_wire::{CanonicalEncode, CodecError, SchemaObject, WireValue};
use agenc_ircd_types::{
    AccountId, ChannelInstanceId, EntryId, Generation, InviteId, MessageId, PublicCloak, Revision,
    ServerId, SessionId, UserId, UtcSecond,
};

const PRESENCE_ABSENT: u64 = 0;
const PRESENCE_PRESENT: u64 = 1;
const PRINCIPAL_ACCOUNT: u64 = 1;
const PRINCIPAL_GUEST: u64 = 2;
const TARGET_CHANNEL: u64 = 1;
const TARGET_USER: u64 = 2;
const DIRECTION_ADD: u64 = 1;
const DIRECTION_REMOVE: u64 = 2;
const MASK_ACCOUNT: u64 = 1;
const MASK_USER: u64 = 2;
const MASK_NICKNAME: u64 = 3;
const MASK_CLOAK: u64 = 4;

fn presence(present: bool) -> WireValue {
    WireValue::Unsigned(if present {
        PRESENCE_PRESENT
    } else {
        PRESENCE_ABSENT
    })
}

fn presence_of(object: &SchemaObject, name: &str) -> Result<bool, CodecError> {
    match unsigned(object, name)? {
        PRESENCE_ABSENT => Ok(false),
        PRESENCE_PRESENT => Ok(true),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

/// Encodes an optional nested object as an opaque field, empty when absent.
pub(crate) fn encoded_or_empty(object: Option<&SchemaObject>) -> Result<WireValue, CodecError> {
    match object {
        Some(object) => opaque(object.encode_canonical()?.as_slice()),
        None => opaque(&[]),
    }
}

fn unsigned_value(value: u64) -> WireValue {
    WireValue::Unsigned(value)
}

fn revision_of(object: &SchemaObject, name: &str) -> Result<Revision, CodecError> {
    Revision::new(unsigned(object, name)?).map_err(|_| CodecError::IntegerOutOfRange)
}

fn generation_of(object: &SchemaObject, name: &str) -> Result<Generation, CodecError> {
    Generation::new(unsigned(object, name)?).map_err(|_| CodecError::IntegerOutOfRange)
}

fn utc_of(object: &SchemaObject, name: &str) -> Result<UtcSecond, CodecError> {
    Ok(UtcSecond::from_unix_seconds(unsigned(object, name)?))
}

fn owned_text(object: &SchemaObject, name: &str) -> Result<String, CodecError> {
    let value = text(object, name)?;
    let mut owned = String::new();
    owned
        .try_reserve_exact(value.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    owned.push_str(value);
    Ok(owned)
}

fn account_id_of(object: &SchemaObject, name: &str) -> Result<AccountId, CodecError> {
    AccountId::parse_wire_bytes(opaque_field(object, name)?).map_err(|_| CodecError::CrossReference)
}

fn optional_account_id(object: &SchemaObject, name: &str) -> Result<Option<AccountId>, CodecError> {
    match opaque_field(object, name)? {
        [] => Ok(None),
        bytes => AccountId::parse_wire_bytes(bytes)
            .map(Some)
            .map_err(|_| CodecError::CrossReference),
    }
}

fn account_text(account: AccountId) -> Result<WireValue, CodecError> {
    opaque(account.to_text().as_bytes())
}

pub(crate) fn nickname_object(nickname: &NicknameValue) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationNickname",
        vec![opaque(nickname.presentation().as_bytes())?],
    )
}

pub(crate) fn nickname_of(object: &SchemaObject) -> Result<NicknameValue, CodecError> {
    expect_schema(object, "FederationNickname")?;
    NicknameValue::parse(text(object, "value")?).map_err(|_| CodecError::CrossReference)
}

pub(crate) fn channel_name_object(name: &str) -> Result<SchemaObject, CodecError> {
    SchemaObject::new("FederationChannelName", vec![opaque(name.as_bytes())?])
}

pub(crate) fn channel_name_of(object: &SchemaObject) -> Result<ChannelNameValue, CodecError> {
    expect_schema(object, "FederationChannelName")?;
    ChannelNameValue::parse(text(object, "value")?).map_err(|_| CodecError::CrossReference)
}

fn cloak_object(cloak: &PublicCloak) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationPublicCloak",
        vec![
            opaque(cloak.user_component())?,
            opaque(cloak.host_component())?,
        ],
    )
}

fn cloak_of(object: &SchemaObject) -> Result<PublicCloak, CodecError> {
    expect_schema(object, "FederationPublicCloak")?;
    PublicCloak::from_components(
        fixed(object, "user_component")?,
        fixed(object, "host_component")?,
    )
    .map_err(|_| CodecError::CrossReference)
}

fn label_value(label: Option<&AccountLabelValue>) -> Result<WireValue, CodecError> {
    opaque(label.map_or("", AccountLabelValue::as_str).as_bytes())
}

fn label_of(object: &SchemaObject, name: &str) -> Result<Option<AccountLabelValue>, CodecError> {
    match text(object, name)? {
        "" => Ok(None),
        label => AccountLabelValue::parse(label)
            .map(Some)
            .map_err(|_| CodecError::CrossReference),
    }
}

pub(crate) fn source_view_object(view: &SourceView) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationSourceView",
        vec![
            opaque(view.user_id.as_bytes())?,
            WireValue::Structure(nickname_object(&view.nickname)?),
            WireValue::Structure(cloak_object(&view.public_cloak)?),
            label_value(view.account_label.as_ref())?,
        ],
    )
}

pub(crate) fn source_view_of(object: &SchemaObject) -> Result<SourceView, CodecError> {
    expect_schema(object, "FederationSourceView")?;
    Ok(SourceView {
        user_id: UserId::from_bytes(fixed(object, "user_id")?),
        nickname: nickname_of(structure(object, "nickname")?)?,
        public_cloak: cloak_of(structure(object, "public_cloak")?)?,
        account_label: label_of(object, "account_label")?,
    })
}

pub(crate) fn session_projection_object(
    record: &SessionRecord,
) -> Result<SchemaObject, CodecError> {
    let (account, generation) = match record.account {
        Some((account, generation)) => (account_text(account)?, generation.get()),
        None => (opaque(&[])?, 0),
    };
    SchemaObject::new(
        "FederationSessionProjection",
        vec![
            opaque(record.session_id.as_bytes())?,
            opaque(record.user_id.as_bytes())?,
            opaque(record.home_server_id.as_bytes())?,
            unsigned_value(record.session_revision.get()),
            account,
            unsigned_value(generation),
            WireValue::Structure(nickname_object(&record.nickname)?),
            opaque(record.display_name.as_str().as_bytes())?,
            WireValue::Structure(cloak_object(&record.public_cloak)?),
            label_value(record.account_label.as_ref())?,
            unsigned_value(u64::from(record.user_mode_bits)),
            presence(record.away.is_some()),
            opaque(record.away.as_deref().unwrap_or("").as_bytes())?,
        ],
    )
}

pub(crate) fn session_projection_of(object: &SchemaObject) -> Result<SessionRecord, CodecError> {
    expect_schema(object, "FederationSessionProjection")?;
    let account = optional_account_id(object, "account_id")?;
    let generation = generation_of(object, "account_session_generation")?;
    if account.is_some() == (generation.get() == 0) {
        return Err(CodecError::CrossReference);
    }
    let away = presence_of(object, "away_kind")?
        .then(|| owned_text(object, "away_text"))
        .transpose()?;
    Ok(SessionRecord {
        session_id: SessionId::from_bytes(fixed(object, "session_id")?),
        user_id: UserId::from_bytes(fixed(object, "user_id")?),
        home_server_id: ServerId::from_bytes(fixed(object, "home_server_id")?),
        session_revision: revision_of(object, "session_revision")?,
        account: account.map(|account| (account, generation)),
        nickname: nickname_of(structure(object, "nickname")?)?,
        display_name: DisplayNameValue::prepare(text(object, "display_name")?)
            .map_err(|_| CodecError::CrossReference)?,
        public_cloak: cloak_of(structure(object, "public_cloak")?)?,
        account_label: label_of(object, "account_label")?,
        user_mode_bits: unsigned_u16(object, "user_mode_bits")?,
        away,
    })
}

pub(crate) fn session_event_view_object(
    view: &SessionEventView,
) -> Result<SchemaObject, CodecError> {
    let projection = view
        .home_projection
        .as_ref()
        .map(session_projection_object)
        .transpose()?;
    SchemaObject::new(
        "FederationSessionEventView",
        vec![
            WireValue::Structure(source_view_object(&view.source)?),
            encoded_or_empty(projection.as_ref())?,
        ],
    )
}

pub(crate) fn session_event_view_of(
    object: &SchemaObject,
    budget: &mut agenc_ircd_federation_wire::DecodeBudget,
) -> Result<SessionEventView, CodecError> {
    expect_schema(object, "FederationSessionEventView")?;
    let source = source_view_of(structure(object, "source")?)?;
    let encoded = opaque_field(object, "home_session_projection")?;
    let home_projection = if encoded.is_empty() {
        None
    } else {
        let nested = SchemaObject::decode_exact("FederationSessionProjection", encoded, budget)?;
        let record = session_projection_of(&nested)?;
        if record.user_id != source.user_id {
            return Err(CodecError::CrossReference);
        }
        Some(record)
    };
    Ok(SessionEventView {
        source,
        home_projection,
    })
}

const fn visibility_value(visibility: Visibility) -> u64 {
    match visibility {
        Visibility::Listed => 1,
        Visibility::Unlisted => 2,
        Visibility::Secret => 3,
    }
}

const fn history_value(history: HistoryPolicy) -> u64 {
    match history {
        HistoryPolicy::Off => 0,
        HistoryPolicy::OneHour => 1,
        HistoryPolicy::TwentyFourHours => 2,
        HistoryPolicy::SevenDays => 3,
    }
}

/// The `channel_settings` setting kind of a history policy: the registered
/// history value plus one, the inverse of `history_of_value(kind - 1)`.
pub(crate) const fn history_setting_kind(history: HistoryPolicy) -> u16 {
    match history {
        HistoryPolicy::Off => 1,
        HistoryPolicy::OneHour => 2,
        HistoryPolicy::TwentyFourHours => 3,
        HistoryPolicy::SevenDays => 4,
    }
}

pub(crate) const fn history_of_value(value: u64) -> Option<HistoryPolicy> {
    match value {
        0 => Some(HistoryPolicy::Off),
        1 => Some(HistoryPolicy::OneHour),
        2 => Some(HistoryPolicy::TwentyFourHours),
        3 => Some(HistoryPolicy::SevenDays),
        _ => None,
    }
}

/// Fills the route binding of a bound channel detail: the domain records
/// only the content policy, and the binding is the channel route
/// identifier over the network and the channel instance (companion 9.2),
/// which the edge decoder requires beside `e2ee_bound`.
pub(crate) fn fill_route_binding(
    network_id: &agenc_ircd_types::NetworkId,
    detail: &mut ChannelDetailRecord,
) {
    if detail.content_policy != ContentPolicy::E2eeBound || detail.e2ee_route_binding.is_some() {
        return;
    }
    detail.e2ee_route_binding = agenc_ircd_e2ee::route::channel_route_binding(
        network_id.as_bytes(),
        detail.channel_id.as_bytes(),
    )
    .ok();
}

/// Fills the route binding of every bound channel detail a projection
/// delta carries, events and standing entries alike.
pub(crate) fn fill_projection_bindings(
    network_id: &agenc_ircd_types::NetworkId,
    edges: &mut [agenc_ircd_domain::federation::EdgeDelta],
) {
    for delta in edges.iter_mut() {
        for event in &mut delta.events {
            if let agenc_ircd_domain::federation::ProjectedEvent::ChannelVisible(detail)
            | agenc_ircd_domain::federation::ProjectedEvent::ChannelPolicyChanged(detail) = event
            {
                fill_route_binding(network_id, detail);
            }
        }
        for record in &mut delta.upserts {
            if let agenc_ircd_domain::federation::ProjectionRecord::ChannelDetail(detail) = record {
                fill_route_binding(network_id, detail);
            }
        }
    }
}

pub(crate) fn channel_detail_object(
    detail: &ChannelDetailRecord,
) -> Result<SchemaObject, CodecError> {
    let binding: &[u8] = detail
        .e2ee_route_binding
        .as_ref()
        .map_or(&[], |binding| binding);
    SchemaObject::new(
        "FederationChannelDetail",
        vec![
            opaque(detail.channel_id.as_bytes())?,
            WireValue::Structure(channel_name_object(detail.name.canonical())?),
            WireValue::Structure(channel_name_object(detail.name.presentation())?),
            unsigned_value(detail.channel_revision.get()),
            unsigned_value(visibility_value(detail.visibility)),
            unsigned_value(match detail.content_policy {
                ContentPolicy::Plaintext => 1,
                ContentPolicy::E2eeBound => 2,
            }),
            unsigned_value(match detail.persistence {
                PersistencePolicy::Ephemeral => 1,
                PersistencePolicy::Registered => 2,
            }),
            unsigned_value(u64::from(detail.simple_mode_bits)),
            unsigned_value(history_value(detail.history)),
            opaque(binding)?,
        ],
    )
}

pub(crate) fn channel_detail_of(object: &SchemaObject) -> Result<ChannelDetailRecord, CodecError> {
    expect_schema(object, "FederationChannelDetail")?;
    let name = channel_name_of(structure(object, "display_name")?)?;
    let canonical = channel_name_of(structure(object, "canonical_name")?)?;
    if canonical.canonical() != name.canonical() {
        return Err(CodecError::CrossReference);
    }
    let visibility = match unsigned(object, "visibility")? {
        1 => Visibility::Listed,
        2 => Visibility::Unlisted,
        3 => Visibility::Secret,
        _ => return Err(CodecError::UnknownDiscriminant),
    };
    let content_policy = match unsigned(object, "content_policy")? {
        1 => ContentPolicy::Plaintext,
        2 => ContentPolicy::E2eeBound,
        _ => return Err(CodecError::UnknownDiscriminant),
    };
    let persistence = match unsigned(object, "persistence_policy")? {
        1 => PersistencePolicy::Ephemeral,
        2 => PersistencePolicy::Registered,
        _ => return Err(CodecError::UnknownDiscriminant),
    };
    let history = history_of_value(unsigned(object, "history_policy")?)
        .ok_or(CodecError::UnknownDiscriminant)?;
    let e2ee_route_binding = match opaque_field(object, "e2ee_route_binding")? {
        [] => None,
        bytes => Some(bytes.try_into().map_err(|_| CodecError::CrossReference)?),
    };
    Ok(ChannelDetailRecord {
        channel_id: ChannelInstanceId::from_bytes(fixed(object, "channel_instance_id")?),
        name,
        channel_revision: revision_of(object, "channel_revision")?,
        visibility,
        content_policy,
        persistence,
        simple_mode_bits: unsigned_u16(object, "simple_mode_bits")?,
        history,
        e2ee_route_binding,
    })
}

pub(crate) const fn role_of_level(level: u64) -> Option<Role> {
    match level {
        0 => Some(Role::Member),
        1 => Some(Role::Voice),
        2 => Some(Role::HalfOperator),
        3 => Some(Role::Operator),
        4 => Some(Role::Administrator),
        5 => Some(Role::Owner),
        _ => None,
    }
}

pub(crate) fn membership_object(record: &MembershipRecord) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationMembership",
        vec![
            opaque(record.channel_id.as_bytes())?,
            opaque(record.user_id.as_bytes())?,
            unsigned_value(u64::from(role_level(record.role))),
            unsigned_value(record.membership_revision.get()),
            unsigned_value(record.joined_at.get()),
        ],
    )
}

pub(crate) fn membership_of(object: &SchemaObject) -> Result<MembershipRecord, CodecError> {
    expect_schema(object, "FederationMembership")?;
    Ok(MembershipRecord {
        channel_id: ChannelInstanceId::from_bytes(fixed(object, "channel_instance_id")?),
        user_id: UserId::from_bytes(fixed(object, "user_id")?),
        role: role_of_level(unsigned(object, "role")?).ok_or(CodecError::UnknownDiscriminant)?,
        membership_revision: revision_of(object, "membership_revision")?,
        joined_at: utc_of(object, "joined_at")?,
    })
}

pub(crate) fn membership_view_object(view: &MembershipView) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationMembershipView",
        vec![
            WireValue::Structure(membership_object(&view.membership)?),
            WireValue::Structure(source_view_object(&view.source)?),
        ],
    )
}

pub(crate) fn membership_view_of(object: &SchemaObject) -> Result<MembershipView, CodecError> {
    expect_schema(object, "FederationMembershipView")?;
    let membership = membership_of(structure(object, "membership")?)?;
    let source = source_view_of(structure(object, "source")?)?;
    if membership.user_id != source.user_id {
        return Err(CodecError::CrossReference);
    }
    Ok(MembershipView { membership, source })
}

fn principal_object(principal: Principal) -> Result<SchemaObject, CodecError> {
    let (kind, identifier) = match principal {
        Principal::Account(account) => (PRINCIPAL_ACCOUNT, account_text(account)?),
        Principal::Guest(user) => (PRINCIPAL_GUEST, opaque(user.as_bytes())?),
    };
    SchemaObject::new("PrincipalRef", vec![unsigned_value(kind), identifier])
}

fn principal_of(object: &SchemaObject) -> Result<Principal, CodecError> {
    expect_schema(object, "PrincipalRef")?;
    match unsigned(object, "kind")? {
        PRINCIPAL_ACCOUNT => account_id_of(object, "identifier").map(Principal::Account),
        PRINCIPAL_GUEST => Ok(Principal::Guest(UserId::from_bytes(fixed(
            object,
            "identifier",
        )?))),
        _ => Err(CodecError::UnknownDiscriminant),
    }
}

pub(crate) fn invite_projection_object(record: &InviteRecord) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationInviteProjection",
        vec![
            opaque(record.channel_id.as_bytes())?,
            opaque(record.invite_id.as_bytes())?,
            WireValue::Structure(principal_object(record.target)?),
            opaque(record.inviter_user_id.as_bytes())?,
            unsigned_value(record.creation_revision.get()),
            unsigned_value(record.expires_at.get()),
        ],
    )
}

pub(crate) fn invite_projection_of(object: &SchemaObject) -> Result<InviteRecord, CodecError> {
    expect_schema(object, "FederationInviteProjection")?;
    Ok(InviteRecord {
        channel_id: ChannelInstanceId::from_bytes(fixed(object, "channel_instance_id")?),
        invite_id: InviteId::from_bytes(fixed(object, "invite_id")?),
        target: principal_of(structure(object, "target_principal")?)?,
        inviter_user_id: UserId::from_bytes(fixed(object, "inviter_user_id")?),
        creation_revision: revision_of(object, "creation_revision")?,
        expires_at: utc_of(object, "expires_at")?,
    })
}

pub(crate) fn account_projection_object(
    record: &AccountRecord,
) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationAccountProjection",
        vec![
            account_text(record.account_id)?,
            unsigned_value(record.account_session_generation.get()),
            unsigned_value(record.account_revision.get()),
        ],
    )
}

pub(crate) fn account_projection_of(object: &SchemaObject) -> Result<AccountRecord, CodecError> {
    expect_schema(object, "FederationAccountProjection")?;
    Ok(AccountRecord {
        account_id: account_id_of(object, "account_id")?,
        account_session_generation: generation_of(object, "account_session_generation")?,
        account_revision: revision_of(object, "account_revision")?,
    })
}

pub(crate) fn actor_view_object(actor: &ActorView) -> Result<SchemaObject, CodecError> {
    let source = actor.0.as_ref().map(source_view_object).transpose()?;
    SchemaObject::new(
        "FederationActorView",
        vec![
            presence(actor.0.is_some()),
            encoded_or_empty(source.as_ref())?,
        ],
    )
}

pub(crate) fn actor_view_of(
    object: &SchemaObject,
    budget: &mut agenc_ircd_federation_wire::DecodeBudget,
) -> Result<ActorView, CodecError> {
    expect_schema(object, "FederationActorView")?;
    let present = presence_of(object, "user_present")?;
    let encoded = opaque_field(object, "source")?;
    if present != !encoded.is_empty() {
        return Err(CodecError::CrossReference);
    }
    if !present {
        return Ok(ActorView(None));
    }
    let nested = SchemaObject::decode_exact("FederationSourceView", encoded, budget)?;
    Ok(ActorView(Some(source_view_of(&nested)?)))
}

const fn direction_value(direction: ModeDirection) -> u64 {
    match direction {
        ModeDirection::Add => DIRECTION_ADD,
        ModeDirection::Remove => DIRECTION_REMOVE,
    }
}

pub(crate) const fn direction_of_value(value: u64) -> Option<ModeDirection> {
    match value {
        DIRECTION_ADD => Some(ModeDirection::Add),
        DIRECTION_REMOVE => Some(ModeDirection::Remove),
        _ => None,
    }
}

/// Splits one stored typed-mask text into its registered kind, quiet flag,
/// and prefix-free value.
fn typed_mask_object(mask: &str) -> Result<SchemaObject, CodecError> {
    let (quiet, rest) = match mask.strip_prefix("$q:") {
        Some(rest) => (true, rest),
        None => (false, mask),
    };
    let (kind, value) = if let Some(value) = rest.strip_prefix("$a:") {
        (MASK_ACCOUNT, value)
    } else if let Some(value) = rest.strip_prefix("$u:") {
        (MASK_USER, value)
    } else if let Some(value) = rest.strip_prefix("$n:") {
        (MASK_NICKNAME, value)
    } else if let Some(value) = rest.strip_prefix("$c:") {
        (MASK_CLOAK, value)
    } else {
        return Err(CodecError::CrossReference);
    };
    SchemaObject::new(
        "FederationTypedMask",
        vec![
            unsigned_value(kind),
            presence(quiet),
            opaque(value.as_bytes())?,
        ],
    )
}

fn typed_mask_of(object: &SchemaObject) -> Result<String, CodecError> {
    expect_schema(object, "FederationTypedMask")?;
    let prefix = match unsigned(object, "kind")? {
        MASK_ACCOUNT => "$a:",
        MASK_USER => "$u:",
        MASK_NICKNAME => "$n:",
        MASK_CLOAK => "$c:",
        _ => return Err(CodecError::UnknownDiscriminant),
    };
    let quiet = presence_of(object, "quiet")?;
    let value = text(object, "value")?;
    let mut mask = String::new();
    mask.try_reserve_exact(value.len().saturating_add(6))
        .map_err(|_| CodecError::AllocationFailed)?;
    if quiet {
        mask.push_str("$q:");
    }
    mask.push_str(prefix);
    mask.push_str(value);
    agenc_ircd_types::TypedMask::parse(&mask).map_err(|_| CodecError::CrossReference)?;
    Ok(mask)
}

pub(crate) fn mode_list_entry_object(
    entry: &ModeListEntryRecord,
) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationModeListEntry",
        vec![
            opaque(entry.channel_id.as_bytes())?,
            unsigned_value(u64::from(entry.mode_code)),
            opaque(entry.entry_id.as_bytes())?,
            WireValue::Structure(typed_mask_object(&entry.mask)?),
            WireValue::Structure(source_view_object(&entry.setter)?),
            unsigned_value(entry.created_at.get()),
            unsigned_value(entry.expires_at.map_or(0, UtcSecond::get)),
        ],
    )
}

pub(crate) fn mode_list_entry_of(object: &SchemaObject) -> Result<ModeListEntryRecord, CodecError> {
    expect_schema(object, "FederationModeListEntry")?;
    let expires = unsigned(object, "expires_at")?;
    Ok(ModeListEntryRecord {
        channel_id: ChannelInstanceId::from_bytes(fixed(object, "channel_instance_id")?),
        mode_code: unsigned_u16(object, "mode_code")?,
        entry_id: EntryId::from_bytes(fixed(object, "entry_id")?),
        mask: typed_mask_of(structure(object, "mask")?)?,
        setter: source_view_of(structure(object, "setter")?)?,
        created_at: utc_of(object, "created_at")?,
        expires_at: (expires != 0).then_some(UtcSecond::from_unix_seconds(expires)),
    })
}

/// Encodes one projected mode change as `FederationProjectedModeChange`.
/// List and prefix changes carry their nested object as the argument.
pub(crate) fn projected_mode_change_object(
    change: &ProjectedModeChange,
) -> Result<SchemaObject, CodecError> {
    let argument = match change {
        ProjectedModeChange::List { entry, .. } => mode_list_entry_object(entry)?
            .encode_canonical()?
            .as_slice()
            .to_vec(),
        ProjectedModeChange::Key { present, .. } => vec![u8::from(*present)],
        ProjectedModeChange::Limit { limit, .. } => limit.to_be_bytes().to_vec(),
        ProjectedModeChange::Simple { .. } => Vec::new(),
        ProjectedModeChange::Prefix { view, .. } => membership_view_object(view)?
            .encode_canonical()?
            .as_slice()
            .to_vec(),
    };
    SchemaObject::new(
        "FederationProjectedModeChange",
        vec![
            unsigned_value(direction_value(change.direction())),
            unsigned_value(u64::from(change.mode_code())),
            opaque(&argument)?,
        ],
    )
}

pub(crate) fn projected_mode_change_of(
    object: &SchemaObject,
    budget: &mut agenc_ircd_federation_wire::DecodeBudget,
) -> Result<ProjectedModeChange, CodecError> {
    expect_schema(object, "FederationProjectedModeChange")?;
    let direction = direction_of_value(unsigned(object, "direction")?)
        .ok_or(CodecError::UnknownDiscriminant)?;
    let mode_code = unsigned_u16(object, "mode_code")?;
    let argument = opaque_field(object, "argument")?;
    let change = match mode_code {
        1..=3 => ProjectedModeChange::List {
            direction,
            entry: mode_list_entry_of(&SchemaObject::decode_exact(
                "FederationModeListEntry",
                argument,
                budget,
            )?)?,
        },
        4 => ProjectedModeChange::Key {
            direction,
            present: match argument {
                [0] => false,
                [1] => true,
                _ => return Err(CodecError::CrossReference),
            },
        },
        5 => ProjectedModeChange::Limit {
            direction,
            limit: u32::from_be_bytes(
                argument
                    .try_into()
                    .map_err(|_| CodecError::CrossReference)?,
            ),
        },
        6..=11 => {
            if !argument.is_empty() {
                return Err(CodecError::CrossReference);
            }
            ProjectedModeChange::Simple {
                direction,
                mode_code,
            }
        }
        12..=16 => ProjectedModeChange::Prefix {
            direction,
            mode_code,
            view: membership_view_of(&SchemaObject::decode_exact(
                "FederationMembershipView",
                argument,
                budget,
            )?)?,
        },
        _ => return Err(CodecError::UnknownDiscriminant),
    };
    Ok(change)
}

const fn message_kind_value(kind: MessageKind) -> u64 {
    match kind {
        MessageKind::Privmsg => 1,
        MessageKind::Notice => 2,
        MessageKind::Tagmsg => 3,
    }
}

pub(crate) const fn message_kind_of_value(value: u64) -> Option<MessageKind> {
    match value {
        1 => Some(MessageKind::Privmsg),
        2 => Some(MessageKind::Notice),
        3 => Some(MessageKind::Tagmsg),
        _ => None,
    }
}

pub(crate) fn client_tag_object(key: &str, value: &str) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(
        "FederationClientTag",
        vec![opaque(key.as_bytes())?, opaque(value.as_bytes())?],
    )
}

pub(crate) fn client_tags_of(
    objects: &[SchemaObject],
) -> Result<Vec<(String, String)>, CodecError> {
    let mut tags = Vec::new();
    tags.try_reserve_exact(objects.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for object in objects {
        expect_schema(object, "FederationClientTag")?;
        tags.push((owned_text(object, "key")?, owned_text(object, "value")?));
    }
    Ok(tags)
}

pub(crate) fn delivered_message_object(
    record: &DeliveredMessageRecord,
) -> Result<SchemaObject, CodecError> {
    let (target_kind, target_id): (u64, &[u8]) = match &record.target {
        DeliveryTarget::Channel(channel) => (TARGET_CHANNEL, channel.as_bytes()),
        DeliveryTarget::User(user) => (TARGET_USER, user.as_bytes()),
    };
    let mut tags = Vec::new();
    tags.try_reserve_exact(record.tags.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for (key, value) in &record.tags {
        tags.push(client_tag_object(key, value)?);
    }
    SchemaObject::new(
        "FederationDeliveredMessage",
        vec![
            opaque(record.message_id.as_bytes())?,
            unsigned_value(message_kind_value(record.kind)),
            unsigned_value(target_kind),
            opaque(target_id)?,
            WireValue::Structure(source_view_object(&record.sender)?),
            unsigned_value(record.target_revision.get()),
            unsigned_value(record.channel_event_sequence),
            unsigned_value(record.received_unix_milliseconds),
            WireValue::Vector(tags),
            opaque(record.body.as_bytes())?,
        ],
    )
}

pub(crate) fn delivered_message_of(
    object: &SchemaObject,
) -> Result<DeliveredMessageRecord, CodecError> {
    expect_schema(object, "FederationDeliveredMessage")?;
    let target_id: [u8; 16] = fixed(object, "target_id")?;
    let target = match unsigned(object, "target_kind")? {
        TARGET_CHANNEL => DeliveryTarget::Channel(ChannelInstanceId::from_bytes(target_id)),
        TARGET_USER => DeliveryTarget::User(UserId::from_bytes(target_id)),
        _ => return Err(CodecError::UnknownDiscriminant),
    };
    Ok(DeliveredMessageRecord {
        message_id: MessageId::from_bytes(fixed(object, "message_id")?),
        kind: message_kind_of_value(unsigned(object, "message_kind")?)
            .ok_or(CodecError::UnknownDiscriminant)?,
        target,
        sender: source_view_of(structure(object, "sender")?)?,
        target_revision: revision_of(object, "target_revision")?,
        channel_event_sequence: unsigned(object, "channel_event_sequence")?,
        received_unix_milliseconds: unsigned(object, "received_unix_milliseconds")?,
        tags: client_tags_of(vector(object, "tags")?)?,
        body: owned_text(object, "body")?,
    })
}

#[cfg(test)]
mod tests {
    mod round_trip;
}
