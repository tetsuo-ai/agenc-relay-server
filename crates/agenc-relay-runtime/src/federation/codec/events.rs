//! `event.<kind>` arm objects for every projected event (spec 20.6, B.5).

use agenc_relay_domain::DisplayNameValue;
use agenc_relay_domain::federation::{
    ActorView, InviteRecord, InviteRemovalKind, ProjectedEvent, ProjectedModeChange,
    SessionHideKind,
};
use agenc_relay_federation_wire::access::{
    expect_schema, fixed, opaque, opaque_field, optional_fixed, projection_union, structure,
    unsigned, unsigned_u16, vector,
};
use agenc_relay_federation_wire::{
    CodecError, DecodeBudget, SchemaObject, WireValue, event_schema_name,
};
use agenc_relay_types::{ChannelInstanceId, FederationEventKind, InviteId, MessageId, Revision};

use super::{
    account_projection_object, account_projection_of, actor_view_object, actor_view_of,
    channel_detail_object, channel_detail_of, delivered_message_object, delivered_message_of,
    encoded_or_empty, invite_projection_object, invite_projection_of, membership_view_object,
    membership_view_of, nickname_object, nickname_of, owned_text, presence, presence_of,
    projected_mode_change_object, projected_mode_change_of, revision_of, session_event_view_object,
    session_event_view_of, session_projection_object, session_projection_of, source_view_object,
    source_view_of, unsigned_value,
};

const PROJECTION_SESSION: u16 = 1;
const PROJECTION_CHANNEL_DETAIL: u16 = 3;
const PROJECTION_ACCOUNT: u16 = 7;

fn id_value(bytes: &[u8]) -> Result<WireValue, CodecError> {
    opaque(bytes)
}

fn revision_value(revision: Option<Revision>) -> WireValue {
    unsigned_value(revision.map_or(0, Revision::get))
}

fn optional_revision(object: &SchemaObject, name: &str) -> Result<Option<Revision>, CodecError> {
    match unsigned(object, name)? {
        0 => Ok(None),
        value => Revision::new(value)
            .map(Some)
            .map_err(|_| CodecError::IntegerOutOfRange),
    }
}

fn union(discriminant: u16, value: SchemaObject) -> WireValue {
    WireValue::ProjectionUnion {
        discriminant,
        value,
    }
}

fn arm(kind: FederationEventKind, fields: Vec<WireValue>) -> Result<SchemaObject, CodecError> {
    SchemaObject::new(event_schema_name(kind), fields)
}

/// Encodes one projected event as its `event.<kind>` arm.
// agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match maps every projected event arm onto its schema fields
pub(crate) fn event_arm_object(event: &ProjectedEvent) -> Result<SchemaObject, CodecError> {
    let kind = event.kind();
    match event {
        ProjectedEvent::SessionVisible(view) | ProjectedEvent::AccountLabelChanged(view) => arm(
            kind,
            vec![WireValue::Structure(session_event_view_object(view)?)],
        ),
        ProjectedEvent::SessionHidden {
            source,
            last_revision,
            kind: hide_kind,
            channels,
            reason,
        } => {
            let mut departed = Vec::new();
            departed
                .try_reserve_exact(channels.len())
                .map_err(|_| CodecError::AllocationFailed)?;
            for (channel_id, revision) in channels {
                departed.push(SchemaObject::new(
                    "FederationDepartedChannel",
                    vec![
                        id_value(channel_id.as_bytes())?,
                        unsigned_value(revision.get()),
                    ],
                )?);
            }
            arm(
                kind,
                vec![
                    WireValue::Structure(source_view_object(source)?),
                    unsigned_value(last_revision.get()),
                    unsigned_value(u64::from(hide_kind.wire_value())),
                    WireValue::Vector(departed),
                    opaque(reason.as_bytes())?,
                ],
            )
        }
        ProjectedEvent::NicknameChanged { old_nickname, view } => arm(
            kind,
            vec![
                WireValue::Structure(nickname_object(old_nickname)?),
                WireValue::Structure(session_event_view_object(view)?),
            ],
        ),
        ProjectedEvent::ChannelVisible(detail) | ProjectedEvent::ChannelPolicyChanged(detail) => {
            arm(
                kind,
                vec![union(
                    PROJECTION_CHANNEL_DETAIL,
                    channel_detail_object(detail)?,
                )],
            )
        }
        ProjectedEvent::ChannelHidden {
            channel_id,
            last_revision,
        } => arm(
            kind,
            vec![
                id_value(channel_id.as_bytes())?,
                unsigned_value(last_revision.get()),
            ],
        ),
        ProjectedEvent::MemberJoined {
            view,
            home_session_revision,
            display_name,
        } => arm(
            kind,
            vec![
                WireValue::Structure(membership_view_object(view)?),
                revision_value(*home_session_revision),
                opaque(display_name.as_str().as_bytes())?,
            ],
        ),
        ProjectedEvent::MemberParted {
            channel_id,
            source,
            resulting_revision,
            home_session_revision,
            reason,
        } => arm(
            kind,
            vec![
                id_value(channel_id.as_bytes())?,
                WireValue::Structure(source_view_object(source)?),
                unsigned_value(resulting_revision.get()),
                revision_value(*home_session_revision),
                opaque(reason.as_bytes())?,
            ],
        ),
        ProjectedEvent::ChannelModesChanged {
            channel_id,
            resulting_revision,
            actor,
            changes,
        } => {
            let mut encoded = Vec::new();
            encoded
                .try_reserve_exact(changes.len())
                .map_err(|_| CodecError::AllocationFailed)?;
            for change in changes {
                encoded.push(projected_mode_change_object(change)?);
            }
            arm(
                kind,
                vec![
                    id_value(channel_id.as_bytes())?,
                    unsigned_value(resulting_revision.get()),
                    WireValue::Structure(actor_view_object(actor)?),
                    WireValue::Vector(encoded),
                ],
            )
        }
        ProjectedEvent::TopicChanged {
            channel_id,
            resulting_revision,
            actor,
            topic,
        } => {
            let actor = ActorView(Some(actor.clone()));
            let (text, set_at, message_id): (&str, u64, &[u8]) = match topic {
                Some((text, set_at, message_id)) => (text, set_at.get(), message_id.as_bytes()),
                None => ("", 0, &[]),
            };
            arm(
                kind,
                vec![
                    id_value(channel_id.as_bytes())?,
                    unsigned_value(resulting_revision.get()),
                    WireValue::Structure(actor_view_object(&actor)?),
                    presence(topic.is_some()),
                    opaque(text.as_bytes())?,
                    unsigned_value(set_at),
                    opaque(message_id)?,
                ],
            )
        }
        ProjectedEvent::Invited {
            channel_id,
            invite_id,
            resulting_revision,
            local_projection,
            inviter,
            named_target,
        } => {
            let projection = local_projection
                .as_ref()
                .map(invite_projection_object)
                .transpose()?;
            let view = SchemaObject::new(
                "FederationInviteEventView",
                vec![
                    id_value(channel_id.as_bytes())?,
                    id_value(invite_id.as_bytes())?,
                    unsigned_value(resulting_revision.get()),
                    encoded_or_empty(projection.as_ref())?,
                    WireValue::Structure(source_view_object(inviter)?),
                    WireValue::Structure(source_view_object(named_target)?),
                ],
            )?;
            arm(kind, vec![WireValue::Structure(view)])
        }
        ProjectedEvent::InviteRemoved {
            channel_id,
            invite_id,
            resulting_revision,
            kind: removal,
        } => arm(
            kind,
            vec![
                id_value(channel_id.as_bytes())?,
                id_value(invite_id.as_bytes())?,
                unsigned_value(resulting_revision.get()),
                unsigned_value(u64::from(removal.wire_value())),
            ],
        ),
        ProjectedEvent::Kicked {
            channel_id,
            actor,
            target,
            resulting_revision,
            target_home_session_revision,
            reason,
        } => arm(
            kind,
            vec![
                id_value(channel_id.as_bytes())?,
                WireValue::Structure(actor_view_object(actor)?),
                WireValue::Structure(source_view_object(target)?),
                unsigned_value(resulting_revision.get()),
                revision_value(*target_home_session_revision),
                opaque(reason.as_bytes())?,
            ],
        ),
        ProjectedEvent::AwayChanged { view, away } => arm(
            kind,
            vec![
                WireValue::Structure(session_event_view_object(view)?),
                presence(away.is_some()),
                opaque(away.as_deref().unwrap_or("").as_bytes())?,
            ],
        ),
        ProjectedEvent::DisplayNameChanged { view, display_name } => arm(
            kind,
            vec![
                WireValue::Structure(session_event_view_object(view)?),
                opaque(display_name.as_str().as_bytes())?,
            ],
        ),
        ProjectedEvent::MessageDelivered(record) => arm(
            kind,
            vec![WireValue::Structure(delivered_message_object(record)?)],
        ),
        ProjectedEvent::ChannelDestroyed {
            channel_id,
            final_revision,
        } => arm(
            kind,
            vec![
                id_value(channel_id.as_bytes())?,
                unsigned_value(final_revision.get()),
            ],
        ),
        ProjectedEvent::NetworkNotice { code, text } => arm(
            kind,
            vec![opaque(code.as_bytes())?, opaque(text.as_bytes())?],
        ),
        ProjectedEvent::UserModesChanged(record) => arm(
            kind,
            vec![union(
                PROJECTION_SESSION,
                session_projection_object(record)?,
            )],
        ),
        ProjectedEvent::ChannelMembershipsRecomputed {
            channel_id,
            resulting_revision,
            actor,
            memberships,
        } => {
            let mut encoded = Vec::new();
            encoded
                .try_reserve_exact(memberships.len())
                .map_err(|_| CodecError::AllocationFailed)?;
            for view in memberships {
                encoded.push(membership_view_object(view)?);
            }
            arm(
                kind,
                vec![
                    id_value(channel_id.as_bytes())?,
                    unsigned_value(resulting_revision.get()),
                    WireValue::Structure(actor_view_object(actor)?),
                    WireValue::Vector(encoded),
                ],
            )
        }
        ProjectedEvent::AccountStateChanged(record) => arm(
            kind,
            vec![union(
                PROJECTION_ACCOUNT,
                account_projection_object(record)?,
            )],
        ),
        ProjectedEvent::RequestCompleted {
            resulting_state_generation,
        } => arm(kind, vec![unsigned_value(*resulting_state_generation)]),
    }
}

fn channel_of(object: &SchemaObject) -> Result<ChannelInstanceId, CodecError> {
    Ok(ChannelInstanceId::from_bytes(fixed(
        object,
        "channel_instance_id",
    )?))
}

fn union_of(object: &SchemaObject, expected: u16) -> Result<&SchemaObject, CodecError> {
    let (discriminant, value) = projection_union(object, "projection")?;
    if discriminant != expected {
        return Err(CodecError::CrossReference);
    }
    Ok(value)
}

fn mode_changes_of(
    object: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<Vec<ProjectedModeChange>, CodecError> {
    let items = vector(object, "changes")?;
    let mut changes = Vec::new();
    changes
        .try_reserve_exact(items.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for item in items {
        changes.push(projected_mode_change_of(item, budget)?);
    }
    Ok(changes)
}

fn invited_of(
    object: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<ProjectedEvent, CodecError> {
    let view = structure(object, "invite")?;
    expect_schema(view, "FederationInviteEventView")?;
    let channel_id = channel_of(view)?;
    let invite_id = InviteId::from_bytes(fixed(view, "invite_id")?);
    let encoded = opaque_field(view, "local_invite_projection")?;
    let local_projection: Option<InviteRecord> = if encoded.is_empty() {
        None
    } else {
        let nested = SchemaObject::decode_exact("FederationInviteProjection", encoded, budget)?;
        let record = invite_projection_of(&nested)?;
        if record.channel_id != channel_id || record.invite_id != invite_id {
            return Err(CodecError::CrossReference);
        }
        Some(record)
    };
    Ok(ProjectedEvent::Invited {
        channel_id,
        invite_id,
        resulting_revision: revision_of(view, "resulting_revision")?,
        local_projection,
        inviter: source_view_of(structure(view, "inviter")?)?,
        named_target: source_view_of(structure(view, "named_target")?)?,
    })
}

fn topic_of(
    object: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<ProjectedEvent, CodecError> {
    let ActorView(Some(actor)) = actor_view_of(structure(object, "actor")?, budget)? else {
        return Err(CodecError::CrossReference);
    };
    let present = presence_of(object, "topic_presence")?;
    let message_id: Option<[u8; 16]> = optional_fixed(object, "message_id")?;
    let set_at = unsigned(object, "set_at")?;
    let topic = if present {
        Some((
            owned_text(object, "topic")?,
            agenc_relay_types::UtcSecond::from_unix_seconds(set_at),
            MessageId::from_bytes(message_id.ok_or(CodecError::CrossReference)?),
        ))
    } else {
        if message_id.is_some() || set_at != 0 || !opaque_field(object, "topic")?.is_empty() {
            return Err(CodecError::CrossReference);
        }
        None
    };
    Ok(ProjectedEvent::TopicChanged {
        channel_id: channel_of(object)?,
        resulting_revision: revision_of(object, "resulting_revision")?,
        actor,
        topic,
    })
}

fn session_hidden_of(object: &SchemaObject) -> Result<ProjectedEvent, CodecError> {
    let items = vector(object, "channels")?;
    let mut channels = Vec::new();
    channels
        .try_reserve_exact(items.len())
        .map_err(|_| CodecError::AllocationFailed)?;
    for item in items {
        expect_schema(item, "FederationDepartedChannel")?;
        channels.push((channel_of(item)?, revision_of(item, "resulting_revision")?));
    }
    Ok(ProjectedEvent::SessionHidden {
        source: source_view_of(structure(object, "source")?)?,
        last_revision: revision_of(object, "last_revision")?,
        kind: SessionHideKind::from_wire(unsigned_u16(object, "hide_kind")?)
            .ok_or(CodecError::UnknownDiscriminant)?,
        channels,
        reason: owned_text(object, "reason")?,
    })
}

/// Decodes one `event.<kind>` arm back into a projected event.
// agenc-review: focus owner=runtime reviewed=2026-09-02 reason=one closed match decodes every event arm and checks each cross-field rule in place
pub(crate) fn projected_event_of(
    kind: FederationEventKind,
    object: &SchemaObject,
    budget: &mut DecodeBudget,
) -> Result<ProjectedEvent, CodecError> {
    expect_schema(object, event_schema_name(kind))?;
    let event = match kind {
        FederationEventKind::SessionVisible => ProjectedEvent::SessionVisible(
            session_event_view_of(structure(object, "session")?, budget)?,
        ),
        FederationEventKind::AccountLabelChanged => ProjectedEvent::AccountLabelChanged(
            session_event_view_of(structure(object, "session")?, budget)?,
        ),
        FederationEventKind::SessionHidden => session_hidden_of(object)?,
        FederationEventKind::NicknameChanged => ProjectedEvent::NicknameChanged {
            old_nickname: nickname_of(structure(object, "old_nickname")?)?,
            view: session_event_view_of(structure(object, "session")?, budget)?,
        },
        FederationEventKind::ChannelVisible => ProjectedEvent::ChannelVisible(channel_detail_of(
            union_of(object, PROJECTION_CHANNEL_DETAIL)?,
        )?),
        FederationEventKind::ChannelPolicyChanged => ProjectedEvent::ChannelPolicyChanged(
            channel_detail_of(union_of(object, PROJECTION_CHANNEL_DETAIL)?)?,
        ),
        FederationEventKind::ChannelHidden => ProjectedEvent::ChannelHidden {
            channel_id: channel_of(object)?,
            last_revision: revision_of(object, "last_revision")?,
        },
        FederationEventKind::MemberJoined => ProjectedEvent::MemberJoined {
            view: membership_view_of(structure(object, "membership")?)?,
            home_session_revision: optional_revision(object, "resulting_home_session_revision")?,
            display_name: DisplayNameValue::prepare(super::text(object, "display_name")?)
                .map_err(|_| CodecError::CrossReference)?,
        },
        FederationEventKind::MemberParted => ProjectedEvent::MemberParted {
            channel_id: channel_of(object)?,
            source: source_view_of(structure(object, "source")?)?,
            resulting_revision: revision_of(object, "resulting_revision")?,
            home_session_revision: optional_revision(object, "resulting_home_session_revision")?,
            reason: owned_text(object, "reason")?,
        },
        FederationEventKind::ChannelModesChanged => ProjectedEvent::ChannelModesChanged {
            channel_id: channel_of(object)?,
            resulting_revision: revision_of(object, "resulting_revision")?,
            actor: actor_view_of(structure(object, "actor")?, budget)?,
            changes: mode_changes_of(object, budget)?,
        },
        FederationEventKind::TopicChanged => topic_of(object, budget)?,
        FederationEventKind::Invited => invited_of(object, budget)?,
        FederationEventKind::InviteRemoved => ProjectedEvent::InviteRemoved {
            channel_id: channel_of(object)?,
            invite_id: InviteId::from_bytes(fixed(object, "invite_id")?),
            resulting_revision: revision_of(object, "resulting_revision")?,
            kind: InviteRemovalKind::from_wire(unsigned_u16(object, "removal_kind")?)
                .ok_or(CodecError::UnknownDiscriminant)?,
        },
        FederationEventKind::Kicked => ProjectedEvent::Kicked {
            channel_id: channel_of(object)?,
            actor: actor_view_of(structure(object, "actor")?, budget)?,
            target: source_view_of(structure(object, "target")?)?,
            resulting_revision: revision_of(object, "resulting_revision")?,
            target_home_session_revision: optional_revision(
                object,
                "target_home_session_revision",
            )?,
            reason: owned_text(object, "reason")?,
        },
        FederationEventKind::AwayChanged => {
            let present = presence_of(object, "away_kind")?;
            let text = owned_text(object, "away_text")?;
            if !present && !text.is_empty() {
                return Err(CodecError::CrossReference);
            }
            ProjectedEvent::AwayChanged {
                view: session_event_view_of(structure(object, "session")?, budget)?,
                away: present.then_some(text),
            }
        }
        FederationEventKind::DisplayNameChanged => ProjectedEvent::DisplayNameChanged {
            view: session_event_view_of(structure(object, "session")?, budget)?,
            display_name: DisplayNameValue::prepare(super::text(object, "display_name")?)
                .map_err(|_| CodecError::CrossReference)?,
        },
        FederationEventKind::MessageDelivered => {
            ProjectedEvent::MessageDelivered(delivered_message_of(structure(object, "message")?)?)
        }
        FederationEventKind::ChannelDestroyed => ProjectedEvent::ChannelDestroyed {
            channel_id: channel_of(object)?,
            final_revision: revision_of(object, "final_revision")?,
        },
        FederationEventKind::NetworkNotice => ProjectedEvent::NetworkNotice {
            code: owned_text(object, "code")?,
            text: owned_text(object, "safe_text")?,
        },
        FederationEventKind::UserModesChanged => ProjectedEvent::UserModesChanged(
            session_projection_of(union_of(object, PROJECTION_SESSION)?)?,
        ),
        FederationEventKind::ChannelMembershipsRecomputed => {
            let items = vector(object, "memberships")?;
            let mut memberships = Vec::new();
            memberships
                .try_reserve_exact(items.len())
                .map_err(|_| CodecError::AllocationFailed)?;
            for item in items {
                memberships.push(membership_view_of(item)?);
            }
            ProjectedEvent::ChannelMembershipsRecomputed {
                channel_id: channel_of(object)?,
                resulting_revision: revision_of(object, "resulting_revision")?,
                actor: actor_view_of(structure(object, "actor")?, budget)?,
                memberships,
            }
        }
        FederationEventKind::AccountStateChanged => ProjectedEvent::AccountStateChanged(
            account_projection_of(union_of(object, PROJECTION_ACCOUNT)?)?,
        ),
        FederationEventKind::RequestCompleted => ProjectedEvent::RequestCompleted {
            resulting_state_generation: unsigned(object, "resulting_state_generation")?,
        },
    };
    Ok(event)
}
