//! Privacy-filtered rendering for read-only registered commands.

use std::collections::BTreeSet;
use std::mem::size_of;

use agenc_ircd_client_wire::{WireMessage, numeric_reply};
use agenc_ircd_domain::{
    CanonicalCommandView, ChannelListProjection, ChannelProjection, DomainState, InformationQuery,
    MaskList, ModeCommand, PresenceCommand, ProjectionDecision, QueryPlan, Role, SessionProjection,
    TopicProjection, UserQuery, Visibility, WhoTarget,
};
use agenc_ircd_types::{ChannelInstanceId, MaskSubject, TypedMask, UserId};

use crate::RuntimeError;
use crate::client_render::ReplyInput;
use crate::state_core::StateCoreContext;

const NAMES_CHUNK_BYTES: usize = 8_000;
const WEAK_MASK_NOTICE: &str = "Nickname and cloak masks are weak, reconnectable rules";

/// Returns whether one mask can be bypassed by reconnecting under a new
/// nickname or cloak.
pub(crate) const fn is_reconnectable_mask(mask: &TypedMask) -> bool {
    matches!(
        mask.subject(),
        MaskSubject::Nickname(_) | MaskSubject::Cloak(_)
    )
}

/// Builds the one fixed warning shown before a reconnectable mask is exposed.
pub(crate) fn weak_mask_notice(prefix: &str, target: &str) -> Result<WireMessage, RuntimeError> {
    WireMessage::new(prefix, "NOTICE", &[target], Some(WEAK_MASK_NOTICE))
        .map_err(|_| RuntimeError::InvalidValue)
}

pub(crate) fn render_query(
    context: &mut StateCoreContext,
    reply: ReplyInput<'_>,
    plan: &QueryPlan,
) -> Result<(), RuntimeError> {
    if plan.requester() != reply.requester
        || plan.expected_revision() != context.domain().revision()
    {
        return Err(RuntimeError::InvalidValue);
    }
    let nickname = crate::client_render::requester_nickname(context, reply.requester);
    if let CanonicalCommandView::List(channels) = plan.command().view() {
        return render_list_snapshot(context, reply, &nickname, channels);
    }
    if let CanonicalCommandView::UserQuery(UserQuery::Who(target)) = plan.command().view() {
        return render_who_snapshot(context, reply, &nickname, target.as_ref());
    }
    let frames = render_non_snapshot_query(context, reply, plan, &nickname)?;
    crate::client_render::send_logical(
        context,
        reply.generation,
        reply.capabilities,
        reply.request,
        frames,
    )
}

fn render_non_snapshot_query(
    context: &StateCoreContext,
    reply: ReplyInput<'_>,
    plan: &QueryPlan,
    nickname: &str,
) -> Result<Vec<WireMessage>, RuntimeError> {
    match plan.command().view() {
        CanonicalCommandView::Mode(mode) => render_mode(
            context.domain(),
            context.server_prefix(),
            nickname,
            reply.requester,
            mode,
        ),
        CanonicalCommandView::TopicQuery(channel) => render_topic(
            context.domain(),
            context.server_prefix(),
            nickname,
            reply.requester,
            channel,
        ),
        CanonicalCommandView::Names(channels) => render_names(
            context.domain(),
            context.server_prefix(),
            nickname,
            reply.requester,
            reply.capabilities.enabled("userhost-in-names"),
            channels,
        ),
        CanonicalCommandView::Information(query) => render_information(context, nickname, query),
        CanonicalCommandView::UserQuery(query) => render_user_query(
            context.domain(),
            context.server_prefix(),
            nickname,
            reply.requester,
            query,
        ),
        CanonicalCommandView::Presence(query) => render_presence_query(
            context.domain(),
            context.server_prefix(),
            nickname,
            reply.requester,
            query,
        ),
        CanonicalCommandView::Chathistory(_, _) => Ok(Vec::new()),
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn snapshot_backing_bytes<Row>(rows: usize) -> Result<usize, RuntimeError> {
    rows.checked_mul(size_of::<Row>())
        .ok_or(RuntimeError::Overflow)
}

struct WhoSnapshotRow<'a> {
    session: SessionProjection<'a>,
    role: Option<char>,
}

fn render_list_snapshot(
    context: &mut StateCoreContext,
    reply: ReplyInput<'_>,
    nickname: &str,
    selected: &[agenc_ircd_domain::ChannelNameValue],
) -> Result<(), RuntimeError> {
    let max_rows = context.domain().channel_count().min(200);
    let max_backing = snapshot_backing_bytes::<ChannelListProjection<'static>>(max_rows)?;
    let prepared = context.prepare_query_snapshot(reply.generation, max_rows, max_backing)?;
    let (frames, rows, backing) = {
        let projections = context
            .domain()
            .project_channel_list()
            .map_err(|_| RuntimeError::InvalidValue)?;
        let backing = snapshot_backing_bytes::<ChannelListProjection<'static>>(projections.len())?;
        let mut frames = Vec::new();
        push_numeric(
            &mut frames,
            context.server_prefix(),
            321,
            nickname,
            &["Channel"],
            "Users Name",
        )?;
        let mut rows = 0_usize;
        for channel in &projections {
            if !selected.is_empty() && !selected.iter().any(|name| name == channel.name()) {
                continue;
            }
            rows = rows.checked_add(1).ok_or(RuntimeError::Overflow)?;
            render_list_row(context.server_prefix(), nickname, channel, &mut frames)?;
        }
        push_numeric(
            &mut frames,
            context.server_prefix(),
            323,
            nickname,
            &[],
            "End of LIST",
        )?;
        (frames, rows, backing)
    };
    let snapshot = prepared.finish(rows, backing)?;
    crate::client_render::send_logical_query(
        context,
        reply.generation,
        reply.capabilities,
        reply.request,
        frames,
        snapshot,
    )
}

fn render_who_snapshot(
    context: &mut StateCoreContext,
    reply: ReplyInput<'_>,
    nickname: &str,
    target: Option<&WhoTarget>,
) -> Result<(), RuntimeError> {
    let (frames, snapshot) = match target {
        None => snapshot_who_self(context, reply.generation, nickname, reply.requester)?,
        Some(WhoTarget::Nickname(target)) => {
            snapshot_who_nickname(context, reply.generation, nickname, reply.requester, target)?
        }
        Some(WhoTarget::Channel(target)) => {
            snapshot_who_channel(context, reply.generation, nickname, reply.requester, target)?
        }
    };
    crate::client_render::send_logical_query(
        context,
        reply.generation,
        reply.capabilities,
        reply.request,
        frames,
        snapshot,
    )
}

fn snapshot_who_self(
    context: &StateCoreContext,
    generation: crate::connection::ConnectionGeneration,
    nickname: &str,
    requester: UserId,
) -> Result<
    (
        Vec<WireMessage>,
        crate::connection::sink::QuerySnapshotPermit,
    ),
    RuntimeError,
> {
    let backing = snapshot_backing_bytes::<SessionProjection<'static>>(1)?;
    let prepared = context.prepare_query_snapshot(generation, 1, backing)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(1)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    if let ProjectionDecision::Visible(session) =
        context.domain().project_session(requester, requester)
    {
        rows.push(session);
    }
    let mut frames = Vec::new();
    for session in &rows {
        render_who_session(
            context.server_prefix(),
            nickname,
            "*",
            session,
            None,
            &mut frames,
        )?;
    }
    push_numeric(
        &mut frames,
        context.server_prefix(),
        315,
        nickname,
        &[nickname],
        "End of WHO list",
    )?;
    let snapshot = prepared.finish(rows.len(), backing)?;
    Ok((frames, snapshot))
}

fn snapshot_who_nickname(
    context: &StateCoreContext,
    generation: crate::connection::ConnectionGeneration,
    nickname: &str,
    requester: UserId,
    target: &agenc_ircd_domain::NicknameValue,
) -> Result<
    (
        Vec<WireMessage>,
        crate::connection::sink::QuerySnapshotPermit,
    ),
    RuntimeError,
> {
    let backing = snapshot_backing_bytes::<SessionProjection<'static>>(1)?;
    let prepared = context.prepare_query_snapshot(generation, 1, backing)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(1)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    if let Some(user_id) = context.domain().resolve_nickname(target)
        && let ProjectionDecision::Visible(session) =
            context.domain().project_session(requester, user_id)
    {
        rows.push(session);
    }
    let mut frames = Vec::new();
    for session in &rows {
        render_who_session(
            context.server_prefix(),
            nickname,
            "*",
            session,
            None,
            &mut frames,
        )?;
    }
    push_numeric(
        &mut frames,
        context.server_prefix(),
        315,
        nickname,
        &[target.presentation()],
        "End of WHO list",
    )?;
    let snapshot = prepared.finish(rows.len(), backing)?;
    Ok((frames, snapshot))
}

fn snapshot_who_channel(
    context: &StateCoreContext,
    generation: crate::connection::ConnectionGeneration,
    nickname: &str,
    requester: UserId,
    target: &agenc_ircd_domain::ChannelNameValue,
) -> Result<
    (
        Vec<WireMessage>,
        crate::connection::sink::QuerySnapshotPermit,
    ),
    RuntimeError,
> {
    // An unknown, unlisted, or secret channel takes the same path as an empty
    // one: only the terminator is sent (spec 13.5, STA-10).
    let channel = visible_channel(context.domain(), requester, target).ok();
    let row_count = channel.map_or(0, |channel| {
        channel
            .members()
            .filter(|user_id| {
                matches!(
                    context.domain().project_session(requester, *user_id),
                    ProjectionDecision::Visible(_)
                )
            })
            .count()
    });
    let backing = snapshot_backing_bytes::<WhoSnapshotRow<'static>>(row_count)?;
    let prepared = context.prepare_query_snapshot(generation, row_count, backing)?;
    let mut rows = Vec::new();
    rows.try_reserve_exact(row_count)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for user_id in channel.into_iter().flat_map(|channel| channel.members()) {
        let ProjectionDecision::Visible(session) =
            context.domain().project_session(requester, user_id)
        else {
            continue;
        };
        let role = channel
            .and_then(|channel| channel.role_of(user_id))
            .ok_or(RuntimeError::InvalidValue)?;
        rows.push(WhoSnapshotRow {
            session,
            role: role_prefix(role),
        });
    }
    if rows.len() != row_count {
        return Err(RuntimeError::InvalidValue);
    }
    let mut frames = Vec::new();
    for row in &rows {
        render_who_session(
            context.server_prefix(),
            nickname,
            target.presentation(),
            &row.session,
            row.role,
            &mut frames,
        )?;
    }
    push_numeric(
        &mut frames,
        context.server_prefix(),
        315,
        nickname,
        &[target.presentation()],
        "End of WHO list",
    )?;
    let snapshot = prepared.finish(rows.len(), backing)?;
    Ok((frames, snapshot))
}

fn render_information(
    context: &StateCoreContext,
    nickname: &str,
    query: InformationQuery,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let prefix = context.server_prefix();
    match query {
        InformationQuery::Motd => render_motd(context, nickname),
        InformationQuery::Lusers => render_lusers(context.domain(), prefix, nickname),
        InformationQuery::Version => info_lines(
            prefix,
            nickname,
            &[concat!("agenc-ircd-", env!("CARGO_PKG_VERSION"))],
        ),
        InformationQuery::Time => {
            let seconds = context
                .utc_now()
                .map_err(|_| RuntimeError::InvalidValue)?
                .get()
                .to_string();
            one_numeric(prefix, 391, nickname, &[prefix], &seconds)
        }
        InformationQuery::Admin => public_info_lines(
            context,
            nickname,
            &["AgenC network administration is available out of band"],
        ),
        InformationQuery::Info => public_info_lines(
            context,
            nickname,
            &["AgenC IRC daemon", "Privacy-preserving federated chat"],
        ),
        InformationQuery::Links => info_lines(
            prefix,
            nickname,
            &["Server topology is not publicly exposed"],
        ),
    }
}

fn render_motd(
    context: &StateCoreContext,
    nickname: &str,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let prefix = context.server_prefix();
    let Some(motd) = context.motd() else {
        return one_numeric(prefix, 422, nickname, &[], "MOTD File is missing");
    };
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(
            crate::runtime_config::public_text_chunks(motd)
                .count()
                .saturating_add(2),
        )
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    push_numeric(
        &mut frames,
        prefix,
        375,
        nickname,
        &[],
        "Message of the day",
    )?;
    for line in crate::runtime_config::public_text_chunks(motd) {
        push_numeric(&mut frames, prefix, 372, nickname, &[], line)?;
    }
    push_numeric(&mut frames, prefix, 376, nickname, &[], "End of MOTD")?;
    Ok(frames)
}

fn public_info_lines(
    context: &StateCoreContext,
    nickname: &str,
    fallback: &[&str],
) -> Result<Vec<WireMessage>, RuntimeError> {
    let Some(public_info) = context.public_info() else {
        return info_lines(context.server_prefix(), nickname, fallback);
    };
    let prefix = context.server_prefix();
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(
            crate::runtime_config::public_text_chunks(public_info)
                .count()
                .saturating_add(1),
        )
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for line in crate::runtime_config::public_text_chunks(public_info) {
        push_numeric(&mut frames, prefix, 371, nickname, &[], line)?;
    }
    push_numeric(&mut frames, prefix, 374, nickname, &[], "End of INFO")?;
    Ok(frames)
}

fn render_lusers(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let users = domain.session_count().to_string();
    let channels = domain.channel_count().to_string();
    let summary = format!("There are {users} users on one server");
    let local = format!("Current local users {users}, max {users}");
    let mut frames = Vec::new();
    push_numeric(&mut frames, prefix, 251, nickname, &[], &summary)?;
    push_numeric(
        &mut frames,
        prefix,
        252,
        nickname,
        &["0"],
        "operator(s) online",
    )?;
    push_numeric(
        &mut frames,
        prefix,
        253,
        nickname,
        &["0"],
        "unknown connection(s)",
    )?;
    push_numeric(
        &mut frames,
        prefix,
        254,
        nickname,
        &[&channels],
        "channels formed",
    )?;
    push_numeric(&mut frames, prefix, 255, nickname, &[], &summary)?;
    push_numeric(
        &mut frames,
        prefix,
        265,
        nickname,
        &[&users, &users],
        &local,
    )?;
    push_numeric(
        &mut frames,
        prefix,
        266,
        nickname,
        &[&users, &users],
        &local,
    )?;
    Ok(frames)
}

fn info_lines(
    prefix: &str,
    nickname: &str,
    lines: &[&str],
) -> Result<Vec<WireMessage>, RuntimeError> {
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(lines.len().saturating_add(1))
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    for line in lines {
        push_numeric(&mut frames, prefix, 371, nickname, &[], line)?;
    }
    push_numeric(&mut frames, prefix, 374, nickname, &[], "End of INFO")?;
    Ok(frames)
}

fn render_mode(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    mode: &ModeCommand,
) -> Result<Vec<WireMessage>, RuntimeError> {
    match mode {
        ModeCommand::UserQuery(_) => {
            let session = domain
                .session(requester)
                .ok_or(RuntimeError::InvalidValue)?;
            let modes = if session.operator_notices() {
                "+iw"
            } else {
                "+i"
            };
            one_numeric_bare(prefix, 221, nickname, &[modes])
        }
        ModeCommand::ChannelQuery(name) => {
            let channel = visible_channel(domain, requester, name)?;
            render_channel_modes(prefix, nickname, channel)
        }
        ModeCommand::ChannelList(name, list) => {
            let channel = visible_channel(domain, requester, name)?;
            render_mask_list(prefix, nickname, channel, *list)
        }
        ModeCommand::UserOperatorNotices(_, _) | ModeCommand::ChannelChange(_, _) => {
            Err(RuntimeError::InvalidValue)
        }
    }
}

fn render_channel_modes(
    prefix: &str,
    nickname: &str,
    channel: &agenc_ircd_domain::ChannelState,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let modes = channel_mode_text(channel);
    let limit = channel.member_limit().map(|value| value.to_string());
    let middle = match limit.as_deref() {
        Some(limit) => vec![channel.name().presentation(), modes.as_str(), limit],
        None => vec![channel.name().presentation(), modes.as_str()],
    };
    let mut frames = Vec::new();
    push_numeric_bare(&mut frames, prefix, 324, nickname, &middle)?;
    let created = channel.created_at().get().to_string();
    push_numeric_bare(
        &mut frames,
        prefix,
        329,
        nickname,
        &[channel.name().presentation(), &created],
    )?;
    Ok(frames)
}

fn channel_mode_text(channel: &agenc_ircd_domain::ChannelState) -> String {
    let simple = channel.modes();
    let mut modes = String::from("+");
    if simple.invite_only {
        modes.push('i');
    }
    if simple.moderated {
        modes.push('m');
    }
    modes.push('n');
    if simple.topic_protected {
        modes.push('t');
    }
    if simple.join_key {
        modes.push('k');
    }
    if channel.member_limit().is_some() {
        modes.push('l');
    }
    match channel.visibility() {
        Visibility::Listed => {}
        Visibility::Unlisted => modes.push('p'),
        Visibility::Secret => modes.push('s'),
    }
    modes
}

fn render_mask_list(
    prefix: &str,
    nickname: &str,
    channel: &agenc_ircd_domain::ChannelState,
    list: MaskList,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let (entry_code, end_code, end_text) = match list {
        MaskList::Ban => (367, 368, "End of channel ban list"),
        MaskList::Exception => (348, 349, "End of channel exception list"),
        MaskList::InviteException => (346, 347, "End of channel invite exception list"),
    };
    let entries = channel.mask_list(list);
    let warns = entries
        .iter()
        .any(|entry| is_reconnectable_mask(entry.mask()));
    let terminal_frames = if warns { 2 } else { 1 };
    let frame_count = entries
        .len()
        .checked_add(terminal_frames)
        .ok_or(RuntimeError::Overflow)?;
    let mut frames = Vec::new();
    frames
        .try_reserve_exact(frame_count)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    if warns {
        frames.push(weak_mask_notice(prefix, nickname)?);
    }
    for entry in entries {
        let mask = typed_mask_text(entry.mask());
        let created = entry.created_at().get().to_string();
        let middle = if list == MaskList::Ban {
            vec![
                channel.name().presentation(),
                mask.as_str(),
                "server",
                &created,
            ]
        } else {
            vec![channel.name().presentation(), mask.as_str()]
        };
        push_numeric_bare(&mut frames, prefix, entry_code, nickname, &middle)?;
    }
    push_numeric(
        &mut frames,
        prefix,
        end_code,
        nickname,
        &[channel.name().presentation()],
        end_text,
    )?;
    Ok(frames)
}

fn render_topic(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    name: &agenc_ircd_domain::ChannelNameValue,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let channel = visible_channel(domain, requester, name)?;
    let projected = visible_projection(
        domain
            .project_channel(requester, channel.channel_id())
            .map_err(|_| RuntimeError::InvalidValue)?,
    )?;
    let topic = match projected.topic() {
        TopicProjection::Plaintext(text) => Some(*text),
        TopicProjection::EncryptedPlaceholder => Some("Encrypted channel topic"),
        TopicProjection::None => None,
    };
    let mut frames = Vec::new();
    match topic {
        Some(topic) => {
            push_numeric(
                &mut frames,
                prefix,
                332,
                nickname,
                &[name.presentation()],
                topic,
            )?;
            if let Some(state) = channel.topic() {
                let setter = domain
                    .session(state.setter())
                    .map_or("server", |session| session.nickname().presentation());
                let set_at = state.set_at().get().to_string();
                push_numeric_bare(
                    &mut frames,
                    prefix,
                    333,
                    nickname,
                    &[name.presentation(), setter, &set_at],
                )?;
            }
        }
        None => push_numeric(
            &mut frames,
            prefix,
            331,
            nickname,
            &[name.presentation()],
            "No topic is set",
        )?,
    }
    Ok(frames)
}

fn render_names(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    include_userhost: bool,
    selected: &[agenc_ircd_domain::ChannelNameValue],
) -> Result<Vec<WireMessage>, RuntimeError> {
    let channel_ids = selected_channel_ids(domain, requester, selected)?;
    let mut frames = Vec::new();
    for channel_id in channel_ids {
        let projected = visible_projection(
            domain
                .project_channel(requester, channel_id)
                .map_err(|_| RuntimeError::InvalidValue)?,
        )?;
        render_names_channel(
            domain,
            prefix,
            nickname,
            include_userhost,
            &projected,
            &mut frames,
        )?;
    }
    Ok(frames)
}

fn selected_channel_ids(
    domain: &DomainState,
    requester: UserId,
    selected: &[agenc_ircd_domain::ChannelNameValue],
) -> Result<BTreeSet<ChannelInstanceId>, RuntimeError> {
    let mut ids = BTreeSet::new();
    if selected.is_empty() {
        for channel in domain
            .project_channel_list()
            .map_err(|_| RuntimeError::InvalidValue)?
        {
            ids.insert(channel.channel_id());
        }
        let session = domain
            .session(requester)
            .ok_or(RuntimeError::InvalidValue)?;
        ids.extend(session.joined_channels());
        return Ok(ids);
    }
    for name in selected {
        let id = domain
            .resolve_channel(name)
            .ok_or(RuntimeError::InvalidValue)?;
        ids.insert(id);
    }
    Ok(ids)
}

fn render_names_channel(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    include_userhost: bool,
    channel: &ChannelProjection<'_>,
    frames: &mut Vec<WireMessage>,
) -> Result<(), RuntimeError> {
    let symbol = match channel.visibility() {
        Visibility::Listed => "=",
        Visibility::Unlisted => "*",
        Visibility::Secret => "@",
    };
    let mut chunk = String::new();
    for member in channel.members() {
        let entry = names_entry(
            domain,
            member.user_id(),
            member.nickname().presentation(),
            member.role(),
            include_userhost,
        )?;
        if !chunk.is_empty()
            && chunk.len().saturating_add(entry.len()).saturating_add(1) > NAMES_CHUNK_BYTES
        {
            push_numeric(
                frames,
                prefix,
                353,
                nickname,
                &[symbol, channel.name().presentation()],
                &chunk,
            )?;
            chunk.clear();
        }
        if !chunk.is_empty() {
            chunk.push(' ');
        }
        chunk.push_str(&entry);
    }
    if !chunk.is_empty() {
        push_numeric(
            frames,
            prefix,
            353,
            nickname,
            &[symbol, channel.name().presentation()],
            &chunk,
        )?;
    }
    push_numeric(
        frames,
        prefix,
        366,
        nickname,
        &[channel.name().presentation()],
        "End of NAMES list",
    )
}

fn names_entry(
    domain: &DomainState,
    user_id: UserId,
    nickname: &str,
    role: Role,
    include_userhost: bool,
) -> Result<String, RuntimeError> {
    let mut entry = String::new();
    if let Some(prefix) = role_prefix(role) {
        entry.push(prefix);
    }
    entry.push_str(nickname);
    if include_userhost {
        let session = domain.session(user_id).ok_or(RuntimeError::InvalidValue)?;
        let cloak = session.public_cloak();
        entry.push('!');
        entry.push_str(ascii(cloak.user_component())?);
        entry.push('@');
        entry.push_str(ascii(cloak.host_component())?);
    }
    Ok(entry)
}

#[cfg(test)]
fn render_list(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    selected: &[agenc_ircd_domain::ChannelNameValue],
) -> Result<Vec<WireMessage>, RuntimeError> {
    let mut frames = Vec::new();
    push_numeric(
        &mut frames,
        prefix,
        321,
        nickname,
        &["Channel"],
        "Users Name",
    )?;
    for channel in domain
        .project_channel_list()
        .map_err(|_| RuntimeError::InvalidValue)?
    {
        if !selected.is_empty() && !selected.iter().any(|name| name == channel.name()) {
            continue;
        }
        render_list_row(prefix, nickname, &channel, &mut frames)?;
    }
    push_numeric(&mut frames, prefix, 323, nickname, &[], "End of LIST")?;
    Ok(frames)
}

fn render_list_row(
    prefix: &str,
    nickname: &str,
    channel: &ChannelListProjection<'_>,
    frames: &mut Vec<WireMessage>,
) -> Result<(), RuntimeError> {
    let count = channel.member_count_lower_bound().to_string();
    let topic = match channel.topic() {
        TopicProjection::Plaintext(text) => *text,
        TopicProjection::EncryptedPlaceholder => "Encrypted channel topic",
        TopicProjection::None => "",
    };
    push_numeric(
        frames,
        prefix,
        322,
        nickname,
        &[channel.name().presentation(), &count],
        topic,
    )
}

fn render_user_query(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    query: &UserQuery,
) -> Result<Vec<WireMessage>, RuntimeError> {
    match query {
        UserQuery::Who(target) => render_who(domain, prefix, nickname, requester, target.as_ref()),
        UserQuery::Whois(target) => render_whois(domain, prefix, nickname, requester, target),
        UserQuery::Whowas(target, _) => {
            let mut frames = Vec::new();
            push_numeric(
                &mut frames,
                prefix,
                406,
                nickname,
                &[target.presentation()],
                "No WHOWAS history",
            )?;
            push_numeric(
                &mut frames,
                prefix,
                369,
                nickname,
                &[target.presentation()],
                "End of WHOWAS",
            )?;
            Ok(frames)
        }
        UserQuery::Ison(targets) | UserQuery::Userhost(targets) => {
            render_ison(domain, prefix, nickname, requester, targets)
        }
    }
}

fn render_who(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    target: Option<&WhoTarget>,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let mut frames = Vec::new();
    let mask = match target {
        None => render_who_self(domain, prefix, nickname, requester, &mut frames)?,
        Some(WhoTarget::Nickname(target)) => {
            render_who_nickname(domain, prefix, nickname, requester, target, &mut frames)?
        }
        Some(WhoTarget::Channel(target)) => {
            render_who_channel(domain, prefix, nickname, requester, target, &mut frames)?
        }
    };
    push_numeric(
        &mut frames,
        prefix,
        315,
        nickname,
        &[mask],
        "End of WHO list",
    )?;
    Ok(frames)
}

fn render_who_self<'a>(
    domain: &DomainState,
    prefix: &str,
    nickname: &'a str,
    requester: UserId,
    frames: &mut Vec<WireMessage>,
) -> Result<&'a str, RuntimeError> {
    if let ProjectionDecision::Visible(session) = domain.project_session(requester, requester) {
        render_who_session(prefix, nickname, "*", &session, None, frames)?;
    }
    Ok(nickname)
}

fn render_who_nickname<'a>(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    target: &'a agenc_ircd_domain::NicknameValue,
    frames: &mut Vec<WireMessage>,
) -> Result<&'a str, RuntimeError> {
    if let Some(user_id) = domain.resolve_nickname(target)
        && let ProjectionDecision::Visible(session) = domain.project_session(requester, user_id)
    {
        render_who_session(prefix, nickname, "*", &session, None, frames)?;
    }
    Ok(target.presentation())
}

fn render_who_channel<'a>(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    target: &'a agenc_ircd_domain::ChannelNameValue,
    frames: &mut Vec<WireMessage>,
) -> Result<&'a str, RuntimeError> {
    let channel = visible_channel(domain, requester, target)?;
    let projection = visible_projection(
        domain
            .project_channel(requester, channel.channel_id())
            .map_err(|_| RuntimeError::InvalidValue)?,
    )?;
    for member in projection.members() {
        let ProjectionDecision::Visible(session) =
            domain.project_session(requester, member.user_id())
        else {
            continue;
        };
        render_who_session(
            prefix,
            nickname,
            target.presentation(),
            &session,
            role_prefix(member.role()),
            frames,
        )?;
    }
    Ok(target.presentation())
}

fn render_who_session(
    prefix: &str,
    nickname: &str,
    channel: &str,
    session: &SessionProjection<'_>,
    role: Option<char>,
    frames: &mut Vec<WireMessage>,
) -> Result<(), RuntimeError> {
    let cloak = session.public_cloak();
    let mut flags = String::from(if session.away_text().is_some() {
        "G"
    } else {
        "H"
    });
    if let Some(role) = role {
        flags.push(role);
    }
    let realname = format!("0 {}", session.display_name().as_str());
    push_numeric(
        frames,
        prefix,
        352,
        nickname,
        &[
            channel,
            ascii(cloak.user_component())?,
            ascii(cloak.host_component())?,
            prefix,
            session.nickname().presentation(),
            &flags,
        ],
        &realname,
    )
}

fn render_whois(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    target: &agenc_ircd_domain::NicknameValue,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let Some(user_id) = domain.resolve_nickname(target) else {
        return missing_whois(prefix, nickname, target.presentation());
    };
    let ProjectionDecision::Visible(session) = domain.project_session(requester, user_id) else {
        return missing_whois(prefix, nickname, target.presentation());
    };
    let cloak = session.public_cloak();
    let mut frames = Vec::new();
    push_numeric(
        &mut frames,
        prefix,
        311,
        nickname,
        &[
            session.nickname().presentation(),
            ascii(cloak.user_component())?,
            ascii(cloak.host_component())?,
            "*",
        ],
        session.display_name().as_str(),
    )?;
    push_numeric(
        &mut frames,
        prefix,
        312,
        nickname,
        &[session.nickname().presentation(), prefix],
        "AgenC IRC server",
    )?;
    if let Some(away) = session.away_text() {
        push_numeric(
            &mut frames,
            prefix,
            301,
            nickname,
            &[session.nickname().presentation()],
            away,
        )?;
    }
    render_whois_channels(
        domain,
        prefix,
        nickname,
        requester,
        user_id,
        &session,
        &mut frames,
    )?;
    push_numeric(
        &mut frames,
        prefix,
        318,
        nickname,
        &[session.nickname().presentation()],
        "End of WHOIS",
    )?;
    Ok(frames)
}

fn render_whois_channels(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    target: UserId,
    session: &SessionProjection<'_>,
    frames: &mut Vec<WireMessage>,
) -> Result<(), RuntimeError> {
    let state = domain.session(target).ok_or(RuntimeError::InvalidValue)?;
    let mut channels = String::new();
    for channel_id in state.joined_channels() {
        let ProjectionDecision::Visible(channel) = domain
            .project_channel(requester, channel_id)
            .map_err(|_| RuntimeError::InvalidValue)?
        else {
            continue;
        };
        let mut entry = String::new();
        if let Some(member) = channel
            .members()
            .iter()
            .find(|member| member.user_id() == target)
            && let Some(role) = role_prefix(member.role())
        {
            entry.push(role);
        }
        entry.push_str(channel.name().presentation());
        // Many long channel names overflow one line; split like NAMES does.
        if !channels.is_empty()
            && channels.len().saturating_add(entry.len()).saturating_add(1) > NAMES_CHUNK_BYTES
        {
            push_numeric(
                frames,
                prefix,
                319,
                nickname,
                &[session.nickname().presentation()],
                &channels,
            )?;
            channels.clear();
        }
        if !channels.is_empty() {
            channels.push(' ');
        }
        channels.push_str(&entry);
    }
    push_numeric(
        frames,
        prefix,
        319,
        nickname,
        &[session.nickname().presentation()],
        &channels,
    )
}

fn missing_whois(
    prefix: &str,
    nickname: &str,
    target: &str,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let mut frames = Vec::new();
    push_numeric(
        &mut frames,
        prefix,
        401,
        nickname,
        &[target],
        "No such nick",
    )?;
    push_numeric(
        &mut frames,
        prefix,
        318,
        nickname,
        &[target],
        "End of WHOIS",
    )?;
    Ok(frames)
}

fn render_ison(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    targets: &[agenc_ircd_domain::NicknameValue],
) -> Result<Vec<WireMessage>, RuntimeError> {
    let mut online = String::new();
    for target in targets {
        let Some(user_id) = domain.resolve_nickname(target) else {
            continue;
        };
        if agenc_ircd_domain::PresenceProjection::Present
            != domain.project_presence(requester, user_id)
        {
            continue;
        }
        if !online.is_empty() {
            online.push(' ');
        }
        online.push_str(target.presentation());
    }
    one_numeric(prefix, 303, nickname, &[], &online)
}

fn render_presence_query(
    domain: &DomainState,
    prefix: &str,
    nickname: &str,
    requester: UserId,
    query: &PresenceCommand,
) -> Result<Vec<WireMessage>, RuntimeError> {
    let session = domain
        .session(requester)
        .ok_or(RuntimeError::InvalidValue)?;
    match query {
        PresenceCommand::MonitorList => {
            let monitored: Vec<_> = session.monitored_nicknames().cloned().collect();
            render_ison(domain, prefix, nickname, requester, &monitored)
        }
        PresenceCommand::MonitorStatus => {
            let monitored: Vec<_> = session.monitored_nicknames().cloned().collect();
            render_ison(domain, prefix, nickname, requester, &monitored)
        }
        _ => Err(RuntimeError::InvalidValue),
    }
}

fn visible_channel<'a>(
    domain: &'a DomainState,
    requester: UserId,
    name: &agenc_ircd_domain::ChannelNameValue,
) -> Result<&'a agenc_ircd_domain::ChannelState, RuntimeError> {
    let channel_id = domain
        .resolve_channel(name)
        .ok_or(RuntimeError::InvalidValue)?;
    let channel = domain
        .channel(channel_id)
        .ok_or(RuntimeError::InvalidValue)?;
    let _projection = visible_projection(
        domain
            .project_channel(requester, channel_id)
            .map_err(|_| RuntimeError::InvalidValue)?,
    )?;
    Ok(channel)
}

fn visible_projection<T>(decision: ProjectionDecision<T>) -> Result<T, RuntimeError> {
    match decision {
        ProjectionDecision::Visible(value) => Ok(value),
        ProjectionDecision::Hidden => Err(RuntimeError::InvalidValue),
    }
}

fn typed_mask_text(mask: &TypedMask) -> String {
    let subject = match mask.subject() {
        MaskSubject::Account(account) => format!("$a:{}", account.to_text()),
        MaskSubject::User(user_id) => format!("$u:{}", user_id.to_base64url()),
        MaskSubject::Nickname(glob) => format!("$n:{}", glob.pattern()),
        MaskSubject::Cloak(glob) => format!("$c:{}", glob.pattern()),
    };
    if mask.is_quiet() {
        format!("$q:{subject}")
    } else {
        subject
    }
}

const fn role_prefix(role: Role) -> Option<char> {
    match role {
        Role::Member => None,
        Role::Voice => Some('+'),
        Role::HalfOperator => Some('%'),
        Role::Operator => Some('@'),
        Role::Administrator => Some('&'),
        Role::Owner => Some('~'),
    }
}

fn ascii(bytes: &[u8]) -> Result<&str, RuntimeError> {
    std::str::from_utf8(bytes).map_err(|_| RuntimeError::InvalidValue)
}

fn one_numeric(
    prefix: &str,
    code: u16,
    nickname: &str,
    middle: &[&str],
    trailing: &str,
) -> Result<Vec<WireMessage>, RuntimeError> {
    Ok(vec![numeric(prefix, code, nickname, middle, trailing)?])
}

fn one_numeric_bare(
    prefix: &str,
    code: u16,
    nickname: &str,
    middle: &[&str],
) -> Result<Vec<WireMessage>, RuntimeError> {
    Ok(vec![numeric_bare(prefix, code, nickname, middle)?])
}

fn push_numeric(
    frames: &mut Vec<WireMessage>,
    prefix: &str,
    code: u16,
    nickname: &str,
    middle: &[&str],
    trailing: &str,
) -> Result<(), RuntimeError> {
    frames
        .try_reserve(1)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    frames.push(numeric(prefix, code, nickname, middle, trailing)?);
    Ok(())
}

fn push_numeric_bare(
    frames: &mut Vec<WireMessage>,
    prefix: &str,
    code: u16,
    nickname: &str,
    middle: &[&str],
) -> Result<(), RuntimeError> {
    frames
        .try_reserve(1)
        .map_err(|_| RuntimeError::MemoryExhausted)?;
    frames.push(numeric_bare(prefix, code, nickname, middle)?);
    Ok(())
}

fn numeric(
    prefix: &str,
    code: u16,
    nickname: &str,
    middle: &[&str],
    trailing: &str,
) -> Result<WireMessage, RuntimeError> {
    numeric_reply(prefix, code, nickname, middle, Some(trailing))
        .map_err(|_| RuntimeError::InvalidValue)
}

fn numeric_bare(
    prefix: &str,
    code: u16,
    nickname: &str,
    middle: &[&str],
) -> Result<WireMessage, RuntimeError> {
    numeric_reply(prefix, code, nickname, middle, None).map_err(|_| RuntimeError::InvalidValue)
}

#[cfg(test)]
mod tests {
    use std::error::Error;

    use agenc_ircd_client_wire::{OutputBudget, RenderError};
    use agenc_ircd_domain::{
        CanonicalCommand, ChannelKeyVerifier, ChannelNameValue, ChannelTarget, ExternalInputs,
        ModeChange, ModeOperation, PresenceCommand, TopicText, VisibilityMode,
    };
    use agenc_ircd_testkit::{
        DomainTestIdentity, account_id, apply_command, bytes, channel_id, create_account,
        open_session, registered_admission,
    };
    use agenc_ircd_types::{ControlPolicy, EntryId, MessageId, TypedMask, UtcSecond};

    use super::*;

    struct ExactBudget(usize);

    impl OutputBudget for ExactBudget {
        type Permit = usize;

        fn try_reserve_exact(&mut self, bytes: usize) -> Result<Self::Permit, RenderError> {
            if bytes != self.0 {
                return Err(RenderError::ReservationFailed);
            }
            Ok(bytes)
        }
    }

    fn encoded(message: WireMessage) -> Result<String, Box<dyn Error>> {
        let measured = message.measure()?;
        let mut budget = ExactBudget(measured.bytes());
        Ok(String::from_utf8(
            measured.encode(&mut budget)?.as_bytes().to_vec(),
        )?)
    }

    struct QueryFixture {
        state: DomainState,
        owner: DomainTestIdentity,
        member: DomainTestIdentity,
        outsider: DomainTestIdentity,
        listed: ChannelNameValue,
        unlisted: ChannelNameValue,
        secret: ChannelNameValue,
    }

    fn join_new(
        state: &mut DomainState,
        identity: DomainTestIdentity,
        name: &ChannelNameValue,
        seed: u8,
    ) -> Result<(), Box<dyn Error>> {
        apply_command(
            state,
            identity,
            CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])?,
            &registered_admission(identity.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_000)),
                channel_ids: vec![channel_id(seed)],
                ..ExternalInputs::default()
            }),
        )?;
        Ok(())
    }

    fn join_existing(
        state: &mut DomainState,
        identity: DomainTestIdentity,
        name: &ChannelNameValue,
    ) -> Result<(), Box<dyn Error>> {
        apply_command(
            state,
            identity,
            CanonicalCommand::join(vec![ChannelTarget::new(name.clone(), false)])?,
            &registered_admission(identity.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_001)),
                ..ExternalInputs::default()
            }),
        )?;
        Ok(())
    }

    fn fixture() -> Result<QueryFixture, Box<dyn Error>> {
        let mut state = DomainState::new()?;
        let (owner_account, owner_generation) = create_account(&mut state, 1, 1)?;
        let owner = open_session(
            &mut state,
            1,
            "RenderOwner",
            Some((owner_account, owner_generation)),
        )?;
        let member = open_session(&mut state, 2, "RenderMember", None)?;
        let outsider = open_session(&mut state, 3, "RenderOutsider", None)?;
        let listed = ChannelNameValue::parse("#render-listed")?;
        let unlisted = ChannelNameValue::parse("#render-unlisted")?;
        let secret = ChannelNameValue::parse("#render-secret")?;

        join_new(&mut state, owner, &listed, 20)?;
        join_existing(&mut state, member, &listed)?;
        join_new(&mut state, owner, &unlisted, 21)?;
        join_new(&mut state, owner, &secret, 22)?;

        let owner_credit = registered_admission(owner.user_id)?;
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::mode(
                listed.clone(),
                vec![
                    ModeChange::InviteOnly(true),
                    ModeChange::Moderated(true),
                    ModeChange::TopicProtected(false),
                    ModeChange::MemberLimit(Some(25)),
                    ModeChange::Role {
                        operation: ModeOperation::Add,
                        target: agenc_ircd_domain::NicknameValue::parse("RenderMember")?,
                        role: Role::Administrator,
                    },
                ],
            )?,
            &owner_credit,
            None,
        )?;
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::mode(listed.clone(), vec![ModeChange::JoinKey(true)])?,
            &owner_credit,
            Some(ExternalInputs {
                key_verifiers: vec![ChannelKeyVerifier::new([40; 16], [41; 32])],
                ..ExternalInputs::default()
            }),
        )?;
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::mode(
                unlisted.clone(),
                vec![ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Unlisted,
                }],
            )?,
            &owner_credit,
            None,
        )?;
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::mode(
                secret.clone(),
                vec![ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Secret,
                }],
            )?,
            &owner_credit,
            None,
        )?;
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::topic_set(
                listed.clone(),
                TopicText::try_from_str("visible topic", ControlPolicy::RejectAll)?,
            ),
            &owner_credit,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_010)),
                message_ids: vec![MessageId::from_bytes(bytes(30))],
                ..ExternalInputs::default()
            }),
        )?;
        apply_command(
            &mut state,
            member,
            CanonicalCommand::presence(PresenceCommand::Away(Some(
                agenc_ircd_domain::AwayText::try_from_str(
                    "testing away",
                    ControlPolicy::RejectAll,
                )?,
            )))?,
            &registered_admission(member.user_id)?,
            None,
        )?;
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::user_operator_notices(
                agenc_ircd_domain::NicknameValue::parse("RenderOwner")?,
                true,
            ),
            &owner_credit,
            None,
        )?;

        let masks = [
            TypedMask::parse(&format!("$a:{}", account_id(30).random().to_text()))?,
            TypedMask::parse(&format!("$u:{}", member.user_id.to_base64url()))?,
            TypedMask::parse("$n:render*")?,
            TypedMask::parse("$q:$c:h-*.invalid")?,
        ];
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::mode(
                listed.clone(),
                vec![
                    ModeChange::AddMask {
                        list: MaskList::Ban,
                        mask: masks.into_iter().next().ok_or("missing mask")?,
                    },
                    ModeChange::AddMask {
                        list: MaskList::Exception,
                        mask: TypedMask::parse(&format!("$u:{}", member.user_id.to_base64url()))?,
                    },
                    ModeChange::AddMask {
                        list: MaskList::InviteException,
                        mask: TypedMask::parse("$n:render*")?,
                    },
                    ModeChange::AddMask {
                        list: MaskList::Ban,
                        mask: TypedMask::parse("$q:$c:h-*.invalid")?,
                    },
                ],
            )?,
            &owner_credit,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_020)),
                entry_ids: vec![
                    EntryId::from_bytes(bytes(31)),
                    EntryId::from_bytes(bytes(32)),
                    EntryId::from_bytes(bytes(33)),
                    EntryId::from_bytes(bytes(34)),
                ],
                ..ExternalInputs::default()
            }),
        )?;
        apply_command(
            &mut state,
            owner,
            CanonicalCommand::presence(PresenceCommand::MonitorAdd(vec![
                agenc_ircd_domain::NicknameValue::parse("RenderOwner")?,
                agenc_ircd_domain::NicknameValue::parse("RenderMember")?,
                agenc_ircd_domain::NicknameValue::parse("MissingRenderUser")?,
            ]))?,
            &owner_credit,
            None,
        )?;

        Ok(QueryFixture {
            state,
            owner,
            member,
            outsider,
            listed,
            unlisted,
            secret,
        })
    }

    #[test]
    fn role_prefixes_follow_the_frozen_prefix_order() {
        assert_eq!(role_prefix(Role::Owner), Some('~'));
        assert_eq!(role_prefix(Role::Administrator), Some('&'));
        assert_eq!(role_prefix(Role::Operator), Some('@'));
        assert_eq!(role_prefix(Role::HalfOperator), Some('%'));
        assert_eq!(role_prefix(Role::Voice), Some('+'));
        assert_eq!(role_prefix(Role::Member), None);
    }

    #[test]
    fn empty_list_uses_the_registered_start_and_end_shapes() -> Result<(), Box<dyn Error>> {
        let domain = DomainState::new()?;
        let frames = render_list(&domain, "server.test", "reader", &[])?;

        assert_eq!(frames.len(), 2);
        assert_eq!(
            encoded(frames.into_iter().next().ok_or("missing LIST start")?)?,
            ":server.test 321 reader Channel :Users Name\r\n"
        );
        Ok(())
    }

    #[test]
    fn hidden_projections_fail_closed() {
        assert_eq!(
            visible_projection::<()>(ProjectionDecision::Hidden).err(),
            Some(RuntimeError::InvalidValue)
        );
    }

    #[test]
    fn modes_topics_masks_and_visibility_render_every_closed_shape() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let listed = visible_channel(&fixture.state, fixture.owner.user_id, &fixture.listed)?;
        let modes = channel_mode_text(listed);
        assert!(modes.contains('i'));
        assert!(modes.contains('m'));
        assert!(modes.contains('l'));
        assert!(!modes.contains('t'));
        assert!(modes.contains('k'));
        assert_eq!(
            render_channel_modes("server.test", "owner", listed)?.len(),
            2
        );

        let unlisted = visible_channel(&fixture.state, fixture.owner.user_id, &fixture.unlisted)?;
        assert!(channel_mode_text(unlisted).contains('p'));
        let secret = visible_channel(&fixture.state, fixture.owner.user_id, &fixture.secret)?;
        assert!(channel_mode_text(secret).contains('s'));
        assert_eq!(
            visible_channel(&fixture.state, fixture.outsider.user_id, &fixture.secret).err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            visible_channel(
                &fixture.state,
                fixture.owner.user_id,
                &ChannelNameValue::parse("#missing-render")?,
            )
            .err(),
            Some(RuntimeError::InvalidValue)
        );

        assert_eq!(
            render_mode(
                &fixture.state,
                "server.test",
                "owner",
                fixture.owner.user_id,
                &ModeCommand::UserQuery(agenc_ircd_domain::NicknameValue::parse("RenderOwner",)?),
            )?
            .len(),
            1
        );
        assert_eq!(
            render_mode(
                &fixture.state,
                "server.test",
                "owner",
                fixture.owner.user_id,
                &ModeCommand::ChannelQuery(fixture.listed.clone()),
            )?
            .len(),
            2
        );
        for list in [
            MaskList::Ban,
            MaskList::Exception,
            MaskList::InviteException,
        ] {
            assert!(
                render_mode(
                    &fixture.state,
                    "server.test",
                    "owner",
                    fixture.owner.user_id,
                    &ModeCommand::ChannelList(fixture.listed.clone(), list),
                )?
                .len()
                    >= 2
            );
        }
        assert_eq!(
            render_mode(
                &fixture.state,
                "server.test",
                "owner",
                fixture.owner.user_id,
                &ModeCommand::UserOperatorNotices(
                    agenc_ircd_domain::NicknameValue::parse("RenderOwner")?,
                    false,
                ),
            )
            .err(),
            Some(RuntimeError::InvalidValue)
        );

        assert_eq!(
            render_topic(
                &fixture.state,
                "server.test",
                "owner",
                fixture.owner.user_id,
                &fixture.listed,
            )?
            .len(),
            2
        );
        assert_eq!(
            render_topic(
                &fixture.state,
                "server.test",
                "owner",
                fixture.owner.user_id,
                &fixture.unlisted,
            )?
            .len(),
            1
        );

        for input in [
            format!("$a:{}", account_id(40).random().to_text()),
            format!("$u:{}", fixture.member.user_id.to_base64url()),
            "$n:render*".to_owned(),
            "$c:h-*".to_owned(),
            "$q:$n:quiet*".to_owned(),
        ] {
            let mask = TypedMask::parse(&input)?;
            assert_eq!(typed_mask_text(&mask), input);
        }
        Ok(())
    }

    #[test]
    fn mask_lists_warn_once_before_reconnectable_rules() -> Result<(), Box<dyn Error>> {
        let mut fixture = fixture()?;
        apply_command(
            &mut fixture.state,
            fixture.owner,
            CanonicalCommand::mode(
                fixture.listed.clone(),
                vec![ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: TypedMask::parse("$n:another*")?,
                }],
            )?,
            &registered_admission(fixture.owner.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_021)),
                entry_ids: vec![EntryId::from_bytes(bytes(35))],
                ..ExternalInputs::default()
            }),
        )?;
        apply_command(
            &mut fixture.state,
            fixture.owner,
            CanonicalCommand::mode(
                fixture.unlisted.clone(),
                vec![ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: TypedMask::parse(&format!("$a:{}", account_id(50).random().to_text()))?,
                }],
            )?,
            &registered_admission(fixture.owner.user_id)?,
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_022)),
                entry_ids: vec![EntryId::from_bytes(bytes(36))],
                ..ExternalInputs::default()
            }),
        )?;

        let listed = visible_channel(&fixture.state, fixture.owner.user_id, &fixture.listed)?;
        let rendered = render_mask_list("server.test", "owner", listed, MaskList::Ban)?
            .into_iter()
            .map(encoded)
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(
            rendered.first().map(String::as_str),
            Some(
                ":server.test NOTICE owner :Nickname and cloak masks are weak, reconnectable rules\r\n"
            )
        );
        assert_eq!(
            rendered
                .iter()
                .filter(|line| line.contains(" NOTICE "))
                .count(),
            1
        );
        assert!(
            rendered
                .get(1)
                .is_some_and(|line| line.contains(" 367 owner "))
        );
        assert!(
            rendered
                .last()
                .is_some_and(|line| line.contains(" 368 owner "))
        );

        let user_only = render_mask_list("server.test", "owner", listed, MaskList::Exception)?
            .into_iter()
            .map(encoded)
            .collect::<Result<Vec<_>, _>>()?;
        assert!(user_only.iter().all(|line| !line.contains(" NOTICE ")));

        let unlisted = visible_channel(&fixture.state, fixture.owner.user_id, &fixture.unlisted)?;
        let account_only = render_mask_list("server.test", "owner", unlisted, MaskList::Ban)?
            .into_iter()
            .map(encoded)
            .collect::<Result<Vec<_>, _>>()?;
        assert!(account_only.iter().all(|line| !line.contains(" NOTICE ")));
        Ok(())
    }

    #[test]
    fn names_lists_who_and_presence_apply_privacy_before_rendering() -> Result<(), Box<dyn Error>> {
        let fixture = fixture()?;
        let all_names = render_names(
            &fixture.state,
            "server.test",
            "owner",
            fixture.owner.user_id,
            true,
            &[],
        )?;
        assert!(all_names.len() >= 6);
        let selected_names = render_names(
            &fixture.state,
            "server.test",
            "owner",
            fixture.owner.user_id,
            false,
            std::slice::from_ref(&fixture.listed),
        )?;
        assert!(selected_names.len() >= 2);
        assert_eq!(
            selected_channel_ids(
                &fixture.state,
                fixture.owner.user_id,
                &[ChannelNameValue::parse("#missing-render")?],
            )
            .err(),
            Some(RuntimeError::InvalidValue)
        );

        assert_eq!(
            render_list(&fixture.state, "server.test", "owner", &[])?.len(),
            3
        );
        assert_eq!(
            render_list(
                &fixture.state,
                "server.test",
                "owner",
                &[fixture.listed.clone(), fixture.unlisted.clone()],
            )?
            .len(),
            3
        );
        assert_eq!(
            render_list(
                &fixture.state,
                "server.test",
                "owner",
                std::slice::from_ref(&fixture.unlisted),
            )?
            .len(),
            2
        );

        let member_name = agenc_ircd_domain::NicknameValue::parse("RenderMember")?;
        let missing_name = agenc_ircd_domain::NicknameValue::parse("MissingRenderUser")?;
        let queries = [
            UserQuery::Who(None),
            UserQuery::Who(Some(WhoTarget::Nickname(member_name.clone()))),
            UserQuery::Who(Some(WhoTarget::Channel(fixture.listed.clone()))),
            UserQuery::Whois(member_name.clone()),
            UserQuery::Whois(missing_name.clone()),
            UserQuery::Whowas(member_name.clone(), 1),
            UserQuery::Ison(vec![
                agenc_ircd_domain::NicknameValue::parse("RenderOwner")?,
                member_name.clone(),
                missing_name.clone(),
            ]),
            UserQuery::Userhost(vec![member_name.clone(), missing_name.clone()]),
        ];
        for query in &queries {
            assert!(
                !render_user_query(
                    &fixture.state,
                    "server.test",
                    "owner",
                    fixture.owner.user_id,
                    query,
                )?
                .is_empty()
            );
        }
        for query in [PresenceCommand::MonitorList, PresenceCommand::MonitorStatus] {
            assert_eq!(
                render_presence_query(
                    &fixture.state,
                    "server.test",
                    "owner",
                    fixture.owner.user_id,
                    &query,
                )?
                .len(),
                1
            );
        }
        assert_eq!(
            render_presence_query(
                &fixture.state,
                "server.test",
                "owner",
                fixture.owner.user_id,
                &PresenceCommand::MonitorClear,
            )
            .err(),
            Some(RuntimeError::InvalidValue)
        );
        assert_eq!(
            render_who_self(
                &fixture.state,
                "server.test",
                "missing",
                agenc_ircd_types::UserId::from_bytes(bytes(200)),
                &mut Vec::new(),
            )?,
            "missing"
        );
        assert_eq!(
            render_whois(
                &fixture.state,
                "server.test",
                "outsider",
                fixture.outsider.user_id,
                &agenc_ircd_domain::NicknameValue::parse("RenderOwner")?,
            )?
            .len(),
            2
        );
        assert!(
            render_whois(
                &fixture.state,
                "server.test",
                "outsider",
                fixture.outsider.user_id,
                &agenc_ircd_domain::NicknameValue::parse("RenderOutsider")?,
            )?
            .len()
                >= 4
        );

        let listed = visible_projection(
            fixture
                .state
                .project_channel(fixture.owner.user_id, channel_id(20))?,
        )?;
        let unlisted = visible_projection(
            fixture
                .state
                .project_channel(fixture.owner.user_id, channel_id(21))?,
        )?;
        let secret = visible_projection(
            fixture
                .state
                .project_channel(fixture.owner.user_id, channel_id(22))?,
        )?;
        let mut frames = Vec::new();
        render_names_channel(
            &fixture.state,
            "server.test",
            "owner",
            true,
            &listed,
            &mut frames,
        )?;
        render_names_channel(
            &fixture.state,
            "server.test",
            "owner",
            false,
            &unlisted,
            &mut frames,
        )?;
        render_names_channel(
            &fixture.state,
            "server.test",
            "owner",
            false,
            &secret,
            &mut frames,
        )?;
        assert!(frames.len() >= 6);
        Ok(())
    }

    #[test]
    fn live_queries_render_lists_names_who_whois_topics_modes_and_information()
    -> Result<(), Box<dyn Error>> {
        use agenc_ircd_client_wire::{FramedLine, parse_message};
        use agenc_ircd_domain::{
            AwayText, DomainError, InformationQuery, MaskList, NicknameValue, PlanDecision,
            UserQuery, WhoTarget,
        };

        use crate::client_render::ReplyInput;
        use crate::connection::ConnectionGeneration;
        use crate::test_support::{
            StateCoreFixture, apply_live_plan, bind_live_session, negotiated_capabilities,
            plan_live, seed_account, seed_session,
        };

        const CAPABILITIES: &[&str] = &[
            "batch",
            "labeled-response",
            "userhost-in-names",
            "multi-prefix",
            "server-time",
            "message-tags",
            "away-notify",
            "account-notify",
            "extended-join",
            "standard-replies",
        ];
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let context = fixture.context_mut()?;
        let account = seed_account(context, 1, 1)?;
        let owner = seed_session(context, 1, "QueryOwner", Some(account))?;
        let member = seed_session(context, 2, "QueryMember", None)?;
        let _owner_sink = bind_live_session(
            context,
            1,
            owner,
            negotiated_capabilities(CAPABILITIES)?,
            true,
        )?;
        let member_sink = bind_live_session(
            context,
            2,
            member,
            negotiated_capabilities(CAPABILITIES)?,
            true,
        )?;
        let capabilities = negotiated_capabilities(CAPABILITIES)?;
        let listed = ChannelNameValue::parse("#query-listed")?;
        let secret = ChannelNameValue::parse("#query-secret")?;
        let mutate = |context: &mut StateCoreContext,
                      identity: DomainTestIdentity,
                      label: &str,
                      command: &dyn Fn() -> Result<CanonicalCommand, DomainError>|
         -> Result<(), Box<dyn Error>> {
            let decision = plan_live(context, identity, command)
                .map_err(|error| format!("{label}: {error}"))?;
            let PlanDecision::Mutation(plan) = decision else {
                return Err(format!("{label}: expected a mutation").into());
            };
            apply_live_plan(context, plan)
        };
        mutate(context, owner, "join listed owner", &|| {
            CanonicalCommand::join(vec![ChannelTarget::new(listed.clone(), false)])
        })?;
        mutate(context, member, "join listed member", &|| {
            CanonicalCommand::join(vec![ChannelTarget::new(listed.clone(), false)])
        })?;
        mutate(context, owner, "join secret owner", &|| {
            CanonicalCommand::join(vec![ChannelTarget::new(secret.clone(), false)])
        })?;
        mutate(context, owner, "mode secret", &|| {
            CanonicalCommand::mode(
                secret.clone(),
                vec![ModeChange::Visibility {
                    operation: ModeOperation::Add,
                    mode: VisibilityMode::Secret,
                }],
            )
        })?;
        mutate(context, owner, "topic listed", &|| {
            let topic = TopicText::try_from_str("topic", ControlPolicy::RejectAll)
                .map_err(|_| DomainError::InvalidArgument)?;
            Ok(CanonicalCommand::topic_set(listed.clone(), topic))
        })?;
        mutate(context, owner, "ban listed", &|| {
            CanonicalCommand::mode(
                listed.clone(),
                vec![ModeChange::AddMask {
                    list: MaskList::Ban,
                    mask: TypedMask::parse("$n:banned")
                        .map_err(|_| DomainError::InvalidArgument)?,
                }],
            )
        })?;
        mutate(context, owner, "away owner", &|| {
            let away = AwayText::try_from_str("away", ControlPolicy::RejectAll)
                .map_err(|_| DomainError::InvalidArgument)?;
            CanonicalCommand::presence(PresenceCommand::Away(Some(away)))
        })?;

        let query = |context: &mut StateCoreContext,
                     identity: DomainTestIdentity,
                     generation: u64,
                     line: &str,
                     command: &dyn Fn() -> Result<CanonicalCommand, DomainError>|
         -> Result<(), Box<dyn Error>> {
            let request = parse_message(FramedLine::new(line)?)?.ok_or("empty request")?;
            let decision = plan_live(context, identity, command)
                .map_err(|error| format!("{line}: {error}"))?;
            let PlanDecision::Query(plan) = decision else {
                return Err(format!("{line} was not planned as a query").into());
            };
            let reply = ReplyInput {
                requester: identity.user_id,
                generation: ConnectionGeneration::new(generation),
                capabilities: &capabilities,
                request: &request,
            };
            render_query(context, reply, &plan).map_err(|_| format!("{line} failed to render"))?;
            Ok(())
        };
        let nick = |name: &str| NicknameValue::parse(name);
        query(context, owner, 1, "LIST", &|| {
            CanonicalCommand::list(Vec::new())
        })?;
        query(context, member, 2, "LIST #query-listed", &|| {
            CanonicalCommand::list(vec![listed.clone()])
        })?;
        query(context, member, 2, "NAMES #query-listed", &|| {
            CanonicalCommand::names(vec![listed.clone()])
        })?;
        query(context, owner, 1, "NAMES #query-secret", &|| {
            CanonicalCommand::names(vec![secret.clone()])
        })?;
        query(context, member, 2, "TOPIC #query-listed", &|| {
            Ok(CanonicalCommand::topic_query(listed.clone()))
        })?;
        query(context, member, 2, "MODE #query-listed", &|| {
            Ok(CanonicalCommand::channel_mode_query(listed.clone()))
        })?;
        query(context, member, 2, "MODE #query-listed +b", &|| {
            Ok(CanonicalCommand::channel_mode_list(
                listed.clone(),
                MaskList::Ban,
            ))
        })?;
        query(context, member, 2, "MODE QueryMember", &|| {
            Ok(CanonicalCommand::user_mode_query(nick("QueryMember")?))
        })?;
        query(context, member, 2, "WHO", &|| {
            CanonicalCommand::user_query(UserQuery::Who(None))
        })?;
        query(context, member, 2, "WHO #query-listed", &|| {
            CanonicalCommand::user_query(UserQuery::Who(Some(WhoTarget::Channel(listed.clone()))))
        })?;
        query(context, member, 2, "WHO QueryOwner", &|| {
            CanonicalCommand::user_query(UserQuery::Who(Some(WhoTarget::Nickname(nick(
                "QueryOwner",
            )?))))
        })?;
        query(context, member, 2, "WHOIS QueryOwner", &|| {
            CanonicalCommand::user_query(UserQuery::Whois(nick("QueryOwner")?))
        })?;
        query(context, owner, 1, "WHOIS QueryOwner", &|| {
            CanonicalCommand::user_query(UserQuery::Whois(nick("QueryOwner")?))
        })?;
        query(context, member, 2, "WHOWAS QueryOwner 1", &|| {
            CanonicalCommand::user_query(UserQuery::Whowas(nick("QueryOwner")?, 1))
        })?;
        query(context, member, 2, "ISON QueryOwner Nobody", &|| {
            CanonicalCommand::user_query(UserQuery::Ison(vec![
                nick("QueryOwner")?,
                nick("Nobody")?,
            ]))
        })?;
        query(context, member, 2, "USERHOST QueryOwner", &|| {
            CanonicalCommand::user_query(UserQuery::Userhost(vec![nick("QueryOwner")?]))
        })?;
        let information = [
            ("MOTD", InformationQuery::Motd),
            ("LUSERS", InformationQuery::Lusers),
            ("VERSION", InformationQuery::Version),
            ("TIME", InformationQuery::Time),
            ("ADMIN", InformationQuery::Admin),
            ("INFO", InformationQuery::Info),
            ("LINKS", InformationQuery::Links),
        ];
        for (line, information) in information {
            query(context, member, 2, line, &|| {
                Ok(CanonicalCommand::information(information))
            })?;
        }
        assert!(member_sink.commits() > 0);
        Ok(())
    }
}
