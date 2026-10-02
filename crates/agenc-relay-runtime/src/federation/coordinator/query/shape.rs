//! Allocation-free upper bounds for the existing federation query renderers.

#![forbid(unsafe_code)]

use agenc_relay_domain::{
    CanonicalCommandView, ChannelListProjection, ChannelNameValue, DomainError, DomainState,
    InformationQuery, MemberProjection, ModeCommand, NicknameValue, PresenceCommand, QueryPlan,
    SessionProjection, UserQuery, WhoTarget,
};
use agenc_relay_types::UserId;

use crate::budget::MemoryCharge;
use crate::state_core::StateCoreContext;

// A full 8,000-byte chunk holds at least this many of the longest tokens: a
// role byte, the longest framed user mask, and a separator. Federated NAMES
// replies carry no user masks today, so the bound is conservative.
const MIN_FULL_NAMES_ROWS: usize = 8_000 / (1 + agenc_relay_client_wire::MAX_USER_MASK_BYTES + 1);
// Scratch strings are bounded by the existing 8,000-byte chunk renderer;
// this also covers scalar formatting and individual temporary allocations.
const FIXED_SCRATCH_BYTES: usize = 65_536;
// A selected-ID BTreeSet node holds at most eleven 16-byte keys. Charging
// one allocation quantum per selected ID also covers its node/edge backing.
const SELECTED_ID_ALLOCATION_BYTES: usize = 4_096;
const LIST_RESULTS: usize = 200;

pub(super) struct Bounds {
    pub(super) rows: usize,
    pub(super) frames: usize,
    pub(super) scratch_bytes: usize,
    pub(super) middle_parameters: usize,
}

impl Bounds {
    fn new(rows: usize, frames: usize, middle_parameters: usize) -> Self {
        Self {
            rows,
            frames,
            scratch_bytes: FIXED_SCRATCH_BYTES,
            middle_parameters,
        }
    }

    fn with_scratch(mut self, additional: usize) -> Result<Self, DomainError> {
        self.scratch_bytes = add(self.scratch_bytes, additional)?;
        Ok(self)
    }
}

fn add(left: usize, right: usize) -> Result<usize, DomainError> {
    left.checked_add(right).ok_or(DomainError::ServerBusy)
}

fn multiply(left: usize, right: usize) -> Result<usize, DomainError> {
    left.checked_mul(right).ok_or(DomainError::ServerBusy)
}

fn projection_bytes(members: usize) -> Result<usize, DomainError> {
    // Include geometric growth in who_channel_rows as well as the exact
    // member projection produced by visible_channel.
    multiply(
        members,
        2 * size_of::<MemberProjection<'static>>()
            + 2 * size_of::<(SessionProjection<'static>, Option<char>)>(),
    )
}

fn channel_members(domain: &DomainState, name: &ChannelNameValue) -> usize {
    domain
        .resolve_channel(name)
        .and_then(|id| domain.channel(id))
        .map_or(0, |channel| channel.member_count())
}

pub(super) fn bounds(
    context: &StateCoreContext,
    requester: UserId,
    plan: &QueryPlan,
) -> Result<Bounds, DomainError> {
    if plan.requester() != requester || plan.expected_revision() != context.domain().revision() {
        return Err(DomainError::ServerBusy);
    }
    let domain = context.domain();
    match plan.command().view() {
        CanonicalCommandView::Names(selected) => names(domain, requester, selected),
        CanonicalCommandView::List(_) => {
            let rows = domain.channel_count().min(LIST_RESULTS);
            Bounds::new(rows, add(rows, 2)?, 3)
                .with_scratch(multiply(rows, size_of::<ChannelListProjection<'static>>())?)
        }
        CanonicalCommandView::UserQuery(query) => user_query(context, requester, query),
        CanonicalCommandView::Mode(query) => mode(domain, query),
        CanonicalCommandView::TopicQuery(name) => {
            Bounds::new(1, 2, 4).with_scratch(projection_bytes(channel_members(domain, name))?)
        }
        CanonicalCommandView::Presence(query) => presence(domain, requester, query),
        CanonicalCommandView::Information(query) => information(context, query),
        _ => Err(DomainError::ServerBusy),
    }
}

fn names(
    domain: &DomainState,
    requester: UserId,
    selected: &[ChannelNameValue],
) -> Result<Bounds, DomainError> {
    let mut channels = 0_usize;
    let mut members = 0_usize;
    let mut peak_members = 0_usize;
    let mut count = |rows| -> Result<(), DomainError> {
        channels = add(channels, 1)?;
        members = add(members, rows)?;
        peak_members = peak_members.max(rows);
        Ok(())
    };
    if selected.is_empty() {
        let session = domain.session(requester).ok_or(DomainError::ServerBusy)?;
        for id in session.joined_channels() {
            count(
                domain
                    .channel(id)
                    .map_or(0, |channel| channel.member_count()),
            )?;
        }
    } else {
        for name in selected {
            count(channel_members(domain, name))?;
        }
    }
    let frames = add(members / MIN_FULL_NAMES_ROWS, multiply(channels, 2)?)?.max(1);
    let scratch = add(
        projection_bytes(peak_members)?,
        multiply(channels, SELECTED_ID_ALLOCATION_BYTES)?,
    )?;
    Bounds::new(add(members, channels)?.max(1), frames, 3).with_scratch(scratch)
}

fn user_query(
    context: &StateCoreContext,
    requester: UserId,
    query: &UserQuery,
) -> Result<Bounds, DomainError> {
    match query {
        UserQuery::Who(Some(WhoTarget::Channel(name))) => {
            let rows = channel_members(context.domain(), name);
            Bounds::new(rows, add(rows, 1)?, 7).with_scratch(projection_bytes(rows)?)
        }
        UserQuery::Who(_) => Ok(Bounds::new(1, 2, 7)),
        UserQuery::Whois(target) => whois(context.domain(), target),
        UserQuery::Whowas(target, count) => {
            let rows = context
                .whowas()
                .visible(context.domain(), requester, target, context.now())
                .take(usize::from(*count))
                .count();
            Ok(Bounds::new(rows, add(multiply(rows, 2)?, 1)?.max(2), 5))
        }
        // Input syntax limits these to twenty and five nicknames. The fixed
        // scratch allowance covers both USERHOST's entry Vec and joined copy.
        UserQuery::Ison(targets) | UserQuery::Userhost(targets) => {
            Ok(Bounds::new(targets.len(), 1, 1))
        }
    }
}

fn whois(domain: &DomainState, target: &NicknameValue) -> Result<Bounds, DomainError> {
    let Some(session) = domain
        .resolve_nickname(target)
        .and_then(|id| domain.session(id))
    else {
        return Ok(Bounds::new(0, 2, 5));
    };
    let mut channels = 0_usize;
    let mut peak_members = 0_usize;
    for id in session.joined_channels() {
        channels = add(channels, 1)?;
        peak_members = peak_members.max(
            domain
                .channel(id)
                .map_or(0, |channel| channel.member_count()),
        );
    }
    // Every channel can produce at most one new chunk. One final319 is
    // emitted even with no visible channels, beside up to four other frames.
    Bounds::new(add(channels, 1)?, add(channels, 5)?, 5)
        .with_scratch(projection_bytes(peak_members)?)
}

fn mode(domain: &DomainState, query: &ModeCommand) -> Result<Bounds, DomainError> {
    match query {
        ModeCommand::UserQuery(_) => Ok(Bounds::new(1, 1, 2)),
        ModeCommand::ChannelQuery(name) => {
            Bounds::new(1, 2, 4).with_scratch(projection_bytes(channel_members(domain, name))?)
        }
        ModeCommand::ChannelList(name, list) => {
            let channel = domain
                .resolve_channel(name)
                .and_then(|id| domain.channel(id))
                .ok_or(DomainError::ServerBusy)?;
            let rows = channel.mask_list(*list).len();
            Bounds::new(rows, add(rows, 2)?, 5)
                .with_scratch(projection_bytes(channel.member_count())?)
        }
        _ => Err(DomainError::ServerBusy),
    }
}

fn presence(
    domain: &DomainState,
    requester: UserId,
    query: &PresenceCommand,
) -> Result<Bounds, DomainError> {
    let session = domain.session(requester).ok_or(DomainError::ServerBusy)?;
    let rows = session.monitored_nicknames().count();
    match query {
        PresenceCommand::MonitorList => Ok(Bounds::new(rows, add(rows, 1)?, 1)),
        PresenceCommand::MonitorStatus => {
            // Each cloned NicknameValue owns two separately charged Strings.
            let string_charge = MemoryCharge::allocation(32)
                .map_err(|_| DomainError::ServerBusy)?
                .bytes();
            let strings = usize::try_from(string_charge).map_err(|_| DomainError::ServerBusy)?;
            let per_row = add(multiply(strings, 2)?, 2 * size_of::<NicknameValue>())?;
            Bounds::new(rows, rows, 1).with_scratch(multiply(rows, per_row)?)
        }
        _ => Err(DomainError::ServerBusy),
    }
}

fn information(context: &StateCoreContext, query: InformationQuery) -> Result<Bounds, DomainError> {
    let (frames, middle) = match query {
        InformationQuery::Motd => (
            match context.motd() {
                Some(text) => add(crate::runtime_config::public_text_chunks(text).count(), 2)?,
                None => 1,
            },
            1,
        ),
        InformationQuery::Admin | InformationQuery::Info => (
            match context.public_info() {
                Some(text) => add(crate::runtime_config::public_text_chunks(text).count(), 1)?,
                None if query == InformationQuery::Admin => 2,
                None => 3,
            },
            1,
        ),
        InformationQuery::Lusers => (7, 3),
        InformationQuery::Time => (1, 2),
        InformationQuery::Version | InformationQuery::Links => (2, 1),
    };
    Ok(Bounds::new(frames, frames, middle))
}

#[cfg(test)]
mod tests {
    use agenc_relay_domain::{CanonicalCommand, ChannelTarget, ExternalInputs};
    use agenc_relay_testkit::{apply_command, channel_id, open_session, registered_admission};
    use agenc_relay_types::UtcSecond;

    use super::*;

    /// AUD-18: the NAMES frame bound still covers framed user masks for
    /// 32-byte nicknames, even though federated NAMES replies carry no masks
    /// today. Only the founder's token here carries a role byte, so 218 of
    /// the 219 tokens are 72 bytes; they need three 353 chunks and the 366,
    /// and the bare-cloak bound allowed three. The next test holds the bound
    /// at its worst case, every token a role byte and a framed mask.
    #[test]
    fn the_names_frame_bound_covers_the_longest_framed_tokens()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut state = DomainState::new()?;
        let channel = ChannelNameValue::parse("#longest-tokens")?;
        let mut requester = None;
        for seed in 1..=219_u8 {
            let member = open_session(&mut state, seed, &format!("M{seed:031}"), None)?;
            apply_command(
                &mut state,
                member,
                CanonicalCommand::join(vec![ChannelTarget::new(channel.clone(), false)])?,
                &registered_admission(member.user_id)?,
                Some(ExternalInputs {
                    utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_000)),
                    channel_ids: requester
                        .is_none()
                        .then(|| channel_id(80))
                        .into_iter()
                        .collect(),
                    ..ExternalInputs::default()
                }),
            )?;
            requester.get_or_insert(member);
        }
        let requester = requester.ok_or("requester")?;
        let bounds = names(&state, requester.user_id, std::slice::from_ref(&channel))?;
        let frames = crate::query_render::render_names(
            &state,
            "hub.example",
            "M0000000000000000000000000000001",
            requester.user_id,
            true,
            std::slice::from_ref(&channel),
        )?;
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.command())
                .collect::<Vec<_>>(),
            ["353", "353", "353", "366"]
        );
        assert!(
            frames.len() <= bounds.frames,
            "{} frames exceed the bound {}",
            frames.len(),
            bounds.frames
        );
        Ok(())
    }

    /// AUD-18, the worst case of the NAMES frame bound: the founder and 215
    /// voiced members each render a role byte and a framed mask for a 32-byte
    /// nickname, 73 bytes, and with its separator a full 8,000-byte chunk
    /// holds exactly 108 of them, `MIN_FULL_NAMES_ROWS`. With the requester
    /// the channel has 217 members, rendered as chunks of 108, 108 and 1 and
    /// the 366: four frames, which 217 / 108 + 2 admits and 217 / 109 + 2
    /// would not.
    #[test]
    fn the_names_frame_bound_covers_role_prefixed_framed_tokens()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut state = DomainState::new()?;
        let channel = ChannelNameValue::parse("#voiced-tokens")?;
        let external = |first: bool| {
            Some(ExternalInputs {
                utc_now: Some(UtcSecond::from_unix_seconds(1_720_000_000)),
                channel_ids: first.then(|| channel_id(80)).into_iter().collect(),
                ..ExternalInputs::default()
            })
        };
        let join = || CanonicalCommand::join(vec![ChannelTarget::new(channel.clone(), false)]);
        let mut founder = None;
        for seed in 1..=216_u8 {
            let nickname = format!("M{seed:031}");
            let member = open_session(&mut state, seed, &nickname, None)?;
            apply_command(
                &mut state,
                member,
                join()?,
                &registered_admission(member.user_id)?,
                external(founder.is_none()),
            )?;
            let Some(owner) = founder else {
                founder = Some(member);
                continue;
            };
            apply_command(
                &mut state,
                owner,
                CanonicalCommand::mode(
                    channel.clone(),
                    vec![agenc_relay_domain::ModeChange::Role {
                        operation: agenc_relay_domain::ModeOperation::Add,
                        target: NicknameValue::parse(&nickname)?,
                        role: agenc_relay_domain::Role::Voice,
                    }],
                )?,
                &registered_admission(owner.user_id)?,
                None,
            )?;
        }
        let nickname = format!("R{:031}", 217);
        let requester = open_session(&mut state, 217, &nickname, None)?;
        apply_command(
            &mut state,
            requester,
            join()?,
            &registered_admission(requester.user_id)?,
            external(false),
        )?;
        let bounds = names(&state, requester.user_id, std::slice::from_ref(&channel))?;
        let frames = crate::query_render::render_names(
            &state,
            "hub.example",
            &nickname,
            requester.user_id,
            true,
            std::slice::from_ref(&channel),
        )?;
        assert_eq!(
            frames
                .iter()
                .map(|frame| frame.command())
                .collect::<Vec<_>>(),
            ["353", "353", "353", "366"]
        );
        let chunks: Vec<&str> = frames.iter().filter_map(|frame| frame.trailing()).collect();
        assert_eq!(
            chunks
                .iter()
                .take(3)
                .map(|chunk| chunk.split(' ').count())
                .collect::<Vec<_>>(),
            [108, 108, 1]
        );
        assert_eq!(
            chunks
                .iter()
                .take(3)
                .flat_map(|chunk| chunk.split(' '))
                .filter(|token| token.len() == 1 + agenc_relay_client_wire::MAX_USER_MASK_BYTES)
                .count(),
            216
        );
        assert!(
            frames.len() <= bounds.frames,
            "{} frames exceed the bound {}",
            frames.len(),
            bounds.frames
        );
        assert_eq!((bounds.frames, MIN_FULL_NAMES_ROWS), (4, 108));
        Ok(())
    }
}
