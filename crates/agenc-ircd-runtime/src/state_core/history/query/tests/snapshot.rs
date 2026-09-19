//! Frozen history cuts use durable state generations despite ephemeral domain revisions.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_domain::{
    ChannelModes, DomainState, DurableChannel, DurableMembership, HistorySelector, Principal, Role,
};
use agenc_ircd_storage::history_records::HistoryControlRecord;
use agenc_ircd_testkit::DomainTestIdentity;

fn channel(
    context: &StateCoreContext,
    identity: DomainTestIdentity,
) -> Result<DurableChannel, Box<dyn std::error::Error>> {
    let account = identity.account_id.ok_or("account")?;
    Ok(DurableChannel {
        channel_id: ChannelInstanceId::from_bytes([30; 16]),
        name: ChannelNameValue::parse("#history")?,
        scope: ChannelScope::Global,
        visibility: Visibility::Listed,
        content_policy: ContentPolicy::Plaintext,
        persistence: PersistencePolicy::Registered,
        creator: Principal::Account(account),
        created_at: context.utc_now()?,
        revision: context.domain.revision(),
        modes: ChannelModes::default(),
        key_verifier: None,
        member_limit: None,
        topic: None,
        memberships: vec![DurableMembership {
            user_id: identity.user_id,
            account_id: Some(account),
            session_role: Role::Member,
            effective_role: Role::Owner,
            membership_revision: context.domain.revision(),
            joined_at: context.utc_now()?,
        }],
        role_grants: vec![(account, Role::Owner)],
        bans: Vec::new(),
        exceptions: Vec::new(),
        invite_exceptions: Vec::new(),
        invites: Vec::new(),
        history: HistoryPolicy::OneHour,
        e2ee_removal_pending: Vec::new(),
        admin_quarantined: false,
    })
}

fn install_reader(
    context: &mut StateCoreContext,
) -> Result<(DomainTestIdentity, ChannelInstanceId), Box<dyn std::error::Error>> {
    install_reader_with(context, |_| Ok(()))
}

/// Installs the reader with one deliberate change to its channel row.
fn install_reader_with(
    context: &mut StateCoreContext,
    adjust: impl FnOnce(&mut DurableChannel) -> Result<(), Box<dyn std::error::Error>>,
) -> Result<(DomainTestIdentity, ChannelInstanceId), Box<dyn std::error::Error>> {
    context.enable_history_for_test(true);
    context.head.state_generation = 1;
    let account = seed_account(context, 20, 1)?;
    let identity = seed_session(context, 21, "HistoryReader", Some(account))?;
    let mut channel = channel(context, identity)?;
    adjust(&mut channel)?;
    let id = channel.channel_id;
    let mut session = context
        .domain
        .durable_session(identity.user_id)
        .ok_or("session")?;
    session.joined_channels.push(id);
    context.domain = DomainState::restore_authoritative(
        context.domain.revision(),
        context.domain.durable_accounts().collect(),
        vec![session],
        vec![channel],
        Vec::new(),
        context.now(),
        context.utc_now()?,
    )?;
    assert!(context.domain.revision().get() > context.head.state_generation);
    let history = context.history.as_mut().ok_or("history")?;
    let permit = history.reserve_index_entry()?;
    history.channels.insert(
        id,
        crate::state_core::history::HistoryChannel {
            control: HistoryControlRecord::empty(id, context.head.state_generation)?,
            rows: Default::default(),
            available_results: 0,
            _permit: permit,
        },
    );
    Ok((identity, id))
}

#[tokio::test]
async fn history_snapshot_cut_never_uses_an_ephemeral_domain_revision() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let (identity, id) = install_reader(context)?;
    let bound = crate::test_support::bound(identity);
    let snapshot = context.history_select(
        bound,
        id,
        HistoryQuery::new(HistorySelector::Latest(None), 1)?,
    )?;
    assert_eq!(
        snapshot.snapshot_state_generation,
        context.head.state_generation
    );
    assert!(
        context
            .history_restore_selection(
                bound,
                id,
                snapshot.authorization,
                HistorySelection::empty(),
                snapshot.channel_name.clone(),
                context.domain.revision().get(),
            )
            .is_err()
    );
    assert!(context.history_recheck(&snapshot).is_ok());
    Ok(())
}

fn latest() -> Result<HistoryQuery, Box<dyn std::error::Error>> {
    Ok(HistoryQuery::new(HistorySelector::Latest(None), 1)?)
}

#[tokio::test]
async fn history_authority_needs_a_live_coordinator_and_an_exact_session() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let (identity, id) = install_reader(context)?;
    let bound = crate::test_support::bound(identity);
    context.history.as_mut().ok_or("history")?.coordinator = false;
    assert!(context.history_select(bound, id, latest()?).is_err());
    context.history.as_mut().ok_or("history")?.coordinator = true;
    context.history.as_mut().ok_or("history")?.enabled = false;
    assert!(context.history_select(bound, id, latest()?).is_err());
    context.history.as_mut().ok_or("history")?.enabled = true;
    context.quiescing = true;
    assert!(context.history_select(bound, id, latest()?).is_err());
    context.quiescing = false;
    let other_session = BoundSession {
        session_id: SessionId::from_bytes([9; 16]),
        ..bound
    };
    assert!(
        context
            .history_select(other_session, id, latest()?)
            .is_err()
    );
    context.history_select(bound, id, latest()?)?;
    context.domain.admin_quarantine_channel(id)?;
    assert!(context.history_select(bound, id, latest()?).is_err());
    Ok(())
}

#[tokio::test]
async fn history_authority_needs_a_listed_registered_global_channel_with_history() -> TestResult {
    type Adjust = fn(&mut DurableChannel) -> Result<(), Box<dyn std::error::Error>>;
    let adjustments: [Adjust; 4] = [
        |channel| {
            channel.history = HistoryPolicy::Off;
            channel.visibility = Visibility::Unlisted;
            Ok(())
        },
        |channel| {
            channel.history = HistoryPolicy::Off;
            channel.persistence = PersistencePolicy::Ephemeral;
            channel.role_grants.clear();
            for membership in &mut channel.memberships {
                membership.session_role = Role::Owner;
            }
            Ok(())
        },
        |channel| {
            channel.history = HistoryPolicy::Off;
            Ok(())
        },
        |channel| {
            channel.history = HistoryPolicy::Off;
            channel.scope = ChannelScope::Local;
            channel.name = ChannelNameValue::parse("&history")?;
            Ok(())
        },
    ];
    for (index, adjust) in adjustments.into_iter().enumerate() {
        let mut fixture = StateCoreFixture::new(Vec::new())?;
        let context = fixture.context_mut()?;
        let (identity, id) = install_reader_with(context, adjust)
            .map_err(|error| format!("variant {index}: {error}"))?;
        let bound = crate::test_support::bound(identity);
        assert!(context.history_select(bound, id, latest()?).is_err());
    }
    Ok(())
}

#[tokio::test]
async fn restored_selections_reads_and_rechecks_are_bound_to_their_snapshot() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    let context = fixture.context_mut()?;
    let (identity, id) = install_reader(context)?;
    let bound = crate::test_support::bound(identity);
    let snapshot = context.history_select(bound, id, latest()?)?;
    let name = snapshot.channel_name.clone();
    let generation = snapshot.snapshot_state_generation;
    let mut other_authorization = snapshot.authorization;
    other_authorization.session_generation += 1;
    assert!(
        context
            .history_restore_selection(
                bound,
                id,
                other_authorization,
                HistorySelection::empty(),
                name.clone(),
                generation,
            )
            .is_err()
    );
    assert!(
        context
            .history_restore_selection(
                bound,
                id,
                snapshot.authorization,
                HistorySelection::empty(),
                name.clone(),
                0,
            )
            .is_err()
    );
    assert!(
        context
            .history_restore_selection(
                bound,
                id,
                snapshot.authorization,
                HistorySelection::empty(),
                ChannelNameValue::parse("#elsewhere")?,
                generation,
            )
            .is_err()
    );
    context.history_restore_selection(
        bound,
        id,
        snapshot.authorization,
        HistorySelection::empty(),
        name,
        generation,
    )?;

    assert!(context.history_read(&snapshot, &[]).is_err());
    let position = HistoryPosition::new(1, agenc_ircd_types::MessageId::from_bytes([1; 16]), 1)?;
    let many = vec![position; HISTORY_PAGE_MESSAGES + 1];
    assert!(context.history_read(&snapshot, &many).is_err());
    assert!(context.history_read(&snapshot, &[position]).is_err());

    let mut altered = context.history_select(bound, id, latest()?)?;
    altered.authorization.session_generation += 1;
    assert!(context.history_recheck(&altered).is_err());

    let now = context.history_now()?;
    let history = context.history.as_mut().ok_or("history")?;
    let permit = history.reserve_index_entry()?;
    let reference = HistoryRowReference {
        channel_sequence: 5,
        message_id: [7; 16],
        received_unix_milliseconds: now,
        expires_unix_milliseconds: now.checked_add(3_600_000).ok_or("expiry")?,
    };
    history.channels.get_mut(&id).ok_or("channel")?.rows.insert(
        5,
        crate::state_core::history::HistoryRow {
            reference,
            logical_bytes: 10,
            _permit: permit,
        },
    );
    let with_rows = context.history_select(bound, id, latest()?)?;
    assert_eq!(with_rows.references.len(), 1);
    context.history_recheck(&with_rows)?;
    let channel = context
        .history
        .as_mut()
        .ok_or("history")?
        .channels
        .get_mut(&id)
        .ok_or("channel")?;
    channel.control.purged_through = 5;
    assert!(context.history_recheck(&with_rows).is_err());
    let channel = context
        .history
        .as_mut()
        .ok_or("history")?
        .channels
        .get_mut(&id)
        .ok_or("channel")?;
    channel.control.purged_through = 0;
    channel.rows.get_mut(&5).ok_or("row")?.reference.message_id = [8; 16];
    assert!(context.history_recheck(&with_rows).is_err());
    Ok(())
}
