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
    context.enable_history_for_test(true);
    context.head.state_generation = 1;
    let account = seed_account(context, 20, 1)?;
    let identity = seed_session(context, 21, "HistoryReader", Some(account))?;
    let channel = channel(context, identity)?;
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
