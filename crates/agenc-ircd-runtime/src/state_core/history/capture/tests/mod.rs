//! Plaintext retention must not cross the encrypted binding boundary.
#![forbid(unsafe_code)]

use super::*;
use crate::test_support::StateCoreFixture;
use agenc_ircd_domain::{
    ChannelModes, ChannelNameValue, DurableChannel, NicknameValue, Principal, Role,
};
use agenc_ircd_types::{MessageId, UserId, UtcSecond};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn channel() -> TestResult<(DomainState, DurableChannel)> {
    let mut domain = DomainState::new()?;
    let (owner, _) = agenc_ircd_testkit::create_account(&mut domain, 1, 1)?;
    let channel = DurableChannel {
        channel_id: ChannelInstanceId::from_bytes([1; 16]),
        name: ChannelNameValue::parse("#history")?,
        scope: ChannelScope::Global,
        visibility: Visibility::Listed,
        content_policy: ContentPolicy::Plaintext,
        persistence: PersistencePolicy::Registered,
        creator: Principal::Account(owner),
        created_at: UtcSecond::from_unix_seconds(1),
        revision: domain.revision(),
        modes: ChannelModes::default(),
        key_verifier: None,
        member_limit: None,
        topic: None,
        memberships: Vec::new(),
        role_grants: vec![(owner, Role::Owner)],
        bans: Vec::new(),
        exceptions: Vec::new(),
        invite_exceptions: Vec::new(),
        invites: Vec::new(),
        history: HistoryPolicy::Off,
        e2ee_removal_pending: Vec::new(),
        admin_quarantined: false,
    };
    Ok((domain, channel))
}

fn message(channel: &DurableChannel) -> TestResult<HistoryMessageRecord> {
    Ok(HistoryMessageRecord {
        channel_id: channel.channel_id,
        channel_sequence: channel.revision.get(),
        message_id: MessageId::from_bytes([2; 16]),
        received_unix_milliseconds: 1_000,
        expires_unix_milliseconds: 3_601_000,
        retention_seconds: 3_600,
        channel_name: channel.name.clone(),
        sender: SourceView {
            user_id: UserId::from_bytes([3; 16]),
            nickname: NicknameValue::parse("Sender")?,
            public_cloak: agenc_ircd_testkit::deterministic_cloak(4)?,
            account_label: None,
        },
        kind: MessageKind::Privmsg,
        tags: Vec::new(),
        body: "retained plaintext".into(),
    })
}

#[tokio::test]
async fn retained_plaintext_and_pending_purge_each_refuse_encrypted_binding() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    fixture.context_mut()?.enable_history_for_test(true);
    let history = fixture.context_mut()?.history.as_mut().ok_or("history")?;
    let (domain, mut channel) = channel()?;
    let mut pending = HistoryMutation::new();
    history.admit_message(
        &mut pending,
        message(&channel)?,
        &mut Vec::new(),
        channel.revision.get(),
    )?;
    history.committed(pending)?;
    channel.content_policy = ContentPolicy::E2eeBound;
    assert!(history.policy_needs_control(&domain, &channel).is_err());
    let (_, purge) = history.prepare_purge(
        channel.channel_id,
        channel.revision.get() + 1,
        [5; 32],
        0,
        channel.revision.get() + 1,
    )?;
    history.committed(purge)?;
    assert!(history.policy_needs_control(&domain, &channel).is_err());
    assert!(history.has_messages_or_purge(channel.channel_id));
    Ok(())
}

#[tokio::test]
async fn empty_control_does_not_block_binding_and_bound_channel_rejects_plaintext_capture()
-> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    fixture.context_mut()?.enable_history_for_test(true);
    let history = fixture.context_mut()?.history.as_mut().ok_or("history")?;
    let (domain, mut channel) = channel()?;
    let (_, empty) = history.prepare_purge(
        channel.channel_id,
        channel.revision.get(),
        [5; 32],
        0,
        channel.revision.get(),
    )?;
    history.committed(empty)?;
    channel.content_policy = ContentPolicy::E2eeBound;
    assert!(history.policy_needs_control(&domain, &channel).is_ok());
    assert!(!history.has_messages_or_purge(channel.channel_id));
    let domain = DomainState::restore(
        domain.revision(),
        domain.durable_accounts().collect(),
        vec![channel.clone()],
        Vec::new(),
    )?;
    let plan = domain.plan_account_service_checkpoint()?;
    let intent = MutationContext::default();
    let input = CaptureInput {
        domain: &domain,
        plan: &plan,
        intent: &intent,
        wall_trusted: true,
        accepting_generation: 1,
    };
    assert!(
        validate_message_channel(&input, domain.channel(channel.channel_id).ok_or("channel")?)
            .is_err()
    );
    Ok(())
}
