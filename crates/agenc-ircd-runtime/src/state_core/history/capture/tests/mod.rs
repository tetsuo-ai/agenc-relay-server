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

fn restored(domain: &DomainState, channel: &DurableChannel) -> TestResult<DomainState> {
    Ok(DomainState::restore(
        domain.revision(),
        domain.durable_accounts().collect(),
        vec![channel.clone()],
        Vec::new(),
    )?)
}

#[tokio::test]
async fn message_channels_need_a_trusted_clock_and_a_listed_global_registered_channel() -> TestResult
{
    let (domain, base) = channel()?;
    let plan = domain.plan_account_service_checkpoint()?;
    let intent = MutationContext::default();
    let untrusted = CaptureInput {
        domain: &domain,
        plan: &plan,
        intent: &intent,
        wall_trusted: false,
        accepting_generation: 1,
    };
    let live = restored(&domain, &base)?;
    assert!(
        validate_message_channel(&untrusted, live.channel(base.channel_id).ok_or("channel")?)
            .is_err()
    );
    let mut unlisted = base.clone();
    unlisted.visibility = Visibility::Unlisted;
    let live = restored(&domain, &unlisted)?;
    let plan = live.plan_account_service_checkpoint()?;
    let input = CaptureInput {
        domain: &live,
        plan: &plan,
        intent: &intent,
        wall_trusted: true,
        accepting_generation: 1,
    };
    assert!(
        validate_message_channel(&input, live.channel(base.channel_id).ok_or("channel")?).is_err()
    );
    let mut quarantined = restored(&domain, &base)?;
    quarantined.admin_quarantine_channel(base.channel_id)?;
    let plan = quarantined.plan_account_service_checkpoint()?;
    let input = CaptureInput {
        domain: &quarantined,
        plan: &plan,
        intent: &intent,
        wall_trusted: true,
        accepting_generation: 1,
    };
    assert!(
        validate_message_channel(
            &input,
            quarantined.channel(base.channel_id).ok_or("channel")?
        )
        .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn policy_changes_are_detected_field_by_field() -> TestResult {
    let (domain, base) = channel()?;
    let live = restored(&domain, &base)?;
    assert!(!policy_changed(&live, &base));
    let mut persistence = base.clone();
    persistence.persistence = PersistencePolicy::Ephemeral;
    assert!(policy_changed(&live, &persistence));
    let mut quarantined = base.clone();
    quarantined.admin_quarantined = true;
    assert!(policy_changed(&live, &quarantined));
    Ok(())
}

#[tokio::test]
async fn admitted_messages_advance_the_high_water_mark_and_changes_apply_exactly() -> TestResult {
    let mut fixture = StateCoreFixture::new(Vec::new())?;
    fixture.context_mut()?.enable_history_for_test(true);
    let history = fixture.context_mut()?.history.as_mut().ok_or("history")?;
    let (_, channel) = channel()?;
    let revision = channel.revision.get();
    let mut pending = HistoryMutation::new();
    history.admit_message(&mut pending, message(&channel)?, &mut Vec::new(), revision)?;
    history.committed(pending)?;

    let mut repeated = HistoryMutation::new();
    assert!(
        history
            .admit_message(&mut repeated, message(&channel)?, &mut Vec::new(), revision)
            .is_err(),
        "a sequence at or below the high-water mark is corrupt"
    );

    let unknown_deletion = || -> TestResult<HistoryMutation> {
        let mut pending = HistoryMutation::new();
        pending.changes.insert(
            channel.channel_id,
            ChannelChange {
                control: HistoryControlRecord::empty(channel.channel_id, revision)?,
                new_control_permit: None,
                rows: Vec::new(),
                deleted: vec![999],
                remove_control: false,
            },
        );
        Ok(pending)
    };
    assert!(history.committed(unknown_deletion()?).is_err());

    let permit = history.reserve_index_entry()?;
    let mut duplicate = HistoryMutation::new();
    duplicate.changes.insert(
        channel.channel_id,
        ChannelChange {
            control: HistoryControlRecord::empty(channel.channel_id, revision)?,
            new_control_permit: None,
            rows: vec![HistoryRow {
                reference: row_reference(&message(&channel)?),
                logical_bytes: 1,
                _permit: permit,
            }],
            deleted: Vec::new(),
            remove_control: false,
        },
    );
    assert!(history.committed(duplicate).is_err());

    let mut removal = HistoryMutation::new();
    removal.changes.insert(
        channel.channel_id,
        ChannelChange {
            control: HistoryControlRecord::empty(channel.channel_id, revision)?,
            new_control_permit: None,
            rows: Vec::new(),
            deleted: Vec::new(),
            remove_control: true,
        },
    );
    assert!(
        history.committed(removal).is_err(),
        "a control with retained rows cannot be removed"
    );
    Ok(())
}
