//! Metadata must be usable by the selector before it enters the startup index.
#![forbid(unsafe_code)]

use super::*;

mod encrypted;
use agenc_relay_domain::federation::SourceView;
use agenc_relay_domain::{ChannelNameValue, MessageKind, NicknameValue};
use agenc_relay_types::{ChannelInstanceId, MessageId, UserId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn empty(budget: Arc<MemoryBudget>) -> HistoryState {
    HistoryState {
        enabled: true,
        coordinator: true,
        default: HistoryPolicy::OneHour,
        budget,
        maximum_bytes: MAX_TOTAL_BYTES,
        maximum_index_bytes: MAX_INDEX_BYTES,
        index_bytes: 0,
        message_count: 0,
        logical_bytes: 0,
        channels: BTreeMap::new(),
        queries: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    }
}

#[test]
fn storage_valid_zero_timestamp_is_refused_before_index_insertion() -> TestResult {
    let budget = Arc::new(MemoryBudget::new(1_048_576));
    let mut history = empty(Arc::clone(&budget));
    let channel_id = ChannelInstanceId::from_bytes([1; 16]);
    history.insert_control(HistoryControlRecord::empty(channel_id, 1)?)?;
    let message = HistoryMessageRecord {
        channel_id,
        channel_sequence: 1,
        message_id: MessageId::from_bytes([2; 16]),
        received_unix_milliseconds: 0,
        expires_unix_milliseconds: 3_600_000,
        retention_seconds: 3_600,
        channel_name: ChannelNameValue::parse("#history")?,
        sender: SourceView {
            user_id: UserId::from_bytes([3; 16]),
            nickname: NicknameValue::parse("HistorySender")?,
            public_cloak: agenc_relay_testkit::deterministic_cloak(4)?,
            account_label: None,
        },
        kind: MessageKind::Privmsg,
        tags: Vec::new(),
        body: "message".into(),
    };
    assert!(message.validate().is_ok());
    assert!(history.insert_message(message, 100).is_err());
    assert!(
        history
            .channels
            .get(&channel_id)
            .ok_or("channel")?
            .rows
            .is_empty()
    );
    assert_eq!(history.message_count, 0);
    drop(history);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn startup_control_cannot_name_a_future_authority_or_message_cut() -> TestResult {
    let mut control = HistoryControlRecord::empty(ChannelInstanceId::from_bytes([1; 16]), 3)?;
    assert!(validate_control_cut(&control, 2).is_err());
    assert!(validate_control_cut(&control, 3).is_ok());
    control.high_water_sequence = 4;
    assert!(validate_control_cut(&control, 3).is_err());
    assert!(validate_control_cut(&control, 4).is_ok());
    Ok(())
}

#[test]
fn coordinator_requires_live_history_controls_while_edges_keep_only_projection() -> TestResult {
    use agenc_relay_domain::{
        ChannelModes, ChannelScope, DurableChannel, PersistencePolicy, Principal, Role, Visibility,
    };
    let mut domain = DomainState::new()?;
    let (owner, _) = agenc_relay_testkit::create_account(&mut domain, 1, 1)?;
    let channel_id = ChannelInstanceId::from_bytes([1; 16]);
    let channel = DurableChannel {
        channel_id,
        name: ChannelNameValue::parse("#history")?,
        scope: ChannelScope::Global,
        visibility: Visibility::Listed,
        content_policy: ContentPolicy::Plaintext,
        persistence: PersistencePolicy::Registered,
        creator: Principal::Account(owner),
        created_at: agenc_relay_types::UtcSecond::from_unix_seconds(1),
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
        history: HistoryPolicy::OneHour,
        e2ee_removal_pending: Vec::new(),
        admin_quarantined: false,
    };
    let domain = DomainState::restore(
        domain.revision(),
        domain.durable_accounts().collect(),
        vec![channel],
        Vec::new(),
    )?;
    let mut history = empty(Arc::new(MemoryBudget::new(1_048_576)));
    assert!(history.validate_loaded(&domain).is_err());
    history.coordinator = false;
    assert!(history.validate_loaded(&domain).is_ok());
    history.coordinator = true;
    history.insert_control(HistoryControlRecord::empty(
        channel_id,
        domain.revision().get(),
    )?)?;
    assert!(history.validate_loaded(&domain).is_ok());
    Ok(())
}
