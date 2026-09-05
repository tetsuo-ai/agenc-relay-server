//! Restored encrypted channels cannot own plaintext rows or unfinished purges.
#![forbid(unsafe_code)]

use super::*;
use agenc_ircd_domain::{
    ChannelModes, ChannelScope, DurableChannel, PersistencePolicy, Principal, Role, Visibility,
};
use agenc_ircd_storage::history_records::HistoryPurgeState;

fn restored_domain(policy: ContentPolicy) -> Result<DomainState, Box<dyn std::error::Error>> {
    let mut domain = DomainState::new()?;
    let (owner, _) = agenc_ircd_testkit::create_account(&mut domain, 1, 1)?;
    let channel = DurableChannel {
        channel_id: ChannelInstanceId::from_bytes([1; 16]),
        name: ChannelNameValue::parse("#history")?,
        scope: ChannelScope::Global,
        visibility: Visibility::Listed,
        content_policy: policy,
        persistence: PersistencePolicy::Registered,
        creator: Principal::Account(owner),
        created_at: agenc_ircd_types::UtcSecond::from_unix_seconds(1),
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
    Ok(DomainState::restore(
        domain.revision(),
        domain.durable_accounts().collect(),
        vec![channel],
        Vec::new(),
    )?)
}

fn retained_message() -> Result<HistoryMessageRecord, Box<dyn std::error::Error>> {
    Ok(HistoryMessageRecord {
        channel_id: ChannelInstanceId::from_bytes([1; 16]),
        channel_sequence: 1,
        message_id: MessageId::from_bytes([2; 16]),
        received_unix_milliseconds: 1_000,
        expires_unix_milliseconds: 3_601_000,
        retention_seconds: 3_600,
        channel_name: ChannelNameValue::parse("#history")?,
        sender: SourceView {
            user_id: UserId::from_bytes([3; 16]),
            nickname: NicknameValue::parse("HistorySender")?,
            public_cloak: agenc_ircd_testkit::deterministic_cloak(4)?,
            account_label: None,
        },
        kind: MessageKind::Privmsg,
        tags: Vec::new(),
        body: "retained plaintext".into(),
    })
}

#[test]
fn startup_rejects_encrypted_rows_and_pending_purges_with_history_enabled_or_disabled() -> TestResult
{
    for enabled in [false, true] {
        for (retained, purging) in [(false, false), (true, false), (false, true), (true, true)] {
            let mut history = empty(Arc::new(MemoryBudget::new(1_048_576)));
            history.enabled = enabled;
            let mut control =
                HistoryControlRecord::empty(ChannelInstanceId::from_bytes([1; 16]), 1)?;
            control.high_water_sequence = 1;
            if retained {
                control.retained_message_count = 1;
                control.retained_logical_bytes = 100;
            }
            if purging {
                control.purged_through = 1;
                control.purge = HistoryPurgeState::Active {
                    cutoff_sequence: 1,
                    last_scanned_sequence: u64::from(!retained),
                    operation_id: [5; 32],
                    audit_intent_sequence: 1,
                };
            }
            let control = HistoryControlRecord::decode(&control.encode()?)?;
            history.insert_control(control)?;
            if retained {
                history.insert_message(retained_message()?, 100)?;
            }
            assert!(
                history
                    .validate_loaded(&restored_domain(ContentPolicy::Plaintext)?)
                    .is_ok()
            );
            let result = history.validate_loaded(&restored_domain(ContentPolicy::E2eeBound)?);
            if retained || purging {
                assert!(
                    matches!(
                        result,
                        Err(RuntimeError::Storage(
                            agenc_ircd_storage::StorageError::StaleState
                        ))
                    ),
                    "accepted encrypted state: enabled={enabled}, retained={retained}, purging={purging}"
                );
            } else {
                assert!(
                    result.is_ok(),
                    "empty idle control prevented encrypted startup"
                );
            }
        }
    }
    Ok(())
}
