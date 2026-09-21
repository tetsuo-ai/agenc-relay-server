#![forbid(unsafe_code)]
//! Selection and source facts survive both federation codec directions.

use super::*;
use agenc_relay_domain::federation::SourceView;
use agenc_relay_domain::{ChannelNameValue, MessageKind, NicknameValue};
use agenc_relay_storage::history_records::HistoryRowReference;
use agenc_relay_types::{ChannelInstanceId, PublicCloak, UserId};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn every_selector_round_trips_without_losing_reference_direction() -> TestResult {
    let message = HistoryReference::Message(MessageId::from_bytes([2; 16]));
    let timestamp = HistoryReference::Timestamp(HistoryTimestamp::new(1_700_000_000_123)?);
    for selector in [
        HistorySelector::Latest(None),
        HistorySelector::Latest(Some(message)),
        HistorySelector::Before(timestamp),
        HistorySelector::After(message),
        HistorySelector::Around(timestamp),
        HistorySelector::Between(message, timestamp),
        HistorySelector::Between(timestamp, message),
    ] {
        let query = HistoryQuery::new(selector, 100)?;
        assert_eq!(query_of(&selector_object(selector)?, 100)?, query);
    }
    Ok(())
}

#[test]
fn a_page_preserves_the_original_sender_time_ids_and_body() -> TestResult {
    let channel = ChannelNameValue::parse("#room")?;
    let message = HistoryMessageRecord {
        channel_id: ChannelInstanceId::from_bytes([1; 16]),
        channel_sequence: 10,
        message_id: MessageId::from_bytes([2; 16]),
        received_unix_milliseconds: 1_700_000_000_123,
        expires_unix_milliseconds: 1_700_003_600_123,
        retention_seconds: 3_600,
        channel_name: channel.clone(),
        sender: SourceView {
            user_id: UserId::from_bytes([3; 16]),
            nickname: NicknameValue::parse("old-nick")?,
            public_cloak: PublicCloak::parse("aaaaaaaaaa", "bbbbbbbbbbbbbbbb")?,
            account_label: None,
        },
        kind: MessageKind::Privmsg,
        tags: vec![("+example".into(), "original".into())],
        body: "original body".into(),
    };
    let metadata = HistoryPageMetadata {
        authorization: HistoryAuthorizationBinding {
            session_id: [4; 16],
            user_id: [5; 16],
            session_generation: 1,
            account_id: None,
            account_session_generation: 0,
            membership_revision: 1,
            history_authorization_generation: 1,
        },
        channel_id: [1; 16],
        channel_name: "#room".into(),
        snapshot_token: [6; 32],
        state_cut: 10,
        page_sequence: 0,
        next_cursor: None,
        selected: vec![HistoryRowReference {
            channel_sequence: 10,
            message_id: [2; 16],
            received_unix_milliseconds: message.received_unix_milliseconds,
            expires_unix_milliseconds: message.expires_unix_milliseconds,
        }],
        created_unix_milliseconds: 1_700_000_000_123,
        deadline_unix_milliseconds: 1_700_000_600_123,
    };
    let page = page_object(&metadata, std::slice::from_ref(&message))?;
    let decoded = messages_of(&page, &channel)?;
    assert!(decoded == vec![message]);
    assert_eq!(
        authorization_of(page.authorization()?.as_object())?,
        metadata.authorization
    );
    Ok(())
}
