//! Typed history storage trust-boundary evidence.
#![forbid(unsafe_code)]

use agenc_ircd_domain::federation::SourceView;
use agenc_ircd_domain::{ChannelNameValue, MessageKind, NicknameValue};
use agenc_ircd_storage::history_records::*;
use agenc_ircd_storage::{
    PersistentRecordValue, ReadPlan, StorageError, StoredKey, TableId, validate_record_plaintext,
};
use agenc_ircd_types::{ChannelInstanceId, MessageId, PublicCloak, UserId};

pub(crate) fn message() -> Result<HistoryMessageRecord, StorageError> {
    Ok(HistoryMessageRecord {
        channel_id: ChannelInstanceId::from_bytes([1; 16]),
        channel_sequence: 1,
        message_id: MessageId::from_bytes([2; 16]),
        received_unix_milliseconds: 3_999_996_400_000,
        expires_unix_milliseconds: 4_000_000_000_000,
        retention_seconds: 3_600,
        channel_name: ChannelNameValue::parse("#history")
            .map_err(|_| StorageError::InvalidEncoding)?,
        sender: SourceView {
            user_id: UserId::from_bytes([3; 16]),
            nickname: NicknameValue::parse("Alice").map_err(|_| StorageError::InvalidEncoding)?,
            public_cloak: PublicCloak::from_components(*b"aaaaaaaaaa", *b"bbbbbbbbbbbbbbbb")
                .map_err(|_| StorageError::InvalidEncoding)?,
            account_label: None,
        },
        kind: MessageKind::Privmsg,
        tags: vec![("+example.org/test".into(), "value".into())],
        body: "retained message".into(),
    })
}

pub(crate) fn body(kind: u16) -> Result<Vec<u8>, StorageError> {
    match kind {
        1 => message()?.encode(),
        2 => HistoryControlRecord::empty(ChannelInstanceId::from_bytes([1; 16]), 7)?.encode(),
        _ => Err(StorageError::UnsupportedVersion),
    }
}

#[test]
fn history_rows_bind_their_channel_sequence_expiry_and_complete_body() -> Result<(), StorageError> {
    let message = message()?;
    let body = message.encode()?;
    assert!(HistoryMessageRecord::decode(&body)? == message);
    for length in 0..body.len() {
        assert!(
            HistoryMessageRecord::decode(body.get(..length).ok_or(StorageError::InvalidEncoding)?)
                .is_err()
        );
    }
    let key = history_message_key(message.channel_id, message.channel_sequence)?;
    let value = |expiry| {
        PersistentRecordValue::new(TableId::History, 1, 1, 0, expiry, Vec::new(), body.clone())?
            .encode()
    };
    validate_record_plaintext(TableId::History, &key, 1, &value(Some(4_000_000_000))?)?;
    assert!(
        validate_record_plaintext(TableId::History, &key, 1, &value(Some(3_999_999_999))?).is_err()
    );
    assert!(
        validate_record_plaintext(
            TableId::History,
            &history_message_key(message.channel_id, 2)?,
            1,
            &value(Some(4_000_000_000))?
        )
        .is_err()
    );
    let mut changed = message.clone();
    changed.expires_unix_milliseconds += 1;
    assert!(changed.encode().is_err());
    let mut changed = message.clone();
    changed.tags.push(("label".into(), "private".into()));
    assert!(changed.encode().is_err());
    let mut changed = message;
    changed.kind = MessageKind::Tagmsg;
    assert!(changed.encode().is_err());
    assert!(history_message_key(ChannelInstanceId::from_bytes([1; 16]), 0).is_err());
    Ok(())
}

#[test]
fn history_control_rejects_inconsistent_counts_and_purge_cursors() -> Result<(), StorageError> {
    let mut control = HistoryControlRecord::empty(ChannelInstanceId::from_bytes([1; 16]), 7)?;
    assert!(HistoryControlRecord::decode(&control.encode()?)? == control);
    control.retained_message_count = 1;
    assert!(control.encode().is_err());
    control.high_water_sequence = 10;
    control.retained_logical_bytes = 100;
    control.purged_through = 7;
    control.purge = HistoryPurgeState::Active {
        cutoff_sequence: 7,
        last_scanned_sequence: 8,
        operation_id: [1; 32],
        audit_intent_sequence: 1,
    };
    assert!(control.encode().is_err());
    control.purge = HistoryPurgeState::Active {
        cutoff_sequence: 7,
        last_scanned_sequence: 7,
        operation_id: [1; 32],
        audit_intent_sequence: 1,
    };
    assert!(HistoryControlRecord::decode(&control.encode()?)? == control);
    control.history_authorization_generation = 0;
    assert!(control.encode().is_err());
    Ok(())
}

#[test]
fn exact_key_reads_reject_empty_duplicate_and_excessive_selection() -> Result<(), StorageError> {
    assert!(ReadPlan::exact_keys(TableId::History, Vec::new()).is_err());
    let key = || history_control_key(ChannelInstanceId::from_bytes([1; 16]));
    assert!(ReadPlan::exact_keys(TableId::History, vec![key()?, key()?]).is_err());
    let keys = (1..=100)
        .map(|sequence| history_message_key(ChannelInstanceId::from_bytes([1; 16]), sequence))
        .collect::<Result<Vec<_>, _>>()?;
    ReadPlan::exact_keys(TableId::History, keys)?;
    let keys = (1..=101)
        .map(|sequence| history_message_key(ChannelInstanceId::from_bytes([1; 16]), sequence))
        .collect::<Result<Vec<_>, _>>()?;
    assert!(ReadPlan::exact_keys(TableId::History, keys).is_err());
    assert!(ReadPlan::exact_keys(TableId::History, vec![StoredKey::new(vec![1])?]).is_err());
    Ok(())
}

fn authorization() -> HistoryAuthorizationBinding {
    HistoryAuthorizationBinding {
        session_id: [3; 16],
        user_id: [4; 16],
        session_generation: 1,
        account_id: None,
        account_session_generation: 0,
        membership_revision: 2,
        history_authorization_generation: 3,
    }
}

fn request() -> HistoryRequestIdentity {
    HistoryRequestIdentity {
        replay_key: [5; 64],
        request_id: [6; 16],
        request_object_id: [7; 32],
        request_object: b"request-metadata".to_vec(),
    }
}

#[test]
fn history_result_records_retain_only_bounded_reconstruction_metadata() -> Result<(), StorageError>
{
    let mut record = HistoryCoordinatorResultRecord {
        request: request(),
        original_result_object_id: [8; 32],
        page: HistoryPageMetadata {
            authorization: authorization(),
            channel_id: [1; 16],
            channel_name: "#history".into(),
            snapshot_token: [9; 32],
            state_cut: 10,
            page_sequence: 0,
            next_cursor: None,
            selected: vec![HistoryRowReference {
                channel_sequence: 1,
                message_id: [2; 16],
                received_unix_milliseconds: 100,
                expires_unix_milliseconds: 3_600_100,
            }],
            created_unix_milliseconds: 101,
            deadline_unix_milliseconds: 60_101,
        },
        status: HistoryResultStatus::Available,
    };
    let encoded = record.encode()?;
    assert_eq!(HistoryCoordinatorResultRecord::decode(&encoded)?, record);
    for length in 0..encoded.len() {
        assert!(
            HistoryCoordinatorResultRecord::decode(
                encoded.get(..length).ok_or(StorageError::InvalidEncoding)?
            )
            .is_err()
        );
    }
    let value = PersistentRecordValue::new(
        TableId::RequestResult,
        HISTORY_COORDINATOR_RESULT_KIND,
        1,
        0,
        None,
        Vec::new(),
        encoded,
    )?
    .encode()?;
    validate_record_plaintext(
        TableId::RequestResult,
        &StoredKey::new(vec![5; 64])?,
        1,
        &value,
    )?;
    assert!(
        validate_record_plaintext(
            TableId::RequestResult,
            &StoredKey::new(vec![6; 64])?,
            1,
            &value
        )
        .is_err()
    );
    record.status = HistoryResultStatus::Expired {
        result_object_id: [10; 32],
    };
    assert_eq!(
        HistoryCoordinatorResultRecord::decode(&record.encode()?)?,
        record
    );
    let row = *record
        .page
        .selected
        .first()
        .ok_or(StorageError::InvalidEncoding)?;
    record.page.selected.push(row);
    assert!(record.encode().is_err());
    record.page.selected = vec![row; 101];
    assert!(record.encode().is_err());
    record.page.selected.clear();
    record.request.request_object = vec![0; MAX_HISTORY_REQUEST_BYTES + 1];
    assert!(record.encode().is_err());
    Ok(())
}

#[test]
fn history_edge_records_reject_impossible_render_and_expiry_states() -> Result<(), StorageError> {
    let mut record = HistoryEdgeRequestRecord {
        request: request(),
        original_result_object_id: None,
        expired_result_object_id: None,
        authorization: None,
        deadline_unix_milliseconds: 100,
        phase: HistoryEdgePhase::Pending,
        sink_gone: false,
    };
    assert_eq!(HistoryEdgeRequestRecord::decode(&record.encode()?)?, record);
    record.phase = HistoryEdgePhase::Rendered;
    assert!(record.encode().is_err());
    record.original_result_object_id = Some([8; 32]);
    record.authorization = Some(authorization());
    assert_eq!(HistoryEdgeRequestRecord::decode(&record.encode()?)?, record);
    record.phase = HistoryEdgePhase::Expired;
    assert!(record.encode().is_err());
    record.expired_result_object_id = Some([9; 32]);
    record.sink_gone = true;
    assert_eq!(HistoryEdgeRequestRecord::decode(&record.encode()?)?, record);
    record
        .authorization
        .as_mut()
        .ok_or(StorageError::InvalidEncoding)?
        .history_authorization_generation = 0;
    assert!(record.encode().is_err());
    Ok(())
}

fn invalid_message(adjust: impl FnOnce(&mut HistoryMessageRecord)) -> Result<bool, StorageError> {
    let mut record = message()?;
    adjust(&mut record);
    Ok(record.validate().is_err())
}

#[test]
fn history_messages_reject_each_shape_violation() -> Result<(), StorageError> {
    let local = ChannelNameValue::parse("&local").map_err(|_| StorageError::InvalidEncoding)?;
    assert!(invalid_message(|record| record.channel_sequence = 0)?);
    assert!(invalid_message(|record| record.channel_name = local)?);
    assert!(invalid_message(|record| record.retention_seconds = 10)?);
    assert!(invalid_message(|record| record.body = String::new())?);
    assert!(invalid_message(|record| {
        record.kind = MessageKind::Notice;
        record.body = "x".repeat(513);
    })?);
    assert!(invalid_message(|record| {
        record.tags = (0..17)
            .map(|index| (format!("+t/{index:02}"), "v".to_owned()))
            .collect();
    })?);
    assert!(!invalid_message(|record| {
        record.kind = MessageKind::Notice;
        record.body = String::new();
    })?);
    Ok(())
}

#[test]
fn history_message_tags_are_bounded_clean_and_sorted() -> Result<(), StorageError> {
    let long_key = format!("+{}", "k".repeat(255));
    let bad_tags: [Vec<(String, String)>; 7] = [
        vec![(long_key, "v".into())],
        vec![("+a b".into(), "v".into())],
        vec![("+agenc.ag/x".into(), "v".into())],
        vec![("+a".into(), "v".repeat(257))],
        vec![("+a".into(), "v\0".into())],
        vec![("+b".into(), "v".into()), ("+a".into(), "v".into())],
        vec![("+a".into(), "v".into()), ("+a".into(), "w".into())],
    ];
    for tags in bad_tags {
        assert!(invalid_message(|record| record.tags = tags)?);
    }
    Ok(())
}

#[test]
fn history_message_decoding_bounds_the_body_and_the_tag_count() -> Result<(), StorageError> {
    assert_eq!(
        HistoryMessageRecord::decode(&vec![0; 1 << 20]).err(),
        Some(StorageError::LimitExceeded)
    );
    let mut labelled = message()?;
    labelled.sender.account_label = Some(
        agenc_ircd_domain::AccountLabelValue::parse("alice")
            .map_err(|_| StorageError::InvalidEncoding)?,
    );
    let body = labelled.encode()?;
    assert!(HistoryMessageRecord::decode(&body)? == labelled);

    let mut untagged = message()?;
    untagged.tags.clear();
    let mut body = untagged.encode()?;
    let count_at = body.len() - 4 - untagged.body.len() - 2;
    assert_eq!(body.get(count_at..count_at + 2), Some([0, 0].as_slice()));
    *body
        .get_mut(count_at + 1)
        .ok_or(StorageError::InvalidEncoding)? = 17;
    assert_eq!(
        HistoryMessageRecord::decode(&body).err(),
        Some(StorageError::LimitExceeded)
    );
    Ok(())
}

#[test]
fn history_edge_records_need_a_deadline_and_exactly_their_phase_shape() -> Result<(), StorageError>
{
    let pending = HistoryEdgeRequestRecord {
        request: request(),
        original_result_object_id: None,
        expired_result_object_id: None,
        authorization: None,
        deadline_unix_milliseconds: 100,
        phase: HistoryEdgePhase::Pending,
        sink_gone: false,
    };
    let mut undated = pending.clone();
    undated.deadline_unix_milliseconds = 0;
    assert!(undated.encode().is_err(), "a record without a deadline");
    let mut pending_with_original = pending.clone();
    pending_with_original.original_result_object_id = Some([8; 32]);
    assert!(
        pending_with_original.encode().is_err(),
        "a pending record with an original result"
    );
    let mut pending_with_expired = pending.clone();
    pending_with_expired.expired_result_object_id = Some([9; 32]);
    assert!(
        pending_with_expired.encode().is_err(),
        "a pending record with an expired result"
    );
    let mut received_expired = pending.clone();
    received_expired.phase = HistoryEdgePhase::Received;
    received_expired.original_result_object_id = Some([8; 32]);
    received_expired.authorization = Some(authorization());
    received_expired.expired_result_object_id = Some([9; 32]);
    assert!(
        received_expired.encode().is_err(),
        "a received record with an expired result"
    );
    let mut expired_without_expiry = pending.clone();
    expired_without_expiry.phase = HistoryEdgePhase::Expired;
    expired_without_expiry.original_result_object_id = Some([8; 32]);
    assert!(
        expired_without_expiry.encode().is_err(),
        "an expired record without its expired result"
    );
    assert_eq!(
        HistoryEdgeRequestRecord::decode(&vec![0; MAX_HISTORY_RESULT_RECORD_BYTES + 1]).err(),
        Some(StorageError::LimitExceeded)
    );
    Ok(())
}

fn page() -> HistoryPageMetadata {
    HistoryPageMetadata {
        authorization: authorization(),
        channel_id: [1; 16],
        channel_name: "#history".into(),
        snapshot_token: [9; 32],
        state_cut: 10,
        page_sequence: 0,
        next_cursor: None,
        selected: vec![HistoryRowReference {
            channel_sequence: 1,
            message_id: [2; 16],
            received_unix_milliseconds: 100,
            expires_unix_milliseconds: 3_600_100,
        }],
        created_unix_milliseconds: 101,
        deadline_unix_milliseconds: 60_101,
    }
}

#[test]
fn history_page_metadata_rejects_each_scope_cut_deadline_and_row_bound() -> Result<(), StorageError>
{
    assert!(page().validate().is_ok());
    let row = *page()
        .selected
        .first()
        .ok_or(StorageError::InvalidEncoding)?;
    let mut local = page();
    local.channel_name = "&history".into();
    assert!(local.validate().is_err(), "a local channel");
    let mut no_cut = page();
    no_cut.state_cut = 0;
    assert!(no_cut.validate().is_err(), "a zero state cut");
    let mut deadline = page();
    deadline.deadline_unix_milliseconds = deadline.created_unix_milliseconds;
    assert!(deadline.validate().is_err(), "a deadline at creation");
    let mut beyond = page();
    beyond.selected = vec![HistoryRowReference {
        channel_sequence: 11,
        ..row
    }];
    assert!(beyond.validate().is_err(), "a row past the cut");
    let mut expired = page();
    expired.selected = vec![HistoryRowReference {
        expires_unix_milliseconds: row.received_unix_milliseconds,
        ..row
    }];
    assert!(expired.validate().is_err(), "a row expiring at receipt");
    let mut unordered = page();
    unordered.selected = vec![
        HistoryRowReference {
            channel_sequence: 2,
            ..row
        },
        row,
    ];
    assert!(unordered.validate().is_err(), "descending rows");
    let mut empty_request = HistoryCoordinatorResultRecord {
        request: request(),
        original_result_object_id: [8; 32],
        page: page(),
        status: HistoryResultStatus::Available,
    };
    empty_request.request.request_object.clear();
    assert!(empty_request.encode().is_err(), "an empty request object");
    Ok(())
}

#[test]
fn history_control_rejects_each_accounting_and_purge_bound() -> Result<(), StorageError> {
    let base = || -> Result<HistoryControlRecord, StorageError> {
        let mut control = HistoryControlRecord::empty(ChannelInstanceId::from_bytes([1; 16]), 7)?;
        control.high_water_sequence = 10;
        control.retained_message_count = 1;
        control.retained_logical_bytes = 100;
        control.purged_through = 7;
        Ok(control)
    };
    assert!(base()?.validate().is_ok());
    let mut too_many = base()?;
    too_many.high_water_sequence = 65_537;
    too_many.retained_message_count = 65_537;
    assert!(
        too_many.validate().is_err(),
        "more messages than the ceiling"
    );
    let mut too_large = base()?;
    too_large.retained_logical_bytes = 67_108_865;
    assert!(too_large.validate().is_err(), "more bytes than the ceiling");
    let mut purged_past_head = base()?;
    purged_past_head.purged_through = 11;
    assert!(
        purged_past_head.validate().is_err(),
        "a purge past the high water"
    );
    let mut bytes_without_messages = base()?;
    bytes_without_messages.retained_message_count = 0;
    assert!(
        bytes_without_messages.validate().is_err(),
        "bytes retained without messages"
    );
    let mut cutoff = base()?;
    cutoff.purge = HistoryPurgeState::Active {
        cutoff_sequence: 8,
        last_scanned_sequence: 8,
        operation_id: [1; 32],
        audit_intent_sequence: 1,
    };
    assert!(cutoff.validate().is_err(), "a cutoff past the purge point");
    let mut unnamed = base()?;
    unnamed.purge = HistoryPurgeState::Active {
        cutoff_sequence: 7,
        last_scanned_sequence: 7,
        operation_id: [0; 32],
        audit_intent_sequence: 1,
    };
    assert!(unnamed.validate().is_err(), "a purge without an operation");
    assert!(matches!(
        HistoryControlRecord::decode(&[0; 129]),
        Err(StorageError::LimitExceeded)
    ));
    Ok(())
}
