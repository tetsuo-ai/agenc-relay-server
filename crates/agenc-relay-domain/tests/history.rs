#![forbid(unsafe_code)]

//! Deterministic history selector, ordering, and command-boundary regressions.

use agenc_relay_domain::{
    CanonicalCommand, CanonicalCommandView, ChannelCommand, HistoryError, HistoryPolicy,
    HistoryPosition, HistoryQuery, HistoryReference, HistorySelection, HistorySelector,
    HistoryTimestamp, select_history,
};
use agenc_relay_types::{ChannelInstanceId, MessageId};

fn positions() -> Result<Vec<HistoryPosition>, HistoryError> {
    (1_u8..=8)
        .map(|sequence| {
            HistoryPosition::new(
                u64::from(sequence),
                MessageId::from_bytes([9 - sequence; 16]),
                u64::from(sequence) * 1_000,
            )
        })
        .collect()
}

fn message(sequence: u8) -> HistoryReference {
    HistoryReference::Message(MessageId::from_bytes([9 - sequence; 16]))
}

fn timestamp(milliseconds: u64) -> Result<HistoryReference, HistoryError> {
    Ok(HistoryReference::Timestamp(HistoryTimestamp::new(
        milliseconds,
    )?))
}

fn selected(selector: HistorySelector, limit: u16) -> Result<Vec<u64>, HistoryError> {
    Ok(
        select_history(&HistoryQuery::new(selector, limit)?, &positions()?)?
            .positions()
            .iter()
            .map(|position| position.channel_sequence())
            .collect(),
    )
}

#[test]
fn exclusive_selectors_resolve_message_ids_by_event_position() -> Result<(), HistoryError> {
    assert_eq!(selected(HistorySelector::Latest(None), 3)?, vec![6, 7, 8]);
    assert_eq!(
        selected(HistorySelector::Latest(Some(message(3))), 3)?,
        vec![6, 7, 8]
    );
    assert_eq!(
        selected(HistorySelector::Latest(Some(message(7))), 3)?,
        vec![8]
    );
    assert_eq!(
        selected(HistorySelector::Before(message(5)), 3)?,
        vec![2, 3, 4]
    );
    assert_eq!(
        selected(HistorySelector::After(message(3)), 3)?,
        vec![4, 5, 6]
    );
    assert_eq!(
        selected(HistorySelector::Between(message(2), message(7)), 2)?,
        vec![3, 4]
    );
    assert_eq!(
        selected(HistorySelector::Between(message(7), message(2)), 2)?,
        vec![5, 6]
    );
    Ok(())
}

#[test]
fn mixed_between_keeps_direction_but_renders_chronologically() -> Result<(), HistoryError> {
    assert_eq!(
        selected(HistorySelector::Between(timestamp(2_000)?, message(7)), 2)?,
        vec![3, 4]
    );
    assert_eq!(
        selected(HistorySelector::Between(message(7), timestamp(2_000)?), 2)?,
        vec![5, 6]
    );
    assert_eq!(
        selected(
            HistorySelector::Between(timestamp(7_000)?, timestamp(2_000)?),
            100
        )?,
        vec![3, 4, 5, 6]
    );
    assert!(selected(HistorySelector::Between(message(3), timestamp(3_000)?), 100)?.is_empty());
    assert!(
        selected(
            HistorySelector::Between(timestamp(3_000)?, timestamp(3_000)?),
            100
        )?
        .is_empty()
    );
    Ok(())
}

#[test]
fn around_includes_the_pivot_and_backfills_at_either_boundary() -> Result<(), HistoryError> {
    assert_eq!(selected(HistorySelector::Around(message(5)), 1)?, vec![5]);
    assert_eq!(
        selected(HistorySelector::Around(message(5)), 4)?,
        vec![4, 5, 6, 7]
    );
    assert_eq!(
        selected(HistorySelector::Around(message(1)), 4)?,
        vec![1, 2, 3, 4]
    );
    assert_eq!(
        selected(HistorySelector::Around(message(8)), 4)?,
        vec![5, 6, 7, 8]
    );
    assert_eq!(
        selected(HistorySelector::Around(timestamp(4_001)?), 3)?,
        vec![4, 5, 6]
    );
    assert_eq!(
        selected(HistorySelector::Around(timestamp(99_000)?), 3)?,
        vec![6, 7, 8]
    );
    Ok(())
}

#[test]
fn timestamp_exclusion_removes_all_rows_at_the_boundary_time() -> Result<(), HistoryError> {
    let rows = vec![
        HistoryPosition::new(1, MessageId::from_bytes([4; 16]), 1_000)?,
        HistoryPosition::new(2, MessageId::from_bytes([3; 16]), 2_000)?,
        HistoryPosition::new(3, MessageId::from_bytes([2; 16]), 2_000)?,
        HistoryPosition::new(4, MessageId::from_bytes([1; 16]), 3_000)?,
    ];
    let before = HistoryQuery::new(HistorySelector::Before(timestamp(2_000)?), 100)?;
    let after = HistoryQuery::new(HistorySelector::After(timestamp(2_000)?), 100)?;
    assert_eq!(
        select_history(&before, &rows)?.positions(),
        rows.get(..1).ok_or(HistoryError::InvalidPosition)?
    );
    assert_eq!(
        select_history(&after, &rows)?.positions(),
        rows.get(3..).ok_or(HistoryError::InvalidPosition)?
    );
    let around = HistoryQuery::new(HistorySelector::Around(timestamp(2_000)?), 1)?;
    assert_eq!(
        select_history(&around, &rows)?.positions(),
        rows.get(1..2).ok_or(HistoryError::InvalidPosition)?
    );
    Ok(())
}

#[test]
fn empty_and_unknown_references_are_distinct_for_the_replay_owner() -> Result<(), HistoryError> {
    let latest = HistoryQuery::new(HistorySelector::Latest(None), 100)?;
    assert_eq!(select_history(&latest, &[])?, HistorySelection::empty());
    let around = HistoryQuery::new(HistorySelector::Around(timestamp(1)?), 100)?;
    assert_eq!(select_history(&around, &[])?, HistorySelection::empty());
    let unknown = HistoryReference::Message(MessageId::from_bytes([99; 16]));
    assert_eq!(
        selected(HistorySelector::After(unknown), 1),
        Err(HistoryError::UnknownReference)
    );
    assert_eq!(
        selected(HistorySelector::Between(message(2), unknown), 1),
        Err(HistoryError::UnknownReference)
    );
    Ok(())
}

#[test]
fn constructors_and_selection_reject_invalid_metadata() -> Result<(), HistoryError> {
    assert_eq!(
        HistoryQuery::new(HistorySelector::Latest(None), 0),
        Err(HistoryError::InvalidLimit)
    );
    assert_eq!(
        HistoryQuery::new(HistorySelector::Latest(None), 101),
        Err(HistoryError::InvalidLimit)
    );
    assert_eq!(
        HistoryTimestamp::new(0),
        Err(HistoryError::InvalidTimestamp)
    );
    assert_eq!(
        HistoryPosition::new(0, MessageId::from_bytes([1; 16]), 1),
        Err(HistoryError::InvalidPosition)
    );
    assert_eq!(
        HistoryPosition::new(1, MessageId::from_bytes([1; 16]), 0),
        Err(HistoryError::InvalidPosition)
    );
    let mut rows = positions()?;
    rows.reverse();
    assert_eq!(HistorySelection::new(rows), Err(HistoryError::InvalidOrder));
    let one = HistoryPosition::new(1, MessageId::from_bytes([1; 16]), 1)?;
    assert_eq!(
        HistorySelection::new(vec![one; 101]),
        Err(HistoryError::InvalidLimit)
    );
    assert_eq!(
        HistorySelection::new(vec![one; 2]),
        Err(HistoryError::InvalidOrder)
    );
    Ok(())
}

#[test]
fn command_retains_selector_and_on_requires_an_authoritative_default()
-> Result<(), Box<dyn std::error::Error>> {
    let channel = ChannelInstanceId::from_bytes([1; 16]);
    let query = HistoryQuery::new(HistorySelector::Between(message(7), message(2)), 3)?;
    let command = CanonicalCommand::history_query(channel, query);
    assert!(
        matches!(command.view(), CanonicalCommandView::Chathistory(id, actual) if id == channel && actual == query)
    );
    let command = CanonicalCommand::channel(ChannelCommand::HistoryDefault(channel))
        .resolve_history_default(HistoryPolicy::SevenDays)?;
    assert!(
        matches!(command.view(), CanonicalCommandView::Channel(ChannelCommand::History(id, HistoryPolicy::SevenDays)) if id == channel)
    );
    assert!(
        CanonicalCommand::channel(ChannelCommand::HistoryDefault(channel))
            .resolve_history_default(HistoryPolicy::Off)
            .is_err()
    );
    Ok(())
}
