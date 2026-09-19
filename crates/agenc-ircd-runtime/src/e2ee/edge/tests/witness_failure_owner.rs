#![forbid(unsafe_code)]

//! The witness failure owner releases or marks only the durable row of the conversation it
//! holds; a staged row, another conversation or no row at all leaves it untouched.

use super::*;

fn row() -> WitnessRow {
    WitnessRow {
        event_kind: 1,
        expected_sequence: 4,
        expected_head_id: [4; 32],
        observed_sequence: 6,
        observed_id: [6; 32],
        observed_predecessor_id: Some([5; 32]),
        conflict: false,
    }
}

fn holding(conversation: [u8; 32], durable: bool) -> WitnessFailure {
    WitnessFailure {
        timer: None,
        record: Some(Record {
            conversation,
            row: row(),
            link: None,
            staged: None,
            durable,
        }),
    }
}

#[test]
fn a_durable_row_is_released_only_for_its_own_conversation() {
    let mut empty = WitnessFailure::default();
    assert!(!empty.forget_durable(&[1; 32]));
    let mut staged = holding([1; 32], false);
    assert!(!staged.forget_durable(&[1; 32]));
    assert!(staged.record.is_some(), "a staged row is not released");
    let mut other = holding([2; 32], true);
    assert!(!other.forget_durable(&[1; 32]));
    assert!(other.record.is_some());
    let mut owner = holding([1; 32], true);
    assert!(owner.durable());
    assert!(owner.forget_durable(&[1; 32]));
    assert!(owner.record.is_none());
}

#[test]
fn a_conflict_is_marked_only_on_the_durable_row_of_its_conversation() {
    let mut empty = WitnessFailure::default();
    assert!(!empty.mark_conflict(&[1; 32]));
    let mut staged = holding([1; 32], false);
    assert!(!staged.mark_conflict(&[1; 32]));
    let mut other = holding([2; 32], true);
    assert!(!other.mark_conflict(&[1; 32]));
    let mut owner = holding([1; 32], true);
    assert!(owner.mark_conflict(&[1; 32]));
    assert!(
        !owner.durable(),
        "a conflict row blocks only its conversation"
    );
    assert!(owner.durable_row().is_some_and(|(_, row)| row.conflict));
}
