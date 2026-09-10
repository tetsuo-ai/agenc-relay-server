//! Restart admission uses the exact surviving logical mailbox rows.

#![forbid(unsafe_code)]

use super::*;

#[path = "mailbox_sequence_owner.rs"]
mod sequence_owner;

#[test]
fn an_acknowledged_mailbox_item_is_absent_after_reconstruction() -> TestResult {
    let (mut source, _, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    deliver_binding(&mut source, &binding)?;
    let page = ok(source.run(Op::FetchMailbox, &[2, 0], None)?)?;
    let token = page
        .responses
        .first()
        .and_then(|response| response.delivery_token)
        .ok_or("mailbox token")?;
    let mut parameters = token.to_vec();
    parameters.extend_from_slice(&object_id(&binding));
    let ack = ok(source.run(Op::AcknowledgeMailbox, &parameters, None)?)?;
    assert_eq!(source.coordinator.state.mailboxes.item_count(), 0);
    apply_fixture_deletions(&mut source, &ack.writes);
    let mut restored = source.reloaded()?;
    let fetch = ok(evaluate_request(
        &mut restored,
        Op::FetchMailbox,
        &[2, 0],
        None,
    )?)?;
    assert_eq!(fetch.result, ResultBody::Empty(EmptyKind::Binding));
    assert!(fetch.responses.is_empty());
    assert!(fetch.writes.is_empty());
    assert_eq!(restored.coordinator.state.mailboxes.item_count(), 0);
    Ok(())
}

/// Harness::run retains Put rows only. Apply every actual Delete before
/// reconstructing, so the regression does not depend on that fixture shortcut.
fn apply_fixture_deletions(source: &mut Harness, writes: &[Write]) {
    for write in writes {
        let Write::Delete { table, key } = write else {
            continue;
        };
        source.writes.retain(|row| {
            !matches!(row, Write::Put { table: stored_table, key: stored_key, .. }
                if stored_table == table && stored_key == key)
        });
    }
}
