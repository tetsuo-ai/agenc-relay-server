//! A retired item cannot erase or redirect its mailbox sequence owner.

#![forbid(unsafe_code)]

use agenc_ircd_storage::e2ee_records::{
    MAILBOX_ROW_KIND, MAILBOX_SEQUENCE_ROW_KIND, MailboxRow, MailboxSequenceRow,
};

use super::*;

fn delivered(count: usize) -> TestResult<(Harness, Vec<u8>)> {
    let (mut source, _, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    for _ in 0..count {
        deliver_binding(&mut source, &binding)?;
    }
    Ok((source, binding))
}

fn acknowledge_first(source: &mut Harness, binding: &[u8]) -> TestResult<([u8; 32], Outcome)> {
    let page = ok(source.run(Op::FetchMailbox, &[2, 0], None)?)?;
    let token = page
        .responses
        .first()
        .and_then(|response| response.delivery_token)
        .ok_or("first token")?;
    let mut parameters = token.to_vec();
    parameters.extend_from_slice(&object_id(binding));
    Ok((
        token,
        ok(source.run(Op::AcknowledgeMailbox, &parameters, None)?)?,
    ))
}

fn owner(source: &Harness) -> TestResult<MailboxSequenceRow> {
    let mut owner = None;
    for write in &source.writes {
        let Write::Put {
            table: TableId::E2eeState,
            key,
            plaintext,
        } = write
        else {
            continue;
        };
        let value = PersistentRecordValue::decode(TableId::E2eeState, plaintext)?;
        if value.record_kind() == MAILBOX_SEQUENCE_ROW_KIND {
            assert!(owner.is_none(), "one mailbox scope in this fixture");
            owner = Some(MailboxSequenceRow::decode_keyed(key, value.body())?);
        }
    }
    owner.ok_or_else(|| "explicit mailbox owner".into())
}

fn item_sequences(source: &Harness) -> Vec<u64> {
    source
        .writes
        .iter()
        .filter_map(|write| {
            let Write::Put {
                table: TableId::E2eeState,
                key,
                ..
            } = write
            else {
                return None;
            };
            MailboxRow::parse_item_key(key)
                .ok()
                .map(|parts| parts.sequence)
        })
        .collect()
}

fn replace_owner(source: &mut Harness, next: u64) -> TestResult {
    let previous = owner(source)?;
    let row = MailboxSequenceRow::new(
        *previous.account_digest(),
        *previous.device_id(),
        previous.kind(),
        next,
    )?;
    let write = request::state_row(
        TableId::E2eeState,
        MAILBOX_SEQUENCE_ROW_KIND,
        row.key()?,
        row.encode()?,
    )
    .map_err(|code| format!("owner write failed: {code:?}"))?;
    source.apply_logical_write(&write)
}

#[test]
fn retiring_the_final_item_keeps_its_sequence_owner_across_restart() -> TestResult {
    let (mut source, binding) = delivered(1)?;
    assert_eq!(item_sequences(&source), vec![0]);
    let initial = owner(&source)?;
    assert_eq!(initial.next_sequence(), 1);
    let (token, ack) = acknowledge_first(&mut source, &binding)?;
    assert!(item_sequences(&source).is_empty());
    assert_eq!(owner(&source)?, initial);
    assert_eq!(ack.writes.len(), 3);
    let mut restored = source.reloaded()?;
    deliver_binding(&mut restored, &binding)?;
    assert_eq!(item_sequences(&restored), vec![1]);
    assert_eq!(owner(&restored)?.next_sequence(), 2);
    let before = retained_state(&restored)?;
    let mut parameters = token.to_vec();
    parameters.extend_from_slice(&object_id(&binding));
    let replay = ok(evaluate_request(
        &mut restored,
        Op::AcknowledgeMailbox,
        &parameters,
        None,
    )?)?;
    assert_eq!(
        replay.result,
        ResultBody::MailboxAcked(token, object_id(&binding))
    );
    assert!(replay.writes.is_empty());
    assert_eq!(retained_state(&restored)?, before);
    assert_eq!(restored.coordinator.state.mailboxes.item_count(), 1);
    Ok(())
}

#[test]
fn acknowledgement_retires_only_its_exact_sequence_when_objects_repeat() -> TestResult {
    let (mut source, binding) = delivered(2)?;
    assert_eq!(item_sequences(&source), vec![0, 1]);
    let (_, ack) = acknowledge_first(&mut source, &binding)?;
    let deleted_items: Vec<_> = ack
        .writes
        .iter()
        .filter_map(|write| {
            let Write::Delete {
                table: TableId::E2eeState,
                key,
            } = write
            else {
                return None;
            };
            MailboxRow::parse_item_key(key)
                .ok()
                .map(|parts| parts.sequence)
        })
        .collect();
    assert_eq!(deleted_items, vec![0]);
    assert_eq!(item_sequences(&source), vec![1]);
    let mut restored = source.reloaded()?;
    let page = ok(evaluate_request(
        &mut restored,
        Op::FetchMailbox,
        &[2, 0],
        None,
    )?)?;
    assert_eq!(page.result, ResultBody::MailboxPage);
    assert_eq!(page.responses.len(), 1);
    assert_eq!(
        page.responses.first().ok_or("remaining object")?.bytes,
        binding
    );
    assert_eq!(owner(&restored)?.next_sequence(), 2);
    Ok(())
}

#[test]
fn an_unapplied_acknowledgement_keeps_the_exact_item_token_and_owner() -> TestResult {
    let (mut source, binding) = delivered(1)?;
    let page = ok(source.run(Op::FetchMailbox, &[2, 0], None)?)?;
    let token = page
        .responses
        .first()
        .and_then(|row| row.delivery_token)
        .ok_or("token")?;
    let before = retained_state(&source)?;
    let mut parameters = token.to_vec();
    parameters.extend_from_slice(&object_id(&binding));
    let pending = ok(evaluate_request(
        &mut source,
        Op::AcknowledgeMailbox,
        &parameters,
        None,
    )?)?;
    assert_eq!(pending.writes.len(), 3);
    assert!(!pending.effects.is_empty());
    drop(pending);
    assert_eq!(retained_state(&source)?, before);
    assert_eq!(source.coordinator.state.mailboxes.item_count(), 1);
    let mut restored = source.reloaded()?;
    let page = ok(evaluate_request(
        &mut restored,
        Op::FetchMailbox,
        &[2, 0],
        None,
    )?)?;
    assert_eq!(
        page.responses.first().and_then(|row| row.delivery_token),
        Some(token)
    );
    Ok(())
}

#[test]
fn restored_mailboxes_refuse_missing_or_lowered_owners() -> TestResult {
    let (mut source, binding) = delivered(2)?;
    let owner_key = owner(&source)?.key()?;
    let mut absent = source.reloaded()?;
    absent
        .writes
        .retain(|write| !matches!(write, Write::Put { key, .. } if *key == owner_key));
    assert!(absent.reloaded().is_err());
    replace_owner(&mut source, 1)?;
    assert!(source.reloaded().is_err());
    let (mut ack_only, _) = delivered(1)?;
    acknowledge_first(&mut ack_only, &binding)?;
    ack_only
        .writes
        .retain(|write| !matches!(write, Write::Put { key, .. } if *key == owner_key));
    assert!(ack_only.reloaded().is_err());
    Ok(())
}

#[test]
fn an_exhausted_owner_refuses_delivery_without_reusing_an_item_sequence() -> TestResult {
    let (mut source, binding) = delivered(1)?;
    acknowledge_first(&mut source, &binding)?;
    replace_owner(&mut source, u64::MAX)?;
    let mut restored = source.reloaded()?;
    let before = retained_state(&restored)?;
    let mut parameters = account_param(&restored.account);
    parameters.extend_from_slice(&DEVICE_ID);
    assert_eq!(
        code(evaluate_request(
            &mut restored,
            Op::DeliverBinding,
            &parameters,
            Some(&binding)
        )?),
        Some(E2eeReplyCode::RateLimited)
    );
    assert_eq!(retained_state(&restored)?, before);
    assert_eq!(owner(&restored)?.next_sequence(), u64::MAX);
    assert_eq!(restored.coordinator.state.mailboxes.item_count(), 0);
    Ok(())
}

#[test]
fn the_acknowledgement_row_remains_an_exact_old_kind_eight_value() -> TestResult {
    let (mut source, binding) = delivered(1)?;
    let (_, ack) = acknowledge_first(&mut source, &binding)?;
    let values = ack
        .writes
        .iter()
        .filter_map(|write| {
            let Write::Put {
                table: TableId::E2eeState,
                plaintext,
                ..
            } = write
            else {
                return None;
            };
            Some(PersistentRecordValue::decode(TableId::E2eeState, plaintext))
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(values.len(), 1);
    let value = values.first().ok_or("ACK value")?;
    assert_eq!(value.record_kind(), MAILBOX_ROW_KIND);
    assert!(matches!(
        MailboxRow::decode(value.body())?,
        MailboxRow::Ack { .. }
    ));
    Ok(())
}
