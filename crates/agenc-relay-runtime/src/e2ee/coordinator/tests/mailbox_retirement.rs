//! ACK retirement keeps the stored application while releasing its final resident reference.
#![forbid(unsafe_code)]
use super::*;
use crate::e2ee::coordinator::resident;
use crate::e2ee::coordinator::tests::support::private_message_bytes;
use agenc_relay_domain::e2ee::mailbox::Grant as DeliveryGrant;
use agenc_relay_e2ee::objects::aad::ArcApplicationAad;
use agenc_relay_storage::e2ee_records::{MAILBOX_ROW_KIND, MailboxRow};

fn application_mailbox() -> TestResult<(Harness, Vec<u8>, [u8; 32])> {
    let (mut source, conversation, _) = finalization_fixture()?;
    let metadata = source
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("conversation")?;
    let aad = ArcApplicationAad {
        profile_version: 1,
        network_id: NETWORK,
        conversation_id: conversation,
        route_binding: metadata.route_binding,
        latest_state_id: [22; 32],
    }
    .encode()?;
    let bytes = wire_raw(
        ArcWireObjectKind::ApplicationMls,
        private_message_bytes(metadata.group_id.as_slice(), 1, &aad)?,
    )?;
    let origin = source
        .coordinator
        .state
        .origins
        .values()
        .next()
        .ok_or("origin")?;
    let (device, session_generation) = origin.device.ok_or("attachment")?;
    let target = Target {
        account_digest: origin.account_digest.ok_or("account")?,
        device_id: device,
    };
    let token = [44; 32];
    let object_id = object_id(&bytes);
    let grant = DeliveryGrant {
        token,
        session_generation,
        expires_at: NOW + 60,
    };
    let key = MailboxRow::item_key(
        &target.account_digest,
        &device,
        agenc_relay_storage::e2ee_records::MailboxKind::Application,
        0,
    )?;
    let row = MailboxRow::Item {
        object_id,
        conversation_id: conversation,
        inserted_at: NOW,
        expires_at: NOW + 3600,
        grant: Some(agenc_relay_storage::e2ee_records::DeliveryGrant {
            token,
            session_generation,
            expires_at: NOW + 60,
        }),
    };
    let writes = vec![
        crate::e2ee::coordinator::CompanionCoordinator::object_write(&bytes)
            .map_err(|e| format!("object: {e:?}"))?,
        request::state_row(TableId::E2eeState, MAILBOX_ROW_KIND, key, row.encode()?)
            .map_err(|e| format!("item: {e:?}"))?,
    ];
    resident::prepare(&source.coordinator.state, &writes, &source.backing, None)
        .map_err(|e| format!("resident: {e:?}"))?
        .apply(&mut source.coordinator.state);
    // Seed an admitted opaque application and its exact grant; ACK exercises the
    // normal attached-device and application-envelope checks before any effect.
    source.coordinator.state.mailboxes.restore_item(
        target,
        MailboxKind::Application,
        0,
        Item {
            object_id,
            conversation_id: conversation,
            inserted_at: NOW,
            expires_at: NOW + 3600,
            grant: Some(grant),
        },
    );
    for write in &writes {
        source.apply_logical_write(write)?;
    }
    Ok((source, bytes, token))
}

#[test]
fn acknowledging_the_last_mailbox_payload_releases_only_its_resident_copy() -> TestResult {
    let (mut source, bytes, token) = application_mailbox()?;
    let id = object_id(&bytes);
    let mut params = token.to_vec();
    params.extend_from_slice(&id);
    let before = source.coordinator.state.object_bytes;
    let result = ok(source.run(Op::AcknowledgeMailbox, &params, None)?)?;
    assert_eq!(result.result, ResultBody::MailboxAcked(token, id));
    assert_eq!(source.coordinator.state.mailboxes.item_count(), 0);
    assert!(source.writes.iter().any(|write| {
        write
            .encoded_record()
            .is_some_and(|(table, key, _)| table == TableId::E2eeObject && key.as_bytes() == id)
    }));
    assert!(
        !source.coordinator.state.objects.contains_key(&id),
        "the final mailbox ACK left its application body resident"
    );
    assert!(!source.coordinator.state.object_memory.contains_key(&id));
    assert_eq!(source.coordinator.state.object_bytes, before - bytes.len());
    Ok(())
}

#[test]
fn a_shared_payload_stays_resident_until_both_mailbox_items_are_acknowledged() -> TestResult {
    let (mut source, bytes, first_token) = application_mailbox()?;
    let origin = source
        .coordinator
        .state
        .origins
        .values()
        .next()
        .ok_or("origin")?;
    let target = Target {
        account_digest: origin.account_digest.ok_or("account")?,
        device_id: origin.device.ok_or("device")?.0,
    };
    let mut item = *source
        .coordinator
        .state
        .mailboxes
        .retained_item(target, MailboxKind::Application, 0)
        .ok_or("first item")?;
    let second_token = [45; 32];
    item.grant.as_mut().ok_or("grant")?.token = second_token;
    source
        .coordinator
        .state
        .mailboxes
        .restore_item(target, MailboxKind::Application, 1, item);
    let id = object_id(&bytes);
    let before = source.coordinator.state.object_bytes;
    for (index, token) in [first_token, second_token].into_iter().enumerate() {
        let mut params = token.to_vec();
        params.extend_from_slice(&id);
        ok(source.run(Op::AcknowledgeMailbox, &params, None)?)?;
        assert_eq!(source.coordinator.state.mailboxes.item_count(), 1 - index);
        assert_eq!(
            source.coordinator.state.objects.contains_key(&id),
            index == 0
        );
        assert_eq!(
            source.coordinator.state.object_memory.contains_key(&id),
            index == 0
        );
    }
    assert_eq!(source.coordinator.state.object_bytes, before - bytes.len());
    Ok(())
}

#[test]
fn an_unapplied_mailbox_ack_keeps_the_item_body_and_charge() -> TestResult {
    let (mut source, bytes, token) = application_mailbox()?;
    let id = object_id(&bytes);
    let before = source.coordinator.state.object_bytes;
    let charge = source
        .coordinator
        .state
        .object_memory
        .get(&id)
        .ok_or("charge")?
        .bytes();
    let mut params = token.to_vec();
    params.extend_from_slice(&id);
    let outcome = ok(evaluate_request(
        &mut source,
        Op::AcknowledgeMailbox,
        &params,
        None,
    )?)?;
    assert!(!outcome.writes.is_empty());
    assert!(!outcome.effects.is_empty());
    drop(outcome);
    assert_eq!(source.coordinator.state.mailboxes.item_count(), 1);
    assert_eq!(source.coordinator.state.objects.get(&id), Some(&bytes));
    assert_eq!(
        source
            .coordinator
            .state
            .object_memory
            .get(&id)
            .ok_or("charge")?
            .bytes(),
        charge
    );
    assert_eq!(source.coordinator.state.object_bytes, before);
    Ok(())
}

#[test]
fn a_repeated_mailbox_ack_cannot_release_resident_bytes_twice() -> TestResult {
    let (mut source, bytes, token) = application_mailbox()?;
    let mut params = token.to_vec();
    params.extend_from_slice(&object_id(&bytes));
    ok(source.run(Op::AcknowledgeMailbox, &params, None)?)?;
    let before = source.coordinator.state.object_bytes;
    let replay = ok(source.run(Op::AcknowledgeMailbox, &params, None)?)?;
    assert_eq!(
        replay.result,
        ResultBody::MailboxAcked(token, object_id(&bytes))
    );
    assert!(replay.writes.is_empty());
    assert_eq!(source.coordinator.state.object_bytes, before);
    Ok(())
}

#[test]
fn acknowledging_a_binding_keeps_its_control_object_and_charge() -> TestResult {
    let (mut source, _, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    deliver_binding(&mut source, &binding)?;
    let page = ok(source.run(Op::FetchMailbox, &[2, 0], None)?)?;
    let token = page
        .responses
        .first()
        .and_then(|r| r.delivery_token)
        .ok_or("token")?;
    let id = object_id(&binding);
    let before = source.coordinator.state.object_bytes;
    let mut params = token.to_vec();
    params.extend_from_slice(&id);
    ok(source.run(Op::AcknowledgeMailbox, &params, None)?)?;
    assert_eq!(source.coordinator.state.mailboxes.item_count(), 0);
    assert_eq!(source.coordinator.state.objects.get(&id), Some(&binding));
    assert!(source.coordinator.state.object_memory.contains_key(&id));
    assert_eq!(source.coordinator.state.object_bytes, before);
    Ok(())
}
