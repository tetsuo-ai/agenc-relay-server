//! A modeled full counter exercises the net resident size of a mailbox ACK batch.
#![forbid(unsafe_code)]
use super::*;

type FullMailbox = (
    CompanionState,
    Vec<u8>,
    Vec<Write>,
    Arc<MemoryBudget>,
    BackingReservationPort,
);

fn full_mailbox(kind: Kind, mailbox_kind: MailboxKind) -> TestResult<FullMailbox> {
    let (budget, port) = pool(1 << 20);
    let (bytes, body) = object(kind, 1, 16_000)?;
    let mut state = CompanionState::default();
    admitted(&state, &[body, mailbox(&bytes, mailbox_kind, 1)?], &port)?.apply(&mut state);
    let domain_kind = match mailbox_kind {
        MailboxKind::Application => DomainKind::Application,
        MailboxKind::Binding => DomainKind::Binding,
        MailboxKind::Welcome => DomainKind::Welcome,
        MailboxKind::StagedReinit => DomainKind::StagedReinit,
    };
    state.mailboxes.restore_item(
        Target {
            account_digest: [1; 32],
            device_id: [1; 16],
        },
        domain_kind,
        0,
        Item {
            object_id: *ObjectId::compute(&bytes).as_bytes(),
            conversation_id: [2; 32],
            inserted_at: 1,
            expires_at: 1000,
            grant: None,
        },
    );
    state.object_bytes = MAX_RETAINED_OBJECT_BYTES;
    let key = MailboxRow::item_key(&[1; 32], &[1; 16], mailbox_kind, 0)?;
    let writes = vec![
        Write::delete(TableId::E2eeState, key)?,
        object(Kind::FederationResult, 2, 100)?.1,
    ];
    Ok((state, bytes, writes, budget, port))
}

#[test]
fn an_ack_can_use_the_payload_space_it_retires_for_its_smaller_result() -> TestResult {
    let (_, port) = pool(1 << 20);
    let (bytes, body) = object(Kind::ApplicationMls, 1, 16_000)?;
    let id = *ObjectId::compute(&bytes).as_bytes();
    let mut state = CompanionState::default();
    admitted(
        &state,
        &[body, mailbox(&bytes, MailboxKind::Application, 1)?],
        &port,
    )?
    .apply(&mut state);
    state.mailboxes.restore_item(
        Target {
            account_digest: [1; 32],
            device_id: [1; 16],
        },
        DomainKind::Application,
        0,
        Item {
            object_id: id,
            conversation_id: [2; 32],
            inserted_at: 1,
            expires_at: 1000,
            grant: None,
        },
    );
    // The real allocation above is small; this counter models other resident bodies.
    state.object_bytes = MAX_RETAINED_OBJECT_BYTES;
    let key = MailboxRow::item_key(&[1; 32], &[1; 16], MailboxKind::Application, 0)?;
    let writes = vec![
        Write::delete(TableId::E2eeState, key)?,
        object(Kind::FederationResult, 2, 100)?.1,
    ];
    let result = prepare(&state, &writes, &port, None);
    assert!(
        result.is_ok(),
        "the ACK cannot stage the result that releases its larger payload"
    );
    assert_eq!(state.objects.get(&id), Some(&bytes));
    assert!(state.object_memory.contains_key(&id));
    Ok(())
}

#[test]
fn unused_capacity_credit_does_not_release_the_live_body_but_receipt_transfers_the_net_size()
-> TestResult {
    let (mut state, bytes, writes, budget, port) =
        full_mailbox(Kind::ApplicationMls, MailboxKind::Application)?;
    let id = *ObjectId::compute(&bytes).as_bytes();
    let before = budget.charged();
    let prepared = admitted(&state, &writes, &port)?;
    assert!(budget.charged() > before);
    assert_eq!(state.objects.get(&id), Some(&bytes));
    drop(prepared);
    assert_eq!(budget.charged(), before);
    admitted(&state, &writes, &port)?.apply(&mut state);
    // The caller's immediately following receipt effect removes the planned item.
    state.mailboxes = Default::default();
    assert!(!state.objects.contains_key(&id));
    assert!(!state.object_memory.contains_key(&id));
    assert_eq!(state.objects.len(), 1);
    let result = state.objects.values().next().ok_or("result")?;
    assert_eq!(
        state.object_bytes,
        MAX_RETAINED_OBJECT_BYTES - bytes.len() + result.len()
    );
    assert_eq!(
        budget.charged(),
        state
            .object_memory
            .values()
            .next()
            .ok_or("result charge")?
            .bytes()
    );
    drop(state);
    assert_eq!(budget.charged(), 0);
    Ok(())
}

#[test]
fn capacity_credit_requires_one_exact_deletion_and_no_remaining_or_new_reference() -> TestResult {
    for fault in 0..4 {
        let (mut state, bytes, mut writes, budget, port) =
            full_mailbox(Kind::ApplicationMls, MailboxKind::Application)?;
        let id = *ObjectId::compute(&bytes).as_bytes();
        let before = budget.charged();
        match fault {
            0 => state.mailboxes.restore_item(
                Target {
                    account_digest: [99; 32],
                    device_id: [99; 16],
                },
                DomainKind::Application,
                0,
                Item {
                    object_id: id,
                    conversation_id: [2; 32],
                    inserted_at: 1,
                    expires_at: 1000,
                    grant: None,
                },
            ),
            1 => writes.push(mailbox(&bytes, MailboxKind::Application, 99)?),
            2 => {
                let Write::Delete { key, .. } = writes.first_mut().ok_or("delete")? else {
                    return Err("delete".into());
                };
                *key = MailboxRow::item_key(&[99; 32], &[1; 16], MailboxKind::Application, 0)?;
            }
            3 => writes.push(Write::delete(
                TableId::E2eeState,
                MailboxRow::item_key(&[99; 32], &[1; 16], MailboxKind::Application, 0)?,
            )?),
            _ => return Err("fault".into()),
        }
        assert!(matches!(
            prepare(&state, &writes, &port, None),
            Err(Code::RateLimited)
        ));
        assert_eq!(state.objects.get(&id), Some(&bytes));
        assert_eq!(state.object_bytes, MAX_RETAINED_OBJECT_BYTES);
        assert_eq!(budget.charged(), before);
    }
    Ok(())
}

#[test]
fn a_binding_ack_cannot_spend_its_protected_control_body_as_capacity_credit() -> TestResult {
    let (state, bytes, writes, budget, port) =
        full_mailbox(Kind::ConversationBinding, MailboxKind::Binding)?;
    let before = budget.charged();
    assert!(matches!(
        prepare(&state, &writes, &port, None),
        Err(Code::RateLimited)
    ));
    assert_eq!(
        state.objects.get(ObjectId::compute(&bytes).as_bytes()),
        Some(&bytes)
    );
    assert_eq!(budget.charged(), before);
    Ok(())
}
