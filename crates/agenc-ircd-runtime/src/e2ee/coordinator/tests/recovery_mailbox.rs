//! Pending-route mailbox and private-object reads retain exact lineage checks.

#![forbid(unsafe_code)]

use crate::e2ee::coordinator::tests::support::{BindingSpec, binding_package, channel_route};
use crate::e2ee::coordinator::tests::{DEVICE_ID, NOW, account_param};
use agenc_ircd_domain::e2ee::mailbox::{Item, MailboxKind, Target};
use agenc_ircd_e2ee::objects::conversation::IrcPolicy;

use super::*;

const OTHER_INSTANCE: [u8; 16] = [98; 16];
const OTHER_GROUP: [u8; 32] = [99; 32];

#[path = "binding_delivery_auth.rs"]
mod binding_delivery_auth;

#[path = "reinit_collision.rs"]
mod reinit_collision;

#[path = "mailbox_ack_restart.rs"]
mod mailbox_ack_restart;

#[path = "mailbox_cursor.rs"]
mod mailbox_cursor;

#[path = "mailbox_grant_restart.rs"]
mod mailbox_grant_restart;

#[path = "cold_object_reads.rs"]
mod cold_object_reads;

#[path = "mailbox_retirement.rs"]
mod mailbox_retirement;

fn deliver_binding(fixture: &mut Harness, bytes: &[u8]) -> TestResult {
    let mut parameters = account_param(&fixture.account);
    parameters.extend_from_slice(&DEVICE_ID);
    let outcome = ok(fixture.run(Op::DeliverBinding, &parameters, Some(bytes))?)?;
    assert!(matches!(
        outcome.result,
        ResultBody::Stored(StoreKind::Binding, ..)
    ));
    Ok(())
}

type MailboxFixture = (Harness, [u8; 32], Vec<u8>, Option<[u8; 32]>);

fn mailbox_fixture(grant: bool) -> TestResult<MailboxFixture> {
    let (mut source, conversation, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    deliver_binding(&mut source, &binding)?;
    let token = if grant {
        let page = ok(source.run(Op::FetchMailbox, &[2, 0], None)?)?;
        Some(
            page.responses
                .first()
                .and_then(|response| response.delivery_token)
                .ok_or("issued token")?,
        )
    } else {
        None
    };
    Ok((
        restored_pending(&mut source, conversation)?,
        conversation,
        binding,
        token,
    ))
}

#[test]
fn a_pending_binding_cannot_allocate_a_mailbox_sequence() -> TestResult {
    let (mut fixture, _, binding, _) = mailbox_fixture(false)?;
    let before = retained_state(&fixture)?;
    let count = fixture.coordinator.state.mailboxes.item_count();
    let mut parameters = account_param(&fixture.account);
    parameters.extend_from_slice(&DEVICE_ID);
    assert_route_refused(evaluate_request(
        &mut fixture,
        Op::DeliverBinding,
        &parameters,
        Some(&binding),
    )?)?;
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), count);
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

#[test]
fn a_pending_mailbox_item_is_retained_without_a_new_token() -> TestResult {
    let (mut fixture, _, binding, _) = mailbox_fixture(false)?;
    let before = retained_state(&fixture)?;
    let entropy = fixture.entropy.0;
    let outcome = ok(evaluate_request(
        &mut fixture,
        Op::FetchMailbox,
        &[2, 0],
        None,
    )?)?;
    assert_eq!(outcome.result, ResultBody::Empty(EmptyKind::Binding));
    assert!(outcome.responses.is_empty());
    assert!(outcome.writes.is_empty());
    assert!(outcome.effects.is_empty());
    assert_eq!(fixture.entropy.0, entropy);
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), 1);
    assert_eq!(
        fixture.coordinator.state.objects.get(&object_id(&binding)),
        Some(&binding)
    );
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

#[test]
fn a_pending_live_mailbox_token_cannot_be_acknowledged() -> TestResult {
    let (mut fixture, _, binding, token) = mailbox_fixture(true)?;
    let before = retained_state(&fixture)?;
    let mut parameters = token.ok_or("issued token")?.to_vec();
    parameters.extend_from_slice(&object_id(&binding));
    assert_route_refused(evaluate_request(
        &mut fixture,
        Op::AcknowledgeMailbox,
        &parameters,
        None,
    )?)?;
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), 1);
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

struct OtherBinding {
    conversation: [u8; 32],
    bytes: Vec<u8>,
    initial: IrcPolicy,
    operational: IrcPolicy,
}

fn other_binding(fixture: &Harness) -> TestResult<OtherBinding> {
    let conversation = agenc_ircd_e2ee::ids::conversation_id(&NETWORK, &OTHER_GROUP)?;
    let principals = std::slice::from_ref(&fixture.principal);
    let bootstrap = PolicySpec::bootstrap(principals, conversation, IrcConversationKind::Channel);
    let initial = policy(&bootstrap)?;
    let operational = policy(&bootstrap.successor(policy_id_of(&initial)?))?;
    let fingerprint = root_fingerprint(&fixture.principal.root)?;
    let mut package = binding_package(&BindingSpec {
        principals,
        route: channel_route(b"#other", fingerprint)?,
        channel_instance_id: Some(OTHER_INSTANCE),
        conversation_nonce: None,
        group_id: OTHER_GROUP,
        generation: 0,
        previous_binding_id: [0; 32],
        lock_sequence: 1,
        plan_devices: vec![(&fixture.account, fingerprint, DEVICE)],
        initial_policy_id: policy_id_of(&initial)?,
        required_operational_policy_id: policy_id_of(&operational)?,
    })?;
    let digest = agenc_ircd_e2ee::ids::account_id_digest(&NETWORK, &fixture.account)?;
    let head = fixture
        .coordinator
        .state
        .binding_locks
        .get(&(digest, fingerprint))
        .and_then(|chain| chain.last_key_value())
        .ok_or("retained binding lock")?;
    let mut locks = package.root_binding_locks.as_slice().to_vec();
    let lock = locks.first_mut().ok_or("one binding lock")?;
    lock.tbs.root_binding_sequence = head.0.checked_add(1).ok_or("lock sequence overflow")?;
    lock.tbs.previous_root_binding_lock_id = head.1.lock_id;
    lock.root_signature = sign(
        &fixture.principal.root_secret,
        SignatureDomain::RootBindingLock,
        &lock.tbs,
    )?;
    package.root_binding_locks = TlsVec::new(locks)?;
    Ok(OtherBinding {
        conversation,
        bytes: wire(IrcWireObjectKind::ConversationBinding, &package)?,
        initial,
        operational,
    })
}

fn bind_other(fixture: &mut Harness) -> TestResult<OtherBinding> {
    let binding = other_binding(fixture)?;
    let mut reserve = OTHER_INSTANCE.to_vec();
    reserve.push(6);
    reserve.extend_from_slice(b"#other");
    let outcome = ok(fixture.run(Op::ReserveChannel, &reserve, None)?)?;
    let ResultBody::Reserved(reservation, _) = outcome.result else {
        return Err("independent reservation".into());
    };
    let mut parameters = reservation.to_vec();
    parameters.extend_from_slice(&binding.conversation);
    parameters.extend_from_slice(&[44; 32]);
    let bound = ok(fixture.run(Op::BindGroup, &parameters, Some(&binding.bytes))?)?;
    assert!(matches!(bound.result, ResultBody::Bound { .. }));
    fixture.publish_policy(binding.conversation, &binding.initial)?;
    fixture.publish_policy(binding.conversation, &binding.operational)?;
    Ok(binding)
}

#[test]
fn a_mixed_mailbox_preserves_the_pending_item_and_delivers_the_other_lineage() -> TestResult {
    let (mut fixture, _, pending, _) = mailbox_fixture(false)?;
    let other = bind_other(&mut fixture)?;
    deliver_binding(&mut fixture, &other.bytes)?;
    let page = ok(fixture.run(Op::FetchMailbox, &[2, 0], None)?)?;
    assert_eq!(page.responses.len(), 1);
    let response = page.responses.first().ok_or("independent binding")?;
    assert_eq!(response.bytes, other.bytes);
    let mut ack = response.delivery_token.ok_or("independent token")?.to_vec();
    ack.extend_from_slice(&object_id(&other.bytes));
    let outcome = ok(fixture.run(Op::AcknowledgeMailbox, &ack, None)?)?;
    assert_eq!(outcome.writes.len(), 3);
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), 1);
    assert_eq!(
        fixture.coordinator.state.objects.get(&object_id(&pending)),
        Some(&pending)
    );
    let empty = ok(fixture.run(Op::FetchMailbox, &[2, 0], None)?)?;
    assert_eq!(empty.result, ResultBody::Empty(EmptyKind::Binding));
    Ok(())
}

#[test]
fn a_malformed_retained_binding_refuses_the_page_before_any_grant() -> TestResult {
    let (mut fixture, _, _, _) = mailbox_fixture(false)?;
    let malformed = wire_raw(IrcWireObjectKind::ConversationBinding, vec![1])?;
    let id = object_id(&malformed);
    crate::e2ee::coordinator::CompanionCoordinator::retain_object(
        &mut fixture.coordinator.state,
        malformed,
    )
    .map_err(|_| "retaining malformed-object fixture")?;
    let target = Target {
        account_digest: agenc_ircd_e2ee::ids::account_id_digest(&NETWORK, &fixture.account)?,
        device_id: DEVICE_ID,
    };
    fixture.coordinator.state.mailboxes.restore_item(
        target,
        MailboxKind::Binding,
        1,
        Item {
            object_id: id,
            conversation_id: [0; 32],
            inserted_at: NOW,
            expires_at: NOW + 1000,
            grant: None,
        },
    );
    let entropy = fixture.entropy.0;
    assert_eq!(
        code(evaluate_request(
            &mut fixture,
            Op::FetchMailbox,
            &[2, 0],
            None
        )?),
        Some(E2eeReplyCode::InvalidFragment)
    );
    assert_eq!(fixture.entropy.0, entropy);
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), 2);
    Ok(())
}

#[test]
fn a_normal_route_cannot_expose_a_pending_routes_encrypted_commit() -> TestResult {
    let (mut source, pending, _) = finalization_fixture()?;
    let candidate = source
        .coordinator
        .state
        .logs
        .get(&pending)
        .and_then(|log| log.candidate())
        .ok_or("pending candidate")?;
    let object_id = candidate.commit_object_id;
    let bytes = source
        .coordinator
        .state
        .objects
        .get(&object_id)
        .ok_or("retained Commit")?
        .clone();
    let mut parameters = pending.to_vec();
    parameters.extend_from_slice(&object_id);
    let normal = ok(evaluate_request(
        &mut source,
        Op::FetchObject,
        &parameters,
        None,
    )?)?;
    assert_eq!(
        normal.responses.first().map(|response| &response.bytes),
        Some(&bytes)
    );
    let mut fixture = restored_pending(&mut source, pending)?;
    let other = bind_other(&mut fixture)?;
    for conversation in [pending, other.conversation] {
        let mut parameters = conversation.to_vec();
        parameters.extend_from_slice(&object_id);
        let outcome = ok(evaluate_request(
            &mut fixture,
            Op::FetchObject,
            &parameters,
            None,
        )?)?;
        assert!(outcome.responses.is_empty());
        assert!(outcome.writes.is_empty());
        assert!(outcome.effects.is_empty());
    }
    assert_eq!(
        fixture.coordinator.state.objects.get(&object_id),
        Some(&bytes)
    );
    Ok(())
}

#[test]
fn a_pending_route_keeps_an_exact_retained_mailbox_ack_replay() -> TestResult {
    let (mut source, conversation, _) = finalization_fixture()?;
    let binding = source.binding_bytes()?;
    deliver_binding(&mut source, &binding)?;
    let page = ok(source.run(Op::FetchMailbox, &[2, 0], None)?)?;
    let token = page
        .responses
        .first()
        .and_then(|response| response.delivery_token)
        .ok_or("token")?;
    let mut parameters = token.to_vec();
    parameters.extend_from_slice(&object_id(&binding));
    ok(source.run(Op::AcknowledgeMailbox, &parameters, None)?)?;
    let mut fixture = restored_pending(&mut source, conversation)?;
    let before = retained_state(&fixture)?;
    let count = fixture.coordinator.state.mailboxes.item_count();
    let outcome = ok(evaluate_request(
        &mut fixture,
        Op::AcknowledgeMailbox,
        &parameters,
        None,
    )?)?;
    assert_eq!(
        outcome.result,
        ResultBody::MailboxAcked(token, object_id(&binding))
    );
    assert!(outcome.writes.is_empty());
    assert!(outcome.events.is_empty());
    assert!(outcome.responses.is_empty());
    for effect in outcome.effects {
        effect(&mut fixture.coordinator.state);
    }
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), count);
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}

#[test]
fn a_valid_binding_cannot_use_a_different_retained_mailbox_lineage() -> TestResult {
    let (mut fixture, _, binding, _) = mailbox_fixture(false)?;
    let other = bind_other(&mut fixture)?;
    let target = Target {
        account_digest: agenc_ircd_e2ee::ids::account_id_digest(&NETWORK, &fixture.account)?,
        device_id: DEVICE_ID,
    };
    fixture.coordinator.state.mailboxes.restore_item(
        target,
        MailboxKind::Binding,
        1,
        Item {
            object_id: object_id(&binding),
            conversation_id: other.conversation,
            inserted_at: NOW,
            expires_at: NOW + 1000,
            grant: None,
        },
    );
    let before = retained_state(&fixture)?;
    let entropy = fixture.entropy.0;
    assert_eq!(
        code(evaluate_request(
            &mut fixture,
            Op::FetchMailbox,
            &[2, 0],
            None
        )?),
        Some(E2eeReplyCode::InvalidFragment)
    );
    assert_eq!(fixture.entropy.0, entropy);
    assert_eq!(fixture.coordinator.state.mailboxes.item_count(), 2);
    assert_eq!(retained_state(&fixture)?, before);
    Ok(())
}
