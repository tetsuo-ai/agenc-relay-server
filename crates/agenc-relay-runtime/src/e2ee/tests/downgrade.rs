#![forbid(unsafe_code)]

//! The coordinator refuses a plaintext message line any of whose nickname
//! targets is a session of the other account of an encrypted direct pair
//! the sender's account belongs to: live, closing, closed, recovery-gated or
//! recreated (companion 11.4). Every session of either account, any
//! spelling of the nickname and any position in the target list meet the
//! refusal; guests, one account's own sessions, unrelated pairs and channel
//! targets do not.

use agenc_relay_domain::e2ee::{
    BindingSummary, ConversationId, DirectPair, RecoveryState, ReservationId, RouteTable,
    SemanticLockId,
};
use agenc_relay_domain::{
    CanonicalCommand, ChannelNameValue, ChannelTarget, E2eeApplicationProof, MessageCommand,
    MessageKind, MessageTarget, MessageText, NicknameValue,
};
use agenc_relay_types::{ChannelInstanceId, UserId};

use super::*;
use crate::test_support::{StateCoreFixture, seed_account, seed_session};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

/// The seeded sessions: alice and a second session of her account, bob,
/// carol, and a guest.
struct Sessions {
    alice: UserId,
    alice_again: UserId,
    bob: UserId,
    carol: UserId,
    guest: UserId,
    pair: DirectPair,
}

fn sessions(context: &mut crate::state_core::StateCoreContext) -> TestResult<Sessions> {
    let alice_account = seed_account(context, 1, 1)?;
    let bob_account = seed_account(context, 2, 1)?;
    let carol_account = seed_account(context, 3, 1)?;
    let alice = seed_session(context, 10, "alice", Some(alice_account))?.user_id;
    let alice_again = seed_session(context, 11, "alice2", Some(alice_account))?.user_id;
    let bob = seed_session(context, 12, "bob", Some(bob_account))?.user_id;
    let carol = seed_session(context, 13, "carol", Some(carol_account))?.user_id;
    let guest = seed_session(context, 14, "guest", None)?.user_id;
    Ok(Sessions {
        alice,
        alice_again,
        bob,
        carol,
        guest,
        pair: DirectPair::new(alice_account.0, bob_account.0)?,
    })
}

fn message(kind: MessageKind, targets: &[&str]) -> TestResult<CanonicalCommand> {
    let targets = targets
        .iter()
        .map(|target| {
            if target.starts_with('#') {
                Ok(MessageTarget::Channel(ChannelNameValue::parse(target)?))
            } else {
                Ok(MessageTarget::User(NicknameValue::parse(target)?))
            }
        })
        .collect::<Result<Vec<_>, agenc_relay_domain::DomainError>>()?;
    let body = (kind != MessageKind::Tagmsg)
        .then(|| MessageText::parse("hello"))
        .transpose()?;
    Ok(CanonicalCommand::message(MessageCommand::new(
        kind, targets, body,
    )?))
}

/// The route table holding one direct binding of `pair` at incarnation zero.
fn bound(pair: DirectPair) -> TestResult<RouteTable> {
    let mut routes = RouteTable::new();
    routes.reserve_direct(ReservationId([1; 16]), pair, [7; 32], pair.smaller(), 100)?;
    routes.bind(
        ReservationId([1; 16]),
        pair.smaller(),
        BindingSummary {
            conversation_id: ConversationId([20; 32]),
            lock: SemanticLockId([21; 32]),
            lineage: SemanticLockId([21; 32]),
            incarnation: 0,
            predecessor_close_id: [0; 32],
            binding_id: [22; 32],
            binding_generation: 0,
            previous_binding_id: [0; 32],
            channel_instance_id: None,
            conversation_nonce: Some([7; 32]),
            direct_pair: Some(pair),
        },
        10,
    )?;
    Ok(routes)
}

/// The nickname the coordinator refuses `command` from `sender` for.
fn refused(
    context: &crate::state_core::StateCoreContext,
    routes: &RouteTable,
    sender: UserId,
    command: &CanonicalCommand,
) -> Option<String> {
    refused_direct_target(context.domain(), routes, sender, command)
        .map(|nickname| nickname.presentation().to_owned())
}

fn assert_refused_in_every_form(
    context: &crate::state_core::StateCoreContext,
    routes: &RouteTable,
    seeded: &Sessions,
    state: &str,
) -> TestResult {
    for (sender, kind, targets, nickname) in [
        (seeded.alice, MessageKind::Privmsg, &["bob"][..], "bob"),
        (seeded.alice, MessageKind::Notice, &["bob"][..], "bob"),
        (seeded.alice, MessageKind::Tagmsg, &["bob"][..], "bob"),
        (seeded.alice, MessageKind::Privmsg, &["BOB"][..], "BOB"),
        (
            seeded.alice,
            MessageKind::Privmsg,
            &["carol", "bob"][..],
            "bob",
        ),
        (
            seeded.alice,
            MessageKind::Privmsg,
            &["#room", "bob"][..],
            "bob",
        ),
        (
            seeded.alice_again,
            MessageKind::Privmsg,
            &["bob"][..],
            "bob",
        ),
        (seeded.bob, MessageKind::Privmsg, &["alice"][..], "alice"),
        (seeded.bob, MessageKind::Notice, &["alice2"][..], "alice2"),
    ] {
        assert_eq!(
            refused(context, routes, sender, &message(kind, targets)?).as_deref(),
            Some(nickname),
            "{state}: {kind:?} {targets:?}"
        );
    }
    for (sender, targets) in [
        (seeded.alice, &["carol"][..]),
        (seeded.carol, &["bob"][..]),
        (seeded.guest, &["bob"][..]),
        (seeded.alice, &["guest"][..]),
        (seeded.alice, &["alice2"][..]),
        (seeded.alice, &["#room"][..]),
        (seeded.alice, &["nobody"][..]),
    ] {
        assert_eq!(
            refused(
                context,
                routes,
                sender,
                &message(MessageKind::Privmsg, targets)?
            ),
            None,
            "{state}: {targets:?}"
        );
    }
    Ok(())
}

#[test]
fn the_coordinator_refuses_plaintext_between_an_encrypted_pair_in_every_state() -> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let context = fixture.context_mut()?;
    let seeded = sessions(context)?;
    let pair = seeded.pair;
    // No binding: plaintext between the pair flows.
    assert_eq!(
        refused(
            context,
            &RouteTable::new(),
            seeded.alice,
            &message(MessageKind::Privmsg, &["bob"])?
        ),
        None
    );
    let mut routes = bound(pair)?;
    assert_refused_in_every_form(context, &routes, &seeded, "live")?;
    let conversation = ConversationId([20; 32]);
    routes.begin_close(&conversation)?;
    assert_refused_in_every_form(context, &routes, &seeded, "closing")?;
    routes.close(&conversation, [30; 32])?;
    assert_refused_in_every_form(context, &routes, &seeded, "closed")?;
    // The pair is reserved again: a reservation alone changes nothing.
    routes.reserve_direct(ReservationId([2; 16]), pair, [8; 32], pair.smaller(), 100)?;
    assert_refused_in_every_form(context, &routes, &seeded, "reserved again")?;
    routes.bind(
        ReservationId([2; 16]),
        pair.smaller(),
        BindingSummary {
            conversation_id: ConversationId([40; 32]),
            lock: SemanticLockId([41; 32]),
            lineage: SemanticLockId([21; 32]),
            incarnation: 1,
            predecessor_close_id: [30; 32],
            binding_id: [42; 32],
            binding_generation: 0,
            previous_binding_id: [0; 32],
            channel_instance_id: None,
            conversation_nonce: Some([8; 32]),
            direct_pair: Some(pair),
        },
        10,
    )?;
    assert_refused_in_every_form(context, &routes, &seeded, "recreated")?;
    Ok(())
}

#[test]
fn a_recovery_gated_pair_refuses_plaintext_and_an_application_object_is_left_to_the_plan()
-> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let context = fixture.context_mut()?;
    let seeded = sessions(context)?;
    let mut routes = bound(seeded.pair)?;
    routes.restore_pending();
    assert_refused_in_every_form(context, &routes, &seeded, "pending")?;
    routes.resolve_recovery(&ConversationId([20; 32]), RecoveryState::Conflict, None)?;
    assert_refused_in_every_form(context, &routes, &seeded, "conflict")?;
    // An encrypted application object never names a user; the plan refuses
    // one that does, so this rule leaves it.
    let proof = E2eeApplicationProof::new(
        ChannelInstanceId::from_bytes([5; 16]),
        seeded.alice,
        context.domain().revision(),
    );
    let application = CanonicalCommand::message(MessageCommand::e2ee_tagmsg(
        MessageTarget::Channel(ChannelNameValue::parse("#room")?),
        proof,
    )?);
    assert_eq!(refused(context, &routes, seeded.alice, &application), None);
    // A command that carries no message is the plan's alone.
    let join = CanonicalCommand::join(vec![ChannelTarget::new(
        ChannelNameValue::parse("#room")?,
        false,
    )])?;
    assert_eq!(refused(context, &routes, seeded.alice, &join), None);
    Ok(())
}

#[test]
fn a_refusal_line_names_the_targets_as_supplied() -> TestResult {
    let line = refusal_line("core.example", "NOTICE", "carol,BoB").ok_or("a line")?;
    assert_eq!(
        line,
        agenc_relay_client_wire::WireMessage::extension_line(
            ":core.example FAIL NOTICE E2EE_REQUIRED carol,BoB :plaintext is forbidden for the target"
        )?
    );
    Ok(())
}
