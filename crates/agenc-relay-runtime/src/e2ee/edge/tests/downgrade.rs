#![forbid(unsafe_code)]

//! An edge refuses plaintext from a local session to a local member of an
//! encrypted direct pair the sender's account belongs to, while the pair's
//! binding is live, closing or closed, and after its next incarnation binds
//! (companion 11.4), by every target's canonical nickname. Its projection
//! orders a pair's routes by their state generation (companion 12.5), so a
//! pair keeps its index while any of its routes is still projected.

use agenc_relay_client_wire::{FramedLine, ParsedMessage, WireMessage, parse_message};
use agenc_relay_domain::e2ee::{ConversationId, DirectPair, RecoveryState, RouteLifecycle};
use agenc_relay_domain::federation::{ProjectedEvent, SessionEventView, SessionRecord};
use agenc_relay_domain::{DisplayNameValue, NicknameValue};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_types::{AccountId, AccountRandomId, Generation, Revision, SessionId, UserId};

use super::projection::base_edge;
use super::*;
use crate::federation::edge::EdgeFederation;
use crate::test_support::StateCoreFixture;

const FIRST: [u8; 32] = [41; 32];
const NEXT: [u8; 32] = [42; 32];

fn account(seed: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([seed; 16]))
}

fn wire(account: AccountId) -> TestResult<[u8; 24]> {
    Ok(account.to_text().as_bytes().try_into()?)
}

/// Projects one local session of `account`, a guest without one, named
/// `nickname`.
fn local_session(
    edge: &mut EdgeFederation,
    seed: u8,
    nickname: &str,
    account: Option<AccountId>,
) -> TestResult {
    let record = SessionRecord {
        session_id: SessionId::from_bytes([seed; 16]),
        user_id: UserId::from_bytes([seed; 16]),
        home_server_id: agenc_relay_types::ServerId::from_bytes([2; 16]),
        session_revision: Revision::new(1)?,
        account: account
            .map(|account| Generation::new(1).map(|generation| (account, generation)))
            .transpose()?,
        nickname: NicknameValue::parse(nickname)?,
        display_name: DisplayNameValue::prepare("Member")?,
        public_cloak: agenc_relay_testkit::deterministic_cloak(seed)?,
        account_label: None,
        user_mode_bits: 1,
        away: None,
    };
    edge.replica_mut().apply(
        &ProjectedEvent::SessionVisible(SessionEventView {
            source: record.source_view(),
            home_projection: Some(record),
        }),
        1,
    )?;
    Ok(())
}

/// The route state of a direct conversation of `pair` at `generation`.
fn direct_state(
    conversation: [u8; 32],
    pair: DirectPair,
    state: ArcRouteStateKind,
    generation: u64,
) -> TestResult<Vec<u8>> {
    let route = ArcFederationRouteState {
        profile_version: 1,
        network_id: [1; 32],
        state_generation: generation,
        conversation_id: conversation,
        conversation_kind: ArcConversationKind::Direct,
        route_binding: [26; 32],
        semantic_route_lock_id: [conversation[0]; 32],
        channel_instance_id: Opaque::new(Vec::new())?,
        canonical_channel_name_hash: [0; 32],
        direct_account_a: Opaque::new(wire(pair.smaller())?.to_vec())?,
        direct_account_b: Opaque::new(wire(pair.larger())?.to_vec())?,
        binding_id: [conversation[0].wrapping_add(1); 32],
        finalized_epoch: 1,
        accepted_state_id: [58; 32],
        sequencer_record_head_sequence: 4,
        sequencer_record_head_id: [59; 32],
        state,
    };
    Ok(ArcWireObject::new(ArcWireObjectKind::FederationState, route.encode()?)?.encode()?)
}

fn parsed(line: &str) -> TestResult<ParsedMessage> {
    parse_message(FramedLine::new(line)?)?.ok_or_else(|| "empty message".into())
}

/// The refusal line `edge` answers `line` from `sender` with, if any.
fn refusal(
    e2ee: &E2eeEdge,
    edge: &EdgeFederation,
    line: &str,
    sender: Option<AccountId>,
) -> TestResult<Option<WireMessage>> {
    let sender = sender.map(wire).transpose()?;
    Ok(e2ee.plaintext_refusal(edge, &parsed(line)?, sender))
}

/// Every line `alice` may send `bob` that names him is refused once their
/// pair is encrypted, and nothing else is.
fn assert_pair_refused(e2ee: &E2eeEdge, edge: &EdgeFederation, state: &str) -> TestResult {
    let (alice, carol) = (account(1), account(3));
    for (line, command, context) in [
        ("PRIVMSG bob :hello", "PRIVMSG", "bob"),
        ("NOTICE bob :hello", "NOTICE", "bob"),
        ("TAGMSG bob", "TAGMSG", "bob"),
        ("PRIVMSG BoB :hello", "PRIVMSG", "BoB"),
        ("PRIVMSG carol,bob :hello", "PRIVMSG", "carol,bob"),
        ("PRIVMSG #room,bob :hello", "PRIVMSG", "#room,bob"),
    ] {
        let expected = WireMessage::extension_line(&format!(
            ":edge.example FAIL {command} E2EE_REQUIRED {context} :plaintext is forbidden for the target"
        ))?;
        assert_eq!(
            refusal(e2ee, edge, line, Some(alice))?,
            Some(expected),
            "{state}: {line}"
        );
    }
    // bob refuses alice the same way.
    assert!(
        refusal(e2ee, edge, "PRIVMSG alice :hello", Some(account(2)))?.is_some(),
        "{state}"
    );
    // Unrelated pairs, guests and channels are not this rule's.
    for (line, sender) in [
        ("PRIVMSG carol :hello", Some(alice)),
        ("PRIVMSG bob :hello", Some(carol)),
        ("PRIVMSG bob :hello", None),
        ("PRIVMSG guest :hello", Some(alice)),
        ("PRIVMSG alice :hello", Some(alice)),
        ("PRIVMSG #room :hello", Some(alice)),
        ("PRIVMSG nobody :hello", Some(alice)),
    ] {
        assert_eq!(
            refusal(e2ee, edge, line, sender)?,
            None,
            "{state}: {line} from {sender:?}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn an_edge_refuses_plaintext_to_a_local_member_of_an_encrypted_pair_in_every_state()
-> TestResult {
    let mut fixture = StateCoreFixture::new(vec![0; 4_096])?;
    let mut base = base_edge();
    local_session(&mut base, 10, "alice", Some(account(1)))?;
    local_session(&mut base, 11, "bob", Some(account(2)))?;
    local_session(&mut base, 12, "carol", Some(account(3)))?;
    local_session(&mut base, 13, "guest", None)?;
    let edge_view = &base;
    let pair = DirectPair::new(account(1), account(2))?;
    let mut e2ee = edge();
    // Before any binding, plaintext between the pair flows.
    assert_eq!(
        refusal(&e2ee, edge_view, "PRIVMSG bob :hello", Some(account(1)))?,
        None
    );
    e2ee.route_changed(&direct_state(
        FIRST,
        pair,
        ArcRouteStateKind::ActiveRoute,
        5,
    )?)
    .map_err(|refusal| refusal.code.to_string())?;
    assert_pair_refused(&e2ee, edge_view, "live")?;
    // A closing route and one behind a recovery gate keep the pair.
    let live = *e2ee
        .routes
        .route(&ConversationId(FIRST))
        .ok_or("the projected route")?;
    for (lifecycle, recovery) in [
        (RouteLifecycle::Closing, RecoveryState::Normal),
        (RouteLifecycle::Active, RecoveryState::Pending),
    ] {
        let mut gated = e2ee.routes.clone();
        gated.restore_entry(agenc_relay_domain::e2ee::RouteEntry {
            lifecycle,
            recovery,
            ..live
        });
        let saved = std::mem::replace(&mut e2ee.routes, gated);
        assert_pair_refused(&e2ee, edge_view, "closing or gated")?;
        e2ee.routes = saved;
    }
    // The close leaves a tombstone, which keeps refusing until and after the
    // next incarnation binds.
    e2ee.route_changed(&direct_state(
        FIRST,
        pair,
        ArcRouteStateKind::EncryptedTombstone,
        7,
    )?)
    .map_err(|refusal| refusal.code.to_string())?;
    assert_pair_refused(&e2ee, edge_view, "closed")?;
    e2ee.route_changed(&direct_state(
        NEXT,
        pair,
        ArcRouteStateKind::ActiveRoute,
        9,
    )?)
    .map_err(|refusal| refusal.code.to_string())?;
    assert_pair_refused(&e2ee, edge_view, "recreated")?;
    assert_eq!(
        e2ee.routes
            .direct_route(&pair)
            .map(|route| route.conversation_id),
        Some(ConversationId(NEXT))
    );
    // Hiding the next incarnation hands the pair back to the tombstone,
    // which still refuses; hiding both frees it.
    let context = fixture.context_mut()?;
    e2ee.route_hidden(context, NEXT)
        .map_err(|refusal| refusal.code.to_string())?;
    assert_eq!(
        e2ee.routes
            .direct_route(&pair)
            .map(|route| route.conversation_id),
        Some(ConversationId(FIRST))
    );
    assert_pair_refused(&e2ee, edge_view, "next hidden")?;
    e2ee.route_hidden(context, FIRST)
        .map_err(|refusal| refusal.code.to_string())?;
    assert_eq!(
        refusal(&e2ee, edge_view, "PRIVMSG bob :hello", Some(account(1)))?,
        None
    );
    Ok(())
}

#[test]
fn an_edge_indexes_a_pairs_newest_projection_whatever_the_order() -> TestResult {
    let pair = DirectPair::new(account(1), account(2))?;
    // Two tombstones of one pair, and a closed pair's next incarnation live.
    for (older, newer) in [
        (
            direct_state(FIRST, pair, ArcRouteStateKind::EncryptedTombstone, 7)?,
            direct_state(NEXT, pair, ArcRouteStateKind::EncryptedTombstone, 12)?,
        ),
        (
            direct_state(FIRST, pair, ArcRouteStateKind::EncryptedTombstone, 7)?,
            direct_state(NEXT, pair, ArcRouteStateKind::ActiveRoute, 9)?,
        ),
    ] {
        for order in [[&older, &newer], [&newer, &older]] {
            let mut e2ee = edge();
            for state in order {
                e2ee.route_changed(state)
                    .map_err(|refusal| refusal.code.to_string())?;
            }
            assert_eq!(
                e2ee.routes
                    .direct_route(&pair)
                    .map(|route| route.conversation_id),
                Some(ConversationId(NEXT))
            );
        }
    }
    Ok(())
}
