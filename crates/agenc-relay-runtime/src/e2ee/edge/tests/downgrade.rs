#![forbid(unsafe_code)]

//! An edge's projection orders a pair's routes by their state generation
//! (companion 12.5), so a pair keeps its index on its newest route whatever
//! the order its projections arrive in.

use agenc_relay_domain::e2ee::{ConversationId, DirectPair};
use agenc_relay_e2ee::object::{ArcWireObject, ArcWireObjectKind};
use agenc_relay_e2ee::objects::conversation::ArcConversationKind;
use agenc_relay_e2ee::objects::federation::{ArcFederationRouteState, ArcRouteStateKind};
use agenc_relay_e2ee::tls::{Opaque, TlsEncode};
use agenc_relay_types::{AccountId, AccountRandomId};

use super::*;

const FIRST: [u8; 32] = [41; 32];
const NEXT: [u8; 32] = [42; 32];

fn account(seed: u8) -> AccountId {
    AccountId::from_random(AccountRandomId::from_bytes([seed; 16]))
}

fn wire(account: AccountId) -> TestResult<[u8; 24]> {
    Ok(account.to_text().as_bytes().try_into()?)
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
