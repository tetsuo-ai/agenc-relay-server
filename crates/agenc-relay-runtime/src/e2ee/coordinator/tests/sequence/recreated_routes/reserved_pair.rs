//! `EGROUP BIND` under a direct reservation binds only the pair that
//! reservation reserved: "Direct reservation binds the authenticated sender
//! and named peer" (companion 11.5), and the concrete route binding the
//! reservation signed covers that pair with the nonce (companion 9.1 and
//! 9.4). A binding of the creator with another account under the reserved
//! nonce is `E2EE_BINDING_AUTH_INVALID`, so no pair is indexed under a
//! route its binding does not name, and the plaintext refusal of every
//! encrypted pair follows its own binding.

#![forbid(unsafe_code)]

use super::*;

/// A second direct peer, besides [`direct_peer`]'s, with its root and
/// device published.
const OTHER_ROOT_SEED: u8 = 43;
const OTHER_DEVICE: u8 = 13;

fn other_peer(harness: &mut Harness) -> TestResult<Principal> {
    let account = account_bytes(12)?;
    assert!(
        harness.account.as_slice() < account.as_slice(),
        "the harness account creates the pair"
    );
    let other = principal(OTHER_ROOT_SEED, &account, &[OTHER_DEVICE])?;
    let origin_key = origin_key();
    let saved = harness
        .coordinator
        .state
        .origins
        .get(&origin_key)
        .cloned()
        .ok_or("origin")?;
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key) {
        origin.account_id = Some(account);
        origin.account_digest = Some(agenc_relay_e2ee::ids::account_id_digest(
            &NETWORK, &account,
        )?);
        origin.device = None;
    }
    let root = wire(ArcWireObjectKind::RootIdentity, &other.root)?;
    ok(harness.run(Op::PublishIdentity, &[], Some(&root))?)?;
    let roster = wire(ArcWireObjectKind::DeviceRoster, &other.roster)?;
    ok(harness.run(Op::PublishRoster, &[], Some(&roster))?)?;
    if let Some(origin) = harness.coordinator.state.origins.get_mut(&origin_key) {
        origin.account_id = saved.account_id;
        origin.account_digest = saved.account_digest;
        origin.device = saved.device;
    }
    Ok(other)
}

#[test]
fn a_direct_reservation_binds_no_other_pair_under_its_nonce() -> TestResult {
    let mut harness = Harness::new()?;
    harness.publish_identity_and_roster()?;
    harness.attach()?;
    let peer = direct_peer(&mut harness)?;
    let other = other_peer(&mut harness)?;
    let account = |principal: &Principal| -> TestResult<AccountId> {
        let bytes: [u8; 24] = principal.root.tbs.account_id.as_slice().try_into()?;
        Ok(AccountId::parse_wire_bytes(&bytes)?)
    };
    let creator_account = AccountId::parse_wire_bytes(&harness.account)?;
    let reserved_pair = DirectPair::new(creator_account, account(&peer)?)?;
    let other_pair = DirectPair::new(creator_account, account(&other)?)?;
    let peer_account: [u8; 24] = peer.root.tbs.account_id.as_slice().try_into()?;
    let (reservation, nonce) = ok_reservation(reserve_direct(&mut harness, &peer_account)?)?;
    // The creator and the other account, under the nonce reserved for the
    // peer: signed by both, root-locked, and on the reserved nonce, but not
    // the reserved pair.
    let other_copy = principal(
        OTHER_ROOT_SEED,
        &other.root.tbs.account_id.as_slice().try_into()?,
        &[OTHER_DEVICE],
    )?;
    let foreign = group(
        &harness,
        &[creator(&harness)?, other_copy],
        direct_route(&harness, &other, 0, [0; 32])?,
        (None, Some(nonce)),
        DIRECT_GROUP,
    )?;
    assert_eq!(
        code(bind(&mut harness, reservation, &foreign)?),
        Some(E2eeReplyCode::BindingAuthInvalid)
    );
    let routes = &harness.coordinator.state.routes;
    assert!(routes.direct_plaintext_allowed(&reserved_pair));
    assert!(routes.direct_plaintext_allowed(&other_pair));
    assert_eq!(routes.reservations().count(), 1);
    // The reservation still binds the pair it reserved.
    let own = direct_group(&harness, &peer, (0, [0; 32]), nonce, SECOND_DIRECT_GROUP)?;
    bind_and_publish(&mut harness, reservation, &own)?;
    let routes = &harness.coordinator.state.routes;
    assert_eq!(
        routes
            .direct_route(&reserved_pair)
            .map(|route| route.conversation_id),
        Some(ConversationId(own.conversation))
    );
    assert!(!routes.direct_plaintext_allowed(&reserved_pair));
    assert!(routes.direct_plaintext_allowed(&other_pair));
    Ok(())
}
