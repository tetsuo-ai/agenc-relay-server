#![forbid(unsafe_code)]

//! What a live conversation reads stays retained while its route exists
//! (companion 11.7, 15 and 16). Its route row holds the conversation's
//! binding package, so `EGROUP QUERY` answers with it and a restart restores
//! the route from it; only the row's deletion releases the package to
//! object expiry. The tests run object expiry past every retention window,
//! apply each pass's batch to the store as the coordinator commits it, and
//! restart from that store.

use std::collections::BTreeSet;

mod capabilities;
mod earlier_lineage;
mod earlier_stores;
mod replaced_candidates;
mod rosters;

use super::super::NOW;
use super::object_expiry::sweep_writes;
use super::*;
use crate::state_core::durable::AccountServiceDurableWrite as Write;
use agenc_relay_e2ee::limits::SEQUENCER_RECORD_RETENTION_SECONDS;
use agenc_relay_storage::TableId;
use agenc_relay_storage::e2ee_records::{ROUTE_ROW_KIND, RetentionClass, RouteLifecycle, RouteRow};
use agenc_relay_types::ChannelInstanceId;

/// The first second after every window an unowned object serves.
pub(in crate::e2ee::coordinator::tests::sequence) const PAST_EVERY_WINDOW: u64 =
    NOW + SEQUENCER_RECORD_RETENTION_SECONDS + 1;

/// Runs object expiry at `now` until a whole sweep collects nothing, and
/// applies every pass that deleted an object to the harness store, as the
/// coordinator commits it. Returns the collected objects.
pub(in crate::e2ee::coordinator::tests::sequence) fn expire(
    harness: &mut Harness,
    now: u64,
) -> TestResult<BTreeSet<[u8; 32]>> {
    let mut collected = BTreeSet::new();
    let mut sweep_collected = false;
    for _ in 0..256 {
        let writes = sweep_writes(&mut harness.coordinator, now)?;
        let deleted: Vec<[u8; 32]> = writes
            .iter()
            .filter_map(|write| match write {
                Write::Delete {
                    table: TableId::E2eeObject,
                    key,
                } => <[u8; 32]>::try_from(key.as_bytes()).ok(),
                _ => None,
            })
            .collect();
        // A pass that deletes nothing stages no batch.
        if !deleted.is_empty() {
            for write in &writes {
                harness.apply_logical_write(write)?;
            }
            collected.extend(deleted);
            sweep_collected = true;
        }
        if harness.coordinator.expiry_progress().cursor.is_none() {
            if !sweep_collected {
                return Ok(collected);
            }
            sweep_collected = false;
        }
    }
    Err("object expiry did not settle".into())
}

/// The retained binding package object of `conversation`.
pub(in crate::e2ee::coordinator::tests::sequence) fn binding_object(
    harness: &Harness,
    conversation: [u8; 32],
) -> TestResult<[u8; 32]> {
    Ok(harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the conversation")?
        .binding_object_id)
}

/// Asserts that `object` is resident and that its ownership account names
/// exactly `owners`.
pub(in crate::e2ee::coordinator::tests::sequence) fn assert_held_by(
    harness: &Harness,
    object: [u8; 32],
    owners: &[Vec<u8>],
) -> TestResult {
    let state = &harness.coordinator.state;
    assert!(
        state.objects.contains_key(&object),
        "the object is resident"
    );
    let account = state.owners.account(&object).ok_or("its account")?;
    let named: Vec<&Vec<u8>> = account.owners.keys().collect();
    assert_eq!(named, owners.iter().collect::<Vec<_>>());
    assert_eq!(account.retention, RetentionClass::SecurityProof);
    assert_eq!(account.retired_at, None);
    Ok(())
}

/// `EGROUP QUERY CHANNEL` for `#room` answers with the exact current
/// binding package object.
fn queried_binding(harness: &mut Harness) -> TestResult<Vec<u8>> {
    let mut query = INSTANCE.to_vec();
    query.push(5);
    query.extend_from_slice(b"#room");
    let outcome = ok(harness.run(Op::QueryChannel, &query, None)?)?;
    let ResultBody::Bound {
        binding_object_id, ..
    } = outcome.result
    else {
        return Err("expected the bound route".into());
    };
    let response = outcome.responses.first().ok_or("the BINDING object")?;
    assert_eq!(object_id(&response.bytes), binding_object_id);
    Ok(response.bytes.clone())
}

#[test]
fn a_bound_channel_keeps_its_binding_package_and_restarts_after_expiry() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    harness.activate_bootstrap(conversation)?;
    let package = binding_object(&harness, conversation)?;
    let route_row = RouteRow::key(&conversation)?.as_bytes().to_vec();
    assert_held_by(&harness, package, std::slice::from_ref(&route_row))?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    // Expiry still collects what no row names: superseded route states.
    assert!(!collected.is_empty());
    assert!(!collected.contains(&package));
    assert_held_by(&harness, package, std::slice::from_ref(&route_row))?;
    assert_eq!(object_id(&queried_binding(&mut harness)?), package);
    let mut restarted = harness.reloaded()?;
    // The store the restart reads holds exactly the ownership live
    // admission derived.
    assert!(restarted.coordinator.owner_reconstruction.is_clean());
    assert_eq!(binding_object(&restarted, conversation)?, package);
    assert_held_by(&restarted, package, std::slice::from_ref(&route_row))?;
    assert_eq!(
        restarted
            .coordinator
            .state
            .routes
            .channel_route(&ChannelInstanceId::from_bytes(INSTANCE))
            .map(|route| route.conversation_id.0),
        Some(conversation)
    );
    assert_eq!(object_id(&queried_binding(&mut restarted)?), package);
    Ok(())
}

#[tokio::test]
async fn a_bound_channel_restores_from_sealed_storage_after_expiry() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    harness.activate_bootstrap(conversation)?;
    expire(&mut harness, PAST_EVERY_WINDOW)?;
    let (restored, result) = Box::pin(super::reinit::successor::reconstruction::reconstruct(
        &harness.writes,
    ))
    .await?;
    result?;
    assert!(restored.owner_reconstruction.is_clean());
    assert!(restored.state.conversations.contains_key(&conversation));
    Ok(())
}

#[test]
fn a_deleted_route_row_releases_its_binding_package_to_expiry() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let package = binding_object(&harness, conversation)?;
    let route_object = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the conversation")?
        .route_object_id;
    // While the row exists no window releases them.
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&package) && !collected.contains(&route_object));
    // The batch that deletes the row retires both at its trusted second.
    let removed_at = PAST_EVERY_WINDOW;
    let mut writes = vec![Write::delete(
        TableId::E2eeState,
        RouteRow::key(&conversation)?,
    )?];
    let staged = harness
        .coordinator
        .stage_owners(
            &mut writes,
            removed_at,
            false,
            super::super::STATE_GENERATION,
        )
        .map_err(|code| format!("{code:?}"))?;
    staged.apply(&mut harness.coordinator.state);
    for write in &writes {
        harness.apply_logical_write(write)?;
    }
    for object in [package, route_object] {
        let account = harness
            .coordinator
            .state
            .owners
            .account(&object)
            .ok_or("the account")?;
        assert!(account.owners.is_empty());
        assert_eq!(account.retired_at, Some(removed_at));
        assert_eq!(account.retention, RetentionClass::SecurityProof);
    }
    let window = removed_at + SEQUENCER_RECORD_RETENTION_SECONDS;
    let early = expire(&mut harness, window - 1)?;
    assert!(!early.contains(&package) && !early.contains(&route_object));
    let due = expire(&mut harness, window)?;
    assert!(due.contains(&package) && due.contains(&route_object));
    Ok(())
}

#[test]
fn a_bound_package_delivered_to_a_mailbox_stays_held_by_its_route() -> TestResult {
    let mut harness = Harness::new()?;
    let conversation = harness.bind_channel()?;
    let package = binding_object(&harness, conversation)?;
    let binding = harness.binding_bytes()?;
    assert_eq!(object_id(&binding), package);
    let mut deliver = super::super::account_param(&harness.account);
    deliver.extend_from_slice(&super::super::DEVICE_ID);
    ok(harness.run(Op::DeliverBinding, &deliver, Some(&binding))?)?;
    let page = ok(harness.run(Op::FetchMailbox, &[2, 0], None)?)?;
    let token = page
        .responses
        .first()
        .and_then(|response| response.delivery_token)
        .ok_or("a delivery token")?;
    let mut ack = token.to_vec();
    ack.extend_from_slice(&package);
    ok(harness.run(Op::AcknowledgeMailbox, &ack, None)?)?;
    // The mailbox names the package too, but the route row keeps it a
    // security proof of the conversation.
    let account = harness
        .coordinator
        .state
        .owners
        .account(&package)
        .ok_or("its account")?;
    let route_row = RouteRow::key(&conversation)?.as_bytes().to_vec();
    assert!(account.owners.contains_key(&route_row));
    assert!(account.owners.len() > 1);
    assert_eq!(account.retention, RetentionClass::SecurityProof);
    assert_eq!(account.conversations(), BTreeSet::from([conversation]));
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&package));
    Ok(())
}

/// The route state object `state` of a synthetic route row.
fn route_state(state: u8) -> TestResult<Vec<u8>> {
    wire_raw(ArcWireObjectKind::FederationState, vec![state; 24])
}

/// A route row of `conversation` naming `binding_id`, whose route state is
/// `state`.
fn route_row(conversation: [u8; 32], binding_id: [u8; 32], state: u8) -> TestResult<Write> {
    let row = RouteRow {
        route_state: route_state(state)?,
        lifecycle: RouteLifecycle::Active,
        binding_id,
        lock_id: [1; 32],
        accepted_state_id: [2; 32],
        sequencer_head_id: [3; 32],
        route_sequence: 0,
        close_id: None,
        predecessor_close_id: None,
        recovery_gate: false,
        stored_bytes: 0,
        sequencer_credential_id: Some([4; 32]),
        blocked_credential_id: None,
    };
    Ok(crate::e2ee::coordinator::request::state_row(
        TableId::E2eeState,
        ROUTE_ROW_KIND,
        RouteRow::key(&conversation)?,
        row.encode()?,
    )
    .map_err(|code| format!("{code:?}"))?)
}

/// Stages one batch at `NOW` as the coordinator does at commit.
fn commit(harness: &mut Harness, mut writes: Vec<Write>) -> TestResult {
    let staged = harness
        .coordinator
        .stage_owners(&mut writes, NOW, true, super::super::STATE_GENERATION)
        .map_err(|code| format!("{code:?}"))?;
    staged.apply(&mut harness.coordinator.state);
    Ok(())
}

#[test]
fn a_route_row_acquires_only_the_package_of_its_binding_that_its_batch_stages() -> TestResult {
    use crate::e2ee::coordinator::CompanionCoordinator;
    use agenc_relay_e2ee::objects::conversation::ArcConversationBindingPackage;
    let mut harness = Harness::new()?;
    let bytes = harness.binding_bytes()?;
    let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
    let object = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
        &bytes,
        Some(ArcWireObjectKind::ConversationBinding),
        &mut budget,
    )?;
    let package = ArcConversationBindingPackage::decode_exact(object.body(), &mut budget)?;
    let binding_id = semantic_id_of(SemanticHashDomain::BindingId, &package.binding.tbs)?;
    let package_id = object_id(&bytes);
    let write = |bytes: &[u8]| {
        CompanionCoordinator::object_write(bytes).map_err(|code| format!("{code:?}"))
    };
    let (bound, other, unreadable) = ([81; 32], [82; 32], [83; 32]);
    // A route row naming another binding acquires nothing the batch stages,
    // and neither does one whose staged package does not decode.
    let garbage = wire_raw(ArcWireObjectKind::ConversationBinding, vec![9; 40])?;
    for resident in [&bytes, &garbage] {
        CompanionCoordinator::retain_object(&mut harness.coordinator.state, resident.clone())
            .map_err(|code| format!("{code:?}"))?;
    }
    commit(
        &mut harness,
        vec![
            write(&bytes)?,
            write(&garbage)?,
            route_row(other, [7; 32], 1)?,
            route_row(unreadable, [7; 32], 2)?,
        ],
    )?;
    let ledger = &harness.coordinator.state.owners;
    for id in [package_id, object_id(&garbage)] {
        assert!(ledger.account(&id).ok_or("account")?.owners.is_empty());
    }
    // The batch that binds a route stages its package, which its row
    // acquires as a security proof charged to the conversation.
    let row = RouteRow::key(&bound)?.as_bytes().to_vec();
    commit(
        &mut harness,
        vec![
            write(&bytes)?,
            write(&route_state(3)?)?,
            route_row(bound, binding_id, 3)?,
        ],
    )?;
    assert_held_by(&harness, package_id, std::slice::from_ref(&row))?;
    let held = |harness: &Harness| {
        harness
            .coordinator
            .state
            .owners
            .owned_by(&row)
            .cloned()
            .unwrap_or_default()
    };
    let first_state = object_id(&route_state(3)?);
    assert_eq!(held(&harness), BTreeSet::from([package_id, first_state]));
    // A rewrite stages no package and keeps it, releasing only the route
    // state it replaced.
    commit(
        &mut harness,
        vec![write(&route_state(4)?)?, route_row(bound, binding_id, 4)?],
    )?;
    assert_held_by(&harness, package_id, std::slice::from_ref(&row))?;
    assert_eq!(
        held(&harness),
        BTreeSet::from([package_id, object_id(&route_state(4)?)])
    );
    // Only the row's deletion releases it.
    commit(
        &mut harness,
        vec![Write::delete(TableId::E2eeState, RouteRow::key(&bound)?)?],
    )?;
    let account = harness
        .coordinator
        .state
        .owners
        .account(&package_id)
        .ok_or("account")?;
    assert!(account.owners.is_empty());
    assert_eq!(account.retired_at, Some(NOW));
    assert_eq!(account.retention, RetentionClass::SecurityProof);
    Ok(())
}
