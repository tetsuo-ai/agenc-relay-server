//! Restore of stores written by earlier coordinators (G-08, storage
//! generation 5): the rows of `test-data/stage-ten/binding-retention/`,
//! written by the test harness of release candidate 3 (`70c832c`) and of the
//! integration main before this topic (`c262ce1`), which this tree seals into
//! a storage fixture and restores through the storage reads a restart uses,
//! and through the harness's reload for the requests that follow.
//!
//! A store that holds its routes' binding packages restores, and from then
//! on each route row holds its package and the rosters its conversation's
//! statements name, so object expiry keeps them. A store
//! that does not hold a route's binding package lacks the facts a restart
//! restores that route from, and startup refuses it.

#![forbid(unsafe_code)]

use super::super::reinit::successor::reconstruction::reconstruct;
use super::*;
use crate::e2ee::coordinator::CompanionFault;
use agenc_relay_storage::StoredKey;
use std::collections::BTreeMap;

fn unhex(text: &str) -> TestResult<Vec<u8>> {
    let pair = |at: usize| -> TestResult<u8> {
        Ok(u8::from_str_radix(text.get(at..at + 2).ok_or("hex")?, 16)?)
    };
    if !text.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..text.len()).step_by(2).map(pair).collect()
}

/// The rows of the store `name`, one `<table> <key hex> <value hex>` per
/// line.
fn rows(name: &str) -> TestResult<Vec<Write>> {
    rows_of("binding-retention", name)
}

/// The rows of the store `name` of the fixture directory `topic` under
/// `test-data/stage-ten/`.
pub(super) fn rows_of(topic: &str, name: &str) -> TestResult<Vec<Write>> {
    let text = std::fs::read_to_string(format!(
        "{}/../../test-data/stage-ten/{topic}/{name}.rows",
        env!("CARGO_MANIFEST_DIR")
    ))?;
    let mut rows = Vec::new();
    for line in text.lines() {
        let mut fields = line.split(' ');
        let (Some(table), Some(key), Some(value), None) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            return Err("a row has three fields".into());
        };
        rows.push(Write::put(
            TableId::from_u16(table.parse()?)?,
            StoredKey::new(unhex(key)?)?,
            unhex(value)?,
        )?);
    }
    Ok(rows)
}

/// The harness restarted from `rows`.
pub(super) fn restarted_from(rows: Vec<Write>) -> TestResult<Harness> {
    let mut source = Harness::new()?;
    source.writes = rows;
    source.reloaded()
}

/// The harness restarted from the rows of `name`.
fn restarted(name: &str) -> TestResult<Harness> {
    restarted_from(rows(name)?)
}

/// The rows of `name` without the object row and the owner row of every
/// binding package its routes restore from.
fn without_packages(name: &str) -> TestResult<Vec<Write>> {
    let harness = restarted(name)?;
    let packages: Vec<[u8; 32]> = harness
        .coordinator
        .state
        .conversations
        .values()
        .map(|conversation| conversation.binding_object_id)
        .collect();
    let mut rows = rows(name)?;
    let before = rows.len();
    rows.retain(|row| {
        !matches!(row, Write::Put { key, .. }
            if packages.iter().any(|package| key.as_bytes().ends_with(package)))
    });
    assert_eq!(rows.len() + 2 * packages.len(), before);
    Ok(rows)
}

/// The retained roster objects of the store, by roster generation.
fn rosters(harness: &Harness) -> TestResult<BTreeMap<u64, [u8; 32]>> {
    use agenc_relay_e2ee::objects::identity::ArcDeviceRoster;
    let mut found = BTreeMap::new();
    for (id, bytes) in &harness.coordinator.state.objects {
        let mut budget = DecodeBudget::new(1 << 20, 1 << 16);
        let Ok(object) = agenc_relay_e2ee::object::ArcWireObject::decode_kind(
            bytes,
            Some(ArcWireObjectKind::DeviceRoster),
            &mut budget,
        ) else {
            continue;
        };
        let roster = ArcDeviceRoster::decode_exact(object.body(), &mut budget)?;
        found.insert(roster.tbs.roster_generation, *id);
    }
    Ok(found)
}

/// The conversation the `#room` route names.
fn room(harness: &Harness) -> TestResult<[u8; 32]> {
    Ok(harness
        .coordinator
        .state
        .routes
        .channel_route(&ChannelInstanceId::from_bytes(INSTANCE))
        .ok_or("the #room route")?
        .conversation_id
        .0)
}

#[tokio::test]
async fn every_store_that_holds_its_packages_restores_from_sealed_storage() -> TestResult {
    for name in [
        "bound-channel",
        "council-roster-replaced",
        "installed-successor",
    ] {
        let (_, result) = Box::pin(reconstruct(&rows(name)?)).await?;
        assert!(result.is_ok(), "{name}: {result:?}");
    }
    Ok(())
}

#[test]
fn an_earlier_bound_channel_restores_and_its_route_holds_its_package_from_then_on() -> TestResult {
    let mut harness = restarted("bound-channel")?;
    let conversation = room(&harness)?;
    let package = binding_object(&harness, conversation)?;
    let route_row = RouteRow::key(&conversation)?.as_bytes().to_vec();
    // The restart derives the route row's holding of the package and
    // rebuilds its account.
    assert!(harness.coordinator.owner_reconstruction.mismatched > 0);
    assert_held_by(&harness, package, std::slice::from_ref(&route_row))?;
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(!collected.contains(&package));
    assert_eq!(object_id(&queried_binding(&mut harness)?), package);
    let mut again = harness.reloaded()?;
    assert_eq!(binding_object(&again, conversation)?, package);
    assert_held_by(&again, package, std::slice::from_ref(&route_row))?;
    assert_eq!(object_id(&queried_binding(&mut again)?), package);
    Ok(())
}

#[test]
fn an_earlier_store_keeps_the_roster_its_policies_were_verified_under() -> TestResult {
    let mut harness = restarted("council-roster-replaced")?;
    let conversation = room(&harness)?;
    let policies = harness
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the conversation")?
        .policies
        .clone();
    assert_eq!(policies.len(), 2);
    // The replaced roster, which the binding names and which holds both
    // council certificates, is held by the route row from this restart on.
    let replaced = *rosters(&harness)?.get(&0).ok_or("the replaced roster")?;
    let route_row = RouteRow::key(&conversation)?.as_bytes().to_vec();
    assert_held_by(&harness, replaced, std::slice::from_ref(&route_row))?;
    expire(&mut harness, PAST_EVERY_WINDOW)?;
    let again = harness.reloaded()?;
    assert_held_by(&again, replaced, std::slice::from_ref(&route_row))?;
    let restored = again
        .coordinator
        .state
        .conversations
        .get(&conversation)
        .ok_or("the restored conversation")?;
    assert_eq!(restored.policies, policies);
    assert!(restored.policies.contains_key(&restored.current_policy_id));
    Ok(())
}

#[test]
fn an_earlier_installed_successor_restores_and_keeps_both_packages() -> TestResult {
    let mut harness = restarted("installed-successor")?;
    let successor = room(&harness)?;
    let predecessor =
        agenc_relay_e2ee::ids::conversation_id(&NETWORK, &crate::e2ee::coordinator::tests::GROUP)?;
    assert_ne!(successor, predecessor);
    let state = &harness.coordinator.state;
    assert_eq!(
        state.logs.get(&successor).map(|log| log.phase()),
        Some(agenc_relay_domain::e2ee::sequencer_log::Phase::Open)
    );
    let packages = [
        (successor, binding_object(&harness, successor)?),
        (predecessor, binding_object(&harness, predecessor)?),
    ];
    for (conversation, package) in packages {
        let row = RouteRow::key(&conversation)?.as_bytes().to_vec();
        assert_held_by(&harness, package, std::slice::from_ref(&row))?;
    }
    let collected = expire(&mut harness, PAST_EVERY_WINDOW)?;
    assert!(
        packages
            .iter()
            .all(|(_, package)| !collected.contains(package))
    );
    let again = harness.reloaded()?;
    assert_eq!(room(&again)?, successor);
    assert_eq!(binding_object(&again, successor)?, packages[0].1);
    Ok(())
}

#[tokio::test]
async fn a_store_without_a_routes_binding_package_refuses_startup() -> TestResult {
    for name in ["bound-channel", "installed-successor"] {
        assert!(restarted_from(without_packages(name)?).is_err(), "{name}");
        let (_, result) = Box::pin(reconstruct(&without_packages(name)?)).await?;
        assert!(
            matches!(result, Err(CompanionFault::Storage)),
            "{name}: {result:?}"
        );
    }
    Ok(())
}
